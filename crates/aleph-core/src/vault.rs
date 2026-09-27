//! The vault file.
//!
//! ```text
//! file       = MAGIC ‖ CBOR([format_version, header, header_mac, body_nonce, body_ct])
//! header     = CBOR({ vault_id, generation, mk_id, keyslots: [bstr(CBOR(slot)), …] })
//!                                                       (stored as a byte string)
//! header_mac = HMAC(HKDF(MK, "aleph header v1"), MAGIC ‖ be32(format_version) ‖ header)
//! body_ct    = XChaCha20-Poly1305(HKDF(MK, "aleph body v1"), CBOR(Body),
//!                                 aad = vault_id ‖ be32(format_version) ‖ header_mac)
//! ```
//!
//! - The MAC covers the header's exact stored bytes, never a re-encoding,
//!   so it cannot be affected by CBOR encoding choices. The outer container
//!   is an array, so there are no field names to alter.
//! - The body's AAD includes `header_mac`, binding each body to the exact
//!   header it was written with.
//! - `generation` rises on every write, and `mk_id` fingerprints MK. With a
//!   high-water mark kept outside the file (`highwater`), they reveal a
//!   rolled-back or replaced file.
//!
//! Removing a keyslot rotates MK (spec §4, "Rotation and revocation"), so a
//! removed credential plus an old copy of the file never opens a newer one.
//!
//! A `LockedVault` is the parsed file with nothing decrypted. Unlocking
//! one keyslot yields an `UnlockedVault`, which owns the master key and the
//! plaintext body and can re-serialize itself.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ciborium::Value;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, MAC_LEN, NONCE_LEN};
use crate::error::{Error, Result};
use crate::highwater::Mark;
use crate::kdf::{self, Argon2Params};
use crate::key::{Kek, KeyHandle};
use crate::keyslot::{Argon2Slot, Keyslot, RecoverySlot, SlotEntry, SlotKind, UnknownSlot};
use crate::model::{Body, now};
use crate::recovery::RecoveryKey;
use crate::xwing;

pub const MAGIC: &[u8; 6] = b"ALEPH\0";
pub const FORMAT_VERSION: u32 = 1;

const HEADER_MAC_INFO: &[u8] = b"aleph header v1";
const BODY_KEY_INFO: &[u8] = b"aleph body v1";
const RECOVERY_KEK_INFO: &[u8] = b"aleph recovery v1";

#[derive(Serialize, Deserialize)]
struct VaultFile(
    u32,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] [u8; MAC_LEN],
    #[serde(with = "serde_bytes")] [u8; NONCE_LEN],
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    vault_id: Uuid,
    generation: u64,
    #[serde(with = "serde_bytes")]
    mk_id: [u8; 16],
    keyslots: Vec<serde_bytes::ByteBuf>,
}

fn mac_input(format_version: u32, header: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(MAGIC.len() + 4 + header.len());
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&format_version.to_be_bytes());
    buf.extend_from_slice(header);
    buf
}

fn body_aad(vault_id: Uuid, format_version: u32, header_mac: &[u8; MAC_LEN]) -> Vec<u8> {
    let mut aad = vault_id.as_bytes().to_vec();
    aad.extend_from_slice(&format_version.to_be_bytes());
    aad.extend_from_slice(header_mac);
    aad
}

/// Strict CBOR decode: exactly one item, no trailing bytes, and (via
/// `check`) any structural constraint serde would silently tolerate.
fn decode_strict<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    check: impl FnOnce(&Value) -> bool,
) -> Result<T> {
    let malformed = |e: &dyn std::fmt::Display| Error::Malformed(e.to_string());
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value = ciborium::from_reader(&mut cursor).map_err(|e| malformed(&e))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::Malformed("trailing data after CBOR item".into()));
    }
    if !check(&value) {
        return Err(Error::Malformed("unexpected CBOR structure".into()));
    }
    value.deserialized().map_err(|e| malformed(&e))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    decode_strict(bytes, |_| true)
}

fn encode<T: Serialize>(value: &T, out: &mut Vec<u8>) -> Result<()> {
    ciborium::into_writer(value, out).map_err(|e| Error::Malformed(e.to_string()))
}

/// Decode the plaintext body straight into `Body`: no intermediate
/// `ciborium::Value`, whose byte and text buffers would be freed without
/// being zeroized. Still rejects trailing bytes.
fn decode_body(bytes: &[u8]) -> Result<Body> {
    let mut cursor = std::io::Cursor::new(bytes);
    let body: Body =
        ciborium::from_reader(&mut cursor).map_err(|e| Error::Malformed(e.to_string()))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::Malformed("trailing data after CBOR item".into()));
    }
    Ok(body)
}

/// Counts bytes without storing them, to size the body buffer exactly.
struct CountingWriter(usize);

impl std::io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Encode the plaintext body into a buffer allocated once at its exact
/// size, so a growing `Vec` never frees a block holding plaintext.
fn encode_body(body: &Body) -> Result<Zeroizing<Vec<u8>>> {
    let malformed = |e: ciborium::ser::Error<std::io::Error>| Error::Malformed(e.to_string());
    let mut counter = CountingWriter(0);
    ciborium::into_writer(body, &mut counter).map_err(malformed)?;
    let mut pt = Zeroizing::new(Vec::with_capacity(counter.0));
    ciborium::into_writer(body, &mut *pt).map_err(malformed)?;
    debug_assert_eq!(pt.len(), pt.capacity());
    Ok(pt)
}

/// `KEK = HKDF(X-Wing shared secret, "aleph recovery v1")`.
fn recovery_kek(ss: &[u8; 32]) -> Result<Kek> {
    Kek::try_init(|buf| {
        buf.copy_from_slice(crypto::hkdf(ss, RECOVERY_KEK_INFO).as_slice());
        Ok(())
    })
}

fn known(entries: &[SlotEntry]) -> impl Iterator<Item = &Keyslot> {
    entries.iter().filter_map(|e| match e {
        SlotEntry::Known(k) => Some(k),
        SlotEntry::Unknown(_) => None,
    })
}

fn unknown(entries: &[SlotEntry]) -> impl Iterator<Item = &UnknownSlot> {
    entries.iter().filter_map(|e| match e {
        SlotEntry::Unknown(u) => Some(u),
        SlotEntry::Known(_) => None,
    })
}

fn find(entries: &[SlotEntry], id: Uuid) -> Result<&Keyslot> {
    known(entries)
        .find(|s| s.id == id)
        .ok_or(Error::NoSuchKeyslot(id))
}

pub struct LockedVault {
    file: VaultFile,
    vault_id: Uuid,
    generation: u64,
    mk_id: [u8; 16],
    entries: Vec<SlotEntry>,
}

impl LockedVault {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let rest = bytes
            .strip_prefix(MAGIC.as_slice())
            .ok_or(Error::BadMagic)?;
        // serde would accept a longer array and ignore the extra elements.
        let file: VaultFile = decode_strict(rest, |v| v.as_array().is_some_and(|a| a.len() == 5))?;
        if file.0 != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(file.0));
        }
        // Parsed before authentication so callers can list keyslots while
        // locked; `unlock` authenticates these exact bytes.
        let header: Header = decode(&file.1)?;
        let entries = header
            .keyslots
            .iter()
            .map(|raw| SlotEntry::decode(raw))
            .collect::<Result<_>>()?;
        Ok(Self {
            vault_id: header.vault_id,
            generation: header.generation,
            mk_id: header.mk_id,
            entries,
            file,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        Self::from_bytes(&fs::read(path)?)
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// Slot metadata, readable while locked so callers can pick a method.
    /// Not yet authenticated: treat as untrusted until an unlock succeeds.
    pub fn keyslots(&self) -> impl Iterator<Item = &Keyslot> {
        known(&self.entries)
    }

    /// Slots of types this build does not understand (not unlockable).
    pub fn unknown_keyslots(&self) -> impl Iterator<Item = &UnknownSlot> {
        unknown(&self.entries)
    }

    /// The file's high-water identity. Unauthenticated until unlock.
    pub fn mark(&self) -> Mark {
        Mark {
            vault_id: self.vault_id,
            generation: self.generation,
            mk_id: self.mk_id,
        }
    }

    /// Unlock the login-password slot by running Argon2id over `password`
    /// with the slot's stored parameters.
    pub fn unlock_login_password(&self, slot_id: Uuid, password: &[u8]) -> Result<UnlockedVault> {
        let kek = login_password_kek(&self.entries, slot_id, password)?;
        self.unlock(slot_id, &kek)
    }

    /// Unlock a recovery slot with the recovery key.
    pub fn unlock_recovery(&self, slot_id: Uuid, key: &RecoveryKey) -> Result<UnlockedVault> {
        let slot = find(&self.entries, slot_id)?;
        let SlotKind::Recovery(r) = &slot.kind else {
            return Err(Error::WrongSlotType(slot_id));
        };
        let recipient = key.recipient();
        // Faster, clearer failure for a mistyped-but-valid key: its public
        // key will not match. (The AEAD would reject it anyway.)
        if recipient.public_key() != r.xwing_pk {
            return Err(Error::UnwrapFailed);
        }
        let ss = recipient.decapsulate(&r.xwing_ct)?;
        self.unlock(slot_id, &recovery_kek(&ss)?)
    }

    /// Unwrap the master key from one slot, authenticate the header, and
    /// decrypt the body.
    pub fn unlock(&self, slot_id: Uuid, kek: &Kek) -> Result<UnlockedVault> {
        let VaultFile(version, header_bytes, header_mac, body_nonce, body_ct) = &self.file;
        let slot = find(&self.entries, slot_id)?;
        let key = KeyHandle::unwrap(
            kek,
            &slot.wrapped(),
            &Keyslot::aad(self.vault_id, slot.id, &slot.kind),
        )?;
        if !key.verify_mac(
            HEADER_MAC_INFO,
            &mac_input(*version, header_bytes),
            header_mac,
        ) || key.id() != self.mk_id
        {
            return Err(Error::HeaderTampered);
        }
        let pt = key
            .open(
                BODY_KEY_INFO,
                body_nonce,
                &body_aad(self.vault_id, *version, header_mac),
                body_ct,
            )
            .ok_or(Error::BodyTampered)?;
        let body = decode_body(&pt)?;
        Ok(UnlockedVault {
            vault_id: self.vault_id,
            generation: AtomicU64::new(self.generation),
            rotated: AtomicBool::new(false),
            entries: self.entries.clone(),
            key,
            body,
        })
    }
}

fn login_password_kek(entries: &[SlotEntry], slot_id: Uuid, password: &[u8]) -> Result<Kek> {
    let slot = find(entries, slot_id)?;
    let SlotKind::LoginPassword(a) = &slot.kind else {
        return Err(Error::WrongSlotType(slot_id));
    };
    kdf::derive_kek(password, &a.salt, &a.params)
}

/// What a rotation did besides re-wrapping.
#[derive(Debug, Default)]
pub struct Rotation {
    /// Slots removed because the caller asked (`drop`).
    pub dropped: Vec<Uuid>,
    /// Slots of unknown types, removed because they cannot be re-wrapped.
    pub dropped_unknown: Vec<UnknownSlot>,
}

pub struct UnlockedVault {
    vault_id: Uuid,
    /// The generation last read or written; the next write uses one more.
    generation: AtomicU64,
    /// MK rotated since the last write: that write must not leave the
    /// pre-rotation file (old MK, removed slots) behind as `.bak`.
    rotated: AtomicBool,
    entries: Vec<SlotEntry>,
    key: KeyHandle,
    body: Body,
}

impl UnlockedVault {
    /// A new vault with a fresh master key, the default body, and no
    /// keyslots. Add a recovery slot (required) before serializing.
    pub fn create() -> Result<Self> {
        Ok(Self {
            vault_id: Uuid::new_v4(),
            generation: AtomicU64::new(0),
            rotated: AtomicBool::new(false),
            entries: Vec::new(),
            key: KeyHandle::generate()?,
            body: Body::default(),
        })
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    pub fn keyslots(&self) -> impl Iterator<Item = &Keyslot> {
        known(&self.entries)
    }

    pub fn unknown_keyslots(&self) -> impl Iterator<Item = &UnknownSlot> {
        unknown(&self.entries)
    }

    /// Identity of the last-read or last-written generation.
    pub fn mark(&self) -> Mark {
        Mark {
            vault_id: self.vault_id,
            generation: self.generation.load(Ordering::SeqCst),
            mk_id: self.key.id(),
        }
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    fn push(&mut self, label: String, kind: SlotKind, kek: &Kek) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let wrapped = self
            .key
            .wrap(kek, &Keyslot::aad(self.vault_id, id, &kind))?;
        self.entries.push(SlotEntry::Known(Keyslot {
            id,
            label,
            created: now(),
            nonce: wrapped.nonce,
            wrapped_mk: wrapped.ciphertext,
            kind,
        }));
        Ok(id)
    }

    /// Add a TPM or FIDO2 slot whose KEK the caller produced
    /// (`aleph-unlock`). Returns the slot id.
    pub fn add_keyslot(
        &mut self,
        label: impl Into<String>,
        kind: SlotKind,
        kek: &Kek,
    ) -> Result<Uuid> {
        if !matches!(kind, SlotKind::Tpm(_) | SlotKind::Fido2(_)) {
            return Err(Error::NotAHardwareSlot);
        }
        self.push(label.into(), kind, kek)
    }

    /// Add a recovery slot for the recipient `public_key` (from
    /// `RecoveryKey::recipient().public_key()`). Needs no secret.
    pub fn add_recovery_slot(
        &mut self,
        label: impl Into<String>,
        public_key: &[u8],
    ) -> Result<Uuid> {
        let (ct, ss) = xwing::encapsulate(public_key)?;
        let kind = SlotKind::Recovery(RecoverySlot {
            xwing_pk: public_key.to_vec(),
            xwing_ct: ct,
        });
        self.push(label.into(), kind, &recovery_kek(&ss)?)
    }

    /// Add a login-password slot (machines without a TPM). `params` must
    /// meet `Argon2Params::LOGIN_PASSWORD_FLOOR`.
    pub fn add_login_password_slot(
        &mut self,
        label: impl Into<String>,
        password: &[u8],
        params: Argon2Params,
    ) -> Result<Uuid> {
        if !params.enrollable() {
            return Err(Error::WeakParams);
        }
        let salt = crypto::random_array()?;
        let kek = kdf::derive_kek(password, &salt, &params)?;
        self.push(
            label.into(),
            SlotKind::LoginPassword(Argon2Slot { salt, params }),
            &kek,
        )
    }

    /// The KEK of a login-password slot, for supplying to a rotation.
    pub fn login_password_kek(&self, slot_id: Uuid, password: &[u8]) -> Result<Kek> {
        login_password_kek(&self.entries, slot_id, password)
    }

    /// Remove a keyslot and rotate MK, so the removed credential cannot
    /// open any file written from now on. `keks` must cover every remaining
    /// TPM, FIDO2, and login-password slot (see `rotate_master`).
    pub fn remove_keyslot(&mut self, id: Uuid, keks: &[(Uuid, &Kek)]) -> Result<Rotation> {
        self.rotate_master(keks, &[id])
    }

    /// Replace MK and re-wrap every slot. Slots in `drop` are removed
    /// instead; slots of unknown type are removed because they cannot be
    /// re-wrapped. Recovery slots are re-wrapped to their public key and
    /// need no KEK. Every other remaining slot needs its correct KEK in
    /// `keks`, each proven by unwrapping before anything changes: on any
    /// error the vault is untouched. At least one recovery slot must remain.
    pub fn rotate_master(&mut self, keks: &[(Uuid, &Kek)], drop: &[Uuid]) -> Result<Rotation> {
        for id in drop {
            let present = self.entries.iter().any(|e| match e {
                SlotEntry::Known(k) => k.id == *id,
                SlotEntry::Unknown(u) => u.id == Some(*id),
            });
            if !present {
                return Err(Error::NoSuchKeyslot(*id));
            }
        }
        let mut dropped: Vec<Uuid> = known(&self.entries)
            .filter(|s| drop.contains(&s.id))
            .map(|s| s.id)
            .collect();
        dropped.sort();
        dropped.dedup();
        let keep: Vec<&Keyslot> = known(&self.entries)
            .filter(|s| !drop.contains(&s.id))
            .collect();
        if !keep.iter().any(|s| matches!(s.kind, SlotKind::Recovery(_))) {
            return Err(Error::RecoveryRequired);
        }
        for slot in keep
            .iter()
            .filter(|s| !matches!(s.kind, SlotKind::Recovery(_)))
        {
            let (_, kek) = keks
                .iter()
                .find(|(id, _)| *id == slot.id)
                .ok_or(Error::MissingKek(slot.id))?;
            if !KeyHandle::unwraps_to(
                kek,
                &slot.wrapped(),
                &Keyslot::aad(self.vault_id, slot.id, &slot.kind),
                &self.key.id(),
            ) {
                return Err(Error::WrongKek(slot.id));
            }
        }

        let new_key = KeyHandle::generate()?;
        let mut rewrapped = Vec::with_capacity(keep.len());
        for slot in keep {
            let mut slot = slot.clone();
            let fresh_recovery_kek;
            let kek: &Kek = match &mut slot.kind {
                SlotKind::Recovery(r) => {
                    let (ct, ss) = xwing::encapsulate(&r.xwing_pk)?;
                    r.xwing_ct = ct;
                    fresh_recovery_kek = recovery_kek(&ss)?;
                    &fresh_recovery_kek
                }
                _ => keks
                    .iter()
                    .find(|(id, _)| *id == slot.id)
                    .map(|(_, k)| *k)
                    .expect("presence checked above"),
            };
            let w = new_key.wrap(kek, &Keyslot::aad(self.vault_id, slot.id, &slot.kind))?;
            slot.nonce = w.nonce;
            slot.wrapped_mk = w.ciphertext;
            rewrapped.push(SlotEntry::Known(slot));
        }

        let rotation = Rotation {
            dropped,
            dropped_unknown: unknown(&self.entries).cloned().collect(),
        };
        self.entries = rewrapped;
        self.key = new_key;
        self.rotated.store(true, Ordering::SeqCst);
        Ok(rotation)
    }

    /// Serialize the next generation, with a fresh body nonce and a
    /// recomputed header MAC, and advance the generation. Fails without a
    /// recovery slot. Use `write` to put a vault on disk: it returns the
    /// `Mark` of what it wrote.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let generation = self.next_generation()?;
        let bytes = self.serialize(&self.entries, generation)?;
        self.generation.fetch_max(generation, Ordering::SeqCst);
        Ok(bytes)
    }

    fn next_generation(&self) -> Result<u64> {
        if !known(&self.entries).any(|s| matches!(s.kind, SlotKind::Recovery(_))) {
            return Err(Error::RecoveryRequired);
        }
        self.generation
            .load(Ordering::SeqCst)
            .checked_add(1)
            .ok_or(Error::GenerationOverflow)
    }

    /// A copy for `aleph backup`: the current generation with only the
    /// recovery slot(s), so a leaked backup exposes no login-password
    /// slot to offline guessing.
    pub fn to_backup_bytes(&self) -> Result<Vec<u8>> {
        let recovery: Vec<SlotEntry> = self
            .entries
            .iter()
            .filter(|e| matches!(e, SlotEntry::Known(k) if matches!(k.kind, SlotKind::Recovery(_))))
            .cloned()
            .collect();
        if recovery.is_empty() {
            return Err(Error::RecoveryRequired);
        }
        // Generations start at 1, even for a never-written vault.
        self.serialize(&recovery, self.generation.load(Ordering::SeqCst).max(1))
    }

    fn serialize(&self, entries: &[SlotEntry], generation: u64) -> Result<Vec<u8>> {
        self.serialize_with_mk_id(entries, generation, self.key.id())
    }

    fn serialize_with_mk_id(
        &self,
        entries: &[SlotEntry],
        generation: u64,
        mk_id: [u8; 16],
    ) -> Result<Vec<u8>> {
        let keyslots = entries
            .iter()
            .map(|e| e.encode().map(serde_bytes::ByteBuf::from))
            .collect::<Result<Vec<_>>>()?;
        let mut header = Vec::new();
        encode(
            &Header {
                vault_id: self.vault_id,
                generation,
                mk_id,
                keyslots,
            },
            &mut header,
        )?;
        let header_mac = self
            .key
            .mac(HEADER_MAC_INFO, &mac_input(FORMAT_VERSION, &header));
        let pt = encode_body(&self.body)?;
        let (nonce, ct) = self.key.seal(
            BODY_KEY_INFO,
            &body_aad(self.vault_id, FORMAT_VERSION, &header_mac),
            &pt,
        )?;
        let mut out = MAGIC.to_vec();
        encode(
            &VaultFile(FORMAT_VERSION, header, header_mac, nonce, ct),
            &mut out,
        )?;
        Ok(out)
    }

    /// Atomically replace the vault at `path` with the next generation and
    /// return that generation's `Mark` (what the daemon records in the
    /// high-water store).
    ///
    /// - The previous version is kept as `<path>.bak`, except on the first
    ///   write after a rotation, when `.bak` is also the new file (the old
    ///   one still holds the old MK and any removed slot).
    /// - The generation is chosen and serialized while holding
    ///   `<path>.lock`, and committed only after the rename. Concurrent
    ///   writers therefore get distinct generations, the file on disk is the
    ///   highest, and a failed write does not advance the generation.
    /// - Creates the parent directory (0700), tightens an existing one that
    ///   is group- or world-accessible, and refuses to replace a symlink.
    pub fn write(&self, path: &Path) -> Result<Mark> {
        let rotated = self.rotated.load(Ordering::SeqCst);
        let mut written = 0;
        write_atomic(
            path,
            || {
                written = self.next_generation()?;
                self.serialize(&self.entries, written)
            },
            rotated,
        )?;
        self.generation.fetch_max(written, Ordering::SeqCst);
        if rotated {
            self.rotated.store(false, Ordering::SeqCst);
        }
        Ok(Mark {
            vault_id: self.vault_id,
            generation: written,
            mk_id: self.key.id(),
        })
    }
}

fn sibling(path: &Path, suffix: &str) -> Result<std::path::PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("vault path {} has no file name", path.display()),
            )
        })?
        .to_os_string();
    name.push(suffix);
    Ok(path.with_file_name(name))
}

/// Write a fresh 0600 file. Any existing file at `path` (a temp file left
/// by a crash or another tool) is removed first, because `mode` only
/// applies when a file is created and would not tighten an existing one.
fn write_file_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Replace `path` atomically with the bytes `make` produces. `make` runs
/// while `<path>.lock` is held, so what it reads (e.g. the next generation)
/// cannot interleave with another writer. With `replace_backup`, `.bak`
/// becomes a copy of the new file instead of the previous one.
fn write_atomic(
    path: &Path,
    make: impl FnOnce() -> Result<Vec<u8>>,
    replace_backup: bool,
) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    } else if dir.metadata()?.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    // `rename` would silently replace a symlink (e.g. into a sync folder)
    // with a regular file.
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing to replace symlink {}", path.display()),
        )));
    }
    // Serialize writers. Without this, one writer's `write_file_synced`
    // could unlink another's temp file mid-write, and the other's rename
    // would then put this half-written file in place. The lock is on a
    // sibling that is never renamed, so it guards every path below.
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(sibling(path, ".lock")?)?;
    lock.lock()?;
    let bytes = make()?;
    let bak_tmp = sibling(path, ".bak.tmp")?;
    let bak = sibling(path, ".bak")?;
    if path.exists() && !replace_backup {
        write_file_synced(&bak_tmp, &fs::read(path)?)?;
        fs::rename(&bak_tmp, &bak)?;
    }
    let tmp = sibling(path, ".tmp")?;
    write_file_synced(&tmp, &bytes)?;
    fs::rename(&tmp, path)?;
    if replace_backup {
        write_file_synced(&bak_tmp, &bytes)?;
        fs::rename(&bak_tmp, &bak)?;
    }
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Atomically write a small private file (0600, in a 0700 directory it
/// creates if needed): temp file, fsync, rename. No backup, no lock.
pub(crate) fn write_small_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let tmp = sibling(path, ".tmp")?;
    write_file_synced(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Hooks for this crate's own tests, only with `insecure-test-params`.
#[cfg(feature = "insecure-test-params")]
#[doc(hidden)]
pub mod testing {
    use std::sync::atomic::Ordering;

    use super::{SlotEntry, UnlockedVault};
    use crate::error::Result;

    /// Add an encoded slot as if a newer aleph had written it.
    pub fn push_unknown(v: &mut UnlockedVault, raw: Vec<u8>) {
        v.entries
            .push(SlotEntry::decode(&raw).expect("decodable slot"));
    }

    /// Force the generation counter (to test overflow).
    pub fn set_generation(v: &UnlockedVault, generation: u64) {
        v.generation.store(generation, Ordering::SeqCst);
    }

    /// Serialize with a chosen `mk_id` but a valid MAC under the real key:
    /// what someone holding this (old) MK could forge.
    pub fn to_bytes_with_mk_id(v: &UnlockedVault, mk_id: [u8; 16]) -> Result<Vec<u8>> {
        v.serialize_with_mk_id(&v.entries, 1, mk_id)
    }
}
