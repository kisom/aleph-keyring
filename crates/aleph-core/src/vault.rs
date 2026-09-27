//! The vault file.
//!
//! ```text
//! file       = MAGIC ‖ CBOR([format_version, header, header_mac, body_nonce, body_ct])
//! header     = CBOR(Header { vault_id, keyslots })          (stored as a byte string)
//! header_mac = HMAC(HKDF(MK, "aleph header v1"), MAGIC ‖ be32(format_version) ‖ header)
//! body_ct    = XChaCha20-Poly1305(HKDF(MK, "aleph body v1"), CBOR(Body),
//!                                 aad = vault_id ‖ be32(format_version) ‖ header_mac)
//! ```
//!
//! The MAC covers the header's exact stored bytes, never a re-encoding,
//! so it cannot be affected by CBOR encoding choices (ours or a future
//! ciborium's). The outer container is an array: no field names to alter.
//! The body's AAD includes `header_mac`, binding each body to the exact
//! header it was written with: an older header (e.g. one still listing a
//! since-removed keyslot) cannot be spliced onto a newer body.
//!
//! A `LockedVault` is the parsed file with nothing decrypted. Unlocking
//! one keyslot yields an `UnlockedVault`, which owns the master key and
//! the plaintext body and can re-serialize itself.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ciborium::Value;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{MAC_LEN, NONCE_LEN};
use crate::error::{Error, Result};
use crate::kdf::{self, Argon2Params};
use crate::key::{Kek, KeyHandle};
use crate::keyslot::{Argon2Kind, Argon2Slot, Keyslot, SlotKind};
use crate::model::{Body, now};

pub const MAGIC: &[u8; 6] = b"ALEPH\0";
pub const FORMAT_VERSION: u32 = 1;

const HEADER_MAC_INFO: &[u8] = b"aleph header v1";
const BODY_KEY_INFO: &[u8] = b"aleph body v1";

#[derive(Serialize, Deserialize)]
struct VaultFile(
    u32,
    #[serde(with = "serde_bytes")] Vec<u8>,
    #[serde(with = "serde_bytes")] [u8; MAC_LEN],
    #[serde(with = "serde_bytes")] [u8; NONCE_LEN],
    #[serde(with = "serde_bytes")] Vec<u8>,
);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Header {
    vault_id: Uuid,
    keyslots: Vec<Keyslot>,
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

pub struct LockedVault {
    file: VaultFile,
    header: Header,
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
        Ok(Self { file, header })
    }

    pub fn read(path: &Path) -> Result<Self> {
        Self::from_bytes(&fs::read(path)?)
    }

    pub fn vault_id(&self) -> Uuid {
        self.header.vault_id
    }

    /// Slot metadata, readable while locked so callers can pick a method.
    /// Not yet authenticated: treat as untrusted until `unlock` succeeds.
    pub fn keyslots(&self) -> &[Keyslot] {
        &self.header.keyslots
    }

    /// Unlock a recovery-key, passphrase, or login-password slot by running
    /// Argon2id over `secret` with the slot's stored parameters.
    pub fn unlock_argon2(&self, slot_id: Uuid, secret: &[u8]) -> Result<UnlockedVault> {
        let slot = self
            .keyslots()
            .iter()
            .find(|s| s.id == slot_id)
            .ok_or(Error::NoSuchKeyslot(slot_id))?;
        let a = slot.kind.as_argon2().ok_or(Error::WrongSlotType(slot_id))?;
        let kek = kdf::derive_kek(secret, &a.salt, &a.params)?;
        self.unlock(slot_id, &kek)
    }

    /// Unwrap the master key from one slot, authenticate the header, and
    /// decrypt the body.
    pub fn unlock(&self, slot_id: Uuid, kek: &Kek) -> Result<UnlockedVault> {
        let VaultFile(version, header_bytes, header_mac, body_nonce, body_ct) = &self.file;
        let h = &self.header;
        let slot = h
            .keyslots
            .iter()
            .find(|s| s.id == slot_id)
            .ok_or(Error::NoSuchKeyslot(slot_id))?;
        let key = KeyHandle::unwrap(
            kek,
            &slot.wrapped(),
            &Keyslot::aad(h.vault_id, slot.id, &slot.kind),
        )?;
        if !key.verify_mac(
            HEADER_MAC_INFO,
            &mac_input(*version, header_bytes),
            header_mac,
        ) {
            return Err(Error::HeaderTampered);
        }
        let pt = key
            .open(
                BODY_KEY_INFO,
                body_nonce,
                &body_aad(h.vault_id, *version, header_mac),
                body_ct,
            )
            .ok_or(Error::BodyTampered)?;
        let body = decode_body(&pt)?;
        Ok(UnlockedVault {
            vault_id: h.vault_id,
            keyslots: h.keyslots.clone(),
            key,
            body,
        })
    }
}

pub struct UnlockedVault {
    vault_id: Uuid,
    keyslots: Vec<Keyslot>,
    key: KeyHandle,
    body: Body,
}

impl UnlockedVault {
    /// A new vault with a fresh master key, the default body, and no
    /// keyslots. Add at least one slot before serializing.
    pub fn create() -> Result<Self> {
        Ok(Self {
            vault_id: Uuid::new_v4(),
            keyslots: Vec::new(),
            key: KeyHandle::generate()?,
            body: Body::default(),
        })
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    pub fn keyslots(&self) -> &[Keyslot] {
        &self.keyslots
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    /// Wrap the master key under `kek` in a new slot. Returns the slot id.
    pub fn add_keyslot(
        &mut self,
        label: impl Into<String>,
        kind: SlotKind,
        kek: &Kek,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let wrapped = self
            .key
            .wrap(kek, &Keyslot::aad(self.vault_id, id, &kind))?;
        self.keyslots.push(Keyslot {
            id,
            label: label.into(),
            created: now(),
            nonce: wrapped.nonce,
            wrapped_mk: wrapped.ciphertext,
            kind,
        });
        Ok(id)
    }

    /// Add a recovery-key, passphrase, or login-password slot with a fresh
    /// random salt.
    pub fn add_argon2_keyslot(
        &mut self,
        label: impl Into<String>,
        kind: Argon2Kind,
        secret: &[u8],
        params: Argon2Params,
    ) -> Result<Uuid> {
        let salt = crate::crypto::random_array()?;
        let kek = kdf::derive_kek(secret, &salt, &params)?;
        self.add_keyslot(
            label,
            SlotKind::argon2(kind, Argon2Slot { salt, params }),
            &kek,
        )
    }

    pub fn remove_keyslot(&mut self, id: Uuid) -> Result<()> {
        let pos = self
            .keyslots
            .iter()
            .position(|s| s.id == id)
            .ok_or(Error::NoSuchKeyslot(id))?;
        if self.keyslots.len() == 1 {
            return Err(Error::LastKeyslot);
        }
        self.keyslots.remove(pos);
        Ok(())
    }

    /// Replace the master key and re-wrap every slot. `keks` must supply
    /// the correct KEK for every existing slot; each is proven by
    /// unwrapping the slot before anything changes, so a missing or wrong
    /// KEK leaves the vault untouched.
    pub fn rotate_master(&mut self, keks: &[(Uuid, &Kek)]) -> Result<()> {
        for slot in &self.keyslots {
            let (_, kek) = keks
                .iter()
                .find(|(id, _)| *id == slot.id)
                .ok_or(Error::MissingKek(slot.id))?;
            if !KeyHandle::unwraps(
                kek,
                &slot.wrapped(),
                &Keyslot::aad(self.vault_id, slot.id, &slot.kind),
            ) {
                return Err(Error::WrongKek(slot.id));
            }
        }
        let new_key = KeyHandle::generate()?;
        let mut rewrapped = self.keyslots.clone();
        for slot in &mut rewrapped {
            let kek = keks
                .iter()
                .find(|(id, _)| *id == slot.id)
                .map(|(_, k)| *k)
                .expect("checked above");
            let w = new_key.wrap(kek, &Keyslot::aad(self.vault_id, slot.id, &slot.kind))?;
            slot.nonce = w.nonce;
            slot.wrapped_mk = w.ciphertext;
        }
        self.keyslots = rewrapped;
        self.key = new_key;
        Ok(())
    }

    /// Serialize with a fresh body nonce and a recomputed header MAC.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.keyslots.is_empty() {
            return Err(Error::LastKeyslot);
        }
        let mut header = Vec::new();
        encode(
            &Header {
                vault_id: self.vault_id,
                keyslots: self.keyslots.clone(),
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

    /// Atomically replace the vault at `path`, keeping the previous
    /// version as `<path>.bak`. Creates the parent directory (0700).
    /// Concurrent writers are serialized on `<path>.lock`; the last one to
    /// write wins, but the vault and backup are always intact.
    pub fn write(&self, path: &Path) -> Result<()> {
        write_atomic(path, &self.to_bytes()?)
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

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
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
    if path.exists() {
        let bak_tmp = sibling(path, ".bak.tmp")?;
        write_file_synced(&bak_tmp, &fs::read(path)?)?;
        fs::rename(&bak_tmp, sibling(path, ".bak")?)?;
    }
    let tmp = sibling(path, ".tmp")?;
    write_file_synced(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
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
