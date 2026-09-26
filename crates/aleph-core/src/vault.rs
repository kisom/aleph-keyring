//! The vault file.
//!
//! ```text
//! file       = MAGIC ‖ CBOR([format_version, header, header_mac, body_nonce, body_ct])
//! header     = CBOR(Header { vault_id, keyslots })          (stored as a byte string)
//! header_mac = HMAC(HKDF(MK, "aleph header v1"), MAGIC ‖ be32(format_version) ‖ header)
//! body_ct    = XChaCha20-Poly1305(HKDF(MK, "aleph body v1"), CBOR(Body),
//!                                 aad = vault_id ‖ be32(format_version))
//! ```
//!
//! The MAC covers the header's exact stored bytes, never a re-encoding,
//! so it cannot be affected by CBOR encoding choices (ours or a future
//! ciborium's). The outer container is an array: no field names to alter.
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

fn body_aad(vault_id: Uuid, format_version: u32) -> Vec<u8> {
    let mut aad = vault_id.as_bytes().to_vec();
    aad.extend_from_slice(&format_version.to_be_bytes());
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
                &body_aad(h.vault_id, *version),
                body_ct,
            )
            .ok_or(Error::BodyTampered)?;
        let body: Body = decode(&pt)?;
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
    /// the KEK for every existing slot; nothing changes if one is missing.
    pub fn rotate_master(&mut self, keks: &[(Uuid, &Kek)]) -> Result<()> {
        for slot in &self.keyslots {
            if !keks.iter().any(|(id, _)| *id == slot.id) {
                return Err(Error::MissingKek(slot.id));
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
        let mut pt = Zeroizing::new(Vec::new());
        encode(&self.body, &mut pt)?;
        let (nonce, ct) =
            self.key
                .seal(BODY_KEY_INFO, &body_aad(self.vault_id, FORMAT_VERSION), &pt)?;
        let mut out = MAGIC.to_vec();
        encode(
            &VaultFile(FORMAT_VERSION, header, header_mac, nonce, ct),
            &mut out,
        )?;
        Ok(out)
    }

    /// Atomically replace the vault at `path`, keeping the previous
    /// version as `<path>.bak`. Creates the parent directory (0700).
    pub fn write(&self, path: &Path) -> Result<()> {
        write_atomic(path, &self.to_bytes()?)
    }
}

fn sibling(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .expect("vault path has a file name")
        .to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}

fn write_file_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
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
    if path.exists() {
        let bak_tmp = sibling(path, ".bak.tmp");
        write_file_synced(&bak_tmp, &fs::read(path)?)?;
        fs::rename(&bak_tmp, sibling(path, ".bak"))?;
    }
    let tmp = sibling(path, ".tmp");
    write_file_synced(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}
