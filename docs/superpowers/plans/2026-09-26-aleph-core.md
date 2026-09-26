# aleph-core Implementation Plan (Plan 1 of 6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the Cargo workspace and the `aleph-core` crate: the vault file format, its cryptography, keyslots, the recovery-key encoding, and the Secret Service data model, fully tested with no hardware or D-Bus.

**Architecture:** `aleph-core` is a pure library. A random 32-byte master key (held only by `KeyHandle`) encrypts the vault body and authenticates the header. Each keyslot stores the master key wrapped under a slot-specific KEK. This crate derives KEKs itself only for Argon2id slots (recovery key, passphrase, login password); TPM and FIDO2 KEKs come from `aleph-unlock` in Plan 2. `LockedVault` is a parsed file; unlocking one slot yields an `UnlockedVault` that can edit and re-serialize the vault.

**Tech Stack:** Rust 1.98 (edition 2024), `chacha20poly1305` 0.11, `hkdf` 0.13, `hmac` 0.13, `sha2` 0.11, `argon2` 0.6, `ciborium` 0.2, `serde`, `serde_bytes`, `secrecy` 0.10, `zeroize`, `uuid`, `getrandom` 0.4, `thiserror` 2, `libc`; dev: `proptest`, `tempfile`.

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` (§3 workspace and `KeyHandle` seam, §4 vault format, §5 recovery secret, §9 testing).

## Plan series

The spec is delivered as six plans, each producing working, tested software:

1. **aleph-core** (this plan): workspace, vault format, crypto, keyslots, recovery key, data model.
2. **aleph-unlock**: TPM sealing (`tss-esapi`, `swtpm` in CI) and FIDO2 `hmac-secret` (`Authenticator` trait + mock).
3. **alephd + CLI basics**: Secret Service over `zbus`, admin interface, `aleph get/store/search/ls`, `secret-tool` conformance.
4. **Session integration**: `pam_aleph`, lock policy (logind), `aleph setup`/`--revert`, gnome-keyring import, `backup`/`restore`.
5. **aleph-gui**: egui prompter (FIDO2 insert → PIN → touch) and manager; Omarchy theme + scanlines.
6. **Packaging & CI**: PKGBUILD/AUR, Nix flake + NixOS module, GitHub Actions, `cargo deny`, `cargo-fuzz` targets.

## Deviations from the spec (found while prototyping; spec updated in Task 9)

- **Recovery-key checksum is 4 characters, not 2.** 52 data + 2 check characters is 54, which does not divide into groups of 4; 52 + 4 = 56 gives 14 even groups and 20 bits of typo detection instead of 10.
- **The header MAC covers the header's exact stored bytes.** The spec's "HMAC over all preceding fields" was prototyped as re-serializing the parsed header. An exhaustive bit-flip test showed CBOR encoding malleability (a field name's major type can flip from text to bytes and still decode identically), and a future `ciborium` encoding change would have invalidated every vault. The file is now `MAGIC ‖ CBOR([format_version, header_bytes, header_mac, body_nonce, body_ct])` and the MAC input is `MAGIC ‖ be32(format_version) ‖ header_bytes`. Decoding is strict: exactly one CBOR item, no trailing bytes, exactly five outer elements.
- **Argon2 parameters read from a vault are capped** (`m ≤ 4 GiB`, `t ≤ 64`, `p ≤ 16`) so a corrupt or hostile slot errors instead of attempting a huge allocation.
- **Login-password fallback floor** is `m = 64 MiB, t = 2, p = 4` before tuning to ≈0.3 s (the spec gave only the time target).

## Global Constraints

- Rust stable 1.98, edition 2024, workspace resolver 3.
- Every crate: `license = "Apache-2.0"`.
- `aleph-core` has no D-Bus, no hardware access, no global state. The only `unsafe` is `mlock`/`munlock` in `key.rs`.
- Algorithms: XChaCha20-Poly1305 (24-byte random nonces), HKDF-SHA-256 (no salt), HMAC-SHA-256, Argon2id v0x13. HKDF info strings are exactly `"aleph header v1"` and `"aleph body v1"`; the magic is exactly `b"ALEPH\0"`; `FORMAT_VERSION = 1`.
- Wrapped-key AAD is `vault_id(16) ‖ slot_id(16) ‖ slot_type` where `slot_type` is one of `tpm`, `fido2`, `recovery-key`, `passphrase`, `login-password`.
- Secret-holding types never print their contents: `Debug` shows `[REDACTED]`.
- Vault file mode `0600`; a vault directory created by aleph is `0700`.
- `cargo fmt` with default settings; `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit message ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` (the commit steps include it).

## Review Focus

These are the failure modes most likely to bite a real user that the spec implies but doesn't spell out. Each is pinned by a test in the owning task.

1. **A corrupt or hostile vault file** (truncated, random bytes, a slot demanding terabytes of Argon2 memory) must return an `Err`, never panic, abort, or allocate unboundedly. → Task 3 `oversized_params_are_rejected_before_allocating`, Task 7 `arbitrary_bytes_never_panic`, `trailing_bytes_and_extra_elements_are_rejected`.
2. **A crash or power loss mid-write** must leave either the old or the new complete vault at the path, and a stale `.tmp` from a crashed write must not break the next write. → Task 8 `write_is_atomic_private_and_keeps_a_backup`, `stale_temp_file_from_a_crashed_write_is_replaced`.
3. **A mistyped recovery key** must be reported as a typo, not accepted as a different key and not fail silently at unwrap time. Lowercase, spaces instead of dashes, and O/I/L lookalikes must still work. → Task 4 `parse_rejects_typos_wrong_length_and_bad_chars`, `parse_is_forgiving_about_case_separators_and_lookalikes`.
4. **Any modification of the file** (including encoding-level changes) must be detected, and vaults written by this version must open in every later version. → Task 7 `every_single_bit_flip_is_detected` (exhaustive), Task 9 golden file.
5. **Non-ASCII labels, empty secrets, and binary secrets** must round-trip byte-for-byte. → Task 7 `body_round_trips` (proptest).

## File Structure

```
Cargo.toml                         workspace, shared deps, opt-level overrides for crypto in dev/test
LICENSE, NOTICE, README.md, .gitignore
crates/aleph-core/
  Cargo.toml
  src/lib.rs                       module list + re-exports
  src/error.rs                     Error enum, Result alias
  src/crypto.rs                    AEAD seal/open, HKDF, HMAC, CSPRNG (the only place algorithms are named)
  src/key.rs                       Kek, WrappedKey, KeyHandle (master key custody, the v2 privilege-separation seam)
  src/kdf.rs                       Argon2Params, derive_kek, tune
  src/recovery.rs                  RecoveryKey: Crockford base32 + checksum
  src/model.rs                     Body, Collection, Item, SecretBytes
  src/keyslot.rs                   Keyslot, SlotKind and per-type params, AAD construction
  src/vault.rs                     file format, LockedVault, UnlockedVault, atomic write
  tests/common/mod.rs              shared fixtures and CBOR-editing helpers for tamper tests
  tests/vault.rs                   format, unlock, tamper, rotation, property tests
  tests/write.rs                   atomic write behaviour
  tests/golden.rs                  golden-file compatibility
  tests/golden/v1.aleph            generated once in Task 9, committed, never regenerated
```

---
### Task 1: Workspace scaffolding, errors, and crypto primitives

**Files:**
- Create: `Cargo.toml`, `LICENSE`, `NOTICE`, `README.md`, `.gitignore`
- Create: `crates/aleph-core/Cargo.toml`, `crates/aleph-core/src/lib.rs`, `crates/aleph-core/src/error.rs`, `crates/aleph-core/src/crypto.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `aleph_core::Error` (variants: `Io`, `BadMagic`, `UnsupportedVersion(u32)`, `Malformed(String)`, `NoSuchKeyslot(Uuid)`, `WrongSlotType(Uuid)`, `UnwrapFailed`, `HeaderTampered`, `BodyTampered`, `LastKeyslot`, `MissingKek(Uuid)`, `InvalidRecoveryKey(&'static str)`, `Kdf(String)`, `Random`), `aleph_core::Result<T>`.
  - `crypto::{KEY_LEN = 32, NONCE_LEN = 24, MAC_LEN = 32}`
  - `crypto::random_array<const N: usize>() -> Result<[u8; N]>`
  - `crypto::seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<([u8; 24], Vec<u8>)>`
  - `crypto::open(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>>`
  - `crypto::hkdf(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]>`
  - `crypto::hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32]`, `crypto::hmac_sha256_verify(key, data, tag: &[u8; 32]) -> bool`

- [ ] **Step 1: Create the workspace and crate manifests**

`Cargo.toml` (workspace root):

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "Apache-2.0"
rust-version = "1.98"

[workspace.dependencies]
argon2 = "0.6"
chacha20poly1305 = "0.11"
ciborium = "0.2"
getrandom = "0.4"
hkdf = "0.13"
hmac = "0.13"
libc = "0.2"
proptest = "1"
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
sha2 = "0.11"
tempfile = "3"
thiserror = "2"
uuid = { version = "1", features = ["v4", "serde"] }
zeroize = { version = "1.9", features = ["derive"] }

# Argon2 and the AEAD are unusably slow unoptimized; keep tests fast.
[profile.dev.package.argon2]
opt-level = 3
[profile.dev.package.blake2]
opt-level = 3
[profile.dev.package.chacha20poly1305]
opt-level = 3
[profile.dev.package.chacha20]
opt-level = 3
[profile.dev.package.poly1305]
opt-level = 3
```

`crates/aleph-core/Cargo.toml`:

```toml
[package]
name = "aleph-core"
description = "Vault format and cryptography for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
argon2.workspace = true
chacha20poly1305.workspace = true
ciborium.workspace = true
getrandom.workspace = true
hkdf.workspace = true
hmac.workspace = true
libc.workspace = true
secrecy.workspace = true
serde.workspace = true
serde_bytes.workspace = true
sha2.workspace = true
thiserror.workspace = true
uuid.workspace = true
zeroize.workspace = true

[dev-dependencies]
proptest.workspace = true
tempfile.workspace = true
```

`.gitignore`:

```gitignore
/target
```

`NOTICE`:

```text
aleph
Copyright 2026 K. Isom

This product is licensed under the Apache License, Version 2.0.
```

`LICENSE`: the full Apache-2.0 text. On Arch it is installed by the `licenses` package:

```bash
cp /usr/share/licenses/spdx/Apache-2.0.txt LICENSE
```

`README.md`:

```markdown
# aleph

A Secret Service (`org.freedesktop.secrets`) keyring for
[Omarchy](https://omarchy.org), with TPM and FIDO2 unlock. It replaces
gnome-keyring's secrets store; libsecret applications work unmodified.

> *Aleph*: in William Gibson's *Mona Lisa Overdrive*, a biochip holding an
> entire world, sealed away.

**Status:** early development. The design is in
[`docs/superpowers/specs/2026-09-26-aleph-design.md`](docs/superpowers/specs/2026-09-26-aleph-design.md).

## Crates

| Crate | Purpose |
|---|---|
| `aleph-core` | Vault format and cryptography (no D-Bus, no hardware) |

## Development

~~~sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
~~~

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
```

- [ ] **Step 2: Write the error type and the failing crypto tests**

`crates/aleph-core/src/error.rs`:

```rust
use uuid::Uuid;

/// Everything that can go wrong opening, unlocking, or writing a vault.
///
/// Variants deliberately do not distinguish "wrong key" from "tampered
/// ciphertext": an AEAD failure is reported the same way in both cases.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not an aleph vault (bad magic)")]
    BadMagic,

    #[error("vault format version {0} is not supported")]
    UnsupportedVersion(u32),

    #[error("malformed vault: {0}")]
    Malformed(String),

    #[error("no keyslot with id {0}")]
    NoSuchKeyslot(Uuid),

    #[error("keyslot {0} is not a password-type (Argon2id) slot")]
    WrongSlotType(Uuid),

    #[error("keyslot could not be unlocked (wrong secret or tampered slot)")]
    UnwrapFailed,

    #[error("vault header failed authentication")]
    HeaderTampered,

    #[error("vault body failed authentication")]
    BodyTampered,

    #[error("refusing to remove the last keyslot")]
    LastKeyslot,

    #[error("master key rotation needs a KEK for keyslot {0}")]
    MissingKek(Uuid),

    #[error("invalid recovery key: {0}")]
    InvalidRecoveryKey(&'static str),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("system randomness unavailable")]
    Random,
}

pub type Result<T> = std::result::Result<T, Error>;
```

`crates/aleph-core/src/lib.rs`:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;

pub use error::{Error, Result};
```

`crates/aleph-core/src/crypto.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = [1u8; KEY_LEN];
        let (nonce, ct) = seal(&key, b"aad", b"secret").unwrap();
        assert_eq!(
            open(&key, &nonce, b"aad", &ct).unwrap().as_slice(),
            b"secret"
        );
    }

    #[test]
    fn open_rejects_wrong_key_wrong_aad_and_tampering() {
        let key = [1u8; KEY_LEN];
        let (nonce, mut ct) = seal(&key, b"aad", b"secret").unwrap();
        assert!(open(&[2u8; KEY_LEN], &nonce, b"aad", &ct).is_none());
        assert!(open(&key, &nonce, b"other", &ct).is_none());
        ct[0] ^= 1;
        assert!(open(&key, &nonce, b"aad", &ct).is_none());
    }

    #[test]
    fn seal_uses_fresh_nonces() {
        let key = [1u8; KEY_LEN];
        let (n1, _) = seal(&key, b"", b"x").unwrap();
        let (n2, _) = seal(&key, b"", b"x").unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn hkdf_separates_by_info() {
        let a = hkdf(&[9u8; 32], b"aleph header v1");
        let b = hkdf(&[9u8; 32], b"aleph body v1");
        assert_ne!(*a, *b);
        assert_eq!(*a, *hkdf(&[9u8; 32], b"aleph header v1"));
    }

    #[test]
    fn hmac_verify() {
        let key = [3u8; KEY_LEN];
        let tag = hmac_sha256(&key, b"data");
        assert!(hmac_sha256_verify(&key, b"data", &tag));
        assert!(!hmac_sha256_verify(&key, b"datb", &tag));
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p aleph-core`
Expected: the build fails because `seal`, `open`, `hkdf`, `hmac_sha256`, and `random_array` do not exist yet.

- [ ] **Step 4: Implement the primitives**

Insert above the `#[cfg(test)]` line in `crates/aleph-core/src/crypto.rs`:

```rust
//! Thin wrappers over the RustCrypto primitives aleph uses. Every other
//! module goes through these so algorithm choices live in one place.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 32;

/// Fill an array from the OS CSPRNG.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::Random)?;
    Ok(out)
}

/// Encrypt `plaintext` under `key` with a fresh random nonce.
pub fn seal(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = random_array::<NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Malformed("encryption failed".into()))?;
    Ok((nonce, ct))
}

/// Decrypt and authenticate. `None` on any failure; callers map it to the
/// error that fits their context (wrong key vs. tampered body).
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

/// HKDF-SHA-256 with no salt, expanded to one 32-byte key.
pub fn hkdf(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    okm
}

pub fn hmac_sha256(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time HMAC verification.
pub fn hmac_sha256_verify(key: &[u8; KEY_LEN], data: &[u8], tag: &[u8; MAC_LEN]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}
```

- [ ] **Step 5: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `test result: ok. 5 passed`; clippy and fmt print nothing.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock LICENSE NOTICE README.md .gitignore crates/aleph-core
git commit -m "feat(core): workspace scaffolding, error type, crypto primitives" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: Key types (`Kek`, `WrappedKey`, `KeyHandle`)

**Files:**
- Create: `crates/aleph-core/src/key.rs`
- Modify: `crates/aleph-core/src/lib.rs`

**Interfaces:**
- Consumes: `crypto::*` from Task 1.
- Produces:
  - `Kek::from_bytes([u8; 32]) -> Kek`, `Kek::generate() -> Result<Kek>`; `pub(crate) Kek::expose(&self) -> &[u8; 32]` (crate-private: only aleph-core touches KEK bytes).
  - `WrappedKey { pub nonce: [u8; 24], pub ciphertext: Vec<u8> }`
  - `KeyHandle::generate() -> Result<KeyHandle>`
  - `KeyHandle::wrap(&self, kek: &Kek, aad: &[u8]) -> Result<WrappedKey>`
  - `KeyHandle::unwrap(kek: &Kek, wrapped: &WrappedKey, aad: &[u8]) -> Result<KeyHandle>` (`Err(Error::UnwrapFailed)` on any failure)
  - `KeyHandle::seal(&self, info, aad, plaintext) -> Result<([u8; 24], Vec<u8>)>`, `KeyHandle::open(&self, info, nonce, aad, ct) -> Option<Zeroizing<Vec<u8>>>`, `KeyHandle::mac(&self, info, data) -> [u8; 32]`, `KeyHandle::verify_mac(&self, info, data, tag) -> bool`. Each uses the subkey `HKDF(MK, info)`.

`KeyHandle` never exposes the master key. This is the seam the spec reserves for v2 privilege separation: a future out-of-process `KeyHandle` can offer the same methods.

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-core/src/lib.rs` with:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod key;

pub use error::{Error, Result};
pub use key::{Kek, KeyHandle, WrappedKey};
```

Create `crates/aleph-core/src/key.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip_preserves_key() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        let back = KeyHandle::unwrap(&kek, &wrapped, b"slot-aad").unwrap();
        // Same master key => same derived MAC.
        assert_eq!(mk.mac(b"x", b"data"), back.mac(b"x", b"data"));
    }

    #[test]
    fn unwrap_fails_with_wrong_kek_or_aad() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        assert!(matches!(
            KeyHandle::unwrap(&Kek::generate().unwrap(), &wrapped, b"slot-aad"),
            Err(Error::UnwrapFailed)
        ));
        assert!(matches!(
            KeyHandle::unwrap(&kek, &wrapped, b"other-aad"),
            Err(Error::UnwrapFailed)
        ));
    }

    #[test]
    fn debug_output_is_redacted() {
        assert_eq!(
            format!("{:?}", KeyHandle::generate().unwrap()),
            "KeyHandle([REDACTED])"
        );
        assert_eq!(format!("{:?}", Kek::generate().unwrap()), "Kek([REDACTED])");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core key::`
Expected: the build fails because `KeyHandle` and `Kek` do not exist yet.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` line in `key.rs`:

```rust
//! Key types. `KeyHandle` is the only holder of the vault master key and
//! is the seam for v2 privilege separation: callers ask it to wrap, seal,
//! open, and MAC, and never see the key bytes.

use secrecy::{ExposeSecret, SecretBox};

use crate::crypto::{self, KEY_LEN, MAC_LEN, NONCE_LEN};
use crate::error::{Error, Result};

/// A key-encryption key produced by an unlock method (TPM, FIDO2, Argon2).
pub struct Kek(SecretBox<[u8; KEY_LEN]>);

impl Kek {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    pub fn generate() -> Result<Self> {
        Ok(Self::from_bytes(crypto::random_array()?))
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kek([REDACTED])")
    }
}

/// The vault master key, wrapped by a KEK: what a keyslot stores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Holds the master key in page-locked memory.
pub struct KeyHandle {
    mk: SecretBox<[u8; KEY_LEN]>,
}

impl KeyHandle {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_bytes(crypto::random_array()?))
    }

    fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let mk = SecretBox::new(Box::new(bytes));
        // Best effort: keep the master key out of swap. Failure (e.g.
        // RLIMIT_MEMLOCK exhausted) is not fatal; the vault still works.
        unsafe {
            libc::mlock(mk.expose_secret().as_ptr().cast(), KEY_LEN);
        }
        Self { mk }
    }

    /// Wrap the master key for storage in a keyslot.
    pub fn wrap(&self, kek: &Kek, aad: &[u8]) -> Result<WrappedKey> {
        let (nonce, ciphertext) = crypto::seal(kek.expose(), aad, self.mk.expose_secret())?;
        Ok(WrappedKey { nonce, ciphertext })
    }

    /// Recover the master key from a keyslot.
    pub fn unwrap(kek: &Kek, wrapped: &WrappedKey, aad: &[u8]) -> Result<Self> {
        let pt = crypto::open(kek.expose(), &wrapped.nonce, aad, &wrapped.ciphertext)
            .ok_or(Error::UnwrapFailed)?;
        let bytes: [u8; KEY_LEN] = pt.as_slice().try_into().map_err(|_| Error::UnwrapFailed)?;
        Ok(Self::from_bytes(bytes))
    }

    pub fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        crypto::seal(&self.derive(info), aad, plaintext)
    }

    pub fn open(
        &self,
        info: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        crypto::open(&self.derive(info), nonce, aad, ct)
    }

    pub fn mac(&self, info: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
        crypto::hmac_sha256(&self.derive(info), data)
    }

    pub fn verify_mac(&self, info: &[u8], data: &[u8], tag: &[u8; MAC_LEN]) -> bool {
        crypto::hmac_sha256_verify(&self.derive(info), data, tag)
    }

    fn derive(&self, info: &[u8]) -> zeroize::Zeroizing<[u8; KEY_LEN]> {
        crypto::hkdf(self.mk.expose_secret(), info)
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        // SecretBox zeroizes on drop; release the page lock first.
        unsafe {
            libc::munlock(self.mk.expose_secret().as_ptr().cast(), KEY_LEN);
        }
    }
}

impl std::fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyHandle([REDACTED])")
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `test result: ok. 8 passed`.

- [ ] **Step 5: Commit**

```bash
git add crates/aleph-core/src
git commit -m "feat(core): master key handle and key wrapping" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: Argon2id KDF

**Files:**
- Create: `crates/aleph-core/src/kdf.rs`
- Modify: `crates/aleph-core/src/lib.rs`

**Interfaces:**
- Consumes: `Kek::from_bytes` (Task 2), `crypto::KEY_LEN`.
- Produces:
  - `kdf::SALT_LEN = 16`
  - `Argon2Params { pub m_kib: u32, pub t: u32, pub p: u32 }` (serde), with consts `RECOVERY_KEY` (256 MiB, 3, 4), `PASSPHRASE_FLOOR` (1 GiB, 3, 4), `LOGIN_PASSWORD_FLOOR` (64 MiB, 2, 4), `INSECURE_TEST` (32 KiB, 1, 1), `MAX` (4 GiB, 64, 16).
  - `derive_kek(secret: &[u8], salt: &[u8; 16], params: &Argon2Params) -> Result<Kek>` (`Err(Error::Kdf)` for invalid or over-limit params).
  - `tune(floor: Argon2Params, target: Duration) -> Result<Argon2Params>`: raises `t` only.

The known-answer value below was produced by this code and independently confirmed with the reference C implementation (`/usr/bin/argon2` from Arch's `argon2` package):
`printf "aleph known answer" | argon2 BBBBBBBBBBBBBBBB -id -t 3 -m 18 -p 4 -l 32 -r` → `c9fe4f6f54f7be70ac688b57e8f6aa5d496cf378fa86f60e38176f2f77bcce1f`.

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-core/src/lib.rs` with:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod kdf;
pub mod key;

pub use error::{Error, Result};
pub use kdf::{Argon2Params, derive_kek};
pub use key::{Kek, KeyHandle, WrappedKey};
```

Create `crates/aleph-core/src/kdf.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_and_salted() {
        let p = Argon2Params::INSECURE_TEST;
        let a = derive_kek(b"pw", &[1; SALT_LEN], &p).unwrap();
        let b = derive_kek(b"pw", &[1; SALT_LEN], &p).unwrap();
        let c = derive_kek(b"pw", &[2; SALT_LEN], &p).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    /// Known answer for the production recovery-key parameters. If this
    /// changes, existing recovery slots can no longer be opened. Verified
    /// against the reference C implementation:
    /// `printf "aleph known answer" | argon2 BBBBBBBBBBBBBBBB -id -t 3 -m 18 -p 4 -l 32 -r`
    #[test]
    fn recovery_key_params_known_answer() {
        let kek = derive_kek(
            b"aleph known answer",
            &[0x42; SALT_LEN],
            &Argon2Params::RECOVERY_KEY,
        )
        .unwrap();
        assert_eq!(
            hex(kek.expose()),
            "c9fe4f6f54f7be70ac688b57e8f6aa5d496cf378fa86f60e38176f2f77bcce1f"
        );
    }

    #[test]
    fn tune_never_goes_below_floor() {
        let floor = Argon2Params {
            m_kib: 64,
            t: 1,
            p: 1,
        };
        let tuned = tune(floor, Duration::from_millis(5)).unwrap();
        assert!(tuned.t >= floor.t);
        assert_eq!(tuned.m_kib, floor.m_kib);
        assert_eq!(tuned.p, floor.p);
    }

    #[test]
    fn invalid_params_are_an_error_not_a_panic() {
        let bad = Argon2Params {
            m_kib: 1,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            derive_kek(b"pw", &[0; SALT_LEN], &bad),
            Err(Error::Kdf(_))
        ));
    }

    #[test]
    fn oversized_params_are_rejected_before_allocating() {
        let huge = Argon2Params {
            m_kib: u32::MAX,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            derive_kek(b"pw", &[0; SALT_LEN], &huge),
            Err(Error::Kdf(_))
        ));
        let slow = Argon2Params {
            m_kib: 64,
            t: u32::MAX,
            p: 1,
        };
        assert!(matches!(
            derive_kek(b"pw", &[0; SALT_LEN], &slow),
            Err(Error::Kdf(_))
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core kdf::`
Expected: the build fails because `derive_kek`, `tune`, and `Argon2Params` do not exist yet.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` line in `kdf.rs`:

```rust
//! Argon2id key derivation for the password-like keyslots.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};
use crate::key::Kek;

pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters, stored in each keyslot so they can change
/// per slot and over time without a format change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Argon2Params {
    /// Recovery keys carry 256 bits of entropy; the KDF only needs to be
    /// non-trivial, not the main defence.
    pub const RECOVERY_KEY: Self = Self {
        m_kib: 256 * 1024,
        t: 3,
        p: 4,
    };
    /// Floor for user-chosen passphrases; `tune` may raise it.
    pub const PASSPHRASE_FLOOR: Self = Self {
        m_kib: 1024 * 1024,
        t: 3,
        p: 4,
    };
    /// Floor for the no-TPM login-password fallback; must not slow login.
    pub const LOGIN_PASSWORD_FLOOR: Self = Self {
        m_kib: 64 * 1024,
        t: 2,
        p: 4,
    };
    /// Only for tests: fast, and never valid in a real vault.
    pub const INSECURE_TEST: Self = Self {
        m_kib: 32,
        t: 1,
        p: 1,
    };

    /// Upper bounds accepted from a vault file. A corrupt or hostile slot
    /// must produce an error, not a multi-terabyte allocation.
    pub const MAX: Self = Self {
        m_kib: 4 * 1024 * 1024,
        t: 64,
        p: 16,
    };

    fn argon2(&self) -> Result<argon2::Argon2<'static>> {
        if self.m_kib > Self::MAX.m_kib || self.t > Self::MAX.t || self.p > Self::MAX.p {
            return Err(Error::Kdf(format!("parameters exceed limits: {self:?}")));
        }
        let params = argon2::Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map_err(|e| Error::Kdf(e.to_string()))?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// Derive a KEK from a password-like secret.
pub fn derive_kek(secret: &[u8], salt: &[u8; SALT_LEN], params: &Argon2Params) -> Result<Kek> {
    let mut out = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    params
        .argon2()?
        .hash_password_into(secret, salt, out.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(Kek::from_bytes(*out))
}

/// Raise the pass count from `floor` until one derivation takes at least
/// `target` on this machine. Memory and lanes stay at the floor.
pub fn tune(floor: Argon2Params, target: Duration) -> Result<Argon2Params> {
    let salt = [0u8; SALT_LEN];
    let mut params = floor;
    loop {
        let start = Instant::now();
        derive_kek(b"aleph tune", &salt, &params)?;
        let elapsed = start.elapsed();
        if elapsed >= target || params.t >= 64 {
            return Ok(params);
        }
        // Scale passes proportionally, always making progress.
        let scale = target.as_secs_f64() / elapsed.as_secs_f64().max(1e-6);
        params.t = ((params.t as f64 * scale).ceil() as u32).clamp(params.t + 1, 64);
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `test result: ok. 13 passed`. The known-answer test takes about 0.3 s: the workspace `Cargo.toml` builds `argon2` at `opt-level = 3` even in test profile. If it takes many seconds, check those `[profile.dev.package.*]` sections.

- [ ] **Step 5: Commit**

```bash
git add crates/aleph-core/src
git commit -m "feat(core): Argon2id KEK derivation with parameter limits" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 4: Recovery-key encoding

**Files:**
- Create: `crates/aleph-core/src/recovery.rs`
- Modify: `crates/aleph-core/src/lib.rs`

**Interfaces:**
- Consumes: `crypto::random_array`.
- Produces:
  - `RecoveryKey::generate() -> Result<RecoveryKey>`
  - `RecoveryKey::as_bytes(&self) -> &[u8; 32]` (the Argon2id input)
  - `RecoveryKey::format(&self) -> Zeroizing<String>`: 14 groups of 4, dash-separated
  - `RecoveryKey::parse(&str) -> Result<RecoveryKey>` (`Err(Error::InvalidRecoveryKey(reason))`)

**Encoding:** Crockford base32 alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. The 256 key bits are read big-endian and padded with 4 zero bits to 52 characters. Then 4 checksum characters encode the top 20 bits of `SHA-256(key)`. Parsing ignores case, `-`, and whitespace, maps `O→0` and `I/L→1`, and rejects nonzero padding bits.

The expected string in `known_encoding_of_bytes_0_to_31` was computed by an independent Python implementation of this scheme, not by this Rust code.

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-core/src/lib.rs` with:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod kdf;
pub mod key;
pub mod recovery;

pub use error::{Error, Result};
pub use kdf::{Argon2Params, derive_kek};
pub use key::{Kek, KeyHandle, WrappedKey};
pub use recovery::RecoveryKey;
```

Create `crates/aleph-core/src/recovery.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_14_groups_of_4() {
        let s = RecoveryKey::generate().unwrap().format();
        let groups: Vec<&str> = s.split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups.iter().all(|g| g.len() == 4));
    }

    /// Cross-checked against an independent Python encoder of the same
    /// scheme (big-endian bits, 4 zero pad bits, SHA-256 top 20 bits).
    #[test]
    fn known_encoding_of_bytes_0_to_31() {
        let bytes: [u8; KEY_BYTES] = std::array::from_fn(|i| i as u8);
        let k = RecoveryKey(SecretBox::new(Box::new(bytes)));
        assert_eq!(
            k.format().as_str(),
            "000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG-CC6W"
        );
    }

    #[test]
    fn parse_round_trips_format() {
        let k = RecoveryKey::generate().unwrap();
        let back = RecoveryKey::parse(&k.format()).unwrap();
        assert_eq!(k.as_bytes(), back.as_bytes());
    }

    #[test]
    fn parse_is_forgiving_about_case_separators_and_lookalikes() {
        let k = RecoveryKey(SecretBox::new(Box::new([0u8; KEY_BYTES])));
        let canonical = k.format().to_string();
        assert!(canonical.starts_with("0000-"));
        let sloppy = canonical
            .replacen('0', "o", 1)
            .replacen('0', "O", 1)
            .to_lowercase()
            .replace('-', " ");
        assert_eq!(
            RecoveryKey::parse(&sloppy).unwrap().as_bytes(),
            &[0u8; KEY_BYTES]
        );
        // I and L read as 1.
        assert_eq!(decode_char('i'), Some(1));
        assert_eq!(decode_char('L'), Some(1));
    }

    #[test]
    fn parse_rejects_typos_wrong_length_and_bad_chars() {
        let s = RecoveryKey::generate().unwrap().format().to_string();
        // Change one data character to a different valid one.
        let mut chars: Vec<char> = s.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(
            RecoveryKey::parse(&typo),
            Err(Error::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            RecoveryKey::parse(&s[..s.len() - 1]),
            Err(Error::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            RecoveryKey::parse(&s.replacen(|c: char| c.is_ascii_alphanumeric(), "U", 1)),
            Err(Error::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            RecoveryKey::parse(""),
            Err(Error::InvalidRecoveryKey(_))
        ));
    }

    #[test]
    fn nonzero_padding_bits_are_rejected() {
        let k = RecoveryKey(SecretBox::new(Box::new([0u8; KEY_BYTES])));
        let mut chars: Vec<u8> = encode(k.as_bytes());
        chars[DATA_CHARS - 1] = b'1'; // sets a padding bit
        let vals: Vec<u8> = chars
            .iter()
            .map(|&c| decode_char(c as char).unwrap())
            .collect();
        assert!(decode(&vals).is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core recovery::`
Expected: the build fails because `RecoveryKey`, `encode`, `decode`, and `decode_char` do not exist yet.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` line in `recovery.rs`:

```rust
//! Recovery keys: 256 random bits shown to the user once as Crockford
//! base32, `XXXX-XXXX-…`, 14 groups of 4 (52 data chars + 4 checksum).

use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{Error, Result};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const KEY_BYTES: usize = 32;
const DATA_CHARS: usize = 52; // ceil(256 / 5); the final 4 bits are zero padding
const CHECK_CHARS: usize = 4; // 20 bits of SHA-256
const GROUP: usize = 4;

pub struct RecoveryKey(SecretBox<[u8; KEY_BYTES]>);

impl RecoveryKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(SecretBox::new(Box::new(crypto::random_array()?))))
    }

    /// The bytes fed to Argon2id.
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        self.0.expose_secret()
    }

    /// Display form, e.g. `7K3M-…`. Show once; never log.
    pub fn format(&self) -> Zeroizing<String> {
        let mut chars = Zeroizing::new(encode(self.as_bytes()));
        chars.extend_from_slice(&checksum(self.as_bytes()));
        let mut out = Zeroizing::new(String::with_capacity(chars.len() + chars.len() / GROUP));
        for (i, c) in chars.iter().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(*c as char);
        }
        out
    }

    /// Parse user input. Case-insensitive; ignores `-` and whitespace;
    /// reads `O` as `0` and `I`/`L` as `1`.
    pub fn parse(input: &str) -> Result<Self> {
        let mut vals = Zeroizing::new(Vec::with_capacity(DATA_CHARS + CHECK_CHARS));
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            vals.push(decode_char(c).ok_or(Error::InvalidRecoveryKey(
                "contains a character that is not in the recovery alphabet",
            ))?);
        }
        if vals.len() != DATA_CHARS + CHECK_CHARS {
            return Err(Error::InvalidRecoveryKey(
                "wrong length (expected 56 characters)",
            ));
        }
        let bytes = decode(&vals[..DATA_CHARS])?;
        let expected: Vec<u8> = checksum(&bytes)
            .iter()
            .map(|&c| decode_char(c as char).expect("alphabet char"))
            .collect();
        if expected[..] != vals[DATA_CHARS..] {
            return Err(Error::InvalidRecoveryKey(
                "checksum mismatch (check for a typo)",
            ));
        }
        Ok(Self(SecretBox::new(Box::new(*bytes))))
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

fn encode(bytes: &[u8; KEY_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_CHARS + CHECK_CHARS);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize]);
        }
    }
    // 256 = 51*5 + 1: one leftover bit, padded with four zero bits.
    out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize]);
    out
}

fn decode(vals: &[u8]) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let mut out = Zeroizing::new([0u8; KEY_BYTES]);
    let (mut acc, mut bits, mut i) = (0u32, 0u32, 0usize);
    for &v in vals {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if i < KEY_BYTES {
                out[i] = (acc >> bits) as u8;
                i += 1;
            }
        }
    }
    // The 4 padding bits must be zero, otherwise two inputs would decode
    // to the same key.
    if acc & ((1 << bits) - 1) != 0 {
        return Err(Error::InvalidRecoveryKey("non-canonical encoding"));
    }
    Ok(out)
}

fn checksum(bytes: &[u8; KEY_BYTES]) -> [u8; CHECK_CHARS] {
    let digest = Sha256::digest(bytes);
    let v =
        (u32::from(digest[0]) << 12) | (u32::from(digest[1]) << 4) | (u32::from(digest[2]) >> 4);
    let mut out = [0u8; CHECK_CHARS];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ALPHABET[((v >> (5 * (CHECK_CHARS - 1 - i))) & 31) as usize];
    }
    out
}

fn decode_char(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|p| p as u8)
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `test result: ok. 19 passed`.

- [ ] **Step 5: Commit**

```bash
git add crates/aleph-core/src
git commit -m "feat(core): recovery key Crockford base32 encoding with checksum" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 5: Vault body data model

**Files:**
- Create: `crates/aleph-core/src/model.rs`
- Modify: `crates/aleph-core/src/lib.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `model::{DEFAULT_ALIAS = "default", LOGIN_COLLECTION_LABEL = "Login"}`, `model::now() -> u64`
  - `SecretBytes::new(Vec<u8>)`, `SecretBytes::expose(&self) -> &[u8]` (zeroized on drop, redacted `Debug`)
  - `Item { id: Uuid, label, attributes: BTreeMap<String,String>, secret: SecretBytes, content_type, created: u64, modified: u64 }`, `Item::new(label, attributes, secret, content_type)`, `Item::matches(&query) -> bool`
  - `Collection { id, label, created, modified, items: Vec<Item> }`, `Collection::new(label)`, `search(&query) -> impl Iterator<Item=&Item>`, `upsert(item, replace: bool) -> Uuid`, `remove(id) -> Option<Item>`
  - `Body { collections: Vec<Collection>, aliases: BTreeMap<String, Uuid> }`, `Body::default()` (one `Login` collection aliased `default`), `collection(id)`, `collection_mut(id)`, `resolve_alias(&str)`, `remove_collection(id)`

Semantics follow the Secret Service spec: search matches items having *all* query attributes (so an empty query matches everything). `upsert(replace = true)` replaces an item whose attributes are *exactly* equal, keeping its id and `created`.

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-core/src/lib.rs` with:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod kdf;
pub mod key;
pub mod model;
pub mod recovery;

pub use error::{Error, Result};
pub use kdf::{Argon2Params, derive_kek};
pub use key::{Kek, KeyHandle, WrappedKey};
pub use model::{Body, Collection, Item, SecretBytes};
pub use recovery::RecoveryKey;
```

Create `crates/aleph-core/src/model.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn item(pairs: &[(&str, &str)], secret: &[u8]) -> Item {
        Item::new(
            "label",
            attrs(pairs),
            SecretBytes::new(secret.to_vec()),
            "text/plain",
        )
    }

    #[test]
    fn default_body_has_login_collection_aliased_default() {
        let body = Body::default();
        assert_eq!(body.collections.len(), 1);
        assert_eq!(
            body.resolve_alias(DEFAULT_ALIAS).unwrap().label,
            LOGIN_COLLECTION_LABEL
        );
    }

    #[test]
    fn search_requires_all_query_attributes() {
        let mut c = Collection::new("c");
        c.upsert(
            item(&[("service", "github"), ("user", "kyle")], b"1"),
            false,
        );
        c.upsert(item(&[("service", "github"), ("user", "bot")], b"2"), false);
        assert_eq!(c.search(&attrs(&[("service", "github")])).count(), 2);
        assert_eq!(
            c.search(&attrs(&[("service", "github"), ("user", "kyle")]))
                .count(),
            1
        );
        assert_eq!(c.search(&attrs(&[("service", "gitlab")])).count(), 0);
        assert_eq!(c.search(&BTreeMap::new()).count(), 2);
    }

    #[test]
    fn upsert_replace_updates_in_place_keeping_id_and_created() {
        let mut c = Collection::new("c");
        let first = c.upsert(item(&[("k", "v")], b"old"), true);
        let created = c.items[0].created;
        let second = c.upsert(item(&[("k", "v")], b"new"), true);
        assert_eq!(first, second);
        assert_eq!(c.items.len(), 1);
        assert_eq!(c.items[0].secret.expose(), b"new");
        assert_eq!(c.items[0].created, created);
    }

    #[test]
    fn upsert_without_replace_adds_duplicate() {
        let mut c = Collection::new("c");
        c.upsert(item(&[("k", "v")], b"a"), false);
        c.upsert(item(&[("k", "v")], b"b"), false);
        assert_eq!(c.items.len(), 2);
    }

    #[test]
    fn removing_collection_drops_its_aliases() {
        let mut body = Body::default();
        let id = body.resolve_alias(DEFAULT_ALIAS).unwrap().id;
        body.remove_collection(id).unwrap();
        assert!(body.resolve_alias(DEFAULT_ALIAS).is_none());
        assert!(body.aliases.is_empty());
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", SecretBytes::new(b"hunter2".to_vec())),
            "SecretBytes([REDACTED])"
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core model::`
Expected: the build fails because `Collection`, `Item`, `Body`, and `SecretBytes` do not exist yet.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` line in `model.rs`:

```rust
//! The decrypted vault body: collections of items, as the Secret Service
//! models them.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_ALIAS: &str = "default";
pub const LOGIN_COLLECTION_LABEL: &str = "Login";

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Secret bytes: zeroized on drop, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretBytes(#[serde(with = "serde_bytes")] Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: SecretBytes,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

impl Item {
    pub fn new(
        label: impl Into<String>,
        attributes: BTreeMap<String, String>,
        secret: SecretBytes,
        content_type: impl Into<String>,
    ) -> Self {
        let t = now();
        Self {
            id: Uuid::new_v4(),
            label: label.into(),
            attributes,
            secret,
            content_type: content_type.into(),
            created: t,
            modified: t,
        }
    }

    /// True if every `(key, value)` in `query` is present on this item.
    /// An empty query matches everything, as in the Secret Service spec.
    pub fn matches(&self, query: &BTreeMap<String, String>) -> bool {
        query.iter().all(|(k, v)| self.attributes.get(k) == Some(v))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collection {
    pub id: Uuid,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    pub items: Vec<Item>,
}

impl Collection {
    pub fn new(label: impl Into<String>) -> Self {
        let t = now();
        Self {
            id: Uuid::new_v4(),
            label: label.into(),
            created: t,
            modified: t,
            items: Vec::new(),
        }
    }

    pub fn search<'a>(
        &'a self,
        query: &'a BTreeMap<String, String>,
    ) -> impl Iterator<Item = &'a Item> + 'a {
        self.items.iter().filter(move |i| i.matches(query))
    }

    /// Add `item`. With `replace`, an existing item whose attributes are
    /// exactly equal is updated in place (keeping its id and `created`),
    /// matching `CreateItem(replace=true)`. Returns the stored item's id.
    pub fn upsert(&mut self, mut item: Item, replace: bool) -> Uuid {
        self.modified = now();
        if replace
            && let Some(existing) = self
                .items
                .iter_mut()
                .find(|i| i.attributes == item.attributes)
        {
            item.id = existing.id;
            item.created = existing.created;
            item.modified = self.modified;
            *existing = item;
            return existing.id;
        }
        let id = item.id;
        self.items.push(item);
        id
    }

    pub fn remove(&mut self, id: Uuid) -> Option<Item> {
        let pos = self.items.iter().position(|i| i.id == id)?;
        self.modified = now();
        Some(self.items.remove(pos))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub collections: Vec<Collection>,
    /// Alias name → collection id (e.g. `default` → the login collection).
    pub aliases: BTreeMap<String, Uuid>,
}

impl Default for Body {
    /// A new vault: one `Login` collection, aliased as `default`.
    fn default() -> Self {
        let login = Collection::new(LOGIN_COLLECTION_LABEL);
        let aliases = BTreeMap::from([(DEFAULT_ALIAS.to_string(), login.id)]);
        Self {
            collections: vec![login],
            aliases,
        }
    }
}

impl Body {
    pub fn collection(&self, id: Uuid) -> Option<&Collection> {
        self.collections.iter().find(|c| c.id == id)
    }

    pub fn collection_mut(&mut self, id: Uuid) -> Option<&mut Collection> {
        self.collections.iter_mut().find(|c| c.id == id)
    }

    pub fn resolve_alias(&self, alias: &str) -> Option<&Collection> {
        self.aliases.get(alias).and_then(|id| self.collection(*id))
    }

    /// Remove a collection and any aliases pointing at it.
    pub fn remove_collection(&mut self, id: Uuid) -> Option<Collection> {
        let pos = self.collections.iter().position(|c| c.id == id)?;
        self.aliases.retain(|_, target| *target != id);
        Some(self.collections.remove(pos))
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `test result: ok. 25 passed`.

- [ ] **Step 5: Commit**

```bash
git add crates/aleph-core/src
git commit -m "feat(core): collections and items data model" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 6: Keyslots

**Files:**
- Create: `crates/aleph-core/src/keyslot.rs`
- Modify: `crates/aleph-core/src/lib.rs`

**Interfaces:**
- Consumes: `WrappedKey` (Task 2), `Argon2Params`, `SALT_LEN` (Task 3), `crypto::NONCE_LEN`.
- Produces:
  - `TpmAuth { None, Pin, LoginPassword }` (serialized kebab-case)
  - `TpmSlot { public: Vec<u8>, private: Vec<u8>, auth: TpmAuth, pcrs: Vec<u8>, pcr_bank: Option<String> }`: data only; Plan 2 fills it.
  - `Fido2Slot { credential_id: Vec<u8>, rp_id: String, salt: [u8; 32], uv_required: bool, pin_required: bool }`: data only; Plan 2 fills it.
  - `Argon2Slot { salt: [u8; 16], params: Argon2Params }`
  - `SlotKind { Tpm(TpmSlot), Fido2(Fido2Slot), RecoveryKey(Argon2Slot), Passphrase(Argon2Slot), LoginPassword(Argon2Slot) }`, internally tagged `slot_type`, with `type_name() -> &'static str`, `SlotKind::argon2(Argon2Kind, Argon2Slot)`, `as_argon2() -> Option<&Argon2Slot>`
  - `Argon2Kind { RecoveryKey, Passphrase, LoginPassword }`
  - `Keyslot { id: Uuid, label: String, created: u64, nonce: [u8; 24], wrapped_mk: Vec<u8>, kind: SlotKind }`, `wrapped() -> WrappedKey`, `Keyslot::aad(vault_id, slot_id, &kind) -> Vec<u8>`

Byte fields use `#[serde(with = "serde_bytes")]` so they encode as CBOR byte strings rather than arrays of integers.

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-core/src/lib.rs` with:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod kdf;
pub mod key;
pub mod keyslot;
pub mod model;
pub mod recovery;

pub use error::{Error, Result};
pub use kdf::{Argon2Params, derive_kek};
pub use key::{Kek, KeyHandle, WrappedKey};
pub use keyslot::{Argon2Kind, Argon2Slot, Fido2Slot, Keyslot, SlotKind, TpmAuth, TpmSlot};
pub use model::{Body, Collection, Item, SecretBytes};
pub use recovery::RecoveryKey;
```

Create `crates/aleph-core/src/keyslot.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_differs_by_vault_slot_and_type() {
        let (v, s) = (Uuid::new_v4(), Uuid::new_v4());
        let argon = Argon2Slot {
            salt: [0; SALT_LEN],
            params: Argon2Params::INSECURE_TEST,
        };
        let a = Keyslot::aad(v, s, &SlotKind::RecoveryKey(argon.clone()));
        assert_ne!(
            a,
            Keyslot::aad(Uuid::new_v4(), s, &SlotKind::RecoveryKey(argon.clone()))
        );
        assert_ne!(
            a,
            Keyslot::aad(v, Uuid::new_v4(), &SlotKind::RecoveryKey(argon.clone()))
        );
        assert_ne!(a, Keyslot::aad(v, s, &SlotKind::Passphrase(argon)));
    }

    #[test]
    fn slot_kind_serializes_with_slot_type_tag() {
        let kind = SlotKind::RecoveryKey(Argon2Slot {
            salt: [0; SALT_LEN],
            params: Argon2Params::INSECURE_TEST,
        });
        let mut buf = Vec::new();
        ciborium::into_writer(&kind, &mut buf).unwrap();
        let value: ciborium::Value = ciborium::from_reader(buf.as_slice()).unwrap();
        let map = value.as_map().unwrap();
        let tag = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("slot_type"))
            .unwrap();
        assert_eq!(tag.1.as_text(), Some("recovery-key"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core keyslot::`
Expected: the build fails because `Keyslot`, `SlotKind`, and `Argon2Slot` do not exist yet.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` line in `keyslot.rs`:

```rust
//! Keyslots: one wrapped copy of the master key per unlock method.
//!
//! `aleph-core` only stores slot parameters. Turning them into a `Kek`
//! (talking to the TPM, a FIDO2 key, or running Argon2id on user input)
//! is `aleph-unlock`'s job, except for the Argon2 slots, whose KEK
//! derivation lives in `kdf` so recovery works without any hardware.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::NONCE_LEN;
use crate::kdf::{Argon2Params, SALT_LEN};
use crate::key::WrappedKey;

/// How a TPM slot's sealed object is authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TpmAuth {
    None,
    Pin,
    LoginPassword,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmSlot {
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    pub auth: TpmAuth,
    /// PCR indices the seal is bound to; empty means no PCR policy.
    pub pcrs: Vec<u8>,
    /// Hash bank for `pcrs`, e.g. `"sha256"`. `None` when `pcrs` is empty.
    pub pcr_bank: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fido2Slot {
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    #[serde(with = "serde_bytes")]
    pub salt: [u8; 32],
    pub uv_required: bool,
    pub pin_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Slot {
    #[serde(with = "serde_bytes")]
    pub salt: [u8; SALT_LEN],
    pub params: Argon2Params,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "slot_type", rename_all = "kebab-case")]
pub enum SlotKind {
    Tpm(TpmSlot),
    Fido2(Fido2Slot),
    RecoveryKey(Argon2Slot),
    Passphrase(Argon2Slot),
    LoginPassword(Argon2Slot),
}

/// The three keyslot types whose KEK comes from Argon2id over a secret
/// the user types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Kind {
    RecoveryKey,
    Passphrase,
    LoginPassword,
}

impl SlotKind {
    pub fn argon2(kind: Argon2Kind, slot: Argon2Slot) -> Self {
        match kind {
            Argon2Kind::RecoveryKey => SlotKind::RecoveryKey(slot),
            Argon2Kind::Passphrase => SlotKind::Passphrase(slot),
            Argon2Kind::LoginPassword => SlotKind::LoginPassword(slot),
        }
    }

    /// The Argon2 parameters if this is a password-type slot.
    pub fn as_argon2(&self) -> Option<&Argon2Slot> {
        match self {
            SlotKind::RecoveryKey(s) | SlotKind::Passphrase(s) | SlotKind::LoginPassword(s) => {
                Some(s)
            }
            SlotKind::Tpm(_) | SlotKind::Fido2(_) => None,
        }
    }

    /// Stable name, bound into the wrapped key's AAD.
    pub fn type_name(&self) -> &'static str {
        match self {
            SlotKind::Tpm(_) => "tpm",
            SlotKind::Fido2(_) => "fido2",
            SlotKind::RecoveryKey(_) => "recovery-key",
            SlotKind::Passphrase(_) => "passphrase",
            SlotKind::LoginPassword(_) => "login-password",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyslot {
    pub id: Uuid,
    pub label: String,
    pub created: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "serde_bytes")]
    pub wrapped_mk: Vec<u8>,
    pub kind: SlotKind,
}

impl Keyslot {
    pub fn wrapped(&self) -> WrappedKey {
        WrappedKey {
            nonce: self.nonce,
            ciphertext: self.wrapped_mk.clone(),
        }
    }

    /// AAD binding a wrapped master key to this vault, this slot id, and
    /// this slot type, so it cannot be transplanted elsewhere.
    pub fn aad(vault_id: Uuid, slot_id: Uuid, kind: &SlotKind) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + 16);
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(slot_id.as_bytes());
        aad.extend_from_slice(kind.type_name().as_bytes());
        aad
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `test result: ok. 27 passed`.

- [ ] **Step 5: Commit**

```bash
git add crates/aleph-core/src
git commit -m "feat(core): keyslot types and AAD binding" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 7: Vault file format (`LockedVault`, `UnlockedVault`)

**Files:**
- Create: `crates/aleph-core/src/vault.rs`
- Create: `crates/aleph-core/tests/common/mod.rs`, `crates/aleph-core/tests/vault.rs`
- Modify: `crates/aleph-core/src/lib.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–6.
- Produces:
  - `vault::{MAGIC = b"ALEPH\0", FORMAT_VERSION = 1}`
  - `LockedVault::from_bytes(&[u8]) -> Result<LockedVault>`, `LockedVault::read(&Path)`, `vault_id() -> Uuid`, `keyslots() -> &[Keyslot]` (unauthenticated until unlock)
  - `LockedVault::unlock(&self, slot_id: Uuid, kek: &Kek) -> Result<UnlockedVault>`: Plan 2 calls this with TPM/FIDO2 KEKs
  - `LockedVault::unlock_argon2(&self, slot_id: Uuid, secret: &[u8]) -> Result<UnlockedVault>`
  - `UnlockedVault::create() -> Result<UnlockedVault>` (fresh MK, default body, no slots)
  - `vault_id()`, `keyslots()`, `body() -> &Body`, `body_mut() -> &mut Body`
  - `add_keyslot(label, kind: SlotKind, kek: &Kek) -> Result<Uuid>`, `add_argon2_keyslot(label, kind: Argon2Kind, secret: &[u8], params: Argon2Params) -> Result<Uuid>`
  - `remove_keyslot(id) -> Result<()>` (`Err(LastKeyslot)` for the last one)
  - `rotate_master(&mut self, keks: &[(Uuid, &Kek)]) -> Result<()>` (`Err(MissingKek(id))`, atomic: nothing changes on error)
  - `to_bytes(&self) -> Result<Vec<u8>>` (`Err(LastKeyslot)` with no slots)

**Format** (see the doc comment at the top of `vault.rs`): `MAGIC ‖ CBOR([format_version, header_bytes, header_mac, body_nonce, body_ct])`. `header_mac` is computed over the exact stored `header_bytes`. Unlock order is: unwrap the slot (AEAD) → verify the header MAC → decrypt the body. A wrong secret is `UnwrapFailed`, an edited header is `HeaderTampered`, and an edited body is `BodyTampered`.

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-core/src/lib.rs` with:

```rust
//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod kdf;
pub mod key;
pub mod keyslot;
pub mod model;
pub mod recovery;
pub mod vault;

pub use error::{Error, Result};
pub use kdf::{Argon2Params, derive_kek};
pub use key::{Kek, KeyHandle, WrappedKey};
pub use keyslot::{Argon2Kind, Argon2Slot, Fido2Slot, Keyslot, SlotKind, TpmAuth, TpmSlot};
pub use model::{Body, Collection, Item, SecretBytes};
pub use recovery::RecoveryKey;
pub use vault::{LockedVault, UnlockedVault};
```

Create `crates/aleph-core/src/vault.rs` as an empty placeholder so the crate compiles:

```rust
// implemented in step 3
```

Create `crates/aleph-core/tests/common/mod.rs`:

```rust
//! Shared fixtures for aleph-core integration tests.
#![allow(dead_code)] // each test binary uses a different subset

use std::collections::BTreeMap;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{Argon2Kind, Argon2Params, Item, RecoveryKey, SecretBytes, UnlockedVault};
use ciborium::Value;
use uuid::Uuid;

pub const PASSPHRASE: &[u8] = b"correct horse";

pub const FAST: Argon2Params = Argon2Params::INSECURE_TEST;

/// A vault with one recovery slot, one passphrase slot, and one item.
pub fn sample() -> (UnlockedVault, RecoveryKey, Uuid, Uuid) {
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::generate().unwrap();
    let rec = v
        .add_argon2_keyslot("recovery", Argon2Kind::RecoveryKey, rk.as_bytes(), FAST)
        .unwrap();
    let pass = v
        .add_argon2_keyslot("passphrase", Argon2Kind::Passphrase, PASSPHRASE, FAST)
        .unwrap();
    let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
    let attrs = BTreeMap::from([("service".to_string(), "github".to_string())]);
    v.body_mut().collection_mut(login).unwrap().upsert(
        Item::new(
            "GitHub token",
            attrs,
            SecretBytes::new(b"ghp_secret".to_vec()),
            "text/plain",
        ),
        false,
    );
    (v, rk, rec, pass)
}

pub fn first_secret(v: &UnlockedVault) -> Vec<u8> {
    v.body().resolve_alias(DEFAULT_ALIAS).unwrap().items[0]
        .secret
        .expose()
        .to_vec()
}

/// Decode the file's outer CBOR array (after the magic), let `f` edit it,
/// re-encode.
pub fn edit_outer(bytes: &[u8], f: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut value: Value = ciborium::from_reader(&bytes[6..]).unwrap();
    f(match &mut value {
        Value::Array(a) => a,
        _ => panic!("vault is a CBOR array"),
    });
    let mut out = bytes[..6].to_vec();
    ciborium::into_writer(&value, &mut out).unwrap();
    out
}

/// Decode the header (outer element 1, a byte string holding a CBOR map),
/// let `f` edit it, re-encode. Simulates an attacker rewriting the header.
pub fn edit_header(bytes: &[u8], f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    edit_outer(bytes, |outer| {
        let mut header: Value =
            ciborium::from_reader(outer[1].as_bytes().unwrap().as_slice()).unwrap();
        f(match &mut header {
            Value::Map(m) => m,
            _ => panic!("header is a CBOR map"),
        });
        let mut buf = Vec::new();
        ciborium::into_writer(&header, &mut buf).unwrap();
        outer[1] = Value::Bytes(buf);
    })
}

pub fn field<'a>(map: &'a mut [(Value, Value)], name: &str) -> &'a mut Value {
    &mut map
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(name))
        .unwrap()
        .1
}
```

Create `crates/aleph-core/tests/vault.rs`:

```rust
mod common;

use std::collections::BTreeMap;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{Error, Item, LockedVault, SecretBytes, UnlockedVault};
use ciborium::Value;
use common::*;
use proptest::prelude::*;
use uuid::Uuid;

#[test]
fn round_trip_through_bytes_with_either_slot() {
    let (v, rk, rec, pass) = sample();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert_eq!(locked.keyslots().len(), 2);
    assert_eq!(
        first_secret(&locked.unlock_argon2(rec, rk.as_bytes()).unwrap()),
        b"ghp_secret"
    );
    assert_eq!(
        first_secret(&locked.unlock_argon2(pass, PASSPHRASE).unwrap()),
        b"ghp_secret"
    );
}

#[test]
fn wrong_secret_is_unwrap_failed() {
    let (v, _, rec, pass) = sample();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        locked.unlock_argon2(pass, b"wrong"),
        Err(Error::UnwrapFailed)
    ));
    assert!(matches!(
        locked.unlock_argon2(rec, &[0u8; 32]),
        Err(Error::UnwrapFailed)
    ));
    assert!(matches!(
        locked.unlock_argon2(Uuid::new_v4(), b"x"),
        Err(Error::NoSuchKeyslot(_))
    ));
}

#[test]
fn bad_magic_and_future_versions_are_rejected() {
    let (v, ..) = sample();
    let bytes = v.to_bytes().unwrap();
    let mut bad = bytes.clone();
    bad[0] = b'X';
    assert!(matches!(
        LockedVault::from_bytes(&bad),
        Err(Error::BadMagic)
    ));
    let future = edit_outer(&bytes, |a| a[0] = Value::Integer(2.into()));
    assert!(matches!(
        LockedVault::from_bytes(&future),
        Err(Error::UnsupportedVersion(2))
    ));
}

#[test]
fn trailing_bytes_and_extra_elements_are_rejected() {
    let (v, ..) = sample();
    let bytes = v.to_bytes().unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        LockedVault::from_bytes(&trailing),
        Err(Error::Malformed(_))
    ));
    let extra = edit_outer(&bytes, |a| a.push(Value::Null));
    assert!(matches!(
        LockedVault::from_bytes(&extra),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn deleting_a_keyslot_from_the_file_is_detected() {
    let (v, _, _, pass) = sample();
    // Drop the recovery slot (index 0), then unlock with the passphrase.
    let edited = edit_header(&v.to_bytes().unwrap(), |m| match field(m, "keyslots") {
        Value::Array(slots) => {
            slots.remove(0);
        }
        _ => panic!("keyslots is an array"),
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    assert!(matches!(
        locked.unlock_argon2(pass, PASSPHRASE),
        Err(Error::HeaderTampered)
    ));
}

#[test]
fn wrapped_key_moved_to_another_slot_does_not_unwrap() {
    let (v, rk, rec, _) = sample();
    // Copy the recovery slot's wrapped key and nonce into slot 1 and give
    // slot 1 the recovery slot's salt/params, so the KEK is identical and
    // only the AAD (slot id + type) differs.
    let edited = edit_header(&v.to_bytes().unwrap(), |m| match field(m, "keyslots") {
        Value::Array(slots) => {
            let src = slots[0].clone();
            let dst = match &mut slots[1] {
                Value::Map(d) => d,
                _ => panic!(),
            };
            let src = match src {
                Value::Map(s) => s,
                _ => panic!(),
            };
            for name in ["nonce", "wrapped_mk", "kind"] {
                let val = src
                    .iter()
                    .find(|(k, _)| k.as_text() == Some(name))
                    .unwrap()
                    .1
                    .clone();
                *field(dst, name) = val;
            }
        }
        _ => panic!(),
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    let moved = locked.keyslots()[1].id;
    assert_ne!(moved, rec);
    assert!(matches!(
        locked.unlock_argon2(moved, rk.as_bytes()),
        Err(Error::UnwrapFailed)
    ));
}

#[test]
fn remove_keyslot_refuses_the_last_one() {
    let (mut v, _, rec, pass) = sample();
    v.remove_keyslot(pass).unwrap();
    assert!(matches!(v.remove_keyslot(rec), Err(Error::LastKeyslot)));
    assert!(matches!(
        v.remove_keyslot(Uuid::new_v4()),
        Err(Error::NoSuchKeyslot(_))
    ));
}

#[test]
fn vault_without_keyslots_cannot_be_serialized() {
    assert!(matches!(
        UnlockedVault::create().unwrap().to_bytes(),
        Err(Error::LastKeyslot)
    ));
}

#[test]
fn rotate_master_rewraps_all_slots_and_requires_every_kek() {
    let (mut v, rk, rec, pass) = sample();
    let slot_kek = |v: &UnlockedVault, id: Uuid, secret: &[u8]| {
        let a = v
            .keyslots()
            .iter()
            .find(|s| s.id == id)
            .unwrap()
            .kind
            .as_argon2()
            .unwrap()
            .clone();
        aleph_core::derive_kek(secret, &a.salt, &a.params).unwrap()
    };
    let rec_kek = slot_kek(&v, rec, rk.as_bytes());
    let pass_kek = slot_kek(&v, pass, PASSPHRASE);

    assert!(
        matches!(v.rotate_master(&[(rec, &rec_kek)]), Err(Error::MissingKek(id)) if id == pass)
    );

    let before: Vec<Vec<u8>> = v.keyslots().iter().map(|s| s.wrapped_mk.clone()).collect();
    v.rotate_master(&[(rec, &rec_kek), (pass, &pass_kek)])
        .unwrap();
    let after: Vec<Vec<u8>> = v.keyslots().iter().map(|s| s.wrapped_mk.clone()).collect();
    assert!(before.iter().zip(&after).all(|(b, a)| b != a));

    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert_eq!(
        first_secret(&locked.unlock_argon2(rec, rk.as_bytes()).unwrap()),
        b"ghp_secret"
    );
    assert_eq!(
        first_secret(&locked.unlock_argon2(pass, PASSPHRASE).unwrap()),
        b"ghp_secret"
    );
}

/// Flipping any single bit of the file must never yield a successfully
/// unlocked vault. Exhaustive over every bit, not sampled.
#[test]
fn every_single_bit_flip_is_detected() {
    let (v, _, _, pass) = sample();
    let bytes = v.to_bytes().unwrap();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut b = bytes.clone();
            b[i] ^= 1 << bit;
            let unlocked =
                LockedVault::from_bytes(&b).and_then(|l| l.unlock_argon2(pass, PASSPHRASE));
            assert!(
                unlocked.is_err(),
                "bit {bit} of byte {i} flipped undetected"
            );
        }
    }
}

proptest! {

    /// Arbitrary input must be rejected with an error, never a panic.
    #[test]
    fn arbitrary_bytes_never_panic(tail in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut bytes = b"ALEPH\0".to_vec();
        bytes.extend(tail);
        let _ = LockedVault::from_bytes(&bytes);
    }

    #[test]
    fn body_round_trips(secret in prop::collection::vec(any::<u8>(), 0..256), label in ".{0,40}") {
        let (mut v, rk, rec, _) = sample();
        let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
        v.body_mut().collection_mut(login).unwrap().upsert(
            Item::new(label.clone(), BTreeMap::new(), SecretBytes::new(secret.clone()), "application/octet-stream"),
            false,
        );
        let back = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap().unlock_argon2(rec, rk.as_bytes()).unwrap();
        prop_assert_eq!(back.body(), v.body());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core --test vault`
Expected: the build fails with unresolved imports of `aleph_core::LockedVault` and `aleph_core::UnlockedVault`.

- [ ] **Step 3: Implement**

Replace `crates/aleph-core/src/vault.rs` with:

```rust
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

use std::fs;
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
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: unit tests `27 passed`; `tests/vault.rs` `12 passed`. `every_single_bit_flip_is_detected` tries all ~8,000 single-bit flips and takes under a second.

- [ ] **Step 5: Confirm the tamper tests have teeth**

Temporarily change `if !key.verify_mac(` to `if false && !key.verify_mac(` in `LockedVault::unlock`, then run `cargo test -p aleph-core --test vault`.
Expected: `deleting_a_keyslot_from_the_file_is_detected` and `every_single_bit_flip_is_detected` FAIL. Revert the change (`git diff crates/aleph-core/src/vault.rs` must show only the new file) and re-run to confirm green.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-core/src crates/aleph-core/tests
git commit -m "feat(core): authenticated vault file format" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 8: Atomic vault writes

**Files:**
- Modify: `crates/aleph-core/src/vault.rs` (imports, new `write` method, new private helpers)
- Create: `crates/aleph-core/tests/write.rs`

**Interfaces:**
- Consumes: `UnlockedVault::to_bytes` (Task 7).
- Produces: `UnlockedVault::write(&self, path: &Path) -> Result<()>`. It creates the parent directory as `0700` if missing, writes the file as `0600`, and copies the previous file to `<path>.bak` (also `0600`) first. The new file goes to `<path>.tmp`, is `fsync`ed, renamed over `path`, and then the directory is `fsync`ed.

- [ ] **Step 1: Write the failing tests**

Create `crates/aleph-core/tests/write.rs`:

```rust
mod common;

use std::os::unix::fs::PermissionsExt;

use aleph_core::LockedVault;
use common::*;

#[test]
fn write_is_atomic_private_and_keeps_a_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aleph").join("vault.aleph");
    let (mut v, rk, rec, _) = sample();

    v.write(&path).unwrap();
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!path.with_file_name("vault.aleph.bak").exists());

    let first = std::fs::read(&path).unwrap();
    v.body_mut().collections[0].label = "Renamed".into();
    v.write(&path).unwrap();

    let bak = path.with_file_name("vault.aleph.bak");
    assert_eq!(std::fs::read(&bak).unwrap(), first);
    assert_eq!(
        std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!path.with_file_name("vault.aleph.tmp").exists());

    let reopened = LockedVault::read(&path)
        .unwrap()
        .unlock_argon2(rec, rk.as_bytes())
        .unwrap();
    assert_eq!(reopened.body().collections[0].label, "Renamed");
}

#[test]
fn stale_temp_file_from_a_crashed_write_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    std::fs::write(dir.path().join("vault.aleph.tmp"), b"half-written garbage").unwrap();
    let (v, _, _, pass) = sample();
    v.write(&path).unwrap();
    assert!(!dir.path().join("vault.aleph.tmp").exists());
    LockedVault::read(&path)
        .unwrap()
        .unlock_argon2(pass, PASSPHRASE)
        .unwrap();
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-core --test write`
Expected: the build fails because `UnlockedVault` has no `write` method yet.

- [ ] **Step 3: Implement**

In `crates/aleph-core/src/vault.rs`, replace the line `use std::fs;` with:

```rust
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
```

Add this method at the end of `impl UnlockedVault` (after `to_bytes`):

```rust
    /// Atomically replace the vault at `path`, keeping the previous
    /// version as `<path>.bak`. Creates the parent directory (0700).
    pub fn write(&self, path: &Path) -> Result<()> {
        write_atomic(path, &self.to_bytes()?)
    }
```

Append these private helpers at the end of the file:

```rust
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
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `tests/write.rs` `2 passed`; all earlier tests still pass.

- [ ] **Step 5: Commit**

```bash
git add crates/aleph-core/src/vault.rs crates/aleph-core/tests/write.rs
git commit -m "feat(core): atomic vault writes with backup" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 9: Golden file, spec update, final verification

**Files:**
- Create: `crates/aleph-core/tests/golden.rs`
- Create (generated): `crates/aleph-core/tests/golden/v1.aleph`
- Modify: `docs/superpowers/specs/2026-09-26-aleph-design.md` (§4 Header/Body, §5 Recovery secret, §4 keyslot table)

**Interfaces:**
- Consumes: the whole public API.
- Produces: the committed golden file that every future release must open.

The golden vault uses the recovery key `000G-40R4-…-CC6W` (bytes `0x00..=0x1f`) and the passphrase `aleph golden v1`, both with `INSECURE_TEST` Argon2 params. Those params are stored in the slots, so the test is fast and still exercises the real code path.

- [ ] **Step 1: Write the failing test**

Create `crates/aleph-core/tests/golden.rs`:

```rust
//! Golden vault files. Every released format version gets a file here,
//! and every later release must still open it. Never regenerate an
//! existing version's file; add a new one for a new version.

use std::collections::BTreeMap;
use std::path::PathBuf;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{
    Argon2Kind, Argon2Params, Item, LockedVault, RecoveryKey, SecretBytes, UnlockedVault,
};

const RECOVERY_KEY: &str = "000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG-CC6W";
const PASSPHRASE: &[u8] = b"aleph golden v1";

fn golden_path(version: u32) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/v{version}.aleph"))
}

#[test]
fn golden_v1_opens_with_recovery_key_and_passphrase() {
    let locked = LockedVault::read(&golden_path(1)).expect("golden v1 file present");
    let slots = locked.keyslots();
    assert_eq!(slots.len(), 2);

    let rk = RecoveryKey::parse(RECOVERY_KEY).unwrap();
    for (slot, secret) in [
        (slots[0].id, rk.as_bytes().as_slice()),
        (slots[1].id, PASSPHRASE),
    ] {
        let v = locked.unlock_argon2(slot, secret).unwrap();
        let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap();
        assert_eq!(login.label, "Login");
        assert_eq!(login.items.len(), 1);
        let item = &login.items[0];
        assert_eq!(item.label, "golden item");
        assert_eq!(
            item.attributes.get("service").map(String::as_str),
            Some("example")
        );
        assert_eq!(item.secret.expose(), b"golden secret");
    }
}

/// Run once, by hand, when introducing a new format version:
/// `cargo test -p aleph-core --test golden -- --ignored regenerate`
#[test]
#[ignore]
fn regenerate_golden_v1() {
    let path = golden_path(1);
    assert!(
        !path.exists(),
        "refusing to overwrite an existing golden file"
    );
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::parse(RECOVERY_KEY).unwrap();
    v.add_argon2_keyslot(
        "recovery",
        Argon2Kind::RecoveryKey,
        rk.as_bytes(),
        Argon2Params::INSECURE_TEST,
    )
    .unwrap();
    v.add_argon2_keyslot(
        "passphrase",
        Argon2Kind::Passphrase,
        PASSPHRASE,
        Argon2Params::INSECURE_TEST,
    )
    .unwrap();
    let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
    let attrs = BTreeMap::from([("service".to_string(), "example".to_string())]);
    v.body_mut().collection_mut(login).unwrap().upsert(
        Item::new(
            "golden item",
            attrs,
            SecretBytes::new(b"golden secret".to_vec()),
            "text/plain",
        ),
        false,
    );
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, v.to_bytes().unwrap()).unwrap();
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p aleph-core --test golden`
Expected: FAIL with `golden v1 file present: Io(Os { code: 2, kind: NotFound, … })`.

- [ ] **Step 3: Generate the golden file (once, ever)**

Run: `cargo test -p aleph-core --test golden -- --ignored regenerate`
Expected: `1 passed`; `crates/aleph-core/tests/golden/v1.aleph` now exists (about 1 KB).

- [ ] **Step 4: Run the full suite**

Run: `cargo test -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: unit `27 passed`; `golden` `1 passed, 1 ignored`; `vault` `12 passed`; `write` `2 passed`. That's 42 tests, all passing.

- [ ] **Step 5: Update the spec to match what was built**

In `docs/superpowers/specs/2026-09-26-aleph-design.md`:

1. In §4, replace the **Header** table and the paragraph after it with:

   > **Layout:** `MAGIC ‖ CBOR([format_version, header_bytes, header_mac, body_nonce, body_ct])`. `header_bytes` is `CBOR(Header { vault_id, keyslots })` stored as a byte string. `header_mac = HMAC-SHA-256(HKDF(MK, "aleph header v1"), MAGIC ‖ be32(format_version) ‖ header_bytes)`, computed over the exact stored bytes and never a re-encoding, so the MAC does not depend on CBOR encoder behaviour. Decoding is strict: one CBOR item, no trailing bytes, exactly five outer elements. After unwrapping MK, the daemon verifies `header_mac` before trusting the header. This detects keyslot deletion, substitution, and format-version rollback.

2. In §4 **Body**, change the AAD line to read `AAD = vault_id ‖ be32(format_version)` and note that the body is stored as the outer array's `body_nonce` and `body_ct` elements.
3. In §4, under the keyslot table, add: "Argon2 parameters read from a vault are rejected above `m = 4 GiB`, `t = 64`, `p = 16`." In the `login-password` row, add "floor `m = 64 MiB, t = 2, p = 4`".
4. In §5 **Recovery secret**, change "52 Crockford base32 characters in groups of 4, plus a 2-character checksum" to "52 Crockford base32 characters plus a 4-character checksum (top 20 bits of SHA-256), shown as 14 groups of 4".

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-core/tests/golden.rs crates/aleph-core/tests/golden/v1.aleph docs/superpowers/specs/2026-09-26-aleph-design.md
git commit -m "test(core): golden v1 vault; update spec to built format" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
