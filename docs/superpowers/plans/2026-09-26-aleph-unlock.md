# aleph-unlock Implementation Plan (Plan 2 of 6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `aleph-unlock` crate, which turns a TPM or FIDO2 keyslot's stored parameters (plus a PIN, password, or touch) into that slot's KEK for `aleph-core`.

**Architecture:**
- **TPM:** `Tpm` wraps a `tss-esapi` `Context`. Every operation re-derives an ECC P-256 primary key (never persisted), opens an HMAC session salted with it and with AES-256-CFB parameter encryption both ways, runs the operation, and flushes every transient handle. A sealed keyed-hash object holds a random 32-byte KEK, authorized by `SHA-256(HKDF(secret))` and optionally bound to PCR values.
- **FIDO2:** all hardware access sits behind the `Authenticator` trait. `enroll` and `unlock` are tested against a software mock, and the `libfido2` backend comes from `fido2-rs`.

**Tech Stack:** Rust 1.98, `tss-esapi` 7.7 (on `tpm2-tss` 4.2), `fido2-rs` 0.6 (on `libfido2` 1.17), `hmac`/`sha2`, `aleph-core`; tests use `swtpm` 0.10.

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` (§5 Unlock methods, §9 Testing, §11 open items).

## Decisions made while prototyping

Every task below was prototyped, then replayed from this document on a fresh clone of `master`.

- **`tss-esapi` 7.7, not 8.0:** 8.0 is still `alpha.3` (August 2026). 7.7 is the current stable release and builds against Arch's `tpm2-tss` 4.2.
- **FIDO2 library: `fido2-rs` (libfido2 bindings).** This resolves spec §11's first open item. It supports `hmac-secret` with PIN and UV, and libfido2 is what `systemd-cryptenroll` uses. The pure-Rust `ctap-hid-fido2` was the alternative. `fido2-rs` is MIT-licensed (compatible with Apache-2.0) and pulls in `openssl`, which Arch's `libfido2` already depends on.
- **TPM slots without PCRs use `userWithAuth` + auth value; slots with PCRs use `PolicyPCR ∧ PolicyAuthValue`.** Both require the same HMAC proof of the auth value, so this is equivalent to spec §5's "`PolicyAuthValue`, optionally combined with `PolicyPCR`". It avoids a policy session on the common path. `adminWithPolicy` is off, so `ObjectChangeAuth` is authorized by the auth value in both cases. Dictionary-attack protection stays on (`noDA` is not set).
- **The test harness runs `swtpm` over loopback TCP, not Unix sockets.** `tss-esapi` 7.7's `swtpm:` TCTI parser only understands `host=`/`port=` and silently ignores `path=`. Each test picks a free port pair, retries if a parallel test steals it, and treats "a real TPM connection succeeds" as ready.
- **`libfido2` backend coverage:** it is compile-checked in CI. Its error mapping is unit-tested. There is an opt-in hardware test and a manual checklist (`docs/testing.md`). CI has no virtual authenticator, since one needs root for `/dev/uhid`. That matches spec §9.

## Global Constraints

- Rust stable 1.98, edition 2024. Every crate: `license = "Apache-2.0"`.
- `aleph-unlock` never sees the vault master key. It only produces a `Kek` and the slot parameters (`TpmSlot`, `Fido2Slot`) defined in `aleph-core`.
- **TPM:**
  - The primary key is ECC P-256 with AES-256-CFB under the owner hierarchy, re-created per operation, never `EvictControl`-persisted.
  - All sessions are salted with the primary key, with `decrypt` and `encrypt` attributes, AES-256-CFB, and SHA-256.
- **Exact strings:**
  - TPM auth value: `SHA-256(HKDF-SHA-256(secret, "aleph tpm auth v1"))`, empty for `TpmAuth::None`.
  - FIDO2: KEK `HKDF-SHA-256(hmac-secret, "aleph fido2 v1")`, RP ID `"aleph"`.
- Only PCRs 0–23 of the `sha256` bank are accepted. Anything else is `TpmSlotMalformed`, never a panic.
- Every transient TPM handle and session is flushed on success and on error.
- Secrets pass through `Zeroizing` or the `Kek` buffer, never plain stack arrays that outlive a function.
- `cargo fmt` with default settings; `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit message ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **A user who keeps mistyping their PIN or password** must be told the TPM is locked out (`TpmLockout`), not just see "wrong password" forever. → Task 1 `repeated_wrong_secrets_trip_dictionary_attack_lockout`.
2. **After a firmware or boot change,** a PCR-bound slot must fail with a distinct `TpmPolicyMismatch`, so the prompter can offer the recovery secret and re-seal. A wrong password on a PCR slot must still read as `TpmAuthFailed`. → Task 1 `pcr_bound_slot_unseals_until_the_pcr_changes`.
3. **No TPM, or a user not in `tss`,** must give `TpmUnavailable` with a hint, not an opaque TSS error. → Task 1 `an_unreachable_tpm_is_reported_as_unavailable`.
4. **A long-running daemon** doing many unlocks, including failed ones, must not exhaust the TPM's few transient slots. → Task 1 `many_successful_operations_do_not_exhaust_tpm_handles`, `many_failed_unseals_do_not_exhaust_tpm_handles`.
5. **FIDO2 edge cases:**
   - an unplugged key
   - a key with a PIN
   - a PIN offered to a slot enrolled without one (which would silently switch the key to its UV secret)
   - a UV mismatch

   Each must give a specific error or be handled correctly. → Task 2 `missing_key_is_no_device`, `pin_protected_key_requires_the_pin_at_enroll_and_unlock`, `a_pin_offered_to_a_no_pin_slot_is_ignored`, `uv_setting_is_part_of_the_slot`.

## File Structure

```
Cargo.toml                                workspace: add member aleph-unlock, deps tss-esapi (T1), fido2-rs (T3)
crates/aleph-unlock/
  Cargo.toml
  src/lib.rs                              module list + re-exports (Error, Result, Tpm)
  src/error.rs                            Error enum for TPM and FIDO2 failures
  src/tpm.rs                              Tpm: open, seal, unseal, change_auth; primary/session/policy helpers
  src/fido2/mod.rs                        Authenticator trait, enroll, unlock, RP_ID
  src/fido2/mock.rs                       MockAuthenticator (software; used by later plans' tests too)
  src/fido2/libfido2.rs                   Libfido2Authenticator + libfido2 error-code mapping
  tests/common/mod.rs                     SwTpm fixture (private swtpm per test)
  tests/tpm.rs                            TPM behaviour against swtpm
  tests/tpm_hardware.rs                   opt-in real-TPM test (#[ignore])
  tests/fido2.rs                          FIDO2 behaviour against the mock
  tests/fido2_hardware.rs                 opt-in real-key test (#[ignore])
docs/testing.md                           automated requirements + manual hardware checklist
README.md                                 crate table, test prerequisites
```

**Prerequisites** (once per machine): `sudo pacman -S --needed swtpm tpm2-tools libfido2`. `tpm2-tss` is already a base dependency. `tpm2-tools` is only for poking at the TPM by hand while debugging.

---
### Task 1: TPM sealing (`Tpm`) with a `swtpm` test harness

**Files:**
- Modify: `Cargo.toml` (workspace member + `tss-esapi` dependency)
- Create: `crates/aleph-unlock/Cargo.toml`, `crates/aleph-unlock/src/lib.rs`, `crates/aleph-unlock/src/error.rs`, `crates/aleph-unlock/src/tpm.rs`
- Create: `crates/aleph-unlock/tests/common/mod.rs`, `crates/aleph-unlock/tests/tpm.rs`, `crates/aleph-unlock/tests/tpm_hardware.rs`

**Interfaces:**
- Consumes (from `aleph-core`):
  - `Kek::try_init(fill: impl FnOnce(&mut [u8; 32]) -> aleph_core::Result<()>) -> aleph_core::Result<Kek>`
  - `aleph_core::crypto::hkdf(ikm, info) -> Zeroizing<[u8; 32]>`
  - `TpmSlot { public, private, auth, pcrs, pcr_bank }`, `TpmAuth { None, Pin, LoginPassword }`
  - for the end-to-end test: `UnlockedVault::add_keyslot`, `LockedVault::unlock(slot_id, &Kek)`
- Produces:
  - `aleph_unlock::{Error, Result, Tpm}`, `aleph_unlock::tpm::DEFAULT_TCTI = "device:/dev/tpmrm0"`
  - `Tpm::open(tcti: &str) -> Result<Tpm>` (`Err(TpmUnavailable)` if unreachable)
  - `Tpm::open_default() -> Result<Tpm>` (reads `ALEPH_TCTI`, then `TPM2TOOLS_TCTI`, then the default)
  - `Tpm::seal(&mut self, auth: TpmAuth, secret: Option<&[u8]>, pcrs: &[u8]) -> Result<(Kek, TpmSlot)>`
  - `Tpm::unseal(&mut self, slot: &TpmSlot, secret: Option<&[u8]>) -> Result<Kek>`
  - `Tpm::change_auth(&mut self, slot: &TpmSlot, old: Option<&[u8]>, new: Option<&[u8]>) -> Result<TpmSlot>`
  - `Error` variants: `Core`, `TpmUnavailable(String)`, `TpmAuthFailed`, `TpmLockout`, `TpmPolicyMismatch`, `TpmSlotMalformed(String)`, `SecretRequired`, `Tpm(String)`, plus the FIDO2 variants Task 2 uses: `Fido2NoDevice`, `Fido2Unsupported`, `Fido2PinRequired`, `Fido2PinInvalid`, `Fido2PinBlocked`, `Fido2NoCredential`, `Fido2Timeout`, `Fido2(String)`
  - test fixture `common::SwTpm::start()`, `.tcti()`, `.tpm()`, `.extend_pcr(index)`

**TSS response codes mapped to errors:** `AuthFail`/`BadAuth` → `TpmAuthFailed`, `Lockout` → `TpmLockout`, `PolicyFail`/`PcrChanged` → `TpmPolicyMismatch`. Everything else becomes `Tpm(String)`.

- [ ] **Step 1: Write the manifests, error type, fixture, and failing tests**

Replace the workspace `Cargo.toml` with:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-unlock"]

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
tss-esapi = "7.7"
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

Create `crates/aleph-unlock/Cargo.toml`:

```toml
[package]
name = "aleph-unlock"
description = "TPM and FIDO2 key-encryption-key providers for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
aleph-core = { path = "../aleph-core" }
getrandom.workspace = true
sha2.workspace = true
thiserror.workspace = true
tss-esapi.workspace = true
zeroize.workspace = true

[dev-dependencies]
tempfile.workspace = true
tss-esapi.workspace = true
```

Create `crates/aleph-unlock/src/lib.rs`:

```rust
//! Hardware unlock methods for aleph: each turns a keyslot's stored
//! parameters (plus a PIN, password, or touch) into the slot's KEK.
//! See `docs/superpowers/specs/2026-09-26-aleph-design.md` §5.

pub mod error;
pub mod tpm;

pub use error::{Error, Result};
pub use tpm::Tpm;
```

Create `crates/aleph-unlock/src/error.rs`:

```rust
/// Errors from producing a KEK with a hardware unlock method.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] aleph_core::Error),

    #[error("cannot open the TPM ({0}); is this user in the `tss` group?")]
    TpmUnavailable(String),

    #[error("TPM rejected the PIN or password")]
    TpmAuthFailed,

    #[error("TPM is in dictionary-attack lockout; wait and retry")]
    TpmLockout,

    #[error("TPM policy not satisfied (boot state / PCR values changed)")]
    TpmPolicyMismatch,

    #[error("TPM slot is malformed: {0}")]
    TpmSlotMalformed(String),

    #[error("this slot needs a PIN or password")]
    SecretRequired,

    #[error("TPM error: {0}")]
    Tpm(String),

    #[error("no FIDO2 security key is connected")]
    Fido2NoDevice,

    #[error("FIDO2 key does not support the hmac-secret extension")]
    Fido2Unsupported,

    #[error("FIDO2 PIN is required")]
    Fido2PinRequired,

    #[error("FIDO2 PIN was rejected")]
    Fido2PinInvalid,

    #[error("FIDO2 key is PIN-blocked; reset it or use another method")]
    Fido2PinBlocked,

    #[error("FIDO2 credential not recognised by this key")]
    Fido2NoCredential,

    #[error("FIDO2 operation timed out waiting for touch")]
    Fido2Timeout,

    #[error("FIDO2 error: {0}")]
    Fido2(String),
}

pub type Result<T> = std::result::Result<T, Error>;
```

Create `crates/aleph-unlock/src/tpm.rs` as a placeholder:

```rust
// implemented in step 3
```

Create `crates/aleph-unlock/tests/common/mod.rs`:

```rust
//! A private software TPM per test: `swtpm` on a pair of loopback TCP
//! ports with state in a temp directory, killed when the fixture drops.
//! Tests run in parallel with no shared state and never touch the host TPM.
//!
//! TCP, not Unix sockets: tss-esapi 7.7's `swtpm:` TCTI parser only
//! understands `host=`/`port=` and silently ignores `path=`.
#![allow(dead_code)] // each test binary uses a different subset

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

pub struct SwTpm {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl SwTpm {
    pub fn start() -> Self {
        // A just-freed port can be taken by a parallel test before swtpm
        // binds it; retry with fresh ports if swtpm exits early.
        for _ in 0..20 {
            if let Some(sw) = Self::try_start() {
                return sw;
            }
        }
        panic!("could not start swtpm (is it installed? Arch: pacman -S swtpm)");
    }

    fn try_start() -> Option<Self> {
        let port = free_port_pair()?;
        let dir = tempfile::tempdir().unwrap();
        let child = Command::new("swtpm")
            .arg("socket")
            .arg("--tpm2")
            .arg("--tpmstate")
            .arg(format!("dir={}", dir.path().display()))
            .arg("--server")
            .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1))
            .arg("--flags")
            .arg("not-need-init,startup-clear")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("swtpm not found: install it (Arch: pacman -S swtpm)");
        let mut sw = Self {
            child,
            port,
            _dir: dir,
        };
        // Ready means a real TPM connection succeeds.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if aleph_unlock::Tpm::open(&sw.tcti()).is_ok() {
                return Some(sw);
            }
            if sw.child.try_wait().ok().flatten().is_some() || Instant::now() > deadline {
                return None; // swtpm died (port clash) or never came up; Drop reaps it
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    pub fn tpm(&self) -> aleph_unlock::Tpm {
        aleph_unlock::Tpm::open(&self.tcti()).unwrap()
    }

    /// Simulate a boot-state change by extending a sha256 PCR.
    pub fn extend_pcr(&self, index: u8) {
        use tss_esapi::handles::PcrHandle;
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::structures::{Digest, DigestValues};
        let conf = tss_esapi::tcti_ldr::TctiNameConf::from_str(&self.tcti()).unwrap();
        let mut ctx = tss_esapi::Context::new(conf).unwrap();
        let mut values = DigestValues::new();
        values.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(vec![0xab; 32]).unwrap(),
        );
        let handle = PcrHandle::try_from(u32::from(index)).unwrap();
        ctx.execute_with_nullauth_session(|ctx| ctx.pcr_extend(handle, values))
            .unwrap();
    }
}

impl Drop for SwTpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A port P such that P and P+1 were both free a moment ago (swtpm's TCTI
/// uses P for commands and P+1 for control).
fn free_port_pair() -> Option<u16> {
    for _ in 0..50 {
        let a = TcpListener::bind("127.0.0.1:0").ok()?;
        let port = a.local_addr().ok()?.port();
        if port < u16::MAX && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return Some(port);
        }
    }
    None
}
```

Create `crates/aleph-unlock/tests/tpm.rs`:

```rust
mod common;

use aleph_core::{LockedVault, SlotKind, TpmAuth, UnlockedVault};
use aleph_unlock::Error;
use common::SwTpm;

const PW: &[u8] = b"login password";

/// Two KEKs are equal iff they wrap/unwrap the same master key.
fn same_kek(a: &aleph_core::Kek, b: &aleph_core::Kek) -> bool {
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(a, b"t").unwrap();
    aleph_core::KeyHandle::unwrap(b, &w, b"t").is_ok()
}

#[test]
fn seal_then_unseal_returns_the_same_kek() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (kek, slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[]).unwrap();
    assert_eq!(slot.auth, TpmAuth::LoginPassword);
    assert!(slot.pcrs.is_empty() && slot.pcr_bank.is_none());
    let back = tpm.unseal(&slot, Some(PW)).unwrap();
    assert!(same_kek(&kek, &back));
}

#[test]
fn slot_survives_a_new_connection() {
    // The primary key is re-derived, not persisted: a fresh Context (as
    // after a reboot or daemon restart) must still unseal.
    let sw = SwTpm::start();
    let (kek, slot) = sw.tpm().seal(TpmAuth::Pin, Some(b"1234"), &[]).unwrap();
    let back = sw.tpm().unseal(&slot, Some(b"1234")).unwrap();
    assert!(same_kek(&kek, &back));
}

#[test]
fn wrong_secret_is_auth_failed() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (_, slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[]).unwrap();
    assert!(matches!(
        tpm.unseal(&slot, Some(b"wrong")),
        Err(Error::TpmAuthFailed)
    ));
}

#[test]
fn missing_secret_is_secret_required() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    assert!(matches!(
        tpm.seal(TpmAuth::Pin, None, &[]),
        Err(Error::SecretRequired)
    ));
    let (_, slot) = tpm.seal(TpmAuth::Pin, Some(b"1234"), &[]).unwrap();
    assert!(matches!(
        tpm.unseal(&slot, None),
        Err(Error::SecretRequired)
    ));
}

#[test]
fn auth_none_unseals_without_a_secret() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (kek, slot) = tpm.seal(TpmAuth::None, None, &[]).unwrap();
    assert!(same_kek(&kek, &tpm.unseal(&slot, None).unwrap()));
}

#[test]
fn change_auth_keeps_the_kek_and_retires_the_old_secret() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (kek, slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[]).unwrap();
    let new_slot = tpm
        .change_auth(&slot, Some(PW), Some(b"new password"))
        .unwrap();
    assert_eq!(new_slot.public, slot.public);
    assert_ne!(new_slot.private, slot.private);
    assert!(same_kek(
        &kek,
        &tpm.unseal(&new_slot, Some(b"new password")).unwrap()
    ));
    assert!(matches!(
        tpm.unseal(&new_slot, Some(PW)),
        Err(Error::TpmAuthFailed)
    ));
}

#[test]
fn change_auth_with_wrong_old_secret_fails() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (_, slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[]).unwrap();
    assert!(matches!(
        tpm.change_auth(&slot, Some(b"wrong"), Some(b"new")),
        Err(Error::TpmAuthFailed)
    ));
}

#[test]
fn pcr_bound_slot_unseals_until_the_pcr_changes() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (kek, slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[7]).unwrap();
    assert_eq!(slot.pcrs, vec![7]);
    assert_eq!(slot.pcr_bank.as_deref(), Some("sha256"));
    assert!(same_kek(&kek, &tpm.unseal(&slot, Some(PW)).unwrap()));
    // Wrong password with correct PCRs is still an auth failure.
    assert!(matches!(
        tpm.unseal(&slot, Some(b"wrong")),
        Err(Error::TpmAuthFailed)
    ));

    sw.extend_pcr(7);
    assert!(matches!(
        tpm.unseal(&slot, Some(PW)),
        Err(Error::TpmPolicyMismatch)
    ));
}

#[test]
fn pcr_bound_slot_supports_change_auth() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (kek, slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[7]).unwrap();
    let slot = tpm.change_auth(&slot, Some(PW), Some(b"new")).unwrap();
    assert!(same_kek(&kek, &tpm.unseal(&slot, Some(b"new")).unwrap()));
}

#[test]
fn corrupt_slot_blobs_are_errors_not_panics() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (_, slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[]).unwrap();

    let mut bad = slot.clone();
    bad.public = vec![0xff; 7];
    assert!(matches!(
        tpm.unseal(&bad, Some(PW)),
        Err(Error::TpmSlotMalformed(_))
    ));

    let mut bad = slot.clone();
    let n = bad.private.len();
    bad.private[n - 1] ^= 1; // TPM integrity check rejects it
    assert!(tpm.unseal(&bad, Some(PW)).is_err());

    let mut bad = slot.clone();
    bad.pcrs = vec![40];
    bad.pcr_bank = Some("sha256".into());
    assert!(matches!(
        tpm.unseal(&bad, Some(PW)),
        Err(Error::TpmSlotMalformed(_))
    ));
}

#[test]
fn a_slot_from_another_tpm_does_not_unseal() {
    let (sw_a, sw_b) = (SwTpm::start(), SwTpm::start());
    let (_, slot) = sw_a
        .tpm()
        .seal(TpmAuth::LoginPassword, Some(PW), &[])
        .unwrap();
    assert!(sw_b.tpm().unseal(&slot, Some(PW)).is_err());
}

/// Transient handles and sessions must be flushed: a TPM has only a few
/// slots, and without a resource manager (swtpm, or a daemon holding one
/// connection) a leak would fail within a handful of operations.
#[test]
fn many_successful_operations_do_not_exhaust_tpm_handles() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (_, mut slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[7]).unwrap();
    for _ in 0..40 {
        tpm.unseal(&slot, Some(PW)).unwrap();
        slot = tpm.change_auth(&slot, Some(PW), Some(PW)).unwrap();
        tpm.seal(TpmAuth::Pin, Some(b"1234"), &[]).unwrap();
    }
}

/// The failure paths must flush too. A PCR mismatch is used because,
/// unlike a wrong password, it does not count towards DA lockout.
#[test]
fn many_failed_unseals_do_not_exhaust_tpm_handles() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (_, slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[7]).unwrap();
    sw.extend_pcr(7);
    for _ in 0..40 {
        assert!(matches!(
            tpm.unseal(&slot, Some(PW)),
            Err(Error::TpmPolicyMismatch)
        ));
    }
    let (_, fresh) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[]).unwrap();
    tpm.unseal(&fresh, Some(PW)).unwrap();
}

#[test]
fn repeated_wrong_secrets_trip_dictionary_attack_lockout() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (_, slot) = tpm.seal(TpmAuth::Pin, Some(b"1234"), &[]).unwrap();
    let mut saw_lockout = false;
    for _ in 0..64 {
        match tpm.unseal(&slot, Some(b"0000")) {
            Err(Error::TpmAuthFailed) => {}
            Err(Error::TpmLockout) => {
                saw_lockout = true;
                break;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert!(saw_lockout, "TPM never entered lockout");
}

#[test]
fn tpm_slot_unlocks_a_vault_end_to_end() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let mut v = UnlockedVault::create().unwrap();
    let (kek, slot) = tpm.seal(TpmAuth::LoginPassword, Some(PW), &[]).unwrap();
    let id = v.add_keyslot("tpm", SlotKind::Tpm(slot), &kek).unwrap();
    let bytes = v.to_bytes().unwrap();

    let locked = LockedVault::from_bytes(&bytes).unwrap();
    let SlotKind::Tpm(stored) = &locked.keyslots()[0].kind else {
        panic!("not a TPM slot")
    };
    let kek = sw.tpm().unseal(stored, Some(PW)).unwrap();
    let unlocked = locked.unlock(id, &kek).unwrap();
    assert_eq!(unlocked.vault_id(), v.vault_id());
}

#[test]
fn out_of_range_pcr_index_is_an_error_not_a_panic() {
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    for bad in [24u8, 32, 255] {
        assert!(matches!(
            tpm.seal(TpmAuth::LoginPassword, Some(PW), &[bad]),
            Err(Error::TpmSlotMalformed(_))
        ));
    }
}

#[test]
fn an_unreachable_tpm_is_reported_as_unavailable() {
    // e.g. no TPM, or the user is not in the `tss` group.
    assert!(matches!(
        aleph_unlock::Tpm::open("device:/nonexistent/tpmrm0"),
        Err(Error::TpmUnavailable(_))
    ));
}
```

Create `crates/aleph-unlock/tests/tpm_hardware.rs`:

```rust
//! Opt-in test against the machine's real TPM (not run in CI). Only the
//! success path is exercised: wrong-secret attempts would count towards
//! the real TPM's dictionary-attack lockout.
//!
//! `cargo test -p aleph-unlock --test tpm_hardware -- --ignored`
//! (uses `ALEPH_TCTI`, else `TPM2TOOLS_TCTI`, else `device:/dev/tpmrm0`).

use aleph_core::TpmAuth;

fn same_kek(a: &aleph_core::Kek, b: &aleph_core::Kek) -> bool {
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(a, b"t").unwrap();
    aleph_core::KeyHandle::unwrap(b, &w, b"t").is_ok()
}

#[test]
#[ignore]
fn real_tpm_seal_unseal_change_auth_and_pcr7() {
    let mut tpm = aleph_unlock::Tpm::open_default().expect("open TPM (in the tss group?)");
    let (kek, slot) = tpm
        .seal(TpmAuth::LoginPassword, Some(b"aleph hw test"), &[7])
        .unwrap();
    assert!(same_kek(
        &kek,
        &tpm.unseal(&slot, Some(b"aleph hw test")).unwrap()
    ));
    let slot = tpm
        .change_auth(&slot, Some(b"aleph hw test"), Some(b"aleph hw test 2"))
        .unwrap();
    assert!(same_kek(
        &kek,
        &tpm.unseal(&slot, Some(b"aleph hw test 2")).unwrap()
    ));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-unlock --test tpm`
Expected: the build fails because `tpm::Tpm` does not exist (`unresolved import` in `lib.rs`).

- [ ] **Step 3: Implement `Tpm`**

Replace `crates/aleph-unlock/src/tpm.rs` with:

```rust
//! TPM keyslots: a random 32-byte KEK sealed under a primary key that is
//! re-derived on every use (never persisted), authorized by the user's
//! PIN/login password and optionally bound to PCR values (spec §5).
//!
//! Every command runs in an HMAC session salted with the primary key and
//! with parameter encryption both ways (AES-256-CFB), so neither the auth
//! value nor the KEK crosses the TPM bus in plaintext.

use std::str::FromStr;

use aleph_core::{Kek, TpmAuth, TpmSlot};
use sha2::{Digest as _, Sha256};
use tss_esapi::Context;
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Auth, Digest, EccPoint, KeyedHashScheme, PcrSelectionList, PcrSelectionListBuilder, PcrSlot,
    Private, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
    SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The TCTI used when neither `ALEPH_TCTI` nor `TPM2TOOLS_TCTI` is set:
/// the kernel resource manager, which the `tss` group can open.
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

const AUTH_INFO: &[u8] = b"aleph tpm auth v1";
const PCR_BANK: &str = "sha256";

/// An open connection to a TPM.
pub struct Tpm {
    ctx: Context,
}

impl Tpm {
    /// Connect using a TCTI string such as `device:/dev/tpmrm0` or
    /// `swtpm:path=/run/swtpm/sock`.
    pub fn open(tcti: &str) -> Result<Self> {
        let conf = TctiNameConf::from_str(tcti).map_err(tpm_err)?;
        Ok(Self {
            ctx: Context::new(conf).map_err(|e| Error::TpmUnavailable(e.to_string()))?,
        })
    }

    /// Connect using `ALEPH_TCTI`, then `TPM2TOOLS_TCTI`, then
    /// [`DEFAULT_TCTI`].
    pub fn open_default() -> Result<Self> {
        let tcti = std::env::var("ALEPH_TCTI")
            .or_else(|_| std::env::var("TPM2TOOLS_TCTI"))
            .unwrap_or_else(|_| DEFAULT_TCTI.to_string());
        Self::open(&tcti)
    }

    /// Generate a fresh KEK and seal it. `secret` is the PIN or login
    /// password (required unless `auth` is `TpmAuth::None`); `pcrs` are
    /// the sha256-bank PCR indices to bind to (empty for none).
    pub fn seal(
        &mut self,
        auth: TpmAuth,
        secret: Option<&[u8]>,
        pcrs: &[u8],
    ) -> Result<(Kek, TpmSlot)> {
        validate_pcrs(pcrs)?;
        let auth_value = auth_value(auth, secret)?;
        let policy = if pcrs.is_empty() {
            None
        } else {
            Some(self.trial_policy(pcrs)?)
        };
        let template = sealed_object_template(policy)?;
        let mut kek_bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(kek_bytes.as_mut()).map_err(|_| aleph_core::Error::Random)?;
        let data = SensitiveData::try_from(kek_bytes.to_vec()).map_err(tpm_err)?;
        let (public, private) = self.with_primary(|ctx, primary, session| {
            ctx.execute_with_session(Some(session), |ctx| {
                ctx.create(primary, template, Some(auth_value), Some(data), None, None)
            })
            .map(|r| (r.out_public, r.out_private))
            .map_err(map_tss)
        })?;
        let kek = Kek::try_init(|buf| {
            buf.copy_from_slice(kek_bytes.as_slice());
            Ok(())
        })?;
        Ok((
            kek,
            TpmSlot {
                public: public.marshall().map_err(tpm_err)?,
                private: private.value().to_vec(),
                auth,
                pcrs: pcrs.to_vec(),
                pcr_bank: (!pcrs.is_empty()).then(|| PCR_BANK.to_string()),
            },
        ))
    }

    /// Unseal a slot's KEK.
    pub fn unseal(&mut self, slot: &TpmSlot, secret: Option<&[u8]>) -> Result<Kek> {
        let auth_value = auth_value(slot.auth, secret)?;
        let (public, private) = decode_slot(slot)?;
        let pcrs = slot.pcrs.clone();
        let data = self.with_primary(|ctx, primary, session| {
            let object = ctx
                .execute_with_session(Some(session), |ctx| ctx.load(primary, private, public))
                .map_err(map_tss)?;
            let result = (|| {
                ctx.tr_set_auth(object.into(), auth_value)
                    .map_err(map_tss)?;
                let unseal_session = if pcrs.is_empty() {
                    session
                } else {
                    policy_session(ctx, primary, &pcrs)?
                };
                let out = ctx
                    .execute_with_session(Some(unseal_session), |ctx| ctx.unseal(object.into()))
                    .map_err(map_tss);
                if unseal_session != session {
                    flush_session(ctx, unseal_session);
                }
                out
            })();
            let _ = ctx.flush_context(object.into());
            result
        })?;
        Ok(Kek::try_init(|buf| {
            if data.value().len() != buf.len() {
                return Err(aleph_core::Error::UnwrapFailed);
            }
            buf.copy_from_slice(data.value());
            Ok(())
        })?)
    }

    /// Re-authorize a slot (e.g. after a login-password change) without
    /// changing its KEK. Returns the slot with its new private blob.
    pub fn change_auth(
        &mut self,
        slot: &TpmSlot,
        old: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> Result<TpmSlot> {
        let old_auth = auth_value(slot.auth, old)?;
        let new_auth = auth_value(slot.auth, new)?;
        let (public, private) = decode_slot(slot)?;
        let new_private = self.with_primary(|ctx, primary, session| {
            let object = ctx
                .execute_with_session(Some(session), |ctx| ctx.load(primary, private, public))
                .map_err(map_tss)?;
            let result = ctx
                .tr_set_auth(object.into(), old_auth)
                .map_err(map_tss)
                .and_then(|_| {
                    ctx.execute_with_session(Some(session), |ctx| {
                        ctx.object_change_auth(object.into(), primary.into(), new_auth)
                    })
                    .map_err(map_tss)
                });
            let _ = ctx.flush_context(object.into());
            result
        })?;
        Ok(TpmSlot {
            private: new_private.value().to_vec(),
            ..slot.clone()
        })
    }

    /// Recreate the primary key, open a salted, parameter-encrypting HMAC
    /// session bound to it, run `f`, then flush both.
    fn with_primary<T>(
        &mut self,
        f: impl FnOnce(&mut Context, KeyHandle, AuthSession) -> Result<T>,
    ) -> Result<T> {
        let primary = self
            .ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Owner,
                    primary_template()?,
                    None,
                    None,
                    None,
                    None,
                )
            })
            .map_err(map_tss)?
            .key_handle;
        let result = start_session(&mut self.ctx, primary, SessionType::Hmac).and_then(|session| {
            let out = f(&mut self.ctx, primary, session);
            flush_session(&mut self.ctx, session);
            out
        });
        let _ = self.ctx.flush_context(primary.into());
        result
    }

    /// Compute PolicyPCR(pcrs, current values) ∧ PolicyAuthValue in a
    /// trial session.
    fn trial_policy(&mut self, pcrs: &[u8]) -> Result<Digest> {
        let selection = pcr_selection(pcrs).map_err(map_tss)?;
        let pcr_digest = self.pcr_digest(selection.clone())?;
        let trial = self
            .ctx
            .execute_without_session(|ctx| {
                ctx.start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Trial,
                    SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )
            })
            .map_err(map_tss)?
            .ok_or_else(|| Error::Tpm("no trial session returned".into()))?;
        let policy = PolicySession::try_from(trial).map_err(tpm_err)?;
        let result = (|| {
            self.ctx
                .policy_pcr(policy, pcr_digest, selection)
                .map_err(map_tss)?;
            self.ctx.policy_auth_value(policy).map_err(map_tss)?;
            self.ctx.policy_get_digest(policy).map_err(map_tss)
        })();
        flush_session(&mut self.ctx, trial);
        result
    }

    /// SHA-256 over the concatenated current values of the selected PCRs,
    /// in selection order, as TPM2_PolicyPCR expects.
    fn pcr_digest(&mut self, selection: PcrSelectionList) -> Result<Digest> {
        let (_, _, values) = self
            .ctx
            .execute_without_session(|ctx| ctx.pcr_read(selection))
            .map_err(map_tss)?;
        let mut hasher = Sha256::new();
        for v in values.value() {
            hasher.update(v.value());
        }
        Digest::try_from(hasher.finalize().to_vec()).map_err(tpm_err)
    }
}

/// `SHA-256(HKDF-SHA-256(secret, "aleph tpm auth v1"))`, or the empty
/// auth for `TpmAuth::None`.
fn auth_value(auth: TpmAuth, secret: Option<&[u8]>) -> Result<Auth> {
    match (auth, secret) {
        (TpmAuth::None, _) => Ok(Auth::default()),
        (_, None) => Err(Error::SecretRequired),
        (_, Some(secret)) => {
            let okm = aleph_core::crypto::hkdf(secret, AUTH_INFO);
            let digest = Zeroizing::new(Sha256::digest(okm.as_slice()).to_vec());
            Auth::try_from(digest.to_vec()).map_err(tpm_err)
        }
    }
}

/// ECC P-256 restricted decryption key with AES-256-CFB symmetric
/// protection for its children (spec §5 "Parent key").
fn primary_template() -> tss_esapi::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_256_CFB,
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// Keyed-hash sealed data object. Without a policy it is authorized by its
/// auth value alone (`userWithAuth`); with one, only by the policy, which
/// itself includes PolicyAuthValue. Dictionary-attack protection stays on.
fn sealed_object_template(policy: Option<Digest>) -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(policy.is_none())
        .build()
        .map_err(tpm_err)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(policy.unwrap_or_default())
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .map_err(tpm_err)
}

fn start_session(ctx: &mut Context, primary: KeyHandle, kind: SessionType) -> Result<AuthSession> {
    let session = ctx
        .execute_without_session(|ctx| {
            ctx.start_auth_session(
                Some(primary),
                None,
                None,
                kind,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
        })
        .map_err(map_tss)?
        .ok_or_else(|| Error::Tpm("no session returned".into()))?;
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(session, attrs, mask)
        .map_err(map_tss)?;
    Ok(session)
}

/// A salted policy session satisfying PolicyPCR(current) ∧ PolicyAuthValue.
fn policy_session(ctx: &mut Context, primary: KeyHandle, pcrs: &[u8]) -> Result<AuthSession> {
    let session = start_session(ctx, primary, SessionType::Policy)?;
    let result = (|| {
        let policy = PolicySession::try_from(session).map_err(tpm_err)?;
        // An empty digest makes the TPM use the PCRs' current values; the
        // unseal then succeeds only if they match the sealed policy.
        ctx.execute_without_session(|ctx| {
            ctx.policy_pcr(policy, Digest::default(), pcr_selection(pcrs)?)
        })
        .map_err(map_tss)?;
        ctx.execute_without_session(|ctx| ctx.policy_auth_value(policy))
            .map_err(map_tss)
    })();
    match result {
        Ok(()) => Ok(session),
        Err(e) => {
            flush_session(ctx, session);
            Err(e)
        }
    }
}

fn flush_session(ctx: &mut Context, session: AuthSession) {
    if session != AuthSession::Password {
        let handle = tss_esapi::handles::SessionHandle::from(session);
        let _ = ctx.flush_context(ObjectHandle::from(handle));
    }
}

fn pcr_selection(pcrs: &[u8]) -> tss_esapi::Result<PcrSelectionList> {
    let slots: Vec<PcrSlot> = pcrs
        .iter()
        .map(|&i| PcrSlot::try_from(1u32 << i))
        .collect::<tss_esapi::Result<_>>()?;
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
}

/// PCRs 0-23 exist on every TPM 2.0; anything else is a caller or
/// vault-file error, never a shift overflow.
fn validate_pcrs(pcrs: &[u8]) -> Result<()> {
    if pcrs.iter().any(|&p| p > 23) {
        return Err(Error::TpmSlotMalformed(
            "PCR index out of range (0-23)".into(),
        ));
    }
    Ok(())
}

fn decode_slot(slot: &TpmSlot) -> Result<(Public, Private)> {
    validate_pcrs(&slot.pcrs)?;
    if slot.pcr_bank.as_deref().is_some_and(|b| b != PCR_BANK) {
        return Err(Error::TpmSlotMalformed("unsupported PCR bank".into()));
    }
    let public =
        Public::unmarshall(&slot.public).map_err(|e| Error::TpmSlotMalformed(e.to_string()))?;
    let private = Private::try_from(slot.private.clone())
        .map_err(|e| Error::TpmSlotMalformed(e.to_string()))?;
    Ok((public, private))
}

/// Map TSS response codes that mean something to a user to specific
/// errors; everything else is an opaque TPM error.
fn map_tss(e: tss_esapi::Error) -> Error {
    if let tss_esapi::Error::Tss2Error(rc) = e {
        match rc.kind() {
            Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth) => {
                return Error::TpmAuthFailed;
            }
            Some(Tss2ResponseCodeKind::Lockout) => return Error::TpmLockout,
            Some(Tss2ResponseCodeKind::PolicyFail | Tss2ResponseCodeKind::PcrChanged) => {
                return Error::TpmPolicyMismatch;
            }
            _ => {}
        }
    }
    tpm_err(e)
}

fn tpm_err(e: impl std::fmt::Display) -> Error {
    Error::Tpm(e.to_string())
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-unlock && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `tests/tpm.rs` `17 passed`; `tpm_hardware` `1 ignored`.
- The run takes about 2 seconds, since each test starts its own `swtpm`.
- `ERROR:tcti:...` lines on stderr come from the fixture's readiness probe and from `an_unreachable_tpm_is_reported_as_unavailable`. They are expected.

- [ ] **Step 5: Confirm the leak tests have teeth**

In `Tpm::with_primary`, temporarily replace the three lines

```rust
                let out = f(&mut self.ctx, primary, session);
                flush_session(&mut self.ctx, session);
                out
```

with `f(&mut self.ctx, primary, session)`, then run `cargo test -p aleph-unlock --test tpm`.
Expected: both `many_*_do_not_exhaust_tpm_handles` tests FAIL (along with others). Revert, then re-run to confirm `17 passed`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-unlock
git commit -m "feat(unlock): TPM sealing with salted, parameter-encrypted sessions" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: FIDO2 enroll/unlock over an `Authenticator` trait, with a mock

**Files:**
- Modify: `crates/aleph-unlock/Cargo.toml` (add `hmac`), `crates/aleph-unlock/src/lib.rs` (add `pub mod fido2;`)
- Create: `crates/aleph-unlock/src/fido2/mod.rs`, `crates/aleph-unlock/src/fido2/mock.rs`, `crates/aleph-unlock/tests/fido2.rs`

**Interfaces:**
- Consumes: `Kek::try_init`, `aleph_core::crypto::{hkdf, random_array}`, `Fido2Slot { credential_id, rp_id, salt, uv_required, pin_required }`; the `Error` FIDO2 variants from Task 1.
- Produces:
  - `fido2::RP_ID = "aleph"`
  - `trait Authenticator { fn is_present(&mut self) -> bool; fn has_pin(&mut self) -> Result<bool>; fn make_credential(&mut self, rp_id: &str, pin: Option<&str>, uv: bool) -> Result<Vec<u8>>; fn hmac_secret(&mut self, rp_id: &str, credential_id: &[u8], salt: &[u8; 32], pin: Option<&str>, uv: bool) -> Result<Zeroizing<[u8; 32]>>; }`
  - `fido2::enroll(auth: &mut dyn Authenticator, pin: Option<&str>, uv: bool) -> Result<(Kek, Fido2Slot)>`: two touches
  - `fido2::unlock(auth: &mut dyn Authenticator, slot: &Fido2Slot, pin: Option<&str>) -> Result<Kek>`: one touch
  - `fido2::mock::MockAuthenticator::{new, with_pin}`, public fields `present: bool` and `touches: usize`. Plans 3 and 5 use it in their tests.

The mock models what the logic depends on:
- whether a key is present
- PIN checks, with 8 retries before `Fido2PinBlocked`
- a separate secret per credential, scoped to its RP
- a `hmac-secret` output that differs with and without user verification (supplying a PIN counts as UV, as in CTAP2)

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-unlock/Cargo.toml` with:

```toml
[package]
name = "aleph-unlock"
description = "TPM and FIDO2 key-encryption-key providers for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
aleph-core = { path = "../aleph-core" }
getrandom.workspace = true
hmac.workspace = true
sha2.workspace = true
thiserror.workspace = true
tss-esapi.workspace = true
zeroize.workspace = true

[dev-dependencies]
tempfile.workspace = true
tss-esapi.workspace = true
```

Replace `crates/aleph-unlock/src/lib.rs` with:

```rust
//! Hardware unlock methods for aleph: each turns a keyslot's stored
//! parameters (plus a PIN, password, or touch) into the slot's KEK.
//! See `docs/superpowers/specs/2026-09-26-aleph-design.md` §5.

pub mod error;
pub mod fido2;
pub mod tpm;

pub use error::{Error, Result};
pub use tpm::Tpm;
```

Create `crates/aleph-unlock/src/fido2/mod.rs` (placeholder) and `crates/aleph-unlock/src/fido2/mock.rs` (placeholder):

```rust
// src/fido2/mod.rs
pub mod mock;
```
```rust
// src/fido2/mock.rs
// implemented in step 3
```

Create `crates/aleph-unlock/tests/fido2.rs`:

```rust
use aleph_core::{LockedVault, SlotKind, UnlockedVault};
use aleph_unlock::Error;
use aleph_unlock::fido2::mock::MockAuthenticator;
use aleph_unlock::fido2::{self, RP_ID};

fn same_kek(a: &aleph_core::Kek, b: &aleph_core::Kek) -> bool {
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(a, b"t").unwrap();
    aleph_core::KeyHandle::unwrap(b, &w, b"t").is_ok()
}

#[test]
fn enroll_then_unlock_returns_the_same_kek() {
    let mut key = MockAuthenticator::new();
    let (kek, slot) = fido2::enroll(&mut key, None, false).unwrap();
    assert_eq!(slot.rp_id, RP_ID);
    assert!(!slot.pin_required && !slot.uv_required);
    assert_eq!(key.touches, 2, "enrollment is two touches");
    let back = fido2::unlock(&mut key, &slot, None).unwrap();
    assert_eq!(key.touches, 3, "unlock is one touch");
    assert!(same_kek(&kek, &back));
}

#[test]
fn each_enrollment_gets_its_own_salt_and_kek() {
    let mut key = MockAuthenticator::new();
    let (a, slot_a) = fido2::enroll(&mut key, None, false).unwrap();
    let (b, slot_b) = fido2::enroll(&mut key, None, false).unwrap();
    assert_ne!(slot_a.salt, slot_b.salt);
    assert!(!same_kek(&a, &b));
}

#[test]
fn missing_key_is_no_device() {
    let mut key = MockAuthenticator::new();
    let (_, slot) = fido2::enroll(&mut key, None, false).unwrap();
    key.present = false;
    assert!(matches!(
        fido2::unlock(&mut key, &slot, None),
        Err(Error::Fido2NoDevice)
    ));
    assert!(matches!(
        fido2::enroll(&mut key, None, false),
        Err(Error::Fido2NoDevice)
    ));
}

#[test]
fn a_different_key_does_not_recognise_the_credential() {
    let (_, slot) = fido2::enroll(&mut MockAuthenticator::new(), None, false).unwrap();
    assert!(matches!(
        fido2::unlock(&mut MockAuthenticator::new(), &slot, None),
        Err(Error::Fido2NoCredential)
    ));
}

#[test]
fn pin_protected_key_requires_the_pin_at_enroll_and_unlock() {
    let mut key = MockAuthenticator::with_pin("123456");
    assert!(matches!(
        fido2::enroll(&mut key, None, false),
        Err(Error::Fido2PinRequired)
    ));
    let (kek, slot) = fido2::enroll(&mut key, Some("123456"), false).unwrap();
    assert!(slot.pin_required);
    assert!(matches!(
        fido2::unlock(&mut key, &slot, None),
        Err(Error::Fido2PinRequired)
    ));
    assert!(matches!(
        fido2::unlock(&mut key, &slot, Some("000000")),
        Err(Error::Fido2PinInvalid)
    ));
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut key, &slot, Some("123456")).unwrap()
    ));
}

#[test]
fn repeated_wrong_pins_block_the_key() {
    let mut key = MockAuthenticator::with_pin("123456");
    let (_, slot) = fido2::enroll(&mut key, Some("123456"), false).unwrap();
    let mut last = None;
    for _ in 0..8 {
        last = Some(fido2::unlock(&mut key, &slot, Some("000000")));
    }
    assert!(matches!(last, Some(Err(Error::Fido2PinBlocked))));
    assert!(matches!(
        fido2::unlock(&mut key, &slot, Some("123456")),
        Err(Error::Fido2PinBlocked)
    ));
}

#[test]
fn a_pin_offered_to_a_no_pin_slot_is_ignored() {
    // The prompter may send a PIN it collected for another slot; using it
    // would switch the key to its UV secret and yield the wrong KEK.
    let mut key = MockAuthenticator::new();
    let (kek, slot) = fido2::enroll(&mut key, None, false).unwrap();
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut key, &slot, Some("123456")).unwrap()
    ));
}

#[test]
fn uv_setting_is_part_of_the_slot() {
    let mut key = MockAuthenticator::new();
    let (kek, mut slot) = fido2::enroll(&mut key, None, true).unwrap();
    assert!(slot.uv_required);
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut key, &slot, None).unwrap()
    ));
    // With UV flipped the key returns its other secret: a different KEK.
    slot.uv_required = false;
    assert!(!same_kek(
        &kek,
        &fido2::unlock(&mut key, &slot, None).unwrap()
    ));
}

#[test]
fn fido2_slot_unlocks_a_vault_end_to_end() {
    let mut key = MockAuthenticator::new();
    let mut v = UnlockedVault::create().unwrap();
    let (kek, slot) = fido2::enroll(&mut key, None, false).unwrap();
    let id = v
        .add_keyslot("yubikey", SlotKind::Fido2(slot), &kek)
        .unwrap();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    let SlotKind::Fido2(stored) = &locked.keyslots()[0].kind else {
        panic!("not a FIDO2 slot")
    };
    let kek = fido2::unlock(&mut key, stored, None).unwrap();
    assert_eq!(locked.unlock(id, &kek).unwrap().vault_id(), v.vault_id());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-unlock --test fido2`
Expected: the build fails because `fido2::enroll`, `fido2::unlock`, `fido2::RP_ID` and `mock::MockAuthenticator` do not exist.

- [ ] **Step 3: Implement**

Replace `crates/aleph-unlock/src/fido2/mod.rs` with:

```rust
//! FIDO2 keyslots via the `hmac-secret` extension (spec §5).
//!
//! Enrollment creates a non-resident credential for RP ID `aleph` and a
//! random 32-byte salt; the slot's KEK is `HKDF(hmac-secret(salt))`.
//! Unlocking repeats the assertion with the same salt, PIN and UV setting
//! (the authenticator returns a different secret with and without user
//! verification, so both must match enrollment).
//!
//! All hardware access goes through [`Authenticator`], so the logic here
//! is tested against [`mock::MockAuthenticator`].

pub mod mock;

use aleph_core::{Fido2Slot, Kek};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const RP_ID: &str = "aleph";
const KEK_INFO: &[u8] = b"aleph fido2 v1";

/// The operations aleph needs from a FIDO2 security key.
pub trait Authenticator {
    /// True if a security key is connected (drives the prompter's
    /// "insert your key" screen).
    fn is_present(&mut self) -> bool;

    /// True if the connected key has a PIN set, in which case enrollment
    /// and unlock must supply it.
    fn has_pin(&mut self) -> Result<bool>;

    /// Create a non-resident credential with `hmac-secret` enabled.
    /// Requires a touch. Returns the credential ID.
    fn make_credential(&mut self, rp_id: &str, pin: Option<&str>, uv: bool) -> Result<Vec<u8>>;

    /// Evaluate `hmac-secret` for `credential_id` and `salt`. Requires a
    /// touch.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>>;
}

/// Enroll the connected key: create a credential, then evaluate it once
/// to derive the KEK (two touches, as with `systemd-cryptenroll`).
pub fn enroll(
    auth: &mut dyn Authenticator,
    pin: Option<&str>,
    uv: bool,
) -> Result<(Kek, Fido2Slot)> {
    if !auth.is_present() {
        return Err(Error::Fido2NoDevice);
    }
    if pin.is_none() && auth.has_pin()? {
        return Err(Error::Fido2PinRequired);
    }
    let credential_id = auth.make_credential(RP_ID, pin, uv)?;
    let salt = aleph_core::crypto::random_array::<32>()?;
    let secret = auth.hmac_secret(RP_ID, &credential_id, &salt, pin, uv)?;
    let slot = Fido2Slot {
        credential_id,
        rp_id: RP_ID.to_string(),
        salt,
        uv_required: uv,
        pin_required: pin.is_some(),
    };
    Ok((derive_kek(&secret)?, slot))
}

/// Recover a FIDO2 slot's KEK from the connected key.
pub fn unlock(auth: &mut dyn Authenticator, slot: &Fido2Slot, pin: Option<&str>) -> Result<Kek> {
    if !auth.is_present() {
        return Err(Error::Fido2NoDevice);
    }
    if slot.pin_required && pin.is_none() {
        return Err(Error::Fido2PinRequired);
    }
    // A PIN given for a slot enrolled without one would change the
    // hmac-secret (PIN implies UV); ignore it rather than fail.
    let pin = if slot.pin_required { pin } else { None };
    let secret = auth.hmac_secret(
        &slot.rp_id,
        &slot.credential_id,
        &slot.salt,
        pin,
        slot.uv_required,
    )?;
    derive_kek(&secret)
}

fn derive_kek(secret: &[u8; 32]) -> Result<Kek> {
    Ok(Kek::try_init(|buf| {
        buf.copy_from_slice(aleph_core::crypto::hkdf(secret, KEK_INFO).as_slice());
        Ok(())
    })?)
}
```

Replace `crates/aleph-unlock/src/fido2/mock.rs` with:

```rust
//! A software FIDO2 authenticator for tests (here, in the daemon, and in
//! the GUI). It models the behaviour aleph depends on: presence, PIN
//! checks with a retry counter, per-credential secrets, and hmac-secret
//! outputs that differ with user verification. It is not a CTAP
//! implementation and provides no security.

use std::collections::HashMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::Authenticator;
use crate::error::{Error, Result};

const PIN_RETRIES: u8 = 8;

pub struct MockAuthenticator {
    /// Whether the key is "plugged in".
    pub present: bool,
    pin: Option<String>,
    pin_retries: u8,
    /// Credential ID → (RP ID, per-credential secret).
    credentials: HashMap<Vec<u8>, (String, [u8; 32])>,
    /// Number of touches the user has performed.
    pub touches: usize,
}

impl MockAuthenticator {
    pub fn new() -> Self {
        Self {
            present: true,
            pin: None,
            pin_retries: PIN_RETRIES,
            credentials: HashMap::new(),
            touches: 0,
        }
    }

    pub fn with_pin(pin: &str) -> Self {
        Self {
            pin: Some(pin.to_string()),
            ..Self::new()
        }
    }

    fn check(&mut self, pin: Option<&str>) -> Result<()> {
        if !self.present {
            return Err(Error::Fido2NoDevice);
        }
        match (&self.pin, pin) {
            (_, _) if self.pin_retries == 0 => Err(Error::Fido2PinBlocked),
            (Some(_), None) => Err(Error::Fido2PinRequired),
            (Some(expected), Some(given)) if expected != given => {
                self.pin_retries -= 1;
                Err(if self.pin_retries == 0 {
                    Error::Fido2PinBlocked
                } else {
                    Error::Fido2PinInvalid
                })
            }
            _ => {
                self.pin_retries = PIN_RETRIES;
                self.touches += 1;
                Ok(())
            }
        }
    }
}

impl Default for MockAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator for MockAuthenticator {
    fn is_present(&mut self) -> bool {
        self.present
    }

    fn has_pin(&mut self) -> Result<bool> {
        if !self.present {
            return Err(Error::Fido2NoDevice);
        }
        Ok(self.pin.is_some())
    }

    fn make_credential(&mut self, rp_id: &str, pin: Option<&str>, _uv: bool) -> Result<Vec<u8>> {
        self.check(pin)?;
        let id = aleph_core::crypto::random_array::<32>()?.to_vec();
        let secret = aleph_core::crypto::random_array::<32>()?;
        self.credentials
            .insert(id.clone(), (rp_id.to_string(), secret));
        Ok(id)
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
        self.check(pin)?;
        let (cred_rp, secret) = self
            .credentials
            .get(credential_id)
            .ok_or(Error::Fido2NoCredential)?;
        if cred_rp != rp_id {
            return Err(Error::Fido2NoCredential);
        }
        // CTAP2: supplying a PIN performs user verification, and the
        // authenticator uses a different secret (CredRandomWithUV).
        let verified = uv || pin.is_some();
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("any key length");
        mac.update(&[u8::from(verified)]);
        mac.update(salt);
        Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-unlock && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `tests/fido2.rs` `9 passed`; `tests/tpm.rs` still `17 passed`.

- [ ] **Step 5: Commit**

```bash
git add crates/aleph-unlock
git commit -m "feat(unlock): FIDO2 hmac-secret enroll and unlock with a mock authenticator" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: `libfido2` backend, hardware tests, and docs

**Files:**
- Modify: `Cargo.toml` (add `fido2-rs`), `crates/aleph-unlock/Cargo.toml` (add `fido2-rs`), `crates/aleph-unlock/src/fido2/mod.rs` (add `pub mod libfido2;`)
- Create: `crates/aleph-unlock/src/fido2/libfido2.rs`, `crates/aleph-unlock/tests/fido2_hardware.rs`, `docs/testing.md`
- Modify: `README.md`, `docs/superpowers/specs/2026-09-26-aleph-design.md` (§11)

**Interfaces:**
- Consumes: `Authenticator` (Task 2).
- Produces: `fido2::libfido2::Libfido2Authenticator::new()`, which implements `Authenticator` on the first connected key and opens it per operation.

libfido2 error codes (from `/usr/include/fido/err.h`) map to errors as follows:

| libfido2 code | `Error` |
|---|---|
| `PIN_INVALID` 0x31 | `Fido2PinInvalid` |
| `PIN_BLOCKED` 0x32, `PIN_AUTH_BLOCKED` 0x34, `UV_BLOCKED` 0x3c | `Fido2PinBlocked` |
| `PIN_REQUIRED` 0x36 | `Fido2PinRequired` |
| `NO_CREDENTIALS` 0x2e, `INVALID_CREDENTIAL` 0x22 | `Fido2NoCredential` |
| `USER_ACTION_TIMEOUT` 0x2f, `ACTION_TIMEOUT` 0x3a | `Fido2Timeout` |
| `UNSUPPORTED_EXTENSION` 0x16, `UNSUPPORTED_OPTION` 0x2b | `Fido2Unsupported` |
| `NOTFOUND` -10 | `Fido2NoDevice` |
| anything else | `Fido2(String)` |

- [ ] **Step 1: Write the failing test**

Replace the workspace `Cargo.toml` with:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-unlock"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "Apache-2.0"
rust-version = "1.98"

[workspace.dependencies]
argon2 = "0.6"
chacha20poly1305 = "0.11"
ciborium = "0.2"
fido2-rs = "0.6"
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
tss-esapi = "7.7"
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

Replace `crates/aleph-unlock/Cargo.toml` with:

```toml
[package]
name = "aleph-unlock"
description = "TPM and FIDO2 key-encryption-key providers for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
aleph-core = { path = "../aleph-core" }
fido2-rs.workspace = true
getrandom.workspace = true
hmac.workspace = true
sha2.workspace = true
thiserror.workspace = true
tss-esapi.workspace = true
zeroize.workspace = true

[dev-dependencies]
tempfile.workspace = true
tss-esapi.workspace = true
```

Replace `crates/aleph-unlock/src/fido2/mod.rs` with the Task 2 version plus one line, `pub mod libfido2;`, above `pub mod mock;`:

```rust
//! FIDO2 keyslots via the `hmac-secret` extension (spec §5).
//!
//! Enrollment creates a non-resident credential for RP ID `aleph` and a
//! random 32-byte salt; the slot's KEK is `HKDF(hmac-secret(salt))`.
//! Unlocking repeats the assertion with the same salt, PIN and UV setting
//! (the authenticator returns a different secret with and without user
//! verification, so both must match enrollment).
//!
//! All hardware access goes through [`Authenticator`], so the logic here
//! is tested against [`mock::MockAuthenticator`].

pub mod libfido2;
pub mod mock;

use aleph_core::{Fido2Slot, Kek};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const RP_ID: &str = "aleph";
const KEK_INFO: &[u8] = b"aleph fido2 v1";

/// The operations aleph needs from a FIDO2 security key.
pub trait Authenticator {
    /// True if a security key is connected (drives the prompter's
    /// "insert your key" screen).
    fn is_present(&mut self) -> bool;

    /// True if the connected key has a PIN set, in which case enrollment
    /// and unlock must supply it.
    fn has_pin(&mut self) -> Result<bool>;

    /// Create a non-resident credential with `hmac-secret` enabled.
    /// Requires a touch. Returns the credential ID.
    fn make_credential(&mut self, rp_id: &str, pin: Option<&str>, uv: bool) -> Result<Vec<u8>>;

    /// Evaluate `hmac-secret` for `credential_id` and `salt`. Requires a
    /// touch.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>>;
}

/// Enroll the connected key: create a credential, then evaluate it once
/// to derive the KEK (two touches, as with `systemd-cryptenroll`).
pub fn enroll(
    auth: &mut dyn Authenticator,
    pin: Option<&str>,
    uv: bool,
) -> Result<(Kek, Fido2Slot)> {
    if !auth.is_present() {
        return Err(Error::Fido2NoDevice);
    }
    if pin.is_none() && auth.has_pin()? {
        return Err(Error::Fido2PinRequired);
    }
    let credential_id = auth.make_credential(RP_ID, pin, uv)?;
    let salt = aleph_core::crypto::random_array::<32>()?;
    let secret = auth.hmac_secret(RP_ID, &credential_id, &salt, pin, uv)?;
    let slot = Fido2Slot {
        credential_id,
        rp_id: RP_ID.to_string(),
        salt,
        uv_required: uv,
        pin_required: pin.is_some(),
    };
    Ok((derive_kek(&secret)?, slot))
}

/// Recover a FIDO2 slot's KEK from the connected key.
pub fn unlock(auth: &mut dyn Authenticator, slot: &Fido2Slot, pin: Option<&str>) -> Result<Kek> {
    if !auth.is_present() {
        return Err(Error::Fido2NoDevice);
    }
    if slot.pin_required && pin.is_none() {
        return Err(Error::Fido2PinRequired);
    }
    // A PIN given for a slot enrolled without one would change the
    // hmac-secret (PIN implies UV); ignore it rather than fail.
    let pin = if slot.pin_required { pin } else { None };
    let secret = auth.hmac_secret(
        &slot.rp_id,
        &slot.credential_id,
        &slot.salt,
        pin,
        slot.uv_required,
    )?;
    derive_kek(&secret)
}

fn derive_kek(secret: &[u8; 32]) -> Result<Kek> {
    Ok(Kek::try_init(|buf| {
        buf.copy_from_slice(aleph_core::crypto::hkdf(secret, KEK_INFO).as_slice());
        Ok(())
    })?)
}
```

Create `crates/aleph-unlock/src/fido2/libfido2.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libfido2_error_codes_map_to_user_meaningful_errors() {
        assert!(matches!(map_code(0x31), Error::Fido2PinInvalid));
        assert!(matches!(map_code(0x32), Error::Fido2PinBlocked));
        assert!(matches!(map_code(0x34), Error::Fido2PinBlocked));
        assert!(matches!(map_code(0x36), Error::Fido2PinRequired));
        assert!(matches!(map_code(0x2e), Error::Fido2NoCredential));
        assert!(matches!(map_code(0x2f), Error::Fido2Timeout));
        assert!(matches!(map_code(0x16), Error::Fido2Unsupported));
        assert!(matches!(map_code(-10), Error::Fido2NoDevice));
        assert!(matches!(map_code(0x7f), Error::Fido2(_)));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p aleph-unlock --lib`
Expected: the build fails because `map_code` and `Error` are not in scope in `libfido2.rs`.

- [ ] **Step 3: Implement the backend, hardware test, and docs**

Insert above the `#[cfg(test)]` line in `crates/aleph-unlock/src/fido2/libfido2.rs`:

```rust
//! [`Authenticator`] backed by Yubico's libfido2 (the library
//! `systemd-cryptenroll` uses), through the `fido2-rs` bindings.
//!
//! Not exercised in CI (no virtual authenticator without root); covered
//! by the opt-in hardware test and `docs/testing.md`.

use fido2_rs::assertion::AssertRequest;
use fido2_rs::credentials::{CoseType, Credential, Extensions, Opt};
use fido2_rs::device::{Device, DeviceList};
use fido2_rs::error::Error as FidoRsError;
use zeroize::Zeroizing;

use super::Authenticator;
use crate::error::{Error, Result};

/// The first connected FIDO2 key, opened per operation (keys come and go).
#[derive(Default)]
pub struct Libfido2Authenticator;

impl Libfido2Authenticator {
    pub fn new() -> Self {
        Self
    }

    fn open(&self) -> Result<Device> {
        let info = DeviceList::list_devices(16)
            .map_err(map_err)?
            .next()
            .ok_or(Error::Fido2NoDevice)?;
        let dev = info.open().map_err(map_err)?;
        if !dev.is_fido2() {
            return Err(Error::Fido2Unsupported);
        }
        Ok(dev)
    }
}

impl Authenticator for Libfido2Authenticator {
    fn is_present(&mut self) -> bool {
        DeviceList::list_devices(16).is_ok_and(|mut l| l.next().is_some())
    }

    fn has_pin(&mut self) -> Result<bool> {
        Ok(self.open()?.has_pin())
    }

    fn make_credential(&mut self, rp_id: &str, pin: Option<&str>, uv: bool) -> Result<Vec<u8>> {
        let dev = self.open()?;
        let mut cred = Credential::new().map_err(map_err)?;
        cred.set_client_data_hash(aleph_core::crypto::random_array::<32>()?)
            .map_err(map_err)?;
        cred.set_rp(rp_id, "aleph keyring").map_err(map_err)?;
        cred.set_user(
            aleph_core::crypto::random_array::<32>()?,
            "aleph",
            None,
            None,
        )
        .map_err(map_err)?;
        cred.set_cose_type(CoseType::ES256).map_err(map_err)?;
        cred.set_extension(Extensions::HMAC_SECRET)
            .map_err(map_err)?;
        cred.set_rk(Opt::False).map_err(map_err)?;
        if uv {
            cred.set_uv(Opt::True).map_err(map_err)?;
        }
        dev.make_credential(&mut cred, pin).map_err(map_err)?;
        Ok(cred.id().to_vec())
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let dev = self.open()?;
        let mut req = AssertRequest::new().map_err(map_err)?;
        req.set_rp(rp_id).map_err(map_err)?;
        req.set_client_data_hash(aleph_core::crypto::random_array::<32>()?)
            .map_err(map_err)?;
        req.set_allow_credential(credential_id).map_err(map_err)?;
        req.set_extensions(Extensions::HMAC_SECRET)
            .map_err(map_err)?;
        req.set_hmac_salt(salt).map_err(map_err)?;
        req.set_up(Opt::True).map_err(map_err)?;
        if uv {
            req.set_uv(Opt::True).map_err(map_err)?;
        }
        let assertions = dev.get_assertion(req, pin).map_err(map_err)?;
        let assertion = assertions.iter().next().ok_or(Error::Fido2NoCredential)?;
        let secret: [u8; 32] = assertion
            .hmac_secret()
            .try_into()
            .map_err(|_| Error::Fido2Unsupported)?;
        Ok(Zeroizing::new(secret))
    }
}

// libfido2 error codes (fido/err.h).
const FIDO_ERR_UNSUPPORTED_EXTENSION: i32 = 0x16;
const FIDO_ERR_INVALID_CREDENTIAL: i32 = 0x22;
const FIDO_ERR_UNSUPPORTED_OPTION: i32 = 0x2b;
const FIDO_ERR_NO_CREDENTIALS: i32 = 0x2e;
const FIDO_ERR_USER_ACTION_TIMEOUT: i32 = 0x2f;
const FIDO_ERR_PIN_INVALID: i32 = 0x31;
const FIDO_ERR_PIN_BLOCKED: i32 = 0x32;
const FIDO_ERR_PIN_AUTH_BLOCKED: i32 = 0x34;
const FIDO_ERR_PIN_REQUIRED: i32 = 0x36;
const FIDO_ERR_ACTION_TIMEOUT: i32 = 0x3a;
const FIDO_ERR_UV_BLOCKED: i32 = 0x3c;
const FIDO_ERR_NOTFOUND: i32 = -10;

fn map_err(e: FidoRsError) -> Error {
    match e {
        FidoRsError::Fido(f) => map_code(f.code),
        FidoRsError::Unsupported => Error::Fido2Unsupported,
        other => Error::Fido2(other.to_string()),
    }
}

fn map_code(code: i32) -> Error {
    match code {
        FIDO_ERR_PIN_INVALID => Error::Fido2PinInvalid,
        FIDO_ERR_PIN_BLOCKED | FIDO_ERR_PIN_AUTH_BLOCKED | FIDO_ERR_UV_BLOCKED => {
            Error::Fido2PinBlocked
        }
        FIDO_ERR_PIN_REQUIRED => Error::Fido2PinRequired,
        FIDO_ERR_NO_CREDENTIALS | FIDO_ERR_INVALID_CREDENTIAL => Error::Fido2NoCredential,
        FIDO_ERR_USER_ACTION_TIMEOUT | FIDO_ERR_ACTION_TIMEOUT => Error::Fido2Timeout,
        FIDO_ERR_UNSUPPORTED_EXTENSION | FIDO_ERR_UNSUPPORTED_OPTION => Error::Fido2Unsupported,
        FIDO_ERR_NOTFOUND => Error::Fido2NoDevice,
        other => Error::Fido2(format!("libfido2 error {other:#x}")),
    }
}
```

Create `crates/aleph-unlock/tests/fido2_hardware.rs`:

```rust
//! Opt-in test against a real FIDO2 security key (not run in CI).

use aleph_unlock::fido2;
use aleph_unlock::fido2::libfido2::Libfido2Authenticator;

fn same_kek(a: &aleph_core::Kek, b: &aleph_core::Kek) -> bool {
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(a, b"t").unwrap();
    aleph_core::KeyHandle::unwrap(b, &w, b"t").is_ok()
}

/// Needs a real security key and two touches. Run by hand before a
/// release (see docs/testing.md):
/// `ALEPH_FIDO2_PIN=<pin, if set> cargo test -p aleph-unlock --test fido2_hardware -- --ignored`
#[test]
#[ignore]
fn hardware_key_enroll_and_unlock() {
    let pin = std::env::var("ALEPH_FIDO2_PIN").ok();
    let mut key = Libfido2Authenticator::new();
    assert!(
        fido2::Authenticator::is_present(&mut key),
        "plug in a FIDO2 key"
    );
    eprintln!("touch the key twice to enroll, then once to unlock");
    let (kek, slot) = fido2::enroll(&mut key, pin.as_deref(), false).unwrap();
    let back = fido2::unlock(&mut key, &slot, pin.as_deref()).unwrap();
    assert!(same_kek(&kek, &back));
}
```

Create `docs/testing.md`:

~~~markdown
# Testing aleph

## Automated (CI and local)

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Requirements:

- **`swtpm`**: the TPM tests start a private software TPM per test on
  loopback TCP ports. They never touch the host TPM.
  - Arch: `pacman -S swtpm`
  - Nix: `pkgs.swtpm`
- **`tpm2-tss`** and **`libfido2`** (build-time libraries).
  - Arch: `pacman -S tpm2-tss libfido2`

FIDO2 logic is tested against `aleph_unlock::fido2::mock::MockAuthenticator`.
No test in the default run needs a security key.

## Manual, before each release

These need real hardware and a person to touch things. Record the result
(pass/fail, hardware model, firmware) in the release notes.

### FIDO2 security key

1. Plug in one FIDO2 key that supports `hmac-secret`: YubiKey 5, SoloKey,
   Nitrokey 3, or similar. Unplug any others.
2. Key **without** a PIN: run
   `cargo test -p aleph-unlock --test fido2_hardware -- --ignored`.
   Touch the key twice (enroll), then once (unlock). Expect `1 passed`.
3. Key **with** a PIN: set one using `fido2-token -S <device>`, then run
   `ALEPH_FIDO2_PIN=<pin> cargo test -p aleph-unlock --test fido2_hardware -- --ignored`.
   Expect `1 passed`.
4. Wrong PIN: rerun step 3 with a wrong `ALEPH_FIDO2_PIN`. Expect a
   failure reporting `Fido2PinInvalid`, and the key's retry counter drops
   by one (`fido2-token -I <device>`).
5. No key: unplug the key and rerun step 2. Expect a failure with
   "plug in a FIDO2 key".

### Real TPM

Only run this on a machine where you are in the `tss` group
(`id -nG | grep -w tss`). It exercises only the success path, because
wrong-secret attempts count towards the real TPM's lockout.

1. Run `cargo test -p aleph-unlock --test tpm_hardware -- --ignored`.
   Expect `1 passed`. It seals against PCR 7 with a test password, unseals,
   changes the auth, and unseals again. It writes nothing persistent to
   the TPM.
2. If it fails with `TpmUnavailable`, check the group membership and
   that `/dev/tpmrm0` exists.
~~~

In `README.md`, add a row to the Crates table and a prerequisites paragraph at the top of Development, so those sections read:

```markdown
## Crates

| Crate | Purpose |
|---|---|
| `aleph-core` | Vault format and cryptography (no D-Bus, no hardware) |
| `aleph-unlock` | TPM and FIDO2 unlock methods that produce keyslot KEKs |

## Development

Tests need `swtpm`, `tpm2-tss` and `libfido2` (Arch:
`pacman -S swtpm tpm2-tss libfido2`). Hardware tests are opt-in; see
[docs/testing.md](docs/testing.md).

~~~sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
~~~
```

In `docs/superpowers/specs/2026-09-26-aleph-design.md` §11, replace the first bullet (about FIDO2 bindings) with:

> - ~~FIDO2 bindings~~ **Resolved (Plan 2):** `fido2-rs` 0.6 (libfido2 bindings) supports `hmac-secret` with PIN/UV; chosen over `ctap-hid-fido2` to share libfido2 with `systemd-cryptenroll`.

- [ ] **Step 4: Run the whole workspace, clippy, and fmt**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected:
- `aleph-unlock` lib `1 passed`
- `fido2` `9 passed`, `tpm` `17 passed`
- `fido2_hardware` and `tpm_hardware` `1 ignored` each
- all 52 `aleph-core` tests still pass

- [ ] **Step 5 (only if a FIDO2 key is available): run the hardware checklist**

Follow `docs/testing.md` → "FIDO2 security key", steps 1–2. Expect `1 passed` after three touches. If no key is available, write "hardware checklist not run: no key" in the commit body.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-unlock docs/testing.md README.md docs/superpowers/specs/2026-09-26-aleph-design.md
git commit -m "feat(unlock): libfido2 authenticator backend and hardware test docs" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
