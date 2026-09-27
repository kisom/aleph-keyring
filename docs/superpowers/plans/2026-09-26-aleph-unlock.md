# aleph-tpmd and aleph-unlock Implementation Plan (Plan 2, rewritten)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the TPM helper service `aleph-tpmd` (with its wire protocol `aleph-tpm-proto`) and the `aleph-unlock` crate. `aleph-unlock` turns a TPM or FIDO2 keyslot into its KEK: TPM through the helper, FIDO2 through libfido2.

**Architecture:**
- **`aleph-tpmd`** is the only process that talks to the TPM. It is a socket-activated system service running as a throwaway user in the `tss` group; users are never added to `tss`. It reads the caller's uid from the socket.
  - It seals `be32(uid) ‖ KEK` under an auth value derived from the password, a per-slot salt, and the uid.
  - It verifies the parent key's Name before using it to salt a session.
  - It rate-limits failed unseals per uid and reports TPM state.
- **`aleph-unlock`**'s TPM client only speaks the protocol.
- **FIDO2** runs behind `Keys`/`Authenticator` traits: a software mock for tests and a libfido2 backend. It requires PIN/UV by default, checks `hmac-secret` support, needs exactly one key to enroll, and preflights every connected key without a touch to find the right one at unlock.

**Tech Stack:** Rust 1.98, `tss-esapi` 7.7 (on `tpm2-tss` 4.2), `fido2-rs` 0.6 (on `libfido2` 1.17), `hkdf`/`sha2`/`hmac`, `libc` (`SO_PEERCRED`), `aleph-core`. Tests need `swtpm` 0.10 and `tpm2-tools` 5.8.

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` revision 2 (§3 crates, §5 "TPM, via aleph-tpmd" and "FIDO2", §9 TPM/FIDO2 tests). This plan replaces the pre-review Plan 2, whose in-process TPM design the design review superseded.

**Plan series:** 1 core (done) → 1b core revision 2 (done) → **2 aleph-tpmd + aleph-unlock (this plan)** → 3 `alephd` + CLI basics → 4 session integration → 5 `aleph-gui` → 6 packaging and CI.

**Prerequisites** (once per machine): `sudo pacman -S --needed swtpm tpm2-tools libfido2`.

## Decisions made while prototyping

Every task was prototyped, then replayed from this document on a fresh clone of `master` (`6f073ff`): red, then green, then clippy and fmt clean, with the final tree identical to the prototype. The security properties below were each checked by reverting them: the pinning test fails with the revert and passes once restored.

- **Parent key.** aleph's own ECC P-256/AES-256-CFB primary, re-created per use, whose Name is stable per TPM. When `ownerAuth` is set (TPMA_PERMANENT bit 0), the persistent TCG SRK at `0x81000001` is used instead; if it is absent, `NoParent`.
  - The Name is recorded at seal time and checked before the parent salts a session. A slot from another TPM, or from before `ownerAuth` was set, is therefore `ParentMismatch`, with no password attempt.
  - Sessions always use AES-256-CFB parameter encryption. Task 5 corrects the spec, which said AES-128 for the SRK fallback; that AES-128 applies only to how the TPM protects child blobs under the SRK.
- **Uid binding is layered.** The uid is part of the auth-value derivation, so another uid gets `AuthFailed`, and the sealed payload's stored uid is checked (`WrongUser`) as defense in depth.
- **FIDO2 credProtect is level 2, not 3.** A level-3 credential is invisible to the no-touch preflight unless user verification happens first, so choosing among several keys would burn PIN retries on the wrong ones (`systemd-cryptenroll` uses level 2 too). Security is unchanged: PIN/UV is required at every unlock of a PIN/UV slot, and the key's `hmac-secret` without UV is a different value. Task 5 corrects the spec.
- **Rate limiting:** 5 failed unseals per uid per 60 s. `Lockout` replies count as failures, so a locked-out caller cannot keep polling.
- **Status:**
  - `in_lockout` is the TPMA_PERMANENT bit **or** `failed_tries >= max_tries`, because swtpm never sets the bit.
  - `Status` is an empty struct variant (`Status {}`), because serde's internally tagged unit variants ignore unknown fields even with `deny_unknown_fields`.
- **The helper serves connections one at a time,** each with 5 s read/write timeouts. The TPM is serial anyway, and a stuck client cannot hold it.
- **Test fixture:**
  - swtpm over loopback TCP. tss-esapi 7.7's `swtpm:` TCTI ignores `path=`.
  - It lives in `aleph-tpmd` behind the `testing` feature, shared with `aleph-unlock`'s tests.
  - Port selection, spawning, and the readiness probe are serialized by a process-wide lock, and the probe runs only while our own swtpm is alive. Without this, parallel tests hung: a test's swtpm lost a port race, and its probe connected to another test's single-client swtpm and blocked forever.
  - The fixture sets realistic DA parameters with `tpm2_dictionarylockout`, since tss-esapi 7.7 lacks `TPM2_DictionaryAttackParameters`. It can also provision a persistent SRK and set `ownerAuth` to test the fallback.
- **systemd units** are in `packaging/systemd/`. `systemd-analyze verify` passes and `systemd-analyze security` rates the service 0.7 ("SAFE"). Plan 6 installs them.
- **Not in this plan:**
  - marking TPM slots stale after a failure (daemon, Plan 3/4)
  - the password-change flow: fresh seal, rotation, removing the old slot (Plan 4)
  - offering to set `lockoutAuth` (setup, Plan 4)

## Global Constraints

- Rust stable 1.98, edition 2024; every crate `license = "Apache-2.0"`.
- Only `aleph-tpmd` opens the TPM. Neither `aleph-unlock` nor anything else links `tss-esapi` outside tests.
- **Exact strings and values:**
  - TPM auth value: `HKDF-SHA-256(password, salt = auth_salt (16 random bytes), info = "aleph tpm auth v1" ‖ be32(uid))`
  - sealed payload `be32(uid) ‖ KEK(32)`
  - SRK handle `0x81000001`
  - socket `/run/aleph/tpm.sock`
  - FIDO2 RP ID `"aleph"`, KEK `HKDF-SHA-256(hmac-secret, "aleph fido2 v1")`
  - frame = `be32(len) ‖ CBOR`, `len ≤ 65536`, strict decoding
- The helper learns the uid only from `SO_PEERCRED`, never from a message. Every transient TPM handle and session is flushed on every path.
- Secrets travel in zeroize-on-drop types (`Secret`, `Kek`, `Zeroizing`) with redacted `Debug`.
- `cargo fmt` default; `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **Another local user who copies your TPM slot blobs**, even knowing your password, must get nothing. → Task 2 `another_user_cannot_unseal_even_with_the_password`, `the_socket_binds_objects_to_the_callers_real_uid`.
2. **A different TPM, an interposer substituting the parent key, or `ownerAuth` being set later** must be reported as `ParentMismatch` before any session is salted or any password reaches the TPM. With `ownerAuth` set, the persistent SRK must still work. → Task 2 `a_parent_name_mismatch_is_refused_without_an_auth_attempt`, `a_slot_from_another_tpm_is_a_parent_mismatch`, `with_owner_auth_set_the_persistent_srk_is_used`, `with_owner_auth_set_and_no_srk_enrollment_is_refused`.
3. **One user guessing passwords** must not be able to exhaust the TPM-wide dictionary-attack counter. That counter is shared with other users and with `systemd-cryptenroll`. → Task 2 `failed_unseals_are_rate_limited_per_user`, `a_locked_out_caller_is_rate_limited_too`.
4. **With several FIDO2 keys plugged in,** unlock must pick the right one without touching or PIN-prompting the others, and enrollment must refuse ambiguity. → Task 4 `unlock_picks_the_right_key_among_several_and_touches_only_it`, `enrollment_needs_exactly_one_key`.
5. **A thief with a PIN-protected FIDO2 key but no PIN** must not unlock. A key with neither PIN nor UV must be refused unless touch-only is explicitly chosen. → Task 4 `a_touch_without_verification_cannot_open_a_verified_slot`, `a_bare_key_is_refused_unless_touch_only_is_chosen`, `by_default_the_pin_is_required_at_enroll_and_unlock`.

## File Structure

```
Cargo.toml                                members grow per task
crates/aleph-tpm-proto/src/lib.rs         Request/Response/Status/Failure, SealedObject, Secret, frames
crates/aleph-tpmd/
  Cargo.toml                              feature `testing` (swtpm fixture)
  src/lib.rs, main.rs                     socket activation (LISTEN_FDS) or --socket
  src/tpm.rs                              Tpm: seal/unseal/status, parent selection + Name check
  src/limiter.rs                          RateLimiter (5 failures / 60 s / uid)
  src/server.rs                           Helper::handle, peer_uid, serve_connection, serve
  src/testing.rs                          SwTpm fixture (feature `testing`)
  tests/helper.rs, socket.rs              behaviour against swtpm; tests/tpm_hardware.rs (#[ignore])
crates/aleph-unlock/
  src/error.rs, lib.rs, tpm.rs            TpmClient over the helper socket
  src/fido2/mod.rs, mock.rs, libfido2.rs  Keys/Authenticator, enroll/unlock, MockKeys, Libfido2Keys
  tests/tpm_client.rs, fido2.rs           tests/fido2_hardware.rs (#[ignore])
packaging/systemd/aleph-tpmd.{socket,service}
docs/testing.md, README.md, spec §5 corrections
```

---
### Task 1: `aleph-tpm-proto`, the helper wire protocol

**Files:** Modify `Cargo.toml`; Create `crates/aleph-tpm-proto/Cargo.toml`, `crates/aleph-tpm-proto/src/lib.rs`.

**Interfaces:**
- Produces:
  - `MAX_FRAME = 65536`
  - `Secret(pub Vec<u8>)` (zeroized, redacted)
  - `SealedObject { public, private, auth_salt, srk_name }`
  - `Request { Seal { secret }, Unseal { object, secret }, Status {} }`
  - `Parent { AlephPrimary, PersistentSrk, Unavailable }`
  - `Status { parent, owner_auth_set, lockout_auth_set, in_lockout, max_tries, recovery_time, lockout_recovery, failed_tries }`
  - `Failure { AuthFailed, Lockout, RateLimited, WrongUser, ParentMismatch, NoParent, Malformed(String), Tpm(String) }`
  - `Response { Sealed { object, kek }, Unsealed { kek }, Status(Status), Failed(Failure) }`
  - `write_frame(&mut impl Write, &T)`, `read_frame::<T>(&mut impl Read)` → `Result<_, FrameError { Io, TooLarge, Malformed }>`

- [ ] **Step 1: Write the failing tests**

Replace the workspace `Cargo.toml` with:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-tpm-proto"]

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
hex = "0.4"
hybrid-array = { version = "0.4", features = ["zeroize"] }
hmac = "0.13"
libc = "0.2"
proptest = "1"
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
serde_json = "1"
sha2 = "0.11"
tempfile = "3"
thiserror = "2"
tss-esapi = "7.7"
uuid = { version = "1", features = ["v4", "serde"] }
# Pinned exactly: recovery keys must open vaults forever, and the crate
# tracks a draft (the local KATs against the draft vectors are the tripwire).
x-wing = { version = "=0.1.0", features = ["zeroize"] }
zeroize = { version = "1.9", features = ["derive"] }

# Argon2, the AEAD, X-Wing (ML-KEM, X25519, SHA-3), and CBOR parsing are
# unusably slow unoptimized; keep tests fast.
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
[profile.dev.package.ml-kem]
opt-level = 3
[profile.dev.package.module-lattice]
opt-level = 3
[profile.dev.package.x25519-dalek]
opt-level = 3
[profile.dev.package.curve25519-dalek]
opt-level = 3
[profile.dev.package.sha3]
opt-level = 3
[profile.dev.package.keccak]
opt-level = 3
[profile.dev.package.shake]
opt-level = 3
[profile.dev.package.ciborium]
opt-level = 3
[profile.dev.package.ciborium-ll]
opt-level = 3
```

Create `crates/aleph-tpm-proto/Cargo.toml`:

```toml
[package]
name = "aleph-tpm-proto"
description = "Wire protocol between alephd and the aleph-tpmd TPM helper"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
ciborium.workspace = true
serde.workspace = true
serde_bytes.workspace = true
thiserror.workspace = true
zeroize.workspace = true

[dev-dependencies]
proptest.workspace = true
```

Create `crates/aleph-tpm-proto/src/lib.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> SealedObject {
        SealedObject {
            public: vec![1, 2],
            private: vec![3],
            auth_salt: vec![4; 16],
            srk_name: vec![5; 34],
        }
    }

    fn round_trip<T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
        msg: T,
    ) {
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).unwrap();
        assert_eq!(read_frame::<T>(&mut buf.as_slice()).unwrap(), msg);
    }

    #[test]
    fn every_message_round_trips() {
        round_trip(Request::Seal {
            secret: Secret(b"pw".to_vec()),
        });
        round_trip(Request::Unseal {
            object: object(),
            secret: Secret(b"pw".to_vec()),
        });
        round_trip(Request::Status {});
        round_trip(Response::Sealed {
            object: object(),
            kek: Secret(vec![9; 32]),
        });
        round_trip(Response::Unsealed {
            kek: Secret(vec![9; 32]),
        });
        round_trip(Response::Status(Status {
            parent: Parent::AlephPrimary,
            owner_auth_set: false,
            lockout_auth_set: false,
            in_lockout: false,
            max_tries: 32,
            recovery_time: 600,
            lockout_recovery: 86400,
            failed_tries: 0,
        }));
        for f in [
            Failure::AuthFailed,
            Failure::Lockout,
            Failure::RateLimited,
            Failure::WrongUser,
            Failure::ParentMismatch,
            Failure::NoParent,
            Failure::Malformed("x".into()),
            Failure::Tpm("y".into()),
        ] {
            round_trip(Response::Failed(f));
        }
    }

    #[test]
    fn oversized_length_is_rejected_before_allocating() {
        let mut buf = (u32::MAX).to_be_bytes().to_vec();
        buf.extend([0u8; 8]);
        assert!(matches!(
            read_frame::<Request>(&mut buf.as_slice()),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn trailing_bytes_and_truncation_are_rejected() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Request::Status {}).unwrap();
        let mut padded = buf.clone();
        padded[3] += 1; // claim one more byte
        padded.push(0);
        assert!(matches!(
            read_frame::<Request>(&mut padded.as_slice()),
            Err(FrameError::Malformed(_))
        ));
        let truncated = &buf[..buf.len() - 1];
        assert!(matches!(
            read_frame::<Request>(&mut &truncated[..]),
            Err(FrameError::Io(_))
        ));
    }

    #[test]
    fn unknown_fields_and_ops_are_rejected() {
        use ciborium::Value;
        let encode = |v: &Value| {
            let mut body = Vec::new();
            ciborium::into_writer(v, &mut body).unwrap();
            let mut buf = (body.len() as u32).to_be_bytes().to_vec();
            buf.extend(body);
            buf
        };
        let extra = Value::Map(vec![
            (Value::Text("op".into()), Value::Text("status".into())),
            (Value::Text("uid".into()), Value::Integer(0.into())),
        ]);
        assert!(read_frame::<Request>(&mut encode(&extra).as_slice()).is_err());
        let unknown = Value::Map(vec![(
            Value::Text("op".into()),
            Value::Text("clear".into()),
        )]);
        assert!(read_frame::<Request>(&mut encode(&unknown).as_slice()).is_err());
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let r = Request::Seal {
            secret: Secret(b"hunter2".to_vec()),
        };
        assert!(!format!("{r:?}").contains("hunter2"));
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_frames_never_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            let _ = read_frame::<Request>(&mut bytes.as_slice());
            let _ = read_frame::<Response>(&mut bytes.as_slice());
        }
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-tpm-proto`
Expected: the build fails because `Request`, `Response`, `write_frame`, `read_frame`, etc. do not exist yet.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` line in `crates/aleph-tpm-proto/src/lib.rs`:

```rust
//! The `aleph-tpmd` wire protocol (spec §5, "The helper").
//!
//! One request and one response per connection turn, each a frame: a
//! big-endian `u32` length followed by exactly that many bytes of CBOR.
//! Frames are capped at [`MAX_FRAME`] and decoded strictly (one item, no
//! trailing bytes), because the helper reads frames from any local user.
//!
//! The helper learns the caller's uid from the socket (`SO_PEERCRED`),
//! never from the message.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Largest accepted frame. Real requests are well under 4 KiB.
pub const MAX_FRAME: usize = 64 * 1024;

/// A secret carried in a message (a login password, or a KEK): zeroized
/// on drop, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

/// The TPM-side parameters of a sealed KEK, as stored in a vault keyslot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedObject {
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub auth_salt: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub srk_name: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    /// Generate a fresh KEK and seal it to the caller's uid and `secret`.
    Seal { secret: Secret },
    /// Unseal a KEK previously sealed for the caller.
    Unseal {
        object: SealedObject,
        secret: Secret,
    },
    /// Report TPM and helper state. (An empty struct variant rather than a
    /// unit variant: serde's internally tagged unit variants ignore extra
    /// fields even with `deny_unknown_fields`.)
    Status {},
}

/// Which parent key sealed objects are created under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Parent {
    /// aleph's own primary (ECC P-256, AES-256-CFB), re-created per use.
    AlephPrimary,
    /// The persistent TCG SRK at 0x81000001 (AES-128-CFB), used when
    /// `ownerAuth` is set.
    PersistentSrk,
    /// Neither is usable: TPM enrollment is refused.
    Unavailable,
}

/// `Status` reply: what setup shows the user (spec §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub parent: Parent,
    pub owner_auth_set: bool,
    pub lockout_auth_set: bool,
    pub in_lockout: bool,
    /// Failed authorizations before lockout (TPM2_PT_MAX_AUTH_FAIL).
    pub max_tries: u32,
    /// Seconds for one failure to be forgotten (TPM2_PT_LOCKOUT_INTERVAL).
    pub recovery_time: u32,
    /// Seconds before lockout auth may be retried (TPM2_PT_LOCKOUT_RECOVERY).
    pub lockout_recovery: u32,
    /// Current failure count (TPM2_PT_LOCKOUT_COUNTER).
    pub failed_tries: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", content = "detail", rename_all = "kebab-case")]
pub enum Failure {
    #[error("the TPM rejected the password")]
    AuthFailed,
    #[error("the TPM is in dictionary-attack lockout")]
    Lockout,
    #[error("too many failed attempts; wait a minute")]
    RateLimited,
    #[error("this sealed object belongs to another user")]
    WrongUser,
    #[error("the TPM's parent key does not match this slot (different TPM or tampering)")]
    ParentMismatch,
    #[error("no usable parent key (ownerAuth set and no persistent SRK)")]
    NoParent,
    #[error("malformed request: {0}")]
    Malformed(String),
    #[error("TPM error: {0}")]
    Tpm(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    Sealed { object: SealedObject, kek: Secret },
    Unsealed { kek: Secret },
    Status(Status),
    Failed(Failure),
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    #[error("malformed frame: {0}")]
    Malformed(String),
}

/// Write one message as a frame.
pub fn write_frame<T: Serialize>(w: &mut impl Write, msg: &T) -> Result<(), FrameError> {
    let mut body = zeroize::Zeroizing::new(Vec::new());
    ciborium::into_writer(msg, &mut *body).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read one frame and decode it strictly. The length is checked before
/// anything is allocated.
pub fn read_frame<T: serde::de::DeserializeOwned>(r: &mut impl Read) -> Result<T, FrameError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = zeroize::Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut body)?;
    let mut cursor = std::io::Cursor::new(body.as_slice());
    let msg =
        ciborium::from_reader(&mut cursor).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if cursor.position() != len as u64 {
        return Err(FrameError::Malformed("trailing data in frame".into()));
    }
    Ok(msg)
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-tpm-proto && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `6 passed`.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-tpm-proto
git commit -m "feat(tpm-proto): wire protocol for the aleph-tpmd helper" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: `aleph-tpmd`, the TPM helper

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/aleph-tpmd/Cargo.toml`, `crates/aleph-tpmd/src/{lib,main,tpm,limiter,server,testing}.rs`, `crates/aleph-tpmd/tests/{helper,socket,tpm_hardware}.rs`

**Interfaces:**
- Consumes: `aleph-tpm-proto` (Task 1).
- Produces:
  - `aleph_tpmd::{Tpm, TpmError, Helper}`
  - `tpm::{DEFAULT_TCTI = "device:/dev/tpmrm0", SRK_HANDLE = 0x8100_0001}`
  - `Tpm::open(tcti)`, `Tpm::open_default()` (reads `ALEPH_TCTI`, then `TPM2TOOLS_TCTI`)
  - `Tpm::seal(uid, secret) -> Result<(SealedObject, Zeroizing<[u8; 32]>)>`
  - `Tpm::unseal(uid, &SealedObject, secret) -> Result<Zeroizing<[u8; 32]>>`
  - `Tpm::status() -> Result<Status>`
  - `TpmError { Unavailable, AuthFailed, Lockout, WrongUser, ParentMismatch, NoParent, Malformed, Tpm }`
  - `limiter::{RateLimiter, MAX_FAILURES = 5, WINDOW = 60 s}`
  - `Helper::new(Tpm)`, `.handle(uid, Request) -> Response`, `.handle_at(uid, Request, Instant)`
  - `server::{peer_uid, serve_connection, serve, IO_TIMEOUT = 5 s}`
  - feature `testing` → `testing::SwTpm { start(), tcti(), tpm(), helper(), provision_persistent_srk(), set_owner_auth(), set_da_parameters(max_tries, recovery_time, lockout_recovery) }`

- [ ] **Step 1: Write the failing tests**

Replace the workspace `Cargo.toml` with:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-tpm-proto", "crates/aleph-tpmd"]

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
hex = "0.4"
hybrid-array = { version = "0.4", features = ["zeroize"] }
hmac = "0.13"
libc = "0.2"
proptest = "1"
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
serde_json = "1"
sha2 = "0.11"
tempfile = "3"
thiserror = "2"
tss-esapi = "7.7"
uuid = { version = "1", features = ["v4", "serde"] }
# Pinned exactly: recovery keys must open vaults forever, and the crate
# tracks a draft (the local KATs against the draft vectors are the tripwire).
x-wing = { version = "=0.1.0", features = ["zeroize"] }
zeroize = { version = "1.9", features = ["derive"] }

# Argon2, the AEAD, X-Wing (ML-KEM, X25519, SHA-3), and CBOR parsing are
# unusably slow unoptimized; keep tests fast.
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
[profile.dev.package.ml-kem]
opt-level = 3
[profile.dev.package.module-lattice]
opt-level = 3
[profile.dev.package.x25519-dalek]
opt-level = 3
[profile.dev.package.curve25519-dalek]
opt-level = 3
[profile.dev.package.sha3]
opt-level = 3
[profile.dev.package.keccak]
opt-level = 3
[profile.dev.package.shake]
opt-level = 3
[profile.dev.package.ciborium]
opt-level = 3
[profile.dev.package.ciborium-ll]
opt-level = 3
```

Create `crates/aleph-tpmd/Cargo.toml`:

```toml
[package]
name = "aleph-tpmd"
description = "TPM helper service for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
getrandom.workspace = true
hkdf.workspace = true
libc.workspace = true
sha2.workspace = true
thiserror.workspace = true
tss-esapi.workspace = true
tempfile = { workspace = true, optional = true }
zeroize.workspace = true

[features]
# A swtpm test fixture (`aleph_tpmd::testing::SwTpm`) for this crate's and
# aleph-unlock's tests. Needs `swtpm` and `tpm2-tools` at run time.
testing = ["dep:tempfile"]

[dev-dependencies]
aleph-tpmd = { path = ".", features = ["testing"] }
libc.workspace = true
tempfile.workspace = true
```

Create `crates/aleph-tpmd/src/lib.rs`:

```rust
//! `aleph-tpmd`: the only process that talks to the TPM for aleph
//! (spec §5, "TPM, via aleph-tpmd"). It runs as a socket-activated system
//! service with a throwaway user in the `tss` group, keeps no state on
//! disk, and binds every sealed object to the uid of the local user who
//! asked for it.

pub mod limiter;
pub mod server;
pub mod tpm;

#[cfg(feature = "testing")]
pub mod testing;

pub use server::Helper;
pub use tpm::{Tpm, TpmError};
```

Create `crates/aleph-tpmd/src/limiter.rs` (tests only for now):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_max_failures_within_the_window_then_recovers() {
        let t0 = Instant::now();
        let mut l = RateLimiter::default();
        for i in 0..MAX_FAILURES {
            assert!(!l.blocked(1000, t0), "blocked after {i}");
            l.record_failure(1000, t0);
        }
        assert!(l.blocked(1000, t0));
        assert!(l.blocked(1000, t0 + WINDOW - Duration::from_secs(1)));
        assert!(!l.blocked(1000, t0 + WINDOW));
    }

    #[test]
    fn uids_are_limited_independently() {
        let t0 = Instant::now();
        let mut l = RateLimiter::default();
        for _ in 0..MAX_FAILURES {
            l.record_failure(1000, t0);
        }
        assert!(l.blocked(1000, t0));
        assert!(!l.blocked(1001, t0));
    }
}
```

Create `crates/aleph-tpmd/src/tpm.rs`, `crates/aleph-tpmd/src/server.rs`, and `crates/aleph-tpmd/src/testing.rs` each containing only `// implemented in step 3`, and `crates/aleph-tpmd/src/main.rs` containing `fn main() {}`.

Create `crates/aleph-tpmd/tests/helper.rs`:

```rust
use std::time::Instant;

use aleph_tpm_proto::{Failure, Parent, Request, Response, SealedObject, Secret};
use aleph_tpmd::limiter::{MAX_FAILURES, WINDOW};
use aleph_tpmd::testing::SwTpm;

const UID: u32 = 1000;
const PW: &[u8] = b"login password";

fn seal(h: &aleph_tpmd::Helper, uid: u32, pw: &[u8]) -> (SealedObject, Vec<u8>) {
    match h.handle(
        uid,
        Request::Seal {
            secret: Secret(pw.to_vec()),
        },
    ) {
        Response::Sealed { object, kek } => (object, kek.0.clone()),
        other => panic!("seal: {other:?}"),
    }
}

fn unseal(h: &aleph_tpmd::Helper, uid: u32, object: &SealedObject, pw: &[u8]) -> Response {
    h.handle(
        uid,
        Request::Unseal {
            object: object.clone(),
            secret: Secret(pw.to_vec()),
        },
    )
}

fn unsealed_kek(r: Response) -> Vec<u8> {
    match r {
        Response::Unsealed { kek } => kek.0.clone(),
        other => panic!("unseal: {other:?}"),
    }
}

#[test]
fn seal_then_unseal_returns_the_same_kek() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, kek) = seal(&h, UID, PW);
    assert_eq!(kek.len(), 32);
    assert_eq!(object.auth_salt.len(), 16);
    assert!(!object.srk_name.is_empty());
    assert_eq!(unsealed_kek(unseal(&h, UID, &object, PW)), kek);
}

#[test]
fn a_slot_survives_a_new_helper_process() {
    // aleph's primary is re-derived, not persisted: a fresh helper (as after
    // a reboot) finds the same parent Name and unseals.
    let sw = SwTpm::start();
    let (object, kek) = seal(&sw.helper(), UID, PW);
    assert_eq!(unsealed_kek(unseal(&sw.helper(), UID, &object, PW)), kek);
}

#[test]
fn each_seal_gets_its_own_salt_and_kek() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (a, ka) = seal(&h, UID, PW);
    let (b, kb) = seal(&h, UID, PW);
    assert_ne!(a.auth_salt, b.auth_salt);
    assert_ne!(ka, kb);
}

#[test]
fn a_wrong_password_is_auth_failed() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    assert_eq!(
        unseal(&h, UID, &object, b"wrong"),
        Response::Failed(Failure::AuthFailed)
    );
}

/// Another local user who copies your blobs gets nothing, even with your
/// password: the uid is part of the auth value and of the sealed payload.
#[test]
fn another_user_cannot_unseal_even_with_the_password() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    let r = unseal(&h, UID + 1, &object, PW);
    assert!(
        matches!(
            r,
            Response::Failed(Failure::AuthFailed | Failure::WrongUser)
        ),
        "{r:?}"
    );
}

/// A tampered or foreign parent Name is refused before the parent salts a
/// session and before any password attempt reaches the TPM.
#[test]
fn a_parent_name_mismatch_is_refused_without_an_auth_attempt() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (mut object, _) = seal(&h, UID, PW);
    object.srk_name[5] ^= 1;
    for _ in 0..(MAX_FAILURES + 2) {
        assert_eq!(
            unseal(&h, UID, &object, PW),
            Response::Failed(Failure::ParentMismatch)
        );
    }
    // No failures were counted against the user or the TPM.
    object.srk_name[5] ^= 1;
    unsealed_kek(unseal(&h, UID, &object, PW));
}

#[test]
fn a_slot_from_another_tpm_is_a_parent_mismatch() {
    // Each TPM's seed differs, so aleph's primary has a different Name.
    let (a, b) = (SwTpm::start(), SwTpm::start());
    let (object, _) = seal(&a.helper(), UID, PW);
    assert_eq!(
        unseal(&b.helper(), UID, &object, PW),
        Response::Failed(Failure::ParentMismatch)
    );
}

#[test]
fn corrupt_objects_are_errors_not_panics() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);

    let mut bad = object.clone();
    bad.public = vec![0xff; 7];
    assert!(matches!(
        unseal(&h, UID, &bad, PW),
        Response::Failed(Failure::Malformed(_))
    ));

    let mut bad = object.clone();
    bad.auth_salt = vec![0; 3];
    assert!(matches!(
        unseal(&h, UID, &bad, PW),
        Response::Failed(Failure::Malformed(_))
    ));

    let mut bad = object.clone();
    let n = bad.private.len();
    bad.private[n - 1] ^= 1; // the TPM's integrity check rejects it
    assert!(matches!(unseal(&h, UID, &bad, PW), Response::Failed(_)));
}

#[test]
fn failed_unseals_are_rate_limited_per_user() {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    let t0 = Instant::now();
    let attempt = |pw: &[u8], uid: u32, at| {
        h.handle_at(
            uid,
            Request::Unseal {
                object: object.clone(),
                secret: Secret(pw.to_vec()),
            },
            at,
        )
    };
    for _ in 0..MAX_FAILURES {
        assert_eq!(
            attempt(b"wrong", UID, t0),
            Response::Failed(Failure::AuthFailed)
        );
    }
    // Blocked now, even with the right password: the TPM is not asked.
    assert_eq!(attempt(PW, UID, t0), Response::Failed(Failure::RateLimited));
    // Another user is unaffected.
    let (other, _) = seal(&h, UID + 1, PW);
    assert!(matches!(
        h.handle_at(
            UID + 1,
            Request::Unseal {
                object: other,
                secret: Secret(PW.to_vec())
            },
            t0
        ),
        Response::Unsealed { .. }
    ));
    // After the window, the user may try again.
    assert!(matches!(
        attempt(PW, UID, t0 + WINDOW),
        Response::Unsealed { .. }
    ));
}

/// Transient handles and sessions must be flushed on every path: a TPM has
/// only a few slots, and a leak would fail within a handful of operations.
#[test]
fn many_operations_do_not_exhaust_tpm_handles() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    let mut mismatched = object.clone();
    mismatched.srk_name[0] ^= 1;
    for _ in 0..40 {
        unsealed_kek(unseal(&h, UID, &object, PW));
        seal(&h, UID, PW);
        assert_eq!(
            unseal(&h, UID, &mismatched, PW),
            Response::Failed(Failure::ParentMismatch)
        );
        assert!(matches!(
            h.handle(UID, Request::Status {}),
            Response::Status(_)
        ));
    }
}

#[test]
fn repeated_wrong_passwords_reach_tpm_lockout() {
    // Bypass the helper's rate limit to reach the TPM's own lockout.
    let sw = SwTpm::start();
    let mut tpm = sw.tpm();
    let (object, _) = tpm.seal(UID, PW).unwrap();
    let mut saw_lockout = false;
    for _ in 0..64 {
        match tpm.unseal(UID, &object, b"0000") {
            Err(aleph_tpmd::TpmError::AuthFailed) => {}
            Err(aleph_tpmd::TpmError::Lockout) => {
                saw_lockout = true;
                break;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert!(saw_lockout, "TPM never entered lockout");
    let status = tpm.status().unwrap();
    assert!(status.in_lockout);
    assert_eq!(status.failed_tries, status.max_tries);
}

#[test]
fn status_reports_a_fresh_tpm() {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let Response::Status(s) = sw.helper().handle(UID, Request::Status {}) else {
        panic!()
    };
    assert_eq!(s.parent, Parent::AlephPrimary);
    assert!(!s.owner_auth_set);
    assert!(!s.lockout_auth_set);
    assert!(!s.in_lockout);
    assert_eq!(
        (s.max_tries, s.recovery_time, s.lockout_recovery),
        (32, 600, 86400)
    );
    assert_eq!(s.failed_tries, 0);
}

/// With `ownerAuth` set, aleph's primary cannot be created; the persistent
/// SRK is used instead, and its Name is what the slot records.
#[test]
fn with_owner_auth_set_the_persistent_srk_is_used() {
    let sw = SwTpm::start();
    // A slot sealed under aleph's primary before ownerAuth was set...
    let (old, _) = seal(&sw.helper(), UID, PW);
    sw.provision_persistent_srk();
    sw.set_owner_auth();
    let h = sw.helper();
    let Response::Status(s) = h.handle(UID, Request::Status {}) else {
        panic!()
    };
    assert_eq!(s.parent, Parent::PersistentSrk);
    assert!(s.owner_auth_set);
    let (object, kek) = seal(&h, UID, PW);
    assert_ne!(object.srk_name, old.srk_name);
    assert_eq!(unsealed_kek(unseal(&h, UID, &object, PW)), kek);
    // ...no longer finds its parent: re-enrollment is needed (setup explains).
    assert_eq!(
        unseal(&h, UID, &old, PW),
        Response::Failed(Failure::ParentMismatch)
    );
}

#[test]
fn with_owner_auth_set_and_no_srk_enrollment_is_refused() {
    let sw = SwTpm::start();
    sw.set_owner_auth();
    let h = sw.helper();
    let Response::Status(s) = h.handle(UID, Request::Status {}) else {
        panic!()
    };
    assert_eq!(s.parent, Parent::Unavailable);
    assert_eq!(
        h.handle(
            UID,
            Request::Seal {
                secret: Secret(PW.to_vec())
            }
        ),
        Response::Failed(Failure::NoParent)
    );
}

/// Lockout replies count against the caller too, so a locked-out user
/// cannot keep polling the TPM (swtpm's default is 3 tries).
#[test]
fn a_locked_out_caller_is_rate_limited_too() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    let t0 = Instant::now();
    let mut replies = Vec::new();
    for _ in 0..MAX_FAILURES {
        replies.push(h.handle_at(
            UID,
            Request::Unseal {
                object: object.clone(),
                secret: Secret(b"wrong".to_vec()),
            },
            t0,
        ));
    }
    assert!(
        replies.contains(&Response::Failed(Failure::Lockout)),
        "{replies:?}"
    );
    assert_eq!(
        h.handle_at(
            UID,
            Request::Unseal {
                object,
                secret: Secret(PW.to_vec())
            },
            t0
        ),
        Response::Failed(Failure::RateLimited)
    );
}
```

Create `crates/aleph-tpmd/tests/socket.rs`:

```rust
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use aleph_tpm_proto::{Failure, Request, Response, Secret, read_frame, write_frame};
use aleph_tpmd::testing::SwTpm;

/// A helper serving `n` connections on a socket in a temp directory.
fn serve(
    sw: &SwTpm,
    n: usize,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::thread::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let helper = Arc::new(sw.helper());
    let handle = std::thread::spawn(move || {
        for _ in 0..n {
            let (stream, _) = listener.accept().unwrap();
            let _ = aleph_tpmd::server::serve_connection(&helper, stream);
        }
    });
    (dir, path, handle)
}

fn call(path: &std::path::Path, request: &Request) -> Response {
    let mut s = UnixStream::connect(path).unwrap();
    write_frame(&mut s, request).unwrap();
    read_frame(&mut s).unwrap()
}

#[test]
fn a_client_seals_and_unseals_over_the_socket_as_itself() {
    let sw = SwTpm::start();
    let (_dir, path, server) = serve(&sw, 2);
    let Response::Sealed { object, kek } = call(
        &path,
        &Request::Seal {
            secret: Secret(b"pw".to_vec()),
        },
    ) else {
        panic!("seal failed")
    };
    let Response::Unsealed { kek: back } = call(
        &path,
        &Request::Unseal {
            object,
            secret: Secret(b"pw".to_vec()),
        },
    ) else {
        panic!("unseal failed")
    };
    assert_eq!(kek, back);
    server.join().unwrap();
}

/// The uid comes from the kernel: an object sealed over the socket (as the
/// real uid) does not open for any other uid handled directly.
#[test]
fn the_socket_binds_objects_to_the_callers_real_uid() {
    let sw = SwTpm::start();
    let (_dir, path, server) = serve(&sw, 1);
    let Response::Sealed { object, .. } = call(
        &path,
        &Request::Seal {
            secret: Secret(b"pw".to_vec()),
        },
    ) else {
        panic!("seal failed")
    };
    server.join().unwrap();
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let helper = sw.helper();
    let other = helper.handle(
        me.wrapping_add(1),
        Request::Unseal {
            object: object.clone(),
            secret: Secret(b"pw".to_vec()),
        },
    );
    assert!(matches!(
        other,
        Response::Failed(Failure::AuthFailed | Failure::WrongUser)
    ));
    assert!(matches!(
        helper.handle(
            me,
            Request::Unseal {
                object,
                secret: Secret(b"pw".to_vec())
            }
        ),
        Response::Unsealed { .. }
    ));
}

#[test]
fn a_garbage_frame_gets_a_malformed_reply() {
    let sw = SwTpm::start();
    let (_dir, path, server) = serve(&sw, 1);
    let mut s = UnixStream::connect(&path).unwrap();
    s.write_all(&4u32.to_be_bytes()).unwrap();
    s.write_all(b"\xff\xff\xff\xff").unwrap();
    let reply: Response = read_frame(&mut s).unwrap();
    assert!(matches!(reply, Response::Failed(Failure::Malformed(_))));
    server.join().unwrap();
}
```

Create `crates/aleph-tpmd/tests/tpm_hardware.rs`:

```rust
//! Opt-in test against the machine's real TPM (not run in CI). Only the
//! success path is exercised: wrong-password attempts would count towards
//! the real TPM's dictionary-attack lockout. Needs access to the TPM
//! (root, or the `tss` group), as aleph-tpmd itself has.
//!
//! `cargo test -p aleph-tpmd --test tpm_hardware -- --ignored`
//! (uses `ALEPH_TCTI`, else `TPM2TOOLS_TCTI`, else `device:/dev/tpmrm0`).

#[test]
#[ignore]
fn real_tpm_status_seal_and_unseal() {
    let mut tpm = aleph_tpmd::Tpm::open_default().expect("open TPM (root or tss group?)");
    let status = tpm.status().unwrap();
    eprintln!("TPM status: {status:?}");
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let (object, kek) = tpm.seal(uid, b"aleph hw test").unwrap();
    assert_eq!(tpm.unseal(uid, &object, b"aleph hw test").unwrap(), kek);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-tpmd`
Expected: the build fails because `server::Helper`, `tpm::{Tpm, TpmError}`, and `RateLimiter` do not exist yet.

- [ ] **Step 3: Implement**

Insert above the `#[cfg(test)]` line in `crates/aleph-tpmd/src/limiter.rs`:

```rust
//! Per-uid rate limiting of failed unseals (spec §5): at most
//! [`MAX_FAILURES`] per [`WINDOW`]. It protects the TPM's dictionary-attack
//! counter, which is shared by every user and by `systemd-cryptenroll`,
//! from any one local user.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const MAX_FAILURES: usize = 5;
pub const WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct RateLimiter {
    failures: HashMap<u32, VecDeque<Instant>>,
}

impl RateLimiter {
    /// Whether `uid` is currently blocked.
    pub fn blocked(&mut self, uid: u32, now: Instant) -> bool {
        self.prune(uid, now);
        self.failures
            .get(&uid)
            .is_some_and(|f| f.len() >= MAX_FAILURES)
    }

    /// Record a failed unseal by `uid`.
    pub fn record_failure(&mut self, uid: u32, now: Instant) {
        self.prune(uid, now);
        self.failures.entry(uid).or_default().push_back(now);
    }

    fn prune(&mut self, uid: u32, now: Instant) {
        if let Some(f) = self.failures.get_mut(&uid) {
            while f.front().is_some_and(|t| now.duration_since(*t) >= WINDOW) {
                f.pop_front();
            }
            if f.is_empty() {
                self.failures.remove(&uid);
            }
        }
    }
}
```

Replace `crates/aleph-tpmd/src/tpm.rs` with:

```rust
//! The helper's TPM operations (spec §5, "TPM, via aleph-tpmd").
//!
//! - **Parent:** aleph's own primary (ECC P-256, AES-256-CFB), re-created
//!   from a fixed template on each use, whose Name is therefore stable per
//!   TPM. When `ownerAuth` is set that is impossible, and the persistent TCG
//!   SRK at `0x81000001` is used instead. Either way the parent's Name is
//!   recorded at seal time and checked before it salts a session, which
//!   detects a different TPM or an interposer substituting a key.
//! - **Sealed object:** a keyed hash holding `be32(uid) ‖ KEK`, authorized
//!   by `HKDF(secret, salt = auth_salt, info = "aleph tpm auth v1" ‖
//!   be32(uid))`. Unseal returns the KEK only to the uid it was sealed for.
//! - **Sessions:** HMAC sessions salted to the verified parent, with
//!   AES-256-CFB parameter encryption both ways. Every transient handle and
//!   session is flushed on success and on error.

use std::str::FromStr;

use aleph_tpm_proto::{Parent, SealedObject, Status};
use hkdf::Hkdf;
use sha2::Sha256;
use tss_esapi::Context;
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::PropertyTag;
use tss_esapi::constants::SessionType;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, EccPoint, KeyedHashScheme, Private, Public, PublicBuilder, PublicEccParametersBuilder,
    PublicKeyedHashParameters, SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use zeroize::Zeroizing;

/// The TCTI used when neither `ALEPH_TCTI` nor `TPM2TOOLS_TCTI` is set.
pub const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";
/// Where the TCG provisioning guidance puts the storage root key.
pub const SRK_HANDLE: u32 = 0x8100_0001;

const AUTH_INFO: &[u8] = b"aleph tpm auth v1";
const AUTH_SALT_LEN: usize = 16;
const KEK_LEN: usize = 32;
// TPMA_PERMANENT bits (TPM 2.0 Part 2, 8.6).
const PERMANENT_OWNER_AUTH_SET: u32 = 1 << 0;
const PERMANENT_LOCKOUT_AUTH_SET: u32 = 1 << 2;
const PERMANENT_IN_LOCKOUT: u32 = 1 << 9;

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("cannot open the TPM: {0}")]
    Unavailable(String),
    #[error("the TPM rejected the password")]
    AuthFailed,
    #[error("the TPM is in dictionary-attack lockout")]
    Lockout,
    #[error("sealed for another user")]
    WrongUser,
    #[error("parent key Name does not match the slot")]
    ParentMismatch,
    #[error("no usable parent key")]
    NoParent,
    #[error("malformed sealed object: {0}")]
    Malformed(String),
    #[error("TPM error: {0}")]
    Tpm(String),
}

pub type Result<T> = std::result::Result<T, TpmError>;

/// An open connection to a TPM.
pub struct Tpm {
    ctx: Context,
}

/// A parent key in use for one operation.
struct ParentKey {
    handle: KeyHandle,
    name: Vec<u8>,
    /// Transient (aleph's primary) keys are flushed; the persistent SRK is not.
    transient: bool,
}

impl Tpm {
    /// Connect using a TCTI string such as `device:/dev/tpmrm0` or
    /// `swtpm:host=127.0.0.1,port=2321`.
    pub fn open(tcti: &str) -> Result<Self> {
        let conf =
            TctiNameConf::from_str(tcti).map_err(|e| TpmError::Unavailable(e.to_string()))?;
        Ok(Self {
            ctx: Context::new(conf).map_err(|e| TpmError::Unavailable(e.to_string()))?,
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

    /// Generate a fresh KEK and seal it for `uid` under `secret`.
    pub fn seal(
        &mut self,
        uid: u32,
        secret: &[u8],
    ) -> Result<(SealedObject, Zeroizing<[u8; KEK_LEN]>)> {
        let mut kek = Zeroizing::new([0u8; KEK_LEN]);
        getrandom::fill(kek.as_mut()).map_err(|e| TpmError::Tpm(e.to_string()))?;
        let mut auth_salt = [0u8; AUTH_SALT_LEN];
        getrandom::fill(&mut auth_salt).map_err(|e| TpmError::Tpm(e.to_string()))?;
        let mut payload = Zeroizing::new(Vec::with_capacity(4 + KEK_LEN));
        payload.extend_from_slice(&uid.to_be_bytes());
        payload.extend_from_slice(kek.as_slice());
        let data = SensitiveData::try_from(payload.to_vec()).map_err(tpm_err)?;
        let auth = auth_value(secret, &auth_salt, uid)?;
        let (public, private, srk_name) = self.with_parent(None, |ctx, parent, session| {
            let created = ctx
                .execute_with_session(Some(session), |ctx| {
                    ctx.create(
                        parent.handle,
                        sealed_template()?,
                        Some(auth),
                        Some(data),
                        None,
                        None,
                    )
                })
                .map_err(map_tss)?;
            Ok((created.out_public, created.out_private, parent.name.clone()))
        })?;
        Ok((
            SealedObject {
                public: public.marshall().map_err(tpm_err)?,
                private: private.value().to_vec(),
                auth_salt: auth_salt.to_vec(),
                srk_name,
            },
            kek,
        ))
    }

    /// Unseal a KEK sealed for `uid`.
    pub fn unseal(
        &mut self,
        uid: u32,
        object: &SealedObject,
        secret: &[u8],
    ) -> Result<Zeroizing<[u8; KEK_LEN]>> {
        let public =
            Public::unmarshall(&object.public).map_err(|e| TpmError::Malformed(e.to_string()))?;
        let private = Private::try_from(object.private.clone())
            .map_err(|e| TpmError::Malformed(e.to_string()))?;
        let auth_salt: [u8; AUTH_SALT_LEN] = object
            .auth_salt
            .as_slice()
            .try_into()
            .map_err(|_| TpmError::Malformed("auth_salt must be 16 bytes".into()))?;
        let auth = auth_value(secret, &auth_salt, uid)?;
        let data = self.with_parent(Some(&object.srk_name), |ctx, parent, session| {
            let loaded = ctx
                .execute_with_session(Some(session), |ctx| {
                    ctx.load(parent.handle, private, public)
                })
                .map_err(map_tss)?;
            let result = ctx
                .tr_set_auth(loaded.into(), auth)
                .map_err(map_tss)
                .and_then(|()| {
                    ctx.execute_with_session(Some(session), |ctx| ctx.unseal(loaded.into()))
                        .map_err(map_tss)
                });
            let _ = ctx.flush_context(loaded.into());
            result
        })?;
        let bytes = Zeroizing::new(data.value().to_vec());
        if bytes.len() != 4 + KEK_LEN {
            return Err(TpmError::Malformed(
                "sealed payload has the wrong length".into(),
            ));
        }
        if bytes[..4] != uid.to_be_bytes() {
            return Err(TpmError::WrongUser);
        }
        let mut kek = Zeroizing::new([0u8; KEK_LEN]);
        kek.copy_from_slice(&bytes[4..]);
        Ok(kek)
    }

    /// TPM state for `aleph setup` (spec §5).
    pub fn status(&mut self) -> Result<Status> {
        let prop = |ctx: &mut Context, tag| {
            ctx.get_tpm_property(tag)
                .map_err(map_tss)
                .map(|v| v.unwrap_or(0))
        };
        let permanent = prop(&mut self.ctx, PropertyTag::Permanent)?;
        let parent = match self.parent() {
            Ok(p) => {
                let kind = if p.transient {
                    Parent::AlephPrimary
                } else {
                    Parent::PersistentSrk
                };
                self.release(p);
                kind
            }
            Err(TpmError::NoParent) => Parent::Unavailable,
            Err(e) => return Err(e),
        };
        let max_tries = prop(&mut self.ctx, PropertyTag::MaxAuthFail)?;
        let failed_tries = prop(&mut self.ctx, PropertyTag::LockoutCounter)?;
        Ok(Status {
            parent,
            owner_auth_set: permanent & PERMANENT_OWNER_AUTH_SET != 0,
            lockout_auth_set: permanent & PERMANENT_LOCKOUT_AUTH_SET != 0,
            // Not every TPM (swtpm, for one) sets the inLockout bit; the
            // counter reaching the maximum is the definition.
            in_lockout: permanent & PERMANENT_IN_LOCKOUT != 0
                || (max_tries > 0 && failed_tries >= max_tries),
            max_tries,
            recovery_time: prop(&mut self.ctx, PropertyTag::LockoutInterval)?,
            lockout_recovery: prop(&mut self.ctx, PropertyTag::LockoutRecovery)?,
            failed_tries,
        })
    }

    /// The parent for this TPM: aleph's primary unless `ownerAuth` is set,
    /// then the persistent SRK if present.
    fn parent(&mut self) -> Result<ParentKey> {
        let permanent = self
            .ctx
            .get_tpm_property(PropertyTag::Permanent)
            .map_err(map_tss)?
            .unwrap_or(0);
        let (handle, transient) = if permanent & PERMANENT_OWNER_AUTH_SET == 0 {
            let key = self
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
            (key, true)
        } else {
            let handle = PersistentTpmHandle::new(SRK_HANDLE).map_err(tpm_err)?;
            let object = self
                .ctx
                .execute_without_session(|ctx| {
                    ctx.tr_from_tpm_public(TpmHandle::Persistent(handle))
                })
                .map_err(|_| TpmError::NoParent)?;
            (KeyHandle::from(object), false)
        };
        let name = match self.ctx.read_public(handle) {
            Ok((_, name, _)) => name.value().to_vec(),
            Err(e) => {
                if transient {
                    let _ = self.ctx.flush_context(handle.into());
                }
                return Err(map_tss(e));
            }
        };
        Ok(ParentKey {
            handle,
            name,
            transient,
        })
    }

    fn release(&mut self, parent: ParentKey) {
        if parent.transient {
            let _ = self.ctx.flush_context(parent.handle.into());
        }
    }

    /// Get the parent, verify its Name against `expected` (if any), open a
    /// salted parameter-encrypting session bound to it, run `f`, and flush
    /// everything transient.
    fn with_parent<T>(
        &mut self,
        expected: Option<&[u8]>,
        f: impl FnOnce(&mut Context, &ParentKey, AuthSession) -> Result<T>,
    ) -> Result<T> {
        let parent = self.parent()?;
        if expected.is_some_and(|name| name != parent.name.as_slice()) {
            self.release(parent);
            return Err(TpmError::ParentMismatch);
        }
        let result = start_session(&mut self.ctx, parent.handle).and_then(|session| {
            let out = f(&mut self.ctx, &parent, session);
            flush_session(&mut self.ctx, session);
            out
        });
        self.release(parent);
        result
    }
}

/// `HKDF-SHA-256(secret, salt = auth_salt, info = "aleph tpm auth v1" ‖ be32(uid))`.
fn auth_value(secret: &[u8], salt: &[u8; AUTH_SALT_LEN], uid: u32) -> Result<Auth> {
    let mut info = AUTH_INFO.to_vec();
    info.extend_from_slice(&uid.to_be_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(&info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-256 length");
    Auth::try_from(okm.to_vec()).map_err(tpm_err)
}

/// ECC P-256 restricted decryption key protecting children with
/// AES-256-CFB.
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

/// Keyed-hash sealed data object authorized by its auth value, with
/// dictionary-attack protection on.
fn sealed_template() -> tss_esapi::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
}

fn start_session(ctx: &mut Context, parent: KeyHandle) -> Result<AuthSession> {
    let session = ctx
        .execute_without_session(|ctx| {
            ctx.start_auth_session(
                Some(parent),
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
        })
        .map_err(map_tss)?
        .ok_or_else(|| TpmError::Tpm("no session returned".into()))?;
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    if let Err(e) = ctx.tr_sess_set_attributes(session, attrs, mask) {
        flush_session(ctx, session);
        return Err(map_tss(e));
    }
    Ok(session)
}

fn flush_session(ctx: &mut Context, session: AuthSession) {
    if session != AuthSession::Password {
        let _ = ctx.flush_context(ObjectHandle::from(SessionHandle::from(session)));
    }
}

fn map_tss(e: tss_esapi::Error) -> TpmError {
    if let tss_esapi::Error::Tss2Error(rc) = e {
        match rc.kind() {
            Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth) => {
                return TpmError::AuthFailed;
            }
            Some(Tss2ResponseCodeKind::Lockout) => return TpmError::Lockout,
            _ => {}
        }
    }
    tpm_err(e)
}

fn tpm_err(e: impl std::fmt::Display) -> TpmError {
    TpmError::Tpm(e.to_string())
}
```

Replace `crates/aleph-tpmd/src/server.rs` with:

```rust
//! Request handling and the socket loop.
//!
//! The caller's uid comes only from `SO_PEERCRED`. Connections are served
//! one at a time (the TPM is serial anyway), each with read and write
//! timeouts so an idle or slow client cannot hold the helper.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aleph_tpm_proto::{Failure, Request, Response, Secret, read_frame, write_frame};

use crate::limiter::RateLimiter;
use crate::tpm::{Tpm, TpmError};

/// How long a client may take to send its request or read the reply.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Helper {
    tpm: Mutex<Tpm>,
    limiter: Mutex<RateLimiter>,
}

impl Helper {
    pub fn new(tpm: Tpm) -> Self {
        Self {
            tpm: Mutex::new(tpm),
            limiter: Mutex::new(RateLimiter::default()),
        }
    }

    /// Handle one request from `uid` (as reported by the kernel).
    pub fn handle(&self, uid: u32, request: Request) -> Response {
        self.handle_at(uid, request, Instant::now())
    }

    /// `handle` with an explicit clock, for tests.
    pub fn handle_at(&self, uid: u32, request: Request, now: Instant) -> Response {
        let mut tpm = self.tpm.lock().unwrap_or_else(|e| e.into_inner());
        match request {
            Request::Seal { secret } => match tpm.seal(uid, &secret.0) {
                Ok((object, kek)) => Response::Sealed {
                    object,
                    kek: Secret(kek.to_vec()),
                },
                Err(e) => Response::Failed(failure(e)),
            },
            Request::Unseal { object, secret } => {
                let mut limiter = self.limiter.lock().unwrap_or_else(|e| e.into_inner());
                if limiter.blocked(uid, now) {
                    return Response::Failed(Failure::RateLimited);
                }
                match tpm.unseal(uid, &object, &secret.0) {
                    Ok(kek) => Response::Unsealed {
                        kek: Secret(kek.to_vec()),
                    },
                    Err(e) => {
                        // Lockout counts too: a locked-out caller must not be
                        // able to keep polling the TPM.
                        if matches!(
                            e,
                            TpmError::AuthFailed | TpmError::WrongUser | TpmError::Lockout
                        ) {
                            limiter.record_failure(uid, now);
                        }
                        Response::Failed(failure(e))
                    }
                }
            }
            Request::Status {} => match tpm.status() {
                Ok(s) => Response::Status(s),
                Err(e) => Response::Failed(failure(e)),
            },
        }
    }
}

fn failure(e: TpmError) -> Failure {
    match e {
        TpmError::AuthFailed => Failure::AuthFailed,
        TpmError::Lockout => Failure::Lockout,
        TpmError::WrongUser => Failure::WrongUser,
        TpmError::ParentMismatch => Failure::ParentMismatch,
        TpmError::NoParent => Failure::NoParent,
        TpmError::Malformed(m) => Failure::Malformed(m),
        TpmError::Unavailable(m) | TpmError::Tpm(m) => Failure::Tpm(m),
    }
}

/// The connected peer's uid, from the kernel.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes given.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Serve one connection: one request, one response.
pub fn serve_connection(helper: &Helper, mut stream: UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let uid = peer_uid(&stream)?;
    let response = match read_frame::<Request>(&mut stream) {
        Ok(request) => helper.handle(uid, request),
        Err(e) => Response::Failed(Failure::Malformed(e.to_string())),
    };
    write_frame(&mut stream, &response).map_err(io::Error::other)
}

/// Accept and serve connections forever. Per-connection errors are logged
/// and do not stop the helper.
pub fn serve(listener: &UnixListener, helper: &Helper) -> ! {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(e) = serve_connection(helper, stream) {
                    eprintln!("aleph-tpmd: connection error: {e}");
                }
            }
            Err(e) => eprintln!("aleph-tpmd: accept error: {e}"),
        }
    }
}
```

Replace `crates/aleph-tpmd/src/testing.rs` with:

```rust
//! Test support (feature `testing`): a private software TPM per test: `swtpm` on a pair of loopback TCP
//! ports with state in a temp directory, killed when the fixture drops.
//! Tests run in parallel with no shared state and never touch the host TPM.
//!
//! TCP, not Unix sockets: tss-esapi 7.7's `swtpm:` TCTI parser only
//! understands `host=`/`port=` and silently ignores `path=`.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use tss_esapi::Context;

static START_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub struct SwTpm {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl SwTpm {
    pub fn start() -> Self {
        // Choosing ports, spawning swtpm, and waiting for it are serialized
        // across this process's tests. Otherwise a parallel test can bind a
        // port we just checked, our swtpm dies, and our readiness probe
        // connects to the *other* test's swtpm, which serves one client at
        // a time: the probe then blocks forever. (Cargo runs one test binary
        // at a time, so a process-wide lock suffices.)
        let _serial = START_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
            // Probe only while our own swtpm is alive, so a dead one (port
            // clash) is never mistaken for another test's.
            if sw.child.try_wait().ok().flatten().is_some() || Instant::now() > deadline {
                return None; // swtpm died (port clash) or never came up; Drop reaps it
            }
            if crate::Tpm::open(&sw.tcti()).is_ok() {
                return Some(sw);
            }
            if Instant::now() > deadline {
                return None; // swtpm died (port clash) or never came up; Drop reaps it
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    pub fn tpm(&self) -> crate::Tpm {
        crate::Tpm::open(&self.tcti()).unwrap()
    }

    pub fn helper(&self) -> crate::Helper {
        crate::Helper::new(self.tpm())
    }

    fn raw(&self) -> Context {
        let conf = tss_esapi::tcti_ldr::TctiNameConf::from_str(&self.tcti()).unwrap();
        Context::new(conf).unwrap()
    }

    /// Provision the TCG storage root key (ECC P-256, AES-128-CFB) at the
    /// persistent handle `0x81000001`, as `systemd-cryptenroll` does.
    pub fn provision_persistent_srk(&self) {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::handles::PersistentTpmHandle;
        use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
        use tss_esapi::interface_types::dynamic_handles::Persistent;
        use tss_esapi::interface_types::ecc::EccCurve;
        use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
        use tss_esapi::structures::{
            EccPoint, PublicBuilder, PublicEccParametersBuilder, SymmetricDefinitionObject,
        };
        let mut ctx = self.raw();
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .unwrap();
        let template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    EccCurve::NistP256,
                )
                .build()
                .unwrap(),
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .unwrap();
        let key = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
            })
            .unwrap()
            .key_handle;
        let persistent =
            Persistent::Persistent(PersistentTpmHandle::new(crate::tpm::SRK_HANDLE).unwrap());
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(Provision::Owner, key.into(), persistent)
        })
        .unwrap();
        ctx.flush_context(key.into()).unwrap();
    }

    /// Set the owner hierarchy's authorization, which makes creating
    /// aleph's own primary impossible.
    pub fn set_owner_auth(&self) {
        use tss_esapi::handles::AuthHandle;
        use tss_esapi::structures::Auth;
        let mut ctx = self.raw();
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.hierarchy_change_auth(
                AuthHandle::Owner,
                Auth::try_from(b"owner".to_vec()).unwrap(),
            )
        })
        .unwrap();
    }
}

impl SwTpm {
    /// Set the TPM's dictionary-attack parameters, as a real TPM might ship
    /// (swtpm defaults to 3 tries). tss-esapi 7.7 lacks
    /// TPM2_DictionaryAttackParameters, so this uses tpm2-tools.
    pub fn set_da_parameters(&self, max_tries: u32, recovery_time: u32, lockout_recovery: u32) {
        let status = Command::new("tpm2_dictionarylockout")
            .env("TPM2TOOLS_TCTI", self.tcti())
            .arg("--setup-parameters")
            .arg(format!("--max-tries={max_tries}"))
            .arg(format!("--recovery-time={recovery_time}"))
            .arg(format!("--lockout-recovery-time={lockout_recovery}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("tpm2_dictionarylockout not found: install tpm2-tools");
        assert!(status.success(), "tpm2_dictionarylockout failed");
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

Replace `crates/aleph-tpmd/src/main.rs` with:

```rust
//! `aleph-tpmd` entry point.
//!
//! Normally socket-activated by systemd (`aleph-tpmd.socket`), receiving
//! the listening socket as fd 3 (`LISTEN_FDS=1`, `LISTEN_PID` = our pid).
//! For development: `aleph-tpmd --socket <path>` binds its own socket.
//! The TPM is chosen by `ALEPH_TCTI`/`TPM2TOOLS_TCTI`, default
//! `device:/dev/tpmrm0`.

use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::process::ExitCode;

use aleph_tpmd::{Helper, Tpm};

const SD_LISTEN_FDS_START: i32 = 3;

fn listener() -> std::io::Result<UnixListener> {
    let mut args = std::env::args().skip(1);
    if let (Some(flag), Some(path)) = (args.next(), args.next())
        && flag == "--socket"
    {
        let _ = std::fs::remove_file(&path);
        return UnixListener::bind(path);
    }
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        == Some(std::process::id());
    let fds = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|n| n.parse::<i32>().ok());
    if pid_ok && fds == Some(1) {
        // SAFETY: systemd passed exactly one listening socket at fd 3, and
        // nothing else in this process owns it.
        return Ok(unsafe { UnixListener::from_raw_fd(SD_LISTEN_FDS_START) });
    }
    Err(std::io::Error::other(
        "not socket-activated; run under aleph-tpmd.socket or pass --socket <path>",
    ))
}

fn main() -> ExitCode {
    let listener = match listener() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("aleph-tpmd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let tpm = match Tpm::open_default() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("aleph-tpmd: {e}");
            return ExitCode::FAILURE;
        }
    };
    aleph_tpmd::server::serve(&listener, &Helper::new(tpm))
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-tpmd && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected:
- unit `2 passed`, `helper` `15 passed`, `socket` `3 passed`, `tpm_hardware` `1 ignored`
- about 2 s in total
- `WARNING:tcti:…`/`WARNING:esys:…` lines on stderr: expected (readiness probes and deliberate failures)

Run it 3 times. It must never hang; a hang means the fixture's start lock is missing.

- [ ] **Step 5: Confirm the security tests have teeth**

Revert each of these one at a time, run the named test and see it FAIL, then restore (`touch` the file) and see it pass:
- In `tpm.rs`, delete `info.extend_from_slice(&uid.to_be_bytes());` in `auth_value` **and** change `if bytes[..4] != uid.to_be_bytes() {` to `if false && bytes[..4] != uid.to_be_bytes() {`. Test: `--test helper another_user_cannot_unseal`.
- In `tpm.rs` `with_parent`, prefix the Name check's condition with `false &&`. Test: `--test helper a_parent_name_mismatch`.
- In `server.rs`, replace `limiter.record_failure(uid, now);` with `let _ = &limiter;`. Test: `--test helper failed_unseals_are_rate_limited`.
- In `server.rs`, remove `| TpmError::Lockout` from the counted errors. Test: `--test helper a_locked_out_caller`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-tpmd
git commit -m "feat(tpmd): TPM helper with uid binding, parent Name check, rate limiting" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: `aleph-unlock` TPM client

**Files:** Modify `Cargo.toml`; Create `crates/aleph-unlock/Cargo.toml`, `crates/aleph-unlock/src/{lib,error,tpm}.rs`, `crates/aleph-unlock/tests/tpm_client.rs`.

**Interfaces:**
- Consumes: Task 1 protocol; Task 2 `testing::SwTpm`, `server::serve` (tests only); `aleph_core::{Kek::try_init, TpmSlot { public, private, auth_salt: [u8; 16], srk_name }}`.
- Produces:
  - `aleph_unlock::{Error, Result, TpmClient}`
  - `tpm::{DEFAULT_SOCKET = "/run/aleph/tpm.sock", TIMEOUT = 30 s}`
  - `TpmClient::new(path)`, `TpmClient::from_env()` (reads `ALEPH_TPM_SOCKET`)
  - `.seal(password) -> Result<(Kek, TpmSlot)>`, `.unseal(&TpmSlot, password) -> Result<Kek>`, `.status() -> Result<Status>`
  - `Error`: `Core`, `TpmUnavailable`, `TpmAuthFailed`, `TpmLockout`, `TpmRateLimited`, `TpmWrongUser`, `TpmParentMismatch`, `TpmNoParent`, `TpmSlotMalformed`, `SecretRequired`, `Tpm`, plus the FIDO2 variants Task 4 uses

- [ ] **Step 1: Write the failing tests**

Replace the workspace `Cargo.toml` with:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-tpm-proto", "crates/aleph-tpmd", "crates/aleph-unlock"]

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
hex = "0.4"
hybrid-array = { version = "0.4", features = ["zeroize"] }
hmac = "0.13"
libc = "0.2"
proptest = "1"
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
serde_json = "1"
sha2 = "0.11"
tempfile = "3"
thiserror = "2"
tss-esapi = "7.7"
uuid = { version = "1", features = ["v4", "serde"] }
# Pinned exactly: recovery keys must open vaults forever, and the crate
# tracks a draft (the local KATs against the draft vectors are the tripwire).
x-wing = { version = "=0.1.0", features = ["zeroize"] }
zeroize = { version = "1.9", features = ["derive"] }

# Argon2, the AEAD, X-Wing (ML-KEM, X25519, SHA-3), and CBOR parsing are
# unusably slow unoptimized; keep tests fast.
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
[profile.dev.package.ml-kem]
opt-level = 3
[profile.dev.package.module-lattice]
opt-level = 3
[profile.dev.package.x25519-dalek]
opt-level = 3
[profile.dev.package.curve25519-dalek]
opt-level = 3
[profile.dev.package.sha3]
opt-level = 3
[profile.dev.package.keccak]
opt-level = 3
[profile.dev.package.shake]
opt-level = 3
[profile.dev.package.ciborium]
opt-level = 3
[profile.dev.package.ciborium-ll]
opt-level = 3
```

Create `crates/aleph-unlock/Cargo.toml`:

```toml
[package]
name = "aleph-unlock"
description = "TPM (via aleph-tpmd) and FIDO2 key-encryption-key providers for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
aleph-core = { path = "../aleph-core" }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
thiserror.workspace = true
zeroize.workspace = true

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
aleph-tpmd = { path = "../aleph-tpmd", features = ["testing"] }
tempfile.workspace = true
```

Create `crates/aleph-unlock/src/lib.rs`:

```rust
//! Hardware unlock methods for aleph: each turns a keyslot's stored
//! parameters (plus a password, PIN, or touch) into the slot's KEK.
//! See `docs/superpowers/specs/2026-09-26-aleph-design.md` §5.

pub mod error;
pub mod tpm;

pub use error::{Error, Result};
pub use tpm::TpmClient;
```

Create `crates/aleph-unlock/src/error.rs`:

```rust
/// Errors from producing a KEK with a hardware unlock method.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] aleph_core::Error),

    #[error("cannot reach aleph-tpmd ({0}); is aleph-tpmd.socket enabled?")]
    TpmUnavailable(String),

    #[error("the TPM rejected the password")]
    TpmAuthFailed,

    #[error("the TPM is in dictionary-attack lockout; wait and retry")]
    TpmLockout,

    #[error("too many failed TPM attempts; wait a minute")]
    TpmRateLimited,

    #[error("this TPM slot belongs to another user")]
    TpmWrongUser,

    #[error("this TPM slot was sealed on a different TPM (or its parent key changed)")]
    TpmParentMismatch,

    #[error("the TPM has no usable parent key (ownerAuth set, no persistent SRK)")]
    TpmNoParent,

    #[error("TPM slot is malformed: {0}")]
    TpmSlotMalformed(String),

    #[error("a password is required")]
    SecretRequired,

    #[error("TPM error: {0}")]
    Tpm(String),

    #[error("no FIDO2 security key is connected")]
    Fido2NoDevice,

    #[error("more than one FIDO2 key is connected; leave only the one to enroll")]
    Fido2MultipleDevices,

    #[error("this FIDO2 key does not support the hmac-secret extension")]
    Fido2Unsupported,

    #[error(
        "this FIDO2 key has neither a PIN nor built-in verification; set a PIN (fido2-token -S) or enroll touch-only"
    )]
    Fido2PinNotSet,

    #[error("FIDO2 PIN is required")]
    Fido2PinRequired,

    #[error("FIDO2 PIN was rejected")]
    Fido2PinInvalid,

    #[error("FIDO2 key is PIN-blocked; reset it or use another method")]
    Fido2PinBlocked,

    #[error("no connected FIDO2 key holds this credential")]
    Fido2NoCredential,

    #[error("FIDO2 operation timed out waiting for touch")]
    Fido2Timeout,

    #[error("FIDO2 error: {0}")]
    Fido2(String),
}

pub type Result<T> = std::result::Result<T, Error>;
```

Create `crates/aleph-unlock/src/tpm.rs` containing only `// implemented in step 3`, and `crates/aleph-unlock/tests/tpm_client.rs`:

```rust
use std::os::unix::net::UnixListener;
use std::sync::Arc;

use aleph_core::{LockedVault, RecoveryKey, SlotKind, UnlockedVault};
use aleph_tpmd::testing::SwTpm;
use aleph_unlock::{Error, TpmClient};

const PW: &[u8] = b"login password";

/// A real aleph-tpmd helper (on a private swtpm) serving a socket in a
/// temp directory; returns a client for it.
struct Helper {
    _sw: SwTpm,
    _dir: tempfile::TempDir,
    client: TpmClient,
}

fn helper() -> Helper {
    let sw = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let helper = Arc::new(sw.helper());
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, &helper));
    Helper {
        _sw: sw,
        _dir: dir,
        client: TpmClient::new(path),
    }
}

fn same_kek(a: &aleph_core::Kek, b: &aleph_core::Kek) -> bool {
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(a, b"t").unwrap();
    aleph_core::KeyHandle::unwraps_to(b, &w, b"t", &mk.id())
}

#[test]
fn seal_then_unseal_through_the_helper() {
    let h = helper();
    let (kek, slot) = h.client.seal(PW).unwrap();
    assert_eq!(slot.auth_salt.len(), 16);
    assert!(same_kek(&kek, &h.client.unseal(&slot, PW).unwrap()));
}

#[test]
fn helper_failures_map_to_specific_errors() {
    let h = helper();
    let (_, slot) = h.client.seal(PW).unwrap();
    assert!(matches!(
        h.client.unseal(&slot, b"wrong"),
        Err(Error::TpmAuthFailed)
    ));
    let mut foreign = slot.clone();
    foreign.srk_name[3] ^= 1;
    assert!(matches!(
        h.client.unseal(&foreign, PW),
        Err(Error::TpmParentMismatch)
    ));
    let mut corrupt = slot.clone();
    corrupt.public = vec![0xff; 5];
    assert!(matches!(
        h.client.unseal(&corrupt, PW),
        Err(Error::TpmSlotMalformed(_))
    ));
}

#[test]
fn an_empty_password_is_refused_locally() {
    let h = helper();
    assert!(matches!(h.client.seal(b""), Err(Error::SecretRequired)));
    let (_, slot) = h.client.seal(PW).unwrap();
    assert!(matches!(
        h.client.unseal(&slot, b""),
        Err(Error::SecretRequired)
    ));
}

#[test]
fn a_missing_helper_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let client = TpmClient::new(dir.path().join("nobody-home.sock"));
    assert!(matches!(client.seal(PW), Err(Error::TpmUnavailable(_))));
    assert!(matches!(client.status(), Err(Error::TpmUnavailable(_))));
}

#[test]
fn status_comes_through() {
    let h = helper();
    let s = h.client.status().unwrap();
    assert_eq!(s.parent, aleph_tpm_proto::Parent::AlephPrimary);
}

#[test]
fn a_tpm_slot_unlocks_a_vault_end_to_end() {
    let h = helper();
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::generate().unwrap();
    v.add_recovery_slot("recovery", &rk.recipient().public_key())
        .unwrap();
    let (kek, slot) = h.client.seal(PW).unwrap();
    let id = v.add_keyslot("tpm", SlotKind::Tpm(slot), &kek).unwrap();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    let stored = locked
        .keyslots()
        .find_map(|s| match &s.kind {
            SlotKind::Tpm(t) if s.id == id => Some(t.clone()),
            _ => None,
        })
        .unwrap();
    let kek = h.client.unseal(&stored, PW).unwrap();
    assert_eq!(locked.unlock(id, &kek).unwrap().vault_id(), v.vault_id());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-unlock`
Expected: the build fails because `tpm::TpmClient` does not exist yet.

- [ ] **Step 3: Implement**

Replace `crates/aleph-unlock/src/tpm.rs` with:

```rust
//! TPM keyslots through `aleph-tpmd` (spec §5). This side never touches
//! the TPM: it sends the login password to the helper over its socket and
//! gets a KEK back. The helper binds every object to our uid, which it
//! reads from the socket.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use aleph_core::{Kek, TpmSlot};
use aleph_tpm_proto::{
    Failure, Request, Response, SealedObject, Secret, Status, read_frame, write_frame,
};

use crate::error::{Error, Result};

/// Where `aleph-tpmd.socket` listens.
pub const DEFAULT_SOCKET: &str = "/run/aleph/tpm.sock";
/// How long to wait for the helper (a real TPM can take a second or two).
pub const TIMEOUT: Duration = Duration::from_secs(30);

pub struct TpmClient {
    socket: PathBuf,
}

impl TpmClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// `ALEPH_TPM_SOCKET`, else [`DEFAULT_SOCKET`].
    pub fn from_env() -> Self {
        Self::new(std::env::var("ALEPH_TPM_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.into()))
    }

    /// Seal a fresh KEK under the login password. Returns the KEK and the
    /// slot parameters to store in the vault.
    pub fn seal(&self, password: &[u8]) -> Result<(Kek, TpmSlot)> {
        if password.is_empty() {
            return Err(Error::SecretRequired);
        }
        match self.call(&Request::Seal {
            secret: Secret(password.to_vec()),
        })? {
            Response::Sealed { object, kek } => Ok((to_kek(&kek)?, to_slot(object)?)),
            other => Err(unexpected(other)),
        }
    }

    /// Unseal a slot's KEK with the login password.
    pub fn unseal(&self, slot: &TpmSlot, password: &[u8]) -> Result<Kek> {
        if password.is_empty() {
            return Err(Error::SecretRequired);
        }
        let object = SealedObject {
            public: slot.public.clone(),
            private: slot.private.clone(),
            auth_salt: slot.auth_salt.to_vec(),
            srk_name: slot.srk_name.clone(),
        };
        match self.call(&Request::Unseal {
            object,
            secret: Secret(password.to_vec()),
        })? {
            Response::Unsealed { kek } => to_kek(&kek),
            other => Err(unexpected(other)),
        }
    }

    /// TPM state for `aleph setup`.
    pub fn status(&self) -> Result<Status> {
        match self.call(&Request::Status {})? {
            Response::Status(s) => Ok(s),
            other => Err(unexpected(other)),
        }
    }

    fn call(&self, request: &Request) -> Result<Response> {
        let unavailable = |e: &dyn std::fmt::Display| Error::TpmUnavailable(e.to_string());
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| unavailable(&e))?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .map_err(|e| unavailable(&e))?;
        stream
            .set_write_timeout(Some(TIMEOUT))
            .map_err(|e| unavailable(&e))?;
        write_frame(&mut stream, request).map_err(|e| unavailable(&e))?;
        read_frame(&mut stream).map_err(|e| unavailable(&e))
    }
}

fn to_kek(secret: &Secret) -> Result<Kek> {
    Ok(Kek::try_init(|buf| {
        if secret.0.len() != buf.len() {
            return Err(aleph_core::Error::UnwrapFailed);
        }
        buf.copy_from_slice(&secret.0);
        Ok(())
    })?)
}

fn to_slot(object: SealedObject) -> Result<TpmSlot> {
    let auth_salt = object
        .auth_salt
        .as_slice()
        .try_into()
        .map_err(|_| Error::TpmSlotMalformed("auth_salt must be 16 bytes".into()))?;
    Ok(TpmSlot {
        public: object.public,
        private: object.private,
        auth_salt,
        srk_name: object.srk_name,
    })
}

fn unexpected(response: Response) -> Error {
    match response {
        Response::Failed(f) => match f {
            Failure::AuthFailed => Error::TpmAuthFailed,
            Failure::Lockout => Error::TpmLockout,
            Failure::RateLimited => Error::TpmRateLimited,
            Failure::WrongUser => Error::TpmWrongUser,
            Failure::ParentMismatch => Error::TpmParentMismatch,
            Failure::NoParent => Error::TpmNoParent,
            Failure::Malformed(m) => Error::TpmSlotMalformed(m),
            Failure::Tpm(m) => Error::Tpm(m),
        },
        other => Error::Tpm(format!("unexpected reply from aleph-tpmd: {other:?}")),
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-unlock && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `tpm_client` `6 passed`.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-unlock
git commit -m "feat(unlock): TPM client for aleph-tpmd" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 4: FIDO2 enroll/unlock with PIN/UV by default, preflight, and a mock

**Files:** Modify `crates/aleph-unlock/Cargo.toml` (add `hmac`, `sha2`), `crates/aleph-unlock/src/lib.rs` (add `pub mod fido2;`); Create `crates/aleph-unlock/src/fido2/{mod,mock}.rs`, `crates/aleph-unlock/tests/fido2.rs`.

**Interfaces:**
- Consumes: `aleph_core::{Fido2Slot { credential_id, salt, uv_required, pin_required }, Kek::try_init, crypto::{hkdf, random_array}}`; Task 3 `Error` FIDO2 variants.
- Produces:
  - `fido2::RP_ID = "aleph"`
  - `DeviceInfo { hmac_secret, pin_set, uv }`
  - `trait Authenticator { info, make_credential(rp_id, pin, uv), has_credential(rp_id, credential_id), hmac_secret(rp_id, credential_id, salt, pin, uv) }`
  - `trait Keys { devices(&mut self) -> Result<Vec<&mut dyn Authenticator>>; any_present(&mut self) -> bool }`
  - `Verification { PinOrUv (default), TouchOnly }`
  - `enroll(&mut dyn Keys, pin, Verification) -> Result<(Kek, Fido2Slot)>`, `unlock(&mut dyn Keys, &Fido2Slot, pin) -> Result<Kek>`
  - `mock::{MockAuthenticator { new, with_pin, with_uv, pub hmac_secret_supported, pub uv_capable, pub touches }, MockKeys { pub devices, one }}`

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-unlock/Cargo.toml` with:

```toml
[package]
name = "aleph-unlock"
description = "TPM (via aleph-tpmd) and FIDO2 key-encryption-key providers for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
aleph-core = { path = "../aleph-core" }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
hmac.workspace = true
sha2.workspace = true
thiserror.workspace = true
zeroize.workspace = true

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
aleph-tpmd = { path = "../aleph-tpmd", features = ["testing"] }
tempfile.workspace = true
```

Replace `crates/aleph-unlock/src/lib.rs` with:

```rust
//! Hardware unlock methods for aleph: each turns a keyslot's stored
//! parameters (plus a password, PIN, or touch) into the slot's KEK.
//! See `docs/superpowers/specs/2026-09-26-aleph-design.md` §5.

pub mod error;
pub mod fido2;
pub mod tpm;

pub use error::{Error, Result};
pub use tpm::TpmClient;
```

Create `crates/aleph-unlock/src/fido2/mod.rs` containing only `pub mod mock;`, `crates/aleph-unlock/src/fido2/mock.rs` containing only `// implemented in step 3`, and `crates/aleph-unlock/tests/fido2.rs`:

```rust
use aleph_core::{LockedVault, RecoveryKey, SlotKind, UnlockedVault};
use aleph_unlock::Error;
use aleph_unlock::fido2::mock::{MockAuthenticator, MockKeys};
use aleph_unlock::fido2::{self, Keys, Verification};

fn same_kek(a: &aleph_core::Kek, b: &aleph_core::Kek) -> bool {
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(a, b"t").unwrap();
    aleph_core::KeyHandle::unwraps_to(b, &w, b"t", &mk.id())
}

const PIN: &str = "123456";

#[test]
fn a_pin_key_enrolls_with_the_pin_and_unlocks_with_it() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    assert!(slot.pin_required && !slot.uv_required);
    assert_eq!(keys.devices[0].touches, 2, "enrollment is two touches");
    let back = fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap();
    assert_eq!(keys.devices[0].touches, 3, "unlock is one touch");
    assert!(same_kek(&kek, &back));
}

#[test]
fn by_default_the_pin_is_required_at_enroll_and_unlock() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    assert!(matches!(
        fido2::enroll(&mut keys, None, Verification::PinOrUv),
        Err(Error::Fido2PinRequired)
    ));
    let (_, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    assert!(matches!(
        fido2::unlock(&mut keys, &slot, None),
        Err(Error::Fido2PinRequired)
    ));
    assert!(matches!(
        fido2::unlock(&mut keys, &slot, Some("000000")),
        Err(Error::Fido2PinInvalid)
    ));
}

#[test]
fn a_key_with_built_in_uv_uses_it_instead_of_a_pin() {
    let mut keys = MockKeys::one(MockAuthenticator::with_uv());
    let (kek, slot) = fido2::enroll(&mut keys, None, Verification::PinOrUv).unwrap();
    assert!(slot.uv_required && !slot.pin_required);
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, None).unwrap()
    ));
}

/// A key with neither PIN nor UV would let anyone holding it unlock, so by
/// default it is refused; touch-only is an explicit opt-in.
#[test]
fn a_bare_key_is_refused_unless_touch_only_is_chosen() {
    let mut keys = MockKeys::one(MockAuthenticator::new());
    assert!(matches!(
        fido2::enroll(&mut keys, None, Verification::PinOrUv),
        Err(Error::Fido2PinNotSet)
    ));
    let (kek, slot) = fido2::enroll(&mut keys, None, Verification::TouchOnly).unwrap();
    assert!(!slot.uv_required && !slot.pin_required);
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, None).unwrap()
    ));
}

#[test]
fn a_key_without_hmac_secret_is_refused() {
    let mut key = MockAuthenticator::with_pin(PIN);
    key.hmac_secret_supported = false;
    let mut keys = MockKeys::one(key);
    assert!(matches!(
        fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv),
        Err(Error::Fido2Unsupported)
    ));
}

#[test]
fn enrollment_needs_exactly_one_key() {
    let mut none = MockKeys::default();
    assert!(matches!(
        fido2::enroll(&mut none, Some(PIN), Verification::PinOrUv),
        Err(Error::Fido2NoDevice)
    ));
    let mut two = MockKeys {
        devices: vec![
            MockAuthenticator::with_pin(PIN),
            MockAuthenticator::with_pin(PIN),
        ],
    };
    assert!(matches!(
        fido2::enroll(&mut two, Some(PIN), Verification::PinOrUv),
        Err(Error::Fido2MultipleDevices)
    ));
}

/// With several keys plugged in, unlock finds the one holding the
/// credential without touching the others (spec §5: preflight).
#[test]
fn unlock_picks_the_right_key_among_several_and_touches_only_it() {
    let mut enrolled = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (kek, slot) = fido2::enroll(&mut enrolled, Some(PIN), Verification::PinOrUv).unwrap();
    let right = enrolled.devices.pop().unwrap();
    let mut keys = MockKeys {
        devices: vec![
            MockAuthenticator::with_pin(PIN),
            right,
            MockAuthenticator::with_pin(PIN),
        ],
    };
    let back = fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap();
    assert!(same_kek(&kek, &back));
    assert_eq!(keys.devices[0].touches, 0);
    assert_eq!(keys.devices[2].touches, 0);
}

#[test]
fn no_key_or_the_wrong_key_is_a_specific_error() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (_, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    assert!(matches!(
        fido2::unlock(&mut MockKeys::default(), &slot, Some(PIN)),
        Err(Error::Fido2NoDevice)
    ));
    let mut other = MockKeys::one(MockAuthenticator::with_pin(PIN));
    assert!(matches!(
        fido2::unlock(&mut other, &slot, Some(PIN)),
        Err(Error::Fido2NoCredential)
    ));
}

#[test]
fn repeated_wrong_pins_block_the_key() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (_, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    let mut last = None;
    for _ in 0..8 {
        last = Some(fido2::unlock(&mut keys, &slot, Some("000000")));
    }
    assert!(matches!(last, Some(Err(Error::Fido2PinBlocked))));
    assert!(matches!(
        fido2::unlock(&mut keys, &slot, Some(PIN)),
        Err(Error::Fido2PinBlocked)
    ));
}

#[test]
fn a_pin_offered_to_a_touch_only_slot_is_ignored() {
    // The prompter may send a PIN it collected for another slot; using it
    // would switch the key to its UV secret and yield the wrong KEK.
    let mut keys = MockKeys::one(MockAuthenticator::new());
    let (kek, slot) = fido2::enroll(&mut keys, None, Verification::TouchOnly).unwrap();
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap()
    ));
}

/// Without verification the key returns its other secret: a thief who can
/// touch a PIN key but not unlock it gets the wrong KEK.
#[test]
fn a_touch_without_verification_cannot_open_a_verified_slot() {
    let mut keys = MockKeys::one(MockAuthenticator::with_uv());
    let (kek, mut slot) = fido2::enroll(&mut keys, None, Verification::PinOrUv).unwrap();
    slot.uv_required = false;
    assert!(!same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, None).unwrap()
    ));
}

#[test]
fn any_present_reflects_connected_keys() {
    assert!(!MockKeys::default().any_present());
    assert!(MockKeys::one(MockAuthenticator::new()).any_present());
}

#[test]
fn a_fido2_slot_unlocks_a_vault_end_to_end() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::generate().unwrap();
    v.add_recovery_slot("recovery", &rk.recipient().public_key())
        .unwrap();
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    let id = v
        .add_keyslot("yubikey", SlotKind::Fido2(slot), &kek)
        .unwrap();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    let stored = locked
        .keyslots()
        .find_map(|s| match &s.kind {
            SlotKind::Fido2(f) if s.id == id => Some(f.clone()),
            _ => None,
        })
        .unwrap();
    let kek = fido2::unlock(&mut keys, &stored, Some(PIN)).unwrap();
    assert_eq!(locked.unlock(id, &kek).unwrap().vault_id(), v.vault_id());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p aleph-unlock --test fido2`
Expected: the build fails because `fido2::{enroll, unlock, Keys, Verification}` and `mock::{MockAuthenticator, MockKeys}` do not exist yet.

- [ ] **Step 3: Implement**

Replace `crates/aleph-unlock/src/fido2/mod.rs` with:

```rust
//! FIDO2 keyslots via the `hmac-secret` extension (spec §5).
//!
//! - **Enrollment** needs exactly one key plugged in, one that lists
//!   `hmac-secret`. It creates a non-resident credential for the constant
//!   RP ID [`RP_ID`] with credential protection "UV optional with
//!   credential ID". By default ([`Verification::PinOrUv`]) it requires
//!   user verification: the key's PIN if it has one, else on-device UV. A
//!   key with neither is refused unless the user opts into
//!   [`Verification::TouchOnly`].
//! - **The KEK** is `HKDF(hmac-secret(salt), "aleph fido2 v1")`. The key
//!   returns a different secret with and without UV, so a slot enrolled
//!   with UV cannot be opened by a touch alone. That is why credProtect
//!   level 2 suffices: level 3 would also hide the credential from the
//!   no-touch preflight, and choosing among several keys would then burn
//!   PIN retries on the wrong ones.
//! - **Unlock** preflights every connected key with a no-touch assertion
//!   to find the one holding the slot's credential, then asks only that
//!   key for a touch.
//!
//! All hardware access goes through [`Keys`] and [`Authenticator`], so the
//! logic is tested against [`mock::MockKeys`].

pub mod mock;

use aleph_core::{Fido2Slot, Kek};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Every aleph FIDO2 credential uses this RP ID. It is not stored in the
/// slot, because the header it would be read from is unauthenticated
/// before unlock.
pub const RP_ID: &str = "aleph";
const KEK_INFO: &[u8] = b"aleph fido2 v1";

/// What a key supports, from `authenticatorGetInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub hmac_secret: bool,
    /// A client PIN is set.
    pub pin_set: bool,
    /// Built-in user verification (fingerprint etc.) is configured.
    pub uv: bool,
}

/// One connected FIDO2 key.
pub trait Authenticator {
    fn info(&mut self) -> Result<DeviceInfo>;

    /// Create a non-resident credential with `hmac-secret` enabled and
    /// credProtect "UV optional with credential ID". Requires a touch.
    fn make_credential(&mut self, rp_id: &str, pin: Option<&str>, uv: bool) -> Result<Vec<u8>>;

    /// Whether this key holds `credential_id`: an assertion without user
    /// presence (no touch, no PIN).
    fn has_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> Result<bool>;

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

/// The set of keys currently connected.
pub trait Keys {
    fn devices(&mut self) -> Result<Vec<&mut dyn Authenticator>>;

    /// True if any key is connected (drives the prompter's "insert your
    /// key" screen).
    fn any_present(&mut self) -> bool {
        self.devices().is_ok_and(|d| !d.is_empty())
    }
}

/// How an enrolled key must verify its user at unlock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verification {
    /// The key's PIN, or on-device UV. The default.
    #[default]
    PinOrUv,
    /// A touch alone. Anyone holding the key can unlock; opt-in only.
    TouchOnly,
}

/// Enroll the single connected key: create a credential, then evaluate it
/// once to derive the KEK (two touches, as with `systemd-cryptenroll`).
pub fn enroll(
    keys: &mut dyn Keys,
    pin: Option<&str>,
    policy: Verification,
) -> Result<(Kek, Fido2Slot)> {
    let mut devices = keys.devices()?;
    let device = match devices.len() {
        0 => return Err(Error::Fido2NoDevice),
        1 => &mut devices[0],
        _ => return Err(Error::Fido2MultipleDevices),
    };
    let info = device.info()?;
    if !info.hmac_secret {
        return Err(Error::Fido2Unsupported);
    }
    // A PIN, when the key has one, performs UV; otherwise use built-in UV.
    let (pin, uv) = match policy {
        Verification::PinOrUv if info.pin_set => (Some(pin.ok_or(Error::Fido2PinRequired)?), false),
        Verification::PinOrUv if info.uv => (None, true),
        Verification::PinOrUv => return Err(Error::Fido2PinNotSet),
        Verification::TouchOnly => (None, false),
    };
    let credential_id = device.make_credential(RP_ID, pin, uv)?;
    let salt = aleph_core::crypto::random_array::<32>()?;
    let secret = device.hmac_secret(RP_ID, &credential_id, &salt, pin, uv)?;
    let slot = Fido2Slot {
        credential_id,
        salt,
        uv_required: uv,
        pin_required: pin.is_some(),
    };
    Ok((derive_kek(&secret)?, slot))
}

/// Recover a FIDO2 slot's KEK from whichever connected key holds it.
pub fn unlock(keys: &mut dyn Keys, slot: &Fido2Slot, pin: Option<&str>) -> Result<Kek> {
    if slot.pin_required && pin.is_none() {
        return Err(Error::Fido2PinRequired);
    }
    // A PIN given for a slot enrolled without one would switch the key to
    // its UV secret and yield the wrong KEK: ignore it.
    let pin = if slot.pin_required { pin } else { None };
    let mut devices = keys.devices()?;
    if devices.is_empty() {
        return Err(Error::Fido2NoDevice);
    }
    for device in devices.iter_mut() {
        if device.has_credential(RP_ID, &slot.credential_id)? {
            let secret = device.hmac_secret(
                RP_ID,
                &slot.credential_id,
                &slot.salt,
                pin,
                slot.uv_required,
            )?;
            return derive_kek(&secret);
        }
    }
    Err(Error::Fido2NoCredential)
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
//! Software FIDO2 keys for tests (here, in the daemon, and in the GUI).
//! They model what aleph depends on: `hmac-secret` support, PIN checks with
//! a retry counter, on-device UV, per-credential secrets scoped to an RP,
//! a no-touch existence check, and an `hmac-secret` output that differs
//! with user verification. Not a CTAP implementation; no security.

use std::collections::HashMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{Authenticator, DeviceInfo, Keys};
use crate::error::{Error, Result};

const PIN_RETRIES: u8 = 8;

pub struct MockAuthenticator {
    pub hmac_secret_supported: bool,
    pin: Option<String>,
    pub uv_capable: bool,
    pin_retries: u8,
    /// Credential ID → (RP ID, per-credential secret).
    credentials: HashMap<Vec<u8>, (String, [u8; 32])>,
    /// Touches performed on this key.
    pub touches: usize,
}

impl MockAuthenticator {
    /// A key with no PIN and no built-in UV.
    pub fn new() -> Self {
        Self {
            hmac_secret_supported: true,
            pin: None,
            uv_capable: false,
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

    /// A key with built-in UV (e.g. a fingerprint) and no PIN.
    pub fn with_uv() -> Self {
        Self {
            uv_capable: true,
            ..Self::new()
        }
    }

    /// Check user verification as CTAP2 would, then take a touch.
    ///
    /// - A PIN, if given, must match (wrong PINs count down to a block).
    /// - `uv` without a PIN needs built-in UV.
    /// - Creating a credential on a key with a PIN set requires the PIN
    ///   (or built-in UV); an assertion may be touch-only.
    fn verify_and_touch(&mut self, pin: Option<&str>, uv: bool, creating: bool) -> Result<()> {
        if self.pin_retries == 0 {
            return Err(Error::Fido2PinBlocked);
        }
        match (&self.pin, pin) {
            (None, Some(_)) => return Err(Error::Fido2PinNotSet),
            (Some(expected), Some(given)) if expected != given => {
                self.pin_retries -= 1;
                return Err(if self.pin_retries == 0 {
                    Error::Fido2PinBlocked
                } else {
                    Error::Fido2PinInvalid
                });
            }
            (Some(_), None) if creating && !(uv && self.uv_capable) => {
                return Err(Error::Fido2PinRequired);
            }
            _ => {}
        }
        if uv && pin.is_none() && !self.uv_capable {
            return Err(Error::Fido2Unsupported);
        }
        self.pin_retries = PIN_RETRIES;
        self.touches += 1;
        Ok(())
    }
}

impl Default for MockAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator for MockAuthenticator {
    fn info(&mut self) -> Result<DeviceInfo> {
        Ok(DeviceInfo {
            hmac_secret: self.hmac_secret_supported,
            pin_set: self.pin.is_some(),
            uv: self.uv_capable,
        })
    }

    fn make_credential(&mut self, rp_id: &str, pin: Option<&str>, uv: bool) -> Result<Vec<u8>> {
        if !self.hmac_secret_supported {
            return Err(Error::Fido2Unsupported);
        }
        self.verify_and_touch(pin, uv, true)?;
        let id = aleph_core::crypto::random_array::<32>()?.to_vec();
        let secret = aleph_core::crypto::random_array::<32>()?;
        self.credentials
            .insert(id.clone(), (rp_id.to_string(), secret));
        Ok(id)
    }

    fn has_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> Result<bool> {
        Ok(self
            .credentials
            .get(credential_id)
            .is_some_and(|(rp, _)| rp == rp_id))
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let (cred_rp, secret) = self
            .credentials
            .get(credential_id)
            .cloned()
            .ok_or(Error::Fido2NoCredential)?;
        if cred_rp != rp_id {
            return Err(Error::Fido2NoCredential);
        }
        self.verify_and_touch(pin, uv, false)?;
        // CTAP2: supplying a PIN performs user verification, and the
        // authenticator then uses a different secret (CredRandomWithUV).
        let verified = uv || pin.is_some();
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("any key length");
        mac.update(&[u8::from(verified)]);
        mac.update(salt);
        Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
    }
}

/// A set of mock keys "plugged in".
#[derive(Default)]
pub struct MockKeys {
    pub devices: Vec<MockAuthenticator>,
}

impl MockKeys {
    pub fn one(device: MockAuthenticator) -> Self {
        Self {
            devices: vec![device],
        }
    }
}

impl Keys for MockKeys {
    fn devices(&mut self) -> Result<Vec<&mut dyn Authenticator>> {
        Ok(self
            .devices
            .iter_mut()
            .map(|d| d as &mut dyn Authenticator)
            .collect())
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-unlock && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `fido2` `13 passed`; `tpm_client` still `6 passed`.

- [ ] **Step 5: Confirm the FIDO2 tests have teeth**

Revert one at a time, see the test FAIL, then restore and see it pass:
- In `unlock`, replace `if device.has_credential(RP_ID, &slot.credential_id)? {` with `if true {`. Test: `--test fido2 unlock_picks_the_right_key`.
- In `enroll`, replace `Verification::PinOrUv => return Err(Error::Fido2PinNotSet),` with `Verification::PinOrUv => (None, false),`. Test: `--test fido2 a_bare_key_is_refused`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-unlock
git commit -m "feat(unlock): FIDO2 with PIN/UV by default, multi-key preflight, mock keys" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 5: libfido2 backend, systemd units, docs, and spec corrections

**Files:**
- Modify: `crates/aleph-unlock/Cargo.toml` (add `fido2-rs`), `crates/aleph-unlock/src/fido2/mod.rs` (add `pub mod libfido2;`), `README.md`, `docs/superpowers/specs/2026-09-26-aleph-design.md`
- Create: `crates/aleph-unlock/src/fido2/libfido2.rs`, `crates/aleph-unlock/tests/fido2_hardware.rs`, `packaging/systemd/aleph-tpmd.{socket,service}`, `docs/testing.md`

**Interfaces:**
- Consumes: Task 4 traits.
- Produces: `fido2::libfido2::{Libfido2Keys::new(), Libfido2Authenticator}`. It re-enumerates keys on every call, checks `hmac-secret` via `getInfo`, uses `Protection::UvOptionalWithId`, and preflights with `up = false`.

- [ ] **Step 1: Write the failing test**

Replace `crates/aleph-unlock/Cargo.toml` with:

```toml
[package]
name = "aleph-unlock"
description = "TPM (via aleph-tpmd) and FIDO2 key-encryption-key providers for the aleph keyring"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
aleph-core = { path = "../aleph-core" }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
fido2-rs.workspace = true
hmac.workspace = true
sha2.workspace = true
thiserror.workspace = true
zeroize.workspace = true

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
aleph-tpmd = { path = "../aleph-tpmd", features = ["testing"] }
tempfile.workspace = true
```

Replace `crates/aleph-unlock/src/fido2/mod.rs` with (Task 4's version plus `pub mod libfido2;`):

```rust
//! FIDO2 keyslots via the `hmac-secret` extension (spec §5).
//!
//! - **Enrollment** needs exactly one key plugged in, one that lists
//!   `hmac-secret`. It creates a non-resident credential for the constant
//!   RP ID [`RP_ID`] with credential protection "UV optional with
//!   credential ID". By default ([`Verification::PinOrUv`]) it requires
//!   user verification: the key's PIN if it has one, else on-device UV. A
//!   key with neither is refused unless the user opts into
//!   [`Verification::TouchOnly`].
//! - **The KEK** is `HKDF(hmac-secret(salt), "aleph fido2 v1")`. The key
//!   returns a different secret with and without UV, so a slot enrolled
//!   with UV cannot be opened by a touch alone. That is why credProtect
//!   level 2 suffices: level 3 would also hide the credential from the
//!   no-touch preflight, and choosing among several keys would then burn
//!   PIN retries on the wrong ones.
//! - **Unlock** preflights every connected key with a no-touch assertion
//!   to find the one holding the slot's credential, then asks only that
//!   key for a touch.
//!
//! All hardware access goes through [`Keys`] and [`Authenticator`], so the
//! logic is tested against [`mock::MockKeys`].

pub mod libfido2;
pub mod mock;

use aleph_core::{Fido2Slot, Kek};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Every aleph FIDO2 credential uses this RP ID. It is not stored in the
/// slot, because the header it would be read from is unauthenticated
/// before unlock.
pub const RP_ID: &str = "aleph";
const KEK_INFO: &[u8] = b"aleph fido2 v1";

/// What a key supports, from `authenticatorGetInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub hmac_secret: bool,
    /// A client PIN is set.
    pub pin_set: bool,
    /// Built-in user verification (fingerprint etc.) is configured.
    pub uv: bool,
}

/// One connected FIDO2 key.
pub trait Authenticator {
    fn info(&mut self) -> Result<DeviceInfo>;

    /// Create a non-resident credential with `hmac-secret` enabled and
    /// credProtect "UV optional with credential ID". Requires a touch.
    fn make_credential(&mut self, rp_id: &str, pin: Option<&str>, uv: bool) -> Result<Vec<u8>>;

    /// Whether this key holds `credential_id`: an assertion without user
    /// presence (no touch, no PIN).
    fn has_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> Result<bool>;

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

/// The set of keys currently connected.
pub trait Keys {
    fn devices(&mut self) -> Result<Vec<&mut dyn Authenticator>>;

    /// True if any key is connected (drives the prompter's "insert your
    /// key" screen).
    fn any_present(&mut self) -> bool {
        self.devices().is_ok_and(|d| !d.is_empty())
    }
}

/// How an enrolled key must verify its user at unlock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verification {
    /// The key's PIN, or on-device UV. The default.
    #[default]
    PinOrUv,
    /// A touch alone. Anyone holding the key can unlock; opt-in only.
    TouchOnly,
}

/// Enroll the single connected key: create a credential, then evaluate it
/// once to derive the KEK (two touches, as with `systemd-cryptenroll`).
pub fn enroll(
    keys: &mut dyn Keys,
    pin: Option<&str>,
    policy: Verification,
) -> Result<(Kek, Fido2Slot)> {
    let mut devices = keys.devices()?;
    let device = match devices.len() {
        0 => return Err(Error::Fido2NoDevice),
        1 => &mut devices[0],
        _ => return Err(Error::Fido2MultipleDevices),
    };
    let info = device.info()?;
    if !info.hmac_secret {
        return Err(Error::Fido2Unsupported);
    }
    // A PIN, when the key has one, performs UV; otherwise use built-in UV.
    let (pin, uv) = match policy {
        Verification::PinOrUv if info.pin_set => (Some(pin.ok_or(Error::Fido2PinRequired)?), false),
        Verification::PinOrUv if info.uv => (None, true),
        Verification::PinOrUv => return Err(Error::Fido2PinNotSet),
        Verification::TouchOnly => (None, false),
    };
    let credential_id = device.make_credential(RP_ID, pin, uv)?;
    let salt = aleph_core::crypto::random_array::<32>()?;
    let secret = device.hmac_secret(RP_ID, &credential_id, &salt, pin, uv)?;
    let slot = Fido2Slot {
        credential_id,
        salt,
        uv_required: uv,
        pin_required: pin.is_some(),
    };
    Ok((derive_kek(&secret)?, slot))
}

/// Recover a FIDO2 slot's KEK from whichever connected key holds it.
pub fn unlock(keys: &mut dyn Keys, slot: &Fido2Slot, pin: Option<&str>) -> Result<Kek> {
    if slot.pin_required && pin.is_none() {
        return Err(Error::Fido2PinRequired);
    }
    // A PIN given for a slot enrolled without one would switch the key to
    // its UV secret and yield the wrong KEK: ignore it.
    let pin = if slot.pin_required { pin } else { None };
    let mut devices = keys.devices()?;
    if devices.is_empty() {
        return Err(Error::Fido2NoDevice);
    }
    for device in devices.iter_mut() {
        if device.has_credential(RP_ID, &slot.credential_id)? {
            let secret = device.hmac_secret(
                RP_ID,
                &slot.credential_id,
                &slot.salt,
                pin,
                slot.uv_required,
            )?;
            return derive_kek(&secret);
        }
    }
    Err(Error::Fido2NoCredential)
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
        assert!(matches!(map_code(0x35), Error::Fido2PinNotSet));
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

- [ ] **Step 3: Implement, add the units and docs**

Insert above the `#[cfg(test)]` line in `crates/aleph-unlock/src/fido2/libfido2.rs`:

```rust
//! [`Keys`] and [`Authenticator`] backed by Yubico's libfido2 (the library
//! `systemd-cryptenroll` uses), through the `fido2-rs` bindings.
//!
//! Not exercised in CI (no virtual authenticator without root); covered
//! by the opt-in hardware test and `docs/testing.md`.

use fido2_rs::assertion::AssertRequest;
use fido2_rs::credentials::{CoseType, Credential, Extensions, Opt, Protection};
use fido2_rs::device::{Device, DeviceList};
use fido2_rs::error::Error as FidoRsError;
use zeroize::Zeroizing;

use super::{Authenticator, DeviceInfo, Keys};
use crate::error::{Error, Result};

/// One connected key, opened when enumerated.
pub struct Libfido2Authenticator {
    device: Device,
}

impl Authenticator for Libfido2Authenticator {
    fn info(&mut self) -> Result<DeviceInfo> {
        let info = self.device.info().map_err(map_err)?;
        Ok(DeviceInfo {
            hmac_secret: info.extensions().contains(&"hmac-secret"),
            pin_set: self.device.has_pin(),
            uv: self.device.has_uv(),
        })
    }

    fn make_credential(&mut self, rp_id: &str, pin: Option<&str>, uv: bool) -> Result<Vec<u8>> {
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
        cred.set_extension(Extensions::HMAC_SECRET | Extensions::CRED_PROTECT)
            .map_err(map_err)?;
        // Level 2: the credential is usable without UV when its ID is
        // given, so the no-touch preflight can find it. Security comes from
        // requiring UV/PIN at unlock (the UV hmac-secret differs).
        cred.set_protection(Protection::UvOptionalWithId)
            .map_err(map_err)?;
        cred.set_rk(Opt::False).map_err(map_err)?;
        if uv {
            cred.set_uv(Opt::True).map_err(map_err)?;
        }
        self.device
            .make_credential(&mut cred, pin)
            .map_err(map_err)?;
        Ok(cred.id().to_vec())
    }

    fn has_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> Result<bool> {
        let mut req = AssertRequest::new().map_err(map_err)?;
        req.set_rp(rp_id).map_err(map_err)?;
        req.set_client_data_hash(aleph_core::crypto::random_array::<32>()?)
            .map_err(map_err)?;
        req.set_allow_credential(credential_id).map_err(map_err)?;
        req.set_up(Opt::False).map_err(map_err)?;
        match self.device.get_assertion(req, None) {
            Ok(_) => Ok(true),
            Err(e) => match map_err(e) {
                Error::Fido2NoCredential => Ok(false),
                other => Err(other),
            },
        }
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
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
        let assertions = self.device.get_assertion(req, pin).map_err(map_err)?;
        let assertion = assertions.iter().next().ok_or(Error::Fido2NoCredential)?;
        let secret: [u8; 32] = assertion
            .hmac_secret()
            .try_into()
            .map_err(|_| Error::Fido2Unsupported)?;
        Ok(Zeroizing::new(secret))
    }
}

/// The FIDO2 keys connected right now, re-enumerated on every call.
#[derive(Default)]
pub struct Libfido2Keys {
    open: Vec<Libfido2Authenticator>,
}

impl Libfido2Keys {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Keys for Libfido2Keys {
    fn devices(&mut self) -> Result<Vec<&mut dyn Authenticator>> {
        self.open.clear();
        for info in DeviceList::list_devices(16).map_err(map_err)? {
            // A key that fails to open (unplugged mid-scan, not FIDO2) is
            // skipped rather than failing the whole scan.
            if let Ok(device) = info.open()
                && device.is_fido2()
            {
                self.open.push(Libfido2Authenticator { device });
            }
        }
        Ok(self
            .open
            .iter_mut()
            .map(|d| d as &mut dyn Authenticator)
            .collect())
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
const FIDO_ERR_PIN_NOT_SET: i32 = 0x35;
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
        FIDO_ERR_PIN_NOT_SET => Error::Fido2PinNotSet,
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
//!
//! With one key plugged in (PIN set, or built-in UV):
//! `ALEPH_FIDO2_PIN=<pin, if set> cargo test -p aleph-unlock --test fido2_hardware -- --ignored`
//! Touch the key twice to enroll, then once to unlock.

use aleph_unlock::fido2::libfido2::Libfido2Keys;
use aleph_unlock::fido2::{self, Keys, Verification};

#[test]
#[ignore]
fn hardware_key_enroll_and_unlock() {
    let pin = std::env::var("ALEPH_FIDO2_PIN").ok();
    let mut keys = Libfido2Keys::new();
    assert!(keys.any_present(), "plug in a FIDO2 key");
    eprintln!("touch the key twice to enroll, then once to unlock");
    let (kek, slot) = fido2::enroll(&mut keys, pin.as_deref(), Verification::PinOrUv).unwrap();
    let back = fido2::unlock(&mut keys, &slot, pin.as_deref()).unwrap();
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(&kek, b"t").unwrap();
    assert!(aleph_core::KeyHandle::unwraps_to(&back, &w, b"t", &mk.id()));
}
```

Create `packaging/systemd/aleph-tpmd.socket`:

```ini
[Unit]
Description=aleph keyring TPM helper socket
Documentation=https://github.com/kisom/aleph-keyring

[Socket]
ListenStream=/run/aleph/tpm.sock
# Any local user may connect; the helper binds every object to the
# caller's uid (SO_PEERCRED), so access control is per uid, not per file.
SocketMode=0666
DirectoryMode=0755
Accept=no

[Install]
WantedBy=sockets.target
```

Create `packaging/systemd/aleph-tpmd.service`:

```ini
[Unit]
Description=aleph keyring TPM helper
Documentation=https://github.com/kisom/aleph-keyring
Requires=aleph-tpmd.socket
After=aleph-tpmd.socket

[Service]
ExecStart=/usr/lib/aleph/aleph-tpmd
# A throwaway user whose only privilege is the tss group (spec §5). Users
# themselves are never added to tss.
DynamicUser=yes
SupplementaryGroups=tss
DevicePolicy=closed
DeviceAllow=/dev/tpmrm0 rw
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
UMask=0077
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
  loopback TCP ports (`aleph_tpmd::testing::SwTpm`). They never touch the
  host TPM.
- **`tpm2-tools`**: the fixture uses `tpm2_dictionarylockout` to give
  swtpm realistic dictionary-attack parameters (tss-esapi 7.7 lacks
  `TPM2_DictionaryAttackParameters`).
- **`tpm2-tss`** and **`libfido2`**: build-time libraries.
- Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2`.
  Nix: `swtpm tpm2-tools tpm2-tss libfido2`.

FIDO2 logic is tested against `aleph_unlock::fido2::mock::MockKeys`; no
test in the default run needs a security key.

The systemd units in `packaging/systemd/` are checked with:

```sh
systemd-analyze verify packaging/systemd/aleph-tpmd.socket packaging/systemd/aleph-tpmd.service
systemd-analyze security --offline=true packaging/systemd/aleph-tpmd.service
```

(`verify` needs the `ExecStart` binary to exist; point it at any
executable in a temporary copy of the unit.) Expect no output from
`verify`, and an exposure level of about 0.7 ("SAFE").

## Manual, before each release

These need real hardware and a person. Record the result (pass/fail,
hardware model, firmware) in the release notes.

### FIDO2 security key

1. Plug in exactly one FIDO2 key that supports `hmac-secret` (YubiKey 5,
   SoloKey, Nitrokey 3, …) and has a PIN set (`fido2-token -S <device>`)
   or built-in UV.
2. Run `ALEPH_FIDO2_PIN=<pin, if set> cargo test -p aleph-unlock --test fido2_hardware -- --ignored`.
   Touch twice (enroll), then once (unlock). Expect `1 passed`.
3. Plug in a second FIDO2 key as well and rerun step 2. Expect a failure
   reporting `Fido2MultipleDevices`, since enrollment needs exactly one key.
4. With a wrong `ALEPH_FIDO2_PIN`, expect `Fido2PinInvalid`, and the key's
   retry counter drops by one (`fido2-token -I <device>`).

### Real TPM

As root, or as a user in the `tss` group (the same access `aleph-tpmd`
has). It exercises only the success path, since wrong-password attempts
count towards the real TPM's lockout:

1. Run `cargo test -p aleph-tpmd --test tpm_hardware -- --ignored --nocapture`.
   Expect `1 passed`. It prints the TPM `Status` (parent, whether
   `lockoutAuth` is set, the DA parameters), seals and unseals once, and
   writes nothing persistent to the TPM.
~~~

In `README.md`, make the Crates table and the top of Development read:

```markdown
## Crates

| Crate | Purpose |
|---|---|
| `aleph-core` | Vault format and cryptography (no D-Bus, no hardware) |
| `aleph-tpm-proto` | Wire protocol between `alephd` and the TPM helper |
| `aleph-tpmd` | The TPM helper service (the only process that talks to the TPM) |
| `aleph-unlock` | TPM client and FIDO2 unlock methods that produce keyslot KEKs |

## Development

Tests need `swtpm`, `tpm2-tools`, `tpm2-tss` and `libfido2` (Arch:
`pacman -S swtpm tpm2-tools tpm2-tss libfido2`). Hardware tests are opt-in;
see [docs/testing.md](docs/testing.md).

~~~sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
~~~
```

In `docs/superpowers/specs/2026-09-26-aleph-design.md` §5:

1. Replace the **Sessions** bullet with:
   > - **Sessions:** HMAC sessions salted to the verified parent, with AES-256-CFB parameter encryption in both directions, whichever parent is used. (The SRK fallback's AES-128 affects only how the TPM protects child blobs under that parent, not the session.)
2. In FIDO2 **Enrollment**, replace "`credProtect = 3` (userVerificationRequired)" with:
   > `credProtect = 2` ("UV optional with credential ID"). Level 2 rather than 3: a level-3 credential is invisible to the no-touch preflight below unless UV happens first, so choosing among several keys would burn PIN retries on the wrong ones (`systemd-cryptenroll` uses level 2 for the same reason). The protection level 3 would add is already provided: aleph requires UV/PIN at every unlock of a PIN/UV slot, and the key's `hmac-secret` without UV is a different secret, so a touch alone derives the wrong KEK.
3. In §9 FIDO2, replace "`credProtect`/UV defaults" with "PIN/UV defaults".

- [ ] **Step 4: Run the whole workspace, clippy, fmt, and check the units**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected:
- core unchanged (58 unit, 27 vault, 10 write, golden, zeroize)
- `aleph-tpm-proto` 6, `aleph-tpmd` 2 + 15 + 3, `aleph-unlock` 1 + 13 + 6
- `fido2_hardware` and `tpm_hardware` `1 ignored` each

Then check the units as described in `docs/testing.md`: `systemd-analyze verify` prints nothing, and `systemd-analyze security --offline=true` reports about 0.7 "SAFE".

- [ ] **Step 5 (only with a FIDO2 key and/or TPM access): run the hardware checklist**

Follow `docs/testing.md` "Manual, before each release". If no key or access is available, note "hardware checklist not run" in the commit body.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-unlock packaging/systemd docs/testing.md README.md docs/superpowers/specs/2026-09-26-aleph-design.md
git commit -m "feat(unlock): libfido2 backend; aleph-tpmd units; testing docs; spec corrections" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
