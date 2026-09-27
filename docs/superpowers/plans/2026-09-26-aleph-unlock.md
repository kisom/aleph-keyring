# aleph-tpmd and aleph-unlock Implementation Plan (Plan 2, rewritten)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the TPM helper service `aleph-tpmd` (with its wire protocol `aleph-tpm-proto`) and the `aleph-unlock` crate. `aleph-unlock` turns a TPM or FIDO2 keyslot into its KEK: TPM through the helper, FIDO2 through libfido2.

**Architecture:**
- **`aleph-tpmd`** is the only process that talks to the TPM. It is a socket-activated system service running as a throwaway user in the `tss` group; users are never added to `tss`. It reads the caller's uid from the socket.
  - It seals `be32(uid) ‖ KEK` under an auth value derived from the password, a per-slot salt, and the uid.
  - It unseals only under the parent whose Name the slot recorded, compared before that key salts a session.
  - It serves login uids only, budgets the TPM's shared dictionary-attack counter so that aleph can never cause a TPM lockout, and reports TPM state.
  - Each connection has its own thread and a 2 s deadline for its request; only TPM access is serialized.
- **`aleph-unlock`**'s TPM client only speaks the protocol.
- **FIDO2** runs behind `Keys`/`Authenticator` traits: a software mock for tests and a libfido2 backend. It requires PIN/UV by default, checks `hmac-secret` support, needs exactly one key to enroll, and at unlock asks a lone key directly or preflights several without a touch to find the right one.

**Tech Stack:** Rust 1.98, `tss-esapi` 7.7 (on `tpm2-tss` 4.2), `fido2-rs` 0.6 (on `libfido2` 1.17), `hkdf`/`sha2`/`hmac`, `libc` (`SO_PEERCRED`), `aleph-core`. Tests need `swtpm` 0.10 and `tpm2-tools` 5.8.

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` revision 2 (§3 crates, §5 "TPM, via aleph-tpmd" and "FIDO2", §9 TPM/FIDO2 tests). This plan replaces the pre-review Plan 2, whose in-process TPM design the design review superseded.

**Plan series:** 1 core (done) → 1b core revision 2 (done) → **2 aleph-tpmd + aleph-unlock (this plan)** → 3 `alephd` + CLI basics → 4 session integration → 5 `aleph-gui` → 6 packaging and CI.

**Prerequisites** (once per machine): `sudo pacman -S --needed swtpm tpm2-tools libfido2`.

## Decisions made while prototyping

Every task was prototyped, then replayed from this document on a fresh clone of `master` (code as of `6f073ff`): red, then green, then clippy and fmt clean, with the final tree identical to the prototype. The security properties below were each checked by reverting them: the pinning test fails with the revert and passes once restored. This revision folds in a plan review (a TPM-lockout attack across uids, a slow-client stall, the Name source, FIDO2 preflight errors, and minors); prototyping the fixes also found that `tss-esapi`'s `get_tpm_property` caches values forever.

- **Parent key.** New slots are sealed under aleph's own ECC P-256/AES-256-CFB primary (`noDA`, like the TCG SRK), re-created per use, whose Name is stable per TPM. When `ownerAuth` is set (TPMA_PERMANENT bit 0), the persistent TCG SRK at `0x81000001` is used instead; if it is absent, `NoParent`.
  - The Name is recorded at seal time. To unseal, the helper uses whichever available parent has that Name, so an SRK slot survives `ownerAuth` being cleared. No match is `ParentMismatch`, before any session or password attempt: a slot from another TPM, or an aleph-primary slot once `ownerAuth` is set.
  - The Name compared is `Esys_TR_GetName` of the handle ESYS will salt with, not a separate `ReadPublic` answer.
  - Sessions always use AES-256-CFB parameter encryption. Task 5 corrects the spec, which said AES-128 for the SRK fallback; that AES-128 applies only to how the TPM protects child blobs under the SRK.
- **Uid binding is layered.** The uid is part of the auth-value derivation, so another uid gets `AuthFailed`, and the sealed payload's stored uid is checked (`WrongUser`) as defense in depth.
- **FIDO2 credProtect is level 2, not 3.** A level-3 credential is invisible to the no-touch preflight unless user verification happens first, so choosing among several keys would burn PIN retries on the wrong ones (`systemd-cryptenroll` uses level 2 too). Security is unchanged: PIN/UV is required at every unlock of a PIN/UV slot, and the key's `hmac-secret` without UV is a different value. Task 5 corrects the spec.
- **Dictionary-attack budget, in three layers.** The TPM's failure counter is shared by every user and by `systemd-cryptenroll`, and a lockout survives reboot. A per-uid limit alone did not protect it: 5 failures per uid per minute from a few uids reached swtpm's default 3-try lockout at once.
  - **Global reserve:** once `failed_tries ≥ max_tries − max(1, max_tries/2)`, every unseal is refused with `Busy` without asking the TPM. aleph therefore never causes a lockout, and at least half the budget stays for disk unlock. The cost is a temporary denial of TPM unlock (the spec's §2 now says so).
  - **Per uid:** 2 failures per TPM `recovery_time` (at least 60 s), then `RateLimited`.
  - **Login uids only** (`UID_MIN`–`UID_MAX` from `/etc/login.defs`), else `NotPermitted`. Tests use `Policy::allow_all()`.
  - `Lockout` no longer needs counting as a failure: the reserve refuses long before it.
- **TPM properties are read fresh** with `get_capability`. `Context::get_tpm_property` caches every value for the life of the context, so a long-lived helper would never see the failure counter move or `ownerAuth` change.
- **Status:**
  - `in_lockout` is the TPMA_PERMANENT bit **or** `failed_tries >= max_tries` (so also when `max_tries` is 0), because swtpm never sets the bit.
  - `Status` is an empty struct variant (`Status {}`), because serde's internally tagged unit variants ignore unknown fields even with `deny_unknown_fields`.
- **Connections:** a thread each (at most 64, beyond which `Busy`), a 2 s deadline for the whole request (a per-read timeout alone lets a byte-a-second client stay forever), and one connection in flight per uid (a second gets `Busy` at once), so one user cannot occupy every thread. Only the TPM is serialized, behind its mutex.
- **FIDO2 device selection:** a lone key is asked directly. With several, a key whose preflight errors counts as "not this key"; if none matches, the first error is reported. The credProtect level is passed through `make_credential` (`CRED_PROTECT`), and the mock hides level-3 credentials from preflight as real keys do. libfido2 codes `0x33` → `Fido2PinInvalid`, `0x3F` → `Fido2UvInvalid`, `0x27` → `Fido2Denied`.
- **Test fixture:**
  - swtpm over loopback TCP. tss-esapi 7.7's `swtpm:` TCTI ignores `path=`.
  - It lives in `aleph-tpmd` behind the `testing` feature, shared with `aleph-unlock`'s tests.
  - Port selection, spawning, and the readiness probe are serialized by a process-wide lock, and the probe runs only while our own swtpm is alive. Without this, parallel tests hung: a test's swtpm lost a port race, and its probe connected to another test's single-client swtpm and blocked forever.
  - The fixture sets realistic DA parameters with `tpm2_dictionarylockout`, since tss-esapi 7.7 lacks `TPM2_DictionaryAttackParameters`. It can also provision a persistent SRK and set `ownerAuth` to test the fallback.
- **systemd units** are in `packaging/systemd/`: `Restart=on-failure`, `After=tpm2.target`, `LimitCORE=0`, `TSS2_LOG=all+NONE`, and the helper also sets `PR_SET_DUMPABLE=0`. `systemd-analyze verify` passes and `systemd-analyze security` rates the service 0.7 ("SAFE"). Plan 6 installs them.
- **Not in this plan:**
  - marking TPM slots stale after a failure (daemon, Plan 3/4). Only `AuthFailed` and `WrongUser` may mark a slot stale; `Lockout`, `RateLimited`, `Busy`, and `NotPermitted` say nothing about the slot.
  - fuzzing the frame decoder (Plan 6, with the other `cargo-fuzz` targets)
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
3. **Local users guessing passwords, from as many uids as they have, across many recovery windows,** must never drive the TPM into lockout (which would also block disk unlock and survive reboot), and a slow or idle client must not stall the helper for others. → Task 2 `guessing_from_many_uids_over_many_windows_never_locks_the_tpm`, `failed_unseals_are_rate_limited_per_user`, `only_login_uids_are_served`, `a_trickling_client_is_cut_off_and_does_not_queue_others`.
4. **With several FIDO2 keys plugged in,** unlock must pick the right one without touching or PIN-prompting the others, even if one of them misbehaves, and enrollment must refuse ambiguity. → Task 4 `unlock_picks_the_right_key_among_several_and_touches_only_it`, `a_failing_preflight_does_not_stop_the_search`, `enrollment_needs_exactly_one_key`.
5. **A thief with a PIN-protected FIDO2 key but no PIN** must not unlock. A key with neither PIN nor UV must be refused unless touch-only is explicitly chosen. → Task 4 `a_touch_without_verification_cannot_open_a_verified_slot`, `a_bare_key_is_refused_unless_touch_only_is_chosen`, `by_default_the_pin_is_required_at_enroll_and_unlock`.

## File Structure

```
Cargo.toml                                members grow per task
crates/aleph-tpm-proto/src/lib.rs         Request/Response/Status/Failure, SealedObject, Secret, frames
crates/aleph-tpmd/
  Cargo.toml                              feature `testing` (swtpm fixture)
  src/lib.rs, main.rs                     socket activation (LISTEN_FDS) or --socket
  src/tpm.rs                              Tpm: seal/unseal/status/da_counters, parent chosen by Name
  src/limiter.rs                          global reserve threshold; RateLimiter (2 failures / recovery window / uid)
  src/server.rs                           Policy, Helper::handle, peer_uid, deadline reads, threaded serve
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
  - `Failure { AuthFailed, Lockout, RateLimited, Busy, NotPermitted, WrongUser, ParentMismatch, NoParent, Malformed(String), Tpm(String) }`
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
            Failure::Busy,
            Failure::NotPermitted,
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
    #[error("too many failed attempts from this user; wait for the TPM's recovery time")]
    RateLimited,
    #[error(
        "the TPM's failure budget is exhausted or this user has a request in progress; try later"
    )]
    Busy,
    #[error("this user may not use the TPM helper (not a login uid)")]
    NotPermitted,
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
  - `Tpm::status() -> Result<Status>`, `Tpm::da_counters() -> Result<(failed_tries, max_tries, recovery_time)>`
  - feature `testing` → `Tpm::seal_with_payload_uid(auth_uid, payload_uid, secret)`
  - `TpmError { Unavailable, AuthFailed, Lockout, WrongUser, ParentMismatch, NoParent, Malformed, Tpm }`
  - `limiter::{RateLimiter { blocked(uid, now, window), record_failure(uid, now, window) }, FAILURES_PER_UID = 2, MIN_WINDOW = 60 s, reserve_threshold(max_tries), window(recovery_time_secs)}`
  - `server::Policy { uid_min, uid_max; from_login_defs(&str), system(), allow_all(), allows(uid) }`
  - `Helper::new(Tpm, Policy)`, `.handle(uid, Request) -> Response`, `.handle_at(uid, Request, Instant)`, `.claim(uid) -> Option<Claim>`
  - `server::{peer_uid, serve_connection(&Helper, UnixStream), serve(&UnixListener, Arc<Helper>) -> !, REQUEST_DEADLINE = 2 s, WRITE_TIMEOUT = 5 s, MAX_CONNECTIONS = 64}`
  - feature `testing` → `testing::SwTpm { start(), tcti(), tpm(), helper() (allow-all policy), helper_with(Policy), provision_persistent_srk(), set_owner_auth(), clear_owner_auth(), set_da_parameters(max_tries, recovery_time, lockout_recovery) }`

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
    fn tracked(&self) -> usize {
        self.failures.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(600);

    #[test]
    fn blocks_after_the_per_uid_budget_then_recovers_after_the_window() {
        let t0 = Instant::now();
        let mut l = RateLimiter::default();
        for i in 0..FAILURES_PER_UID {
            assert!(!l.blocked(1000, t0, W), "blocked after {i}");
            l.record_failure(1000, t0, W);
        }
        assert!(l.blocked(1000, t0, W));
        assert!(l.blocked(1000, t0 + W - Duration::from_secs(1), W));
        assert!(!l.blocked(1000, t0 + W, W));
    }

    #[test]
    fn uids_are_limited_independently() {
        let t0 = Instant::now();
        let mut l = RateLimiter::default();
        for _ in 0..FAILURES_PER_UID {
            l.record_failure(1000, t0, W);
        }
        assert!(l.blocked(1000, t0, W));
        assert!(!l.blocked(1001, t0, W));
    }

    #[test]
    fn stale_uids_are_forgotten() {
        let t0 = Instant::now();
        let mut l = RateLimiter::default();
        for uid in 0..1000 {
            l.record_failure(uid, t0, W);
        }
        l.record_failure(5000, t0 + W, W);
        assert_eq!(l.tracked(), 1);
    }

    #[test]
    fn the_reserve_keeps_half_the_tries_and_at_least_one() {
        assert_eq!(reserve_threshold(32), 16);
        assert_eq!(reserve_threshold(3), 2);
        assert_eq!(reserve_threshold(1), 0);
        assert_eq!(reserve_threshold(0), 0);
        assert_eq!(window(600), Duration::from_secs(600));
        assert_eq!(window(0), MIN_WINDOW);
    }
}
```

Create `crates/aleph-tpmd/src/tpm.rs`, `crates/aleph-tpmd/src/server.rs`, and `crates/aleph-tpmd/src/testing.rs` each containing only `// implemented in step 3`, and `crates/aleph-tpmd/src/main.rs` containing `fn main() {}`.

Create `crates/aleph-tpmd/tests/helper.rs`:

```rust
use std::time::Instant;

use aleph_tpm_proto::{Failure, Parent, Request, Response, SealedObject, Secret};
use aleph_tpmd::limiter::{FAILURES_PER_UID, reserve_threshold, window};
use aleph_tpmd::server::Policy;
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
    for _ in 0..(FAILURES_PER_UID + 2) {
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
    for _ in 0..FAILURES_PER_UID {
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
        attempt(PW, UID, t0 + window(600)),
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
    // Bypass the helper's limits to reach the TPM's own lockout.
    let sw = SwTpm::start();
    sw.set_da_parameters(3, 600, 86400);
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
    // One long-lived helper throughout: it must notice ownerAuth change.
    let h = sw.helper();
    // A slot sealed under aleph's primary before ownerAuth was set...
    let (old, _) = seal(&h, UID, PW);
    sw.provision_persistent_srk();
    sw.set_owner_auth();
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

/// The attack the budgets exist for: many uids (a compromised account can
/// have several, and every login uid has its own budget) guessing across
/// many recovery windows. The TPM must never reach lockout, which would
/// also block disk unlock and survive reboot; refusing with `Busy` is the
/// accepted cost.
#[test]
fn guessing_from_many_uids_over_many_windows_never_locks_the_tpm() {
    for max_tries in [3, 32] {
        let sw = SwTpm::start();
        sw.set_da_parameters(max_tries, 600, 86400);
        let h = sw.helper();
        let t0 = Instant::now();
        let uids: Vec<u32> = (0..20).map(|i| UID + i).collect();
        let objects: Vec<_> = uids.iter().map(|&u| seal(&h, u, PW).0).collect();
        let mut busy = 0;
        for w in 0..5 {
            let at = t0 + window(600) * w;
            for (&uid, object) in uids.iter().zip(&objects) {
                for _ in 0..(FAILURES_PER_UID + 1) {
                    let reply = h.handle_at(
                        uid,
                        Request::Unseal {
                            object: object.clone(),
                            secret: Secret(b"guess".to_vec()),
                        },
                        at,
                    );
                    match reply {
                        Response::Failed(Failure::AuthFailed | Failure::RateLimited) => {}
                        Response::Failed(Failure::Busy) => busy += 1,
                        other => panic!("max_tries {max_tries}: {other:?}"),
                    }
                }
            }
        }
        assert!(busy > 0, "the reserve never engaged");
        let Response::Status(s) = h.handle(UID, Request::Status {}) else {
            panic!()
        };
        assert!(!s.in_lockout, "max_tries {max_tries}: TPM locked out");
        assert_eq!(s.failed_tries, reserve_threshold(max_tries));
        // Disk unlock (or anything else) still has the reserve.
        assert!(s.max_tries - s.failed_tries >= 1);
    }
}

/// An object whose auth value is right but whose payload names another
/// uid is `WrongUser`, and counts against the caller.
#[test]
fn a_payload_for_another_uid_is_wrong_user() {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let (object, _) = sw.tpm().seal_with_payload_uid(UID, UID + 1, PW).unwrap();
    let h = sw.helper();
    let t0 = Instant::now();
    let attempt = || {
        h.handle_at(
            UID,
            Request::Unseal {
                object: object.clone(),
                secret: Secret(PW.to_vec()),
            },
            t0,
        )
    };
    for _ in 0..FAILURES_PER_UID {
        assert_eq!(attempt(), Response::Failed(Failure::WrongUser));
    }
    assert_eq!(attempt(), Response::Failed(Failure::RateLimited));
}

#[test]
fn only_login_uids_are_served() {
    let sw = SwTpm::start();
    let h = sw.helper_with(Policy {
        uid_min: 1000,
        uid_max: 60000,
    });
    for uid in [0, 999, 60001, u32::MAX] {
        for request in [
            Request::Seal {
                secret: Secret(PW.to_vec()),
            },
            Request::Status {},
        ] {
            assert_eq!(
                h.handle(uid, request),
                Response::Failed(Failure::NotPermitted),
                "uid {uid}"
            );
        }
    }
    let (object, kek) = seal(&h, 1000, PW);
    assert_eq!(unsealed_kek(unseal(&h, 1000, &object, PW)), kek);
    seal(&h, 60000, PW);
}

#[test]
fn the_policy_reads_login_defs() {
    let text = "# comment\nUID_MIN\t\t 2000\nUID_MAX 3000\nGID_MIN 5\nUID_MAX_ bogus\n";
    assert_eq!(
        Policy::from_login_defs(text),
        Policy {
            uid_min: 2000,
            uid_max: 3000
        }
    );
    assert_eq!(
        Policy::from_login_defs(""),
        Policy {
            uid_min: 1000,
            uid_max: 60000
        }
    );
}

/// A slot sealed under the persistent SRK keeps working after `ownerAuth`
/// is cleared, although new slots then go under aleph's primary.
#[test]
fn a_slot_unseals_under_whichever_parent_it_names() {
    let sw = SwTpm::start();
    sw.provision_persistent_srk();
    sw.set_owner_auth();
    let (object, kek) = seal(&sw.helper(), UID, PW);
    sw.clear_owner_auth();
    let h = sw.helper();
    let Response::Status(s) = h.handle(UID, Request::Status {}) else {
        panic!()
    };
    assert_eq!(s.parent, Parent::AlephPrimary);
    assert_eq!(unsealed_kek(unseal(&h, UID, &object, PW)), kek);
    let (fresh, _) = seal(&h, UID, PW);
    assert_ne!(fresh.srk_name, object.srk_name);
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

/// A client trickling its request a byte at a time (which a per-read
/// timeout would never catch) is cut off at the request deadline; while
/// it holds its uid's slot, a second connection from the same uid is told
/// `Busy` at once rather than queued behind it.
#[test]
fn a_trickling_client_is_cut_off_and_does_not_queue_others() {
    use aleph_tpmd::server::REQUEST_DEADLINE;
    use std::time::{Duration, Instant};

    let sw = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let helper = Arc::new(sw.helper());
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, helper));

    let start = Instant::now();
    let mut slow = UnixStream::connect(&path).unwrap();
    slow.write_all(&100u32.to_be_bytes()).unwrap();
    let mut trickle = slow.try_clone().unwrap();
    std::thread::spawn(move || {
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(200));
            if trickle.write_all(b"\xa0").is_err() {
                break;
            }
        }
    });
    std::thread::sleep(Duration::from_millis(200));

    let t = Instant::now();
    assert_eq!(
        call(&path, &Request::Status {}),
        Response::Failed(Failure::Busy)
    );
    assert!(t.elapsed() < Duration::from_millis(500));

    let reply: Response = read_frame(&mut slow).unwrap();
    assert!(
        matches!(reply, Response::Failed(Failure::Malformed(_))),
        "{reply:?}"
    );
    let cut_off = start.elapsed();
    assert!(
        cut_off >= REQUEST_DEADLINE && cut_off < REQUEST_DEADLINE + Duration::from_secs(1),
        "{cut_off:?}"
    );
    assert!(matches!(
        call(&path, &Request::Status {}),
        Response::Status(_)
    ));
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
//! Rate limiting of failed unseals (spec §5), in two layers.
//!
//! The TPM's dictionary-attack counter is shared by every user and by
//! `systemd-cryptenroll` disk unlock, and a lockout survives reboot. So:
//!
//! - **Global reserve:** the helper refuses any DA-counted unseal once
//!   the TPM's failure counter reaches [`reserve_threshold`], half of its
//!   maximum. aleph can therefore never drive the TPM into lockout, and
//!   the other half stays available to disk unlock.
//! - **Per-uid budget:** each uid may have at most [`FAILURES_PER_UID`]
//!   failures outstanding per TPM recovery interval (the time the TPM
//!   takes to forget one failure), so one user cannot spend the whole
//!   reserve alone.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Failures a uid may have outstanding within one recovery window.
pub const FAILURES_PER_UID: usize = 2;
/// Window used when the TPM reports a recovery time of zero.
pub const MIN_WINDOW: Duration = Duration::from_secs(60);

/// The TPM failure count at which the helper stops attempting DA-counted
/// unseals: half of `max_tries`, keeping at least one try in reserve. A
/// TPM with `max_tries == 0` is always locked for DA-protected auth.
pub fn reserve_threshold(max_tries: u32) -> u32 {
    max_tries.saturating_sub((max_tries / 2).max(1))
}

/// The per-uid window for a TPM recovery time in seconds.
pub fn window(recovery_time_secs: u32) -> Duration {
    Duration::from_secs(recovery_time_secs.into()).max(MIN_WINDOW)
}

#[derive(Default)]
pub struct RateLimiter {
    failures: HashMap<u32, VecDeque<Instant>>,
}

impl RateLimiter {
    /// Whether `uid` has used up its budget within `window`.
    pub fn blocked(&mut self, uid: u32, now: Instant, window: Duration) -> bool {
        self.prune(now, window);
        self.failures
            .get(&uid)
            .is_some_and(|f| f.len() >= FAILURES_PER_UID)
    }

    /// Record a failed unseal by `uid`.
    pub fn record_failure(&mut self, uid: u32, now: Instant, window: Duration) {
        self.prune(now, window);
        self.failures.entry(uid).or_default().push_back(now);
    }

    /// Forget failures older than `window`, for every uid (bounded memory
    /// however many uids have come and gone).
    fn prune(&mut self, now: Instant, window: Duration) {
        self.failures.retain(|_, f| {
            while f.front().is_some_and(|t| now.duration_since(*t) >= window) {
                f.pop_front();
            }
            !f.is_empty()
        });
    }
```

Replace `crates/aleph-tpmd/src/tpm.rs` with:

```rust
//! The helper's TPM operations (spec §5, "TPM, via aleph-tpmd").
//!
//! - **Parent:** new objects are sealed under aleph's own primary (ECC
//!   P-256, AES-256-CFB, `noDA`), re-created from a fixed template on each
//!   use, whose Name is therefore stable per TPM. When `ownerAuth` is set
//!   that is impossible, and the persistent TCG SRK at `0x81000001` is used
//!   instead. The parent's Name is recorded at seal time. To unseal, the
//!   helper uses whichever available parent has that Name (so an SRK slot
//!   keeps working if `ownerAuth` is cleared later), and fails with
//!   `ParentMismatch` if none does: a different TPM, or an interposer
//!   substituting a key. The Name compared is the one ESYS itself holds for
//!   the handle (`Esys_TR_GetName`), i.e. the key that will salt the
//!   session.
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
use tss_esapi::constants::SessionType;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::constants::{CapabilityType, PropertyTag};
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, CapabilityData, EccPoint, KeyedHashScheme, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    SymmetricDefinitionObject,
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
        self.seal_inner(uid, uid, secret)
    }

    /// Test hook: seal with the auth value for `auth_uid` but the payload
    /// naming `payload_uid`, so the payload check is testable on its own.
    #[cfg(feature = "testing")]
    pub fn seal_with_payload_uid(
        &mut self,
        auth_uid: u32,
        payload_uid: u32,
        secret: &[u8],
    ) -> Result<(SealedObject, Zeroizing<[u8; KEK_LEN]>)> {
        self.seal_inner(auth_uid, payload_uid, secret)
    }

    fn seal_inner(
        &mut self,
        uid: u32,
        payload_uid: u32,
        secret: &[u8],
    ) -> Result<(SealedObject, Zeroizing<[u8; KEK_LEN]>)> {
        let mut kek = Zeroizing::new([0u8; KEK_LEN]);
        getrandom::fill(kek.as_mut()).map_err(|e| TpmError::Tpm(e.to_string()))?;
        let mut auth_salt = [0u8; AUTH_SALT_LEN];
        getrandom::fill(&mut auth_salt).map_err(|e| TpmError::Tpm(e.to_string()))?;
        let mut payload = Zeroizing::new(Vec::with_capacity(4 + KEK_LEN));
        payload.extend_from_slice(&payload_uid.to_be_bytes());
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
        let prop = |ctx: &mut Context, tag| property(ctx, tag);
        let permanent = prop(&mut self.ctx, PropertyTag::Permanent)?;
        let parent = match self.seal_parent() {
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
            // counter reaching the maximum is the definition, and a maximum
            // of zero locks DA-protected authorization permanently.
            in_lockout: permanent & PERMANENT_IN_LOCKOUT != 0 || failed_tries >= max_tries,
            max_tries,
            recovery_time: prop(&mut self.ctx, PropertyTag::LockoutInterval)?,
            lockout_recovery: prop(&mut self.ctx, PropertyTag::LockoutRecovery)?,
            failed_tries,
        })
    }

    /// `(failed_tries, max_tries, recovery_time)`: the dictionary-attack
    /// counters the helper budgets against.
    pub fn da_counters(&mut self) -> Result<(u32, u32, u32)> {
        Ok((
            property(&mut self.ctx, PropertyTag::LockoutCounter)?,
            property(&mut self.ctx, PropertyTag::MaxAuthFail)?,
            property(&mut self.ctx, PropertyTag::LockoutInterval)?,
        ))
    }

    fn owner_auth_set(&mut self) -> Result<bool> {
        Ok(property(&mut self.ctx, PropertyTag::Permanent)? & PERMANENT_OWNER_AUTH_SET != 0)
    }

    /// aleph's own primary (possible only while `ownerAuth` is empty).
    fn aleph_primary(&mut self) -> Result<ParentKey> {
        let handle = self
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
        self.named(handle, true)
    }

    /// The persistent SRK, if provisioned.
    fn persistent_srk(&mut self) -> Result<ParentKey> {
        let handle = PersistentTpmHandle::new(SRK_HANDLE).map_err(tpm_err)?;
        let object = self
            .ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(TpmHandle::Persistent(handle)))
            .map_err(|_| TpmError::NoParent)?;
        self.named(KeyHandle::from(object), false)
    }

    /// Wrap `handle` with the Name ESYS holds for it: the key that will
    /// salt sessions, whatever a later ReadPublic might claim.
    fn named(&mut self, handle: KeyHandle, transient: bool) -> Result<ParentKey> {
        match self.ctx.tr_get_name(handle.into()) {
            Ok(name) => Ok(ParentKey {
                handle,
                name: name.value().to_vec(),
                transient,
            }),
            Err(e) => {
                if transient {
                    let _ = self.ctx.flush_context(handle.into());
                }
                Err(map_tss(e))
            }
        }
    }

    /// The parent new objects are sealed under: aleph's primary unless
    /// `ownerAuth` is set, then the persistent SRK if present.
    fn seal_parent(&mut self) -> Result<ParentKey> {
        if self.owner_auth_set()? {
            self.persistent_srk()
        } else {
            self.aleph_primary()
        }
    }

    /// The available parent whose Name is `expected`, else
    /// `ParentMismatch`.
    fn parent_named(&mut self, expected: &[u8]) -> Result<ParentKey> {
        if !self.owner_auth_set()? {
            let primary = self.aleph_primary()?;
            if primary.name == expected {
                return Ok(primary);
            }
            self.release(primary);
        }
        match self.persistent_srk() {
            Ok(srk) if srk.name == expected => Ok(srk),
            Ok(srk) => {
                self.release(srk);
                Err(TpmError::ParentMismatch)
            }
            Err(_) => Err(TpmError::ParentMismatch),
        }
    }

    fn release(&mut self, parent: ParentKey) {
        if parent.transient {
            let _ = self.ctx.flush_context(parent.handle.into());
        }
    }

    /// Get the parent (the one named `expected`, or the seal parent), open a
    /// salted parameter-encrypting session bound to it, run `f`, and flush
    /// everything transient.
    fn with_parent<T>(
        &mut self,
        expected: Option<&[u8]>,
        f: impl FnOnce(&mut Context, &ParentKey, AuthSession) -> Result<T>,
    ) -> Result<T> {
        let parent = match expected {
            Some(name) => self.parent_named(name)?,
            None => self.seal_parent()?,
        };
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

/// A TPM property, read fresh (0 if the TPM does not report it).
/// `Context::get_tpm_property` caches every value forever, which is wrong
/// for a long-lived helper: the DA counter and `ownerAuth` change.
fn property(ctx: &mut Context, tag: PropertyTag) -> Result<u32> {
    let (data, _) = ctx
        .execute_without_session(|ctx| {
            ctx.get_capability(CapabilityType::TpmProperties, tag.into(), 1)
        })
        .map_err(map_tss)?;
    let CapabilityData::TpmProperties(props) = data else {
        return Err(TpmError::Tpm("unexpected capability data".into()));
    };
    Ok(props
        .into_iter()
        .find(|p| p.property() == tag)
        .map_or(0, |p| p.value()))
}

/// ECC P-256 restricted decryption key protecting children with
/// AES-256-CFB. `noDA` (as in the TCG SRK template): using the parent
/// itself needs no secret, so it should keep working during lockout; the
/// sealed objects under it remain DA-protected.
fn primary_template() -> tss_esapi::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
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
//! The caller's uid comes only from `SO_PEERCRED`, and only login uids
//! are served ([`Policy`]). Each connection gets its own thread (at most
//! [`MAX_CONNECTIONS`]) and must deliver its whole request within
//! [`REQUEST_DEADLINE`], so a slow or idle client cannot hold the helper;
//! a uid may have one connection in flight at a time, so one user cannot
//! take every thread. Only the TPM itself is serialized.

use std::collections::HashSet;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aleph_tpm_proto::{Failure, Request, Response, Secret, read_frame, write_frame};

use crate::limiter::{RateLimiter, reserve_threshold, window};
use crate::tpm::{Tpm, TpmError};

/// How long a client has to deliver its whole request.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(2);
/// How long a client may take to read the reply.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections served at once; more are refused with `Busy`.
pub const MAX_CONNECTIONS: usize = 64;

/// Which uids the helper serves: login users only (system accounts have
/// no business sealing secrets, and each served uid is a DA budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub uid_min: u32,
    pub uid_max: u32,
}

impl Policy {
    /// `UID_MIN`/`UID_MAX` from `login.defs` text, defaulting to the
    /// shadow-utils values 1000 and 60000.
    pub fn from_login_defs(text: &str) -> Self {
        let mut policy = Self {
            uid_min: 1000,
            uid_max: 60000,
        };
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let (Some(key), Some(value)) = (words.next(), words.next()) else {
                continue;
            };
            let Ok(value) = value.parse() else { continue };
            match key {
                "UID_MIN" => policy.uid_min = value,
                "UID_MAX" => policy.uid_max = value,
                _ => {}
            }
        }
        policy
    }

    /// The system's policy, from `/etc/login.defs` (defaults if absent).
    pub fn system() -> Self {
        Self::from_login_defs(
            &std::fs::read_to_string(Path::new("/etc/login.defs")).unwrap_or_default(),
        )
    }

    /// Every uid (tests, which run as arbitrary users).
    pub fn allow_all() -> Self {
        Self {
            uid_min: 0,
            uid_max: u32::MAX,
        }
    }

    pub fn allows(&self, uid: u32) -> bool {
        (self.uid_min..=self.uid_max).contains(&uid)
    }
}

pub struct Helper {
    tpm: Mutex<Tpm>,
    limiter: Mutex<RateLimiter>,
    policy: Policy,
    in_flight: Mutex<HashSet<u32>>,
    connections: AtomicUsize,
}

/// A uid's in-flight slot, released on drop.
pub struct Claim<'a> {
    helper: &'a Helper,
    uid: u32,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        lock(&self.helper.in_flight).remove(&self.uid);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Helper {
    pub fn new(tpm: Tpm, policy: Policy) -> Self {
        Self {
            tpm: Mutex::new(tpm),
            limiter: Mutex::new(RateLimiter::default()),
            policy,
            in_flight: Mutex::new(HashSet::new()),
            connections: AtomicUsize::new(0),
        }
    }

    /// Take `uid`'s in-flight slot, or `None` if it already has a request
    /// in progress.
    pub fn claim(&self, uid: u32) -> Option<Claim<'_>> {
        // Not `then_some`: that would build (and drop) a Claim even when
        // the insert fails, releasing the other request's slot.
        if lock(&self.in_flight).insert(uid) {
            Some(Claim { helper: self, uid })
        } else {
            None
        }
    }

    /// Handle one request from `uid` (as reported by the kernel).
    pub fn handle(&self, uid: u32, request: Request) -> Response {
        self.handle_at(uid, request, Instant::now())
    }

    /// `handle` with an explicit clock, for tests.
    pub fn handle_at(&self, uid: u32, request: Request, now: Instant) -> Response {
        if !self.policy.allows(uid) {
            return Response::Failed(Failure::NotPermitted);
        }
        let mut tpm = lock(&self.tpm);
        match request {
            Request::Seal { secret } => match tpm.seal(uid, &secret.0) {
                Ok((object, kek)) => Response::Sealed {
                    object,
                    kek: Secret(kek.to_vec()),
                },
                Err(e) => Response::Failed(failure(e)),
            },
            Request::Unseal { object, secret } => {
                let (failed, max, recovery) = match tpm.da_counters() {
                    Ok(c) => c,
                    Err(e) => return Response::Failed(failure(e)),
                };
                let window = window(recovery);
                let mut limiter = lock(&self.limiter);
                if limiter.blocked(uid, now, window) {
                    return Response::Failed(Failure::RateLimited);
                }
                // Never spend the second half of the TPM's budget: that is
                // what keeps aleph from ever locking the TPM out.
                if failed >= reserve_threshold(max) {
                    return Response::Failed(Failure::Busy);
                }
                match tpm.unseal(uid, &object, &secret.0) {
                    Ok(kek) => Response::Unsealed {
                        kek: Secret(kek.to_vec()),
                    },
                    Err(e) => {
                        // (A Lockout reply needs no counting: the reserve
                        // check above already refuses long before it.)
                        if matches!(e, TpmError::AuthFailed | TpmError::WrongUser) {
                            limiter.record_failure(uid, now, window);
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

/// Reads that fail once `deadline` passes, however the client paces its
/// bytes (a per-read timeout alone lets a byte-a-second client stay).
struct DeadlineReader<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(remaining))?;
        (&*self.stream).read(buf)
    }
}

/// Serve one connection: one request, one response.
pub fn serve_connection(helper: &Helper, mut stream: UnixStream) -> io::Result<()> {
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let uid = peer_uid(&stream)?;
    let Some(_claim) = helper.claim(uid) else {
        return reply(&mut stream, &Response::Failed(Failure::Busy));
    };
    let mut reader = DeadlineReader {
        stream: &stream,
        deadline: Instant::now() + REQUEST_DEADLINE,
    };
    let response = match read_frame::<Request>(&mut reader) {
        Ok(request) => helper.handle(uid, request),
        Err(e) => Response::Failed(Failure::Malformed(e.to_string())),
    };
    reply(&mut stream, &response)
}

fn reply(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    write_frame(stream, response).map_err(io::Error::other)
}

/// Accept connections forever, each on its own thread. Per-connection
/// errors are logged and do not stop the helper.
pub fn serve(listener: &UnixListener, helper: Arc<Helper>) -> ! {
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) => {
                eprintln!("aleph-tpmd: accept error: {e}");
                continue;
            }
        };
        if helper.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            helper.connections.fetch_sub(1, Ordering::SeqCst);
            let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
            let _ = reply(&mut stream, &Response::Failed(Failure::Busy));
            continue;
        }
        let helper = Arc::clone(&helper);
        let spawned = std::thread::Builder::new().spawn({
            let helper = Arc::clone(&helper);
            move || {
                if let Err(e) = serve_connection(&helper, stream) {
                    eprintln!("aleph-tpmd: connection error: {e}");
                }
                helper.connections.fetch_sub(1, Ordering::SeqCst);
            }
        });
        if let Err(e) = spawned {
            helper.connections.fetch_sub(1, Ordering::SeqCst);
            eprintln!("aleph-tpmd: cannot spawn a connection thread: {e}");
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

    /// A helper serving every uid (tests run as whoever runs them).
    pub fn helper(&self) -> crate::Helper {
        self.helper_with(crate::server::Policy::allow_all())
    }

    pub fn helper_with(&self, policy: crate::server::Policy) -> crate::Helper {
        crate::Helper::new(self.tpm(), policy)
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

    /// Clear the owner authorization set by [`Self::set_owner_auth`].
    pub fn clear_owner_auth(&self) {
        use tss_esapi::handles::{AuthHandle, ObjectHandle};
        use tss_esapi::structures::Auth;
        let mut ctx = self.raw();
        ctx.tr_set_auth(
            ObjectHandle::Owner,
            Auth::try_from(b"owner".to_vec()).unwrap(),
        )
        .unwrap();
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.hierarchy_change_auth(AuthHandle::Owner, Auth::default())
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
use std::sync::Arc;

use aleph_tpmd::server::Policy;
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
    // No core dumps and no ptrace by same-uid processes: this process
    // holds KEKs in memory. (The unit also sets LimitCORE=0.)
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) has no memory-safety preconditions.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
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
    aleph_tpmd::server::serve(&listener, Arc::new(Helper::new(tpm, Policy::system())))
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -p aleph-tpmd && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected:
- unit `4 passed`, `helper` `19 passed`, `socket` `4 passed`, `tpm_hardware` `1 ignored`
- about 3 s in total (the trickling-client test waits out the 2 s deadline)
- `WARNING:tcti:…`/`WARNING:esys:…` lines on stderr: expected (readiness probes and deliberate failures)

Run it 3 times. It must never hang; a hang means the fixture's start lock is missing.

- [ ] **Step 5: Confirm the security tests have teeth**

Revert each of these one at a time, run the named test and see it FAIL, then restore (`touch` the file) and see it pass:
- In `tpm.rs`, delete `info.extend_from_slice(&uid.to_be_bytes());` in `auth_value` **and** change `if bytes[..4] != uid.to_be_bytes() {` to `if false && bytes[..4] != uid.to_be_bytes() {`. Test: `--test helper another_user_cannot_unseal`.
- In `tpm.rs`, only the payload change above. Test: `--test helper a_payload_for_another_uid`.
- In `tpm.rs` `parent_named`, change `if primary.name == expected {` to `if true {`. Test: `--test helper a_parent_name_mismatch`.
- In `tpm.rs` `parent_named`, change `Ok(srk) if srk.name == expected => Ok(srk),` to `Ok(srk) if true => Ok(srk),`. Test: `--test helper with_owner_auth_set_the_persistent_srk_is_used`.
- In `tpm.rs` `with_parent`, replace `Some(name) => self.parent_named(name)?,` with `Some(name) => { let p = self.seal_parent()?; if p.name != name { self.release(p); return Err(TpmError::ParentMismatch); } p }`. Test: `--test helper a_slot_unseals_under_whichever_parent`.
- In `tpm.rs` `property`, make the first statement `if true { return ctx.get_tpm_property(tag).map_err(map_tss).map(|v| v.unwrap_or(0)); }`. Tests: `--test helper guessing_from_many_uids` and `--test helper with_owner_auth_set_the_persistent_srk_is_used`.
- In `server.rs`, replace `limiter.record_failure(uid, now, window);` with `let _ = &limiter;`. Test: `--test helper failed_unseals_are_rate_limited`.
- In `server.rs`, prefix `failed >= reserve_threshold(max)` with `false &&`. Test: `--test helper guessing_from_many_uids`.
- In `server.rs`, prefix `!self.policy.allows(uid)` with `false &&`. Test: `--test helper only_login_uids_are_served`.
- In `server.rs` `DeadlineReader::read`, replace the `remaining` computation with `let remaining = Duration::from_secs(1);`. Test: `--test socket a_trickling_client`.
- In `server.rs` `claim`, append `|| true` to the `insert(uid)` condition. Test: `--test socket a_trickling_client`.

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
  - `Error`: `Core`, `TpmUnavailable`, `TpmAuthFailed`, `TpmLockout`, `TpmRateLimited`, `TpmBusy`, `TpmNotPermitted`, `TpmWrongUser`, `TpmParentMismatch`, `TpmNoParent`, `TpmSlotMalformed`, `SecretRequired`, `Tpm`, plus the FIDO2 variants Tasks 4–5 use (`Fido2NoDevice`, `Fido2MultipleDevices`, `Fido2Unsupported`, `Fido2PinNotSet`, `Fido2UvInvalid`, `Fido2Denied`, `Fido2PinRequired`, `Fido2PinInvalid`, `Fido2PinBlocked`, `Fido2NoCredential`, `Fido2Timeout`, `Fido2(String)`)

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
libc.workspace = true
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

    #[error("too many failed TPM attempts; wait a few minutes")]
    TpmRateLimited,

    /// Temporary: the TPM's shared failure budget is spent (aleph keeps
    /// the rest for disk unlock), or another request is in progress. Not
    /// a reason to mark the slot stale.
    #[error(
        "the TPM is not accepting password attempts right now; try later or use another method"
    )]
    TpmBusy,

    #[error("aleph-tpmd serves login users only")]
    TpmNotPermitted,

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

    #[error("FIDO2 built-in verification (fingerprint) failed")]
    Fido2UvInvalid,

    #[error("the FIDO2 operation was declined on the key")]
    Fido2Denied,

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
use aleph_tpmd::server::Policy;
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
    helper_with(SwTpm::start(), Policy::allow_all())
}

fn helper_with(sw: SwTpm, policy: Policy) -> Helper {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let helper = Arc::new(sw.helper_with(policy));
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, helper));
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
fn helper_refusals_map_to_specific_errors() {
    // A TPM allowing one failure has no budget to spare: every unseal is
    // refused as Busy before it reaches the TPM.
    let sw = SwTpm::start();
    sw.set_da_parameters(1, 600, 86400);
    let h = helper_with(sw, Policy::allow_all());
    let (_, slot) = h.client.seal(PW).unwrap();
    assert!(matches!(h.client.unseal(&slot, PW), Err(Error::TpmBusy)));

    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let others = Policy {
        uid_min: me.wrapping_add(1),
        uid_max: me.wrapping_add(1),
    };
    let h = helper_with(SwTpm::start(), others);
    assert!(matches!(h.client.seal(PW), Err(Error::TpmNotPermitted)));
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
            Failure::Busy => Error::TpmBusy,
            Failure::NotPermitted => Error::TpmNotPermitted,
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
Expected: `tpm_client` `7 passed`.

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
  - `CredProtect { UvOptional, UvOptionalWithId, UvRequired }`, `CRED_PROTECT = CredProtect::UvOptionalWithId`
  - `DeviceInfo { hmac_secret, pin_set, uv }`
  - `trait Authenticator { info, make_credential(rp_id, protect, pin, uv), has_credential(rp_id, credential_id), hmac_secret(rp_id, credential_id, salt, pin, uv) }`
  - `trait Keys { devices(&mut self) -> Result<Vec<&mut dyn Authenticator>>; any_present(&mut self) -> bool }`
  - `Verification { PinOrUv (default), TouchOnly }`
  - `enroll(&mut dyn Keys, pin, Verification) -> Result<(Kek, Fido2Slot)>`, `unlock(&mut dyn Keys, &Fido2Slot, pin) -> Result<Kek>`
  - `mock::{MockAuthenticator { new, with_pin, with_uv, pub hmac_secret_supported, pub uv_capable, pub touches, pub fail_preflight }, MockKeys { pub devices, one }}`

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
libc.workspace = true
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
use aleph_unlock::fido2::{self, Authenticator, CRED_PROTECT, CredProtect, Keys, Verification};

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

/// A key whose preflight errors is "not this key": the right key among
/// several still unlocks, and only if none matches is the error reported.
#[test]
fn a_failing_preflight_does_not_stop_the_search() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    let mut broken = MockAuthenticator::new();
    broken.fail_preflight = true;
    keys.devices.insert(0, broken);
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap()
    ));
    keys.devices[1] = MockAuthenticator::new();
    assert!(matches!(
        fido2::unlock(&mut keys, &slot, Some(PIN)),
        Err(Error::Fido2(m)) if m == "preflight failed"
    ));
}

/// With one key there is nothing to choose between: no preflight, so a
/// preflight quirk cannot block it.
#[test]
fn a_single_key_is_asked_directly() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    keys.devices[0].fail_preflight = true;
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap()
    ));
}

/// Enrollment uses credProtect level 2, which the multi-key preflight
/// depends on: a level-3 credential is invisible to it.
#[test]
fn enrollment_uses_cred_protect_level_2() {
    assert_eq!(CRED_PROTECT, CredProtect::UvOptionalWithId);
    let mut hidden = MockAuthenticator::with_pin(PIN);
    let id = hidden
        .make_credential(fido2::RP_ID, CredProtect::UvRequired, Some(PIN), false)
        .unwrap();
    assert!(!hidden.has_credential(fido2::RP_ID, &id).unwrap());
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (_, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    assert!(
        keys.devices[0]
            .has_credential(fido2::RP_ID, &slot.credential_id)
            .unwrap()
    );
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
//!   What level 2 gives away: anyone holding the key (no PIN) can learn
//!   that it holds a given credential ID, and can obtain the key's
//!   *non-UV* hmac-secret output for it, which opens nothing aleph
//!   enrolled with UV.
//! - **Unlock** with a single key connected asks it directly. With several,
//!   it preflights each with a no-touch assertion to find the one holding
//!   the slot's credential, then asks only that key for a touch. A key
//!   whose preflight fails (unplugged mid-scan, a firmware quirk) is
//!   treated as "not this key"; if no key matches, the first such error is
//!   reported instead of "no credential".
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

/// CTAP2.1 credProtect levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredProtect {
    /// Level 1: usable without UV, discoverable.
    UvOptional,
    /// Level 2: usable without UV only when the credential ID is given.
    UvOptionalWithId,
    /// Level 3: every use requires UV (so no no-touch preflight either).
    UvRequired,
}

/// The level aleph enrolls with (see the module docs for why 2).
pub const CRED_PROTECT: CredProtect = CredProtect::UvOptionalWithId;

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
    /// credProtect `protect`. Requires a touch.
    fn make_credential(
        &mut self,
        rp_id: &str,
        protect: CredProtect,
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Vec<u8>>;

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
    let credential_id = device.make_credential(RP_ID, CRED_PROTECT, pin, uv)?;
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
    let ask = |device: &mut &mut dyn Authenticator| {
        let secret = device.hmac_secret(
            RP_ID,
            &slot.credential_id,
            &slot.salt,
            pin,
            slot.uv_required,
        )?;
        derive_kek(&secret)
    };
    match devices.len() {
        0 => return Err(Error::Fido2NoDevice),
        // Nothing to choose between: skip the preflight round trip.
        1 => return ask(&mut devices[0]),
        _ => {}
    }
    let mut first_error = None;
    for device in devices.iter_mut() {
        match device.has_credential(RP_ID, &slot.credential_id) {
            Ok(true) => return ask(device),
            Ok(false) => {}
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.unwrap_or(Error::Fido2NoCredential))
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

use super::{Authenticator, CredProtect, DeviceInfo, Keys};
use crate::error::{Error, Result};

const PIN_RETRIES: u8 = 8;

pub struct MockAuthenticator {
    pub hmac_secret_supported: bool,
    pin: Option<String>,
    pub uv_capable: bool,
    pin_retries: u8,
    /// Credential ID → (RP ID, protection, per-credential secret).
    credentials: HashMap<Vec<u8>, (String, CredProtect, [u8; 32])>,
    /// Touches performed on this key.
    pub touches: usize,
    /// Make the no-touch preflight fail (a key unplugged mid-scan).
    pub fail_preflight: bool,
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
            fail_preflight: false,
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

    fn make_credential(
        &mut self,
        rp_id: &str,
        protect: CredProtect,
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Vec<u8>> {
        if !self.hmac_secret_supported {
            return Err(Error::Fido2Unsupported);
        }
        self.verify_and_touch(pin, uv, true)?;
        let id = aleph_core::crypto::random_array::<32>()?.to_vec();
        let secret = aleph_core::crypto::random_array::<32>()?;
        self.credentials
            .insert(id.clone(), (rp_id.to_string(), protect, secret));
        Ok(id)
    }

    fn has_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> Result<bool> {
        if self.fail_preflight {
            return Err(Error::Fido2("preflight failed".into()));
        }
        // A level-3 credential is invisible to an assertion without UV.
        Ok(self
            .credentials
            .get(credential_id)
            .is_some_and(|(rp, protect, _)| rp == rp_id && *protect != CredProtect::UvRequired))
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let (cred_rp, _, secret) = self
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
Expected: `fido2` `16 passed`; `tpm_client` still `7 passed`.

- [ ] **Step 5: Confirm the FIDO2 tests have teeth**

Revert one at a time, see the test FAIL, then restore and see it pass:
- In `unlock`, replace `Ok(true) => return ask(device),` and the `Ok(false) => {}` line after it with `Ok(_) => return ask(device),`. Test: `--test fido2 unlock_picks_the_right_key`.
- In `unlock`, replace the `Err(e) => { first_error.get_or_insert(e); }` arm with `Err(e) => return Err(e),`. Test: `--test fido2 a_failing_preflight`.
- In `unlock`, replace `1 => return ask(&mut devices[0]),` with `1 => {}`. Test: `--test fido2 a_single_key_is_asked_directly`.
- Set `CRED_PROTECT` to `CredProtect::UvRequired`. Test: `--test fido2 unlock_picks_the_right_key`.
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
- Produces: `fido2::libfido2::{Libfido2Keys::new(), Libfido2Authenticator}`. It re-enumerates keys on every call, checks `hmac-secret` via `getInfo`, sets the `CredProtect` level it is given, and preflights with `up = false`.

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
libc.workspace = true
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
//!   What level 2 gives away: anyone holding the key (no PIN) can learn
//!   that it holds a given credential ID, and can obtain the key's
//!   *non-UV* hmac-secret output for it, which opens nothing aleph
//!   enrolled with UV.
//! - **Unlock** with a single key connected asks it directly. With several,
//!   it preflights each with a no-touch assertion to find the one holding
//!   the slot's credential, then asks only that key for a touch. A key
//!   whose preflight fails (unplugged mid-scan, a firmware quirk) is
//!   treated as "not this key"; if no key matches, the first such error is
//!   reported instead of "no credential".
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

/// CTAP2.1 credProtect levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredProtect {
    /// Level 1: usable without UV, discoverable.
    UvOptional,
    /// Level 2: usable without UV only when the credential ID is given.
    UvOptionalWithId,
    /// Level 3: every use requires UV (so no no-touch preflight either).
    UvRequired,
}

/// The level aleph enrolls with (see the module docs for why 2).
pub const CRED_PROTECT: CredProtect = CredProtect::UvOptionalWithId;

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
    /// credProtect `protect`. Requires a touch.
    fn make_credential(
        &mut self,
        rp_id: &str,
        protect: CredProtect,
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Vec<u8>>;

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
    let credential_id = device.make_credential(RP_ID, CRED_PROTECT, pin, uv)?;
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
    let ask = |device: &mut &mut dyn Authenticator| {
        let secret = device.hmac_secret(
            RP_ID,
            &slot.credential_id,
            &slot.salt,
            pin,
            slot.uv_required,
        )?;
        derive_kek(&secret)
    };
    match devices.len() {
        0 => return Err(Error::Fido2NoDevice),
        // Nothing to choose between: skip the preflight round trip.
        1 => return ask(&mut devices[0]),
        _ => {}
    }
    let mut first_error = None;
    for device in devices.iter_mut() {
        match device.has_credential(RP_ID, &slot.credential_id) {
            Ok(true) => return ask(device),
            Ok(false) => {}
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.unwrap_or(Error::Fido2NoCredential))
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
        assert!(matches!(map_code(0x33), Error::Fido2PinInvalid));
        assert!(matches!(map_code(0x3f), Error::Fido2UvInvalid));
        assert!(matches!(map_code(0x27), Error::Fido2Denied));
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

use super::{Authenticator, CredProtect, DeviceInfo, Keys};
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

    fn make_credential(
        &mut self,
        rp_id: &str,
        protect: CredProtect,
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Vec<u8>> {
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
        cred.set_protection(match protect {
            CredProtect::UvOptional => Protection::UvOptional,
            CredProtect::UvOptionalWithId => Protection::UvOptionalWithId,
            CredProtect::UvRequired => Protection::UvRequired,
        })
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
const FIDO_ERR_OPERATION_DENIED: i32 = 0x27;
const FIDO_ERR_INVALID_CREDENTIAL: i32 = 0x22;
const FIDO_ERR_UNSUPPORTED_OPTION: i32 = 0x2b;
const FIDO_ERR_NO_CREDENTIALS: i32 = 0x2e;
const FIDO_ERR_USER_ACTION_TIMEOUT: i32 = 0x2f;
const FIDO_ERR_PIN_INVALID: i32 = 0x31;
const FIDO_ERR_PIN_BLOCKED: i32 = 0x32;
const FIDO_ERR_PIN_AUTH_INVALID: i32 = 0x33;
const FIDO_ERR_PIN_AUTH_BLOCKED: i32 = 0x34;
const FIDO_ERR_PIN_NOT_SET: i32 = 0x35;
const FIDO_ERR_PIN_REQUIRED: i32 = 0x36;
const FIDO_ERR_UV_INVALID: i32 = 0x3f;
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
        FIDO_ERR_PIN_INVALID | FIDO_ERR_PIN_AUTH_INVALID => Error::Fido2PinInvalid,
        FIDO_ERR_UV_INVALID => Error::Fido2UvInvalid,
        FIDO_ERR_OPERATION_DENIED => Error::Fido2Denied,
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
//! Touch the key twice to enroll, once to unlock, then twice more.

use aleph_unlock::fido2::libfido2::Libfido2Keys;
use aleph_unlock::fido2::{self, Keys, Verification};

#[test]
#[ignore]
fn hardware_key_enroll_and_unlock() {
    let pin = std::env::var("ALEPH_FIDO2_PIN").ok();
    let mut keys = Libfido2Keys::new();
    assert!(keys.any_present(), "plug in a FIDO2 key");
    eprintln!("touch the key twice to enroll, once to unlock, then twice more");
    let (kek, slot) = fido2::enroll(&mut keys, pin.as_deref(), Verification::PinOrUv).unwrap();
    let back = fido2::unlock(&mut keys, &slot, pin.as_deref()).unwrap();
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(&kek, b"t").unwrap();
    assert!(aleph_core::KeyHandle::unwraps_to(&back, &w, b"t", &mk.id()));

    // What credProtect level 2 rests on: this key's hmac-secret output
    // without verification differs from the verified one, so a touch
    // alone cannot recompute the KEK.
    let mut devices = keys.devices().unwrap();
    let key = &mut devices[0];
    let id = &slot.credential_id;
    let verified = key
        .hmac_secret(
            fido2::RP_ID,
            id,
            &slot.salt,
            pin.as_deref(),
            slot.uv_required,
        )
        .unwrap();
    let touch_only = key
        .hmac_secret(fido2::RP_ID, id, &slot.salt, None, false)
        .unwrap();
    assert_ne!(*verified, *touch_only);
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
After=aleph-tpmd.socket tpm2.target

[Service]
ExecStart=/usr/lib/aleph/aleph-tpmd
Restart=on-failure
# The helper handles KEKs: no core dumps. The TSS library's own logging
# would echo every expected failure (wrong password, missing SRK) to the
# journal; the helper reports what matters itself.
LimitCORE=0
Environment=TSS2_LOG=all+NONE
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

Update the spec (§2 threat model; §5 TPM helper service, connections, protocol, parent choice, rate limiting, and sessions; FIDO2 credProtect and device selection; §9 wording) by applying this patch with `git apply`:

```diff
--- a/docs/superpowers/specs/2026-09-26-aleph-design.md
+++ b/docs/superpowers/specs/2026-09-26-aleph-design.md
@@ -85,3 +85,3 @@
 | **A same-user process, briefly** (malware that runs once) | While the vault is unlocked it can read every secret, as with gnome-keyring. Enrolling a new slot, changing configuration, or removing a slot requires re-authentication, so the process cannot turn brief access into permanent access (§6). Removing a slot rotates MK, which revokes any keyslot the process added (§4). |
-| **A different local user** | Nothing. The TPM helper binds sealed objects to the caller's uid (§5), and the vault file is mode `0600`. |
+| **A different local user** | No secrets. The TPM helper binds sealed objects to the caller's uid (§5), and the vault file is mode `0600`. By guessing wrong passwords they can spend the helper's share of the TPM's failure budget and so deny TPM unlock to everyone for a while; FIDO2, recovery, and password fallback still work. They cannot drive the TPM into lockout, which would also block TPM disk unlock and survive reboot (§5, rate limiting). |
 
@@ -377,3 +377,9 @@
   (`aleph-tpmd.socket` → `/run/aleph/tpm.sock`, mode `0666`). Access
-  control is by peer uid, not by file mode.
+  control is by peer uid, not by file mode, and only login uids
+  (`UID_MIN`–`UID_MAX` from `/etc/login.defs`) are served; others get
+  `NotPermitted`.
+- **Connections:** each connection has its own thread (at most 64) and one
+  request, which must arrive in full within 2 seconds however the client
+  paces it. A uid may have one connection in progress; a second gets
+  `Busy` at once. Only TPM access itself is serialized.
 - **Sandboxing:** it runs with `DynamicUser=yes` and
@@ -383,6 +389,9 @@
   an empty `CapabilityBoundingSet`, and so on.
-- **Protocol:** length-prefixed CBOR frames (`aleph-tpm-proto`):
-  - `Seal { secret, uid_bound: true }` → `{ public, private, auth_salt, srk_name }`
-  - `Unseal { public, private, auth_salt, srk_name, secret }` → `{ kek }`
-  - `Status` → `{ srk_present, lockout_auth_set, max_tries, recovery_time, lockout_recovery, failed_tries }`
+- **Protocol:** length-prefixed CBOR frames of at most 64 KiB
+  (`aleph-tpm-proto`), decoded strictly (unknown fields are errors):
+  - `Seal { secret }` → `Sealed { object: { public, private, auth_salt, srk_name }, kek }`
+    (the helper generates the KEK)
+  - `Unseal { object, secret }` → `Unsealed { kek }`
+  - `Status {}` → `{ parent, owner_auth_set, lockout_auth_set, in_lockout, max_tries, recovery_time, lockout_recovery, failed_tries }`
+  - any request → `Failed(AuthFailed | Lockout | RateLimited | Busy | NotPermitted | WrongUser | ParentMismatch | NoParent | Malformed | Tpm)`
 
@@ -402,4 +411,5 @@
   - By default the helper re-creates aleph's own primary on each use: ECC
-    P-256 with an AES-256-CFB symmetric parent, under the owner hierarchy.
-    This keeps the post-quantum margin of §2.
+    P-256 with an AES-256-CFB symmetric parent, under the owner hierarchy,
+    with `noDA` (like the TCG SRK: using the parent needs no secret). This
+    keeps the post-quantum margin of §2.
   - If `ownerAuth` is set, which makes that impossible, it falls back to
@@ -410,8 +420,12 @@
     same Name. Whichever parent is used, its Name is recorded in the slot
-    (`srk_name`) and checked before the helper uses the key to salt a
-    session. A mismatch is an error: it means a different TPM, or an active
-    interposer substituting a key.
+    (`srk_name`). To unseal, the helper uses whichever available parent has
+    that Name, so slots survive `ownerAuth` being set or cleared later as
+    long as their parent still exists. The Name compared is the one ESYS
+    holds for the handle (`Esys_TR_GetName`), i.e. the key that will salt
+    the session. No match is an error (`ParentMismatch`): a different TPM,
+    or an active interposer substituting a key.
 - **Sessions:** HMAC sessions salted to the verified parent, with
-  parameter encryption in both directions. That is AES-256-CFB with aleph's
-  primary, or AES-128-CFB with the SRK fallback.
+  AES-256-CFB parameter encryption in both directions, whichever parent is
+  used. (The SRK fallback's AES-128 affects only how the TPM protects
+  child blobs under that parent, not the session.)
 - **Sealed object:** a keyed hash with `fixedTPM`, `fixedParent`, and
@@ -419,10 +433,18 @@
   protection stays on. There are no PCR policies in v1.
-- **Rate limiting:**
-  - at most 5 failed unseals per uid per minute
-  - after a failure, the daemon marks the slot `stale` and stops trying it
-    automatically until the user re-enrolls it or explicitly retries it,
-    so an outdated password does not keep consuming dictionary-attack
-    attempts
-  - the TPM's own counter is TPM-wide, and is shared with
-    `systemd-cryptenroll` TPM2+PIN disk unlock
+- **Rate limiting.** The TPM's failure counter is TPM-wide, shared with
+  `systemd-cryptenroll` TPM2+PIN disk unlock, and a lockout survives
+  reboot. So the helper budgets it in two layers:
+  - **Global reserve:** once the TPM's failure count reaches
+    `max_tries − max(1, max_tries / 2)`, the helper refuses every unseal
+    with `Busy` without asking the TPM. aleph can therefore never cause a
+    TPM lockout, and at least half the budget stays for disk unlock. The
+    count falls by one per `recovery_time`, so `Busy` is temporary.
+  - **Per uid:** at most 2 failed unseals per uid per `recovery_time`
+    (at least 60 s), then `RateLimited`, so one user cannot spend the
+    whole reserve alone.
+  - After an `AuthFailed` or `WrongUser` failure, the daemon marks the
+    slot `stale` and stops trying it automatically until the user
+    re-enrolls it or explicitly retries it, so an outdated password does
+    not keep consuming attempts. `Lockout`, `RateLimited`, and `Busy` say
+    nothing about the slot and do not mark it stale.
 - **`Status` and setup:**
@@ -450,3 +472,10 @@
   - `makeCredential` with the `hmac-secret` extension, non-resident, RP ID
-    `"aleph"`, `credProtect = 3` (userVerificationRequired)
+    `"aleph"`, `credProtect = 2` ("UV optional with credential ID"). Level 2
+    rather than 3: a level-3 credential is invisible to the no-touch
+    preflight below unless UV happens first, so choosing among several
+    keys would burn PIN retries on the wrong ones (`systemd-cryptenroll`
+    uses level 2 for the same reason). The protection level 3 would add is
+    already provided: aleph requires UV/PIN at every unlock of a PIN/UV
+    slot, and the key's `hmac-secret` without UV is a different secret, so
+    a touch alone derives the wrong KEK.
   - defaults to requiring user verification: the PIN, or on-device UV
@@ -456,5 +485,10 @@
 - **Unlock:**
-  - **Device selection:** with several keys plugged in, each is
-    preflighted with `getAssertion(up = false)` on the slot's credential ID
-    to find the one that holds it, then only that key is asked for a touch.
+  - **Device selection:** with one key plugged in, it is asked directly.
+    With several, each is preflighted with `getAssertion(up = false)` on
+    the slot's credential ID to find the one that holds it, then only that
+    key is asked for a touch. A key whose preflight errors is skipped; if
+    no key matches, the first such error is reported.
+  - **What level 2 exposes:** anyone holding the key, without its PIN, can
+    learn whether it holds a given credential ID and obtain its non-UV
+    `hmac-secret` output, which opens nothing enrolled with PIN/UV.
   - `getAssertion` with the slot's salt yields the `hmac-secret` output,
@@ -806,3 +840,3 @@
 - **FIDO2:** a mock `Authenticator`, including multiple devices,
-  preflight selection, and `credProtect`/UV defaults. A manual checklist
+  preflight selection, and PIN/UV defaults. A manual checklist
   with a real key (`docs/testing.md`) is run before each release.
```

- [ ] **Step 4: Run the whole workspace, clippy, fmt, and check the units**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected:
- core unchanged (58 unit, 27 vault, 10 write, golden, zeroize)
- `aleph-tpm-proto` 6, `aleph-tpmd` 4 + 19 + 4, `aleph-unlock` 1 + 16 + 7
- `fido2_hardware` and `tpm_hardware` `1 ignored` each

Then check the units as described in `docs/testing.md`: `systemd-analyze verify` prints nothing, and `systemd-analyze security --offline=true` reports about 0.7 "SAFE".

- [ ] **Step 5 (only with a FIDO2 key and/or TPM access): run the hardware checklist**

Follow `docs/testing.md` "Manual, before each release". If no key or access is available, note "hardware checklist not run" in the commit body.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-unlock packaging/systemd docs/testing.md README.md docs/superpowers/specs/2026-09-26-aleph-design.md
git commit -m "feat(unlock): libfido2 backend; aleph-tpmd units; testing docs; spec corrections" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
