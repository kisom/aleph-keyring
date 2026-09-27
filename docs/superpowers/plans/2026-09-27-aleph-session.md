# Session unlock Implementation Plan (Plan 4a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unlock the keyring with the login password at login and screen unlock (`pam_aleph` → `pam.sock`), keep the keyslots right across `passwd` and outside password changes, and lock it on sleep, screen lock, and idle.

**Architecture:**
- **`pam_aleph`** (cdylib) is stacked after `pam_unix` in the display manager, the screen locker, and `passwd`. It hands the password to the user's `alephd` from a forked child running as the user, over a tiny binary protocol (`aleph-pam-proto`), and always returns `PAM_IGNORE`.
- **`alephd`** serves `pam.sock` (socket-activated by `alephd.socket`). It unlocks with a login password (still checked with PAM when PAM can check), and replaces the password keyslots on `passwd`: it rotates MK when no FIDO2 slot needs a touch, and otherwise marks a rotation pending.
- **Outside password changes:** after one, the next unlock asks for the previous password and re-seals.
- **Lock policy:** a logind watcher (a sleep inhibitor, `PrepareForSleep`, `Session.Lock`) and an idle timer lock the vault.

**Tech Stack:** Rust 1.98, `zbus` 5 (tokio) also on the system bus for logind, libpam (declared directly, module side and test side), `libc` (fork, pidfd, sockets).

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` revision 2 (§5 "Password change", rate limiting; §6 "PAM integration", "Lock policy"). Task 7 updates the spec with what this plan settled. Design decisions made while the owner was away, each ruled on by an independent reviewer, are in `DECISIONS.md` (Task 7 adds it).

**Plan series:** 1, 1b, 2, 3 (done) → **4a session unlock (this plan)** → 4b custody and setup (recovery unlock and restore, backup, gnome-keyring import/export, setup's system changes and revert, lockoutAuth) → 5 `aleph-gui` → 6 packaging and CI.

**Prerequisites** (once per machine): as for Plan 3 (`sudo pacman -S --needed swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`). `pam_exec.so` and `pam_permit.so` come with `pam`.

## Decisions made while prototyping

Every task was prototyped, then replayed from this document on a fresh clone of `master`: red, then green, then clippy and fmt clean, with the final tree identical to the prototype. The properties below were each checked by reverting them (the "teeth" step of the owning task). `DECISIONS.md` has the reasoning and the reviewer's verdicts (D1–D11).

- **Plan 4 is split** into 4a (this plan) and 4b (D1). 4b's setup installs the PAM lines; until then `docs/testing.md` gives them for manual setup. They go straight into each service with a `-` prefix, not through an `include`d substack (DECISIONS.md E4: a missing substack file could make the whole service fail).
- **The pre-execution review of this plan** found six defects, all fixed with tests (D12): a login password waited behind a FIDO2 PIN question; a late open could install an older copy; `passwd` after a login with the new password failed; without PAM a change did not prove the old password; parallel `pam.sock` connections got past the limit; the previous-password budget was per question.
- **`passwd`** (D2): the daemon acts only on a new password PAM accepts, since `pam_aleph` runs even when `pam_unix` failed.
  - It replaces every password slot: a new TPM slot sealed under the new password, and a new login-password slot if there was one.
  - MK rotates when every other slot is a recovery slot. With FIDO2 slots, which need a touch, the old slots are removed keeping MK (core `remove_keyslot_keeping_mk`, which never keeps the old file as `.bak`), and a **pending rotation** is shown by `aleph status` and every unlock until one is run.
  - A locked vault is changed as a detached copy and never unlocked (D8).
- **Outside password change** (D3): a typed password PAM accepts that opens no TPM slot (all stale, or `AuthFailed`) is `PasswordChanged`. The prompter is asked for the previous password (new message `old_password`).
  - The previous password is tried only on the newest TPM slot, at most twice per conversation, each counted by the typing limit.
  - Declining returns to the choice of method (a FIDO2 touch works too), and the slots are re-sealed under the current password either way.
  - `WrongUser` does not ask. A stale TPM slot still offers "password".
- **Login-stack passwords are PAM-checked** when PAM can check (D5, the reviewer's alternative): a wrong one sent to `pam.sock` never reaches the TPM. A login password does not queue behind an open conversation: whichever open finishes first is installed, and a later one is discarded (D11).
- **`pam.sock`:** only the daemon's uid, one request per connection within 5 s, at most 5 *rejected* passwords a minute (busy refusals do not count). It is the descriptor named `pam` when socket-activated.
- **`pam_aleph`** (D7): at auth it delivers at once if `pam.sock` exists, otherwise at session open; `passwd` delivers in the update phase only when both passwords are known.
  - The forked child drops privileges only as root, calls only async-signal-safe functions, closes the host's descriptors, sends with `MSG_NOSIGNAL`, and has an `alarm` backstop (SIGALRM reset); it exits rather than unwinding into the host. A failed delivery at auth is retried at session open.
  - It reports on a pipe. The parent kills through a pidfd and never touches the host's `SIGCHLD`.
- **Lock policy** (D4): logind cannot tell suspend from hibernate, so `on_suspend` covers both. The inhibitor is released only after locking. `Session.Lock` counts only for this user's sessions. Idle means no body read or write.
- **Tests without root** (D10): the module's logic on a fake PAM handle, the forked delivery on a real socket (including a host that ignores `SIGCHLD`), real libpam loading the built module (`pam_start_confdir`, with `pam_exec expose_authtok` supplying `PAM_AUTHTOK`), and a stand-in logind on the private bus. The privilege drop and a failing `pam_unix` update are Plan 6's root-container tests.
- **Not in this plan:** everything in 4b; setup still only creates the vault (its note now points at `docs/testing.md` for the PAM lines).

## Global Constraints

- Rust stable 1.98, edition 2024; every crate `license = "Apache-2.0"`.
- `pam_aleph` never decides or blocks a login: every entry point returns `PAM_IGNORE` (panics included), it never prompts, and the host waits at most 5 s.
- `pam_aleph`'s forked child calls only async-signal-safe functions on memory prepared before the fork, and never allocates. The host's signal dispositions are never changed.
- **Exact names and paths:**
  - socket `$XDG_RUNTIME_DIR/aleph/pam.sock` (the module uses `/run/user/<uid>/aleph/pam.sock`, or its `socket=` argument), `FileDescriptorName=pam`
  - PAM lines `-auth optional pam_aleph.so`, `-session optional pam_aleph.so`, `-password optional pam_aleph.so` straight in each service (never an `include`: a missing module behind `-` is skipped); module built as `libpam_aleph.so`, installed as `pam_aleph.so`
  - prompter message `{"type":"old_password","error":...}`
- Passwords travel only in zeroizing types and are never logged.
- `cargo fmt` default; `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **A real login or screen unlock through the actual Omarchy PAM files** (the module as root in sddm, the user's systemd instance still starting, hyprlock as the user) must unlock the vault without delaying the login more than 5 s, and a missing or hung daemon must never block it. → Task 5 `with_the_daemon_up_the_password_goes_out_at_auth`, `at_login_the_password_goes_out_at_session_open`, `without_a_daemon_login_goes_on`, `a_silent_daemon_times_out`, `a_host_ignoring_sigchld_keeps_it_and_still_gets_the_answer`; the root-only privilege drop is Plan 6.
2. **Unlocking the screen while an unlock prompt is open** (a password or a security key's PIN) must unlock at once and lose nothing stored meanwhile, even if the vault locked again in between. → Task 3 `a_login_password_does_not_wait_for_a_conversation`, `a_login_password_does_not_wait_behind_a_pin_prompt`, `a_late_unlock_does_not_replace_the_open_vault`; Task 4 `a_login_password_unlocks_and_completes_waiting_prompts`.
3. **A failed `passwd`, or a password changed without aleph,** must never leave the TPM slot sealed under a wrong password or lock the user out, and must cost few TPM attempts. → Task 3 `a_failed_passwd_changes_nothing`, `a_password_changed_elsewhere_is_resealed_with_the_previous_one`, `wrong_previous_passwords_are_few`, `the_previous_password_is_asked_at_most_twice_per_conversation`, `declining_the_previous_password_leaves_the_security_key`, `a_password_change_while_locked_leaves_it_locked`, `passwd_after_a_login_with_the_new_password_still_changes`.
4. **A same-user process guessing or re-sealing through `pam.sock`** must not spend TPM attempts, mark slots stale, re-seal the vault under a password of its choosing, or get past the limit with parallel connections. → Task 3 `a_wrong_login_stack_password_never_reaches_the_tpm`, `without_pam_a_change_must_prove_the_old_password`; Task 4 `failed_requests_are_limited`, `requests_in_flight_are_bounded`, `a_wrong_new_password_is_refused_without_waiting`.
5. **Sleep, another user's or a spoofed screen lock, and idle:** the vault must be locked before the sleep proceeds, only logind's lock of this user's session counts, and a vault in use must not lock. → Task 6 `sleep_locks_first_then_lets_the_sleep_go`, `with_on_suspend_off_sleep_does_not_lock`, `a_screen_lock_of_this_user_locks`, `a_spoofed_screen_lock_is_ignored`, `an_idle_vault_locks`.

## File Structure

```
crates/aleph-pam-proto/src/lib.rs        pam.sock frames (Request, Reply, Password; reply_ok without allocating)
crates/aleph-core/src/vault.rs           remove_keyslot_keeping_mk
crates/aleph-prompt-proto/src/lib.rs     ToPrompter::OldPassword
crates/aleph-daemon/src/keyring.rs       change_login_password, re-seal flow, PAM-checked login passwords, first open wins, idle clock
crates/aleph-daemon/src/state.rs         rotation_pending in slots.json
crates/aleph-daemon/src/pamsock.rs       pam.sock: listener (socket activation), serve, rate limit
crates/aleph-daemon/src/lockpolicy.rs    logind (inhibitor, PrepareForSleep, Session.Lock), idle timer
crates/aleph-daemon/src/{error,paths,config,lib,main,testing}.rs
crates/aleph-daemon/tests/{keyring,pam_socket,lock_policy}.rs
crates/pam_aleph/src/{lib,module,deliver}.rs; tests/{deliver,sigchld,libpam}.rs
crates/aleph-cli/src/{client,prompter,main}.rs  rotation_pending, OldPassword, on_suspend warning
packaging/systemd/alephd.socket
docs: spec (§3, §4, §5, §6, §7, §9), testing.md, README.md, DECISIONS.md
```

---

### Task 1: aleph-pam-proto

**Interfaces:**
- Produces: `aleph_pam_proto::{MAX_FRAME = 4096, Password { new, expose }, Request { Unlock { password }, ChangePassword { old, new } }, Reply { ok, message }, Error, payload_len([u8; 4]) -> Result<usize>, reply_ok(&[u8]) -> Option<bool>}`; `Request::{encode (whole frame, Zeroizing), decode (payload)}`, `Reply::{encode, decode}`

- [ ] **Step 1: Write the failing tests**

Write `Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-tpm-proto", "crates/aleph-tpmd", "crates/aleph-unlock", "crates/aleph-prompt-proto", "crates/aleph-daemon", "crates/aleph-cli", "crates/aleph-pam-proto"]

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

Write `crates/aleph-pam-proto/Cargo.toml`:

```toml
[package]
name = "aleph-pam-proto"
description = "The request format between pam_aleph and alephd's pam.sock"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
zeroize.workspace = true
```

Write `crates/aleph-pam-proto/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn payload(frame: &[u8]) -> &[u8] {
        let len = payload_len(frame[..4].try_into().unwrap()).unwrap();
        assert_eq!(frame.len(), 4 + len);
        &frame[4..]
    }

    #[test]
    fn requests_and_replies_round_trip() {
        for r in [
            Request::Unlock {
                password: Password::new(b"hunter2"),
            },
            Request::ChangePassword {
                old: Password::new(b"old"),
                new: Password::new("n\u{e9}w".as_bytes()),
            },
        ] {
            let frame = r.encode().unwrap();
            assert_eq!(Request::decode(payload(&frame)).unwrap(), r);
        }
        for r in [
            Reply {
                ok: true,
                message: "unlocked".into(),
            },
            Reply {
                ok: false,
                message: "the vault is locked".into(),
            },
        ] {
            let frame = r.encode().unwrap();
            assert_eq!(reply_ok(&frame), Some(r.ok));
            assert_eq!(Reply::decode(payload(&frame)).unwrap(), r);
        }
    }

    #[test]
    fn malformed_payloads_are_refused() {
        assert_eq!(Request::decode(&[]), Err(Error::Truncated));
        assert_eq!(Request::decode(&[9]), Err(Error::UnknownTag(9)));
        assert_eq!(
            Request::decode(&[UNLOCK, 0, 5, b'a']),
            Err(Error::Truncated)
        );
        assert_eq!(
            Request::decode(&[UNLOCK, 0, 1, b'a', 0]),
            Err(Error::Trailing)
        );
        assert_eq!(Reply::decode(&[REPLY_OK, 0, 1, 0xff]), Err(Error::NotUtf8));
        assert_eq!(
            payload_len((MAX_FRAME as u32 + 1).to_be_bytes()),
            Err(Error::TooLong)
        );
        let long = Request::Unlock {
            password: Password::new(&[b'x'; MAX_FRAME]),
        };
        assert_eq!(long.encode().unwrap_err(), Error::TooLong);
        assert_eq!(reply_ok(&[0, 0, 0, 2, REPLY_OK]), None);
    }

    #[test]
    fn passwords_are_never_printed() {
        let r = Request::ChangePassword {
            old: Password::new(b"hunter2"),
            new: Password::new(b"hunter3"),
        };
        let shown = format!("{r:?}");
        assert!(!shown.contains("hunter"), "{shown}");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-pam-proto`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-pam-proto/src/lib.rs`:

```rust
//! The protocol between `pam_aleph` and `alephd`'s `pam.sock` (spec §6
//! "PAM integration"): one request and one reply per connection.
//!
//! Each message is a frame: a big-endian `u32` payload length, then the
//! payload. A payload is a tag byte followed by fields, each a big-endian
//! `u16` length and that many bytes. Decoding is strict: a short, long, or
//! unknown payload is an error.
//!
//! Deliberately tiny, with no dependency but `zeroize`: the PAM module
//! runs inside other programs (the display manager, the screen locker,
//! `passwd`) and must stay small. [`reply_ok`] reads a reply without
//! allocating, for the module's forked child.

use zeroize::Zeroizing;

/// The longest payload either side accepts (passwords are far smaller).
pub const MAX_FRAME: usize = 4096;

const UNLOCK: u8 = 1;
const CHANGE_PASSWORD: u8 = 2;
const REPLY_OK: u8 = 0x10;
const REPLY_FAILED: u8 = 0x11;

/// A password in a message: zeroized on drop, never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(Zeroizing<Vec<u8>>);

impl Password {
    pub fn new(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// The login stack accepted this password: a login, or unlocking the
    /// screen.
    Unlock { password: Password },
    /// `passwd` changed the login password from `old` to `new`.
    ChangePassword { old: Password, new: Password },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub ok: bool,
    /// What happened, for the module's log (never a secret).
    pub message: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    TooLong,
    Truncated,
    Trailing,
    UnknownTag(u8),
    NotUtf8,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong => write!(f, "message longer than {MAX_FRAME} bytes"),
            Self::Truncated => f.write_str("message truncated"),
            Self::Trailing => f.write_str("trailing bytes after the message"),
            Self::UnknownTag(t) => write!(f, "unknown message type {t}"),
            Self::NotUtf8 => f.write_str("reply message is not UTF-8"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Frame `payload`: its length, then the payload itself.
fn frame(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() > MAX_FRAME {
        return Err(Error::TooLong);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::TooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Reads the fields of a payload, strictly.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn next(&mut self) -> Result<&'a [u8]> {
        let [a, b, rest @ ..] = self.0 else {
            return Err(Error::Truncated);
        };
        let len = usize::from(u16::from_be_bytes([*a, *b]));
        if rest.len() < len {
            return Err(Error::Truncated);
        }
        let (value, rest) = rest.split_at(len);
        self.0 = rest;
        Ok(value)
    }

    fn end(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Trailing)
        }
    }
}

/// The payload length a frame header announces, if acceptable.
pub fn payload_len(header: [u8; 4]) -> Result<usize> {
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(Error::TooLong);
    }
    Ok(len)
}

impl Request {
    /// The whole frame, ready to write.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut payload = Zeroizing::new(Vec::new());
        match self {
            Self::Unlock { password } => {
                payload.push(UNLOCK);
                field(&mut payload, password.expose())?;
            }
            Self::ChangePassword { old, new } => {
                payload.push(CHANGE_PASSWORD);
                field(&mut payload, old.expose())?;
                field(&mut payload, new.expose())?;
            }
        }
        frame(&payload)
    }

    /// A payload (the bytes after the frame header).
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let Some((&tag, rest)) = payload.split_first() else {
            return Err(Error::Truncated);
        };
        let mut fields = Fields(rest);
        let request = match tag {
            UNLOCK => Self::Unlock {
                password: Password::new(fields.next()?),
            },
            CHANGE_PASSWORD => Self::ChangePassword {
                old: Password::new(fields.next()?),
                new: Password::new(fields.next()?),
            },
            t => return Err(Error::UnknownTag(t)),
        };
        fields.end()?;
        Ok(request)
    }
}

impl Reply {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut payload = vec![if self.ok { REPLY_OK } else { REPLY_FAILED }];
        field(&mut payload, self.message.as_bytes())?;
        frame(&payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let Some((&tag, rest)) = payload.split_first() else {
            return Err(Error::Truncated);
        };
        let ok = match tag {
            REPLY_OK => true,
            REPLY_FAILED => false,
            t => return Err(Error::UnknownTag(t)),
        };
        let mut fields = Fields(rest);
        let message = std::str::from_utf8(fields.next()?)
            .map_err(|_| Error::NotUtf8)?
            .to_string();
        fields.end()?;
        Ok(Self { ok, message })
    }
}

/// Whether a whole reply frame says "ok", without allocating (the PAM
/// module's forked child may call only async-signal-safe code). `None` if
/// the frame is not a complete reply.
pub fn reply_ok(frame: &[u8]) -> Option<bool> {
    let (header, payload) = frame.split_first_chunk::<4>()?;
    let len = payload_len(*header).ok()?;
    if payload.len() != len {
        return None;
    }
    match *payload.first()? {
        REPLY_OK => Some(true),
        REPLY_FAILED => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(frame: &[u8]) -> &[u8] {
        let len = payload_len(frame[..4].try_into().unwrap()).unwrap();
        assert_eq!(frame.len(), 4 + len);
        &frame[4..]
    }

    #[test]
    fn requests_and_replies_round_trip() {
        for r in [
            Request::Unlock {
                password: Password::new(b"hunter2"),
            },
            Request::ChangePassword {
                old: Password::new(b"old"),
                new: Password::new("n\u{e9}w".as_bytes()),
            },
        ] {
            let frame = r.encode().unwrap();
            assert_eq!(Request::decode(payload(&frame)).unwrap(), r);
        }
        for r in [
            Reply {
                ok: true,
                message: "unlocked".into(),
            },
            Reply {
                ok: false,
                message: "the vault is locked".into(),
            },
        ] {
            let frame = r.encode().unwrap();
            assert_eq!(reply_ok(&frame), Some(r.ok));
            assert_eq!(Reply::decode(payload(&frame)).unwrap(), r);
        }
    }

    #[test]
    fn malformed_payloads_are_refused() {
        assert_eq!(Request::decode(&[]), Err(Error::Truncated));
        assert_eq!(Request::decode(&[9]), Err(Error::UnknownTag(9)));
        assert_eq!(
            Request::decode(&[UNLOCK, 0, 5, b'a']),
            Err(Error::Truncated)
        );
        assert_eq!(
            Request::decode(&[UNLOCK, 0, 1, b'a', 0]),
            Err(Error::Trailing)
        );
        assert_eq!(Reply::decode(&[REPLY_OK, 0, 1, 0xff]), Err(Error::NotUtf8));
        assert_eq!(
            payload_len((MAX_FRAME as u32 + 1).to_be_bytes()),
            Err(Error::TooLong)
        );
        let long = Request::Unlock {
            password: Password::new(&[b'x'; MAX_FRAME]),
        };
        assert_eq!(long.encode().unwrap_err(), Error::TooLong);
        assert_eq!(reply_ok(&[0, 0, 0, 2, REPLY_OK]), None);
    }

    #[test]
    fn passwords_are_never_printed() {
        let r = Request::ChangePassword {
            old: Password::new(b"hunter2"),
            new: Password::new(b"hunter3"),
        };
        let shown = format!("{r:?}");
        assert!(!shown.contains("hunter"), "{shown}");
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-pam-proto && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 3 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **pam frames decode strictly** (`crates/aleph-pam-proto/src/lib.rs`), test `cargo test -p aleph-pam-proto malformed`:

  replace

  ```rust
  t => return Err(Error::UnknownTag(t)),
  };
  fields.end()?;
  Ok(request)
  ```

  with

  ```rust
  t => return Err(Error::UnknownTag(t)),
  };
  Ok(request)
  ```


- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-pam-proto
git commit -m "feat(pam-proto): the pam.sock protocol" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: removing a slot while keeping the master key

**Interfaces:**
- Produces: `aleph_core::UnlockedVault::remove_keyslot_keeping_mk(Uuid) -> Result<()>` (refuses recovery slots; the next write keeps no `.bak` of the previous file)

- [ ] **Step 1: Write the failing tests**

Apply this patch with `git apply` (save it as `/tmp/t2-tests.patch`):

```diff
--- a/crates/aleph-core/tests/vault.rs
+++ b/crates/aleph-core/tests/vault.rs
@@ -426,6 +426,36 @@
     // Remaining slots still work, and recovery was re-wrapped without its key.
     assert!(locked_after.unlock_recovery(rec, &rk).is_ok());
     assert!(locked_after.unlock_login_password(pw, PASSWORD).is_ok());
+}
+
+/// A password slot can be removed without rotating MK (a login password
+/// change, when FIDO2 slots make a rotation impossible without the user):
+/// later files no longer hold it, MK is unchanged, and a recovery slot can
+/// never be removed this way.
+#[test]
+fn a_slot_can_be_removed_keeping_mk_but_never_the_recovery_slot() {
+    let (mut v, rk, rec, pw) = sample();
+    let mk_id = v.mark().mk_id;
+    v.remove_keyslot_keeping_mk(pw).unwrap();
+    assert_eq!(v.mark().mk_id, mk_id);
+    assert!(v.keyslots().all(|k| k.id != pw));
+    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
+    assert!(matches!(
+        locked.unlock_login_password(pw, PASSWORD),
+        Err(Error::NoSuchKeyslot(_))
+    ));
+    assert_eq!(
+        first_secret(&locked.unlock_recovery(rec, &rk).unwrap()),
+        b"ghp_secret"
+    );
+    assert!(matches!(
+        v.remove_keyslot_keeping_mk(rec),
+        Err(Error::RecoveryRequired)
+    ));
+    assert!(matches!(
+        v.remove_keyslot_keeping_mk(Uuid::new_v4()),
+        Err(Error::NoSuchKeyslot(_))
+    ));
 }
 
 #[test]
--- a/crates/aleph-core/tests/write.rs
+++ b/crates/aleph-core/tests/write.rs
@@ -179,6 +179,20 @@
     assert_eq!(v.mark(), before);
 }
 
+/// Removing a slot without rotation does not leave the previous file
+/// (which still holds that slot) in `.bak` either.
+#[test]
+fn the_backup_after_a_removal_keeping_mk_does_not_keep_the_slot() {
+    let dir = tempfile::tempdir().unwrap();
+    let path = dir.path().join("vault.aleph");
+    let (mut v, _, _, pw) = sample();
+    v.write(&path).unwrap();
+    v.remove_keyslot_keeping_mk(pw).unwrap();
+    v.write(&path).unwrap();
+    let bak = LockedVault::read(&path.with_file_name("vault.aleph.bak")).unwrap();
+    assert!(bak.keyslots().all(|s| s.id != pw));
+}
+
 /// After a rotation, the first write must not leave the pre-rotation file
 /// (which still holds the removed slot and the old MK) in `.bak`.
 #[test]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-core`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Apply this patch with `git apply` (save it as `/tmp/t2-impl.patch`):

```diff
--- a/crates/aleph-core/src/vault.rs
+++ b/crates/aleph-core/src/vault.rs
@@ -325,8 +325,9 @@
     vault_id: Uuid,
     /// The generation last read or written; the next write uses one more.
     generation: AtomicU64,
-    /// MK rotated since the last write: that write must not leave the
-    /// pre-rotation file (old MK, removed slots) behind as `.bak`.
+    /// MK rotated (or a slot was removed) since the last write: that write
+    /// must not leave the previous file (old MK, removed slots) behind as
+    /// `.bak`.
     rotated: AtomicBool,
     entries: Vec<SlotEntry>,
     key: KeyHandle,
@@ -456,6 +457,27 @@
     /// TPM, FIDO2, and login-password slot (see `rotate_master`).
     pub fn remove_keyslot(&mut self, id: Uuid, keks: &[(Uuid, &Kek)]) -> Result<Rotation> {
         self.rotate_master(keks, &[id])
+    }
+
+    /// Remove a keyslot *without* rotating MK. Old copies of the file still
+    /// open with the removed credential, so this is only for replacing a
+    /// login password's slots when a rotation is impossible without the
+    /// user (FIDO2 slots need a touch), and the caller must have MK rotated
+    /// soon. The next write does not keep the previous file as `.bak`.
+    /// Recovery slots cannot be removed this way.
+    pub fn remove_keyslot_keeping_mk(&mut self, id: Uuid) -> Result<()> {
+        let at = self
+            .entries
+            .iter()
+            .position(|e| matches!(e, SlotEntry::Known(k) if k.id == id))
+            .ok_or(Error::NoSuchKeyslot(id))?;
+        if matches!(&self.entries[at], SlotEntry::Known(k) if matches!(k.kind, SlotKind::Recovery(_)))
+        {
+            return Err(Error::RecoveryRequired);
+        }
+        self.entries.remove(at);
+        self.rotated.store(true, Ordering::SeqCst);
+        Ok(())
     }
 
     /// Replace MK and re-wrap every slot. Slots in `drop` are removed
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-core && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 59 passed | ok. 1 passed | ok. 28 passed | ok. 11 passed | ok. 1 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **a slot removed keeping MK never keeps .bak** (`crates/aleph-core/src/vault.rs`), test `cargo test -p aleph-core --test write keeping_mk`:

  replace

  ```rust
  self.entries.remove(at);
  self.rotated.store(true, Ordering::SeqCst);
  ```

  with

  ```rust
  self.entries.remove(at);
  ```

- **the recovery slot cannot be removed keeping MK** (`crates/aleph-core/src/vault.rs`), test `cargo test -p aleph-core --test vault keeping_mk`: replace `if matches!(&self.entries[at], SlotEntry::Known(k) if matches!(k.kind, SlotKind::Recovery(_)))` with `if false`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-core
git commit -m "feat(core): remove a keyslot while keeping the master key" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: password changes, re-sealing, and login-stack passwords in the engine

**Interfaces:**
- Consumes: Task 2.
- Produces:
  - `aleph_prompt_proto::ToPrompter::OldPassword { error: Option<String> }` (needs a `Password` reply)
  - `aleph_daemon::Error::PasswordChanged`
  - `state::SlotState::{rotation_pending, set_rotation_pending}`; `keyring::Status::rotation_pending`
  - `Keyring::change_login_password(&str, &str) -> Result<String>`
  - `Keyring::unlock_with_login_password` (now PAM-checked, not queued behind `ops`)
  - CLI: `status` shows a pending rotation; the terminal prompter answers `OldPassword`

- [ ] **Step 1: Write the failing tests**

Apply this patch with `git apply` (save it as `/tmp/t3-tests.patch`):

```diff
--- a/crates/aleph-prompt-proto/src/lib.rs
+++ b/crates/aleph-prompt-proto/src/lib.rs
@@ -163,4 +163,16 @@
             serde_json::from_str(r#"{"type":"password","password":"hunter2"}"#).unwrap();
         assert!(!format!("{p:?}").contains("hunter2"));
     }
+
+    /// The previous-password question expects an answer, and its wire form
+    /// is fixed (prompters in other programs match on it).
+    #[test]
+    fn the_old_password_question_needs_a_reply() {
+        let m = ToPrompter::OldPassword { error: None };
+        assert!(m.needs_reply());
+        assert_eq!(
+            serde_json::to_string(&m).unwrap(),
+            r#"{"type":"old_password","error":null}"#
+        );
+    }
 }
--- a/crates/aleph-daemon/src/state.rs
+++ b/crates/aleph-daemon/src/state.rs
@@ -111,6 +111,22 @@
         assert!(!s.is_stale(a) && !s.is_stale(b));
     }
 
+    /// A pending rotation persists; files written before it existed load.
+    #[test]
+    fn a_pending_rotation_persists_and_old_files_load() {
+        let dir = tempfile::tempdir().unwrap();
+        let path = dir.path().join("slots.json");
+        let a = Uuid::new_v4();
+        std::fs::write(&path, format!("{{\"stale\":[\"{a}\"]}}")).unwrap();
+        let mut s = SlotState::load(&path);
+        assert!(s.is_stale(a) && !s.rotation_pending());
+        s.set_rotation_pending(true).unwrap();
+        let mut s = SlotState::load(&path);
+        assert!(s.rotation_pending() && s.is_stale(a));
+        s.set_rotation_pending(false).unwrap();
+        assert!(!SlotState::load(&path).rotation_pending());
+    }
+
     #[test]
     fn a_corrupt_file_means_nothing_is_stale() {
         let dir = tempfile::tempdir().unwrap();
--- a/crates/aleph-daemon/src/error.rs
+++ b/crates/aleph-daemon/src/error.rs
@@ -106,12 +106,14 @@
     /// Stale-slot advice is read while the vault is locked, so it must not
     /// send the user to commands that need it unlocked (re-enrolling) or
     /// that only repeat the failure (`keyslot retry`); what works then is
-    /// setting the previous password again.
+    /// the previous password, which updates the slot (§5).
     #[test]
     fn stale_advice_works_while_locked() {
-        let stale = Error::Stale("tpm".into()).to_string();
-        for advice in [stale.as_str(), ALL_STALE] {
-            assert!(advice.contains("passwd"), "{advice}");
+        for advice in [
+            Error::Stale("tpm".into()).to_string(),
+            Error::PasswordChanged.to_string(),
+        ] {
+            assert!(advice.contains("previous password"), "{advice}");
             assert!(!advice.contains("re-enroll it with"), "{advice}");
             assert!(!advice.contains("keyslot retry"), "{advice}");
         }
--- a/crates/aleph-daemon/tests/keyring.rs
+++ b/crates/aleph-daemon/tests/keyring.rs
@@ -87,7 +87,8 @@
 }
 
 /// A TPM slot that rejects a password PAM accepts (the password changed
-/// elsewhere) is marked stale and no longer offered; retrying clears it.
+/// elsewhere) is marked stale, and the previous password is asked for
+/// (declined here); retrying clears the mark.
 #[test]
 fn a_slot_that_rejects_the_current_password_goes_stale() {
     let env = env();
@@ -102,12 +103,15 @@
         password: Box::new(Fixed(|p| p == "new password")),
     };
     let k = Keyring::new(&env.paths, backends).unwrap();
-    let p = Interactive::new(vec![password("new password")]);
-    assert!(k.unlock(&mut p.channel(), None).is_err());
-    let errors = asks(&p.sent());
+    let p = Interactive::new(vec![password("new password"), FromPrompter::Cancel {}]);
+    assert!(matches!(
+        k.unlock(&mut p.channel(), None),
+        Err(Error::Cancelled)
+    ));
     assert!(
-        errors[1].0.as_deref().unwrap().contains("stale"),
-        "{errors:?}"
+        p.sent()
+            .iter()
+            .any(|m| matches!(m, ToPrompter::OldPassword { error: None }))
     );
     let tpm = k
         .status()
@@ -117,14 +121,555 @@
         .find(|s| s.kind == "tpm")
         .unwrap();
     assert!(tpm.stale);
-    // With the only password slot stale, there is nothing to offer.
-    let p = Interactive::new(vec![]);
-    assert!(matches!(
-        k.unlock(&mut p.channel(), None),
-        Err(Error::NoMethodWorked(_))
-    ));
     k.retry_slot(tpm.id).unwrap();
     assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
+}
+
+/// The TPM slots' ids and the master key's id on disk.
+fn slots_and_mk(k: &Keyring, env: &Env, kind: &str) -> (Vec<uuid::Uuid>, [u8; 16]) {
+    let ids = k
+        .status()
+        .unwrap()
+        .keyslots
+        .into_iter()
+        .filter(|s| s.kind == kind)
+        .map(|s| s.id)
+        .collect();
+    let mk = aleph_core::LockedVault::read(&env.paths.vault())
+        .unwrap()
+        .mark()
+        .mk_id;
+    (ids, mk)
+}
+
+/// `passwd` (through `pam_aleph`) replaces the TPM slot with one sealed
+/// under the new password and rotates MK: the old slot is gone and the
+/// new password unlocks, with no failed TPM attempt.
+#[test]
+fn a_password_change_reseals_the_tpm_slot_and_rotates() {
+    let env = env();
+    let login = Accepting::new(PW);
+    let k = keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::default(),
+        Box::new(login.clone()),
+    );
+    create_with_password(&k);
+    let (before, mk_before) = slots_and_mk(&k, &env, "tpm");
+    login.set("new");
+    let done = k.change_login_password(PW, "new").unwrap();
+    assert!(done.contains("rotated"), "{done}");
+    let (after, mk_after) = slots_and_mk(&k, &env, "tpm");
+    assert_eq!(after.len(), 1);
+    assert_ne!(after, before);
+    assert_ne!(mk_after, mk_before);
+    k.lock();
+    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
+        .unwrap();
+    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
+    assert!(!k.status().unwrap().rotation_pending);
+}
+
+/// With a FIDO2 slot (which needs a touch) MK cannot rotate during
+/// `passwd`: the TPM slot is replaced keeping MK, and a rotation is marked
+/// pending until the user runs one.
+#[test]
+fn with_a_security_key_a_password_change_marks_a_rotation_pending() {
+    let env = env();
+    let login = Accepting::new(PW);
+    let k = keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::one(MockAuthenticator::with_pin(PIN)),
+        Box::new(login.clone()),
+    );
+    create_with_password(&k);
+    k.enroll_fido2(
+        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
+        false,
+    )
+    .unwrap();
+    let (before, mk_before) = slots_and_mk(&k, &env, "tpm");
+    login.set("new");
+    let done = k.change_login_password(PW, "new").unwrap();
+    assert!(done.contains("rotate-master"), "{done}");
+    let (after, mk_after) = slots_and_mk(&k, &env, "tpm");
+    assert_eq!(after.len(), 1);
+    assert_ne!(after, before);
+    assert_eq!(mk_after, mk_before);
+    assert_eq!(slots_and_mk(&k, &env, "fido2").0.len(), 1);
+    assert!(k.status().unwrap().rotation_pending);
+    // Every unlock repeats it until done.
+    k.lock();
+    let p = Interactive::new(vec![password("new")]);
+    k.unlock(&mut p.channel(), None).unwrap();
+    assert!(
+        matches!(
+            p.sent().last(),
+            Some(ToPrompter::Done { ok: true, message: Some(m) }) if m.contains("rotate-master")
+        ),
+        "{:?}",
+        p.sent().last()
+    );
+    let p = Interactive::new(vec![password("new"), pin(PIN)]);
+    k.rotate_master(&mut p.channel()).unwrap();
+    assert!(!k.status().unwrap().rotation_pending);
+    assert_ne!(slots_and_mk(&k, &env, "tpm").1, mk_before);
+}
+
+/// A password change while locked opens the vault with the old password
+/// for the change, then locks it again.
+#[test]
+fn a_password_change_while_locked_leaves_it_locked() {
+    let env = env();
+    let login = Accepting::new(PW);
+    let k = keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::default(),
+        Box::new(login.clone()),
+    );
+    create_with_password(&k);
+    k.lock();
+    login.set("new");
+    k.change_login_password(PW, "new").unwrap();
+    assert!(k.is_locked());
+    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
+        .unwrap();
+}
+
+/// A login-password slot (no TPM) is replaced by one for the new password.
+#[test]
+fn a_password_change_replaces_a_login_password_slot() {
+    let env = env();
+    let login = Accepting::new(PW);
+    let k = keyring_with(
+        &env,
+        Box::new(NoTpm),
+        MockKeys::default(),
+        Box::new(login.clone()),
+    );
+    create_with_password(&k);
+    login.set("new");
+    k.change_login_password(PW, "new").unwrap();
+    k.lock();
+    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
+        .unwrap();
+    assert_eq!(slots_and_mk(&k, &env, "login-password").0.len(), 1);
+}
+
+/// `pam_aleph` runs even when `passwd` failed to change the password: a new
+/// password PAM does not accept changes nothing.
+#[test]
+fn a_failed_passwd_changes_nothing() {
+    let env = env();
+    let k = keyring(&env, MockKeys::default());
+    create_with_password(&k);
+    let before = slots_and_mk(&k, &env, "tpm");
+    assert!(k.change_login_password(PW, "new").is_err());
+    assert_eq!(slots_and_mk(&k, &env, "tpm"), before);
+}
+
+/// A password from the login stack is still checked with PAM when PAM can:
+/// a wrong one never reaches the TPM or marks a slot stale.
+#[test]
+fn a_wrong_login_stack_password_never_reaches_the_tpm() {
+    let env = env();
+    let k = keyring(&env, MockKeys::default());
+    create_with_password(&k);
+    k.lock();
+    assert!(matches!(
+        k.unlock_with_login_password("wrong"),
+        Err(Error::WrongPassword)
+    ));
+    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
+    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
+    k.unlock_with_login_password(PW).unwrap();
+    assert!(!k.is_locked());
+}
+
+/// A login password does not wait behind an open conversation (a prompter
+/// nobody is answering, say while the screen is locked): it unlocks at
+/// once, and the conversation's own late result does not replace it.
+#[test]
+fn a_login_password_does_not_wait_for_a_conversation() {
+    let env = env();
+    let k = Arc::new(keyring(&env, MockKeys::default()));
+    create_with_password(&k);
+    k.lock();
+    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
+    let mut silent =
+        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(60)).unwrap();
+    let waiting = {
+        let k = k.clone();
+        std::thread::spawn(move || k.unlock(&mut silent, None))
+    };
+    std::thread::sleep(std::time::Duration::from_millis(200));
+    // While the prompter stays silent (its timeout is a minute), the login
+    // password gets in.
+    let (done, wait_done) = std::sync::mpsc::channel();
+    {
+        let k = k.clone();
+        std::thread::spawn(move || done.send(k.unlock_with_login_password(PW)).unwrap());
+    }
+    let unlocked = wait_done.recv_timeout(std::time::Duration::from_secs(30));
+    drop(theirs); // the prompter goes away: the conversation ends
+    unlocked.expect("the login password did not wait").unwrap();
+    assert!(!k.is_locked());
+    assert!(waiting.join().unwrap().is_err());
+    assert!(!k.is_locked());
+}
+
+/// Whichever opens the vault first stays: a conversation that finishes
+/// after a login password unlocked it (and a secret was stored meanwhile,
+/// and the vault locked again) does not put back the older copy it opened:
+/// it opens the current file, which is neither lost nor read as a rollback.
+#[test]
+fn a_late_unlock_does_not_replace_the_open_vault() {
+    use std::io::{BufRead, BufReader, Write};
+    let env = env();
+    let k = Arc::new(keyring(&env, MockKeys::default()));
+    create_with_password(&k);
+    k.lock();
+    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
+    let mut chan =
+        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(10)).unwrap();
+    let (asked, wait_asked) = std::sync::mpsc::channel();
+    let (answer, wait_answer) = std::sync::mpsc::channel::<()>();
+    // A prompter that answers the password question only when told.
+    let prompter = std::thread::spawn(move || {
+        let mut reader = BufReader::new(theirs.try_clone().unwrap());
+        let mut writer = theirs;
+        let mut line = String::new();
+        while reader.read_line(&mut line).unwrap() > 0 {
+            let msg: ToPrompter = serde_json::from_str(&line).unwrap();
+            line.clear();
+            match msg {
+                ToPrompter::Ask { .. } => {
+                    asked.send(()).unwrap();
+                    wait_answer.recv().unwrap();
+                    let mut out = serde_json::to_vec(&password(PW)).unwrap();
+                    out.push(b'\n');
+                    writer.write_all(&out).unwrap();
+                }
+                ToPrompter::Done { .. } => return,
+                _ => {}
+            }
+        }
+    });
+    let conversation = {
+        let k = k.clone();
+        std::thread::spawn(move || k.unlock(&mut chan, None))
+    };
+    wait_asked.recv().unwrap();
+    k.unlock_with_login_password(PW).unwrap();
+    k.modify(|b| {
+        b.collections[0].upsert(
+            aleph_core::Item::new(
+                "x",
+                Default::default(),
+                aleph_core::SecretBytes::new(b"s".to_vec()),
+                "text/plain",
+            ),
+            false,
+        );
+        Ok(())
+    })
+    .unwrap();
+    k.lock();
+    answer.send(()).unwrap();
+    conversation.join().unwrap().unwrap();
+    prompter.join().unwrap();
+    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
+    assert_eq!(k.status().unwrap().untrusted, None);
+}
+
+/// A prompter that answers "security key", then holds the PIN question
+/// until told, then cancels. Returns (the channel, a receiver that fires
+/// when the PIN is asked, a sender that lets it cancel, its thread).
+fn holding_pin_prompter() -> (
+    aleph_daemon::prompt::Channel,
+    std::sync::mpsc::Receiver<()>,
+    std::sync::mpsc::Sender<()>,
+    std::thread::JoinHandle<()>,
+) {
+    use std::io::{BufRead, BufReader, Write};
+    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
+    let chan =
+        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(60)).unwrap();
+    let (asked, wait_asked) = std::sync::mpsc::channel();
+    let (release, wait_release) = std::sync::mpsc::channel::<()>();
+    let thread = std::thread::spawn(move || {
+        let mut reader = BufReader::new(theirs.try_clone().unwrap());
+        let mut writer = theirs;
+        let mut line = String::new();
+        let mut reply = |r: &FromPrompter| {
+            let mut out = serde_json::to_vec(r).unwrap();
+            out.push(b'\n');
+            writer.write_all(&out).unwrap();
+        };
+        while reader.read_line(&mut line).unwrap() > 0 {
+            let msg: ToPrompter = serde_json::from_str(&line).unwrap();
+            line.clear();
+            match msg {
+                ToPrompter::Ask { .. } => reply(&FromPrompter::Fido2 {}),
+                ToPrompter::Fido2Pin { .. } => {
+                    asked.send(()).unwrap();
+                    wait_release.recv().unwrap();
+                    reply(&FromPrompter::Cancel {});
+                }
+                ToPrompter::Done { .. } => return,
+                _ => {}
+            }
+        }
+    });
+    (chan, wait_asked, release, thread)
+}
+
+/// A login password does not wait behind a security-key conversation
+/// either, even while its PIN question is open (the hardware is not held
+/// while the prompter is asked).
+#[test]
+fn a_login_password_does_not_wait_behind_a_pin_prompt() {
+    let env = env();
+    let k = Arc::new(keyring(
+        &env,
+        MockKeys::one(MockAuthenticator::with_pin(PIN)),
+    ));
+    create_with_password(&k);
+    k.enroll_fido2(
+        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
+        false,
+    )
+    .unwrap();
+    k.lock();
+    let (mut chan, pin_asked, release, prompter) = holding_pin_prompter();
+    let conversation = {
+        let k = k.clone();
+        std::thread::spawn(move || k.unlock(&mut chan, None))
+    };
+    pin_asked.recv().unwrap();
+    // While the PIN question stays open (the prompter's timeout is a
+    // minute), the login password gets in.
+    let (done, wait_done) = std::sync::mpsc::channel();
+    {
+        let k = k.clone();
+        std::thread::spawn(move || done.send(k.unlock_with_login_password(PW)).unwrap());
+    }
+    let unlocked = wait_done.recv_timeout(std::time::Duration::from_secs(30));
+    release.send(()).unwrap();
+    unlocked
+        .expect("the login password did not wait for the PIN")
+        .unwrap();
+    assert!(conversation.join().unwrap().is_err());
+    prompter.join().unwrap();
+    assert!(!k.is_locked());
+}
+
+/// `passwd` still changes the slots after a login with the new password got
+/// there first (and marked the old TPM slot stale): the change opens the
+/// file with the previous password whatever the stale mark.
+#[test]
+fn passwd_after_a_login_with_the_new_password_still_changes() {
+    let env = env();
+    let login = Accepting::new(PW);
+    let k = keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::default(),
+        Box::new(login.clone()),
+    );
+    create_with_password(&k);
+    k.lock();
+    login.set("new");
+    assert!(matches!(
+        k.unlock_with_login_password("new"),
+        Err(Error::PasswordChanged)
+    ));
+    k.change_login_password(PW, "new").unwrap();
+    let p = Interactive::new(vec![password("new")]);
+    k.unlock(&mut p.channel(), None).unwrap();
+    assert!(
+        !p.sent()
+            .iter()
+            .any(|m| matches!(m, ToPrompter::OldPassword { .. }))
+    );
+}
+
+/// When PAM cannot vouch for the new password, the old one must open the
+/// vault file first: no same-user process can re-seal the vault under a
+/// password of its choosing.
+#[test]
+fn without_pam_a_change_must_prove_the_old_password() {
+    #[derive(Clone, Default)]
+    struct Vanishing(Arc<std::sync::atomic::AtomicBool>);
+    impl aleph_daemon::password::PasswordCheck for Vanishing {
+        fn check(&self, pw: &str) -> aleph_daemon::Result<bool> {
+            if self.0.load(std::sync::atomic::Ordering::SeqCst) {
+                return Err(Error::PasswordCheckUnavailable);
+            }
+            Ok(pw == PW)
+        }
+    }
+    let env = env();
+    let pam = Vanishing::default();
+    let k = keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::default(),
+        Box::new(pam.clone()),
+    );
+    create_with_password(&k);
+    pam.0.store(true, std::sync::atomic::Ordering::SeqCst);
+    let before = slots_and_mk(&k, &env, "tpm");
+    assert!(matches!(
+        k.change_login_password("junk", "chosen"),
+        Err(Error::WrongPassword)
+    ));
+    assert_eq!(slots_and_mk(&k, &env, "tpm"), before);
+    k.change_login_password(PW, "chosen").unwrap();
+    assert_ne!(slots_and_mk(&k, &env, "tpm").0, before.0);
+}
+
+/// The previous password is asked at most twice per conversation, even
+/// when the current one is typed again in between.
+#[test]
+fn the_previous_password_is_asked_at_most_twice_per_conversation() {
+    let env = env();
+    let login = Accepting::new(PW);
+    let k = keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::default(),
+        Box::new(login.clone()),
+    );
+    create_with_password(&k);
+    k.lock();
+    login.set("new");
+    let p = Interactive::new(vec![
+        password("new"),
+        password("wrong 1"),
+        password("wrong 2"),
+        password("new"),
+        password("wrong 3"),
+    ]);
+    assert!(k.unlock(&mut p.channel(), None).is_err());
+    let asked = p
+        .sent()
+        .iter()
+        .filter(|m| matches!(m, ToPrompter::OldPassword { .. }))
+        .count();
+    assert_eq!(asked, 2);
+}
+
+/// Declining the previous-password question returns to the choice of
+/// method; a security key then opens the vault, and the TPM slot is still
+/// re-sealed under the current password.
+#[test]
+fn declining_the_previous_password_leaves_the_security_key() {
+    let env = env();
+    let login = Accepting::new(PW);
+    let k = keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::one(MockAuthenticator::with_pin(PIN)),
+        Box::new(login.clone()),
+    );
+    create_with_password(&k);
+    k.enroll_fido2(
+        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
+        false,
+    )
+    .unwrap();
+    let (before, _) = slots_and_mk(&k, &env, "tpm");
+    k.lock();
+    login.set("new");
+    let p = Interactive::new(vec![
+        password("new"),
+        FromPrompter::Cancel {},
+        FromPrompter::Fido2 {},
+        pin(PIN),
+    ]);
+    k.unlock(&mut p.channel(), None).unwrap();
+    let (after, _) = slots_and_mk(&k, &env, "tpm");
+    assert_eq!(after.len(), 1);
+    assert_ne!(after, before);
+    k.lock();
+    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
+        .unwrap();
+    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
+}
+
+/// After an outside password change (PAM accepts the new password, the TPM
+/// slot was sealed under the old one), the previous password opens the
+/// vault and the slot is re-sealed under the new one: one failed TPM
+/// attempt in all, and the next unlock needs only the new password.
+#[test]
+fn a_password_changed_elsewhere_is_resealed_with_the_previous_one() {
+    let env = env();
+    let login = Accepting::new(PW);
+    let k = keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::default(),
+        Box::new(login.clone()),
+    );
+    create_with_password(&k);
+    let (before, _) = slots_and_mk(&k, &env, "tpm");
+    k.lock();
+    login.set("new");
+    let p = Interactive::new(vec![password("new"), password(PW)]);
+    k.unlock(&mut p.channel(), None).unwrap();
+    assert!(
+        p.sent()
+            .iter()
+            .any(|m| matches!(m, ToPrompter::OldPassword { .. }))
+    );
+    let (after, _) = slots_and_mk(&k, &env, "tpm");
+    assert_ne!(after, before);
+    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
+    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
+    k.lock();
+    let p = Interactive::new(vec![password("new")]);
+    k.unlock(&mut p.channel(), None).unwrap();
+    assert!(
+        !p.sent()
+            .iter()
+            .any(|m| matches!(m, ToPrompter::OldPassword { .. }))
+    );
+    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
+}
+
+/// Wrong previous passwords go straight to the TPM, so they are few: at
+/// most two per conversation, and the TPM helper's own limit holds.
+#[test]
+fn wrong_previous_passwords_are_few() {
+    let env = env();
+    let login = Accepting::new(PW);
+    let k = keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::default(),
+        Box::new(login.clone()),
+    );
+    create_with_password(&k);
+    k.lock();
+    login.set("new");
+    let p = Interactive::new(vec![
+        password("new"),
+        password("wrong"),
+        password("wrong"),
+        password("wrong"),
+    ]);
+    assert!(k.unlock(&mut p.channel(), None).is_err());
+    let old_asked = p
+        .sent()
+        .iter()
+        .filter(|m| matches!(m, ToPrompter::OldPassword { .. }))
+        .count();
+    assert!(old_asked <= 2, "{old_asked}");
+    assert!(env.sw.tpm().status().unwrap().failed_tries <= 2);
 }
 
 /// Refusals that say nothing about the slot (here the TPM's reserve)
@@ -384,9 +929,8 @@
     assert!(waiting.join().unwrap().is_err());
 }
 
-/// `status` never waits for the hardware: while a FIDO2 unlock waits for
-/// the key to be plugged in (holding the hardware), it answers at once,
-/// with the TPM's usability unknown.
+/// `status` never waits for a conversation: while a FIDO2 unlock waits for
+/// the key to be plugged in, it answers at once.
 #[test]
 fn status_does_not_wait_while_a_key_is_awaited() {
     let env = env();
@@ -404,13 +948,13 @@
     };
     std::thread::sleep(std::time::Duration::from_millis(150));
     let t = std::time::Instant::now();
-    let s = k.status().unwrap();
+    k.status().unwrap();
+    // (One round trip to the TPM helper at most; the key wait takes 600 ms.)
     assert!(
-        t.elapsed() < std::time::Duration::from_millis(100),
+        t.elapsed() < std::time::Duration::from_millis(500),
         "{:?}",
         t.elapsed()
     );
-    assert_eq!(s.tpm, None);
     assert!(waiting.join().unwrap().is_err());
 }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-prompt-proto -p aleph-daemon`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Apply this patch with `git apply` (save it as `/tmp/t3-impl.patch`):

```diff
--- a/crates/aleph-prompt-proto/src/lib.rs
+++ b/crates/aleph-prompt-proto/src/lib.rs
@@ -83,6 +83,12 @@
         /// Seconds until trying again can succeed, when known.
         retry_after: Option<u64>,
     },
+    /// The login password changed without aleph: PAM accepts the one just
+    /// given, but the TPM keyslot was sealed under the previous one. Ask
+    /// for the previous password (reply `Password`) to update the slot.
+    OldPassword {
+        error: Option<String>,
+    },
     /// The key `key` needs its PIN (reply `Pin`).
     Fido2Pin {
         key: String,
@@ -118,6 +124,7 @@
         matches!(
             self,
             Self::Ask { .. }
+                | Self::OldPassword { .. }
                 | Self::Fido2Pin { .. }
                 | Self::Confirm { .. }
                 | Self::ShowRecoveryKey { .. }
--- a/crates/aleph-daemon/src/state.rs
+++ b/crates/aleph-daemon/src/state.rs
@@ -18,27 +18,47 @@
 #[serde(deny_unknown_fields)]
 struct File {
     stale: BTreeSet<Uuid>,
+    /// A password change replaced slots without rotating MK (spec §5
+    /// "Password change"); the next rotation clears it.
+    #[serde(default)]
+    rotation_pending: bool,
 }
 
 #[derive(Debug)]
 pub struct SlotState {
     path: PathBuf,
     stale: BTreeSet<Uuid>,
+    rotation_pending: bool,
 }
 
 impl SlotState {
     /// Load the state; a missing or unreadable file means "nothing stale"
     /// (the worst case is one extra attempt per slot).
     pub fn load(path: &Path) -> Self {
-        let stale = std::fs::read(path)
-            .ok()
-            .and_then(|b| serde_json::from_slice::<File>(&b).ok())
-            .map(|f| f.stale)
-            .unwrap_or_default();
+        let file = match std::fs::read(path) {
+            Ok(b) => serde_json::from_slice::<File>(&b).unwrap_or_else(|e| {
+                tracing::warn!("ignoring unreadable {}: {e}", path.display());
+                File::default()
+            }),
+            Err(_) => File::default(),
+        };
         Self {
             path: path.to_path_buf(),
-            stale,
+            stale: file.stale,
+            rotation_pending: file.rotation_pending,
         }
+    }
+
+    pub fn rotation_pending(&self) -> bool {
+        self.rotation_pending
+    }
+
+    pub fn set_rotation_pending(&mut self, pending: bool) -> Result<()> {
+        if self.rotation_pending != pending {
+            self.rotation_pending = pending;
+            self.save()?;
+        }
+        Ok(())
     }
 
     pub fn is_stale(&self, slot: Uuid) -> bool {
@@ -82,6 +102,7 @@
             &tmp,
             serde_json::to_vec(&File {
                 stale: self.stale.clone(),
+                rotation_pending: self.rotation_pending,
             })
             .expect("serializable"),
         )?;
--- a/crates/aleph-daemon/src/error.rs
+++ b/crates/aleph-daemon/src/error.rs
@@ -32,9 +32,14 @@
     WrongPassword,
 
     #[error(
-        "the TPM keyslot '{0}' no longer accepts your login password (was it changed?) and is marked stale; unlock with another method, or set the previous password again with `passwd`, unlock, and run `aleph keyslot add tpm` before changing it"
+        "the TPM keyslot '{0}' no longer accepts your login password (was it changed?) and is marked stale; unlock again and give your previous password when asked, to update it"
     )]
     Stale(String),
+
+    #[error(
+        "your login password no longer opens the TPM keyslot (was it changed without aleph?); your previous password can update it"
+    )]
+    PasswordChanged,
 
     #[error("too many wrong passwords; retry in {} s", .retry_after.as_secs())]
     TooManyAttempts { retry_after: Duration },
@@ -96,9 +101,6 @@
 
 pub type Result<T> = std::result::Result<T, Error>;
 
-/// Why unlocking cannot start when every enrolled method is stale.
-pub(crate) const ALL_STALE: &str = "every enrolled unlock method is stale (was your login password changed?); set the previous password again with `passwd`, then unlock";
-
 #[cfg(test)]
 mod tests {
     use super::*;
--- a/crates/aleph-daemon/src/keyring.rs
+++ b/crates/aleph-daemon/src/keyring.rs
@@ -91,6 +91,9 @@
     /// (the hardware is busy with a prompt, and status never waits).
     pub tpm: Option<bool>,
     pub keyslots: Vec<SlotInfo>,
+    /// A password change replaced slots without rotating MK (FIDO2 slots
+    /// need a touch): `aleph keyslot rotate-master` should follow.
+    pub rotation_pending: bool,
 }
 
 /// Answers a conversation accepts before giving up.
@@ -100,6 +103,9 @@
 const PIN_ATTEMPTS: usize = 3;
 /// Tries at a login-password slot's own password during a rotation.
 const SLOT_PASSWORD_ATTEMPTS: usize = 3;
+/// Tries at the previous login password after an outside change: each
+/// wrong one goes straight to the TPM (PAM no longer knows it).
+const OLD_PASSWORD_ATTEMPTS: usize = 2;
 
 /// KEKs gathered for a rotation, by slot.
 type Keks = Vec<(Uuid, Kek)>;
@@ -122,6 +128,9 @@
     vault: UnlockedVault,
     slot: Uuid,
     kek: Option<Kek>,
+    /// Opened with the previous login password: re-seal the password slots
+    /// under this one, the current login password, once installed.
+    reseal: Option<Zeroizing<String>>,
 }
 
 struct Inner {
@@ -220,6 +229,7 @@
             memory_locked: inner.vault.as_ref().map(UnlockedVault::memory_locked),
             tpm,
             keyslots,
+            rotation_pending: inner.state.rotation_pending(),
         })
     }
 
@@ -280,16 +290,15 @@
     }
 
     /// The methods the prompter may offer for `vault`: the login password
-    /// if a usable password slot exists, FIDO2 if a FIDO2 slot does. Never
-    /// recovery (§5: recovery is its own flow).
+    /// if a password slot exists (a stale TPM slot counts: the password
+    /// leads to re-sealing it, §5 "Password change"), FIDO2 if a FIDO2 slot
+    /// does. Never recovery (§5: recovery is its own flow).
     fn methods(&self, vault: &LockedVault) -> Vec<Method> {
-        let inner = lock(&self.inner);
         let mut password = false;
         let mut fido = false;
         for k in vault.keyslots() {
             match &k.kind {
-                SlotKind::Tpm(_) if !inner.state.is_stale(k.id) => password = true,
-                SlotKind::LoginPassword(_) => password = true,
+                SlotKind::Tpm(_) | SlotKind::LoginPassword(_) => password = true,
                 SlotKind::Fido2(_) => fido = true,
                 _ => {}
             }
@@ -363,30 +372,73 @@
             return Ok(None);
         }
         let locked = lock(&self.inner).store.read()?;
-        let opened = self.choose_and_open(chan, &locked)?;
-        self.install(opened.vault)
-    }
-
-    /// Unlock with a password the login stack already accepted (from
-    /// `pam_aleph`, Plan 4): no PAM check, no typed-attempt accounting.
+        let Opened {
+            vault,
+            slot,
+            kek,
+            reseal,
+        } = self.choose_and_open(chan, &locked)?;
+        let warning = self.install(vault, slot, kek.as_ref())?;
+        let pending = |message: Option<String>| -> Option<String> {
+            if !lock(&self.inner).state.rotation_pending() {
+                return message;
+            }
+            let note = "a password change still needs the master key rotated: run `aleph keyslot rotate-master`";
+            Some(match message {
+                Some(m) => format!("{m}; {note}"),
+                None => note.into(),
+            })
+        };
+        let Some(current) = reseal else {
+            return Ok(pending(warning));
+        };
+        // Opened with the previous password: seal under the current one.
+        // The vault is open either way; a failure here is only reported.
+        let update = match self.replace_password_slots(&current) {
+            Ok(done) => done,
+            Err(e) => {
+                tracing::warn!("could not update the password keyslots: {e}");
+                format!("the TPM keyslot could not be updated ({e}); unlock again to retry")
+            }
+        };
+        Ok(pending(Some(match warning {
+            Some(w) => format!("{w}; {update}"),
+            None => update,
+        })))
+    }
+
+    /// Unlock with a password from the login stack (`pam_aleph` through
+    /// `pam.sock`). It is still checked with PAM when PAM can check, so a
+    /// wrong one never reaches the TPM; only when PAM cannot is the login
+    /// stack trusted. No typed-attempt accounting (`pam.sock` limits its
+    /// own failures). It does not wait for a running conversation: whichever
+    /// opens the vault first is installed.
     pub fn unlock_with_login_password(&self, password: &str) -> Result<()> {
-        let _op = lock(&self.ops);
         if !self.is_locked() {
             return Ok(());
         }
+        if let Ok(false) = lock(&self.hw).password.check(password) {
+            return Err(Error::WrongPassword);
+        }
         let locked = lock(&self.inner).store.read()?;
         let opened = self.open_with_password(&locked, password, false)?;
-        self.install(opened.vault).map(|_| ())
+        self.install(opened.vault, opened.slot, opened.kek.as_ref())
+            .map(|_| ())
     }
 
     /// Ask for a method until one opens `vault` (or the user cancels).
     fn choose_and_open(&self, chan: &mut Channel, vault: &LockedVault) -> Result<Opened> {
         let methods = self.methods(vault);
         if methods.is_empty() {
-            return Err(Error::NoMethodWorked(Some(crate::error::ALL_STALE.into())));
+            return Err(Error::NoMethodWorked(None));
         }
         let mut error: Option<String> = None;
         let mut retry_after = None;
+        // The current login password, once PAM accepted one that opens no
+        // TPM slot: whatever opens the vault then, it re-seals under it.
+        let mut current: Option<Zeroizing<String>> = None;
+        // Previous-password tries so far (each goes straight to the TPM).
+        let mut old_tries = 0;
         for _ in 0..MAX_ATTEMPTS {
             let reply = chan.ask(&ToPrompter::Ask {
                 methods: methods.clone(),
@@ -395,7 +447,23 @@
             })?;
             let attempt = match reply {
                 FromPrompter::Password { password } if methods.contains(&Method::Password) => {
-                    self.open_with_password(vault, password.expose(), true)
+                    match self.open_with_password(vault, password.expose(), true) {
+                        Err(Error::PasswordChanged) => {
+                            current = Some(Zeroizing::new(password.expose().to_string()));
+                            match self.open_with_old_password(
+                                chan,
+                                vault,
+                                password.expose(),
+                                &mut old_tries,
+                            ) {
+                                // Declined: back to the choice (a security
+                                // key, say), keeping the current password.
+                                Err(Error::Cancelled) => Err(Error::PasswordChanged),
+                                other => other,
+                            }
+                        }
+                        other => other,
+                    }
                 }
                 FromPrompter::Fido2 {} if methods.contains(&Method::Fido2) => {
                     self.open_with_fido2(chan, vault, None)
@@ -403,7 +471,12 @@
                 other => return Err(Error::Prompt(format!("unexpected reply {other:?}"))),
             };
             match attempt {
-                Ok(opened) => return Ok(opened),
+                Ok(mut opened) => {
+                    if opened.reseal.is_none() {
+                        opened.reseal = current;
+                    }
+                    return Ok(opened);
+                }
                 // Waiting is not something to retry at once, and a key's
                 // PIN budget for this conversation is spent (each wrong
                 // PIN costs one of the key's lifetime retries).
@@ -428,7 +501,11 @@
     /// Try `password` on the usable password slots: TPM slots first (after
     /// a PAM check if it was typed, so typos never reach the TPM), then
     /// login-password slots. A TPM slot that rejects a password PAM
-    /// accepted is marked stale.
+    /// accepted is marked stale. A password the login stack vouches for
+    /// (PAM accepted it, or it came from `pam_aleph`) that no TPM slot
+    /// takes, every one being stale or rejecting it, is
+    /// `Error::PasswordChanged`: the login password was changed without
+    /// aleph.
     fn open_with_password(
         &self,
         vault: &LockedVault,
@@ -436,6 +513,7 @@
         typed: bool,
     ) -> Result<Opened> {
         let now = Instant::now();
+        let any_tpm = vault.keyslots().any(|k| matches!(k.kind, SlotKind::Tpm(_)));
         let (tpm_slots, password_slots): (Vec<_>, Vec<_>) = {
             let mut inner = lock(&self.inner);
             if typed && let Some(wait) = inner.typed.blocked(now) {
@@ -450,17 +528,18 @@
                 })
                 .partition(|k| matches!(k.kind, SlotKind::Tpm(_)))
         };
-        if tpm_slots.is_empty() && password_slots.is_empty() {
-            return Err(Error::NoMethodWorked(Some(
-                "no usable password keyslot".into(),
-            )));
+        if !any_tpm && password_slots.is_empty() {
+            return Err(Error::NoMethodWorked(Some("no password keyslot".into())));
         }
         let hw = lock(&self.hw);
         let mut last = None;
-        let mut use_tpm = !tpm_slots.is_empty();
+        let all_stale = tpm_slots.is_empty();
+        let mut use_tpm = !all_stale;
         // PAM vouched for it: a slot refusing it is then not a typo.
         let mut accepted = false;
-        if typed && use_tpm {
+        // (Checked even when every TPM slot is stale: that tells a typo from
+        // a changed password.)
+        if typed && any_tpm {
             match hw.password.check(password) {
                 Ok(true) => accepted = true,
                 // Not the current login password: keep it from the TPM (it
@@ -477,6 +556,8 @@
                 }
             }
         }
+        // A TPM slot rejected it in this attempt.
+        let mut rejected = false;
         if use_tpm {
             // Newest first: the most recently enrolled slot is the one most
             // likely sealed with the current password. Once one rejects it,
@@ -496,17 +577,24 @@
                             vault: vault.unlock(k.id, &kek)?,
                             slot: k.id,
                             kek: Some(kek),
+                            reseal: None,
                         });
                     }
                     // Only these say something about the slot (Plan 2): the
                     // password it was sealed with is not this one.
-                    Err(aleph_unlock::Error::TpmAuthFailed | aleph_unlock::Error::TpmWrongUser) => {
+                    Err(
+                        e
+                        @ (aleph_unlock::Error::TpmAuthFailed | aleph_unlock::Error::TpmWrongUser),
+                    ) => {
                         let mut inner = lock(&self.inner);
                         for older in &tpm_slots[i..] {
                             inner.state.mark_stale(older.id)?;
                         }
                         tracing::warn!(slot = %k.id, "TPM keyslot rejected the login password; marked stale");
                         last = Some(Error::Stale(k.label.clone()));
+                        // (A slot of another user's: the previous password
+                        // cannot help there.)
+                        rejected = matches!(e, aleph_unlock::Error::TpmAuthFailed);
                         break;
                     }
                     Err(e) => last = Some(e.into()),
@@ -520,6 +608,7 @@
                         vault: v,
                         slot: k.id,
                         kek: None,
+                        reseal: None,
                     });
                 }
                 Err(aleph_core::Error::UnwrapFailed) => last = Some(Error::WrongPassword),
@@ -531,7 +620,68 @@
         if typed && !accepted && matches!(last, Some(Error::WrongPassword)) {
             lock(&self.inner).typed.record_failure(now);
         }
+        let vouched = accepted || !typed;
+        if vouched && any_tpm && (all_stale || rejected) {
+            return Err(Error::PasswordChanged);
+        }
         Err(last.unwrap_or(Error::NoMethodWorked(None)))
+    }
+
+    /// After an outside password change (`current`, which PAM accepts, opens
+    /// no TPM slot): ask for the previous password and try it on the newest
+    /// TPM slot, straight at the TPM. PAM no longer knows that password, so
+    /// each wrong one spends one of the TPM's dictionary-attack attempts:
+    /// hence only the newest slot, [`OLD_PASSWORD_ATTEMPTS`] tries per
+    /// conversation (`tries` counts them across questions), and the typing
+    /// limit. Once installed, the vault re-seals under `current`.
+    fn open_with_old_password(
+        &self,
+        chan: &mut Channel,
+        vault: &LockedVault,
+        current: &str,
+        tries: &mut usize,
+    ) -> Result<Opened> {
+        let newest = newest_tpm_slot(vault).ok_or(Error::NoMethodWorked(None))?;
+        let SlotKind::Tpm(slot) = &newest.kind else {
+            unreachable!("a TPM slot")
+        };
+        if *tries >= OLD_PASSWORD_ATTEMPTS {
+            return Err(Error::Invalid(
+                "no more tries at the previous password in this conversation; use another method, or unlock again later"
+                    .into(),
+            ));
+        }
+        let mut error = None;
+        while *tries < OLD_PASSWORD_ATTEMPTS {
+            *tries += 1;
+            let now = Instant::now();
+            if let Some(wait) = lock(&self.inner).typed.blocked(now) {
+                return Err(Error::TooManyAttempts { retry_after: wait });
+            }
+            let reply = chan.ask(&ToPrompter::OldPassword {
+                error: error.take(),
+            })?;
+            let FromPrompter::Password { password: old } = reply else {
+                return Err(Error::Prompt(format!("unexpected reply {reply:?}")));
+            };
+            let unsealed = lock(&self.hw).tpm.unseal(slot, old.expose().as_bytes());
+            match unsealed {
+                Ok(kek) => {
+                    return Ok(Opened {
+                        vault: vault.unlock(newest.id, &kek)?,
+                        slot: newest.id,
+                        kek: Some(kek),
+                        reseal: Some(Zeroizing::new(current.to_string())),
+                    });
+                }
+                Err(aleph_unlock::Error::TpmAuthFailed | aleph_unlock::Error::TpmWrongUser) => {
+                    lock(&self.inner).typed.record_failure(now);
+                    error = Some("that password does not open the TPM keyslot either".into());
+                }
+                Err(e) => return Err(e.into()),
+            }
+        }
+        Err(Error::WrongPassword)
     }
 
     /// Open `vault` with a FIDO2 slot: wait for a key holding one (or only
@@ -553,13 +703,15 @@
         if slots.is_empty() {
             return Err(Error::NoMethodWorked(Some("no FIDO2 keyslot".into())));
         }
-        let mut hw = lock(&self.hw);
         let names = slots
             .iter()
             .map(|s| s.1.as_str())
             .collect::<Vec<_>>()
             .join(" or ");
-        let (id, label, slot) = self.wait_for_key(chan, &mut hw, &slots, &names)?;
+        // The hardware lock is held only for key operations, never while the
+        // prompter is asked: a PIN prompt can stay open for minutes, and a
+        // login password (pam.sock) must not wait behind it.
+        let (id, label, slot) = self.wait_for_key(chan, &slots, &names)?;
         let mut error = None;
         let mut wrong_pins = 0;
         loop {
@@ -575,12 +727,18 @@
                 None
             };
             chan.send(&ToPrompter::Touch { key: label.clone() })?;
-            match fido2::unlock(&mut *hw.keys, &slot, pin.as_ref().map(Secret::expose)) {
+            let unlocked = fido2::unlock(
+                &mut *lock(&self.hw).keys,
+                &slot,
+                pin.as_ref().map(Secret::expose),
+            );
+            match unlocked {
                 Ok(kek) => {
                     return Ok(Opened {
                         vault: vault.unlock(id, &kek)?,
                         slot: id,
                         kek: Some(kek),
+                        reseal: None,
                     });
                 }
                 Err(aleph_unlock::Error::Fido2PinInvalid) if slot.pin_required => {
@@ -603,7 +761,6 @@
     fn wait_for_key(
         &self,
         chan: &mut Channel,
-        hw: &mut Backends,
         slots: &[(Uuid, String, aleph_core::Fido2Slot)],
         names: &str,
     ) -> Result<(Uuid, String, aleph_core::Fido2Slot)> {
@@ -611,7 +768,8 @@
         let mut asked = false;
         loop {
             for s in slots {
-                if fido2::present(&mut *hw.keys, &s.2)? {
+                let found = fido2::present(&mut *lock(&self.hw).keys, &s.2)?;
+                if found {
                     return Ok(s.clone());
                 }
             }
@@ -629,20 +787,40 @@
         }
     }
 
-    /// Make an opened vault the unlocked one, after the high-water check.
-    /// Returns the warning to show if the file is not trusted for writes.
-    fn install(&self, vault: UnlockedVault) -> Result<Option<String>> {
+    /// Make an opened vault (opened through `slot`, with `kek` if the slot
+    /// has one) the unlocked one, after the high-water check. Returns the
+    /// warning to show if the file is not trusted for writes.
+    fn install(
+        &self,
+        vault: UnlockedVault,
+        slot: Uuid,
+        kek: Option<&Kek>,
+    ) -> Result<Option<String>> {
         let mut inner = lock(&self.inner);
-        let untrusted = match inner.store.raise(&vault)? {
-            Standing::Unrecorded | Standing::Current | Standing::Newer => None,
-            Standing::Pending => {
-                inner.store.record(&vault.mark())?;
-                None
-            }
-            Standing::RolledBack { .. } => Some("rolled back to an older version"),
-            Standing::Replaced => Some("replaced by a different vault"),
-            Standing::Rekeyed => Some("re-keyed somewhere else"),
-        };
+        // Unlocked meanwhile (a login password through pam.sock does not
+        // wait for a conversation): the first open stays, and this one is
+        // dropped, never installed over it.
+        if inner.vault.is_some() {
+            return Ok(None);
+        }
+        // The file may also have moved on since this copy was read
+        // (unlocked elsewhere, written, locked again). An older copy must
+        // never be installed: it would read as a rollback and hide what was
+        // written. Reopen the current file with the same key instead.
+        let current = inner.store.read()?;
+        let vault = if current.mark() == vault.mark() {
+            vault
+        } else {
+            match kek.map(|k| current.unlock(slot, k)) {
+                Some(Ok(v)) => v,
+                _ => {
+                    return Err(Error::Invalid(
+                        "the keyring changed while it was being unlocked; unlock again".into(),
+                    ));
+                }
+            }
+        };
+        let untrusted = trust(&inner.store, &vault)?;
         let ids: HashSet<Uuid> = vault.keyslots().map(|k| k.id).collect();
         inner.state.retain(|id| ids.contains(&id))?;
         inner.vault = Some(vault);
@@ -965,7 +1143,161 @@
         for id in &drops {
             inner.state.clear(*id)?;
         }
+        inner.state.set_rotation_pending(false)?;
         Ok(())
+    }
+
+    /// Replace every password slot (TPM and login-password) with fresh ones
+    /// for `new`, the current login password: one TPM slot sealed under it
+    /// if there were TPM slots, one login-password slot if there was one
+    /// (spec §5 "Password change"). MK rotates when that needs no one
+    /// (every other slot is a recovery slot). Otherwise, since FIDO2 slots
+    /// need a touch, the old slots are removed keeping MK, and a rotation
+    /// is marked pending for `aleph keyslot rotate-master`. Sealing comes
+    /// first, so a TPM refusal changes nothing. The caller holds `ops`, and
+    /// the vault is unlocked.
+    fn replace_password_slots(&self, new: &str) -> Result<String> {
+        self.replace_slots(new, None)
+    }
+
+    /// `replace_password_slots`, in `detached` (an opened copy, written
+    /// through the store here) if given, else in the unlocked vault.
+    fn replace_slots(&self, new: &str, detached: Option<&mut UnlockedVault>) -> Result<String> {
+        let (tpm_old, login_old, rotatable) = match &detached {
+            Some(v) => password_slots(v),
+            None => password_slots(lock(&self.inner).vault.as_ref().ok_or(Error::Locked)?),
+        };
+        if tpm_old.is_empty() && login_old.is_empty() {
+            return Ok("no password keyslot to update".into());
+        }
+        let sealed = if tpm_old.is_empty() {
+            None
+        } else {
+            Some(lock(&self.hw).tpm.seal(new.as_bytes())?)
+        };
+        let old: Vec<Uuid> = tpm_old.iter().chain(&login_old).copied().collect();
+        let argon2 = self.argon2;
+        let edit = |v: &mut UnlockedVault| -> Result<()> {
+            let tpm_new = match &sealed {
+                Some((kek, slot)) => {
+                    Some((v.add_keyslot("tpm", SlotKind::Tpm(slot.clone()), kek)?, kek))
+                }
+                None => None,
+            };
+            let login_new = if login_old.is_empty() {
+                None
+            } else {
+                let id = v.add_login_password_slot("login password", new.as_bytes(), argon2)?;
+                Some((id, v.login_password_kek(id, new.as_bytes())?))
+            };
+            if rotatable {
+                let mut keks: Vec<(Uuid, &Kek)> = Vec::new();
+                keks.extend(tpm_new);
+                keks.extend(login_new.as_ref().map(|(id, kek)| (*id, kek)));
+                v.rotate_master(&keks, &old)?;
+            } else {
+                for id in &old {
+                    v.remove_keyslot_keeping_mk(*id)?;
+                }
+            }
+            Ok(())
+        };
+        // Marked before writing: a change written without rotation must
+        // never go unreported (a spurious mark only asks for a rotation).
+        if !rotatable {
+            lock(&self.inner).state.set_rotation_pending(true)?;
+        }
+        let ids: HashSet<Uuid> = match detached {
+            Some(v) => {
+                edit(v)?;
+                lock(&self.inner).store.write(v)?;
+                v.keyslots().map(|k| k.id).collect()
+            }
+            None => {
+                self.modify_vault(edit)?;
+                let inner = lock(&self.inner);
+                let v = inner.vault.as_ref().ok_or(Error::Locked)?;
+                v.keyslots().map(|k| k.id).collect()
+            }
+        };
+        let mut inner = lock(&self.inner);
+        let state = &mut inner.state;
+        state.retain(|id| ids.contains(&id))?;
+        if rotatable {
+            state.set_rotation_pending(false)?;
+            Ok("the keyslots now use the new login password; the master key was rotated".into())
+        } else {
+            Ok(
+                "the keyslots now use the new login password; run `aleph keyslot rotate-master` \
+                to finish (it needs your security keys)"
+                    .into(),
+            )
+        }
+    }
+
+    /// The login password changed from `old` to `new` (`pam_aleph`, during
+    /// `passwd`): replace the password slots (spec §5 "Password change").
+    /// `pam_aleph` runs even when the change itself failed, so nothing
+    /// happens unless PAM accepts `new` (or cannot check). A locked vault
+    /// is never unlocked for this: a copy is opened with `old`, changed,
+    /// and written. Waits for a running conversation.
+    pub fn change_login_password(&self, old: &str, new: &str) -> Result<String> {
+        // Before waiting for anything: a new password PAM rejects changes
+        // nothing.
+        let vouched = match lock(&self.hw).password.check(new) {
+            Ok(true) => true,
+            Ok(false) => {
+                return Err(Error::Invalid(
+                    "the new password is not the login password (did the change fail?); nothing changed"
+                        .into(),
+                ));
+            }
+            Err(_) => false,
+        };
+        let _op = lock(&self.ops);
+        let locked = self.is_locked();
+        if !locked && vouched {
+            return self.replace_password_slots(new);
+        }
+        // `old` must open the vault file: on a locked vault, to change a
+        // copy; on an unlocked one when PAM could not vouch for `new`, so no
+        // same-user process can re-seal the vault under a password of its
+        // choosing.
+        let file = lock(&self.inner).store.read()?;
+        let mut copy = self.open_with_previous(&file, old)?;
+        if !locked {
+            drop(copy);
+            return self.replace_password_slots(new);
+        }
+        if let Some(why) = trust(&lock(&self.inner).store, &copy)? {
+            return Err(Error::Untrusted(why));
+        }
+        self.replace_slots(new, Some(&mut copy))
+    }
+
+    /// Open `file` with the login password it was last sealed under: the
+    /// newest TPM slot whatever its stale mark (a login with the new
+    /// password may have just marked it), then any login-password slot.
+    /// Nothing is marked stale: `old` is expected to be outdated.
+    fn open_with_previous(&self, file: &LockedVault, old: &str) -> Result<UnlockedVault> {
+        if let Some(k) = newest_tpm_slot(file)
+            && let SlotKind::Tpm(slot) = &k.kind
+        {
+            let unsealed = lock(&self.hw).tpm.unseal(slot, old.as_bytes());
+            match unsealed {
+                Ok(kek) => return Ok(file.unlock(k.id, &kek)?),
+                Err(aleph_unlock::Error::TpmAuthFailed | aleph_unlock::Error::TpmWrongUser) => {}
+                Err(e) => return Err(e.into()),
+            }
+        }
+        for k in file.keyslots() {
+            if matches!(k.kind, SlotKind::LoginPassword(_))
+                && let Ok(v) = file.unlock_login_password(k.id, old.as_bytes())
+            {
+                return Ok(v);
+            }
+        }
+        Err(Error::WrongPassword)
     }
 
     /// Create the vault with a recovery slot and one unlock method.
@@ -1179,6 +1511,7 @@
                 Ok(v.rotate_master(&refs, &drops)?)
             })
             .map_err(|e| Error::RecoveryNotInstalled(Box::new(e)))?;
+            lock(&self.inner).state.set_rotation_pending(false)?;
             Ok(Some(
                 "New recovery key issued; the old one no longer works.".into(),
             ))
@@ -1204,6 +1537,49 @@
             f()
         })
     }
+}
+
+/// Whether an opened vault may be written: `Some(reason)` if the file was
+/// rolled back, replaced, or re-keyed elsewhere (§4 "Generation and
+/// high-water mark"). Raises the mark otherwise.
+fn trust(store: &Store, vault: &UnlockedVault) -> Result<Option<&'static str>> {
+    Ok(match store.raise(vault)? {
+        Standing::Unrecorded | Standing::Current | Standing::Newer => None,
+        Standing::Pending => {
+            store.record(&vault.mark())?;
+            None
+        }
+        Standing::RolledBack { .. } => Some("rolled back to an older version"),
+        Standing::Replaced => Some("replaced by a different vault"),
+        Standing::Rekeyed => Some("re-keyed somewhere else"),
+    })
+}
+
+/// The newest TPM slot of `v` (ties within a second: the later-added).
+fn newest_tpm_slot(v: &LockedVault) -> Option<&Keyslot> {
+    v.keyslots()
+        .enumerate()
+        .filter(|(_, k)| matches!(k.kind, SlotKind::Tpm(_)))
+        .max_by_key(|(i, k)| (k.created, *i))
+        .map(|(_, k)| k)
+}
+
+/// The password slots of `v` (TPM, login-password), and whether MK can
+/// rotate without the user (no FIDO2 or unknown-type slots).
+fn password_slots(v: &UnlockedVault) -> (Vec<Uuid>, Vec<Uuid>, bool) {
+    let ids = |tpm: bool| -> Vec<Uuid> {
+        v.keyslots()
+            .filter(|k| match k.kind {
+                SlotKind::Tpm(_) => tpm,
+                SlotKind::LoginPassword(_) => !tpm,
+                _ => false,
+            })
+            .map(|k| k.id)
+            .collect()
+    };
+    let rotatable = v.unknown_keyslots().next().is_none()
+        && v.keyslots().all(|k| !matches!(k.kind, SlotKind::Fido2(_)));
+    (ids(true), ids(false), rotatable)
 }
 
 /// Run a conversation and end it with `Done` either way.
--- a/crates/aleph-cli/src/client.rs
+++ b/crates/aleph-cli/src/client.rs
@@ -33,6 +33,8 @@
     pub memory_locked: Option<bool>,
     pub tpm: Option<bool>,
     pub keyslots: Vec<SlotInfo>,
+    #[serde(default)]
+    pub rotation_pending: bool,
 }
 
 /// One item, as the CLI shows it.
--- a/crates/aleph-cli/src/prompter.rs
+++ b/crates/aleph-cli/src/prompter.rs
@@ -146,6 +146,18 @@
                 Method::Fido2 => FromPrompter::Fido2 {},
             })
         }
+        ToPrompter::OldPassword { error } => {
+            match error {
+                Some(e) => eprintln!("aleph: {e}"),
+                None => eprintln!(
+                    "aleph: your login password was changed without aleph; enter the previous \
+                     one to update the TPM keyslot (a wrong one costs a TPM attempt)"
+                ),
+            }
+            Some(FromPrompter::Password {
+                password: term.secret("Previous login password: ")?,
+            })
+        }
         ToPrompter::Fido2Pin { key, error } => {
             if let Some(e) = error {
                 eprintln!("aleph: {e}");
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -170,7 +170,7 @@
             };
             outcome(c.converse("Create", Args::Str(method)).await?)?;
             eprintln!(
-                "aleph: note: login unlock, taking over from gnome-keyring, and importing its items are not available yet"
+                "aleph: note: setup does not yet set up login unlock (PAM), take over from gnome-keyring, or import its items: these are not available yet (see docs/testing.md for the PAM lines)"
             );
         }
         Cmd::Status => {
@@ -190,6 +190,11 @@
                 if s.memory_locked == Some(false) {
                     println!(
                         "warning: the master key could not be locked in RAM (mlock); it may be swapped"
+                    );
+                }
+                if s.rotation_pending {
+                    println!(
+                        "warning: after a password change the master key still needs rotating: run `aleph keyslot rotate-master`"
                     );
                 }
                 print_slots(&s.keyslots);
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-prompt-proto -p aleph-daemon -p aleph-cli && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 8 passed | ok. 29 passed | ok. 3 passed | ok. 47 passed | ok. 1 passed | ok. 2 passed | ok. 17 passed | ok. 2 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **passwd acts only on a PAM-accepted new password** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_failed_passwd_changes_nothing`:

  replace

  ```rust
  Ok(true) => true,
  Ok(false) => {
  ```

  with

  ```rust
  Ok(true) => true,
  Ok(false) if false => {
  ```


  replace

  ```rust
  Err(_) => false,
  };
  let _op = lock(&self.ops);
  ```

  with

  ```rust
  _ => false,
  };
  let _op = lock(&self.ops);
  ```

- **login-stack passwords are PAM-checked** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_wrong_login_stack_password_never_reaches_the_tpm`:

  replace

  ```rust
  if let Ok(false) = lock(&self.hw).password.check(password) {
  return Err(Error::WrongPassword);
  ```

  with

  ```rust
  if false {
  return Err(Error::WrongPassword);
  ```

- **passwd rotates when no key needs a touch** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_password_change_reseals_the_tpm_slot_and_rotates`:

  replace

  ```rust
  if rotatable {
  let mut keks
  ```

  with

  ```rust
  if false {
  let mut keks
  ```

- **a rotation left undone is marked pending** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring with_a_security_key_a_password_change_marks_a_rotation_pending`: replace `state.set_rotation_pending(true)?;` with `state.set_rotation_pending(false)?;`.
- **an outside change asks for the previous password** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_password_changed_elsewhere_is_resealed`: replace `if vouched && any_tpm && (all_stale || rejected) {` with `if false {`.
- **declining the previous password returns to the choice** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring declining_the_previous_password`: replace `Err(Error::Cancelled) => Err(Error::PasswordChanged),` with `Err(Error::Cancelled) => Err(Error::Cancelled),`.
- **a login password does not queue behind a conversation** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_login_password_does_not_wait_for_a_conversation`:

  replace

  ```rust
  pub fn unlock_with_login_password(&self, password: &str) -> Result<()> {
  ```

  with

  ```rust
  pub fn unlock_with_login_password(&self, password: &str) -> Result<()> {
  let _op = lock(&self.ops);
  ```

- **a late open reopens the current file** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_late_unlock_does_not_replace_the_open_vault`: replace `let vault = if current.mark() == vault.mark() {` with `let vault = if true {`.
- **no hardware lock while the PIN is asked** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring a_login_password_does_not_wait_behind_a_pin_prompt`:

  replace

  ```rust
  let pin = if slot.pin_required {
  ```

  with

  ```rust
  let held = lock(&self.hw);
  let pin = if slot.pin_required {
  ```


  replace

  ```rust
  chan.send(&ToPrompter::Touch { key: label.clone() })?;
  let unlocked = fido2::unlock(
  ```

  with

  ```rust
  drop(held);
  chan.send(&ToPrompter::Touch { key: label.clone() })?;
  let unlocked = fido2::unlock(
  ```

- **passwd opens the file with the previous password whatever the stale marks** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring passwd_after_a_login_with_the_new_password_still_changes`: replace `let mut copy = self.open_with_previous(&file, old)?;` with `let mut copy = self.open_with_password(&file, old, false)?.vault;`.
- **without PAM, a change proves the old password** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring without_pam_a_change_must_prove_the_old_password`: replace `if !locked && vouched {` with `if !locked {`.
- **the previous-password budget spans the conversation** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test keyring the_previous_password_is_asked_at_most_twice`:

  replace

  ```rust
  tries: &mut usize,
  ) -> Result<Opened> {
  ```

  with

  ```rust
  tries: &mut usize,
  ) -> Result<Opened> {
      *tries = 0;
  ```


- [ ] **Step 6: Commit**

```bash
git add crates/aleph-prompt-proto crates/aleph-daemon crates/aleph-cli
git commit -m "feat(daemon): passwd changes, re-sealing after an outside change, PAM-checked login passwords" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 4: pam.sock in alephd

**Interfaces:**
- Consumes: Tasks 1 and 3.
- Produces: `pamsock::{REQUEST_TIMEOUT, listener(&Path) -> Result<UnixListener>, serve(UnixListener, Arc<Keyring>, Arc<SecretService>) -> io::Result<()>}`; `Paths::pam_socket()`; `testing::daemon_with(create, prompts, Box<dyn PasswordCheck>)`; `packaging/systemd/alephd.socket`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-daemon/Cargo.toml`:

```toml
[package]
name = "aleph-daemon"
description = "alephd: the aleph keyring daemon (Secret Service and admin interface)"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "alephd"
path = "src/main.rs"

[features]
testing = ["dep:aleph-tpmd", "dep:tempfile", "aleph-core/insecure-test-params"]

[dependencies]
aes = "0.9"
cbc = { version = "0.2", features = ["alloc"] }
futures-util = { version = "0.3", default-features = false }
hkdf.workspace = true
num-bigint = "0.4"
sha2.workspace = true
aleph-core = { path = "../aleph-core" }
aleph-pam-proto = { path = "../aleph-pam-proto" }
aleph-prompt-proto = { path = "../aleph-prompt-proto" }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
aleph-unlock = { path = "../aleph-unlock" }
libc.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time", "signal", "net", "io-util"] }
toml = "1"
tracing = "0.1"
tracing-journald = "0.3"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
uuid.workspace = true
zbus = { version = "5", default-features = false, features = ["tokio"] }
zeroize.workspace = true
aleph-tpmd = { path = "../aleph-tpmd", features = ["testing"], optional = true }
tempfile = { workspace = true, optional = true }

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-daemon = { path = ".", features = ["testing"] }
tempfile.workspace = true
serde.workspace = true
```

Write `crates/aleph-daemon/src/lib.rs`:

```rust
//! `alephd`, the aleph keyring daemon (spec §6).

pub mod admin;
pub mod config;
pub mod daemon;
pub mod error;
pub mod keyring;
pub mod pamsock;
pub mod password;
pub mod paths;
pub mod prompt;
pub mod secret;
pub mod state;
pub mod store;

#[cfg(feature = "testing")]
pub mod testing;

pub use error::{Error, Result};
```

Create `crates/aleph-daemon/src/pamsock.rs` containing only `// implemented in step 3`.

Write `crates/aleph-daemon/tests/pam_socket.rs`:

```rust
//! `pam.sock` with the real daemon (keyring on swtpm, Secret Service on a
//! private bus), the test playing `pam_aleph`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use aleph_daemon::testing::*;
use aleph_pam_proto::{Password, Reply, Request};
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

/// A daemon with `pam.sock` served at a temporary path.
async fn served() -> (Daemon, PathBuf) {
    served_with(Box::new(Fixed(|p| p == PW))).await
}

/// `served`, with the given password check (PAM).
async fn served_with(check: Box<dyn aleph_daemon::password::PasswordCheck>) -> (Daemon, PathBuf) {
    let d = daemon_with(true, vec![], check).await;
    let path = d.env.paths.pam_socket();
    let listener = aleph_daemon::pamsock::listener(&path).unwrap();
    let (keyring, secrets) = (d.keyring.clone(), d.secrets.clone());
    tokio::spawn(aleph_daemon::pamsock::serve(listener, keyring, secrets));
    (d, path)
}

/// Send `request` as `pam_aleph` would; `None` if the daemon hung up
/// without a reply.
async fn send_raw(path: &std::path::Path, frame: Vec<u8>) -> Option<Reply> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut s = UnixStream::connect(&path).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        s.write_all(&frame).unwrap();
        let mut header = [0u8; 4];
        s.read_exact(&mut header).ok()?;
        let mut payload = vec![0u8; aleph_pam_proto::payload_len(header).unwrap()];
        s.read_exact(&mut payload).unwrap();
        Some(Reply::decode(&payload).unwrap())
    })
    .await
    .unwrap()
}

async fn send(path: &std::path::Path, request: Request) -> Reply {
    send_raw(path, request.encode().unwrap().to_vec())
        .await
        .expect("a reply")
}

fn unlock(pw: &str) -> Request {
    Request::Unlock {
        password: Password::new(pw.as_bytes()),
    }
}

/// The login password unlocks the vault, and a Secret Service prompt that
/// was waiting (no prompter at login) completes with it: the client that
/// asked before the unlock gets its answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_login_password_unlocks_and_completes_waiting_prompts() {
    use futures_util::StreamExt;
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    let c = zbus::connection::Builder::address(d.bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let svc = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = svc
        .call(
            "Unlock",
            &(vec![
                ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
            ],),
        )
        .await
        .unwrap();
    let p = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    let mut completed = p.receive_signal("Completed").await.unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(d.secrets.waiting_count(), 1);

    let reply = send(&path, unlock(PW)).await;
    assert!(reply.ok, "{reply:?}");
    assert!(!d.keyring.is_locked());
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), completed.next())
        .await
        .expect("the waiting prompt completes")
        .unwrap();
    let (dismissed, _): (bool, zbus::zvariant::OwnedValue) = msg.body().deserialize().unwrap();
    assert!(!dismissed);
}

/// Failed requests are limited: after five, even the right password is
/// refused for a while, so a same-user process cannot guess through the
/// socket (and the TPM helper's own limit keeps its failures low).
#[tokio::test(flavor = "multi_thread")]
async fn failed_requests_are_limited() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    for _ in 0..aleph_daemon::password::TYPED_FAILURES {
        assert!(!send(&path, unlock("wrong")).await.ok);
    }
    let reply = send(&path, unlock(PW)).await;
    assert!(!reply.ok && reply.message.contains("too many"), "{reply:?}");
    assert!(d.keyring.is_locked());
    // (PAM rejected every wrong one: none reached the TPM.)
    assert_eq!(d.env.sw.tpm().status().unwrap().failed_tries, 0);
}

/// `passwd`'s change arrives through the socket; the new password then
/// unlocks.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_arrives_through_the_socket() {
    let login = Accepting::new(PW);
    let (d, path) = served_with(Box::new(login.clone())).await;
    // passwd has changed the password when pam_aleph runs.
    login.set("new password");
    let reply = send(
        &path,
        Request::ChangePassword {
            old: Password::new(PW.as_bytes()),
            new: Password::new(b"new password"),
        },
    )
    .await;
    assert!(reply.ok, "{reply:?}");
    d.secrets.lock().await.unwrap();
    assert!(send(&path, unlock("new password")).await.ok);
    assert!(!d.keyring.is_locked());
}

/// A conversation nobody answers holds the daemon's operation lock; returns
/// the prompter's end (drop it to end the conversation) and its thread.
fn hold_a_conversation(
    d: &Daemon,
) -> (
    UnixStream,
    std::thread::JoinHandle<aleph_daemon::Result<()>>,
) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let mut silent =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(60)).unwrap();
    let keyring = d.keyring.clone();
    let thread = std::thread::spawn(move || keyring.unlock(&mut silent, None));
    std::thread::sleep(std::time::Duration::from_millis(200));
    (theirs, thread)
}

fn change(old: &str, new: &str) -> Request {
    Request::ChangePassword {
        old: Password::new(old.as_bytes()),
        new: Password::new(new.as_bytes()),
    }
}

/// A new password PAM rejects is refused at once, even while a
/// conversation holds the daemon (nothing queues behind it).
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_new_password_is_refused_without_waiting() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    let (prompter, conversation) = hold_a_conversation(&d);
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        send(&path, change(PW, "not the login password")),
    )
    .await
    .expect("refused without waiting");
    assert!(
        !reply.ok && reply.message.contains("not the login password"),
        "{reply:?}"
    );
    drop(prompter);
    assert!(conversation.join().unwrap().is_err());
}

/// Requests being answered count against the limit, so parallel
/// connections cannot get past it: with a conversation holding the daemon,
/// five changes wait their turn and the rest are refused at once.
#[tokio::test(flavor = "multi_thread")]
async fn requests_in_flight_are_bounded() {
    let login = Accepting::new(PW);
    let (d, path) = served_with(Box::new(login.clone())).await;
    d.secrets.lock().await.unwrap();
    login.set("new");
    let (prompter, conversation) = hold_a_conversation(&d);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for _ in 0..7 {
        let (path, tx) = (path.clone(), tx.clone());
        tokio::spawn(async move { tx.send(send(&path, change(PW, "new")).await).unwrap() });
    }
    for _ in 0..2 {
        let reply = tokio::time::timeout(std::time::Duration::from_secs(20), rx.recv())
            .await
            .expect("refused at once")
            .unwrap();
        assert!(!reply.ok && reply.message.contains("at once"), "{reply:?}");
    }
    drop(prompter);
    assert!(conversation.join().unwrap().is_err());
    for _ in 0..5 {
        tokio::time::timeout(std::time::Duration::from_secs(60), rx.recv())
            .await
            .expect("answered once the conversation ended")
            .unwrap();
    }
}

/// A malformed request gets no reply, and the socket keeps serving.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_request_is_dropped() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    assert_eq!(send_raw(&path, vec![0, 0, 0, 1, 99]).await, None);
    assert!(send(&path, unlock(PW)).await.ok);
}

/// A leftover socket file (a crashed daemon) is replaced; anything else
/// at the path is left alone.
#[test]
fn the_listener_replaces_only_a_leftover_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run/aleph/pam.sock");
    drop(aleph_daemon::pamsock::listener(&path).unwrap());
    let l = aleph_daemon::pamsock::listener(&path).unwrap();
    drop(l);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"not a socket").unwrap();
    assert!(aleph_daemon::pamsock::listener(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
}

/// A socket something still serves (`alephd.socket`, when alephd is run by
/// hand) is left alone.
#[test]
fn the_listener_leaves_a_served_socket_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run/aleph/pam.sock");
    let serving = aleph_daemon::pamsock::listener(&path).unwrap();
    assert!(aleph_daemon::pamsock::listener(&path).is_err());
    drop(serving);
    // (Nobody serves it now: a leftover, replaced.)
    drop(aleph_daemon::pamsock::listener(&path).unwrap());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-daemon/src/pamsock.rs`:

```rust
//! `pam.sock` (spec §6 "PAM integration"): where `pam_aleph` hands over
//! the login password.
//!
//! - **Who may connect:** only the daemon's own uid (`SO_PEERCRED`).
//!   `pam_aleph` connects from a child that dropped to the user's uid.
//! - **What arrives:** one request per connection (`aleph-pam-proto`),
//!   within [`REQUEST_TIMEOUT`]. `Unlock` carries a password the login
//!   stack accepted (a login, or unlocking the screen) and opens the vault;
//!   `ChangePassword` comes from `passwd` and replaces the password
//!   keyslots. Both are still checked with PAM where PAM can check
//!   (`Keyring::unlock_with_login_password`, `change_login_password`).
//! - **Rate limiting:** at most [`crate::password::TYPED_FAILURES`] rejected
//!   passwords per [`crate::password::TYPED_WINDOW`], which bounds
//!   same-user guessing through the socket. Refusals that say nothing
//!   about the password (busy, rate-limited) do not count. Requests still
//!   being answered count too, so parallel connections cannot get past the
//!   limit, and at most that many are in flight at once.
//! - **The listener** is the descriptor named `pam` that `alephd.socket`
//!   passes (systemd socket activation), or is bound here when not
//!   activated (tests, manual runs).

use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aleph_pam_proto::{Reply, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keyring::Keyring;
use crate::password::{TYPED_FAILURES, TypedLimiter};
use crate::secret::service::SecretService;

/// How long a client has to send its request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The first descriptor systemd passes (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: RawFd = 3;

/// The name `alephd.socket` gives it (`FileDescriptorName=`).
const FD_NAME: &str = "pam";

/// The listening socket: the one `alephd.socket` passed, if this process
/// was socket-activated, else a fresh one bound at `path` (its directory
/// created 0700, the socket 0600, a leftover socket replaced).
pub fn listener(path: &Path) -> Result<UnixListener> {
    if let Some(l) = activated() {
        return Ok(l);
    }
    let dir = path
        .parent()
        .ok_or(Error::Environment("the PAM socket path has no directory"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    match std::fs::symlink_metadata(path) {
        // A leftover of a stopped daemon is replaced; a socket something
        // still serves (`alephd.socket`, another alephd) is not.
        Ok(m) if m.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(Error::Invalid(format!(
                    "{} is served by another process (alephd.socket?)",
                    path.display()
                )));
            }
            std::fs::remove_file(path)?
        }
        Ok(_) => {
            return Err(Error::Invalid(format!(
                "{} exists and is not a socket",
                path.display()
            )));
        }
        Err(_) => {}
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// The socket systemd passed: `LISTEN_PID` is us, and the descriptor
/// `LISTEN_FDNAMES` calls `pam` (or the only one, if unnamed) is a Unix
/// stream socket. Made close-on-exec, so no prompter inherits it.
fn activated() -> Option<UnixListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let fds: usize = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if pid != std::process::id() || fds < 1 {
        return None;
    }
    let index = match std::env::var("LISTEN_FDNAMES") {
        Ok(names) => names.split(':').position(|n| n == FD_NAME)?,
        Err(_) if fds == 1 => 0,
        Err(_) => return None,
    };
    if index >= fds {
        return None;
    }
    let fd = LISTEN_FDS_START + RawFd::try_from(index).ok()?;
    // SAFETY: plain syscalls on a descriptor number; nothing is dereferenced
    // but locals.
    unsafe {
        let mut ty: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut alen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut ty).cast(),
            &mut len,
        ) != 0
            || ty != libc::SOCK_STREAM
            || libc::getsockname(fd, (&raw mut addr).cast(), &mut alen) != 0
            || i32::from(addr.ss_family) != libc::AF_UNIX
        {
            return None;
        }
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        // SAFETY: systemd handed this descriptor to us, and nothing else
        // owns it.
        Some(UnixListener::from_raw_fd(fd))
    }
}

/// Serve `pam.sock` until the listener fails.
pub async fn serve(
    listener: UnixListener,
    keyring: Arc<Keyring>,
    secrets: Arc<SecretService>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let limits = Arc::new(Mutex::new(Limits::default()));
    // SAFETY: getuid cannot fail.
    let own_uid = unsafe { libc::getuid() };
    loop {
        let (stream, _) = listener.accept().await?;
        let (keyring, secrets, limits) = (keyring.clone(), secrets.clone(), limits.clone());
        tokio::spawn(async move {
            match stream.peer_cred() {
                Ok(c) if c.uid() == own_uid => {}
                Ok(c) => {
                    tracing::warn!(
                        uid = c.uid(),
                        "refused a pam.sock connection from another user"
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!("pam.sock: no peer credentials: {e}");
                    return;
                }
            }
            if let Err(e) = handle(stream, keyring, secrets, limits).await {
                tracing::info!("pam.sock: {e}");
            }
        });
    }
}

/// Rejected passwords lately, and requests being answered now.
#[derive(Default)]
struct Limits {
    failures: TypedLimiter,
    in_flight: usize,
}

async fn handle(
    mut stream: tokio::net::UnixStream,
    keyring: Arc<Keyring>,
    secrets: Arc<SecretService>,
    limits: Arc<Mutex<Limits>>,
) -> std::io::Result<()> {
    let request = match tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await {
        Ok(r) => r?,
        Err(_) => return Err(std::io::Error::other("no request in time")),
    };
    let reply = answer(request, &keyring, &limits).await;
    if reply.ok {
        tracing::info!("pam.sock: {}", reply.message);
    } else {
        // (An outside password change shows here, as well as at the next
        // interactive unlock.)
        tracing::warn!("pam.sock: {}", reply.message);
    }
    if !keyring.is_locked() {
        let _ = secrets.unlocked().await;
    }
    let frame = reply.encode().map_err(std::io::Error::other)?;
    stream.write_all(&frame).await
}

async fn read_request(stream: &mut tokio::net::UnixStream) -> std::io::Result<Request> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len = aleph_pam_proto::payload_len(header).map_err(std::io::Error::other)?;
    let mut payload = Zeroizing::new(vec![0u8; len]);
    stream.read_exact(&mut payload).await?;
    Request::decode(&payload).map_err(std::io::Error::other)
}

/// Carry out one request (on a blocking thread: it may wait for the TPM,
/// or for a running conversation to end).
async fn answer(request: Request, keyring: &Arc<Keyring>, limits: &Arc<Mutex<Limits>>) -> Reply {
    let now = Instant::now();
    let refused = {
        let mut l = limits.lock().unwrap();
        if let Some(wait) = l.failures.blocked(now) {
            Some(format!(
                "too many failed requests; retry in {} s",
                wait.as_secs().max(1)
            ))
        } else if l.failures.recent(now) + l.in_flight >= TYPED_FAILURES {
            Some("too many requests at once; retry shortly".to_string())
        } else {
            l.in_flight += 1;
            None
        }
    };
    if let Some(message) = refused {
        return Reply { ok: false, message };
    }
    let keyring = keyring.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<String> {
        let text = |p: &aleph_pam_proto::Password| {
            std::str::from_utf8(p.expose())
                .map(|s| Zeroizing::new(s.to_string()))
                .map_err(|_| Error::Invalid("the password is not UTF-8".into()))
        };
        match request {
            Request::Unlock { password } => {
                keyring.unlock_with_login_password(&text(&password)?)?;
                Ok("unlocked".into())
            }
            Request::ChangePassword { old, new } => {
                keyring.change_login_password(&text(&old)?, &text(&new)?)
            }
        }
    })
    .await
    .unwrap_or_else(|e| Err(Error::Invalid(format!("request failed: {e}"))));
    let mut l = limits.lock().unwrap();
    l.in_flight -= 1;
    match result {
        Ok(message) => Reply { ok: true, message },
        Err(e) => {
            // Only a rejected password counts: a busy or rate-limited TPM
            // must not lock real logins out.
            if matches!(
                e,
                Error::WrongPassword | Error::PasswordChanged | Error::Stale(_) | Error::Invalid(_)
            ) {
                l.failures.record_failure(now);
            }
            Reply {
                ok: false,
                message: e.to_string(),
            }
        }
    }
}
```

Apply this patch with `git apply` (save it as `/tmp/t4-impl.patch`):

```diff
--- a/crates/aleph-daemon/src/paths.rs
+++ b/crates/aleph-daemon/src/paths.rs
@@ -70,4 +70,9 @@
     pub fn slot_state(&self) -> PathBuf {
         self.state_dir.join("slots.json")
     }
+
+    /// Where `pam_aleph` hands over the login password (§6).
+    pub fn pam_socket(&self) -> PathBuf {
+        self.runtime_dir.join("pam.sock")
+    }
 }
--- a/crates/aleph-daemon/src/password.rs
+++ b/crates/aleph-daemon/src/password.rs
@@ -266,6 +266,12 @@
 impl TypedLimiter {
     /// `Some(wait)` if typing is blocked now.
     pub fn blocked(&mut self, now: Instant) -> Option<Duration> {
+        (self.recent(now) >= TYPED_FAILURES)
+            .then(|| TYPED_WINDOW.saturating_sub(now.duration_since(self.failures[0])))
+    }
+
+    /// Failures within the window.
+    pub fn recent(&mut self, now: Instant) -> usize {
         while self
             .failures
             .front()
@@ -273,8 +279,7 @@
         {
             self.failures.pop_front();
         }
-        (self.failures.len() >= TYPED_FAILURES)
-            .then(|| TYPED_WINDOW.saturating_sub(now.duration_since(self.failures[0])))
+        self.failures.len()
     }
 
     pub fn record_failure(&mut self, now: Instant) {
--- a/crates/aleph-daemon/src/testing.rs
+++ b/crates/aleph-daemon/src/testing.rs
@@ -348,8 +348,22 @@
 }
 
 pub async fn daemon(create: bool, prompts: Vec<Vec<FromPrompter>>) -> Daemon {
+    daemon_with(create, prompts, Box::new(Fixed(|p| p == PW))).await
+}
+
+/// `daemon`, with the given password check (PAM).
+pub async fn daemon_with(
+    create: bool,
+    prompts: Vec<Vec<FromPrompter>>,
+    check: Box<dyn crate::password::PasswordCheck>,
+) -> Daemon {
     let env = env();
-    let keyring = Arc::new(keyring(&env, MockKeys::default()));
+    let keyring = Arc::new(keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::default(),
+        check,
+    ));
     if create {
         create_with_password(&keyring);
     }
--- a/crates/aleph-daemon/src/main.rs
+++ b/crates/aleph-daemon/src/main.rs
@@ -55,10 +55,25 @@
         .map_err(|e| {
             format!("cannot own {SECRETS_NAME} on the session bus (is gnome-keyring still running?): {e}")
         })?;
-    aleph_daemon::daemon::serve(&conn, keyring, launcher, config, paths)
+    let pam_socket = paths.pam_socket();
+    let secrets = aleph_daemon::daemon::serve(&conn, keyring.clone(), launcher, config, paths)
         .await
         .map_err(|e| e.to_string())?;
     tracing::info!("serving {SECRETS_NAME} and {BUS_NAME}");
+    // Login unlock needs pam.sock; without it the rest still works.
+    match aleph_daemon::pamsock::listener(&pam_socket) {
+        Ok(listener) => {
+            tokio::spawn(async move {
+                if let Err(e) = aleph_daemon::pamsock::serve(listener, keyring, secrets).await {
+                    tracing::error!("pam.sock stopped: {e}");
+                }
+            });
+        }
+        Err(e) => tracing::warn!(
+            "no pam.sock ({}): login unlock is unavailable: {e}",
+            pam_socket.display()
+        ),
+    }
     let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
         .map_err(|e| e.to_string())?;
     tokio::select! {
```

Write `packaging/systemd/alephd.socket`:

```ini
[Unit]
Description=aleph keyring daemon: the login password socket
Documentation=https://github.com/kisom/aleph-keyring

[Socket]
# pam_aleph connects here (as the user) to hand over the login password;
# a connection starts alephd.service if it is not running yet. alephd
# checks the peer's uid itself (SO_PEERCRED).
ListenStream=%t/aleph/pam.sock
FileDescriptorName=pam
SocketMode=0600
DirectoryMode=0700

[Install]
WantedBy=sockets.target
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 29 passed | ok. 3 passed | ok. 47 passed | ok. 1 passed | ok. 2 passed | ok. 8 passed | ok. 17 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **a wrong new password is refused before waiting** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test pam_socket a_wrong_new_password_is_refused_without_waiting`:

  replace

  ```rust
  let vouched = match lock(&self.hw).password.check(new) {
  ```

  with

  ```rust
  let _early = lock(&self.ops);
  let vouched = match lock(&self.hw).password.check(new) {
  ```

- **requests in flight count against the limit** (`crates/aleph-daemon/src/pamsock.rs`), test `cargo test -p aleph-daemon --test pam_socket requests_in_flight_are_bounded`: replace `} else if l.failures.recent(now) + l.in_flight >= TYPED_FAILURES {` with `} else if false {`.
- **a served socket is left alone** (`crates/aleph-daemon/src/pamsock.rs`), test `cargo test -p aleph-daemon --test pam_socket the_listener_leaves_a_served_socket_alone`: replace `if std::os::unix::net::UnixStream::connect(path).is_ok() {` with `if false {`.
- **pam.sock limits rejected passwords** (`crates/aleph-daemon/src/pamsock.rs`), test `cargo test -p aleph-daemon --test pam_socket failed_requests_are_limited`:

  replace

  ```rust
  l.failures.record_failure(now);
  ```

  with

  ```rust
  // (nothing)
  ```


- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/aleph-daemon packaging/systemd/alephd.socket
git commit -m "feat(daemon): pam.sock" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 5: pam_aleph

**Interfaces:**
- Consumes: Task 1; Task 4 (tests).
- Produces: `pam_aleph::{TIMEOUT, deliver::{Target { uid, gid }, Outcome, target(&str), deliver(Target, &Path, &[u8], Duration) -> Outcome}, module::{Pam, Courier, authenticate, open_session, change_password}}`; `pam_sm_{authenticate, setcred, open_session, close_session, chauthtok}` (installed as `pam_aleph.so`, stacked as `-auth optional pam_aleph.so` and so on)

- [ ] **Step 1: Write the failing tests**

Write `Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/aleph-core", "crates/aleph-tpm-proto", "crates/aleph-tpmd", "crates/aleph-unlock", "crates/aleph-prompt-proto", "crates/aleph-daemon", "crates/aleph-cli", "crates/aleph-pam-proto", "crates/pam_aleph"]

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

Write `crates/pam_aleph/Cargo.toml`:

```toml
[package]
name = "pam_aleph"
description = "PAM module: hands the login password to alephd (login and screen unlock, passwd)"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[lib]
# The module itself (libpam_aleph.so, installed as pam_aleph.so), and an
# rlib so tests and alephd's tests can call its delivery code.
crate-type = ["cdylib", "rlib"]

[dependencies]
aleph-pam-proto = { path = "../aleph-pam-proto" }
libc.workspace = true
zeroize.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

Create `crates/pam_aleph/src/lib.rs` containing only `// implemented in step 3`.

Write `crates/pam_aleph/tests/deliver.rs`:

```rust
//! The forked delivery against a real Unix socket (as the test's own user:
//! no privilege change needed).

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

use aleph_pam_proto::{Password, Reply, Request};
use pam_aleph::deliver::{Outcome, Target, deliver};

fn me() -> Target {
    // SAFETY: getuid/getgid cannot fail.
    unsafe {
        Target {
            uid: libc::getuid(),
            gid: libc::getgid(),
        }
    }
}

fn request() -> Request {
    Request::Unlock {
        password: Password::new(b"hunter2"),
    }
}

/// A one-connection daemon that answers `ok`; returns what it received.
fn daemon(listener: UnixListener, ok: bool) -> std::thread::JoinHandle<Request> {
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut header = [0u8; 4];
        s.read_exact(&mut header).unwrap();
        let mut payload = vec![0u8; aleph_pam_proto::payload_len(header).unwrap()];
        s.read_exact(&mut payload).unwrap();
        let reply = Reply {
            ok,
            message: "done".into(),
        };
        s.write_all(&reply.encode().unwrap()).unwrap();
        Request::decode(&payload).unwrap()
    })
}

#[test]
fn a_request_arrives_and_the_answer_comes_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pam.sock");
    for ok in [true, false] {
        let got = daemon(UnixListener::bind(&path).unwrap(), ok);
        let frame = request().encode().unwrap();
        let outcome = deliver(me(), &path, &frame, Duration::from_secs(5));
        assert_eq!(
            outcome,
            if ok {
                Outcome::Accepted
            } else {
                Outcome::Refused
            }
        );
        assert_eq!(got.join().unwrap(), request());
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn no_daemon_is_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let frame = request().encode().unwrap();
    let outcome = deliver(
        me(),
        &dir.path().join("pam.sock"),
        &frame,
        Duration::from_secs(5),
    );
    assert_eq!(outcome, Outcome::Unreachable);
}

/// A daemon that never answers costs the host program the timeout, no
/// more.
#[test]
fn a_silent_daemon_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pam.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let hold = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(4));
        drop(s);
    });
    let frame = request().encode().unwrap();
    let t = Instant::now();
    let outcome = deliver(me(), &path, &frame, Duration::from_secs(1));
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    assert!(
        matches!(outcome, Outcome::TimedOut | Outcome::Failed),
        "{outcome:?}"
    );
    hold.join().unwrap();
}

/// The child keeps none of the host's descriptors: a pipe the host holds
/// reads end-of-file once the host closes its end, even while the child
/// still waits on a silent daemon.
#[test]
fn the_child_does_not_keep_the_hosts_descriptors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pam.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let hold = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_secs(3));
        drop(s);
    });
    let mut fds = [0; 2];
    // SAFETY: pipe fills the array (no close-on-exec: the child never execs).
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let [read_end, write_end] = fds;
    let delivery = std::thread::spawn(move || {
        let frame = request().encode().unwrap();
        deliver(me(), &path, &frame, Duration::from_secs(2))
    });
    std::thread::sleep(Duration::from_millis(300));
    // SAFETY: our own descriptors.
    unsafe { libc::close(write_end) };
    let mut pfd = libc::pollfd {
        fd: read_end,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd.
    let ready = unsafe { libc::poll(&mut pfd, 1, 500) };
    assert_eq!(ready, 1, "the child still holds the pipe's write end");
    unsafe { libc::close(read_end) };
    delivery.join().unwrap();
    hold.join().unwrap();
}

/// Someone else's uid cannot be delivered as without root.
#[test]
fn another_user_cannot_be_impersonated() {
    // SAFETY: getuid cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return; // root may switch users
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pam.sock");
    let _listener = UnixListener::bind(&path).unwrap();
    let other = Target {
        uid: me().uid + 1,
        gid: me().gid,
    };
    let frame = request().encode().unwrap();
    assert_eq!(
        deliver(other, &path, &frame, Duration::from_secs(5)),
        Outcome::NoPrivileges
    );
}

#[test]
fn the_current_user_is_found_by_name() {
    let name = std::env::var("USER").unwrap_or_default();
    if name.is_empty() {
        return;
    }
    assert_eq!(pam_aleph::deliver::target(&name), Some(me()));
    assert_eq!(pam_aleph::deliver::target("no-such-user-aleph"), None);
}
```

Write `crates/pam_aleph/tests/sigchld.rs`:

```rust
//! The host's `SIGCHLD` handling is its own (a test binary of its own: it
//! changes process-wide state).

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::time::Duration;

use aleph_pam_proto::{Password, Reply, Request};
use pam_aleph::deliver::{Outcome, Target, deliver};

/// A host that ignores `SIGCHLD` (its children are reaped automatically)
/// still gets the answer, and its disposition is left as it was.
#[test]
fn a_host_ignoring_sigchld_keeps_it_and_still_gets_the_answer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pam.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let daemon = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut header = [0u8; 4];
        s.read_exact(&mut header).unwrap();
        let mut payload = vec![0u8; aleph_pam_proto::payload_len(header).unwrap()];
        s.read_exact(&mut payload).unwrap();
        let reply = Reply {
            ok: true,
            message: "unlocked".into(),
        };
        s.write_all(&reply.encode().unwrap()).unwrap();
    });
    // SAFETY: setting and reading this process's SIGCHLD disposition.
    let before = unsafe {
        libc::signal(libc::SIGCHLD, libc::SIG_IGN);
        let mut now: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut now);
        now.sa_sigaction
    };
    let me = unsafe {
        Target {
            uid: libc::getuid(),
            gid: libc::getgid(),
        }
    };
    let frame = Request::Unlock {
        password: Password::new(b"pw"),
    }
    .encode()
    .unwrap();
    let outcome = deliver(me, &path, &frame, Duration::from_secs(5));
    assert_eq!(outcome, Outcome::Accepted);
    let after = unsafe {
        let mut now: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut now);
        now.sa_sigaction
    };
    assert_eq!((before, after), (libc::SIG_IGN, libc::SIG_IGN));
    daemon.join().unwrap();
}
```

Write `crates/pam_aleph/tests/libpam.rs`:

```rust
//! The built module, loaded by real Linux-PAM from a private service
//! directory (`pam_start_confdir`). `pam_exec expose_authtok` stands in for
//! `pam_unix`: it obtains the password through the test's conversation and
//! sets `PAM_AUTHTOK`, which an application cannot set itself.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use aleph_pam_proto::{Password, Reply, Request};

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

#[repr(C)]
struct Message {
    style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct Response {
    resp: *mut c_char,
    retcode: c_int,
}

#[repr(C)]
struct Conv {
    conv: extern "C" fn(c_int, *mut *const Message, *mut *mut Response, *mut c_void) -> c_int,
    appdata: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conv: *const Conv,
        confdir: *const c_char,
        handle: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_open_session(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
}

/// Answers every hidden prompt with "hunter2".
extern "C" fn conversation(
    n: c_int,
    msgs: *mut *const Message,
    out: *mut *mut Response,
    _: *mut c_void,
) -> c_int {
    // SAFETY: PAM passes `n` messages; responses are calloc'd, answers
    // strdup'd, as PAM frees them with free().
    unsafe {
        let responses =
            libc::calloc(n as usize, std::mem::size_of::<Response>()).cast::<Response>();
        for i in 0..n as usize {
            if (**msgs.add(i)).style == PAM_PROMPT_ECHO_OFF {
                (*responses.add(i)).resp = libc::strdup(c"hunter2".as_ptr());
            }
        }
        *out = responses;
    }
    PAM_SUCCESS
}

/// The built module (next to the test binary's directory).
fn module() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let deps = exe.parent().unwrap();
    [
        deps.join("libpam_aleph.so"),
        deps.parent().unwrap().join("libpam_aleph.so"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .expect("libpam_aleph.so is built with the tests")
}

/// A service file in `dir` stacking pam_exec, then pam_aleph.
fn service(dir: &Path, socket: &Path) {
    let m = module();
    let arg = format!("socket={}", socket.display());
    let text = format!(
        "auth     optional pam_exec.so expose_authtok quiet /usr/bin/cat\n\
         auth     optional {m} {arg}\n\
         auth     required pam_permit.so\n\
         session  optional {m} {arg}\n\
         session  required pam_permit.so\n",
        m = m.display()
    );
    std::fs::write(dir.join("aleph-test"), text).unwrap();
}

/// A daemon answering every request `ok`, reporting each on `tx`.
fn daemon(listener: UnixListener, tx: mpsc::Sender<Request>) {
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let mut s = s.unwrap();
            let mut header = [0u8; 4];
            s.read_exact(&mut header).unwrap();
            let mut payload = vec![0u8; aleph_pam_proto::payload_len(header).unwrap()];
            s.read_exact(&mut payload).unwrap();
            let reply = Reply {
                ok: true,
                message: "unlocked".into(),
            };
            s.write_all(&reply.encode().unwrap()).unwrap();
            tx.send(Request::decode(&payload).unwrap()).unwrap();
        }
    });
}

/// Run auth, then (after `between`) session open, through real PAM.
fn login(dir: &Path, between: impl FnOnce()) -> (c_int, c_int) {
    let user = CString::new(std::env::var("USER").expect("USER")).unwrap();
    let confdir = CString::new(dir.to_str().unwrap()).unwrap();
    let conv = Conv {
        conv: conversation,
        appdata: std::ptr::null_mut(),
    };
    let mut h = std::ptr::null_mut();
    // SAFETY: valid strings and conversation for the handle's lifetime.
    unsafe {
        assert_eq!(
            pam_start_confdir(
                c"aleph-test".as_ptr(),
                user.as_ptr(),
                &conv,
                confdir.as_ptr(),
                &mut h
            ),
            PAM_SUCCESS
        );
        let auth = pam_authenticate(h, 0);
        between();
        let session = pam_open_session(h, 0);
        pam_end(h, PAM_SUCCESS);
        (auth, session)
    }
}

fn unlock() -> Request {
    Request::Unlock {
        password: Password::new(b"hunter2"),
    }
}

/// With the daemon up (a screen locker), the password goes out at auth.
#[test]
fn with_the_daemon_up_the_password_goes_out_at_auth() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pam.sock");
    service(dir.path(), &socket);
    let (tx, rx) = mpsc::channel();
    daemon(UnixListener::bind(&socket).unwrap(), tx);
    let (auth, session) = login(dir.path(), || {
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), unlock());
    });
    assert_eq!((auth, session), (PAM_SUCCESS, PAM_SUCCESS));
    // Once only: nothing more at session open.
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
}

/// At login the user's daemon is not up yet: the password is kept and
/// goes out at session open.
#[test]
fn at_login_the_password_goes_out_at_session_open() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pam.sock");
    service(dir.path(), &socket);
    let (tx, rx) = mpsc::channel();
    let (auth, session) = login(dir.path(), || {
        daemon(UnixListener::bind(&socket).unwrap(), tx);
    });
    assert_eq!((auth, session), (PAM_SUCCESS, PAM_SUCCESS));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), unlock());
}

/// No daemon at all: the login still succeeds, promptly.
#[test]
fn without_a_daemon_login_goes_on() {
    let dir = tempfile::tempdir().unwrap();
    service(dir.path(), &dir.path().join("pam.sock"));
    let t = std::time::Instant::now();
    let (auth, session) = login(dir.path(), || {});
    assert_eq!((auth, session), (PAM_SUCCESS, PAM_SUCCESS));
    assert!(t.elapsed() < Duration::from_secs(2));
}
```

Write `crates/aleph-daemon/Cargo.toml`:

```toml
[package]
name = "aleph-daemon"
description = "alephd: the aleph keyring daemon (Secret Service and admin interface)"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[[bin]]
name = "alephd"
path = "src/main.rs"

[features]
testing = ["dep:aleph-tpmd", "dep:tempfile", "aleph-core/insecure-test-params"]

[dependencies]
aes = "0.9"
cbc = { version = "0.2", features = ["alloc"] }
futures-util = { version = "0.3", default-features = false }
hkdf.workspace = true
num-bigint = "0.4"
sha2.workspace = true
aleph-core = { path = "../aleph-core" }
aleph-pam-proto = { path = "../aleph-pam-proto" }
aleph-prompt-proto = { path = "../aleph-prompt-proto" }
aleph-tpm-proto = { path = "../aleph-tpm-proto" }
aleph-unlock = { path = "../aleph-unlock" }
libc.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time", "signal", "net", "io-util"] }
toml = "1"
tracing = "0.1"
tracing-journald = "0.3"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
uuid.workspace = true
zbus = { version = "5", default-features = false, features = ["tokio"] }
zeroize.workspace = true
aleph-tpmd = { path = "../aleph-tpmd", features = ["testing"], optional = true }
tempfile = { workspace = true, optional = true }

[dev-dependencies]
aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
aleph-daemon = { path = ".", features = ["testing"] }
pam_aleph = { path = "../pam_aleph" }
tempfile.workspace = true
serde.workspace = true
```

Write `crates/aleph-daemon/tests/pam_socket.rs`:

```rust
//! `pam.sock` with the real daemon (keyring on swtpm, Secret Service on a
//! private bus), the test playing `pam_aleph`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use aleph_daemon::testing::*;
use aleph_pam_proto::{Password, Reply, Request};
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

/// A daemon with `pam.sock` served at a temporary path.
async fn served() -> (Daemon, PathBuf) {
    served_with(Box::new(Fixed(|p| p == PW))).await
}

/// `served`, with the given password check (PAM).
async fn served_with(check: Box<dyn aleph_daemon::password::PasswordCheck>) -> (Daemon, PathBuf) {
    let d = daemon_with(true, vec![], check).await;
    let path = d.env.paths.pam_socket();
    let listener = aleph_daemon::pamsock::listener(&path).unwrap();
    let (keyring, secrets) = (d.keyring.clone(), d.secrets.clone());
    tokio::spawn(aleph_daemon::pamsock::serve(listener, keyring, secrets));
    (d, path)
}

/// Send `request` as `pam_aleph` would; `None` if the daemon hung up
/// without a reply.
async fn send_raw(path: &std::path::Path, frame: Vec<u8>) -> Option<Reply> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut s = UnixStream::connect(&path).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        s.write_all(&frame).unwrap();
        let mut header = [0u8; 4];
        s.read_exact(&mut header).ok()?;
        let mut payload = vec![0u8; aleph_pam_proto::payload_len(header).unwrap()];
        s.read_exact(&mut payload).unwrap();
        Some(Reply::decode(&payload).unwrap())
    })
    .await
    .unwrap()
}

async fn send(path: &std::path::Path, request: Request) -> Reply {
    send_raw(path, request.encode().unwrap().to_vec())
        .await
        .expect("a reply")
}

fn unlock(pw: &str) -> Request {
    Request::Unlock {
        password: Password::new(pw.as_bytes()),
    }
}

/// The login password unlocks the vault, and a Secret Service prompt that
/// was waiting (no prompter at login) completes with it: the client that
/// asked before the unlock gets its answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_login_password_unlocks_and_completes_waiting_prompts() {
    use futures_util::StreamExt;
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    let c = zbus::connection::Builder::address(d.bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let svc = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = svc
        .call(
            "Unlock",
            &(vec![
                ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
            ],),
        )
        .await
        .unwrap();
    let p = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    let mut completed = p.receive_signal("Completed").await.unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(d.secrets.waiting_count(), 1);

    let reply = send(&path, unlock(PW)).await;
    assert!(reply.ok, "{reply:?}");
    assert!(!d.keyring.is_locked());
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), completed.next())
        .await
        .expect("the waiting prompt completes")
        .unwrap();
    let (dismissed, _): (bool, zbus::zvariant::OwnedValue) = msg.body().deserialize().unwrap();
    assert!(!dismissed);
}

/// Failed requests are limited: after five, even the right password is
/// refused for a while, so a same-user process cannot guess through the
/// socket (and the TPM helper's own limit keeps its failures low).
#[tokio::test(flavor = "multi_thread")]
async fn failed_requests_are_limited() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    for _ in 0..aleph_daemon::password::TYPED_FAILURES {
        assert!(!send(&path, unlock("wrong")).await.ok);
    }
    let reply = send(&path, unlock(PW)).await;
    assert!(!reply.ok && reply.message.contains("too many"), "{reply:?}");
    assert!(d.keyring.is_locked());
    // (PAM rejected every wrong one: none reached the TPM.)
    assert_eq!(d.env.sw.tpm().status().unwrap().failed_tries, 0);
}

/// `passwd`'s change arrives through the socket; the new password then
/// unlocks.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_arrives_through_the_socket() {
    let login = Accepting::new(PW);
    let (d, path) = served_with(Box::new(login.clone())).await;
    // passwd has changed the password when pam_aleph runs.
    login.set("new password");
    let reply = send(
        &path,
        Request::ChangePassword {
            old: Password::new(PW.as_bytes()),
            new: Password::new(b"new password"),
        },
    )
    .await;
    assert!(reply.ok, "{reply:?}");
    d.secrets.lock().await.unwrap();
    assert!(send(&path, unlock("new password")).await.ok);
    assert!(!d.keyring.is_locked());
}

/// The module's own delivery code (fork, connect, answer) against the
/// daemon's socket: the two ends agree.
#[tokio::test(flavor = "multi_thread")]
async fn pam_aleph_delivers_to_the_daemon() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    let outcome = tokio::task::spawn_blocking(move || {
        // SAFETY: getuid/getgid cannot fail.
        let me = unsafe {
            pam_aleph::deliver::Target {
                uid: libc::getuid(),
                gid: libc::getgid(),
            }
        };
        let frame = unlock(PW).encode().unwrap();
        pam_aleph::deliver::deliver(me, &path, &frame, pam_aleph::TIMEOUT)
    })
    .await
    .unwrap();
    assert_eq!(outcome, pam_aleph::deliver::Outcome::Accepted);
    assert!(!d.keyring.is_locked());
}

/// A conversation nobody answers holds the daemon's operation lock; returns
/// the prompter's end (drop it to end the conversation) and its thread.
fn hold_a_conversation(
    d: &Daemon,
) -> (
    UnixStream,
    std::thread::JoinHandle<aleph_daemon::Result<()>>,
) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let mut silent =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(60)).unwrap();
    let keyring = d.keyring.clone();
    let thread = std::thread::spawn(move || keyring.unlock(&mut silent, None));
    std::thread::sleep(std::time::Duration::from_millis(200));
    (theirs, thread)
}

fn change(old: &str, new: &str) -> Request {
    Request::ChangePassword {
        old: Password::new(old.as_bytes()),
        new: Password::new(new.as_bytes()),
    }
}

/// A new password PAM rejects is refused at once, even while a
/// conversation holds the daemon (nothing queues behind it).
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_new_password_is_refused_without_waiting() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    let (prompter, conversation) = hold_a_conversation(&d);
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        send(&path, change(PW, "not the login password")),
    )
    .await
    .expect("refused without waiting");
    assert!(
        !reply.ok && reply.message.contains("not the login password"),
        "{reply:?}"
    );
    drop(prompter);
    assert!(conversation.join().unwrap().is_err());
}

/// Requests being answered count against the limit, so parallel
/// connections cannot get past it: with a conversation holding the daemon,
/// five changes wait their turn and the rest are refused at once.
#[tokio::test(flavor = "multi_thread")]
async fn requests_in_flight_are_bounded() {
    let login = Accepting::new(PW);
    let (d, path) = served_with(Box::new(login.clone())).await;
    d.secrets.lock().await.unwrap();
    login.set("new");
    let (prompter, conversation) = hold_a_conversation(&d);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for _ in 0..7 {
        let (path, tx) = (path.clone(), tx.clone());
        tokio::spawn(async move { tx.send(send(&path, change(PW, "new")).await).unwrap() });
    }
    for _ in 0..2 {
        let reply = tokio::time::timeout(std::time::Duration::from_secs(20), rx.recv())
            .await
            .expect("refused at once")
            .unwrap();
        assert!(!reply.ok && reply.message.contains("at once"), "{reply:?}");
    }
    drop(prompter);
    assert!(conversation.join().unwrap().is_err());
    for _ in 0..5 {
        tokio::time::timeout(std::time::Duration::from_secs(60), rx.recv())
            .await
            .expect("answered once the conversation ended")
            .unwrap();
    }
}

/// A malformed request gets no reply, and the socket keeps serving.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_request_is_dropped() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    assert_eq!(send_raw(&path, vec![0, 0, 0, 1, 99]).await, None);
    assert!(send(&path, unlock(PW)).await.ok);
}

/// A leftover socket file (a crashed daemon) is replaced; anything else
/// at the path is left alone.
#[test]
fn the_listener_replaces_only_a_leftover_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run/aleph/pam.sock");
    drop(aleph_daemon::pamsock::listener(&path).unwrap());
    let l = aleph_daemon::pamsock::listener(&path).unwrap();
    drop(l);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"not a socket").unwrap();
    assert!(aleph_daemon::pamsock::listener(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
}

/// A socket something still serves (`alephd.socket`, when alephd is run by
/// hand) is left alone.
#[test]
fn the_listener_leaves_a_served_socket_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run/aleph/pam.sock");
    let serving = aleph_daemon::pamsock::listener(&path).unwrap();
    assert!(aleph_daemon::pamsock::listener(&path).is_err());
    drop(serving);
    // (Nobody serves it now: a leftover, replaced.)
    drop(aleph_daemon::pamsock::listener(&path).unwrap());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p pam_aleph`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/pam_aleph/src/lib.rs`:

```rust
//! `pam_aleph`: hands the login password to `alephd` (spec §6 "PAM
//! integration").
//!
//! Stacked after `pam_unix` in the display manager's `auth` and `session`
//! stacks, the screen locker's `auth` stack, and `passwd`'s `password`
//! stack (as `-auth optional pam_aleph.so` and so on: with `-`, a missing
//! module is skipped), so it only ever sees a password the login stack
//! accepted. What each phase does is in
//! [`module`]; how a request reaches the user's daemon is in [`deliver`].
//! It always returns `PAM_IGNORE`, and logs to syslog, never a password.
//!
//! Module arguments: `socket=<path>` sends to that socket instead of
//! `/run/user/<uid>/aleph/pam.sock` (for tests).

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::PathBuf;
use std::time::Duration;

use aleph_pam_proto::Request;
use zeroize::Zeroizing;

pub mod deliver;
pub mod module;

/// How long the host program waits for a delivery, at most (§6).
pub const TIMEOUT: Duration = Duration::from_secs(5);

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_USER: c_int = 2;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;
const PAM_UPDATE_AUTHTOK: c_int = 0x2000;
const LOG_INFO: c_int = 6;

/// The `pam_set_data` name for the kept password.
const KEPT: &CStr = c"aleph_password";

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

type Cleanup = unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int);

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_item(pamh: *const PamHandle, item: c_int, value: *mut *const c_void) -> c_int;
    fn pam_set_data(
        pamh: *mut PamHandle,
        name: *const c_char,
        data: *mut c_void,
        cleanup: Option<Cleanup>,
    ) -> c_int;
    fn pam_get_data(pamh: *const PamHandle, name: *const c_char, data: *mut *const c_void)
    -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
}

/// Frees a kept password (zeroizing it) when PAM ends or it is replaced.
unsafe extern "C" fn drop_kept(_: *mut PamHandle, data: *mut c_void, _: c_int) {
    if !data.is_null() {
        // SAFETY: `data` came from `Box::into_raw` in `keep`, and PAM calls
        // the cleanup once.
        drop(unsafe { Box::from_raw(data.cast::<Zeroizing<Vec<u8>>>()) });
    }
}

/// The real PAM handle.
struct Handle(*mut PamHandle);

impl Handle {
    fn item(&self, which: c_int) -> Option<Zeroizing<Vec<u8>>> {
        let mut value = std::ptr::null();
        // SAFETY: a valid handle and out-pointer; string items are
        // NUL-terminated strings owned by PAM.
        unsafe {
            if pam_get_item(self.0, which, &mut value) != PAM_SUCCESS || value.is_null() {
                return None;
            }
            Some(Zeroizing::new(
                CStr::from_ptr(value.cast()).to_bytes().to_vec(),
            ))
        }
    }
}

impl module::Pam for Handle {
    fn user(&self) -> Option<String> {
        String::from_utf8(self.item(PAM_USER)?.to_vec()).ok()
    }

    fn authtok(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.item(PAM_AUTHTOK).filter(|p| !p.is_empty())
    }

    fn old_authtok(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.item(PAM_OLDAUTHTOK).filter(|p| !p.is_empty())
    }

    fn keep(&mut self, password: Zeroizing<Vec<u8>>) {
        let data = Box::into_raw(Box::new(password)).cast::<c_void>();
        // SAFETY: PAM owns `data` from here and frees it with `drop_kept`
        // (also when it replaces it).
        if unsafe { pam_set_data(self.0, KEPT.as_ptr(), data, Some(drop_kept)) } != PAM_SUCCESS {
            // SAFETY: PAM did not take it.
            unsafe { drop_kept(self.0, data, 0) };
        }
    }

    fn take_kept(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        let mut data = std::ptr::null();
        // SAFETY: a valid handle; the data is our boxed password.
        unsafe {
            if pam_get_data(self.0, KEPT.as_ptr(), &mut data) != PAM_SUCCESS || data.is_null() {
                return None;
            }
            let password = (*data.cast::<Zeroizing<Vec<u8>>>()).clone();
            // Replacing it frees (and zeroizes) the kept copy.
            pam_set_data(self.0, KEPT.as_ptr(), std::ptr::null_mut(), None);
            Some(password)
        }
    }

    fn log(&self, message: &str) {
        let Ok(message) = CString::new(format!("pam_aleph: {message}")) else {
            return;
        };
        // SAFETY: a "%s" format with one C string argument.
        unsafe { pam_syslog(self.0, LOG_INFO, c"%s".as_ptr(), message.as_ptr()) };
    }
}

/// Delivers to the user's `pam.sock` (or the `socket=` argument).
struct SocketCourier {
    socket: Option<PathBuf>,
}

impl SocketCourier {
    fn path(&self, target: deliver::Target) -> PathBuf {
        self.socket
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}/aleph/pam.sock", target.uid)))
    }
}

impl module::Courier for SocketCourier {
    fn ready(&self, user: &str) -> bool {
        deliver::target(user).is_some_and(|t| self.path(t).exists())
    }

    fn deliver(&self, user: &str, request: &Request) -> deliver::Outcome {
        let Some(target) = deliver::target(user) else {
            return deliver::Outcome::NoPrivileges;
        };
        let Ok(frame) = request.encode() else {
            return deliver::Outcome::Failed;
        };
        deliver::deliver(target, &self.path(target), &frame, TIMEOUT)
    }
}

fn courier(argc: c_int, argv: *const *const c_char) -> SocketCourier {
    let mut socket = None;
    for i in 0..usize::try_from(argc).unwrap_or(0) {
        // SAFETY: PAM passes `argc` valid C strings.
        let arg = unsafe { CStr::from_ptr(*argv.add(i)) };
        if let Some(path) = arg.to_bytes().strip_prefix(b"socket=") {
            socket = Some(PathBuf::from(String::from_utf8_lossy(path).into_owned()));
        }
    }
    SocketCourier { socket }
}

/// Run a phase; whatever happens (a panic included), answer `PAM_IGNORE`.
fn run(
    pamh: *mut PamHandle,
    argc: c_int,
    argv: *const *const c_char,
    phase: fn(&mut Handle, &SocketCourier),
) -> c_int {
    if pamh.is_null() {
        return PAM_IGNORE;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        phase(&mut Handle(pamh), &courier(argc, argv))
    }));
    PAM_IGNORE
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    run(pamh, argc, argv, |h, c| module::authenticate(h, c))
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    run(pamh, argc, argv, |h, c| module::open_session(h, c))
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_chauthtok(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let update = flags & PAM_UPDATE_AUTHTOK != 0;
    if !update {
        return PAM_IGNORE;
    }
    run(pamh, argc, argv, |h, c| module::change_password(h, c, true))
}
```

Write `crates/pam_aleph/src/deliver.rs`:

```rust
//! Delivering one request to `pam.sock` as the target user.
//!
//! The module runs inside another program, often as root (the display
//! manager, `passwd`), sometimes as the user (the screen locker). The
//! request is sent from a forked child that first drops to the user's
//! uid and gid (only when running as root), so the daemon's
//! `SO_PEERCRED` check sees the user and root never writes into a
//! user-controlled socket path. The parent waits at most the timeout, then
//! kills the child.
//!
//! The host program may be multithreaded, so the child calls only
//! async-signal-safe functions: everything (the socket address, the
//! request frame) is prepared before `fork`, and the child never
//! allocates. Writes use `MSG_NOSIGNAL`, so a daemon that hangs up cannot
//! kill the child with `SIGPIPE`, and `alarm` bounds the child even if the
//! parent is gone.
//!
//! The child closes every descriptor it inherited but its report pipe, and
//! resets `SIGALRM` so the backstop works whatever the host did with it.
//!
//! The host's `SIGCHLD` handling is never touched (it is process-wide, and
//! the host may be reaping its own children): the child reports its result
//! as one byte on a pipe, the parent waits on the pipe with the timeout,
//! kills through a pidfd (never a pid the host may have reaped and the
//! kernel reused), and reaps through the pidfd, ignoring `ECHILD` if the
//! host got there first.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// Whom to deliver as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

/// How a delivery ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The daemon did what was asked.
    Accepted,
    /// The daemon answered, but refused or failed (see its journal).
    Refused,
    /// No daemon listening at the socket.
    Unreachable,
    /// Could not become the target user.
    NoPrivileges,
    /// No answer within the timeout.
    TimedOut,
    /// Anything else (a malformed answer, a failed fork).
    Failed,
}

// What the child reports (one byte on the pipe, and its exit code).
const ACCEPTED: u8 = 0;
const REFUSED: u8 = 10;
const UNREACHABLE: u8 = 11;
const NO_PRIVILEGES: u8 = 12;
const FAILED: u8 = 13;

/// The largest reply read (a reply is a short status message).
const REPLY_MAX: usize = 1024;

/// The target user of `name`, from the password database.
pub fn target(name: &str) -> Option<Target> {
    let name = CString::new(name).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut out = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; `buf` outlives it.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    (rc == 0 && !out.is_null()).then_some(Target {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
    })
}

/// Send `frame` (a whole request frame) to the socket at `socket` as
/// `target`, and wait at most `timeout` for the answer.
pub fn deliver(target: Target, socket: &Path, frame: &[u8], timeout: Duration) -> Outcome {
    let Some(addr) = sockaddr(socket) else {
        return Outcome::Unreachable;
    };
    let secs = timeout.as_secs().max(1) as libc::c_uint;
    let tv = libc::timeval {
        tv_sec: timeout.as_secs().max(1) as libc::time_t,
        tv_usec: 0,
    };
    let mut pipe = [0; 2];
    // SAFETY: pipe2 fills the array.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Outcome::Failed;
    }
    let [report, reporter] = pipe;
    // SAFETY: the child runs only `child`, which calls async-signal-safe
    // functions on memory prepared before the fork, and never returns.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Nothing can panic in `child`; if something ever did, the forked
        // copy must exit, never unwind back into the host's PAM stack.
        let _exit = ExitOnUnwind(reporter);
        unsafe {
            libc::close(report);
            child(target, &addr, frame, &tv, secs, reporter)
        }
    }
    // SAFETY: closing our copy of the child's end.
    unsafe { libc::close(reporter) };
    if pid < 0 {
        unsafe { libc::close(report) };
        return Outcome::Failed;
    }
    // SAFETY: pidfd_open on our fresh child (it cannot have been reaped
    // yet unless it already exited, in which case the pipe says so).
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as libc::c_int;
    let outcome = wait(report, timeout);
    // SAFETY: signalling and reaping our own child, through its pidfd.
    unsafe {
        if pidfd >= 0 {
            if outcome == Outcome::TimedOut {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd,
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
            let mut info: libc::siginfo_t = std::mem::zeroed();
            // (ECHILD: the host reaped it, or ignores SIGCHLD. Either is fine.)
            libc::waitid(libc::P_PIDFD, pidfd as libc::id_t, &mut info, libc::WEXITED);
            libc::close(pidfd);
        } else {
            // No pidfd (an old kernel, a seccomp'd host, no descriptors
            // left): the pid, then. The child is ours and not yet reaped
            // unless the host reaps children itself.
            if outcome == Outcome::TimedOut {
                libc::kill(pid, libc::SIGKILL);
            }
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
        libc::close(report);
    }
    outcome
}

/// In the forked child: exit (reporting a failure) if unwinding, rather
/// than return into the host.
struct ExitOnUnwind(libc::c_int);

impl Drop for ExitOnUnwind {
    fn drop(&mut self) {
        // SAFETY: only ever dropped in the forked child.
        unsafe { finish(self.0, FAILED) }
    }
}

fn sockaddr(path: &Path) -> Option<libc::sockaddr_un> {
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return None;
    }
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    Some(addr)
}

/// The child's report, read from its pipe within `timeout`.
fn wait(report: libc::c_int, timeout: Duration) -> Outcome {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let mut pfd = libc::pollfd {
            fd: report,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(i32::MAX as u128) as i32) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            return Outcome::TimedOut;
        }
        let mut code = [0u8; 1];
        // SAFETY: reading one byte into a local.
        let got = unsafe { libc::read(report, code.as_mut_ptr().cast(), 1) };
        return match (got, code[0]) {
            (1, ACCEPTED) => Outcome::Accepted,
            (1, REFUSED) => Outcome::Refused,
            (1, UNREACHABLE) => Outcome::Unreachable,
            (1, NO_PRIVILEGES) => Outcome::NoPrivileges,
            // A child that died without a word (alarm, crash).
            _ => Outcome::Failed,
        };
    }
}

/// Report `code` on the pipe and exit with it.
///
/// # Safety
///
/// Only in the forked child.
unsafe fn finish(reporter: libc::c_int, code: u8) -> ! {
    unsafe {
        libc::write(reporter, (&raw const code).cast(), 1);
        libc::_exit(i32::from(code))
    }
}

/// The forked child: become the user, send, read the answer, report.
///
/// # Safety
///
/// Called only in a freshly forked child. Uses only async-signal-safe
/// calls, allocates nothing, and never returns.
unsafe fn child(
    target: Target,
    addr: &libc::sockaddr_un,
    frame: &[u8],
    tv: &libc::timeval,
    secs: libc::c_uint,
    reporter: libc::c_int,
) -> ! {
    unsafe {
        // The host's descriptors (sockets, devices) are not the child's
        // business: close all but the report pipe.
        if reporter > 3 {
            libc::syscall(libc::SYS_close_range, 3u32, (reporter - 1) as u32, 0u32);
        }
        libc::syscall(libc::SYS_close_range, (reporter + 1) as u32, u32::MAX, 0u32);
        // The host may ignore, catch, or block SIGALRM: the backstop needs
        // its default action.
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGALRM, &dfl, std::ptr::null_mut());
        let mut alrm: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut alrm);
        libc::sigaddset(&mut alrm, libc::SIGALRM);
        libc::sigprocmask(libc::SIG_UNBLOCK, &alrm, std::ptr::null_mut());
        libc::alarm(secs + 1);
        // Root drops to the user (groups, then gid, then uid); anyone else
        // must already be the user.
        if libc::geteuid() == 0
            && (libc::setgroups(1, &target.gid) != 0
                || libc::setgid(target.gid) != 0
                || libc::setuid(target.uid) != 0)
        {
            finish(reporter, NO_PRIVILEGES);
        }
        if libc::getuid() != target.uid || libc::geteuid() != target.uid {
            finish(reporter, NO_PRIVILEGES);
        }
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            finish(reporter, FAILED);
        }
        let tvp = (tv as *const libc::timeval).cast();
        let tvlen = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, tvp, tvlen);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, tvp, tvlen);
        if libc::connect(
            fd,
            (addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        ) != 0
        {
            finish(reporter, UNREACHABLE);
        }
        let mut sent = 0;
        while sent < frame.len() {
            let n = libc::send(
                fd,
                frame.as_ptr().add(sent).cast(),
                frame.len() - sent,
                libc::MSG_NOSIGNAL,
            );
            if n <= 0 {
                finish(reporter, FAILED);
            }
            sent += n as usize;
        }
        let mut reply = [0u8; REPLY_MAX];
        let mut got = 0;
        while got < REPLY_MAX {
            let n = libc::recv(fd, reply.as_mut_ptr().add(got).cast(), REPLY_MAX - got, 0);
            if n <= 0 {
                break;
            }
            got += n as usize;
            if let Some(ok) = aleph_pam_proto::reply_ok(reply.get_unchecked(..got)) {
                finish(reporter, if ok { ACCEPTED } else { REFUSED });
            }
        }
        finish(reporter, FAILED)
    }
}
```

Write `crates/pam_aleph/src/module.rs`:

```rust
//! What the module does in each PAM phase, over small traits so it can be
//! tested without libpam (`lib.rs` adapts the real handle).
//!
//! - **auth:** read the password (`PAM_AUTHTOK`, set by `pam_unix` before
//!   us). If the user's `pam.sock` exists (a screen locker, or a second
//!   login), deliver it now; otherwise, or if that fails, keep it
//!   (`pam_set_data`, zeroized on cleanup) for session open, when the
//!   user's systemd instance is up.
//! - **session open:** deliver a kept password.
//! - **password (chauthtok):** in the update phase, deliver the old and new
//!   passwords, only when both are known (root changing another user's
//!   password supplies no old one, and nothing is sent).
//!
//! Every phase returns `PAM_IGNORE`: the module never decides or blocks a
//! login. It never prompts either: without a password it does nothing.

use aleph_pam_proto::{Password, Request};
use zeroize::Zeroizing;

use crate::deliver::Outcome;

/// The PAM handle, as the module uses it.
pub trait Pam {
    /// `PAM_USER`.
    fn user(&self) -> Option<String>;
    /// `PAM_AUTHTOK`.
    fn authtok(&self) -> Option<Zeroizing<Vec<u8>>>;
    /// `PAM_OLDAUTHTOK`.
    fn old_authtok(&self) -> Option<Zeroizing<Vec<u8>>>;
    /// Keep the password until session open (replacing any kept one).
    fn keep(&mut self, password: Zeroizing<Vec<u8>>);
    /// Take the kept password, if any (it is no longer kept).
    fn take_kept(&mut self) -> Option<Zeroizing<Vec<u8>>>;
    fn log(&self, message: &str);
}

/// Where requests go.
pub trait Courier {
    /// The user's daemon is listening (its socket exists).
    fn ready(&self, user: &str) -> bool;
    fn deliver(&self, user: &str, request: &Request) -> Outcome;
}

fn send(
    pam: &dyn Pam,
    courier: &dyn Courier,
    user: &str,
    request: &Request,
    what: &str,
) -> Outcome {
    let outcome = courier.deliver(user, request);
    match outcome {
        Outcome::Accepted => pam.log(&format!("{what}: done")),
        other => pam.log(&format!("{what}: not done ({other:?})")),
    }
    outcome
}

pub fn authenticate(pam: &mut dyn Pam, courier: &dyn Courier) {
    let (Some(user), Some(password)) = (pam.user(), pam.authtok()) else {
        return;
    };
    if courier.ready(&user) {
        let request = Request::Unlock {
            password: Password::new(&password),
        };
        if send(pam, courier, &user, &request, "unlock") == Outcome::Accepted {
            return;
        }
    }
    // Not up yet (a login), or it did not work: try again at session open.
    pam.keep(password);
}

pub fn open_session(pam: &mut dyn Pam, courier: &dyn Courier) {
    let (Some(user), Some(password)) = (pam.user(), pam.take_kept()) else {
        return;
    };
    let request = Request::Unlock {
        password: Password::new(&password),
    };
    send(pam, courier, &user, &request, "unlock at login");
}

/// `update`: `PAM_UPDATE_AUTHTOK` is set (the change has been made by the
/// modules before this one).
pub fn change_password(pam: &mut dyn Pam, courier: &dyn Courier, update: bool) {
    if !update {
        return;
    }
    let (Some(user), Some(old), Some(new)) = (pam.user(), pam.old_authtok(), pam.authtok()) else {
        return;
    };
    let request = Request::ChangePassword {
        old: Password::new(&old),
        new: Password::new(&new),
    };
    send(pam, courier, &user, &request, "password change");
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct FakePam {
        authtok: Option<&'static str>,
        old: Option<&'static str>,
        kept: Option<Zeroizing<Vec<u8>>>,
        logs: RefCell<Vec<String>>,
    }

    impl Pam for FakePam {
        fn user(&self) -> Option<String> {
            Some("alice".into())
        }
        fn authtok(&self) -> Option<Zeroizing<Vec<u8>>> {
            self.authtok.map(|s| Zeroizing::new(s.as_bytes().to_vec()))
        }
        fn old_authtok(&self) -> Option<Zeroizing<Vec<u8>>> {
            self.old.map(|s| Zeroizing::new(s.as_bytes().to_vec()))
        }
        fn keep(&mut self, password: Zeroizing<Vec<u8>>) {
            self.kept = Some(password);
        }
        fn take_kept(&mut self) -> Option<Zeroizing<Vec<u8>>> {
            self.kept.take()
        }
        fn log(&self, message: &str) {
            self.logs.borrow_mut().push(message.into());
        }
    }

    struct FakeCourier {
        ready: bool,
        answer: Outcome,
        sent: RefCell<Vec<Request>>,
    }

    impl FakeCourier {
        fn new(ready: bool) -> Self {
            Self {
                ready,
                answer: Outcome::Accepted,
                sent: RefCell::default(),
            }
        }
    }

    impl Courier for FakeCourier {
        fn ready(&self, _: &str) -> bool {
            self.ready
        }
        fn deliver(&self, user: &str, request: &Request) -> Outcome {
            assert_eq!(user, "alice");
            self.sent.borrow_mut().push(request.clone());
            self.answer
        }
    }

    fn unlock(pw: &str) -> Request {
        Request::Unlock {
            password: Password::new(pw.as_bytes()),
        }
    }

    #[test]
    fn with_the_daemon_up_auth_delivers_at_once() {
        let mut pam = FakePam {
            authtok: Some("pw"),
            ..Default::default()
        };
        let courier = FakeCourier::new(true);
        authenticate(&mut pam, &courier);
        assert_eq!(*courier.sent.borrow(), [unlock("pw")]);
        assert!(pam.kept.is_none());
    }

    #[test]
    fn at_login_the_password_waits_for_session_open() {
        let mut pam = FakePam {
            authtok: Some("pw"),
            ..Default::default()
        };
        let courier = FakeCourier::new(false);
        authenticate(&mut pam, &courier);
        assert!(courier.sent.borrow().is_empty());
        open_session(&mut pam, &courier);
        assert_eq!(*courier.sent.borrow(), [unlock("pw")]);
        // Delivered once, and no longer kept.
        open_session(&mut pam, &courier);
        assert_eq!(courier.sent.borrow().len(), 1);
        assert!(pam.kept.is_none());
    }

    #[test]
    fn without_a_password_nothing_is_sent_or_asked() {
        let mut pam = FakePam::default();
        let courier = FakeCourier::new(true);
        authenticate(&mut pam, &courier);
        open_session(&mut pam, &courier);
        change_password(&mut pam, &courier, true);
        assert!(courier.sent.borrow().is_empty());
    }

    #[test]
    fn a_password_change_is_sent_once_both_passwords_are_known() {
        let mut pam = FakePam {
            authtok: Some("new"),
            old: Some("old"),
            ..Default::default()
        };
        let courier = FakeCourier::new(true);
        change_password(&mut pam, &courier, false);
        assert!(courier.sent.borrow().is_empty());
        change_password(&mut pam, &courier, true);
        assert_eq!(
            *courier.sent.borrow(),
            [Request::ChangePassword {
                old: Password::new(b"old"),
                new: Password::new(b"new"),
            }]
        );
        // Root setting another user's password: no old one, nothing sent.
        let mut pam = FakePam {
            authtok: Some("new"),
            ..Default::default()
        };
        let courier = FakeCourier::new(true);
        change_password(&mut pam, &courier, true);
        assert!(courier.sent.borrow().is_empty());
    }

    /// A delivery at auth that does not work (a stale socket, a busy
    /// daemon) is tried again at session open.
    #[test]
    fn a_failed_delivery_at_auth_is_tried_again_at_session_open() {
        let mut pam = FakePam {
            authtok: Some("pw"),
            ..Default::default()
        };
        let mut courier = FakeCourier::new(true);
        courier.answer = Outcome::TimedOut;
        authenticate(&mut pam, &courier);
        assert!(pam.kept.is_some());
        courier.answer = Outcome::Accepted;
        open_session(&mut pam, &courier);
        assert_eq!(*courier.sent.borrow(), [unlock("pw"), unlock("pw")]);
    }

    #[test]
    fn failures_are_logged_without_the_password() {
        let mut pam = FakePam {
            authtok: Some("hunter2"),
            ..Default::default()
        };
        let mut courier = FakeCourier::new(true);
        courier.answer = Outcome::Unreachable;
        authenticate(&mut pam, &courier);
        let logs = pam.logs.borrow();
        assert!(logs.iter().any(|l| l.contains("Unreachable")), "{logs:?}");
        assert!(!logs.iter().any(|l| l.contains("hunter2")));
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p pam_aleph -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 29 passed | ok. 3 passed | ok. 47 passed | ok. 1 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed | ok. 6 passed | ok. 6 passed | ok. 3 passed | ok. 1 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **auth delivers at once when the daemon is up** (`crates/pam_aleph/src/module.rs`), test `cargo test -p pam_aleph --lib with_the_daemon_up`: replace `if courier.ready(&user) {` with `if false {`.
- **a password change needs both passwords** (`crates/pam_aleph/src/module.rs`), test `cargo test -p pam_aleph --lib a_password_change_is_sent_once`:

  replace

  ```rust
  if !update {
      return;
  }
  ```

  with

  ```rust
  // (nothing)
  ```

- **a failed delivery at auth is kept for session open** (`crates/pam_aleph/src/module.rs`), test `cargo test -p pam_aleph --lib a_failed_delivery_at_auth`: replace `if send(pam, courier, &user, &request, "unlock") == Outcome::Accepted {` with `if true {`.
- **the child closes the host's descriptors** (`crates/pam_aleph/src/deliver.rs`), test `cargo test -p pam_aleph --test deliver the_child_does_not_keep`:

  replace

  ```rust
  if reporter > 3 {
      libc::syscall(libc::SYS_close_range, 3u32, (reporter - 1) as u32, 0u32);
  }
  libc::syscall(libc::SYS_close_range, (reporter + 1) as u32, u32::MAX, 0u32);
  ```

  with

  ```rust
  // (nothing)
  ```

- **another user cannot be impersonated** (`crates/pam_aleph/src/deliver.rs`), test `cargo test -p pam_aleph --test deliver another_user`: replace `if libc::getuid() != target.uid || libc::geteuid() != target.uid {` with `if false {`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/pam_aleph crates/aleph-daemon
git commit -m "feat(pam): the pam_aleph module" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 6: lock policy

**Interfaces:**
- Consumes: Task 3 (keyring), Task 4 (`testing::daemon_with`).
- Produces: `lockpolicy::{watch_logind(Connection, Arc<SecretService>, Arc<Mutex<Config>>) -> zbus::Result<()>, lock_when_idle(Arc<Keyring>, Arc<SecretService>, Arc<Mutex<Config>>)}`; `Keyring::idle_for() -> Duration`; `testing::Logind { start, sleep, lock_session, inhibitors, released }`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-daemon/src/lib.rs`:

```rust
//! `alephd`, the aleph keyring daemon (spec §6).

pub mod admin;
pub mod config;
pub mod daemon;
pub mod error;
pub mod keyring;
pub mod lockpolicy;
pub mod pamsock;
pub mod password;
pub mod paths;
pub mod prompt;
pub mod secret;
pub mod state;
pub mod store;

#[cfg(feature = "testing")]
pub mod testing;

pub use error::{Error, Result};
```

Create `crates/aleph-daemon/src/lockpolicy.rs` containing only `// implemented in step 3`.

Write `crates/aleph-daemon/tests/lock_policy.rs`:

```rust
//! The lock policy against a stand-in logind (sleep, screen lock) and the
//! idle timer, with the real daemon.

use std::sync::Mutex;
use std::time::Duration;

use aleph_daemon::config::Config;
use aleph_daemon::testing::*;

/// Wait up to `secs` for `cond`.
async fn eventually(secs: u64, cond: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cond()
}

/// An unlocked daemon following the stand-in logind with `config`, and the
/// unique name of its connection to the (stand-in) system bus.
async fn following(config: Config) -> (Daemon, Logind, Arc<Mutex<Config>>, String) {
    let d = daemon(true, vec![]).await;
    let logind = Logind::start(&d.bus.address).await;
    let config = Arc::new(Mutex::new(config));
    let system = zbus::connection::Builder::address(d.bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let name = system.unique_name().unwrap().to_string();
    tokio::spawn(aleph_daemon::lockpolicy::watch_logind(
        system,
        d.secrets.clone(),
        config.clone(),
    ));
    assert!(eventually(5, || logind.inhibitors() == 1).await);
    assert!(!d.keyring.is_locked());
    (d, logind, config, name)
}

/// Before sleep the vault locks, and only then is the inhibitor released;
/// on resume a new one is taken.
#[tokio::test(flavor = "multi_thread")]
async fn sleep_locks_first_then_lets_the_sleep_go() {
    let (d, logind, _, _) = following(Config::default()).await;
    assert!(!logind.released(0));
    logind.sleep(true).await;
    assert!(eventually(5, || logind.released(0)).await);
    assert!(d.keyring.is_locked());
    logind.sleep(false).await;
    assert!(eventually(5, || logind.inhibitors() == 2).await);
    assert!(!logind.released(1));
}

/// With `on_suspend` off the vault stays unlocked, and the sleep is still
/// let go.
#[tokio::test(flavor = "multi_thread")]
async fn with_on_suspend_off_sleep_does_not_lock() {
    let mut config = Config::default();
    config.lock.on_suspend = false;
    let (d, logind, _, _) = following(config).await;
    logind.sleep(true).await;
    assert!(eventually(5, || logind.released(0)).await);
    assert!(!d.keyring.is_locked());
}

/// Locking this user's session locks the vault; another user's does not,
/// and neither does anything with `on_screen_lock` off.
#[tokio::test(flavor = "multi_thread")]
async fn a_screen_lock_of_this_user_locks() {
    let (d, logind, config, _) = following(Config::default()).await;
    logind.lock_session("other").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!d.keyring.is_locked());
    config.lock().unwrap().lock.on_screen_lock = false;
    logind.lock_session("mine").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!d.keyring.is_locked());
    config.lock().unwrap().lock.on_screen_lock = true;
    logind.lock_session("mine").await;
    assert!(eventually(5, || d.keyring.is_locked()).await);
}

/// A `Session.Lock` from anyone but logind (any peer can send a directed
/// signal) is ignored.
#[tokio::test(flavor = "multi_thread")]
async fn a_spoofed_screen_lock_is_ignored() {
    let (d, logind, _, watcher) = following(Config::default()).await;
    let spoofer = zbus::connection::Builder::address(d.bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    spoofer
        .emit_signal(
            Some(watcher.as_str()),
            "/org/freedesktop/login1/session/mine",
            "org.freedesktop.login1.Session",
            "Lock",
            &(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!d.keyring.is_locked());
    logind.lock_session("mine").await;
    assert!(eventually(5, || d.keyring.is_locked()).await);
}

/// With an idle timeout, the vault locks once nothing has read or written
/// a secret for that long, and not while it is in use.
#[tokio::test(flavor = "multi_thread")]
async fn an_idle_vault_locks() {
    let d = daemon(true, vec![]).await;
    let mut config = Config::default();
    config.lock.idle_timeout = 1;
    tokio::spawn(aleph_daemon::lockpolicy::lock_when_idle(
        d.keyring.clone(),
        d.secrets.clone(),
        Arc::new(Mutex::new(config)),
    ));
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        d.keyring.read(|_| ()).unwrap();
        assert!(!d.keyring.is_locked());
    }
    assert!(eventually(4, || d.keyring.is_locked()).await);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon`
Expected: the build fails because the items the tests use do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-daemon/src/lockpolicy.rs`:

```rust
//! Lock policy (spec §6 "Lock policy"), from `[lock]` in `config.toml`,
//! read at each event so changes apply at once.
//!
//! - **Sleep** (`on_suspend`): while running, `alephd` holds a logind
//!   `delay` inhibitor for `sleep`. On `PrepareForSleep(true)` it locks,
//!   then releases the inhibitor so the sleep can go ahead; on resume it
//!   takes a new one. logind does not say which sleep is coming, and
//!   suspend-then-hibernate moves on to hibernating without telling
//!   anyone, so `on_suspend` covers hibernation too.
//! - **Screen lock** (`on_screen_lock`): logind's `Session.Lock` signal
//!   (`loginctl lock-session`, which hypridle sends) for a session of this
//!   user. Only a signal whose sender is logind itself counts: any peer can
//!   send a directed signal, and a match rule cannot check a well-known
//!   sender on the receiving side.
//! - **Idle** (`idle_timeout`): no secret read or written for that many
//!   seconds.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;

use crate::config::Config;
use crate::keyring::Keyring;
use crate::secret::service::SecretService;

const LOGIN1: &str = "org.freedesktop.login1";

/// Follow logind on `system` (the system bus) until it goes away.
pub async fn watch_logind(
    system: Connection,
    secrets: Arc<SecretService>,
    config: Arc<Mutex<Config>>,
) -> zbus::Result<()> {
    let manager = zbus::Proxy::new(
        &system,
        LOGIN1,
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await?;
    let mut sleeps = manager.receive_signal("PrepareForSleep").await?;
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(LOGIN1)?
        .interface("org.freedesktop.login1.Session")?
        .member("Lock")?
        .path_namespace("/org/freedesktop/login1/session")?
        .build();
    let mut locks = zbus::MessageStream::for_match_rule(rule, &system, None).await?;
    let dbus = zbus::fdo::DBusProxy::new(&system).await?;
    let mut inhibitor = Some(inhibit(&manager).await?);
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    loop {
        tokio::select! {
            Some(msg) = sleeps.next() => {
                let (starting,): (bool,) = msg.body().deserialize()?;
                if starting {
                    if config.lock().unwrap().lock.on_suspend {
                        if let Err(e) = secrets.lock().await {
                            tracing::error!("could not lock before sleep: {e}");
                        }
                        tracing::info!("locked before sleep");
                    }
                    // Done: let the sleep go ahead.
                    inhibitor = None;
                } else if inhibitor.is_none() {
                    inhibitor = inhibit(&manager).await.ok();
                }
            }
            Some(Ok(msg)) = locks.next() => {
                if !config.lock().unwrap().lock.on_screen_lock {
                    continue;
                }
                let Some(path) = msg.header().path().map(|p| OwnedObjectPath::from(p.to_owned())) else {
                    continue;
                };
                if !from_logind(&dbus, &msg).await {
                    tracing::warn!("ignored a Session.Lock that did not come from logind");
                    continue;
                }
                if session_uid(&system, path).await == Some(uid) {
                    if let Err(e) = secrets.lock().await {
                        tracing::error!("could not lock with the screen: {e}");
                    }
                    tracing::info!("locked with the screen");
                }
            }
            else => return Ok(()),
        }
    }
}

/// Whether `msg` was sent by the current owner of logind's name.
async fn from_logind(dbus: &zbus::fdo::DBusProxy<'_>, msg: &zbus::Message) -> bool {
    let Ok(name) = zbus::names::BusName::try_from(LOGIN1) else {
        return false;
    };
    match (dbus.get_name_owner(name).await, msg.header().sender()) {
        (Ok(owner), Some(sender)) => owner.as_str() == sender.as_str(),
        _ => false,
    }
}

/// A `delay` inhibitor for sleep: sleep waits until it is closed.
async fn inhibit(manager: &zbus::Proxy<'_>) -> zbus::Result<zbus::zvariant::OwnedFd> {
    manager
        .call(
            "Inhibit",
            &("sleep", "aleph", "Lock the keyring before sleep", "delay"),
        )
        .await
}

/// The uid owning the logind session at `path`.
async fn session_uid(system: &Connection, path: OwnedObjectPath) -> Option<u32> {
    let session = zbus::Proxy::new(system, LOGIN1, path, "org.freedesktop.login1.Session")
        .await
        .ok()?;
    let (uid, _): (u32, OwnedObjectPath) = session.get_property("User").await.ok()?;
    Some(uid)
}

/// Lock after `lock.idle_timeout` seconds without secret access.
pub async fn lock_when_idle(
    keyring: Arc<Keyring>,
    secrets: Arc<SecretService>,
    config: Arc<Mutex<Config>>,
) {
    loop {
        let timeout = config.lock().unwrap().lock.idle_timeout;
        // Check often enough for the timeout, and at least twice a minute
        // (a changed setting applies by then).
        let every = if timeout == 0 {
            30
        } else {
            timeout.clamp(1, 30)
        };
        tokio::time::sleep(Duration::from_secs(every)).await;
        if timeout > 0 && !keyring.is_locked() && keyring.idle_for() >= Duration::from_secs(timeout)
        {
            if let Err(e) = secrets.lock().await {
                tracing::error!("could not lock when idle: {e}");
            }
            tracing::info!("locked after {timeout} s without use");
        }
    }
}
```

Apply this patch with `git apply` (save it as `/tmp/t6-impl.patch`):

```diff
--- a/crates/aleph-daemon/src/keyring.rs
+++ b/crates/aleph-daemon/src/keyring.rs
@@ -150,6 +150,8 @@
     pub argon2: Argon2Params,
     /// How long to wait for a FIDO2 key to be plugged in.
     pub key_wait: Duration,
+    /// When the body was last read or written (for the idle lock).
+    last_access: Mutex<Instant>,
 }
 
 fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
@@ -179,11 +181,18 @@
             ops: Mutex::new(()),
             argon2: Argon2Params::LOGIN_PASSWORD_FLOOR,
             key_wait: Duration::from_secs(120),
+            last_access: Mutex::new(Instant::now()),
         }
     }
 
     pub fn is_locked(&self) -> bool {
         lock(&self.inner).vault.is_none()
+    }
+
+    /// How long since the body was last read or written, or the vault
+    /// unlocked (`lock.idle_timeout`).
+    pub fn idle_for(&self) -> Duration {
+        lock(&self.last_access).elapsed()
     }
 
     pub fn status(&self) -> Result<Status> {
@@ -243,6 +252,7 @@
     /// Read the unlocked body.
     pub fn read<T>(&self, f: impl FnOnce(&Body) -> T) -> Result<T> {
         let inner = lock(&self.inner);
+        *lock(&self.last_access) = Instant::now();
         inner
             .vault
             .as_ref()
@@ -254,6 +264,7 @@
     /// in-memory body is restored, so memory never runs ahead of the file.
     pub fn modify<T>(&self, f: impl FnOnce(&mut Body) -> Result<T>) -> Result<T> {
         let mut inner = lock(&self.inner);
+        *lock(&self.last_access) = Instant::now();
         let Inner {
             store,
             vault,
@@ -825,6 +836,7 @@
         inner.state.retain(|id| ids.contains(&id))?;
         inner.vault = Some(vault);
         inner.untrusted = untrusted;
+        *lock(&self.last_access) = Instant::now();
         Ok(untrusted.map(|why| Error::Untrusted(why).to_string()))
     }
 
--- a/crates/aleph-daemon/src/config.rs
+++ b/crates/aleph-daemon/src/config.rs
@@ -19,7 +19,8 @@
 #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
 #[serde(deny_unknown_fields, default)]
 pub struct LockConfig {
-    /// Lock on suspend (hibernate always locks).
+    /// Lock before sleep: suspend and hibernate alike (logind does not say
+    /// which is coming). Off, the master key can reach a hibernation image.
     pub on_suspend: bool,
     /// Lock when the session is locked (logind `Session.Lock`).
     pub on_screen_lock: bool,
--- a/crates/aleph-daemon/src/main.rs
+++ b/crates/aleph-daemon/src/main.rs
@@ -56,10 +56,31 @@
             format!("cannot own {SECRETS_NAME} on the session bus (is gnome-keyring still running?): {e}")
         })?;
     let pam_socket = paths.pam_socket();
-    let secrets = aleph_daemon::daemon::serve(&conn, keyring.clone(), launcher, config, paths)
-        .await
-        .map_err(|e| e.to_string())?;
+    let secrets =
+        aleph_daemon::daemon::serve(&conn, keyring.clone(), launcher, config.clone(), paths)
+            .await
+            .map_err(|e| e.to_string())?;
     tracing::info!("serving {SECRETS_NAME} and {BUS_NAME}");
+    // The lock policy: logind (sleep, screen lock) on the system bus, and
+    // the idle timer. Without logind the rest still works.
+    match zbus::Connection::system().await {
+        Ok(system) => {
+            let (secrets, config) = (secrets.clone(), config.clone());
+            tokio::spawn(async move {
+                if let Err(e) =
+                    aleph_daemon::lockpolicy::watch_logind(system, secrets, config).await
+                {
+                    tracing::warn!("not following logind (no lock on sleep or screen lock): {e}");
+                }
+            });
+        }
+        Err(e) => tracing::warn!("no system bus (no lock on sleep or screen lock): {e}"),
+    }
+    tokio::spawn(aleph_daemon::lockpolicy::lock_when_idle(
+        keyring.clone(),
+        secrets.clone(),
+        config,
+    ));
     // Login unlock needs pam.sock; without it the rest still works.
     match aleph_daemon::pamsock::listener(&pam_socket) {
         Ok(listener) => {
--- a/crates/aleph-daemon/src/testing.rs
+++ b/crates/aleph-daemon/src/testing.rs
@@ -395,3 +395,127 @@
         env,
     }
 }
+
+/// A stand-in for logind on a test bus: it hands out sleep inhibitors
+/// (keeping the far end of each, to see when it is released) and sends
+/// `PrepareForSleep` and `Session.Lock` when told. It serves two sessions:
+/// `mine` (this user's) and `other` (another uid's).
+pub struct Logind {
+    pub conn: zbus::Connection,
+    inhibitors: Arc<std::sync::Mutex<Vec<std::os::unix::net::UnixStream>>>,
+}
+
+struct LogindManager {
+    inhibitors: Arc<std::sync::Mutex<Vec<std::os::unix::net::UnixStream>>>,
+}
+
+#[zbus::interface(name = "org.freedesktop.login1.Manager")]
+impl LogindManager {
+    fn inhibit(
+        &self,
+        what: String,
+        _who: String,
+        _why: String,
+        mode: String,
+    ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
+        if (what.as_str(), mode.as_str()) != ("sleep", "delay") {
+            return Err(zbus::fdo::Error::InvalidArgs(format!("{what}/{mode}")));
+        }
+        let (ours, theirs) = std::os::unix::net::UnixStream::pair()
+            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
+        self.inhibitors.lock().unwrap().push(ours);
+        Ok(std::os::fd::OwnedFd::from(theirs).into())
+    }
+
+    #[zbus(signal)]
+    async fn prepare_for_sleep(
+        emitter: &zbus::object_server::SignalEmitter<'_>,
+        start: bool,
+    ) -> zbus::Result<()>;
+}
+
+struct LogindSession {
+    uid: u32,
+}
+
+#[zbus::interface(name = "org.freedesktop.login1.Session")]
+impl LogindSession {
+    #[zbus(property)]
+    fn user(&self) -> (u32, zbus::zvariant::OwnedObjectPath) {
+        (
+            self.uid,
+            zbus::zvariant::OwnedObjectPath::try_from(format!(
+                "/org/freedesktop/login1/user/_{}",
+                self.uid
+            ))
+            .unwrap(),
+        )
+    }
+
+    #[zbus(signal)]
+    async fn lock(emitter: &zbus::object_server::SignalEmitter<'_>) -> zbus::Result<()>;
+}
+
+const LOGIND_PATH: &str = "/org/freedesktop/login1";
+
+impl Logind {
+    pub async fn start(address: &str) -> Self {
+        let inhibitors = Arc::new(std::sync::Mutex::new(Vec::new()));
+        // SAFETY: getuid cannot fail.
+        let me = unsafe { libc::getuid() };
+        let conn = zbus::connection::Builder::address(address)
+            .unwrap()
+            .name("org.freedesktop.login1")
+            .unwrap()
+            .serve_at(
+                LOGIND_PATH,
+                LogindManager {
+                    inhibitors: inhibitors.clone(),
+                },
+            )
+            .unwrap()
+            .serve_at(
+                "/org/freedesktop/login1/session/mine",
+                LogindSession { uid: me },
+            )
+            .unwrap()
+            .serve_at(
+                "/org/freedesktop/login1/session/other",
+                LogindSession { uid: me + 1 },
+            )
+            .unwrap()
+            .build()
+            .await
+            .unwrap();
+        Self { conn, inhibitors }
+    }
+
+    /// Send `PrepareForSleep(start)`.
+    pub async fn sleep(&self, start: bool) {
+        let emitter = zbus::object_server::SignalEmitter::new(&self.conn, LOGIND_PATH).unwrap();
+        LogindManager::prepare_for_sleep(&emitter, start)
+            .await
+            .unwrap();
+    }
+
+    /// Send `Session.Lock` from the session `mine` or `other`.
+    pub async fn lock_session(&self, session: &str) {
+        let path = format!("/org/freedesktop/login1/session/{session}");
+        let emitter = zbus::object_server::SignalEmitter::new(&self.conn, path).unwrap();
+        LogindSession::lock(&emitter).await.unwrap();
+    }
+
+    /// Inhibitors handed out so far.
+    pub fn inhibitors(&self) -> usize {
+        self.inhibitors.lock().unwrap().len()
+    }
+
+    /// Whether the `n`th inhibitor has been released (its holder closed it).
+    pub fn released(&self, n: usize) -> bool {
+        use std::io::Read;
+        let mut list = self.inhibitors.lock().unwrap();
+        let s = &mut list[n];
+        s.set_nonblocking(true).unwrap();
+        matches!(s.read(&mut [0u8; 1]), Ok(0))
+    }
+}
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -316,6 +316,12 @@
         }
         Cmd::Config(ConfigCmd::Get { key }) => println!("{}", c.get_config(&key).await?),
         Cmd::Config(ConfigCmd::Set { key, value }) => {
+            if key == "lock.on_suspend" && value == "false" {
+                eprintln!(
+                    "aleph: warning: the keyring will stay unlocked through suspend and hibernation; \
+                     the master key can then be written to a hibernation image (keep swap encrypted)"
+                );
+            }
             outcome(c.converse("SetConfig", Args::Str2(&key, &value)).await?)?;
         }
     }
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon -p aleph-cli && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 8 passed | ok. 29 passed | ok. 3 passed | ok. 47 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **reads keep an idle vault open** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test lock_policy an_idle_vault_locks`:

  replace

  ```rust
  let inner = lock(&self.inner);
  *lock(&self.last_access) = Instant::now();
  ```

  with

  ```rust
  let inner = lock(&self.inner);
  ```

- **sleep locks only with on_suspend** (`crates/aleph-daemon/src/lockpolicy.rs`), test `cargo test -p aleph-daemon --test lock_policy with_on_suspend_off`: replace `if config.lock().unwrap().lock.on_suspend {` with `if true {`.
- **the inhibitor is released for the sleep** (`crates/aleph-daemon/src/lockpolicy.rs`), test `cargo test -p aleph-daemon --test lock_policy sleep_locks_first`:

  replace

  ```rust
  inhibitor = None;
  ```

  with

  ```rust
  // (nothing)
  ```

- **only logind's screen lock counts** (`crates/aleph-daemon/src/lockpolicy.rs`), test `cargo test -p aleph-daemon --test lock_policy a_spoofed_screen_lock_is_ignored`: replace `if !from_logind(&dbus, &msg).await {` with `if false {`.
- **only this user's screen lock locks** (`crates/aleph-daemon/src/lockpolicy.rs`), test `cargo test -p aleph-daemon --test lock_policy a_screen_lock_of_this_user_locks`: replace `if session_uid(&system, path).await == Some(uid) {` with `if session_uid(&system, path).await.is_some() {`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-daemon crates/aleph-cli
git commit -m "feat(daemon): lock on sleep, screen lock, and idle" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 7: spec, docs, decisions

**Interfaces:**
- Consumes: everything above (documentation only).

- [ ] **Step 1: Update the documents**

Apply this patch with `git apply` (save it as `/tmp/t7-docs.patch`):

~~~~diff
--- a/docs/superpowers/specs/2026-09-26-aleph-design.md
+++ b/docs/superpowers/specs/2026-09-26-aleph-design.md
@@ -136,8 +136,9 @@
 | `aleph-tpmd` | bin | TPM helper: seal and unseal per uid, SRK verification, rate limiting, `Status`. | `aleph-tpm-proto`, `tss-esapi` |
 | `aleph-unlock` | lib | Produces a KEK per hardware keyslot: the TPM client (talks to `aleph-tpmd`) and FIDO2 (`Authenticator` trait, `libfido2` backend, mock). | `aleph-core`, `aleph-tpm-proto`, `fido2-rs` |
 | `aleph-prompt-proto` | lib | The prompter protocol (newline-delimited JSON) shared by `alephd`, the CLI's terminal prompter, and `aleph-gui`. | `serde`, `zeroize` |
-| `aleph-daemon` (bin `alephd`) | bin | Secret Service and admin D-Bus interfaces, PAM socket, lock policy, prompter orchestration. | `aleph-core`, `aleph-unlock`, `aleph-prompt-proto`, `zbus`, `tokio`, `tracing`, `tracing-journald`, libpam |
-| `pam_aleph` | cdylib | PAM module: forwards passwords to `alephd` after dropping to the user's uid. Minimal, no async runtime. | PAM FFI, std |
+| `aleph-pam-proto` | lib | The `pam.sock` protocol between `pam_aleph` and `alephd`: length-prefixed binary frames, strict decoding, a reply check that does not allocate. | `zeroize` |
+| `aleph-daemon` (bin `alephd`) | bin | Secret Service and admin D-Bus interfaces, PAM socket, lock policy, prompter orchestration. | `aleph-core`, `aleph-unlock`, `aleph-prompt-proto`, `aleph-pam-proto`, `zbus`, `tokio`, `tracing`, `tracing-journald`, libpam |
+| `pam_aleph` | cdylib | PAM module: forwards passwords to `alephd` after dropping to the user's uid. Minimal, no async runtime. | `aleph-pam-proto`, PAM FFI, `libc` |
 | `aleph-cli` (bin `aleph`) | bin | CLI. | `aleph-prompt-proto`, `zbus`, `clap` |
 | `aleph-gui` | bin | egui manager and prompter. | `eframe`, `egui`, `zbus`, `notify`, Wayland clipboard crate |
 
@@ -307,8 +308,8 @@
   needed.
 - **The TPM and login-password slots:** unsealed or derived with the login
   password. The password comes from the re-authentication that every
-  rotating operation requires (§6), or from `pam_aleph` during a password
-  change. It is zeroized once the rotation completes.
+  rotating operation requires (§6). It is zeroized once the rotation
+  completes. (A password change replaces these slots instead: §5.)
 - **Each FIDO2 slot:** needs that key's touch. The prompter walks through
   them in turn.
 
@@ -506,8 +507,10 @@
     (no `/etc/pam.d/aleph-check`, or an account `pam_unix` cannot verify),
     the TPM slots are skipped rather than risked, while login-password
     slots are still tried; TPM slots therefore need `pam_unix` accounts.
-    Passwords from `pam_aleph` were accepted by the login stack and skip
-    the check.
+    Passwords from `pam_aleph` were accepted by the login stack, but are
+    checked too whenever PAM can check, so a wrong one sent to `pam.sock`
+    by any same-user process never reaches the TPM or marks a slot stale.
+    Only when PAM cannot check is the login stack trusted.
   - **TPM slots are tried newest first.** Once one rejects a password PAM
     accepted, it and every older TPM slot are marked stale without being
     tried, so a changed password costs one failed attempt, not one per
@@ -526,17 +529,39 @@
     offers to set it to a random value that is printed for the user to
     record. This is opt-in, never the default, because losing it means the
     lockout counter can only be reset by waiting.
-- **Password change:** when `pam_aleph` passes the old and new passwords,
-  `alephd`:
-  1. unseals the slot with the old password
-  2. seals a **new** KEK under the new password
-  3. rotates MK
-  4. removes the old slot
+- **Password change:** `pam_aleph` passes the old and new passwords from
+  `passwd`. It runs even when `pam_unix` failed to make the change, so
+  `alephd` acts only on a new password PAM accepts (or when PAM cannot
+  check). It then replaces every password slot: one **new** TPM slot
+  sealed under the new password (with a fresh KEK) replaces the TPM slots,
+  and one new login-password slot replaces any login-password slot.
+  - If every other slot is a recovery slot, MK rotates, so the old
+    password and old blobs open nothing written from then on.
+  - FIDO2 slots need a touch, which `passwd` cannot give. In that case
+    the old slots are removed keeping MK, and a **pending rotation** is
+    recorded. `aleph status` and every unlock say so until a rotation is
+    run (`aleph keyslot rotate-master`, which needs the keys). Until then,
+    an old copy of the file, plus the old password, plus this machine's
+    TPM, still yields an MK that opens newer files.
+  - A locked vault is never unlocked for this: a copy is opened with the
+    old password, changed, checked against the high-water mark, and
+    written.
 
   There is no `ObjectChangeAuth`, because the old private blob would stay
-  loadable with the old password on this TPM indefinitely. If the password
-  was changed out of band, the slot goes `stale`. The prompter then asks
-  for the old password, or offers FIDO2, and re-seals.
+  loadable with the old password on this TPM indefinitely.
+- **Out-of-band change:** if the password was changed without `pam_aleph`,
+  the next typed password PAM accepts opens no TPM slot (every one is
+  stale, or the newest rejects it with `AuthFailed`). The prompter then
+  asks for the previous password (`OldPassword`).
+  - It is tried only on the newest TPM slot, straight at the TPM (PAM no
+    longer knows it), at most twice per conversation, each counted by the
+    typing limit.
+  - Declining the question returns to the choice of method, where a FIDO2
+    touch also works.
+  - Either way, once the vault is open the password slots are replaced
+    under the current password, as for a password change.
+  - A `WrongUser` refusal does not lead to the question, since the
+    previous password cannot fix it.
 
 ### FIDO2 (libfido2 via `fido2-rs`)
 
@@ -652,44 +677,80 @@
 
 Verified against a stock Omarchy install on 2026-09-26.
 
-- **The shared substack.** aleph installs `/etc/pam.d/aleph`:
+- **The lines.** aleph's lines go straight into each service, each with
+  a `-` prefix, so a missing module is silently skipped (an `include` of a
+  missing substack file could make the whole service fail; DECISIONS.md
+  E4):
 
   ```
-  auth      optional  pam_aleph.so
-  password  optional  pam_aleph.so
-  session   optional  pam_aleph.so
+  -auth      optional  pam_aleph.so
+  -session   optional  pam_aleph.so
+  -password  optional  pam_aleph.so
   ```
 
-- **Which services include it**, with setup editing each and keeping a
-  backup:
+- **Which services get them**, with setup editing each and keeping a
+  backup (Plan 4b; by hand until then, `docs/testing.md`):
 
   | Service | Change |
   |---|---|
-  | `/etc/pam.d/sddm` (graphical login) | Replace the `pam_gnome_keyring` lines with `auth include aleph` after `auth include system-login`, and `session include aleph` after `session include system-login`. |
-  | `/etc/pam.d/omarchy-lock-password` (hyprlock) | Add `auth include aleph` at the very end, after `pam_faillock authsucc`, so it only ever sees a password `pam_unix` has accepted. |
-  | `/etc/pam.d/passwd` | Add `password include aleph` after `password include system-auth`, so that `passwd` changes reach aleph. |
-  | `system-login` and `system-remote-login` | **Not edited.** An SSH login must not unlock the desktop vault. |
-  | `sddm-autologin` | **Not edited.** It has no password, so first-use mode applies. |
+  | `/etc/pam.d/sddm` (graphical login) | Remove the `pam_gnome_keyring` lines; add `-auth optional pam_aleph.so` after `auth include system-login`, and `-session optional pam_aleph.so` after `session include system-login`. |
+  | `/etc/pam.d/omarchy-lock-password` (hyprlock) | Add `-auth optional pam_aleph.so` at the very end, after `pam_faillock authsucc`, so it only ever sees a password `pam_unix` has accepted. |
+  | `/etc/pam.d/passwd` | Add `-password optional pam_aleph.so` after `password include system-auth`, so that `passwd` changes reach aleph (`pam_gnome_keyring` stays, so a later revert still unlocks gnome-keyring at login). |
+  | `system-login`, `system-auth`, `system-local-login`, `system-remote-login`, `login` | **Never edited.** An SSH login must not unlock the desktop vault, and a TTY login stays the escape hatch. |
+  | `sddm-autologin` | Only its `pam_gnome_keyring` lines are removed (they would start gnome-keyring directly); nothing is added: it has no password, so first-use mode applies. |
 
 - **Placement:** in every service, `pam_aleph` comes after the
   `pam_unix`/`pam_faillock` success path. A mistyped password never
   reaches aleph, and never costs a TPM dictionary-attack attempt.
 - **Handing over the password:**
   - `pam_aleph` stores the password with `pam_set_data`, using a cleanup
-    that zeroizes it.
+    that zeroizes it, when it cannot deliver it at once.
   - To deliver it, the module forks a child that drops to the target
-    user's uid and gid (`setgroups`/`setgid`/`setuid`, as
-    `pam_gnome_keyring` does) and connects to `pam.sock`. The parent waits,
-    with a 5-second limit.
+    user's uid and gid (`setgroups`/`setgid`/`setuid`, only when running
+    as root, as `pam_gnome_keyring` does) and connects to
+    `/run/user/<uid>/aleph/pam.sock`.
+  - The host may be multithreaded, so the child calls only
+    async-signal-safe functions on data prepared before the fork. It
+    closes every descriptor it inherited but its report pipe, sends with
+    `MSG_NOSIGNAL`, and has an `alarm` backstop (with `SIGALRM` reset to
+    its default and unblocked).
+  - The child reports its result as one byte on a pipe. The parent waits
+    on the pipe with a 5-second limit, kills the child through a pidfd,
+    and reaps it through the pidfd. The host's `SIGCHLD` handling is never
+    touched.
   - `alephd` checks `SO_PEERCRED` against its own uid.
+  - The wire format is `aleph-pam-proto` (§3). A `socket=<path>` module
+    argument replaces the socket path; it exists for tests.
 - **When it sends:**
-  - login sends at `session` open, once the user's systemd instance is up
-  - the lock screen sends during `auth`
-  - `passwd` sends the old and new passwords during `password`
+  - `auth` sends at once if `pam.sock` exists (the lock screen, or a
+    second login; on a second login the vault then unlocks before the
+    `account` and `session` stacks run, which is harmless: it is the
+    user's own vault and the password was right). Otherwise, or if that
+    delivery fails, it keeps the password for `session` open, once the
+    user's systemd instance is up.
+  - `passwd` sends the old and new passwords in the update phase, only
+    when both are known (root setting another user's password supplies no
+    old one, and nothing is sent).
+  - It never prompts: without a password it does nothing.
+- **Listening:** `alephd.socket` owns `pam.sock` (`FileDescriptorName=pam`);
+  `alephd` takes that descriptor by name, or binds the socket itself when
+  not socket-activated (never replacing a socket something still serves).
+  A login password opens the vault at once, even while a prompter
+  conversation is open, including a security key's PIN question (the
+  hardware is not held while the prompter is asked). Whichever opens
+  first is kept; an open that finishes after the vault was unlocked,
+  written, and locked again reopens the current file rather than
+  installing its older copy. A password change waits its turn, but a new
+  password PAM rejects is refused before waiting, and when PAM cannot
+  vouch for the new password the old one must open the vault file
+  first.
 - **Never blocks login:** every failure is logged and returns
   `PAM_IGNORE`.
-- **Rate limiting:** `pam.sock` accepts at most 5 failed passwords per
-  minute, which bounds same-user guessing through the socket.
+- **Rate limiting:** `pam.sock` accepts at most 5 rejected passwords per
+  minute, which bounds same-user guessing through the socket. Refusals
+  that say nothing about the password (a busy or rate-limited TPM) do not
+  count. Requests still being answered count too, so parallel connections
+  cannot get past the limit, and at most 5 are in flight at once.
 
 ### Secret Service
 
@@ -712,7 +773,7 @@
   whether MK is `mlock`ed, TPM usability, keyslots with stale marks),
   `Lock`, `Unlock`, `Create`, `EnrollTpm`, `EnrollFido2`,
   `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`, `RetryKeyslot`,
-  `GetConfig`, `SetConfig`, and (Plan 4) `ImportGnomeKeyring`,
+  `GetConfig`, `SetConfig`, and (Plan 4b) `ImportGnomeKeyring`,
   `ExportToGnomeKeyring`, `Backup`, `Restore`.
 - **Methods that need the user take a prompter:** one end of a
   socketpair, passed as a Unix fd, speaking the prompter protocol. The
@@ -739,7 +800,7 @@
 
 ```toml
 [lock]
-on_suspend = true        # logind PrepareForSleep(true), with a delay inhibitor
+on_suspend = true        # every sleep, suspend or hibernate: logind PrepareForSleep(true), with a delay inhibitor
 on_screen_lock = true    # logind Session.Lock (hypridle → loginctl lock-session)
 idle_timeout = 0         # seconds without secret access; 0 = disabled
 # setting everything false/0 = lock only at logout
@@ -747,12 +808,22 @@
 
 - **Suspend and hibernate:** `alephd` holds a logind `delay` inhibitor for
   `sleep` while running.
-  1. On `PrepareForSleep(true)` it locks and zeroizes.
+  1. On `PrepareForSleep(true)` it locks and zeroizes (if `on_suspend`).
   2. Then it releases the inhibitor.
   3. On resume it takes the inhibitor again.
 
-  Hibernate is treated the same way, regardless of `on_suspend`, because
-  the hibernation image is written to disk.
+  logind does not say whether a suspend or a hibernation is coming, and
+  suspend-then-hibernate moves on to hibernating without another signal.
+  So `on_suspend` covers both. With it off, the master key can reach a
+  hibernation image, and `aleph config set lock.on_suspend false` warns
+  about this (swap must be encrypted, §4).
+- **Screen lock:** logind's `Session.Lock` for a session of this user
+  (`loginctl lock-session`, which hypridle sends), sent by logind itself
+  (the sender is checked against the name's owner: any peer can send a
+  directed signal).
+- **Idle:** no secret read or written for `idle_timeout` seconds.
+- Without a system bus or logind, `alephd` runs without the sleep and
+  screen-lock parts.
 
 ### Prompter orchestration
 
@@ -819,7 +890,7 @@
   6. system changes (sudo)
 
   Plan 3 implements steps 1, 2, and 4 (creating the vault) and says that
-  the rest is not available yet; Plan 4 adds 3, 5, and 6.
+  the rest is not available yet; Plan 4b adds 3, 5, and 6.
 - **Import** reads every collection and item through the Secret Service
   API while gnome-keyring still owns the bus name. That covers everything
   shown in Seahorse's Passwords view.
@@ -891,7 +962,7 @@
   - Installs:
     - binaries to `/usr/bin`, plus `aleph-tpmd` to `/usr/lib/aleph/`
     - `/usr/lib/security/pam_aleph.so`
-    - `/etc/pam.d/aleph` (the substack; `backup=` in the PKGBUILD)
+    
     - `/usr/lib/systemd/user/alephd.{service,socket}`
     - `/usr/lib/systemd/system/aleph-tpmd.{service,socket}`
     - the `.desktop` file and the icons:
@@ -959,8 +1030,19 @@
     empty.
   - Lock tests inject `PrepareForSleep` and `Lock`, then assert that keys
     are zeroized and the inhibitor has been released.
-- **PAM and setup:** `pamtester` in an Arch container against copies of
-  Omarchy's `sddm`, `omarchy-lock-password`, and `passwd`, covering:
+- **PAM (Plan 4a, no root):**
+  - the module logic, against a fake PAM handle
+  - the forked delivery, against a real socket (including a host that
+    ignores `SIGCHLD`)
+  - real Linux-PAM loading the built module through `pam_start_confdir`,
+    with `pam_exec expose_authtok` setting `PAM_AUTHTOK` from the test's
+    conversation
+  - `pam.sock` against the real daemon, including the module's delivery
+    code end to end
+- **PAM and setup (Plan 6, root container):** `pamtester` in an Arch
+  container against copies of Omarchy's `sddm`, `omarchy-lock-password`,
+  and `passwd`, covering the privilege drop and a `passwd` whose
+  `pam_unix` update fails (nothing may change), and:
   - a wrong password never reaches `pam_aleph`
   - a right one does, after dropping to the user's uid
   - SSH (`system-remote-login`) never reaches aleph
--- a/docs/testing.md
+++ b/docs/testing.md
@@ -23,8 +23,13 @@
   binary. They never touch your session bus or keyring.
 - PAM is exercised for real through a private service directory
   (`pam_start_confdir`, Linux-PAM 1.4+): `pam_unix` rejecting a wrong
-  password, and the shipped `packaging/pam/aleph-check`. Nothing is
-  installed and no root is needed.
+  password, the shipped `packaging/pam/aleph-check`, and the built
+  `pam_aleph` module loaded by libpam (`pam_exec expose_authtok` supplies
+  the password it hands over). Nothing is installed and no root is
+  needed; the module's privilege drop is left to Plan 6's root container.
+- The lock policy runs against a stand-in logind on the private bus
+  (`aleph_daemon::testing::Logind`): sleep inhibitors, `PrepareForSleep`,
+  and `Session.Lock`.
 - Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`.
   Nix: `swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`.
 
@@ -33,9 +38,9 @@
 scripted prompters (`aleph_daemon::testing`), and the CLI reads its answers
 from standard input under `ALEPH_NO_TTY=1`.
 
-`alephd`'s user unit is checked with
-`systemd-analyze verify --user packaging/systemd/alephd.service` (same
-`ExecStart` caveat as below).
+`alephd`'s user units are checked with
+`systemd-analyze verify --user packaging/systemd/alephd.service packaging/systemd/alephd.socket`
+(same `ExecStart` caveat as below).
 
 The systemd units in `packaging/systemd/` are checked with:
 
@@ -122,7 +127,27 @@
    stored for the user ("Store the password only for this user"), lock,
    reconnect, and unlock when asked: the connection must come up without
    asking for the Wi-Fi password again.
-6. `aleph status` shows the keyslots; `journalctl --user` (or the
+6. **Login and screen unlock** (Plan 4a; setup's PAM edits come in 4b, so
+   by hand for now, keeping backups):
+   - `install -Dm755 target/debug/libpam_aleph.so /usr/lib/security/pam_aleph.so`
+   - `/etc/pam.d/sddm`: `-auth optional pam_aleph.so` after `auth include
+     system-login`, and `-session optional pam_aleph.so` after `session
+     include system-login` (remove the `pam_gnome_keyring` lines)
+   - `/etc/pam.d/omarchy-lock-password`: `-auth optional pam_aleph.so` at
+     the end
+   - `/etc/pam.d/passwd`: `-password optional pam_aleph.so` after `password
+     include system-auth`
+   - Never edit `system-login`, `system-auth`, or `login`: a TTY login is
+     the way back in if something goes wrong (keep a root shell open while
+     editing, and try the lock screen before walking away)
+   - `systemctl --user enable --now alephd.socket` (with the units under
+     `~/.config/systemd/user/`)
+
+   Then: log out and in (the vault is unlocked at login, no prompt); lock
+   the screen (`aleph status`: locked) and unlock it (unlocked); `passwd`
+   (the TPM slot's id changes; with a FIDO2 slot, `aleph status` asks for
+   `aleph keyslot rotate-master`); suspend and resume (locked).
+7. `aleph status` shows the keyslots; `journalctl --user` (or the
    terminal) shows no secrets.
 
 Record the results, and the libsecret, Chromium, and NetworkManager
--- a/README.md
+++ b/README.md
@@ -12,11 +12,13 @@
 **Status:** early development. The design is in
 [`docs/superpowers/specs/2026-09-26-aleph-design.md`](docs/superpowers/specs/2026-09-26-aleph-design.md).
 
-Not yet handled: changing your login password outside aleph (`passwd`).
-TPM keyslots are sealed under the login password; after an outside change
-they go stale, and until session integration lands (re-sealing with the
-previous password, recovery-key unlock) the way back in is to set the
-previous password again. A FIDO2 keyslot is unaffected.
+Login and screen unlock (`pam_aleph`), `passwd` changes, and locking on
+sleep, screen lock, or idle are in place (Plan 4a). `aleph setup` does not
+yet edit PAM, take over from gnome-keyring, or import its items (Plan 4b):
+see [docs/testing.md](docs/testing.md) for the lines to add by hand. If
+the login password is changed outside aleph, the next unlock asks for the
+previous one to update the TPM keyslot. Design decisions made along the
+way are in [DECISIONS.md](DECISIONS.md).
 
 ## Crates
 
@@ -27,7 +29,9 @@
 | `aleph-tpmd` | The TPM helper service (the only process that talks to the TPM) |
 | `aleph-unlock` | TPM client and FIDO2 unlock methods that produce keyslot KEKs |
 | `aleph-prompt-proto` | Protocol between `alephd` and its prompters (GUI or terminal) |
+| `aleph-pam-proto` | Protocol between `pam_aleph` and `alephd`'s `pam.sock` |
 | `aleph-daemon` | `alephd`: the Secret Service and the `io.aleph.Admin1` interface |
+| `pam_aleph` | PAM module that hands the login password to `alephd` |
 | `aleph-cli` | `aleph`: the command-line client |
 
 ## Development
~~~~

Write `DECISIONS.md`:

```markdown
# Design decisions

Decisions made while the project owner was away, each proposed by the
implementer and ruled on by an independent reviewer (a fresh model
session with the spec and the code, and no part in writing them). Newest
first. The spec (`docs/superpowers/specs/2026-09-26-aleph-design.md`)
is updated to match wherever a decision changes it.

## 2026-09-27: Plan 4b (custody and setup), design

All twelve proposals were **Accepted with changes**, and the changes are
adopted. Plan 4b is written from these.

### E1. alephd imports from gnome-keyring as a Secret Service client, and queues for the name

Secrets go straight from gnome-keyring to alephd over an encrypted
session, never through the CLI. alephd requests `org.freedesktop.secrets`
queued (never `AllowReplacement` or `ReplaceExisting`), so the bus hands
it over the moment gnome-keyring releases it, and the name is never
unowned.

Changes:
- The unit becomes `BusName=io.aleph.Keyring`, so a queued alephd is not
  killed at `TimeoutStartSec`.
- `Status` reports who owns the Secret Service name. After switchover, a
  queued alephd logs a warning.
- alephd subscribes to gnome-keyring's item and collection signals before
  listing, and keeps importing until the name changes hands, so nothing
  stored in between is lost.

### E2. Import is idempotent and never overwrites

- An item conflicting with one that existed before this run (same
  collection, label and attributes, but a different secret) is skipped and
  listed in the summary. Duplicates within gnome-keyring itself all
  arrive.
- The transient `session` collection is skipped.
- Content types and every attribute (`xdg:schema` included) are kept.
- A dismissed unlock skips that collection and says so; a re-run picks it
  up. A missing or empty gnome-keyring skips the step.

### E3. `setup --revert` exports to a private gnome-keyring, verifies, then switches back

- The export goes to a gnome-keyring instance that alephd runs itself, on
  a private bus, over the real keyring files, after checking that none
  runs for this user. The session never changes hands until the export is
  verified.
- aleph refuses writes from the start of the export to the end of the
  revert.
- What to export is decided by comparison, not by timestamp: every item
  missing from gnome-keyring or different there. Each is verified by
  reading it back on a fresh connection.
- Items imported at setup and deleted in aleph since are listed, with an
  offer to delete them from gnome-keyring too. The aleph vault is left in
  place.
- Order after a verified export: stop the private instance; remove the
  activation files and reload the bus configuration; unmask and restore
  the recorded unit states; alephd releases the name; `sudo aleph system
  revert` runs last.
- Revert is refused if gnome-keyring is not installed.

### E4. PAM edits run as root through `sudo aleph system apply/revert/verify`

- The edits are pure text transformations, tested against fixtures (this
  machine's edited files and stock Omarchy's).
- Writes are atomic (a temporary file, fsync, copied mode and owner,
  rename, fsync of the directory). Symlinks, non-regular files, and files
  not owned by root are refused and handled by hand.
- **Verify, with automatic rollback:** right after applying, a real
  Linux-PAM run through the lock screen's and sddm's stacks, with the
  password asked once (faillock counts wrong tries). Any failure restores
  the originals at once.
- **Revert is conditional:** the `.aleph-orig` backup is restored byte for
  byte only if the current file is still exactly what apply produced;
  otherwise the inverse transformation is used if it applies cleanly, and
  failing that the file is left alone and a diff is shown.
- The root side stays small: it is `sudo <this binary>`, with a warning if
  that binary is user-writable, and it reads no user configuration, no
  D-Bus, and no user-writable paths.
- Anything setup installs as root is recorded in a root-owned manifest, so
  revert removes exactly that.
- `password optional pam_gnome_keyring.so` stays in `passwd`, so
  `login.keyring` keeps following the login password and a later revert
  still unlocks at login.
- **The aleph lines go straight into each service** as `-auth optional
  pam_aleph.so` (and likewise for `session` and `password`), not as
  `include aleph`. A missing substack file could make the whole service
  fail; a missing module behind `-` is silently skipped. This replaces
  Plan 4a's substack.

### E5. Autologin detection is advisory

SDDM's file rules are uncertain: it may read every file in its
configuration directories, not only `*.conf`. So detection only picks the
default unlock method and the summary text.
- aleph is always added to `sddm`.
- The `pam_gnome_keyring` lines are always removed from `sddm-autologin`
  (which would otherwise start gnome-keyring directly, ahead of alephd),
  and nothing is added there.
- The precedence rules get a test against the SDDM source's actual rules.

**Note for the owner:** `/etc/sddm.conf.d/autologin.conf.disabled` (with
`User=kyle`) may still be read by SDDM. Check this before relying on it.

### E6. Manual mode where files are not ordinary

Any PAM target that is not a regular, root-owned file puts setup in manual
mode (it prints what to add), on any distribution. NixOS (`/etc/NIXOS`)
also skips the unit masking and prints the module configuration, and
revert there prints what to undo.

### E7. Restore, `--from-bak`, and `--accept-rollback`

- **No lowering of the high-water mark, ever.** The restored or accepted
  vault is written at generation `max(recorded, found) + 1` (core
  `advance_generation_past`), so every older copy stays detectable.
- **Replacing a vault that still opens needs re-authentication with its
  current method**, as well as the backup's recovery key. Without that, a
  same-user process could swap in a backup whose recovery key it holds.
- The replaced file is kept (`vault.aleph.replaced-<time>` or
  `.corrupt-<time>`), never deleted.
- A plain `restore` on an unreadable `vault.aleph` falls back to `.bak`,
  and is refused while the vault is unlocked and trusted.
- `--accept-rollback` shows exactly what is being accepted, and its
  confirmation defaults to no.
- A new recovery key is offered afterwards, defaulting to yes.
- The recovery-key prompt is a type-level part of the restore conversation
  only.
- Files pass as descriptors, not paths.
- The expected `vault_id` is recorded; a different vault at the path
  counts as untrusted.

### E8. Backup writes to a descriptor the CLI opened

The CLI opens the file (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600; `--force`
writes a temporary file and renames it over the target). Targets inside
aleph's data and state directories are refused. The written bytes are
checked to parse, and their vault id and generation are printed.

### E9. User-level switchover also stops gnome-keyring's other routes in

- **Activation files:** gnome-keyring's D-Bus activation files start it
  directly, bypassing systemd. So user-level files override
  `org.freedesktop.secrets` (pointing to alephd) and `org.gnome.keyring`
  and `org.freedesktop.impl.portal.Secret` (disabled).
- **Bus reload:** `ReloadConfig` is called after writing or removing
  activation files (dbus-broker does not notice new files).
- **Order:** activation files and reload; alephd started (queued); units
  masked; gnome-keyring stopped; then the name's owner is checked.
- The prior unit states are recorded for revert. The user is told that
  gnome-keyring's pkcs11 component goes away.

### E10. Setup steps check the real state on every run

Each run checks the vault, the name owner, the unit states, and the PAM
files, rather than trusting a state file. The state file records only
choices (and which items were imported, for E3). The riskiest step, the
root one, comes last and is optional.

### E11. Testing

Beyond the proposal:
- the name handoff on a private bus
- unlocking a second, password-protected gnome-keyring collection (or
  skipping with a message)
- export verification, the write freeze, deletion reporting, and a revert
  re-run after a partial failure
- PAM fixtures for both variants, with idempotence and exact revert
- the transformed stacks run through real Linux-PAM (`pam_start_confdir`,
  as in D10)
- SDDM precedence

The real gnome-keyring runs isolated on a private bus: this was checked on
this machine.

### E12. Task list

Nine tasks, with the additions above. The switchover-and-revert task and
the wizard task are separate, and the docs task adds an emergency
manual-revert section.

## 2026-09-27: Plan 4a (session unlock)

Reviewer verdicts are given as **Accepted**, **Accepted with changes**
(the changes were adopted), or **Rejected** (the alternative was adopted).

### D1. Plan 4 is split into 4a and 4b — Accepted

- **4a, session unlock:** `pam_aleph` and `pam.sock`, login and
  screen-unlock unlocking, `passwd` changes, re-sealing after an outside
  password change, and the lock policy (suspend, screen lock, idle).
- **4b, custody and setup:** recovery unlock (`aleph restore`), backup,
  `--from-bak` and `--accept-rollback`, gnome-keyring import and export,
  setup's system changes and `setup --revert`, and lockoutAuth.

4b's setup installs the PAM lines 4a's module needs. Until then, 4a's docs
give the lines to add by hand, marked provisional.

### D2. `passwd` without FIDO2 slots rotates MK; with them, it keeps MK and marks a rotation pending — Accepted with changes

A rotation needs a KEK for every slot, and a FIDO2 slot's KEK needs a
touch, which `passwd` cannot provide.

- **Without FIDO2 (or unknown-type) slots:** the password slots are
  replaced (a new TPM slot sealed under the new password, and a new
  login-password slot if there was one) and MK rotates.
- **With them:** the new slots are added and the old ones removed without
  rotating (core `remove_keyslot_keeping_mk`, which refuses recovery slots
  and keeps the pre-change file out of `.bak`). A "rotation pending" mark
  is shown by `aleph status` and by every unlock, and any rotation clears
  it.
- **Residual risk while pending:** an old copy of the file, plus the old
  password, plus this machine's TPM, yields an MK that still opens newer
  files.

Changes adopted:
- **The daemon checks the new password with PAM first.** In Arch's stack,
  `pam_aleph` still runs when `pam_unix`'s update failed. If PAM rejects
  the new password, nothing changes. If PAM cannot check, the change goes
  ahead.
- The pending mark is repeated in the message that ends each unlock.
  Offering the touches right there is left to the GUI prompter (Plan 5).
- An unreadable `slots.json` is logged.

### D3. After an outside password change, the previous password re-seals — Accepted with changes

When a typed password PAM accepts opens no TPM slot (all stale, or one
rejects it with `AuthFailed`), the prompter asks for the previous password
(`ToPrompter::OldPassword`).

- It is tried only on the newest TPM slot, straight at the TPM with no PAM
  check.
- At most 2 tries per conversation, each counted by the typing limiter.
- Once the vault is open, the password slots are replaced under the
  current password, following D2's policy.

Changes adopted:
- **Cancelling the question returns to the choice of method.** A FIDO2
  touch then opens the vault, and it re-seals under the current password
  all the same.
- **A `WrongUser` refusal does not ask for the previous password,** which
  cannot help there.
- **With PAM unavailable and every TPM slot stale,** the attempt fails
  with the "cannot check passwords" error, which says why.

### D4. `lock.on_suspend` covers every sleep, hibernation included — Accepted

logind's `PrepareForSleep` does not say which sleep it is, and
suspend-then-hibernate moves on to hibernating without a second signal.
The spec now says so. `aleph config set lock.on_suspend false` warns that
the master key can then end up in a hibernation image.

### D5. `pam.sock` passwords skip the PAM check — Rejected

This would let one wrong password from any same-user process reach the TPM
and mark slots stale.

Adopted instead:
- `pam.sock` passwords are checked with `aleph-check` whenever PAM can
  check: `Unlock`'s password, and `ChangePassword`'s new one. (The old one
  cannot pass PAM once `passwd` has changed it; it is proven by the slot
  it opens, and only on a locked vault.)
- A rejected password fails without touching the TPM.
- The login stack is trusted only when PAM cannot check (for example, an
  account `pam_unix` cannot verify).
- The limit of 5 failed requests per minute stays, and counts only
  password rejections (not busy or rate-limited answers).

### D6. The `pam_aleph` protocol is a tiny binary crate, `aleph-pam-proto` — Accepted

It depends only on std and `zeroize`, and uses strict length-prefixed
frames. The module's forked child can read a reply without allocating.

### D7. `pam_aleph` delivers from a forked child running as the user — Accepted with changes

The child drops to the user's uid and gid (only when running as root),
calls only async-signal-safe functions, sends with `MSG_NOSIGNAL`, and has
an `alarm` backstop.
- **At auth** it delivers at once if `pam.sock` exists, and otherwise keeps
  the password (`pam_set_data`, zeroized) until session open.
- **At `passwd`** it delivers in the update phase, only when both the old
  and the new password are known.
- Every phase returns `PAM_IGNORE`.

Changes adopted:
- **The host's `SIGCHLD` disposition is never touched.** The child reports
  through a pipe; the parent waits on the pipe with the timeout, kills
  through a pidfd, and ignores `ECHILD` if the host reaped the child.
- **On a second login, delivering at auth unlocks before the `account` and
  `session` stacks run.** This is harmless (it is the user's own vault, and
  the password was right), and the spec records it.

### D8. `passwd` on a locked vault never unlocks it — Accepted with changes

The change works on a detached copy: it is opened with the old password,
changed, checked against the high-water mark, and written. It never
becomes the daemon's unlocked vault, so no Secret Service reader can use
it meanwhile.

### D9. lockoutAuth (Plan 4b) is not set through the TPM helper — Accepted with changes

Any local user can call the helper, so it gets no "set lockoutAuth"
request. On explicit opt-in, setup runs `sudo tpm2_changeauth -c lockout
file:-` itself, feeding the value on standard input, so it never appears
in `argv` or shell history. It shows the value once and asks for it to be
typed back. If the user declines, setup prints that command for them to
run.

### D10. Testing `pam_aleph` without root — Accepted

Three layers:
- unit tests of the module logic, against a fake PAM handle
- the forked delivery, against a real socket
- real Linux-PAM loading the built module through `pam_start_confdir`,
  with `pam_exec expose_authtok` setting `PAM_AUTHTOK` from the test's
  conversation

Left for Plan 6's root container:
- the privilege drop
- a `passwd` whose `pam_unix` update fails, which must change nothing

### D12. The pre-execution review of the Plan 4a document: fixes adopted

The review of the plan and prototype found nothing critical, and six
important defects, all fixed, each with a test.

- **A login password waited behind a security key's PIN question** (the
  FIDO2 flow held the hardware lock while the prompter was asked). The lock
  is now held only for key operations.
- **"First open wins" could install an older copy** when the vault had been
  unlocked, written, and locked again in between (read as a rollback,
  hiding what was written). The late open now reopens the current file
  with its key, or asks to unlock again.
- **A `passwd` change after a login with the new password** (which had
  marked the old slot stale) failed. The change now opens the file with
  the previous password whatever the stale marks.
- **With PAM unable to vouch for the new password, a change never proved
  the old one,** so a same-user process could re-seal the vault under a
  password of its choosing. The old password must now open the file
  first.
- **`pam.sock` rate limiting could be bypassed with parallel connections,**
  and unauthenticated requests queued on the operation lock. Requests in
  flight now count against the limit (at most 5 at once), and the new
  password is checked before waiting.
- **The previous-password question could be asked more than twice per
  conversation.** Its budget now spans the conversation.

Minor fixes adopted:
- `Session.Lock` counts only when sent by logind's name owner (spoofing
  test).
- The forked child closes the host's descriptors, resets and unblocks
  `SIGALRM`, and exits rather than unwinding into the host.
- Without a pidfd, the timed-out child is killed and reaped by pid.
- A failed delivery at auth is retried at session open.
- The listener never replaces a socket something still serves.
- The pending-rotation mark is saved before the write.
- Template artifacts are gone from the plan text.

Deferred: once slots were marked stale by a `WrongUser` refusal, a later
unlock may still ask for the previous password. The case (someone else's
vault file) is rare, and the question is harmless.

### D11. Other points from the review, adopted

- **A login password from `pam.sock` does not queue behind an open
  prompter conversation.** It opens the vault at once. Whichever opens
  first is installed, and a later open is discarded, never installed over
  it. A `passwd` change still waits its turn.
- **Socket activation takes the descriptor named `pam`**
  (`FileDescriptorName=` in `alephd.socket`, `LISTEN_FDNAMES`), not just
  descriptor 3.
- **A password rejected through `pam.sock` is logged at warning level.**
  An outside password change then shows in the journal, as well as at the
  next interactive unlock.
```

- [ ] **Step 2: Run the tests, clippy, and fmt**

Run: `cargo test -q && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 8 passed | ok. 59 passed | ok. 1 passed | ok. 28 passed | ok. 11 passed | ok. 1 passed | ok. 29 passed | ok. 3 passed | ok. 47 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed | ok. 3 passed | ok. 2 passed | ok. 6 passed | ok. 5 passed | ok. 21 passed | ok. 5 passed | ok. 2 passed | ok. 23 passed | ok. 9 passed | ok. 6 passed | ok. 6 passed | ok. 3 passed | ok. 1 passed.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-09-26-aleph-design.md docs/testing.md README.md DECISIONS.md
git commit -m "docs: spec, testing, README, and decisions for session unlock" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
