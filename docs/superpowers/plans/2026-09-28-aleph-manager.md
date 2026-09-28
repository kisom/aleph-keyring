# The Manager Implementation Plan (Plan 5b: the window and its secrets browser)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `aleph-gui` with no arguments opens a keyring manager from the Omarchy launcher: folders and a searchable item list, a detail pane, show and copy after a confirmation, and create, rename, re-secret, and delete items and folders — so Seahorse is no longer needed.

**Architecture:**
- The manager is an ordinary **Secret Service client**, like Seahorse: a store on its own thread talks to `org.freedesktop.secrets` over an encrypted session (the session code moves from alephd into a new crate, `aleph-secret-session`, shared by both), lists labels and attributes, and fetches one secret only when asked.
- **Showing, copying, or editing a secret** first runs alephd's new `Reauth` admin method, answered with the prompter's own screens drawn inside the manager; a confirmation holds for 5 minutes, not past a lock.
- A copy goes to the **Wayland clipboard** with the hint clipboard-history tools honor, and is cleared after 30 s. A `.desktop` entry and the icons put the manager in the launcher.

**Tech Stack:** Rust 1.98; eframe/egui 0.36 (as in Plan 5a); zbus 5 on a tokio current-thread runtime (the store's thread); `wl-clipboard-rs` 0.9; egui_kittest 0.36 (screens and snapshots); the daemon's test harness (a real alephd on a private bus, swtpm) for the store's tests.

**Spec:** `docs/superpowers/specs/2026-09-28-aleph-manager-design.md` (the manager's design; the owner reviewed it), extending `docs/superpowers/specs/2026-09-26-aleph-design.md` §6 (admin methods), §7 (Manager), §8 (installs). Decisions: `DECISIONS.md` H7 (the owner's: scope and approach), H8 (calls made while prototyping), and H9 (the pre-execution review's fixes); Task 7 adds them and updates the main spec.

**Plan series:** 1–5a (done) → **5b the manager's window and secrets (this plan)** → 5c settings → 5d admin → 6 packaging and CI.

**Base:** `master` (with Plan 5a and the fixes after it).

**Prerequisites:** as for Plan 5a (swtpm, tpm2-tools, dbus, libsecret, lua, a GPU driver for the snapshots); `desktop-file-utils` for the manual `desktop-file-validate` check.

## Decisions made while prototyping

Every task was prototyped on a clone of `master` and the whole gate run (`make gate`) green; the code below is that prototype's, verbatim. The properties below were each checked by reverting them (the "teeth" step of the owning task). `DECISIONS.md` H8 lists these calls for the reviewers.

- **The lock state is polled as well as signalled, the lists are not.** alephd signals a lock (`CollectionChanged` on the default alias); the store also reads one property (`Locked` on `/org/freedesktop/secrets/aliases/default`) every 2 s, for a missed signal or a restart, and lists everything only when that changes or a signal arrives (listing costs a few calls per item). With the default folder deleted (its alias goes too), the service answering means unlocked.
- **Only the store's loop lists:** each request runs on its own (an unlock prompt may wait for the person indefinitely, H5) and asks the loop for a fresh listing when it ends, so what the loop last sent is what the window shows. Folders or items that vanish mid-listing are skipped; a burst of signals means one listing; signals are taken only from the service's owner.
- **Sessions follow alephd (and are their openers'):** the store's session is tied to the unique name serving `org.freedesktop.secrets`, closed and replaced when a request using it fails, and that request is tried once more. alephd now serves a session only to the client that opened it (it numbers sessions from 1 on every start: after a restart another client could be handed the manager's cached path).
- **The confirmation reuses the prompter:** `PromptApp` gains `embedded` (it then never closes or resizes the window, and ignores the window's close button); the manager draws it in the detail pane on a socketpair whose other end goes to `Reauth`.
- **The copy is served by `wl-clipboard-rs`** from a thread until another program takes the clipboard (or the manager exits); "still ours" is whether that thread is serving. The served copy is the crate's and is not zeroized (the manager spec: not guaranteed). **It is cleared by a timer thread** 30 s after the copy (if it is still that copy), never by the window's frames: a window on a hidden workspace draws none.
- **An edit saves only what changed** (a loaded secret is rewritten only if it differs; a secret that is not text cannot be loaded into the editor), and **a form stays until its save succeeds** (a failed save keeps what was typed, with the error; a lock keeps a secret the person typed).
- **New items get `xdg:schema = org.freedesktop.Secret.Generic`** unless one is typed; secrets are stored as `text/plain`.
- **Dates are UTC calendar days;** a secret that is not UTF-8 shows as "binary secret, N bytes" (and can still be copied).
- **No folder marker:** "▸" is not in the Omarchy theme's font (it drew a box); folders are bold, items indented.
- **The app id is `aleph`,** matching the launcher entry's `StartupWMClass`; the entry is `Utility;Security;` (a second main category would list it twice).
- **The binary tests never open a window on the real display:** `aleph-gui` with no arguments is now the manager, so the old "no arguments prints usage" test becomes "an unknown argument prints usage", and the manager's test runs with a display socket that does not exist, a private runtime directory, and no session bus.
- **The theme watcher is shared** (`theme::Watch`), so the manager follows Omarchy theme switches like the prompt, and it has a test now.

## Global Constraints

- Rust stable 1.98, edition 2024; every crate `license = "Apache-2.0"` (workspace).
- eframe/egui/egui_kittest 0.36 as in Plan 5a (eframe features `accesskit`, `default_fonts`, `glow`, `wayland`); `wl-clipboard-rs` 0.9; `zbus` 5 (`default-features = false, features = ["tokio"]`); `tokio` 1 (`rt`, `macros`, `sync`, `time`) in `aleph-gui`.
- **Exact names:** the crate `aleph-secret-session`; the admin method `Reauth(prompter: h)`; the app id and `StartupWMClass` `aleph`; `packaging/aleph-gui.desktop` → `/usr/share/applications/aleph-gui.desktop`; icons at `hicolor/scalable/apps/aleph.svg`, `hicolor/24x24/apps/aleph.svg`, `hicolor/16x16/apps/aleph.svg`, `hicolor/symbolic/apps/aleph-symbolic.svg`; the clipboard hint `x-kde-passwordManagerHint` = `secret`.
- Secrets reach the manager only through `org.freedesktop.secrets` over the DH session, only when shown, copied, or edited, in `Zeroizing` buffers; never logged. Labels, attribute keys and values, and folder names from other programs go through `conversation::shown` (no line breaks of their own, cut short) in lists and headings.
- The words follow DECISIONS.md H6 (`ALEPH // VAULT`, `VAULT SEALED`, `LINK DOWN`, `COPIED`); delete confirmations are `Yes` / `No` with No focused.
- Tests never open a window on the real display, never use the real session bus, clipboard, or keyring (a private bus with the daemon's test harness; stand-ins for the store and clipboard in screen tests).
- aleph is live on the development machine: do not restart alephd, reinstall, or open the manager on the real desktop while executing; the manual checks (testing.md, "The manager") are the owner's.
- `cargo fmt` default; `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **Walking away with a secret on screen or on the clipboard,** the manager hidden on another workspace: a lock hides what is shown and forgets the confirmation; the copy is cleared after 30 s by its own timer, unless something else was copied since. → Task 5 `a_lock_seals_the_window`; Task 4 `a_copy_is_cleared_after_its_time_without_the_window`, `a_copy_replaced_since_is_left_alone`, `a_newer_copy_keeps_its_own_time`, `a_confirmation_holds_five_minutes_and_not_past_a_lock`.
2. **alephd restarted while the manager is open** (`make install`, an upgrade): shows and saves keep working on a new session, never on another client's. → Task 2 `a_session_is_usable_only_by_the_client_that_opened_it`; Task 3 `a_forgotten_session_is_replaced`, `without_alephd_the_store_is_unreachable`; Task 5 `without_alephd_the_link_is_down`.
3. **An edit that loses or mangles data:** a label edit after LOAD SECRET, a binary secret, a save that fails, a lock mid-edit. → Task 5 `a_loaded_secret_is_saved_only_if_changed`, `a_binary_secret_is_not_editable`, `a_failed_save_keeps_the_form`, `a_typed_secret_survives_a_lock`, `an_edited_label_is_saved`.
4. **Odd data and odd folders:** a hostile label, a secret that is not text, the default folder deleted. → Task 5 `a_hostile_label_stays_on_one_line_in_the_list`, `a_binary_secret_is_not_shown`; Task 3 `deleting_the_default_folder_keeps_the_keyring_reachable`.
5. **Destructive actions by accident:** deleting asks with No the default (Enter says No); a folder deletion is confirmed by alephd. → Task 5 `delete_asks_first`, `enter_on_the_delete_question_says_no`; Task 3 `folders_are_created_and_deleted_after_alephds_confirmation`. (A keyring with hundreds of items: the lists are fetched only on a change, never on each poll; no test counts calls: the reviewer checks Task 3's loop.)

## File Structure

```
crates/aleph-secret-session/{Cargo.toml,src/lib.rs}   the Secret Service sessions (moved from aleph-daemon/src/secret/session.rs)
crates/aleph-daemon/src/secret/mod.rs                 pub use aleph_secret_session as session
crates/aleph-daemon/src/{keyring,admin}.rs            Keyring::confirm, Admin.Reauth
crates/aleph-daemon/tests/admin.rs
crates/aleph-gui/src/store.rs                         Store (trait), DbusStore, Request, StoreEvent, Vault, Collection, Item
crates/aleph-gui/src/reauth.rs                        Reauth (the 5-minute confirmation clock)
crates/aleph-gui/src/clipboard.rs                     Clipboard<B: Backend> (30 s expiry), Wayland
crates/aleph-gui/src/manager.rs                       Manager<S: Store, B: Backend>: the window
crates/aleph-gui/src/{app,theme,main,lib}.rs          PromptApp.embedded, theme::Watch, `aleph-gui` → the manager
crates/aleph-gui/tests/{store,manager,binary,launcher}.rs; tests/snapshots/manager_*.png
packaging/aleph-gui.desktop; packaging/install.sh
docs: spec (§6, §7, §8, crates), DECISIONS.md (H7, H8), testing.md ("The manager"), README.md
```

---

### Task 1: `aleph-secret-session`: the sessions in a crate of their own

**Files:**
- Create: `crates/aleph-secret-session/Cargo.toml`, `crates/aleph-secret-session/src/lib.rs` (moved from `crates/aleph-daemon/src/secret/session.rs`)
- Modify: `Cargo.toml` (workspace members), `crates/aleph-daemon/Cargo.toml`, `crates/aleph-daemon/src/secret/mod.rs`

**Interfaces:**
- Produces: `aleph_secret_session::{PLAIN, DH, Session, SessionError, ClientDh}` — the same items `aleph_daemon::secret::session` had (`Session::open(&str, &[u8]) -> Result<(Session, Vec<u8>)>`, `encrypt(&[u8]) -> Result<(Vec<u8>, Vec<u8>)>`, `decrypt(&[u8], &[u8]) -> Result<Zeroizing<Vec<u8>>>`, `ClientDh::{new() -> Result<Self>, public: Vec<u8>, finish(self, &[u8]) -> Result<Session>}`); `aleph_daemon::secret::session` stays as a re-export.

- [ ] **Step 1: Move the module (its tests move with it)**

```bash
mkdir -p crates/aleph-secret-session/src
git mv crates/aleph-daemon/src/secret/session.rs crates/aleph-secret-session/src/lib.rs
```

In `Cargo.toml`, replace `"crates/aleph-gui"]` with `"crates/aleph-gui", "crates/aleph-secret-session"]`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-secret-session`
Expected: failure: the crate has no `Cargo.toml` yet (`failed to load manifest for workspace member`).

- [ ] **Step 3: Make it a crate**

Write `crates/aleph-secret-session/Cargo.toml`:

```toml
[package]
name = "aleph-secret-session"
description = "The Secret Service transfer sessions (plain and dh-ietf1024-sha256-aes128-cbc-pkcs7), server and client halves"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
aes = "0.9"
cbc = { version = "0.2", features = ["alloc"] }
getrandom.workspace = true
hkdf.workspace = true
num-bigint = "0.4"
sha2.workspace = true
thiserror.workspace = true
zeroize.workspace = true
```

Replace `crates/aleph-secret-session/src/lib.rs` with (randomness from `getrandom` directly, filled in place for the exponent; the module's doc comment names both users):

```rust
//! Secret Service transfer sessions (spec §6 "Secret Service"), both
//! halves: alephd serves them, and uses the client half to read another
//! Secret Service (the gnome-keyring import); the manager window
//! (`aleph-gui`) uses the client half to read alephd.
//!
//! - `plain`: secrets travel as-is on the (per-user) session bus.
//! - `dh-ietf1024-sha256-aes128-cbc-pkcs7`, which libsecret requires:
//!   Diffie-Hellman in the 1024-bit MODP group of RFC 2409 §6.2, the
//!   shared secret (big-endian, zero-padded to 128 bytes) through
//!   HKDF-SHA-256 with no salt and no info to a 16-byte key, then
//!   AES-128-CBC with PKCS#7 padding and a random IV as the parameters.
//!   Weak by modern standards, acceptable on a per-user local bus, and
//!   documented as such. The modular exponentiation is not constant-time;
//!   each session's key is ephemeral.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const PLAIN: &str = "plain";
pub const DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// RFC 2409 §6.2, "Second Oakley Group".
const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);
const PRIME_LEN: usize = 128;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("unsupported session algorithm {0:?}")]
    Unsupported(String),
    #[error("invalid session input")]
    BadInput,
    #[error("cannot decrypt the secret (wrong session or corrupt data)")]
    Decrypt,
    #[error("system randomness unavailable")]
    Random,
}

pub enum Session {
    Plain,
    Dh { key: Zeroizing<[u8; 16]> },
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Plain => "Session::Plain",
            Self::Dh { .. } => "Session::Dh(<key>)",
        })
    }
}

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("valid prime")
}

fn random<const N: usize>() -> Result<[u8; N], SessionError> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| SessionError::Random)?;
    Ok(out)
}

/// A random DH exponent in [2, p-2].
fn exponent(p: &BigUint) -> Result<BigUint, SessionError> {
    // (Filled in place: the exponent's bytes never sit in a copy.)
    let mut bytes = Zeroizing::new([0u8; PRIME_LEN]);
    getrandom::fill(&mut *bytes).map_err(|_| SessionError::Random)?;
    Ok(BigUint::from_bytes_be(&*bytes) % (p - BigUint::from(3u8)) + BigUint::from(2u8))
}

/// The session key from our exponent and the peer's public value (checked
/// to be in range), as both sides derive it.
fn derive(peer_bytes: &[u8], x: &BigUint, p: &BigUint) -> Result<Session, SessionError> {
    let peer = BigUint::from_bytes_be(peer_bytes);
    let one = BigUint::from(1u8);
    if peer_bytes.len() > PRIME_LEN || peer <= one || peer >= p - &one {
        return Err(SessionError::BadInput);
    }
    // The byte forms are zeroized; num-bigint cannot zeroize its own limbs
    // (the exponent and shared value), which is accepted for an ephemeral
    // per-session key.
    let shared = Zeroizing::new(peer.modpow(x, p).to_bytes_be());
    let mut ikm = Zeroizing::new([0u8; PRIME_LEN]);
    ikm[PRIME_LEN - shared.len()..].copy_from_slice(&shared);
    let mut key = Zeroizing::new([0u8; 16]);
    Hkdf::<Sha256>::new(None, &*ikm)
        .expand(&[], &mut *key)
        .expect("16 bytes is a valid HKDF length");
    Ok(Session::Dh { key })
}

/// The client half of a `dh-ietf1024-sha256-aes128-cbc-pkcs7` exchange:
/// alephd reading another Secret Service (the gnome-keyring import), the
/// manager window reading alephd.
pub struct ClientDh {
    x: BigUint,
    /// Our public value, the `OpenSession` input.
    pub public: Vec<u8>,
}

impl ClientDh {
    pub fn new() -> Result<Self, SessionError> {
        let p = prime();
        let x = exponent(&p)?;
        let public = BigUint::from(2u8).modpow(&x, &p).to_bytes_be();
        Ok(Self { x, public })
    }

    /// The session, from the server's `OpenSession` output.
    pub fn finish(self, server_public: &[u8]) -> Result<Session, SessionError> {
        derive(server_public, &self.x, &prime())
    }
}

impl Session {
    /// Negotiate a session: returns it and the output for the client (our
    /// DH public value, or nothing for `plain`).
    pub fn open(algorithm: &str, input: &[u8]) -> Result<(Self, Vec<u8>), SessionError> {
        match algorithm {
            PLAIN if input.is_empty() => Ok((Self::Plain, Vec::new())),
            PLAIN => Err(SessionError::BadInput),
            DH => {
                let p = prime();
                let x = exponent(&p)?;
                let public = BigUint::from(2u8).modpow(&x, &p);
                Ok((derive(input, &x, &p)?, public.to_bytes_be()))
            }
            other => Err(SessionError::Unsupported(other.into())),
        }
    }

    /// Encrypt a secret for the client: `(parameters, value)`.
    pub fn encrypt(&self, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SessionError> {
        match self {
            Self::Plain => Ok((Vec::new(), secret.to_vec())),
            Self::Dh { key } => {
                let iv = random::<16>()?;
                let ct = cbc::Encryptor::<aes::Aes128>::new(&(**key).into(), &iv.into())
                    .encrypt_padded_vec::<Pkcs7>(secret);
                Ok((iv.to_vec(), ct))
            }
        }
    }

    /// Decrypt a secret from the client.
    pub fn decrypt(
        &self,
        parameters: &[u8],
        value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        match self {
            Self::Plain => Ok(Zeroizing::new(value.to_vec())),
            Self::Dh { key } => {
                let iv: [u8; 16] = parameters.try_into().map_err(|_| SessionError::Decrypt)?;
                cbc::Decryptor::<aes::Aes128>::new(&(**key).into(), &iv.into())
                    .decrypt_padded_vec::<Pkcs7>(value)
                    .map(Zeroizing::new)
                    .map_err(|_| SessionError::Decrypt)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client doing its half of the exchange, as libsecret does.
    fn client_key(server_public: &[u8], x: &BigUint) -> [u8; 16] {
        let shared = BigUint::from_bytes_be(server_public)
            .modpow(x, &prime())
            .to_bytes_be();
        let mut ikm = [0u8; PRIME_LEN];
        ikm[PRIME_LEN - shared.len()..].copy_from_slice(&shared);
        let mut key = [0u8; 16];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[], &mut key)
            .unwrap();
        key
    }

    #[test]
    fn both_sides_derive_the_same_key_and_secrets_round_trip() {
        let x = BigUint::from_bytes_be(&[0x5a; 64]);
        let client_public = BigUint::from(2u8).modpow(&x, &prime()).to_bytes_be();
        let (session, server_public) = Session::open(DH, &client_public).unwrap();
        let key = client_key(&server_public, &x);
        let Session::Dh { key: server_key } = &session else {
            panic!()
        };
        assert_eq!(**server_key, key);
        let (iv, ct) = session.encrypt(b"s3cret").unwrap();
        assert_eq!(iv.len(), 16);
        assert_ne!(&ct[..], b"s3cret");
        assert_eq!(&**session.decrypt(&iv, &ct).unwrap(), b"s3cret");
        assert_eq!(session.decrypt(&iv[..8], &ct), Err(SessionError::Decrypt));
    }

    /// Our client half (the gnome-keyring import) and a server agree, and
    /// a bad server value is refused.
    #[test]
    fn the_client_half_agrees_with_a_server() {
        let client = ClientDh::new().unwrap();
        let (server, server_public) = Session::open(DH, &client.public).unwrap();
        let (iv, ct) = server.encrypt(b"from gnome-keyring").unwrap();
        let session = client.finish(&server_public).unwrap();
        assert_eq!(&**session.decrypt(&iv, &ct).unwrap(), b"from gnome-keyring");
        assert!(ClientDh::new().unwrap().finish(&[1]).is_err());
    }

    #[test]
    fn plain_passes_through_and_bad_inputs_are_refused() {
        let (plain, out) = Session::open(PLAIN, &[]).unwrap();
        assert!(out.is_empty());
        assert_eq!(plain.encrypt(b"x").unwrap(), (vec![], b"x".to_vec()));
        assert!(Session::open(PLAIN, b"junk").is_err());
        assert_eq!(Session::open(DH, &[1]).unwrap_err(), SessionError::BadInput);
        assert_eq!(
            Session::open(DH, &[0xff; 129]).unwrap_err(),
            SessionError::BadInput
        );
        let p_minus_1 = (prime() - BigUint::from(1u8)).to_bytes_be();
        assert_eq!(
            Session::open(DH, &p_minus_1).unwrap_err(),
            SessionError::BadInput
        );
        assert!(matches!(
            Session::open("rot13", &[]),
            Err(SessionError::Unsupported(_))
        ));
    }
}
```

In `crates/aleph-daemon/Cargo.toml`, remove the three lines `aes = "0.9"`, `cbc = { version = "0.2", features = ["alloc"] }`, and `num-bigint = "0.4"`, and after `aleph-prompt-proto = { path = "../aleph-prompt-proto" }` add:

```toml
aleph-secret-session = { path = "../aleph-secret-session" }
```

In `crates/aleph-daemon/src/secret/mod.rs`, replace `pub mod session;` with:

```rust
pub use aleph_secret_session as session;
```

(Every `crate::secret::session::…` path in alephd keeps working.)

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-secret-session && cargo test -q -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `ok. 3 passed` (the session tests, moved), `ok. 0 passed` (doc tests), then every aleph-daemon test binary ok.

- [ ] **Step 5: Confirm the tests have teeth**

In `crates/aleph-secret-session/src/lib.rs`, replace `    if peer_bytes.len() > PRIME_LEN || peer <= one || peer >= p - &one {` with `    if false {`; `cargo test -q -p aleph-secret-session` FAILS (`plain_passes_through_and_bad_inputs_are_refused`: an out-of-range public value is no longer refused); undo it.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-secret-session crates/aleph-daemon
git commit -m "refactor: the Secret Service sessions in a crate of their own" -m "aleph-secret-session: the plain and DH sessions, server and client halves, moved from alephd unchanged but for randomness from getrandom directly; the manager window will use the client half." -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: alephd: `Reauth`, and sessions that are their openers'

**Files:**
- Modify: `crates/aleph-daemon/src/keyring.rs` (`Keyring::confirm`), `crates/aleph-daemon/src/admin.rs` (`Reauth`), `crates/aleph-daemon/src/secret/service.rs` (sessions checked against their opener; `forget_sessions` for tests), `crates/aleph-daemon/tests/admin.rs`, `crates/aleph-daemon/tests/secret_service.rs`

**Interfaces:**
- Produces: `Keyring::confirm(&self, &mut Channel) -> Result<()>`; admin method `io.aleph.Admin1.Reauth(prompter: h)` (a conversation: `Begin { purpose: Reauth, operation: "Confirm it is you" }`, the method choice, `Done`; changes nothing). A session serves only the client that opened it (`NoSession` otherwise). `SecretService::forget_sessions(&self)` (feature `testing`: as a restart does).

- [ ] **Step 1: Write the failing tests**

Add at the end of `crates/aleph-daemon/tests/admin.rs`:

```rust
/// `Reauth` proves an enrolled method again and does nothing else: the
/// manager's guard before it shows or copies a secret (the manager spec).
#[tokio::test(flavor = "multi_thread")]
async fn reauth_confirms_and_changes_nothing() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    let before = status(&d).await;
    let sent = converse(&d, "Reauth", &[], vec![password(PW)]).await;
    assert!(
        matches!(
            sent.first(),
            Some(ToPrompter::Begin {
                purpose: aleph_daemon::prompt::Purpose::Reauth,
                ..
            })
        ),
        "{sent:?}"
    );
    assert_eq!(done(&sent), (true, None));
    assert_eq!(status(&d).await, before);
    // A wrong password is refused (and a typo never reaches the TPM).
    let sent = converse(
        &d,
        "Reauth",
        &[],
        vec![password("typo"), FromPrompter::Cancel {}],
    )
    .await;
    assert!(!done(&sent).0, "{sent:?}");
}
```

Add at the end of `crates/aleph-daemon/tests/secret_service.rs`:

```rust
/// A session is its opener's: another client naming its path (a stale
/// one kept across an alephd restart, where numbering starts again) gets
/// `NoSession`, never secrets under someone else's key.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_is_usable_only_by_the_client_that_opened_it() {
    let s = served(vec![]).await;
    secret_tool(&s, &["store", "--label=T", "service", "x"], Some("pw")).await;
    let (a, b) = (client(&s).await, client(&s).await);
    let (_, session): (OwnedValue, OwnedObjectPath) = service(&a)
        .await
        .call("OpenSession", &("plain", zbus::zvariant::Value::from("")))
        .await
        .unwrap();
    let (items, _): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service(&a)
        .await
        .call(
            "SearchItems",
            &(std::collections::HashMap::from([("service", "x")]),),
        )
        .await
        .unwrap();
    let get = |c: &zbus::Connection| {
        let (c, item, session) = (c.clone(), items[0].clone(), session.clone());
        async move {
            zbus::Proxy::new(
                &c,
                "org.freedesktop.secrets",
                item,
                "org.freedesktop.Secret.Item",
            )
            .await
            .unwrap()
            .call_method("GetSecret", &(session,))
            .await
        }
    };
    assert!(get(&a).await.is_ok());
    let err = get(&b).await.unwrap_err().to_string();
    assert!(err.contains("NoSession"), "{err}");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon --test admin reauth_confirms`
Expected: FAIL: `org.freedesktop.DBus.Error.UnknownMethod`, "Unknown method 'Reauth'".
Run: `cargo test -q -p aleph-daemon --test secret_service a_session_is_usable`
Expected: FAIL at `unwrap_err()`: the second client's `GetSecret` with the first client's session succeeds.

- [ ] **Step 3: Implement**

In `crates/aleph-daemon/src/keyring.rs`, add before `/// Replace the recovery key: the old one stops working (§5).`:

```rust
    /// Prove an enrolled method again, and nothing else: the manager's
    /// guard before it shows or copies a secret (a guard against a glance,
    /// not security: any program running as the user can read secrets).
    pub fn confirm(&self, chan: &mut Channel) -> Result<()> {
        let _op = self.begin(chan)?;
        converse(chan, |chan| {
            // (The manager says what the guard is worth, beside it.)
            self.reauth(chan, "Confirm it is you")?;
            Ok(None)
        })
    }
```

In `crates/aleph-daemon/src/admin.rs`, add before `    async fn rotate_master(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {`:

```rust
    /// Prove an enrolled method again, and nothing else (the manager's
    /// guard before it shows a secret).
    async fn reauth(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.confirm(chan))
    }
```

In `crates/aleph-daemon/src/secret/service.rs` (sessions are their openers': every use passes the caller's name), replace

```rust
    fn session(&self, p: &ObjectPath<'_>) -> Result<SessionGuard<'_>> {
        let sessions = self.sessions.lock().unwrap();
        if !sessions.contains_key(&OwnedObjectPath::from(p.to_owned())) {
            return Err(SecretError::NoSession(format!("no session {p}")));
        }
        Ok(SessionGuard {
            sessions,
            path: OwnedObjectPath::from(p.to_owned()),
        })
    }
```

with

```rust
    /// The session at `p`, if `sender` opened it: a session is its
    /// opener's (another client naming the path, such as a stale one kept
    /// across an alephd restart, where numbering starts again, gets
    /// `NoSession`).
    fn session(&self, p: &ObjectPath<'_>, sender: Option<&str>) -> Result<SessionGuard<'_>> {
        let sessions = self.sessions.lock().unwrap();
        let owner = sessions
            .get(&OwnedObjectPath::from(p.to_owned()))
            .map(|(_, owner)| owner.as_deref());
        match owner {
            Some(owner) if owner.is_none() || sender.is_none() || owner == sender => {}
            _ => return Err(SecretError::NoSession(format!("no session {p}"))),
        }
        Ok(SessionGuard {
            sessions,
            path: OwnedObjectPath::from(p.to_owned()),
        })
    }
```

replace

```rust
    fn secret_for(&self, session: &ObjectPath<'_>, item: &Item) -> Result<SecretStruct> {
        let guard = self.session(session)?;
```

with

```rust
    fn secret_for(
        &self,
        session: &ObjectPath<'_>,
        sender: Option<&str>,
        item: &Item,
    ) -> Result<SecretStruct> {
        let guard = self.session(session, sender)?;
```

replace

```rust
    fn decrypt(&self, secret: &SecretStruct) -> Result<SecretBytes> {
        let guard = self.session(&secret.0.as_ref())?;
```

with

```rust
    fn decrypt(&self, secret: &SecretStruct, sender: Option<&str>) -> Result<SecretBytes> {
        let guard = self.session(&secret.0.as_ref(), sender)?;
```

replace

```rust
    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> Result<HashMap<OwnedObjectPath, SecretStruct>> {
        let found: Vec<(OwnedObjectPath, Item)> = self.svc.keyring.read(|b| {
            items
                .iter()
                .filter_map(|p| {
                    let (c, i) = parse_item(&p.as_ref())?;
                    let item = b.collection(c)?.items.iter().find(|x| x.id == i)?;
                    Some((p.clone(), item.clone()))
                })
                .collect()
        })?;
        let mut out = HashMap::new();
        for (p, item) in found {
            out.insert(p, self.svc.secret_for(&session.as_ref(), &item)?);
        }
        Ok(out)
    }
```

with

```rust
    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, SecretStruct>> {
        let sender = hdr.sender().map(|s| s.to_string());
        let found: Vec<(OwnedObjectPath, Item)> = self.svc.keyring.read(|b| {
            items
                .iter()
                .filter_map(|p| {
                    let (c, i) = parse_item(&p.as_ref())?;
                    let item = b.collection(c)?.items.iter().find(|x| x.id == i)?;
                    Some((p.clone(), item.clone()))
                })
                .collect()
        })?;
        let mut out = HashMap::new();
        for (p, item) in found {
            out.insert(
                p,
                self.svc
                    .secret_for(&session.as_ref(), sender.as_deref(), &item)?,
            );
        }
        Ok(out)
    }
```

replace

```rust
    async fn get_secret(&self, session: OwnedObjectPath) -> Result<(SecretStruct,)> {
        let item = self.with(Item::clone)?;
        Ok((self.svc.secret_for(&session.as_ref(), &item)?,))
    }

    async fn set_secret(&self, secret: SecretStruct) -> Result<()> {
        let value = self.svc.decrypt(&secret)?;
```

with

```rust
    async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(SecretStruct,)> {
        let item = self.with(Item::clone)?;
        let sender = hdr.sender().map(|s| s.to_string());
        Ok((self
            .svc
            .secret_for(&session.as_ref(), sender.as_deref(), &item)?,))
    }

    async fn set_secret(
        &self,
        secret: SecretStruct,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<()> {
        let sender = hdr.sender().map(|s| s.to_string());
        let value = self.svc.decrypt(&secret, sender.as_deref())?;
```

replace

```rust
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
```

with

```rust
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let sender = hdr.sender().map(|s| s.to_string());
```

replace `        let value = self.svc.decrypt(&secret)?;` (in `create_item`) with `        let value = self.svc.decrypt(&secret, sender.as_deref())?;`, and add after `pub fn session_count`:

```rust
    /// Forget every session, as a restart does (the manager's tests).
    #[cfg(feature = "testing")]
    pub fn forget_sessions(&self) {
        self.sessions.lock().unwrap().clear();
    }
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon --test admin --test secret_service && cargo test -q -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `ok. 4 passed` (admin), `ok. 18 passed` (secret_service), then every aleph-daemon test binary ok.

- [ ] **Step 5: Confirm the test has teeth**

- In `admin.rs`, replace `self.converse(prompter, |k, chan| k.confirm(chan))` with `self.converse(prompter, |k, chan| { let _ = k; chan.done(true, None); Ok(()) })`; `cargo test -q -p aleph-daemon --test admin reauth_confirms` FAILS (no `Begin`, and the wrong password is accepted); undo it.
- In `service.rs`, replace `Some(owner) if owner.is_none() || sender.is_none() || owner == sender => {}` with `Some(_) => {}`; `cargo test -q -p aleph-daemon --test secret_service a_session_is_usable` FAILS; undo it.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-daemon
git commit -m "feat: Reauth; a Secret Service session serves only its opener" -m "Reauth proves an enrolled method and nothing else: the manager's guard before it shows or copies a secret. Sessions were numbered from 1 on every start and checked only for existence, so after a restart another client could be handed a stale path; now NoSession." -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: the manager's store

**Files:**
- Create: `crates/aleph-gui/src/store.rs`, `crates/aleph-gui/tests/store.rs`
- Modify: `crates/aleph-gui/Cargo.toml`, `crates/aleph-gui/src/lib.rs`

**Interfaces:**
- Consumes: Task 1's `aleph_secret_session::{ClientDh, DH, Session}`; Task 2's `Reauth`.
- Produces (all in `aleph_gui::store`):
  - `Item { path, label: String, attributes: BTreeMap<String, String>, created: u64, modified: u64 }`, `Collection { path, label: String, is_default: bool, items: Vec<Item> }` (both `Clone, Debug, PartialEq, Eq`)
  - `Vault` (`Clone, Debug, PartialEq, Eq`): `Connecting`, `Unreachable(String)`, `Locked`, `Unlocked(Vec<Collection>)`
  - `Request`: `Unlock`, `Secret(String)`, `SetLabel { path, label }`, `SetSecret { path, secret: Zeroizing<Vec<u8>> }`, `CreateItem { collection, label, attributes: BTreeMap<String, String>, secret: Zeroizing<Vec<u8>> }`, `DeleteItem(String)`, `CreateCollection(String)`, `DeleteCollection(String)`, `Reauth(OwnedFd)`; `Request::name(&self) -> &'static str`
  - `StoreEvent`: `Vault(Vault)`, `Secret { path, secret: Zeroizing<Vec<u8>>, content_type: String }`, `Done { request: &'static str, error: Option<String>, dismissed: bool }`
  - `trait Store { fn request(&self, Request); fn events(&self) -> Vec<StoreEvent>; }`; `DbusStore::start(Option<String>, impl Fn() + Send + Sync + 'static) -> DbusStore` (implements `Store`); `POLL: Duration` (2 s)
  - `Request::name`: `unlock`, `fetch the secret`, `rename`, `change the secret`, `create the item`, `delete the item`, `create the folder`, `delete the folder`, `confirm`

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-gui/Cargo.toml` with (the store's dependencies, and the daemon's test harness for its tests):

```toml
[package]
name = "aleph-gui"
description = "aleph-gui: the aleph keyring's prompter (and, later, its manager)"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true

[dependencies]
aleph-prompt-proto = { path = "../aleph-prompt-proto" }
aleph-secret-session = { path = "../aleph-secret-session" }
eframe = { version = "0.36", default-features = false, features = ["accesskit", "default_fonts", "glow", "wayland"] }
egui = "0.36"
futures-util = { version = "0.3", default-features = false }
libc.workspace = true
notify = "8"
serde.workspace = true
serde_json.workspace = true
tokio = { version = "1", features = ["rt", "macros", "sync", "time"] }
toml = "1"
zbus = { version = "5", default-features = false, features = ["tokio"] }
zeroize.workspace = true

[dev-dependencies]
aleph-daemon = { path = "../aleph-daemon", features = ["testing"] }
egui_kittest = { version = "0.36", features = ["snapshot", "wgpu"] }
tempfile.workspace = true
```

Replace `crates/aleph-gui/src/lib.rs` with:

```rust
//! `aleph-gui`: the aleph keyring's manager window (`aleph-gui`, the
//! manager spec) and the prompter alephd starts (`aleph-gui prompt`, spec
//! §7).

pub mod app;
pub mod conversation;
pub mod link;
pub mod screens;
pub mod settings;
pub mod store;
pub mod theme;
```

Write `crates/aleph-gui/tests/store.rs`:

```rust
//! The manager's store against a real alephd on a private bus (the
//! daemon's test harness: a swtpm TPM helper, scripted prompters). Never
//! the session bus.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use aleph_daemon::testing::{FromPrompter, Interactive, PW, daemon, password};
use aleph_gui::store::{Collection, DbusStore, Request, Store, StoreEvent, Vault};
use zeroize::Zeroizing;

/// A store and the events it sent that no wait has taken yet.
struct Probe {
    store: DbusStore,
    pending: std::collections::VecDeque<StoreEvent>,
}

impl Probe {
    fn new(address: &str) -> Self {
        Self {
            store: DbusStore::start(Some(address.to_string()), || {}),
            pending: Default::default(),
        }
    }

    /// The first event (sent or pending) for which `f` returns something,
    /// dropping the ones before it (or failing after 20 s).
    async fn until<T>(&mut self, mut f: impl FnMut(&StoreEvent) -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            self.pending.extend(self.store.events());
            while let Some(e) = self.pending.pop_front() {
                if let Some(t) = f(&e) {
                    return t;
                }
            }
            assert!(Instant::now() < deadline, "timed out waiting for the store");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn unlocked(&mut self, want: impl Fn(&[Collection]) -> bool) -> Vec<Collection> {
        self.until(|e| match e {
            StoreEvent::Vault(Vault::Unlocked(c)) if want(c) => Some(c.clone()),
            _ => None,
        })
        .await
    }

    async fn done(&mut self, name: &str) -> (Option<String>, bool) {
        self.until(|e| match e {
            StoreEvent::Done {
                request,
                error,
                dismissed,
            } if *request == name => Some((error.clone(), *dismissed)),
            _ => None,
        })
        .await
    }

    fn request(&self, r: Request) {
        self.store.request(r);
    }
}

fn item<'a>(c: &'a [Collection], label: &str) -> Option<&'a aleph_gui::store::Item> {
    c.iter().flat_map(|c| &c.items).find(|i| i.label == label)
}

/// Items are listed, created, shown, renamed, changed, and deleted, all
/// through the Secret Service.
#[tokio::test(flavor = "multi_thread")]
async fn items_are_listed_created_shown_changed_and_deleted() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    let cols = store.unlocked(|c| !c.is_empty()).await;
    assert!(cols[0].is_default, "{cols:?}");
    let default = cols[0].path.clone();

    store.request(Request::CreateItem {
        collection: default,
        label: "GitHub token".into(),
        attributes: BTreeMap::from([("service".into(), "github.com".into())]),
        secret: Zeroizing::new(b"s3cret".to_vec()),
    });
    assert_eq!(store.done("create the item").await, (None, false));
    let cols = store.unlocked(|c| item(c, "GitHub token").is_some()).await;
    let it = item(&cols, "GitHub token").unwrap().clone();
    assert_eq!(it.attributes["service"], "github.com");
    assert_eq!(
        it.attributes["xdg:schema"],
        "org.freedesktop.Secret.Generic"
    );

    store.request(Request::Secret(it.path.clone()));
    let secret = store
        .until(|e| match e {
            StoreEvent::Secret { path, secret, .. } if *path == it.path => Some(secret.clone()),
            _ => None,
        })
        .await;
    assert_eq!(&secret[..], b"s3cret");

    store.request(Request::SetLabel {
        path: it.path.clone(),
        label: "GitHub".into(),
    });
    assert_eq!(store.done("rename").await.0, None);
    store.unlocked(|c| item(c, "GitHub").is_some()).await;

    store.request(Request::SetSecret {
        path: it.path.clone(),
        secret: Zeroizing::new(b"n3w".to_vec()),
    });
    assert_eq!(store.done("change the secret").await.0, None);
    store.request(Request::Secret(it.path.clone()));
    let secret = store
        .until(|e| match e {
            StoreEvent::Secret { secret, .. } => Some(secret.clone()),
            _ => None,
        })
        .await;
    assert_eq!(&secret[..], b"n3w");

    store.request(Request::DeleteItem(it.path.clone()));
    assert_eq!(store.done("delete the item").await, (None, false));
    store.unlocked(|c| item(c, "GitHub").is_none()).await;
}

/// A lock shows as locked (alephd sends no signal: the store polls); an
/// unlock through alephd's prompt shows the items again.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_shows_and_an_unlock_through_the_prompt_restores() {
    let d = daemon(true, vec![vec![password(PW)]]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    d.secrets.lock().await.unwrap();
    store
        .until(|e| matches!(e, StoreEvent::Vault(Vault::Locked)).then_some(()))
        .await;
    store.request(Request::Unlock);
    assert_eq!(store.done("unlock").await, (None, false));
    store.unlocked(|c| !c.is_empty()).await;
}

/// Folders are created and deleted; alephd confirms each through its own
/// prompt (answered yes here).
#[tokio::test(flavor = "multi_thread")]
async fn folders_are_created_and_deleted_after_alephds_confirmation() {
    let yes = || vec![FromPrompter::Confirm { yes: true }];
    let d = daemon(true, vec![yes(), yes()]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    store.request(Request::CreateCollection("work".into()));
    assert_eq!(store.done("create the folder").await, (None, false));
    let cols = store
        .unlocked(|c| c.iter().any(|c| c.label == "work"))
        .await;
    let work = cols
        .iter()
        .find(|c| c.label == "work")
        .unwrap()
        .path
        .clone();
    store.request(Request::DeleteCollection(work));
    assert_eq!(store.done("delete the folder").await, (None, false));
    store
        .unlocked(|c| !c.iter().any(|c| c.label == "work"))
        .await;
}

/// `Reauth` runs on the window's end of a socketpair and changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn reauth_converses_on_the_windows_socket() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let prompter = Interactive::new(vec![password(PW)]);
    prompter.respond(ours);
    store.request(Request::Reauth(theirs.into()));
    assert_eq!(store.done("confirm").await.0, None);
    let sent = tokio::task::spawn_blocking(move || prompter.sent())
        .await
        .unwrap();
    assert!(
        matches!(
            sent.last(),
            Some(aleph_daemon::testing::ToPrompter::Done { ok: true, .. })
        ),
        "{sent:?}"
    );
}

/// After alephd forgets every session (as a restart does), a secret is
/// still shown and an item still created: the store opens a new session.
#[tokio::test(flavor = "multi_thread")]
async fn a_forgotten_session_is_replaced() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    let cols = store.unlocked(|c| !c.is_empty()).await;
    let default = cols[0].path.clone();
    let create = |label: &str| Request::CreateItem {
        collection: default.clone(),
        label: label.into(),
        attributes: BTreeMap::new(),
        secret: Zeroizing::new(b"one".to_vec()),
    };
    store.request(create("A"));
    assert_eq!(store.done("create the item").await, (None, false));
    let cols = store.unlocked(|c| item(c, "A").is_some()).await;
    let a = item(&cols, "A").unwrap().path.clone();
    store.request(Request::Secret(a.clone()));
    assert_eq!(store.done("fetch the secret").await.0, None);
    d.secrets.forget_sessions();
    store.request(Request::Secret(a));
    assert_eq!(store.done("fetch the secret").await.0, None);
    d.secrets.forget_sessions();
    store.request(create("B"));
    assert_eq!(store.done("create the item").await, (None, false));
    store.unlocked(|c| item(c, "B").is_some()).await;
}

/// Deleting the default folder (its alias goes with it) leaves the
/// keyring unlocked, not unreachable.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_the_default_folder_keeps_the_keyring_reachable() {
    let yes = || vec![FromPrompter::Confirm { yes: true }];
    let d = daemon(true, vec![yes(), yes()]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    store.request(Request::CreateCollection("work".into()));
    assert_eq!(store.done("create the folder").await, (None, false));
    let cols = store
        .unlocked(|c| c.iter().any(|c| c.label == "work"))
        .await;
    let default = cols.iter().find(|c| c.is_default).unwrap().path.clone();
    store.request(Request::DeleteCollection(default));
    assert_eq!(store.done("delete the folder").await, (None, false));
    let cols = store
        .unlocked(|c| c.iter().all(|c| !c.is_default) && c.iter().any(|c| c.label == "work"))
        .await;
    assert_eq!(cols.len(), 1);
    // And it stays so across polls.
    tokio::time::sleep(aleph_gui::store::POLL * 2).await;
    store.pending.extend(store.store.events());
    assert!(
        !store
            .pending
            .iter()
            .any(|e| matches!(e, StoreEvent::Vault(Vault::Unreachable(_)))),
        "{:?}",
        store.pending
    );
}

/// With no alephd, the store says so (and keeps trying).
#[tokio::test(flavor = "multi_thread")]
async fn without_alephd_the_store_is_unreachable() {
    let bus = aleph_daemon::testing::bus();
    let mut store = Probe::new(&bus.address);
    store
        .until(|e| matches!(e, StoreEvent::Vault(Vault::Unreachable(_))).then_some(()))
        .await;
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-gui --test store`
Expected: the build fails: `file not found for module store`.

- [ ] **Step 3: Implement**

Write `crates/aleph-gui/src/store.rs`:

```rust
//! The manager's view of the keyring (the manager spec, "Architecture"): a
//! Secret Service client, like Seahorse. Secrets reach it only through
//! `org.freedesktop.secrets`, over an encrypted session, and only when one
//! is asked for.
//!
//! The client runs on a thread of its own; the window sends [`Request`]s
//! and takes [`StoreEvent`]s, through the [`Store`] trait (the window's
//! tests use a stand-in).

use std::collections::{BTreeMap, HashMap};
use std::os::fd::OwnedFd;
use std::sync::mpsc;
use std::time::Duration;

use aleph_secret_session::{ClientDh, DH, Session};
use futures_util::{FutureExt, StreamExt};
use zbus::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

const SECRETS: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const DEFAULT_ALIAS: &str = "/org/freedesktop/secrets/aliases/default";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const SESSION: &str = "org.freedesktop.Secret.Session";
const PROMPT: &str = "org.freedesktop.Secret.Prompt";
const SESSION_COLLECTION: &str = "/org/freedesktop/secrets/collection/session";
const ADMIN_NAME: &str = "io.aleph.Keyring";
const ADMIN_PATH: &str = "/io/aleph/Admin";
const ADMIN: &str = "io.aleph.Admin1";

/// How often the lock state is checked, besides the signals alephd sends
/// (one missed, or alephd restarting, is caught within this).
pub const POLL: Duration = Duration::from_secs(2);

/// How long a burst of signals may run before the lists are fetched once.
const SETTLE: Duration = Duration::from_millis(50);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub path: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    /// Seconds since the epoch.
    pub created: u64,
    pub modified: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub path: String,
    pub label: String,
    pub is_default: bool,
    pub items: Vec<Item>,
}

/// What the keyring looks like now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Vault {
    /// Not known yet.
    Connecting,
    /// alephd cannot be reached (the reason).
    Unreachable(String),
    Locked,
    Unlocked(Vec<Collection>),
}

/// What the window asks for.
#[derive(Debug)]
pub enum Request {
    /// Ask alephd to unlock (its prompt window opens).
    Unlock,
    /// One item's secret.
    Secret(String),
    SetLabel {
        path: String,
        label: String,
    },
    SetSecret {
        path: String,
        secret: Zeroizing<Vec<u8>>,
    },
    CreateItem {
        collection: String,
        label: String,
        attributes: BTreeMap<String, String>,
        secret: Zeroizing<Vec<u8>>,
    },
    DeleteItem(String),
    CreateCollection(String),
    DeleteCollection(String),
    /// Re-authenticate (the reveal guard): alephd converses on this end
    /// of a socketpair; the window answers on the other.
    Reauth(OwnedFd),
}

impl Request {
    /// What it was, for `Done` and the log (never a secret or a label).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unlock => "unlock",
            Self::Secret(_) => "fetch the secret",
            Self::SetLabel { .. } => "rename",
            Self::SetSecret { .. } => "change the secret",
            Self::CreateItem { .. } => "create the item",
            Self::DeleteItem(_) => "delete the item",
            Self::CreateCollection(_) => "create the folder",
            Self::DeleteCollection(_) => "delete the folder",
            Self::Reauth(_) => "confirm",
        }
    }
}

/// What the store tells the window.
#[derive(Debug)]
pub enum StoreEvent {
    Vault(Vault),
    Secret {
        path: String,
        secret: Zeroizing<Vec<u8>>,
        content_type: String,
    },
    /// A request finished; `error` if it failed (a dismissed prompt is
    /// not an error: `dismissed`).
    Done {
        request: &'static str,
        error: Option<String>,
        dismissed: bool,
    },
}

pub trait Store {
    fn request(&self, request: Request);
    /// Events since the last call.
    fn events(&self) -> Vec<StoreEvent>;
}

/// The real store: a Secret Service client on its own thread.
pub struct DbusStore {
    requests: tokio::sync::mpsc::UnboundedSender<Request>,
    events: mpsc::Receiver<StoreEvent>,
}

impl DbusStore {
    /// Connect to `address` (the session bus if `None`); `wake` is called
    /// after every event (the window repaints).
    pub fn start(address: Option<String>, wake: impl Fn() + Send + Sync + 'static) -> Self {
        let (req_tx, req_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("aleph-store".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime");
                let emit = Emit {
                    tx: ev_tx,
                    wake: std::sync::Arc::new(wake),
                };
                rt.block_on(run(address, req_rx, emit));
            })
            .expect("a thread");
        Self {
            requests: req_tx,
            events: ev_rx,
        }
    }
}

impl Store for DbusStore {
    fn request(&self, request: Request) {
        let _ = self.requests.send(request);
    }

    fn events(&self) -> Vec<StoreEvent> {
        self.events.try_iter().collect()
    }
}

#[derive(Clone)]
struct Emit {
    tx: mpsc::Sender<StoreEvent>,
    wake: std::sync::Arc<dyn Fn() + Send + Sync>,
}

impl Emit {
    fn send(&self, e: StoreEvent) {
        let _ = self.tx.send(e);
        (self.wake)();
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

async fn proxy<'a>(
    conn: &Connection,
    path: &'a str,
    iface: &'a str,
) -> Result<zbus::Proxy<'a>, String> {
    zbus::proxy::Builder::new(conn)
        .destination(SECRETS)
        .map_err(err)?
        .path(path)
        .map_err(err)?
        .interface(iface)
        .map_err(err)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(err)
}

async fn connect(address: &Option<String>) -> Result<Connection, String> {
    match address {
        Some(a) => zbus::connection::Builder::address(a.as_str())
            .map_err(err)?
            .build()
            .await
            .map_err(err),
        None => Connection::session().await.map_err(err),
    }
}

/// The session: its keys, its path, and the unique name of the alephd
/// that opened it.
type Opened = (Session, OwnedObjectPath, String);

/// The client on its thread (cheap to clone: each request runs on its
/// own, and an unlock prompt may wait for the person indefinitely).
#[derive(Clone)]
struct Client {
    conn: Connection,
    /// Opened on first use, and again for another alephd (sessions do not
    /// survive a restart).
    session: std::sync::Arc<tokio::sync::Mutex<Option<Opened>>>,
}

impl Client {
    /// Who serves the Secret Service now (its unique name).
    async fn owner(&self) -> Result<String, String> {
        let dbus = zbus::fdo::DBusProxy::new(&self.conn).await.map_err(err)?;
        let name = zbus::names::BusName::try_from(SECRETS).map_err(err)?;
        Ok(dbus.get_name_owner(name).await.map_err(err)?.to_string())
    }

    /// Run `f` with the session, opened if need be, and again if another
    /// alephd serves now.
    async fn with_session<T>(
        &self,
        f: impl FnOnce(&Session, &OwnedObjectPath) -> Result<T, String>,
    ) -> Result<T, String> {
        let owner = self.owner().await?;
        let mut guard = self.session.lock().await;
        if guard.as_ref().is_some_and(|(_, _, o)| *o != owner) {
            *guard = None;
        }
        if guard.is_none() {
            let service = proxy(&self.conn, SERVICE_PATH, SERVICE).await?;
            let dh = ClientDh::new().map_err(err)?;
            let (output, path): (OwnedValue, OwnedObjectPath) = service
                .call("OpenSession", &(DH, Value::from(dh.public.clone())))
                .await
                .map_err(err)?;
            let server: Vec<u8> = output.try_into().map_err(err)?;
            *guard = Some((dh.finish(&server).map_err(err)?, path, owner));
        }
        let (session, path, _) = guard.as_ref().expect("just opened");
        f(session, path)
    }

    /// Drop the session (it failed: alephd forgot it, or it is not ours),
    /// closing it if the same alephd still serves.
    async fn reset_session(&self) {
        let old = self.session.lock().await.take();
        if let Some((_, path, owner)) = old
            && self.owner().await.is_ok_and(|o| o == owner)
            && let Ok(p) = proxy(&self.conn, path.as_str(), SESSION).await
        {
            let _ = p.call_method("Close", &()).await;
        }
    }

    /// Whether the keyring is locked. While locked alephd serves only the
    /// default alias (locked); while unlocked the alias may be gone (its
    /// folder deleted), and then the service answering is enough.
    async fn locked(&self) -> Result<bool, String> {
        let alias = proxy(&self.conn, DEFAULT_ALIAS, COLLECTION)
            .await?
            .get_property::<bool>("Locked")
            .await;
        match alias {
            Ok(locked) => Ok(locked),
            Err(_) => {
                let _: Vec<OwnedObjectPath> = proxy(&self.conn, SERVICE_PATH, SERVICE)
                    .await?
                    .get_property("Collections")
                    .await
                    .map_err(err)?;
                Ok(false)
            }
        }
    }

    async fn vault(&self) -> Vault {
        match self.snapshot().await {
            Ok(v) => v,
            Err(e) => Vault::Unreachable(e),
        }
    }

    async fn snapshot(&self) -> Result<Vault, String> {
        if self.locked().await? {
            return Ok(Vault::Locked);
        }
        let service = proxy(&self.conn, SERVICE_PATH, SERVICE).await?;
        let paths: Vec<OwnedObjectPath> = service.get_property("Collections").await.map_err(err)?;
        let default: Option<OwnedObjectPath> = service.call("ReadAlias", &("default",)).await.ok();
        let mut out = Vec::new();
        for path in paths {
            if path.as_str() == SESSION_COLLECTION || path.as_str().contains("/aliases/") {
                continue;
            }
            // (A folder or item deleted while it is listed is skipped, not
            // an error.)
            if let Some(c) = self.collection(&path, default.as_ref()).await {
                out.push(c);
            }
        }
        // The default folder first, then by label.
        out.sort_by(|a, b| {
            b.is_default
                .cmp(&a.is_default)
                .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
        });
        Ok(Vault::Unlocked(out))
    }

    async fn collection(
        &self,
        path: &OwnedObjectPath,
        default: Option<&OwnedObjectPath>,
    ) -> Option<Collection> {
        let c = proxy(&self.conn, path.as_str(), COLLECTION).await.ok()?;
        let item_paths: Vec<OwnedObjectPath> = c.get_property("Items").await.ok()?;
        let label: String = c.get_property("Label").await.ok()?;
        let mut items = Vec::new();
        for ip in item_paths {
            if let Some(i) = self.item(ip).await {
                items.push(i);
            }
        }
        items.sort_by_key(|i| i.label.to_lowercase());
        Some(Collection {
            is_default: default == Some(path),
            label,
            path: path.to_string(),
            items,
        })
    }

    /// One item's label, attributes, and times (`None` if it went).
    async fn item(&self, path: OwnedObjectPath) -> Option<Item> {
        let i = proxy(&self.conn, path.as_str(), ITEM).await.ok()?;
        let attributes: HashMap<String, String> = i.get_property("Attributes").await.ok()?;
        Some(Item {
            label: i.get_property("Label").await.ok()?,
            attributes: attributes.into_iter().collect(),
            created: i.get_property("Created").await.unwrap_or(0),
            modified: i.get_property("Modified").await.unwrap_or(0),
            path: path.to_string(),
        })
    }

    /// The secret as the session wraps it for alephd.
    async fn wrap(
        &self,
        secret: &[u8],
    ) -> Result<(OwnedObjectPath, Vec<u8>, Vec<u8>, String), String> {
        self.with_session(|session, path| {
            let (params, value) = session.encrypt(secret).map_err(err)?;
            Ok((path.clone(), params, value, "text/plain".into()))
        })
        .await
    }

    async fn fetch(&self, path: &str) -> Result<StoreEvent, String> {
        let session_path = self.with_session(|_, p| Ok(p.clone())).await?;
        type Wrapped = ((OwnedObjectPath, Vec<u8>, Vec<u8>, String),);
        let ((_, params, value, content_type),): Wrapped = proxy(&self.conn, path, ITEM)
            .await?
            .call("GetSecret", &(session_path,))
            .await
            .map_err(err)?;
        let secret = self
            .with_session(|session, _| {
                Ok(Zeroizing::new(
                    session.decrypt(&params, &value).map_err(err)?.to_vec(),
                ))
            })
            .await?;
        Ok(StoreEvent::Secret {
            path: path.to_string(),
            secret,
            content_type,
        })
    }

    async fn set_secret(&self, path: &str, secret: &[u8]) -> Result<(), String> {
        let wrapped = self.wrap(secret).await?;
        proxy(&self.conn, path, ITEM)
            .await?
            .call::<_, _, ()>("SetSecret", &(wrapped,))
            .await
            .map_err(err)
    }

    async fn create(
        &self,
        collection: &str,
        props: &HashMap<&str, Value<'_>>,
        secret: &[u8],
    ) -> Result<OwnedObjectPath, String> {
        let wrapped = self.wrap(secret).await?;
        let (_, prompt): (OwnedObjectPath, OwnedObjectPath) =
            proxy(&self.conn, collection, COLLECTION)
                .await?
                .call("CreateItem", &(props, wrapped, false))
                .await
                .map_err(err)?;
        Ok(prompt)
    }

    /// Run a prompt alephd returned ("/" for none); `true` if dismissed.
    async fn prompt(&self, prompt: &OwnedObjectPath) -> Result<bool, String> {
        if prompt.as_str() == "/" {
            return Ok(false);
        }
        let p = proxy(&self.conn, prompt.as_str(), PROMPT).await?;
        let mut completed = p.receive_signal("Completed").await.map_err(err)?;
        p.call_method("Prompt", &("",)).await.map_err(err)?;
        // (No timeout: alephd's unlock window waits for the person.)
        match completed.next().await {
            Some(msg) => {
                let (dismissed, _): (bool, OwnedValue) = msg.body().deserialize().map_err(err)?;
                Ok(dismissed)
            }
            None => Err("alephd went away during the prompt".into()),
        }
    }

    /// Carry out one request: `(dismissed, secret event)`. A request that
    /// uses the session is tried once more on a new one if it fails
    /// (alephd may have restarted and forgotten ours).
    async fn handle(&self, request: Request) -> Result<(bool, Option<StoreEvent>), String> {
        match request {
            Request::Unlock => {
                let service = proxy(&self.conn, SERVICE_PATH, SERVICE).await?;
                let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
                    .call(
                        "Unlock",
                        &(vec![ObjectPath::try_from(DEFAULT_ALIAS).map_err(err)?],),
                    )
                    .await
                    .map_err(err)?;
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::Secret(path) => {
                let secret = match self.fetch(&path).await {
                    Ok(s) => s,
                    Err(_) => {
                        self.reset_session().await;
                        self.fetch(&path).await?
                    }
                };
                Ok((false, Some(secret)))
            }
            Request::SetLabel { path, label } => {
                proxy(&self.conn, &path, ITEM)
                    .await?
                    .set_property("Label", label)
                    .await
                    .map_err(err)?;
                Ok((false, None))
            }
            Request::SetSecret { path, secret } => {
                if self.set_secret(&path, &secret).await.is_err() {
                    self.reset_session().await;
                    self.set_secret(&path, &secret).await?;
                }
                Ok((false, None))
            }
            Request::CreateItem {
                collection,
                label,
                attributes,
                secret,
            } => {
                let mut attributes: HashMap<String, String> = attributes.into_iter().collect();
                attributes
                    .entry("xdg:schema".into())
                    .or_insert_with(|| "org.freedesktop.Secret.Generic".into());
                let mut props: HashMap<&str, Value> = HashMap::new();
                props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
                props.insert(
                    "org.freedesktop.Secret.Item.Attributes",
                    Value::from(attributes),
                );
                let prompt = match self.create(&collection, &props, &secret).await {
                    Ok(p) => p,
                    Err(_) => {
                        self.reset_session().await;
                        self.create(&collection, &props, &secret).await?
                    }
                };
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::DeleteItem(path) => {
                let prompt: OwnedObjectPath = proxy(&self.conn, &path, ITEM)
                    .await?
                    .call("Delete", &())
                    .await
                    .map_err(err)?;
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::CreateCollection(label) => {
                let mut props: HashMap<&str, Value> = HashMap::new();
                props.insert(
                    "org.freedesktop.Secret.Collection.Label",
                    Value::from(label),
                );
                let (_, prompt): (OwnedObjectPath, OwnedObjectPath) =
                    proxy(&self.conn, SERVICE_PATH, SERVICE)
                        .await?
                        .call("CreateCollection", &(props, ""))
                        .await
                        .map_err(err)?;
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::DeleteCollection(path) => {
                let prompt: OwnedObjectPath = proxy(&self.conn, &path, COLLECTION)
                    .await?
                    .call("Delete", &())
                    .await
                    .map_err(err)?;
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::Reauth(fd) => {
                let admin = zbus::proxy::Builder::<zbus::Proxy>::new(&self.conn)
                    .destination(ADMIN_NAME)
                    .map_err(err)?
                    .path(ADMIN_PATH)
                    .map_err(err)?
                    .interface(ADMIN)
                    .map_err(err)?
                    .build()
                    .await
                    .map_err(err)?;
                admin
                    .call::<_, _, ()>("Reauth", &(zbus::zvariant::OwnedFd::from(fd),))
                    .await
                    .map_err(err)?;
                Ok((false, None))
            }
        }
    }
}

async fn run(
    address: Option<String>,
    mut requests: tokio::sync::mpsc::UnboundedReceiver<Request>,
    emit: Emit,
) {
    emit.send(StoreEvent::Vault(Vault::Connecting));
    let conn = loop {
        match connect(&address).await {
            Ok(c) => break c,
            Err(e) => {
                emit.send(StoreEvent::Vault(Vault::Unreachable(e)));
                tokio::time::sleep(POLL).await;
            }
        }
    };
    // Signals from whoever serves the Secret Service (alephd): any of them
    // means the lists may have changed.
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(SECRETS)
        .expect("a valid name")
        .path_namespace(SERVICE_PATH)
        .expect("a valid path")
        .build();
    let mut signals = zbus::MessageStream::for_match_rule(rule, &conn, Some(256))
        .await
        .ok();
    let client = Client {
        conn: conn.clone(),
        session: Default::default(),
    };
    // Requests ask for a fresh listing when they end; only this loop lists,
    // so what it last sent is always what the window shows.
    let (refresh_tx, mut refresh) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut last = client.vault().await;
    emit.send(StoreEvent::Vault(last.clone()));
    let mut poll = tokio::time::interval(POLL);
    loop {
        let changed = tokio::select! {
            r = requests.recv() => {
                let Some(r) = r else { return };
                let (client, emit, refresh_tx) = (client.clone(), emit.clone(), refresh_tx.clone());
                tokio::spawn(async move {
                    let name = r.name();
                    match client.handle(r).await {
                        Ok((dismissed, secret)) => {
                            if let Some(s) = secret {
                                emit.send(s);
                            }
                            emit.send(StoreEvent::Done { request: name, error: None, dismissed });
                        }
                        Err(e) => {
                            // (Operations and reasons only: never a secret
                            // or a label.)
                            eprintln!("aleph-gui: cannot {name}: {e}");
                            emit.send(StoreEvent::Done { request: name, error: Some(e), dismissed: false });
                        }
                    }
                    let _ = refresh_tx.send(());
                });
                false
            }
            Some(()) = refresh.recv() => true,
            m = async {
                match &mut signals {
                    Some(s) => s.next().await,
                    None => std::future::pending().await,
                }
            } => {
                // (A burst of signals means one listing.)
                tokio::time::sleep(SETTLE).await;
                if let Some(s) = &mut signals {
                    while let Some(Some(_)) = s.next().now_or_never() {}
                }
                m.is_some()
            }
            // (Only the lock state is polled: listing every item each time
            // would cost a few calls per item.)
            _ = poll.tick() => {
                let locked = client.locked().await.ok();
                let known = match &last {
                    Vault::Locked => Some(true),
                    Vault::Unlocked(_) => Some(false),
                    _ => None,
                };
                locked.is_none() || locked != known
            }
        };
        if changed {
            let v = client.vault().await;
            if v != last {
                last = v.clone();
                emit.send(StoreEvent::Vault(v));
            }
        }
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-gui --test store && cargo test -q -p aleph-gui && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `ok. 7 passed` (store), then every aleph-gui test binary ok (the library's 20 unit tests unchanged).

- [ ] **Step 5: Confirm the tests have teeth**

Make each change in `store.rs`, run the named test and see it FAIL, then undo it:

- **the generic schema** (`items_are_listed`): replace `.or_insert_with(|| "org.freedesktop.Secret.Generic".into());` with `.or_insert_with(String::new);`.
- **a new session after a failure** (`a_forgotten_session_is_replaced`): in `Request::Secret`'s arm, replace the `Err(_) => { self.reset_session().await; self.fetch(&path).await? }` arm with `Err(e) => return Err(e),`.
- **the default alias gone** (`deleting_the_default_folder_keeps_the_keyring_reachable`): in `locked`, make an `Err` from the alias's `Locked` an error (`Err(e) => Err(err(e)),`) instead of asking the service.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/aleph-gui
git commit -m "feat(gui): the manager's store, a Secret Service client" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 4: the confirmation clock and the clipboard

**Files:**
- Create: `crates/aleph-gui/src/reauth.rs`, `crates/aleph-gui/src/clipboard.rs`
- Modify: `crates/aleph-gui/Cargo.toml` (`wl-clipboard-rs`), `crates/aleph-gui/src/lib.rs`

**Interfaces:**
- Produces: `reauth::{HOLD, Reauth}` with `Reauth::{needed(&self, Instant) -> bool, confirmed(&mut self, Instant), forget(&mut self)}` (`Default`); `clipboard::{KEEP, HINT_TYPE, HINT, Backend, Clipboard, Wayland}` with `trait Backend: Send + 'static { fn offer(&mut self, Zeroizing<Vec<u8>>) -> Result<(), String>; fn still_ours(&self) -> bool; fn clear(&mut self); }`, `Clipboard::{new(B) -> Self, with_keep(B, Duration) -> Self, copy(&self, Zeroizing<Vec<u8>>) -> Result<(), String>}` (the clearing runs on its own timer thread), `Wayland: Default + Backend`.

- [ ] **Step 1: Write the failing tests**

In `crates/aleph-gui/Cargo.toml`, after `toml = "1"`, add:

```toml
wl-clipboard-rs = "0.9"
```

Replace `crates/aleph-gui/src/lib.rs` with:

```rust
//! `aleph-gui`: the aleph keyring's manager window (`aleph-gui`, the
//! manager spec) and the prompter alephd starts (`aleph-gui prompt`, spec
//! §7).

pub mod app;
pub mod clipboard;
pub mod conversation;
pub mod link;
pub mod reauth;
pub mod screens;
pub mod settings;
pub mod store;
pub mod theme;
```

Write `crates/aleph-gui/src/reauth.rs` with only its tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_confirmation_holds_five_minutes_and_not_past_a_lock() {
        let t = Instant::now();
        let mut r = Reauth::default();
        assert!(r.needed(t));
        r.confirmed(t);
        assert!(!r.needed(t + Duration::from_secs(299)));
        assert!(r.needed(t + HOLD));
        r.confirmed(t);
        r.forget();
        assert!(r.needed(t));
    }
}
```

Write `crates/aleph-gui/src/clipboard.rs` with only its tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct State {
        held: Option<Vec<u8>>,
        replaced: bool,
        cleared: usize,
    }

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<State>>);

    impl Backend for Fake {
        fn offer(&mut self, secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
            let mut s = self.0.lock().unwrap();
            s.held = Some(secret.to_vec());
            s.replaced = false;
            Ok(())
        }
        fn still_ours(&self) -> bool {
            let s = self.0.lock().unwrap();
            s.held.is_some() && !s.replaced
        }
        fn clear(&mut self) {
            let mut s = self.0.lock().unwrap();
            s.held = None;
            s.cleared += 1;
        }
    }

    const KEEP: Duration = Duration::from_millis(60);

    /// Cleared by its own timer: no frame, no call, needed.
    #[test]
    fn a_copy_is_cleared_after_its_time_without_the_window() {
        let fake = Fake::default();
        let c = Clipboard::with_keep(fake.clone(), KEEP);
        c.copy(Zeroizing::new(b"pw".to_vec())).unwrap();
        assert!(fake.0.lock().unwrap().held.is_some());
        std::thread::sleep(KEEP * 3);
        let s = fake.0.lock().unwrap();
        assert!(s.held.is_none());
        assert_eq!(s.cleared, 1);
    }

    /// Something another program copied since is not cleared.
    #[test]
    fn a_copy_replaced_since_is_left_alone() {
        let fake = Fake::default();
        let c = Clipboard::with_keep(fake.clone(), KEEP);
        c.copy(Zeroizing::new(b"pw".to_vec())).unwrap();
        fake.0.lock().unwrap().replaced = true;
        std::thread::sleep(KEEP * 3);
        assert_eq!(fake.0.lock().unwrap().cleared, 0);
    }

    /// A newer copy is not cleared by an older copy's timer.
    #[test]
    fn a_newer_copy_keeps_its_own_time() {
        let fake = Fake::default();
        let c = Clipboard::with_keep(fake.clone(), KEEP);
        c.copy(Zeroizing::new(b"one".to_vec())).unwrap();
        std::thread::sleep(KEEP / 2);
        c.copy(Zeroizing::new(b"two".to_vec())).unwrap();
        std::thread::sleep(KEEP * 3 / 4);
        // (The first timer fired: the second copy stays.)
        assert_eq!(fake.0.lock().unwrap().held.as_deref(), Some(&b"two"[..]));
        std::thread::sleep(KEEP * 2);
        assert!(fake.0.lock().unwrap().held.is_none());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-gui --lib`
Expected: the build fails: `Reauth`, `HOLD`, `Backend`, `Clipboard`, and `KEEP` do not exist.

- [ ] **Step 3: Implement**

Put this above the tests in `crates/aleph-gui/src/reauth.rs`:

```rust
//! The reveal guard's clock (the manager spec, "What each action does"):
//! a confirmation holds for 5 minutes, and not past a lock. A guard
//! against a glance, not security: any program running as the user can
//! read secrets.

use std::time::{Duration, Instant};

/// How long a confirmation holds.
pub const HOLD: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Default)]
pub struct Reauth {
    confirmed: Option<Instant>,
}

impl Reauth {
    /// Whether showing or copying needs a confirmation first.
    pub fn needed(&self, now: Instant) -> bool {
        self.confirmed
            .is_none_or(|at| now.duration_since(at) >= HOLD)
    }

    pub fn confirmed(&mut self, now: Instant) {
        self.confirmed = Some(now);
    }

    /// The keyring locked (or the window closes): confirm again.
    pub fn forget(&mut self) {
        self.confirmed = None;
    }
}
```

Put this above the tests in `crates/aleph-gui/src/clipboard.rs`:

```rust
//! Copying a secret (the manager spec): offered with the hint
//! clipboard-history tools honor (`x-kde-passwordManagerHint: secret`),
//! and cleared after 30 s if the clipboard still holds it. The clearing
//! runs on a timer thread of its own, not with the window's frames: a
//! window on a hidden workspace draws none.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::Zeroizing;

/// How long a copied secret stays on the clipboard.
pub const KEEP: Duration = Duration::from_secs(30);

/// The MIME type clipboard-history tools (cliphist, KDE's Klipper,
/// others) check, and the value that tells them to skip the copy.
pub const HINT_TYPE: &str = "x-kde-passwordManagerHint";
pub const HINT: &[u8] = b"secret";

/// The clipboard itself.
pub trait Backend: Send + 'static {
    /// Offer `secret` as text (with the hint).
    fn offer(&mut self, secret: Zeroizing<Vec<u8>>) -> Result<(), String>;
    /// Whether the clipboard still holds our offer.
    fn still_ours(&self) -> bool;
    fn clear(&mut self);
}

/// Copies with an expiry.
pub struct Clipboard<B: Backend> {
    backend: Arc<Mutex<B>>,
    /// Which copy is the latest (a timer clears only its own).
    copies: Arc<AtomicU64>,
    keep: Duration,
}

impl<B: Backend> Clipboard<B> {
    pub fn new(backend: B) -> Self {
        Self::with_keep(backend, KEEP)
    }

    /// With another expiry (the tests').
    pub fn with_keep(backend: B, keep: Duration) -> Self {
        Self {
            backend: Arc::new(Mutex::new(backend)),
            copies: Arc::default(),
            keep,
        }
    }

    /// Offer `secret`, and clear it after the expiry if it is still ours
    /// and nothing was copied through here since.
    pub fn copy(&self, secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
        self.backend
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .offer(secret)?;
        let this = self.copies.fetch_add(1, Ordering::SeqCst) + 1;
        let (backend, copies, keep) = (self.backend.clone(), self.copies.clone(), self.keep);
        std::thread::Builder::new()
            .name("aleph-clipboard".into())
            .spawn(move || {
                std::thread::sleep(keep);
                if copies.load(Ordering::SeqCst) != this {
                    return;
                }
                let mut b = backend.lock().unwrap_or_else(|e| e.into_inner());
                if b.still_ours() {
                    b.clear();
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// The Wayland clipboard (the wlr data-control protocol, which Hyprland
/// has). The offer is served from a thread until another program takes
/// the clipboard or it is cleared (or the manager exits: the copy goes
/// with it); the served copy is the crate's, and is not zeroized (the
/// manager spec: not guaranteed).
#[derive(Default)]
pub struct Wayland {
    serving: Arc<std::sync::atomic::AtomicBool>,
}

impl Backend for Wayland {
    fn offer(&mut self, secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
        use wl_clipboard_rs::copy::{MimeSource, MimeType, Options, Source};
        let sources = vec![
            MimeSource {
                source: Source::Bytes(secret.to_vec().into_boxed_slice()),
                mime_type: MimeType::Text,
            },
            MimeSource {
                source: Source::Bytes(HINT.into()),
                mime_type: MimeType::Specific(HINT_TYPE.into()),
            },
        ];
        let mut options = Options::new();
        options.foreground(true);
        let prepared = options
            .prepare_copy_multi(sources)
            .map_err(|e| e.to_string())?;
        let serving = Arc::new(std::sync::atomic::AtomicBool::new(true));
        self.serving = serving.clone();
        std::thread::spawn(move || {
            // Returns once the offer is replaced or cleared.
            let _ = prepared.serve();
            serving.store(false, Ordering::SeqCst);
        });
        Ok(())
    }

    fn still_ours(&self) -> bool {
        self.serving.load(Ordering::SeqCst)
    }

    fn clear(&mut self) {
        use wl_clipboard_rs::copy::{ClipboardType, Seat, clear};
        let _ = clear(ClipboardType::Regular, Seat::All);
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-gui --lib && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `ok. 24 passed`.

- [ ] **Step 5: Confirm the tests have teeth**

- `clipboard.rs`: replace `                if b.still_ours() {` with `                if true {`; `cargo test -q -p aleph-gui --lib a_copy_replaced` FAILS; undo it.
- `clipboard.rs`: replace `                if copies.load(Ordering::SeqCst) != this {` with `                if true {`; `cargo test -q -p aleph-gui --lib a_copy_is_cleared` FAILS (nothing clears); undo it.
- `reauth.rs`: replace `.is_none_or(|at| now.duration_since(at) >= HOLD)` with `.is_none_or(|_| false)`; `cargo test -q -p aleph-gui --lib a_confirmation_holds` FAILS; undo it.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/aleph-gui
git commit -m "feat(gui): the confirmation clock and the clipboard (hinted, cleared after 30 s on its own timer)" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 5: the manager window

**Files:**
- Create: `crates/aleph-gui/src/manager.rs`, `crates/aleph-gui/tests/manager.rs`, `crates/aleph-gui/tests/snapshots/manager_*.png` (generated)
- Modify: `crates/aleph-gui/src/app.rs` (`embedded`, the shared watcher), `crates/aleph-gui/src/theme.rs` (`Watch`), `crates/aleph-gui/src/main.rs` (no arguments: the manager), `crates/aleph-gui/src/lib.rs`, `crates/aleph-gui/tests/binary.rs`

**Interfaces:**
- Consumes: Task 3's store types; Task 4's `Reauth`, `Clipboard`, `Backend`, `Wayland`; Plan 5a's `PromptApp`, `conversation::{Screen, shown}`, `link::spawn_reader`, `theme`, `settings`.
- Produces: `manager::{SIZE, Manager, Selection, Want, Shown, Mode, date}` (`Mode::Edit { path, label, secret: Option<Zeroizing<String>>, original: Option<Zeroizing<String>> }`); `Manager::new(S, B, Settings, Option<PathBuf>, bool) -> Self`, `Manager::frame(&mut self, &mut egui::Ui)`, `Manager::watch_theme(&mut self, &egui::Context)`, public fields `store`, `clipboard`, `reauth`, `vault`, `search`, `selected`, `shown`, `mode`, `status`, `confirm_guard`, `saving`, `palette`; `impl eframe::App`. `PromptApp.embedded: bool` (it also paints no scanlines of its own then). `theme::Watch::{start(&Path, &egui::Context) -> Option<Watch>, changed(&self) -> bool}`.

- [ ] **Step 1: Write the failing tests**

Replace `crates/aleph-gui/src/lib.rs` with:

```rust
//! `aleph-gui`: the aleph keyring's manager window (`aleph-gui`, the
//! manager spec) and the prompter alephd starts (`aleph-gui prompt`, spec
//! §7).

pub mod app;
pub mod clipboard;
pub mod conversation;
pub mod link;
pub mod manager;
pub mod reauth;
pub mod screens;
pub mod settings;
pub mod store;
pub mod theme;
```

Write `crates/aleph-gui/tests/manager.rs`:

```rust
//! The manager window, driven as a person would (egui_kittest), against a
//! stand-in store and clipboard; snapshots of its views in both themes.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use aleph_daemon::prompt::{Channel, FromPrompter, Method, Purpose, ToPrompter};
use aleph_gui::clipboard::Backend;
use aleph_gui::manager::{Manager, SIZE};
use aleph_gui::settings::{Settings, ThemeChoice};
use aleph_gui::store::{Collection, Item, Request, Store, StoreEvent, Vault};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use zeroize::Zeroizing;

/// The store's stand-in: requests are recorded, events are queued by the
/// test.
#[derive(Clone, Default)]
struct Fake {
    requests: Rc<RefCell<Vec<Request>>>,
    events: Rc<RefCell<Vec<StoreEvent>>>,
}

impl Store for Fake {
    fn request(&self, r: Request) {
        self.requests.borrow_mut().push(r);
    }
    fn events(&self) -> Vec<StoreEvent> {
        self.events.borrow_mut().drain(..).collect()
    }
}

impl Fake {
    fn send(&self, e: StoreEvent) {
        self.events.borrow_mut().push(e);
    }
    fn take(&self) -> Vec<Request> {
        self.requests.borrow_mut().drain(..).collect()
    }
}

#[derive(Clone, Default)]
struct Clip(std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>);

impl Backend for Clip {
    fn offer(&mut self, secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(secret.to_vec());
        Ok(())
    }
    fn still_ours(&self) -> bool {
        self.0.lock().unwrap().is_some()
    }
    fn clear(&mut self) {
        *self.0.lock().unwrap() = None;
    }
}

type Window = Harness<'static, Manager<Fake, Clip>>;

fn item(path: &str, label: &str, attrs: &[(&str, &str)]) -> Item {
    Item {
        path: path.into(),
        label: label.into(),
        attributes: attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        created: 1_790_553_600,
        modified: 1_790_553_600,
    }
}

fn vault() -> Vault {
    Vault::Unlocked(vec![
        Collection {
            path: "/c/login".into(),
            label: "Login".into(),
            is_default: true,
            items: vec![
                item(
                    "/c/login/1",
                    "GitHub token",
                    &[("service", "github.com"), ("user", "kyle")],
                ),
                item(
                    "/c/login/2",
                    "Mail app password",
                    &[("service", "imap.example.org")],
                ),
            ],
        },
        Collection {
            path: "/c/work".into(),
            label: "work".into(),
            is_default: false,
            items: vec![item("/c/work/1", "VPN", &[("service", "vpn")])],
        },
    ])
}

fn window(theme: ThemeChoice, v: Vault) -> (Window, Fake, Clip) {
    let store = Fake::default();
    let clip = Clip::default();
    let home = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/home");
    let settings = Settings {
        theme,
        scanlines: true,
    };
    let mut m = Manager::new(store.clone(), clip.clone(), settings, Some(home), true);
    m.confirm_guard = Duration::ZERO;
    let palette = m.palette.clone();
    store.send(StoreEvent::Vault(v));
    let mut h = Harness::builder()
        .with_size(egui::Vec2::from(SIZE))
        .build_ui_state(|ui, m: &mut Manager<Fake, Clip>| m.frame(ui), m);
    aleph_gui::theme::apply(&h.ctx, &palette);
    frames(&mut h);
    (h, store, clip)
}

fn frames(h: &mut Window) {
    h.run_steps(4);
}

/// Let the reader thread deliver (the confirmation is asynchronous).
fn settle(h: &mut Window) {
    for _ in 0..40 {
        h.step();
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn type_into(h: &mut Window, label: &str, text: &str) {
    h.get_by_label(label).focus();
    frames(h);
    h.get_by_label(label).type_text(text);
    frames(h);
}

/// Play alephd on the confirmation's socket: ask for the password, and
/// answer whether it was `pw`.
fn alephd_confirms(fd: std::os::fd::OwnedFd, pw: &'static str) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
        chan.send(&ToPrompter::Begin {
            purpose: Purpose::Reauth,
            operation: "Confirm it is you".into(),
            caller: None,
        })
        .unwrap();
        let reply = chan
            .ask(&ToPrompter::Ask {
                methods: vec![Method::Password],
                error: None,
                retry_after: None,
            })
            .unwrap();
        let ok = matches!(reply, FromPrompter::Password { password } if password.expose() == pw);
        chan.done(ok, None);
        ok
    })
}

fn only(requests: Vec<Request>) -> Request {
    assert_eq!(requests.len(), 1, "{requests:?}");
    requests.into_iter().next().unwrap()
}

#[test]
fn folders_and_items_are_listed_and_searched() {
    let (mut h, _, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("Login (default)");
    h.get_by_label("GitHub token");
    h.get_by_label("VPN");
    type_into(&mut h, "Search", "imap");
    assert!(h.query_by_label("GitHub token").is_none());
    h.get_by_label("Mail app password");
}

/// Showing a secret confirms it is you first, then fetches it; within 5
/// minutes a second show does not ask again.
#[test]
fn a_secret_is_shown_after_the_confirmation() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    let Request::Reauth(fd) = only(store.take()) else {
        panic!("no confirmation");
    };
    let alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(alephd.join().unwrap());
    settle(&mut h);
    match only(store.take()) {
        Request::Secret(p) => assert_eq!(p, "/c/login/1"),
        other => panic!("{other:?}"),
    }
    store.send(StoreEvent::Secret {
        path: "/c/login/1".into(),
        secret: Zeroizing::new(b"ghp_s3cret".to_vec()),
        content_type: "text/plain".into(),
    });
    frames(&mut h);
    h.get_by_label("ghp_s3cret");
    h.get_by_label("HIDE").click();
    frames(&mut h);
    assert!(h.query_by_label("ghp_s3cret").is_none());
    // Within 5 minutes: fetched at once.
    h.get_by_label("SHOW").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Secret(_)));
}

/// A refused confirmation fetches nothing.
#[test]
fn a_refused_confirmation_fetches_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    let Request::Reauth(fd) = only(store.take()) else {
        panic!("no confirmation");
    };
    let alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "wrong");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(!alephd.join().unwrap());
    settle(&mut h);
    assert!(store.take().is_empty());
}

/// A copy goes to the clipboard (and nowhere on screen).
#[test]
fn a_copy_goes_to_the_clipboard() {
    let (mut h, store, clip) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("COPY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Secret(_)));
    store.send(StoreEvent::Secret {
        path: "/c/login/1".into(),
        secret: Zeroizing::new(b"ghp_s3cret".to_vec()),
        content_type: "text/plain".into(),
    });
    frames(&mut h);
    assert_eq!(clip.0.lock().unwrap().as_deref(), Some(&b"ghp_s3cret"[..]));
    assert!(h.query_by_label("ghp_s3cret").is_none());
    h.get_by_label_contains("COPIED");
}

/// Editing the label saves only the label (the secret was never loaded).
#[test]
fn an_edited_label_is_saved() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    type_into(&mut h, "Label", " (work)");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    match only(store.take()) {
        Request::SetLabel { path, label } => {
            assert_eq!(path, "/c/login/1");
            assert_eq!(label, "GitHub token (work)");
        }
        other => panic!("{other:?}"),
    }
}

/// A new item goes to the selected folder, with the attributes typed.
#[test]
fn a_new_item_is_created_in_the_folder() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("work").click();
    frames(&mut h);
    h.get_by_label("+ ITEM").click();
    frames(&mut h);
    type_into(&mut h, "Label", "Router");
    type_into(&mut h, "Secret", "admin123");
    h.get_by_label("+ ATTRIBUTE").click();
    frames(&mut h);
    type_into(&mut h, "Attribute 1 key", "host");
    type_into(&mut h, "Attribute 1 value", "192.168.1.1");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    match only(store.take()) {
        Request::CreateItem {
            collection,
            label,
            attributes,
            secret,
        } => {
            assert_eq!(collection, "/c/work");
            assert_eq!(label, "Router");
            assert_eq!(
                attributes,
                BTreeMap::from([("host".into(), "192.168.1.1".into())])
            );
            assert_eq!(&secret[..], b"admin123");
        }
        other => panic!("{other:?}"),
    }
}

/// Delete asks first; No deletes nothing.
#[test]
fn delete_asks_first() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("VPN").click();
    frames(&mut h);
    h.get_by_label("DELETE").click();
    frames(&mut h);
    h.get_by_label("Delete 'VPN'?");
    h.get_by_label("No").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    h.get_by_label("DELETE").click();
    frames(&mut h);
    h.get_by_label("Yes").click();
    frames(&mut h);
    match only(store.take()) {
        Request::DeleteItem(p) => assert_eq!(p, "/c/work/1"),
        other => panic!("{other:?}"),
    }
}

/// A lock hides what is shown and forgets the confirmation; Unlock asks
/// alephd.
#[test]
fn a_lock_seals_the_window() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    store.take();
    store.send(StoreEvent::Secret {
        path: "/c/login/1".into(),
        secret: Zeroizing::new(b"ghp_s3cret".to_vec()),
        content_type: "text/plain".into(),
    });
    frames(&mut h);
    h.get_by_label("ghp_s3cret");
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    assert!(h.query_by_label("ghp_s3cret").is_none());
    assert!(h.state().reauth.needed(Instant::now()));
    h.get_by_label("VAULT SEALED");
    h.get_by_label("UNLOCK").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    // Unlocked again: the secret is not back until shown (and confirmed).
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    assert!(h.query_by_label("ghp_s3cret").is_none());
}

/// A secret that is not text is not shown (its length is), and can still
/// be copied.
#[test]
fn a_binary_secret_is_not_shown() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    store.take();
    store.send(StoreEvent::Secret {
        path: "/c/login/1".into(),
        secret: Zeroizing::new(vec![0xff, 0xfe, 0x00, 0x01]),
        content_type: "application/octet-stream".into(),
    });
    frames(&mut h);
    h.get_by_label("binary secret, 4 bytes");
}

/// A label another program chose (long, with line breaks of its own) is
/// shown on one line, cut short, in the list.
#[test]
fn a_hostile_label_stays_on_one_line_in_the_list() {
    let label = format!("GitHub\n\nALEPH // UNLOCK VAULT\n{}", "w".repeat(500));
    let v = Vault::Unlocked(vec![Collection {
        path: "/c/login".into(),
        label: "Login".into(),
        is_default: true,
        items: vec![item("/c/login/1", &label, &[])],
    }]);
    let (h, _, _) = window(ThemeChoice::Neon, v);
    let row = h.get_by_label_contains("GitHub");
    let text = row.accesskit_node().label().unwrap_or_default().to_string();
    assert!(!text.contains('\n'), "{text:?}");
    assert!(text.chars().count() <= 61, "{}", text.chars().count());
}

fn secret(store: &Fake, path: &str, bytes: &[u8]) {
    store.send(StoreEvent::Secret {
        path: path.into(),
        secret: Zeroizing::new(bytes.to_vec()),
        content_type: "text/plain".into(),
    });
}

fn done(store: &Fake, request: &'static str, error: Option<&str>) {
    store.send(StoreEvent::Done {
        request,
        error: error.map(Into::into),
        dismissed: false,
    });
}

/// After LOAD SECRET, a save sends only what changed: an unchanged secret
/// is not rewritten.
#[test]
fn a_loaded_secret_is_saved_only_if_changed() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    h.get_by_label("LOAD SECRET").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Secret(_)));
    secret(&store, "/c/login/1", b"ghp_s3cret");
    frames(&mut h);
    type_into(&mut h, "Label", "!");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::SetLabel { .. }));
}

/// A secret that is not text is not loaded into the editor.
#[test]
fn a_binary_secret_is_not_editable() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    h.get_by_label("LOAD SECRET").click();
    frames(&mut h);
    store.take();
    secret(&store, "/c/login/1", &[0xff, 0xfe]);
    frames(&mut h);
    assert!(h.query_by_label("Secret").is_none());
    h.get_by_label_contains("not editable");
}

/// A save that fails keeps the form, with what was typed; one that
/// succeeds closes it.
#[test]
fn a_failed_save_keeps_the_form() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("+ ITEM").click();
    frames(&mut h);
    type_into(&mut h, "Label", "Router");
    type_into(&mut h, "Secret", "admin123");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::CreateItem { .. }));
    h.get_by_label("SAVING…");
    done(
        &store,
        "create the item",
        Some("org.freedesktop.Secret.Error.IsLocked"),
    );
    frames(&mut h);
    assert_eq!(h.get_by_label("Label").value().as_deref(), Some("Router"));
    h.get_by_label_contains("cannot create the item");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::CreateItem { .. }));
    done(&store, "create the item", None);
    frames(&mut h);
    assert!(h.query_by_label("Label").is_none());
}

/// A secret typed into the editor survives a lock, and is saved after the
/// unlock.
#[test]
fn a_typed_secret_survives_a_lock() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    h.get_by_label("LOAD SECRET").click();
    frames(&mut h);
    store.take();
    secret(&store, "/c/login/1", b"old");
    frames(&mut h);
    type_into(&mut h, "Secret", "new");
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    h.get_by_label("SAVE").click();
    frames(&mut h);
    match only(store.take()) {
        Request::SetSecret { secret, .. } => assert_eq!(&secret[..], b"oldnew"),
        other => panic!("{other:?}"),
    }
}

/// Enter on the delete question answers its default: No.
#[test]
fn enter_on_the_delete_question_says_no() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("VPN").click();
    frames(&mut h);
    h.get_by_label("DELETE").click();
    frames(&mut h);
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(store.take().is_empty());
    assert!(h.query_by_label("Delete 'VPN'?").is_none());
}

#[test]
fn without_alephd_the_link_is_down() {
    let (h, _, _) = window(ThemeChoice::Neon, Vault::Unreachable("no such name".into()));
    h.get_by_label("LINK DOWN");
}

/// Every view, in both themes.
#[test]
fn snapshots() {
    let mut failures = Vec::new();
    for (theme, suffix) in [(ThemeChoice::Neon, "neon"), (ThemeChoice::Auto, "omarchy")] {
        let mut shot = |h: &mut Window, name: &str| {
            if let Err(e) = h.try_snapshot(format!("manager_{name}_{suffix}")) {
                failures.push(e.to_string());
            }
        };
        let (mut h, store, _) = window(theme, vault());
        shot(&mut h, "empty");
        h.get_by_label("GitHub token").click();
        frames(&mut h);
        shot(&mut h, "item");
        h.state_mut().reauth.confirmed(Instant::now());
        h.get_by_label("SHOW").click();
        frames(&mut h);
        store.take();
        store.send(StoreEvent::Secret {
            path: "/c/login/1".into(),
            secret: Zeroizing::new(b"ghp_s3cret".to_vec()),
            content_type: "text/plain".into(),
        });
        frames(&mut h);
        shot(&mut h, "shown");
        h.get_by_label("EDIT").click();
        frames(&mut h);
        shot(&mut h, "edit");
        h.get_by_label("CANCEL").click();
        frames(&mut h);
        h.get_by_label("+ ITEM").click();
        frames(&mut h);
        shot(&mut h, "new");
        // The confirmation, drawn inside the window (alephd has asked).
        let (mut h, store, _) = window(theme, vault());
        h.get_by_label("GitHub token").click();
        frames(&mut h);
        h.get_by_label("SHOW").click();
        frames(&mut h);
        let Request::Reauth(fd) = only(store.take()) else {
            panic!("no confirmation");
        };
        let alephd = std::thread::spawn(move || {
            let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
            chan.send(&ToPrompter::Begin {
                purpose: Purpose::Reauth,
                operation: "Confirm it is you".into(),
                caller: None,
            })
            .unwrap();
            chan.send(&ToPrompter::Ask {
                methods: vec![Method::Password],
                error: None,
                retry_after: None,
            })
            .unwrap();
            chan
        });
        let chan = alephd.join().unwrap();
        settle(&mut h);
        shot(&mut h, "confirm");
        drop(chan);
        let (mut h, _, _) = window(theme, Vault::Locked);
        shot(&mut h, "locked");
        let (mut h, _, _) = window(
            theme,
            Vault::Unreachable("org.freedesktop.secrets has no owner".into()),
        );
        shot(&mut h, "unreachable");
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
```

Replace `crates/aleph-gui/tests/binary.rs` with (no arguments is now the manager: an unknown argument prints the usage, and the manager's own test never reaches the real display):

```rust
//! `aleph-gui prompt` as alephd starts it. No display is ever reached:
//! each run gets a Wayland socket name that does not exist.

use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

/// The prompter, with a private runtime directory and no display.
fn prompter(runtime: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_aleph-gui"));
    c.arg("prompt")
        .env("XDG_RUNTIME_DIR", runtime)
        .env("WAYLAND_DISPLAY", "aleph-test-no-such-display")
        .env_remove("DISPLAY")
        .env_remove("ALEPH_PROMPT_FD");
    c
}

/// Run with `fd` (any descriptor) as descriptor 10 and `ALEPH_PROMPT_FD=10`.
fn with_fd(mut c: Command, fd: i32) -> Output {
    c.env("ALEPH_PROMPT_FD", "10");
    // SAFETY: dup2 and fcntl are async-signal-safe; they only touch the
    // descriptor in the child. (Close-on-exec is cleared explicitly: when
    // `fd` already is 10, dup2 does nothing and would leave it set.)
    unsafe {
        c.pre_exec(move || {
            if libc::dup2(fd, 10) < 0 || libc::fcntl(10, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c.output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn without_alephd_it_explains_and_exits() {
    let dir = tempfile::tempdir().unwrap();
    let o = prompter(dir.path()).output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(
        stderr(&o).contains("ALEPH_PROMPT_FD is not set"),
        "{}",
        stderr(&o)
    );

    let o = Command::new(env!("CARGO_BIN_EXE_aleph-gui"))
        .arg("frobnicate")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("usage"), "{}", stderr(&o));
}

/// With no arguments it is the manager; with no display to open, it says
/// so and exits. (Never the real display: a socket name that does not
/// exist, a private runtime directory, and no session bus.)
#[test]
fn the_manager_without_a_display_exits() {
    let dir = tempfile::tempdir().unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_aleph-gui"))
        .env("XDG_RUNTIME_DIR", dir.path())
        .env("WAYLAND_DISPLAY", "aleph-test-no-such-display")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env_remove("DISPLAY")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("cannot open the window"),
        "{}",
        stderr(&o)
    );
}

/// Only a socket is taken: not a standard stream, not a file.
#[test]
fn anything_but_a_socket_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let o = prompter(dir.path())
        .env("ALEPH_PROMPT_FD", "1")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("standard stream"), "{}", stderr(&o));

    let file = std::fs::File::create(dir.path().join("f")).unwrap();
    let o = with_fd(prompter(dir.path()), file.as_raw_fd());
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("not a socket"), "{}", stderr(&o));
}

/// With no display to open, it exits without answering: alephd reads the
/// closed socket as "no prompter", and the prompt waits for an unlock from
/// elsewhere (a Cancel would dismiss it).
#[test]
fn without_a_display_it_exits_without_answering() {
    let dir = tempfile::tempdir().unwrap();
    let (ours, theirs) = UnixStream::pair().unwrap();
    let o = with_fd(prompter(dir.path()), theirs.as_raw_fd());
    drop(theirs);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("cannot open the prompt window"),
        "{}",
        stderr(&o)
    );
    let mut line = String::new();
    assert_eq!(
        BufReader::new(ours).read_line(&mut line).unwrap(),
        0,
        "{line}"
    );
}
```

In `crates/aleph-gui/src/theme.rs`, add this test to `mod tests`, before `fn auto_follows_omarchy_and_falls_back_to_neon`:

```rust
    /// A theme switch (Omarchy rewrites the files) is seen.
    #[test]
    fn a_theme_switch_is_seen() {
        let home = tempfile::tempdir().unwrap();
        let file = omarchy_colors(home.path());
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, NORD).unwrap();
        let watch = Watch::start(home.path(), &egui::Context::default()).unwrap();
        // (Events from the setup above may still arrive: let them.)
        std::thread::sleep(std::time::Duration::from_millis(100));
        watch.changed();
        std::fs::write(&file, NORD.replace("#2e3440", "#101010")).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !watch.changed() {
            assert!(
                std::time::Instant::now() < deadline,
                "the change was not seen"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // Nothing to watch without an Omarchy theme.
        let bare = tempfile::tempdir().unwrap();
        assert!(Watch::start(bare.path(), &egui::Context::default()).is_none());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-gui`
Expected: the build fails: `file not found for module manager`, and `Watch` does not exist.

- [ ] **Step 3: Implement**

In `crates/aleph-gui/src/theme.rs`, add before `#[cfg(test)]`:

```rust
/// Follows the Omarchy theme (spec §7): `changed` turns true once, after
/// any change under `~/.local/state/omarchy/current` (Omarchy rewrites the
/// theme's files in place), and the window is asked to repaint.
pub struct Watch {
    changed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _watcher: notify::RecommendedWatcher,
}

impl Watch {
    /// `None` where there is nothing to watch (no Omarchy theme).
    pub fn start(home: &Path, ctx: &egui::Context) -> Option<Self> {
        use notify::Watcher;
        let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (flag, ctx) = (changed.clone(), ctx.clone());
        let mut watcher = notify::recommended_watcher(move |_: notify::Result<notify::Event>| {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            ctx.request_repaint();
        })
        .ok()?;
        watcher
            .watch(&omarchy_current(home), notify::RecursiveMode::Recursive)
            .ok()?;
        Some(Self {
            changed,
            _watcher: watcher,
        })
    }

    /// Whether the theme changed since the last call.
    pub fn changed(&self) -> bool {
        self.changed
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}
```

Replace `crates/aleph-gui/src/app.rs` with (`embedded`; the watcher is `theme::Watch`):

```rust
//! The prompt window: alephd's messages in, the person's answers out.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use aleph_prompt_proto::FromPrompter;

use crate::conversation::Action;
use crate::link::{self, Event};
use crate::screens::PromptUi;
use crate::settings::Settings;
use crate::theme;

pub struct PromptApp {
    pub ui: PromptUi,
    stream: UnixStream,
    events: Receiver<Event>,
    settings: Settings,
    home: Option<PathBuf>,
    /// Scanlines drawn (the setting, unless reduced motion is asked for).
    scanlines: bool,
    /// Set by the theme watcher.
    watch: Option<theme::Watch>,
    /// The window was told to close.
    pub closed: bool,
    /// How long keys are ignored after a screen appears, so the end of
    /// something typed into another window (and its Enter) never becomes
    /// an answer here.
    pub input_guard: Duration,
    /// How long a closing message stays up (the window holds the keyboard
    /// while it is open): a failure's, and a note after success.
    pub message_for: Duration,
    pub note_for: Duration,
    /// When the current screen appeared.
    shown_at: Instant,
    /// When a closing message closes itself.
    close_at: Option<Instant>,
    /// The window size last asked for.
    size: [f32; 2],
    /// Drawn inside another window (the manager's confirmation): closing
    /// ends the conversation, never the window, which it never resizes.
    pub embedded: bool,
}

/// Keys ignored after a screen appears.
pub const INPUT_GUARD: Duration = Duration::from_millis(400);
/// A closing message's time on screen: a failure's, and a note after
/// success (a pending rotation: it would come with every unlock).
pub const MESSAGE_FOR: Duration = Duration::from_secs(20);
pub const NOTE_FOR: Duration = Duration::from_secs(6);

impl PromptApp {
    pub fn new(
        stream: UnixStream,
        events: Receiver<Event>,
        settings: Settings,
        home: Option<PathBuf>,
        still: bool,
    ) -> Self {
        let palette = theme::resolve(&settings, home.as_deref());
        Self {
            ui: PromptUi::new(palette, still),
            stream,
            events,
            scanlines: settings.scanlines && !still,
            settings,
            home,
            watch: None,
            closed: false,
            input_guard: INPUT_GUARD,
            message_for: MESSAGE_FOR,
            note_for: NOTE_FOR,
            shown_at: Instant::now(),
            close_at: None,
            size: crate::screens::SIZE,
            embedded: false,
        }
    }

    /// Re-theme live when the Omarchy theme changes (spec §7).
    pub fn watch_theme(&mut self, ctx: &egui::Context) {
        self.watch = self
            .home
            .as_deref()
            .and_then(|home| theme::Watch::start(home, ctx));
    }

    fn close(&mut self, ctx: &egui::Context) {
        if !self.closed {
            self.closed = true;
            if !self.embedded {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn reply(&mut self, ctx: &egui::Context, reply: FromPrompter) {
        let cancel = reply == FromPrompter::Cancel {};
        // alephd gone: nothing to answer any more.
        if link::send(&self.stream, &reply).is_err() || cancel {
            self.close(ctx);
        }
    }

    /// One frame: take alephd's messages, draw, send what the person did.
    pub fn frame(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let now = Instant::now();
        if self.watch.as_ref().is_some_and(theme::Watch::changed) {
            self.ui.palette = theme::resolve(&self.settings, self.home.as_deref());
            theme::apply(&ctx, &self.ui.palette);
        }
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Message(msg) => {
                    if let Some(refusal) = self.ui.conversation.receive(msg, now) {
                        self.reply(&ctx, refusal);
                    }
                    self.ui.screen_changed();
                    self.shown_at = now;
                    // (The recovery key's screens need a taller window.)
                    let size = crate::screens::size_for(&self.ui.conversation.screen);
                    if size != self.size && !self.embedded {
                        self.size = size;
                        let size = egui::Vec2::from(size);
                        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(size));
                        ctx.send_viewport_cmd(egui::ViewportCommand::MaxInnerSize(size));
                        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
                    }
                }
                // alephd is done with us: nothing more to answer. A
                // closing message stays up until it is read.
                Event::Closed => {
                    if !matches!(
                        self.ui.conversation.screen,
                        crate::conversation::Screen::Finished {
                            message: Some(_),
                            ..
                        }
                    ) {
                        self.close(&ctx);
                    }
                }
                // Prompter trouble, not the person's no: close without
                // answering, so the prompt waits (a Cancel would dismiss it).
                Event::Broken(why) => {
                    eprintln!("aleph-gui: {why}");
                    self.close(&ctx);
                }
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.closed && !self.embedded {
            // Closed by the window manager.
            if !self.ui.conversation.finished() {
                let _ = link::send(&self.stream, &FromPrompter::Cancel {});
            }
            self.closed = true;
        }
        match self.ui.conversation.screen {
            crate::conversation::Screen::Finished { message: None, .. } => self.close(&ctx),
            // A closing message closes itself after a while.
            crate::conversation::Screen::Finished {
                ok,
                message: Some(_),
                ..
            } => {
                let stay = if ok { self.note_for } else { self.message_for };
                let at = *self.close_at.get_or_insert(now + stay);
                if now >= at {
                    self.close(&ctx);
                } else {
                    ctx.request_repaint_after(at - now);
                }
            }
            _ => {}
        }
        if self.closed {
            return;
        }
        // (The guard starts again when the window gets the keyboard: it may
        // have opened unfocused, behind the lock screen, say.)
        if ctx.input(|i| {
            i.events
                .iter()
                .any(|e| matches!(e, egui::Event::WindowFocused(true)))
        }) {
            self.shown_at = now;
        }
        if now < self.shown_at + self.input_guard {
            ctx.input_mut(|i| {
                i.events.retain(|e| {
                    !matches!(
                        e,
                        egui::Event::Key { .. }
                            | egui::Event::Text(_)
                            | egui::Event::Paste(_)
                            | egui::Event::Ime(_)
                    )
                })
            });
            ctx.request_repaint_after(self.shown_at + self.input_guard - now);
        }
        let action = self.ui.show(ui, now);
        // (Embedded, the window around it paints them.)
        if self.scanlines && !self.embedded {
            theme::paint_scanlines(&ctx, &self.ui.palette);
        }
        match action {
            Some(Action::Close) => self.close(&ctx),
            Some(action) => {
                if let Some(reply) = self.ui.conversation.act(action, now) {
                    self.reply(&ctx, reply);
                }
            }
            None => {}
        }
    }
}

impl eframe::App for PromptApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
    }
}
```

Write `crates/aleph-gui/src/manager.rs`:

```rust
//! The manager window (the manager spec, "The window"): folders and items
//! from the [`Store`], a detail pane, and the actions on them. Secrets are
//! fetched only to show, copy, or edit one, after the reveal guard.

use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use egui::{Button, RichText, TextEdit};
use zeroize::Zeroizing;

use crate::app::PromptApp;
use crate::clipboard::{Backend, Clipboard};
use crate::conversation::{Screen, shown};
use crate::reauth::Reauth;
use crate::settings::Settings;
use crate::store::{Collection, Item, Request, Store, StoreEvent, Vault};
use crate::theme::{self, Palette};

/// The window's first size.
pub const SIZE: [f32; 2] = [900.0, 560.0];

/// The longest label or value shown in a list (the full text is in the
/// detail pane, wrapped).
const NAME: usize = 60;

/// The requests a form's SAVE sends ([`Request::name`]).
const SAVES: &[&str] = &[
    "rename",
    "change the secret",
    "create the item",
    "create the folder",
];

/// What is selected in the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    Item(String),
    Collection(String),
}

/// What a fetched secret is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    Show,
    Copy,
    Edit,
}

/// A secret on screen.
pub enum Shown {
    Text(Zeroizing<String>),
    /// Not UTF-8 text: its length.
    Binary(usize),
}

/// What the detail pane is doing.
pub enum Mode {
    Browse,
    Edit {
        path: String,
        label: String,
        /// The secret being edited: fetched (after the reveal guard), or
        /// typed.
        secret: Option<Zeroizing<String>>,
        /// The secret as fetched: a save sends the secret only if it
        /// differs (`None` once a lock forgot it: then what was typed is
        /// sent).
        original: Option<Zeroizing<String>>,
    },
    New {
        collection: String,
        label: String,
        secret: Zeroizing<String>,
        attributes: Vec<(String, String)>,
    },
    DeleteItem {
        path: String,
        label: String,
    },
    NewFolder {
        label: String,
    },
}

pub struct Manager<S: Store, B: Backend> {
    pub store: S,
    pub clipboard: Clipboard<B>,
    pub reauth: Reauth,
    pub vault: Vault,
    pub search: String,
    pub selected: Option<Selection>,
    pub shown: Option<(String, Shown)>,
    pub mode: Mode,
    /// The one-line status at the top (errors, "copied").
    pub status: Option<String>,
    /// A secret asked for, and what for.
    awaiting: Option<(String, Want)>,
    /// What runs once the reveal guard confirms.
    pending: Option<(String, Want)>,
    /// The reveal guard's conversation, drawn in the detail pane.
    confirm: Option<PromptApp>,
    /// Keys ignored as the confirmation appears (the tests set it to 0).
    pub confirm_guard: Duration,
    /// Save requests not answered yet: the form stays until they succeed
    /// (and stays, with the error, if one fails).
    pub saving: usize,
    settings: Settings,
    home: Option<PathBuf>,
    still: bool,
    pub palette: Palette,
    watch: Option<theme::Watch>,
}

impl<S: Store, B: Backend> Manager<S, B> {
    pub fn new(
        store: S,
        backend: B,
        settings: Settings,
        home: Option<PathBuf>,
        still: bool,
    ) -> Self {
        let palette = theme::resolve(&settings, home.as_deref());
        Self {
            store,
            clipboard: Clipboard::new(backend),
            reauth: Reauth::default(),
            vault: Vault::Connecting,
            search: String::new(),
            selected: None,
            shown: None,
            mode: Mode::Browse,
            status: None,
            awaiting: None,
            pending: None,
            confirm: None,
            confirm_guard: crate::app::INPUT_GUARD,
            saving: 0,
            settings,
            home,
            still,
            palette,
            watch: None,
        }
    }

    /// Re-theme live when the Omarchy theme changes (spec §7).
    pub fn watch_theme(&mut self, ctx: &egui::Context) {
        self.watch = self
            .home
            .as_deref()
            .and_then(|home| theme::Watch::start(home, ctx));
    }

    fn collections(&self) -> &[Collection] {
        match &self.vault {
            Vault::Unlocked(c) => c,
            _ => &[],
        }
    }

    fn item(&self, path: &str) -> Option<&Item> {
        self.collections()
            .iter()
            .flat_map(|c| &c.items)
            .find(|i| i.path == path)
    }

    /// Show, copy, or edit `path`'s secret: after the reveal guard, then
    /// fetched.
    fn want(&mut self, path: String, want: Want, now: Instant) {
        if self.reauth.needed(now) {
            self.start_confirm(path, want);
        } else {
            self.fetch(path, want);
        }
    }

    fn fetch(&mut self, path: String, want: Want) {
        self.store.request(Request::Secret(path.clone()));
        self.awaiting = Some((path, want));
    }

    fn start_confirm(&mut self, path: String, want: Want) {
        let Ok((ours, theirs)) = UnixStream::pair() else {
            self.status = Some("cannot start the confirmation".into());
            return;
        };
        let Ok(reader) = ours.try_clone() else {
            self.status = Some("cannot start the confirmation".into());
            return;
        };
        let Ok(events) = crate::link::spawn_reader(reader, || {}) else {
            self.status = Some("cannot start the confirmation".into());
            return;
        };
        let mut app = PromptApp::new(
            ours,
            events,
            self.settings.clone(),
            self.home.clone(),
            self.still,
        );
        app.embedded = true;
        app.input_guard = self.confirm_guard;
        self.confirm = Some(app);
        self.pending = Some((path, want));
        self.store.request(Request::Reauth(theirs.into()));
    }

    /// Hide and forget what the keyring's lock makes unreadable.
    fn sealed(&mut self) {
        self.reauth.forget();
        self.shown = None;
        self.awaiting = None;
        self.pending = None;
        self.confirm = None;
        if let Mode::Edit {
            secret, original, ..
        } = &mut self.mode
        {
            // (The form stays. A fetched secret must be fetched again; one
            // typed stays, and is saved as typed.)
            if *secret == *original {
                *secret = None;
            }
            *original = None;
        }
    }

    fn take_events(&mut self) {
        for e in self.store.events() {
            match e {
                StoreEvent::Vault(v) => {
                    if !matches!(v, Vault::Unlocked(_)) && matches!(self.vault, Vault::Unlocked(_))
                    {
                        self.sealed();
                    }
                    self.vault = v;
                    // (The selection goes if its item or folder went.)
                    let gone = match &self.selected {
                        Some(Selection::Item(p)) => self.item(p).is_none(),
                        Some(Selection::Collection(p)) => {
                            !self.collections().iter().any(|c| &c.path == p)
                        }
                        None => false,
                    };
                    if gone && matches!(self.vault, Vault::Unlocked(_)) {
                        self.selected = None;
                        self.shown = None;
                    }
                }
                StoreEvent::Secret { path, secret, .. } => {
                    // (Only the secret asked for last: an earlier one is
                    // dropped, and wiped.)
                    let Some(want) = self
                        .awaiting
                        .as_ref()
                        .filter(|(p, _)| *p == path)
                        .map(|(_, w)| *w)
                    else {
                        continue;
                    };
                    self.awaiting = None;
                    match want {
                        Want::Show => {
                            let shown = match std::str::from_utf8(&secret) {
                                Ok(t) => Shown::Text(Zeroizing::new(t.to_string())),
                                Err(_) => Shown::Binary(secret.len()),
                            };
                            self.shown = Some((path, shown));
                        }
                        Want::Copy => {
                            self.status = Some(match self.clipboard.copy(secret) {
                                Ok(()) => "COPIED :: the clipboard clears in 30 s".into(),
                                Err(e) => format!("cannot copy: {e}"),
                            });
                        }
                        Want::Edit => {
                            let Ok(text) = std::str::from_utf8(&secret) else {
                                self.status = Some(
                                    "binary secret: not editable here (it can be copied)".into(),
                                );
                                continue;
                            };
                            if let Mode::Edit {
                                path: p,
                                secret: s,
                                original,
                                ..
                            } = &mut self.mode
                                && *p == path
                            {
                                *s = Some(Zeroizing::new(text.to_string()));
                                *original = Some(Zeroizing::new(text.to_string()));
                            }
                        }
                    }
                }
                StoreEvent::Done { request, error, .. } => {
                    let save = SAVES.contains(&request) && self.saving > 0;
                    match error {
                        Some(e) => {
                            self.status = Some(format!("cannot {request}: {e}"));
                            if request == "fetch the secret" {
                                self.awaiting = None;
                            }
                            // (The form stays, with what was typed.)
                            if save {
                                self.saving = 0;
                            }
                        }
                        None if save => {
                            self.saving -= 1;
                            if self.saving == 0 {
                                self.mode = Mode::Browse;
                            }
                        }
                        None => {}
                    }
                }
            }
        }
    }

    /// One frame.
    pub fn frame(&mut self, ui: &mut egui::Ui) {
        let now = Instant::now();
        if self.watch.as_ref().is_some_and(theme::Watch::changed) {
            self.palette = theme::resolve(&self.settings, self.home.as_deref());
            theme::apply(ui.ctx(), &self.palette);
        }
        self.take_events();
        let p = self.palette.clone();
        egui::Panel::left("aleph-nav")
            .exact_size(130.0)
            .resizable(false)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("ALEPH").strong().color(p.accent));
                ui.label(RichText::new("// VAULT").small().color(p.accent));
                ui.add_space(16.0);
                ui.label(RichText::new("SECRETS").strong());
            });
        match self.vault.clone() {
            Vault::Unlocked(collections) => self.unlocked(ui, &p, &collections, now),
            other => {
                egui::CentralPanel::default().show(ui, |ui| {
                    self.status_line(ui, &p);
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| match other {
                        Vault::Connecting => {
                            ui.label("CONNECTING…");
                        }
                        Vault::Unreachable(why) => {
                            ui.label(RichText::new("LINK DOWN").strong().color(p.error));
                            ui.label(shown(&why, 200));
                            ui.label("alephd cannot be reached; retrying.");
                        }
                        Vault::Locked => {
                            ui.label(RichText::new("VAULT SEALED").strong().color(p.warning));
                            ui.add_space(8.0);
                            if ui
                                .add(
                                    Button::new(
                                        RichText::new("UNLOCK").strong().color(p.background),
                                    )
                                    .fill(p.accent),
                                )
                                .clicked()
                            {
                                self.store.request(Request::Unlock);
                            }
                        }
                        Vault::Unlocked(_) => {}
                    });
                });
            }
        }
        if self.settings.scanlines && !self.still {
            theme::paint_scanlines(ui.ctx(), &p);
        }
    }

    fn status_line(&mut self, ui: &mut egui::Ui, p: &Palette) {
        if let Some(s) = &self.status {
            let mut clear = false;
            ui.horizontal(|ui| {
                ui.label(RichText::new(shown(s, 200)).color(p.warning));
                clear = ui.small_button("×").clicked();
            });
            if clear {
                self.status = None;
            }
        }
    }

    fn matches(&self, item: &Item) -> bool {
        let q = self.search.trim().to_lowercase();
        q.is_empty()
            || item.label.to_lowercase().contains(&q)
            || item
                .attributes
                .values()
                .any(|v| v.to_lowercase().contains(&q))
    }

    fn unlocked(
        &mut self,
        ui: &mut egui::Ui,
        p: &Palette,
        collections: &[Collection],
        now: Instant,
    ) {
        egui::Panel::left("aleph-list")
            .default_size(280.0)
            .resizable(true)
            .show(ui, |ui| {
                ui.add_space(6.0);
                let search = ui.add(
                    TextEdit::singleline(&mut self.search)
                        .hint_text("search_")
                        .desired_width(f32::INFINITY),
                );
                let name = "Search".to_string();
                ui.ctx()
                    .accesskit_node_builder(search.id, move |n| n.set_label(name));
                ui.add_space(6.0);
                egui::Panel::bottom("aleph-list-buttons").show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("+ ITEM").clicked() {
                            let collection = match &self.selected {
                                Some(Selection::Collection(c)) => c.clone(),
                                Some(Selection::Item(i)) => collections
                                    .iter()
                                    .find(|c| c.items.iter().any(|it| &it.path == i))
                                    .map(|c| c.path.clone())
                                    .unwrap_or_default(),
                                None => collections
                                    .first()
                                    .map(|c| c.path.clone())
                                    .unwrap_or_default(),
                            };
                            self.shown = None;
                            self.mode = Mode::New {
                                collection,
                                label: String::new(),
                                secret: Zeroizing::default(),
                                attributes: Vec::new(),
                            };
                        }
                        if ui.button("+ FOLDER").clicked() {
                            self.shown = None;
                            self.mode = Mode::NewFolder {
                                label: String::new(),
                            };
                        }
                    });
                });
                let mut clicked = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for c in collections {
                        let title = if c.is_default {
                            format!("{} (default)", shown(&c.label, NAME))
                        } else {
                            shown(&c.label, NAME)
                        };
                        let picked = self.selected == Some(Selection::Collection(c.path.clone()));
                        if ui
                            .selectable_label(picked, RichText::new(title).strong())
                            .clicked()
                        {
                            clicked = Some(Selection::Collection(c.path.clone()));
                        }
                        for it in c.items.iter().filter(|i| self.matches(i)) {
                            let picked = self.selected == Some(Selection::Item(it.path.clone()));
                            ui.horizontal(|ui| {
                                ui.add_space(14.0);
                                if ui
                                    .selectable_label(picked, shown(&it.label, NAME))
                                    .clicked()
                                {
                                    clicked = Some(Selection::Item(it.path.clone()));
                                }
                            });
                        }
                    }
                });
                if let Some(s) = clicked {
                    self.select(s);
                }
            });
        egui::CentralPanel::default().show(ui, |ui| {
            self.status_line(ui, p);
            if self.confirm.is_some() {
                self.confirming(ui, now);
                return;
            }
            self.detail(ui, p, collections, now);
        });
    }

    fn select(&mut self, s: Selection) {
        if self.selected.as_ref() != Some(&s) {
            self.shown = None;
            self.mode = Mode::Browse;
        }
        self.selected = Some(s);
    }

    /// The reveal guard, drawn with the prompter's screens.
    fn confirming(&mut self, ui: &mut egui::Ui, now: Instant) {
        let Some(app) = self.confirm.as_mut() else {
            return;
        };
        // (What the guard is worth: spec §6.)
        ui.label(
            RichText::new(
                "Any program running as you can read secrets; this only guards against a glance.",
            )
            .small()
            .color(self.palette.foreground.gamma_multiply(0.7)),
        );
        app.frame(ui);
        if app.closed {
            let ok = matches!(
                app.ui.conversation.screen,
                Screen::Finished { ok: true, .. }
            );
            self.confirm = None;
            if let Some((path, want)) = self.pending.take()
                && ok
            {
                self.reauth.confirmed(now);
                self.fetch(path, want);
            }
        }
    }

    fn detail(&mut self, ui: &mut egui::Ui, p: &Palette, collections: &[Collection], now: Instant) {
        match std::mem::replace(&mut self.mode, Mode::Browse) {
            Mode::Browse => {
                self.mode = Mode::Browse;
                self.browse(ui, p, collections, now);
            }
            Mode::Edit {
                path,
                mut label,
                secret,
                original,
            } => {
                ui.label(RichText::new("EDIT").strong().color(p.accent));
                ui.add_space(6.0);
                field(ui, &mut label, "Label", "label_", false);
                let mut secret = secret;
                match &mut secret {
                    Some(s) => {
                        field(ui, s, "Secret", "secret_", true);
                    }
                    None => {
                        ui.label(RichText::new("the secret is not loaded").color(p.muted));
                        if ui.button("LOAD SECRET").clicked() {
                            self.want(path.clone(), Want::Edit, now);
                        }
                    }
                }
                ui.add_space(8.0);
                let (save, cancel) = self.save_buttons(ui, !label.trim().is_empty());
                if cancel {
                    // (An answer still to come no longer closes a form.)
                    self.saving = 0;
                }
                if save {
                    let mut sent = 0;
                    if self.item(&path).is_some_and(|i| i.label != label) {
                        self.store.request(Request::SetLabel {
                            path: path.clone(),
                            label: label.clone(),
                        });
                        sent += 1;
                    }
                    // (Only a secret that changed: an unchanged one is not
                    // rewritten.)
                    if let Some(s) = &secret
                        && secret != original
                    {
                        self.store.request(Request::SetSecret {
                            path: path.clone(),
                            secret: Zeroizing::new(s.as_bytes().to_vec()),
                        });
                        sent += 1;
                    }
                    self.shown = None;
                    self.saving = sent;
                }
                if !cancel && !(save && self.saving == 0) {
                    self.mode = Mode::Edit {
                        path,
                        label,
                        secret,
                        original,
                    };
                }
            }
            Mode::New {
                collection,
                mut label,
                mut secret,
                mut attributes,
            } => {
                let folder = collections
                    .iter()
                    .find(|c| c.path == collection)
                    .map(|c| shown(&c.label, NAME))
                    .unwrap_or_default();
                ui.label(
                    RichText::new(format!("NEW ITEM :: {folder}"))
                        .strong()
                        .color(p.accent),
                );
                ui.add_space(6.0);
                field(ui, &mut label, "Label", "label_", false);
                field(ui, &mut secret, "Secret", "secret_", true);
                ui.add_space(4.0);
                ui.label(RichText::new("ATTRIBUTES").small().color(p.muted));
                let mut remove = None;
                for (i, (k, v)) in attributes.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        let key = ui.add(
                            TextEdit::singleline(k)
                                .hint_text("key")
                                .desired_width(120.0),
                        );
                        let name = format!("Attribute {} key", i + 1);
                        ui.ctx()
                            .accesskit_node_builder(key.id, move |n| n.set_label(name));
                        let value = ui.add(
                            TextEdit::singleline(v)
                                .hint_text("value")
                                .desired_width(200.0),
                        );
                        let name = format!("Attribute {} value", i + 1);
                        ui.ctx()
                            .accesskit_node_builder(value.id, move |n| n.set_label(name));
                        if ui.small_button("×").clicked() {
                            remove = Some(i);
                        }
                    });
                }
                if let Some(i) = remove {
                    attributes.remove(i);
                }
                if ui.small_button("+ ATTRIBUTE").clicked() {
                    attributes.push((String::new(), String::new()));
                }
                ui.add_space(8.0);
                let ready =
                    !label.trim().is_empty() && !secret.is_empty() && !collection.is_empty();
                let (save, cancel) = self.save_buttons(ui, ready);
                if cancel {
                    // (An answer still to come no longer closes a form.)
                    self.saving = 0;
                }
                if save {
                    let wanted: BTreeMap<String, String> = attributes
                        .iter()
                        .filter(|(k, _)| !k.trim().is_empty())
                        .map(|(k, v)| (k.trim().to_string(), v.clone()))
                        .collect();
                    self.store.request(Request::CreateItem {
                        collection: collection.clone(),
                        label: label.clone(),
                        attributes: wanted,
                        secret: Zeroizing::new(secret.as_bytes().to_vec()),
                    });
                    self.saving = 1;
                }
                if !cancel {
                    self.mode = Mode::New {
                        collection,
                        label,
                        secret,
                        attributes,
                    };
                }
            }
            Mode::DeleteItem { path, label } => {
                ui.label(format!("Delete '{}'?", shown(&label, NAME)));
                ui.add_space(8.0);
                let (mut yes, mut no) = (false, false);
                ui.horizontal(|ui| {
                    // (No first, and focused: the default.)
                    let n = ui.button("No");
                    n.request_focus();
                    no = n.clicked();
                    yes = ui.button("Yes").clicked();
                });
                if yes {
                    self.store.request(Request::DeleteItem(path));
                    self.selected = None;
                    self.shown = None;
                } else if !no {
                    self.mode = Mode::DeleteItem { path, label };
                }
            }
            Mode::NewFolder { mut label } => {
                ui.label(RichText::new("NEW FOLDER").strong().color(p.accent));
                ui.add_space(6.0);
                field(ui, &mut label, "Folder name", "name_", false);
                let (create, cancel) = self.save_buttons(ui, !label.trim().is_empty());
                if cancel {
                    // (An answer still to come no longer closes a form.)
                    self.saving = 0;
                }
                if create {
                    // (alephd confirms it in its own prompt window.)
                    self.store
                        .request(Request::CreateCollection(label.trim().to_string()));
                    self.saving = 1;
                }
                if !cancel {
                    self.mode = Mode::NewFolder { label };
                }
            }
        }
    }

    /// SAVE (enabled when `ready` and nothing is being saved) and CANCEL;
    /// "SAVING…" while a save is answered.
    fn save_buttons(&self, ui: &mut egui::Ui, ready: bool) -> (bool, bool) {
        let (mut save, mut cancel) = (false, false);
        ui.horizontal(|ui| {
            save = ui
                .add_enabled(ready && self.saving == 0, Button::new("SAVE"))
                .clicked();
            cancel = ui.button("CANCEL").clicked();
            if self.saving > 0 {
                ui.label("SAVING…");
            }
        });
        (save, cancel)
    }

    fn browse(&mut self, ui: &mut egui::Ui, p: &Palette, collections: &[Collection], now: Instant) {
        match self.selected.clone() {
            None => {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("SELECT AN ENTRY").color(p.muted));
                });
            }
            Some(Selection::Collection(path)) => {
                let Some(c) = collections.iter().find(|c| c.path == path) else {
                    return;
                };
                ui.heading(shown(&c.label, 200));
                ui.label(format!(
                    "{} item(s){}",
                    c.items.len(),
                    if c.is_default { " · default" } else { "" }
                ));
                ui.add_space(8.0);
                if ui.button("DELETE FOLDER").clicked() {
                    // (alephd asks, in its own prompt window.)
                    self.store.request(Request::DeleteCollection(path));
                }
            }
            Some(Selection::Item(path)) => {
                let Some(it) = self.item(&path).cloned() else {
                    return;
                };
                ui.heading(shown(&it.label, 200));
                ui.add_space(6.0);
                egui::Grid::new("attributes")
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        for (k, v) in &it.attributes {
                            ui.label(
                                RichText::new(shown(k, NAME))
                                    .color(p.foreground.gamma_multiply(0.7)),
                            );
                            ui.label(shown(v, 200));
                            ui.end_row();
                        }
                        ui.label(RichText::new("created").color(p.foreground.gamma_multiply(0.7)));
                        ui.label(date(it.created));
                        ui.end_row();
                        ui.label(RichText::new("modified").color(p.foreground.gamma_multiply(0.7)));
                        ui.label(date(it.modified));
                        ui.end_row();
                    });
                ui.add_space(8.0);
                let showing = self.shown.as_ref().filter(|(p, _)| *p == path);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("secret").color(p.foreground.gamma_multiply(0.7)));
                    match showing.map(|(_, s)| s) {
                        Some(Shown::Text(t)) => {
                            ui.label(RichText::new(t.as_str()).monospace());
                        }
                        Some(Shown::Binary(n)) => {
                            ui.label(format!("binary secret, {n} bytes"));
                        }
                        None => {
                            ui.label("•••••••");
                        }
                    }
                });
                ui.add_space(6.0);
                let (mut show, mut hide, mut copy, mut edit, mut delete) =
                    (false, false, false, false, false);
                ui.horizontal(|ui| {
                    if showing.is_some() {
                        hide = ui.button("HIDE").clicked();
                    } else {
                        show = ui.button("SHOW").clicked();
                    }
                    copy = ui.button("COPY").clicked();
                    edit = ui.button("EDIT").clicked();
                    delete = ui.button("DELETE").clicked();
                });
                if show {
                    self.want(path.clone(), Want::Show, now);
                }
                if hide {
                    self.shown = None;
                }
                if copy {
                    self.want(path.clone(), Want::Copy, now);
                }
                if edit {
                    self.shown = None;
                    self.mode = Mode::Edit {
                        path: path.clone(),
                        label: it.label.clone(),
                        secret: None,
                        original: None,
                    };
                }
                if delete {
                    self.shown = None;
                    self.mode = Mode::DeleteItem {
                        path,
                        label: it.label,
                    };
                }
            }
        }
    }
}

/// A single-line field with no visible label: `hint` inside it while
/// empty, `name` for screen readers (and the tests).
fn field(ui: &mut egui::Ui, text: &mut String, name: &str, hint: &str, masked: bool) {
    let r = ui.add(
        TextEdit::singleline(text)
            .password(masked)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
    let name = name.to_string();
    ui.ctx()
        .accesskit_node_builder(r.id, move |n| n.set_label(name));
}

/// Seconds since the epoch as a UTC date (0: unknown).
pub fn date(secs: u64) -> String {
    if secs == 0 {
        return "unknown".into();
    }
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

impl<S: Store, B: Backend> eframe::App for Manager<S, B> {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
    }
}

#[cfg(test)]
mod tests {
    use super::date;

    #[test]
    fn dates_are_utc_calendar_days() {
        assert_eq!(date(0), "unknown");
        assert_eq!(date(1), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_790_553_600), "2026-09-28");
    }
}
```

Replace `crates/aleph-gui/src/main.rs` with:

```rust
//! `aleph-gui`: the manager window (the manager spec); `aleph-gui prompt`:
//! the prompter alephd starts, with its end of a socketpair as
//! `ALEPH_PROMPT_FD` (spec §6 "Prompter orchestration").

use std::process::ExitCode;

use aleph_gui::{app, clipboard, link, manager, screens, settings, store};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [] => manage(),
        ["prompt"] => prompt(),
        _ => {
            eprintln!("usage: aleph-gui            the keyring manager");
            eprintln!("       aleph-gui prompt     (alephd starts it)");
            ExitCode::from(2)
        }
    }
}

/// The settings, reduced motion, and home, for either window.
fn look() -> (settings::Settings, bool, Option<std::path::PathBuf>) {
    let (settings, warning) = match settings::config_home() {
        Some(dir) => settings::Settings::load(&settings::path(&dir)),
        None => (settings::Settings::default(), None),
    };
    if let Some(w) = warning {
        eprintln!("aleph-gui: {w}");
    }
    (settings, settings::reduced_motion(), settings::home())
}

fn manage() -> ExitCode {
    // It shows and copies secrets: no core dumps, no ptrace by other
    // processes of the user.
    // SAFETY: prctl with these arguments only sets a process flag.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let (settings, still, home) = look();
    let viewport = egui::ViewportBuilder::default()
        .with_app_id("aleph")
        .with_title("aleph")
        .with_inner_size(manager::SIZE);
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    let result = eframe::run_native(
        "aleph",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let store = store::DbusStore::start(None, move || ctx.request_repaint());
            let mut app =
                manager::Manager::new(store, clipboard::Wayland::default(), settings, home, still);
            aleph_gui::theme::apply(&cc.egui_ctx, &app.palette);
            if still {
                cc.egui_ctx.all_styles_mut(|s| s.animation_time = 0.0);
            }
            app.watch_theme(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aleph-gui: cannot open the window: {e}");
            ExitCode::FAILURE
        }
    }
}

fn prompt() -> ExitCode {
    // What is typed here is a password: no core dumps, no ptrace by
    // other processes of the user.
    // SAFETY: prctl with these arguments only sets a process flag.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    // First, while single-threaded: the variable is removed.
    let stream = match link::take_from_env() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aleph-gui: {e}");
            return ExitCode::from(2);
        }
    };
    let config_home = settings::config_home();
    let (settings, warning) = match &config_home {
        Some(dir) => settings::Settings::load(&settings::path(dir)),
        None => (settings::Settings::default(), None),
    };
    if let Some(w) = warning {
        eprintln!("aleph-gui: {w}");
    }
    let still = settings::reduced_motion();
    let home = settings::home();
    let viewport = egui::ViewportBuilder::default()
        .with_app_id("aleph-prompt")
        .with_title("aleph")
        .with_inner_size(screens::SIZE)
        .with_min_inner_size(screens::SIZE)
        .with_max_inner_size(screens::SIZE)
        .with_resizable(false)
        .with_active(true);
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    let result = eframe::run_native(
        "aleph-prompt",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let events = link::spawn_reader(stream.try_clone()?, move || ctx.request_repaint())?;
            let mut app = app::PromptApp::new(stream, events, settings, home, still);
            aleph_gui::theme::apply(&cc.egui_ctx, &app.ui.palette);
            if still {
                cc.egui_ctx.all_styles_mut(|s| s.animation_time = 0.0);
            }
            app.watch_theme(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Without an answer: alephd reads the closed socket as "no
            // prompter", and the prompt waits for an unlock from elsewhere
            // (a Cancel would dismiss it).
            eprintln!("aleph-gui: cannot open the prompt window: {e}");
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 4: Generate the snapshots and look at every one**

Run: `UPDATE_SNAPSHOTS=1 cargo test -q -p aleph-gui --test manager snapshots`
Expected: `ok. 1 passed`, and 16 new files: `manager_{empty,item,shown,edit,new,confirm,locked,unreachable}_{neon,omarchy}.png`. Open every one: the sidebar reads `ALEPH` / `// VAULT` / `SECRETS`; folders are bold with their items indented under them, no boxes where a glyph is missing; the detail pane's attribute names are legible in both themes; the secret is dots until shown (`manager_shown_*`: `ghp_s3cret` in monospace); `manager_confirm_*`: the caveat line ("Any program running as you can read secrets; this only guards against a glance.") above the embedded confirmation (`ALEPH // IDENTITY CHECK`, "Confirm it is you", the passphrase field, ABORT and PROCEED), one set of scanlines; `manager_locked_*` shows `VAULT SEALED` and UNLOCK; `manager_unreachable_*` shows `LINK DOWN` and the reason.

- [ ] **Step 5: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-gui && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `ok. 26 passed` (lib), `ok. 4 passed` (binary), `ok. 17 passed` (manager), `ok. 24 passed` (screens), `ok. 7 passed` (store).

- [ ] **Step 6: Confirm the tests have teeth**

Make each change below in `crates/aleph-gui/src/manager.rs`, run the named test and see it FAIL, then undo it:

- **the reveal guard** (`a_secret_is_shown_after_the_confirmation`): replace `        if self.reauth.needed(now) {` with `        if false {`.
- **a refused confirmation fetches nothing** (`a_refused_confirmation_fetches_nothing`): in `confirming`, delete the line `                && ok` (and its newline).
- **a lock seals** (`a_lock_seals_the_window`): replace `                        self.sealed();` with `                        {}`.
- **one line for hostile labels** (`a_hostile_label_stays_on_one_line_in_the_list`): replace `.selectable_label(picked, shown(&it.label, NAME))` with `.selectable_label(picked, it.label.clone())`.
- **binary secrets** (`a_binary_secret_is_not_shown`): replace `Err(_) => Shown::Binary(secret.len()),` with `Err(_) => Shown::Text(Zeroizing::new(String::from_utf8_lossy(&secret).into_owned())),`.
- **delete asks** (`delete_asks_first`): make the DELETE button request `Request::DeleteItem(path)` at once instead of setting `Mode::DeleteItem`.
- **only a changed secret is saved** (`a_loaded_secret_is_saved_only_if_changed`): replace `                        && secret != original` with `                        && true`.
- **binary secrets are not edited** (`a_binary_secret_is_not_editable`): replace `let Ok(text) = std::str::from_utf8(&secret) else {` with `let Ok(text) = Ok::<&str, ()>("\u{fffd}") else {`.
- **a typed secret survives a lock** (`a_typed_secret_survives_a_lock`): in `sealed`, replace `            if *secret == *original {` with `            if true {`.
- **a failed save keeps the form** (`a_failed_save_keeps_the_form`): where an error ends a save (`self.saving = 0;` in `take_events`), also set `self.mode = Mode::Browse;`.
- **Enter says No** (`enter_on_the_delete_question_says_no`): delete `                    n.request_focus();`.

- [ ] **Step 7: Commit**

```bash
git add crates/aleph-gui
git commit -m "feat(gui): the manager window (aleph-gui)" -m "Folders and items, search, the detail pane; show and copy after the confirmation (the prompter's screens, embedded); edit, create, and delete; locked and unreachable states; theme followed live." -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 6: the launcher entry

**Files:**
- Create: `packaging/aleph-gui.desktop`, `crates/aleph-gui/tests/launcher.rs`
- Modify: `packaging/install.sh`

- [ ] **Step 1: Write the failing test**

Write `crates/aleph-gui/tests/launcher.rs`:

```rust
//! The launcher entry agrees with the program: it runs the manager, its
//! window class is the manager's app id, and every icon install.sh
//! copies exists.

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

#[test]
fn the_launcher_entry_opens_the_manager_with_its_icon() {
    let entry = std::fs::read_to_string(format!("{ROOT}/packaging/aleph-gui.desktop")).unwrap();
    let value = |key: &str| {
        entry
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key}"))
            .to_string()
    };
    assert_eq!(value("Exec"), "aleph-gui");
    assert_eq!(value("Icon"), "aleph");
    // (The manager's viewport app id, main.rs.)
    assert_eq!(value("StartupWMClass"), "aleph");
    let main = std::fs::read_to_string(format!("{ROOT}/crates/aleph-gui/src/main.rs")).unwrap();
    assert!(main.contains(".with_app_id(\"aleph\")"));

    let install = std::fs::read_to_string(format!("{ROOT}/packaging/install.sh")).unwrap();
    let icons: Vec<&str> = install
        .split_whitespace()
        .filter(|w| w.starts_with("assets/icons/"))
        .collect();
    assert_eq!(icons.len(), 4, "{icons:?}");
    for icon in icons {
        assert!(
            std::path::Path::new(&format!("{ROOT}/{icon}")).is_file(),
            "{icon}"
        );
    }
    assert!(
        install.contains("packaging/aleph-gui.desktop /usr/share/applications/aleph-gui.desktop")
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -q -p aleph-gui --test launcher`
Expected: FAIL: `packaging/aleph-gui.desktop` does not exist (`No such file or directory`).

- [ ] **Step 3: Implement**

Write `packaging/aleph-gui.desktop`:

```ini
[Desktop Entry]
Type=Application
Name=aleph
GenericName=Keyring
Comment=Browse and edit the secrets in your aleph keyring
Exec=aleph-gui
Icon=aleph
Terminal=false
Categories=Utility;Security;
Keywords=keyring;password;secret;vault;
StartupWMClass=aleph
```

Replace `packaging/install.sh` with (the entry and the four icons installed and removed; the caches refreshed when their tools are there):

```sh
#!/bin/sh
# Install (or uninstall) aleph from a release build of this tree, the way
# the package lays it out (spec §9). Until there is a package:
#
#   make && make install                 # or: make uninstall
#
# (`make install` runs this with sudo, then restarts alephd as the user;
# a running alephd keeps the old binary and unit until it restarts.)
# Then `alephctl setup`.
set -eu
cd "$(dirname "$0")/.."
R=target/release

if [ "$(id -u)" != 0 ]; then
    echo "install.sh: run as root (after cargo build --release --workspace)" >&2
    exit 1
fi

case "${1:-install}" in
install)
    for f in "$R/alephctl" "$R/alephd" "$R/aleph-tpmd" "$R/aleph-gui" "$R/libpam_aleph.so"; do
        if [ ! -f "$f" ]; then
            echo "install.sh: $f is missing: run cargo build --release --workspace first" >&2
            exit 1
        fi
    done
    install -Dm755 "$R/alephctl" /usr/bin/alephctl
    install -Dm755 "$R/aleph-gui" /usr/bin/aleph-gui
    install -Dm755 "$R/alephd" /usr/lib/aleph/alephd
    install -Dm755 "$R/aleph-tpmd" /usr/lib/aleph/aleph-tpmd
    install -Dm755 "$R/libpam_aleph.so" /usr/lib/security/pam_aleph.so
    install -Dm644 packaging/pam/aleph-check /etc/pam.d/aleph-check
    install -Dm644 packaging/hyprland/aleph-prompt.lua /usr/share/aleph/hyprland/aleph-prompt.lua
    install -Dm644 packaging/aleph-gui.desktop /usr/share/applications/aleph-gui.desktop
    install -Dm644 assets/icons/aleph.svg /usr/share/icons/hicolor/scalable/apps/aleph.svg
    install -Dm644 assets/icons/aleph-24.svg /usr/share/icons/hicolor/24x24/apps/aleph.svg
    install -Dm644 assets/icons/aleph-16.svg /usr/share/icons/hicolor/16x16/apps/aleph.svg
    install -Dm644 assets/icons/aleph-symbolic.svg /usr/share/icons/hicolor/symbolic/apps/aleph-symbolic.svg
    gtk-update-icon-cache -q -t /usr/share/icons/hicolor 2>/dev/null || true
    update-desktop-database -q /usr/share/applications 2>/dev/null || true
    install -Dm644 -t /usr/lib/systemd/system \
        packaging/systemd/aleph-tpmd.service packaging/systemd/aleph-tpmd.socket
    install -Dm644 -t /usr/lib/systemd/user \
        packaging/systemd/alephd.service packaging/systemd/alephd.socket
    # (io.aleph.Keyring only: the Secret Service name's activation file is
    # the user's, written by `alephctl setup`, so gnome-keyring keeps it
    # until then.)
    install -Dm644 packaging/dbus/io.aleph.Keyring.service \
        /usr/share/dbus-1/services/io.aleph.Keyring.service
    systemctl daemon-reload
    systemctl enable --now aleph-tpmd.socket
    systemctl --global enable alephd.socket
    echo "install.sh: installed. As the user: systemctl --user daemon-reload;"
    echo "  systemctl --user start alephd.socket; alephctl setup"
    ;;
uninstall)
    if [ -e /var/lib/aleph/manifest.json ]; then
        echo "install.sh: the PAM changes are still in place: run alephctl system revert first" >&2
        exit 1
    fi
    user_file="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/.local/share/dbus-1/services/org.freedesktop.secrets.service"
    if grep -qs /usr/lib/aleph/alephd "$user_file"; then
        echo "install.sh: ${SUDO_USER:-root} still has aleph serving the Secret Service: run alephctl setup --revert first" >&2
        exit 1
    fi
    systemctl --global disable alephd.socket || true
    systemctl disable --now aleph-tpmd.socket aleph-tpmd.service || true
    rm -f /usr/bin/alephctl /usr/bin/aleph-gui /usr/lib/aleph/alephd /usr/lib/aleph/aleph-tpmd \
        /usr/share/aleph/hyprland/aleph-prompt.lua \
        /usr/share/applications/aleph-gui.desktop \
        /usr/share/icons/hicolor/scalable/apps/aleph.svg /usr/share/icons/hicolor/24x24/apps/aleph.svg \
        /usr/share/icons/hicolor/16x16/apps/aleph.svg /usr/share/icons/hicolor/symbolic/apps/aleph-symbolic.svg \
        /usr/lib/security/pam_aleph.so /etc/pam.d/aleph-check \
        /usr/lib/systemd/system/aleph-tpmd.service /usr/lib/systemd/system/aleph-tpmd.socket \
        /usr/lib/systemd/user/alephd.service /usr/lib/systemd/user/alephd.socket \
        /usr/share/dbus-1/services/io.aleph.Keyring.service
    rmdir /usr/lib/aleph /usr/share/aleph/hyprland /usr/share/aleph 2>/dev/null || true
    systemctl daemon-reload
    echo "install.sh: uninstalled (the vault in ~/.local/share/aleph is left in place)"
    ;;
*)
    echo "usage: install.sh [install|uninstall]" >&2
    exit 2
    ;;
esac
```

- [ ] **Step 4: Run the test and the gate**

Run: `cargo test -q -p aleph-gui --test launcher && desktop-file-validate packaging/aleph-gui.desktop && make gate`
Expected: `ok. 1 passed`; `desktop-file-validate` prints at most a hint about adding a category (a second main category would list the entry twice: leave it); `make gate` exits 0.

- [ ] **Step 5: Commit**

```bash
git add packaging crates/aleph-gui/tests/launcher.rs
git commit -m "feat: the manager in the launcher (desktop entry and icons)" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 7: spec, docs, decisions

**Files:**
- Modify: `docs/superpowers/specs/2026-09-26-aleph-design.md`, `DECISIONS.md`, `docs/testing.md`, `README.md`

- [ ] **Step 1: Update the documents**

In `docs/superpowers/specs/2026-09-26-aleph-design.md`, replace

```markdown
  `RemovedSinceImport`, `ExportToGnomeKeyring`, `ReleaseSecretService`,
  `ThawWrites`. `Status` also names who owns `org.freedesktop.secrets`.
```

with

```markdown
  `RemovedSinceImport`, `ExportToGnomeKeyring`, `ReleaseSecretService`,
  `ThawWrites`, `Reauth` (proves an enrolled method and changes nothing:
  the manager's guard before it shows a secret). `Status` also names who
  owns `org.freedesktop.secrets`.
```

In `docs/superpowers/specs/2026-09-26-aleph-design.md`, replace

```markdown
| `aleph-gui` | bin | egui manager and prompter. | `eframe`, `egui`, `zbus`, `notify`, Wayland clipboard crate |
```

with

```markdown
| `aleph-gui` | bin | egui manager and prompter. | `aleph-prompt-proto`, `aleph-secret-session`, `eframe`, `egui`, `zbus`, `notify`, `wl-clipboard-rs` |
| `aleph-secret-session` | lib | The Secret Service transfer sessions (`plain`, `dh-ietf1024-sha256-aes128-cbc-pkcs7`), server and client halves: alephd's Secret Service and its gnome-keyring import, and the manager. | `aes`, `cbc`, `hkdf`, `sha2`, `num-bigint`, `getrandom`, `zeroize` |
```

In `docs/superpowers/specs/2026-09-26-aleph-design.md`, replace

```markdown
**Manager (`aleph-gui`)**

- **Secrets:** a collection list, a searchable item list, and a detail
  pane (label, attributes, masked secret).
  - Revealing a secret requires re-authentication (a UX guard, §6).
  - Copying uses the Wayland clipboard with the MIME hint
    `x-kde-passwordManagerHint: secret`, so clipboard-history tools skip
    it, and clears the clipboard after 30 s.
  - Items can be created, edited, and deleted.
- **Keyslots:** a list with stale and unknown markers, enroll and remove
  wizards, and recovery-key reissue.
- **Settings:** lock policy, theme and scanlines, and prompt timeouts.
- **Import and export**, and **Recover…**.
- A `.desktop` entry makes it available in the Omarchy launcher, using the
  icons in `assets/icons/` (§8).
```

with

```markdown
**Manager (`aleph-gui`)**

Designed in its own document,
`docs/superpowers/specs/2026-09-28-aleph-manager-design.md`, and built in
three plans (DECISIONS.md H7):

- **The window and the secrets browser (Plan 5b):** `aleph-gui` with no
  arguments; a Secret Service client like Seahorse (secrets reach it only
  through `org.freedesktop.secrets`, over an encrypted session). Folders
  and a searchable item list, a detail pane (label, attributes read-only,
  dates, the secret masked); show and copy after a re-authentication that
  holds for 5 minutes and not past a lock (a UX guard, §6); copies go to
  the Wayland clipboard with the MIME hint `x-kde-passwordManagerHint:
  secret`, so clipboard-history tools skip them, and are cleared after
  30 s; items are created, renamed, given a new secret, and deleted;
  folders are created and deleted (alephd confirms). A `.desktop` entry
  puts it in the Omarchy launcher, with the icons in `assets/icons/` (§8).
- **Settings (Plan 5c):** lock policy, prompt timeout, theme and
  scanlines.
- **Admin (Plan 5d):** the GUI equivalent of `alephctl`: status, lock and
  unlock, keyslots, master-key rotation, recovery key, backup, restore and
  recover.
- Import and export stay in `alephctl setup` and `setup --revert`
  (DECISIONS.md E3).
```

In `docs/superpowers/specs/2026-09-26-aleph-design.md`, replace

```markdown
- **Repo:** one Cargo workspace (eight crates), plus `packaging/arch/`,
```

with

```markdown
- **Repo:** one Cargo workspace (eleven crates), plus `packaging/arch/`,
```

In `docs/superpowers/specs/2026-09-26-aleph-design.md`, replace

```markdown
    - the `.desktop` file and the icons:
```

with

```markdown
    - the `.desktop` file (`/usr/share/applications/aleph-gui.desktop`)
      and the icons:
```

In `README.md`, replace

```markdown
| `aleph-gui` | `aleph-gui prompt`: the unlock prompt `alephd` opens (the manager window comes later) |
```

with

```markdown
| `aleph-gui` | The keyring manager (`aleph-gui`) and the unlock prompt `alephd` opens (`aleph-gui prompt`) |
| `aleph-secret-session` | The Secret Service transfer sessions, shared by `alephd` and the manager |
```

In `docs/testing.md`, replace

```markdown
## Emergency manual revert
```

with

```markdown
### The manager (Plan 5b)

After `make && make install` (the launcher entry and the icons are
installed with it), on the account aleph serves:

1. Open "aleph" from the Omarchy launcher (Super + Space): the manager
   opens with the aleph icon, showing the folders and items (labels and
   attributes only; no secret is fetched).
2. Search: typing part of a label or an attribute value filters the list.
3. Pick an item and SHOW: the confirmation appears inside the window
   (login password, or a security key); after it, the secret shows. HIDE,
   then SHOW again within 5 minutes: no confirmation. `alephctl lock`:
   the window shows `VAULT SEALED` and hides the secret; UNLOCK opens the
   usual prompt, and a SHOW then asks for the confirmation again.
4. COPY: `COPIED`; paste it somewhere: it is the secret. Clipboard history
   (`cliphist list`, if installed) does not list it. Switch to another
   workspace (the manager hidden) and wait 30 s: the clipboard is empty.
   (Closing the manager also clears a copy it served.)
5. `+ ITEM` in a test folder (`+ FOLDER` first: alephd's prompt asks to
   confirm): a label, a secret, an attribute; SAVE: it appears, and
   `secret-tool lookup <key> <value>` prints the secret. EDIT its label
   and (LOAD SECRET) its secret; SAVE; `secret-tool` prints the new one.
   DELETE: it asks (No leaves it); Yes removes it. DELETE FOLDER on the
   test folder: alephd's prompt asks.
6. An application storing a secret meanwhile (`secret-tool store
   --label=live service live-check`): it appears without a refresh.
7. Switch the Omarchy theme: the manager re-themes.
8. Restart alephd (`systemctl --user restart alephd.service`; the
   keyring locks): the manager shows `VAULT SEALED`; unlock; SHOW and
   `+ ITEM` still work (the manager opens a new session with the new
   alephd). (Stopping alephd shows `LINK DOWN` only briefly: the manager's
   own calls start it again, through D-Bus activation.)

## Emergency manual revert
```

In `DECISIONS.md`, insert before `## 2026-09-28: Plan 5a (the prompter), design`:

```markdown
## 2026-09-28: Plan 5b (the manager), design

### H9. The pre-execution review of the Plan 5b document: fixes adopted

An independent review of the plan and its prototype; no critical finding.
Adopted, each with a test that failed without it:

- **Sessions are their openers' (alephd).** alephd numbered sessions from
  1 on every start and only checked that a session path existed, so after
  a restart another client (Chromium, say) could be handed the manager's
  cached path: the manager's shows then failed, and a save could store
  garbage without an error. A session now serves only the client that
  opened it (`NoSession` otherwise).
- **The store follows alephd's restarts:** its session is tied to the
  unique name that serves `org.freedesktop.secrets`, is closed and
  replaced when a request that uses it fails, and that request is tried
  once more.
- **Deleting the default folder** (its alias goes with it) no longer shows
  `LINK DOWN`: with the alias gone, the service answering means unlocked.
- **The clipboard clears itself** on a timer thread 30 s after the copy
  (if it is still that copy), not with the window's frames: a window on a
  hidden workspace draws none.
- **An edit saves only what changed:** a loaded secret is rewritten only
  if it differs, and a secret that is not text cannot be loaded into the
  editor (it would be mangled).
- **A form stays until its save succeeds:** a failed save keeps what was
  typed, with the error; a lock keeps a secret the person typed (a fetched
  one must be fetched again).
- **Only the store's loop lists,** so what it last sent is what the window
  shows; a folder or item that vanishes mid-listing is skipped; a burst of
  signals means one listing; signals are taken only from the service's
  owner.
- **Minor, adopted:** a secret asked for earlier no longer swallows the one
  asked for last; Enter on the delete question answers No (a test);
  "cannot fetch the secret" (not "cannot secret"); failures reach stderr
  (operations and reasons, never secrets or labels); the embedded
  confirmation paints no second set of scanlines, has a snapshot, and its
  caveat is the manager's own line (it did not fit alephd's title).
- **Left as they are:** a hostile item can carry attributes named
  `created` or `modified`, shown above the real dates; a collection named
  "X (default)" looks like the default (creating one needs alephd's
  confirmation); the clipboard's "still ours" check and its clear are not
  atomic (another program's copy in between is cleared); closing the
  manager clears a copy it served (documented).

### H8. Calls made while prototyping Plan 5b

For the reviewers; each is argued in the plan
(`docs/superpowers/plans/2026-09-28-aleph-manager.md`, "Decisions made
while prototyping") and pinned by a test that was seen to fail without it.

- **The lock state is polled as well as signalled, the lists are not.**
  alephd signals a lock (`CollectionChanged` on the default alias), and the
  store also reads one property (`Locked` on the default alias) every 2 s,
  for a missed signal or an alephd restart; it lists every folder and item
  only when that changes or a signal arrives: listing costs a few calls
  per item.
- **Each request runs on its own** on the store's thread: an unlock prompt
  may wait for the person indefinitely (H5), and nothing else waits for
  it. Only the session is shared, under a lock held just to encrypt or
  decrypt.
- **The confirmation reuses the prompter:** the prompt window's own code
  (`PromptApp`), drawn inside the manager (`embedded`: it never closes or
  resizes the window), on a socketpair whose other end goes to alephd's
  `Reauth`.
- **The copy is served by `wl-clipboard-rs`** (the wlr data-control
  protocol, which Hyprland has) from a thread until another program takes
  the clipboard (or the manager exits: the copy goes with it); "still
  ours" is whether that thread is still serving. The served copy is the
  crate's and is not zeroized.
- **New items get `xdg:schema = org.freedesktop.Secret.Generic`** unless
  one is typed; items are stored as `text/plain`.
- **Dates are UTC calendar days;** a secret that is not UTF-8 shows as
  "binary secret, N bytes".
- **The folder marker is gone:** "▸" is not in the Omarchy theme's font
  (it showed as a box); folders are bold, items indented.
- **The manager's app id is `aleph`,** matching the launcher entry's
  `StartupWMClass`; the entry's category is `Utility;Security;`.
- **The binary tests never open a window on the real display:** with no
  arguments `aleph-gui` is now the manager, so its test runs with a
  display socket that does not exist, a private runtime directory, and no
  session bus.
- **The theme watcher is shared** by both windows (`theme::Watch`), and
  now has a test.

### H7. The manager: scope and approach — owner's decisions

- **Three plans:** 5b the window, the secrets browser, and the launcher
  entry (too small for a plan of its own); 5c settings (alephd's
  `config.toml` and the GUI's `gui.toml`); 5d admin, the GUI equivalent
  of `alephctl`.
- **A Secret Service client:** the manager reaches secrets only through
  `org.freedesktop.secrets`, like Seahorse, over an encrypted session. A
  new admin method listing items or returning secrets was rejected: a
  second, non-standard path to secrets for nothing gained. The session
  code moved into `aleph-secret-session`, shared with alephd.
- **Attributes are read-only** in the manager (applications find their
  secrets by them); new items take the attributes typed.
- **A reveal confirmation holds for 5 minutes,** and not past a lock (5c
  may make the length a setting). It is the guard against a glance that
  §6 describes, not security; the manager says so where it asks. alephd
  gains `Reauth` for it.
- **Import and export stay** in `alephctl setup` and `setup --revert`.
```

- [ ] **Step 2: Check them**

Run: `grep -n "Import and export\*\*, and \*\*Recover\|eight crates\|the manager window comes later" docs/superpowers/specs/2026-09-26-aleph-design.md README.md || echo clean`
Expected: `clean`.
Run: `make gate`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add docs DECISIONS.md README.md
git commit -m "docs: Plan 5b, the manager (spec, decisions H7 and H8, testing)" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: Hand over the manual checks**

testing.md, "The manager": they need the installed build on the owner's session (`make && make install` restarts alephd, which locks the keyring). Do not run them; list them for the owner.
