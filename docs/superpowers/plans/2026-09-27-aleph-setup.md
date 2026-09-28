# Setup Implementation Plan (Plan 4c)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `aleph setup` imports gnome-keyring's items, takes over the session's Secret Service from it, and (as root, last and optional) sets up login and screen unlock; `aleph setup --revert` copies everything back to gnome-keyring, verifies it, and hands it all back.

**Architecture:**
- **alephd** owns `io.aleph.Keyring` and queues for `org.freedesktop.secrets` (never replacing, never replaceable), so it takes the name the moment gnome-keyring lets go. It imports as a Secret Service client of gnome-keyring over an encrypted session, and for revert runs its own gnome-keyring on a private bus to write everything back and read it back.
- **`aleph setup`** (user level): activation files, a bus reload, gnome-keyring's units masked and stopped (states recorded for revert), Omarchy's lock hook, the TPM's lockoutAuth (opt-in), then `sudo aleph system apply`.
- **`aleph system`** (root): pure text transformations of four PAM services, atomic writes, a real Linux-PAM check of the edited login and lock-screen stacks with automatic rollback, and a root-owned manifest for an exact revert.

**Tech Stack:** Rust 1.98, `zbus` 5 (a queued name; a client of another Secret Service), `enumflags2`, libpam (declared directly), gnome-keyring and dbus-daemon at runtime and in tests.

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` revision 2 (§6 "Startup and switchover", "PAM integration"; §7 `aleph setup`, "Import"). Decisions: `DECISIONS.md` E1–E6, E9–E11 (the reviewed design), D9 (lockoutAuth), G1 (Omarchy's lock, the owner's), G2 (calls made while prototyping; Task 5 adds it). Task 5 updates the spec.

**Plan series:** 1–4b (done) → **4c setup (this plan)** → 5 `aleph-gui` → 6 packaging and CI.

**Base:** `master` (with Plan 4b).

**Prerequisites** (once per machine, as for Plan 4b) plus `gnome-keyring` (`sudo pacman -S --needed gnome-keyring`): its tests run a real gnome-keyring on a private bus.

## Decisions made while prototyping

Every task was prototyped, then replayed from this document on a fresh clone: red, then green, then clippy and fmt clean, with the final tree identical to the prototype. The properties below were each checked by reverting them (the "teeth" step of the owning task). `DECISIONS.md` G2 lists these calls for the reviewers.

- **Import** needs the vault unlocked and no aleph prompter: gnome-keyring asks for its own locked collections (a dismissed prompt skips the collection, listed). What it added is recorded (`imported.json`) so revert can list items deleted in aleph since. It keeps following gnome-keyring's item signals until the name changes hands.
- **Revert's export** asks the login password (PAM-checked; it unlocks gnome-keyring's login keyring, kept in step by `pam_gnome_keyring` in `passwd`). If that keyring does not open, nothing changes. Writes pause from the export to the end of the revert (resumed on any failure). "No gnome-keyring runs" is checked on the bus; the private instance has a throwaway home and runtime directory, and only the keyring data directory is real. Collections gnome-keyring lacks go into its default one.
- **E3's order holds as reviewed:** gnome-keyring, started while alephd holds the name, waits and takes it once alephd lets go (checked with the real one).
- **The root side** edits `sddm`, `sddm-autologin`, `omarchy-lock-password`, and `passwd` (never `system-login`, `system-auth`, `login`), refuses symlinks, non-regular files, and files not owned by root (manual mode), checks the lock-screen and login stacks with a real login (never `passwd`), and rolls back on failure. On NixOS it prints what to add.
- **The wizard:** an unanswered question takes its default; the root step defaults to yes and a declined or failed sudo does not fail setup; with autologin the default unlock method is a security key. Autologin detection reads every file in SDDM's directories (E5).
- **`aleph export gnome-keyring` is not a command:** export happens only inside `setup --revert`.
- **Tests never reach the real system:** `ALEPH_SYSTEMCTL` and `ALEPH_SUDO` name stand-ins (a script that knows no unit, and `false`, in the CLI tests), and the CLI tests run with their own home and XDG directories; the PAM check tests use stub stacks (never `pam_aleph`, which could reach a real daemon).

## Global Constraints

- Rust stable 1.98, edition 2024; every crate `license = "Apache-2.0"`.
- alephd never requests `org.freedesktop.secrets` with `ReplaceExisting` or `AllowReplacement`; `alephd.service` has `BusName=io.aleph.Keyring`.
- Secrets move between alephd and gnome-keyring only over an encrypted session (`dh-ietf1024-sha256-aes128-cbc-pkcs7`), never through the CLI.
- The root side reads no user configuration, no D-Bus, and no user-writable paths; it never edits `system-login`, `system-auth`, `system-local-login`, `system-remote-login`, or `login`.
- **Exact names:** activation files `org.freedesktop.secrets.service`, `org.gnome.keyring.service`, `org.freedesktop.impl.portal.Secret.service` in `$XDG_DATA_HOME/dbus-1/services/`; `$XDG_STATE_HOME/aleph/setup.json` and `imported.json`; `/var/lib/aleph/manifest.json`; `/etc/pam.d/<service>.aleph-orig`; PAM lines `-auth      optional  pam_aleph.so`, `-session   optional  pam_aleph.so`, `-password  optional  pam_aleph.so`; `~/.config/omarchy/hooks/lock.d/aleph`; Admin methods `ImportGnomeKeyring`, `RemovedSinceImport`, `ExportToGnomeKeyring`, `ReleaseSecretService`, `ThawWrites`.
- Tests never touch the real user manager, sudo, home, or `/etc/pam.d`.
- `cargo fmt` default; `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **A setup or revert interrupted at any step** (a crash, a failed sudo, gnome-keyring started outside systemd, a user who says no) must leave a working Secret Service and a login that works, and a re-run must finish the job. → Task 2 `gnome_keyring_hands_over_and_a_rerun_changes_nothing`, `a_gnome_keyring_outside_systemd_is_reported`, `a_login_keyring_that_does_not_unlock_changes_nothing`; Task 4 `setup_creates_the_keyring_and_status_shows_it` (a failed sudo, a second run); Task 6 `a_revert_rerun_after_switching_back_goes_straight_to_the_release`, `skipped_collections_stop_setup_before_the_switchover`.
2. **A PAM edit that would lock the user out** must never stay: the edited stacks are checked with a real login and rolled back, the TTY path is never touched, and revert restores exactly what was there. → Task 3 `the_transformed_stacks_run_through_real_pam`, `apply_then_revert_restores_every_file_exactly`, `revert_after_an_edit_keeps_the_edit_or_leaves_the_file`, `a_symlinked_service_is_manual`, `files_not_owned_by_root_are_manual`, `roll_back_restores_the_changed_files`; Task 6 `a_service_without_its_anchor_is_manual_and_the_rest_recorded`, `a_crash_before_the_manifest_keeps_the_original`, `a_stale_backup_is_replaced_by_the_current_file`, `a_checked_apply_rolls_back_on_failure_even_on_a_rerun`. The check-and-roll-back path in `aleph system apply` runs only as root (hardware checklist).
3. **Nothing is lost moving between keyrings:** items stored in gnome-keyring during the import, items stored in aleph after setup, conflicting items, locked collections, and items deleted in aleph since. → Task 1 `items_move_over_and_the_name_changes_hands`, `a_collection_that_stays_locked_is_skipped_with_a_message`, `import_is_idempotent_and_never_overwrites`; Task 2 `items_are_copied_back_and_writes_pause`, `items_deleted_since_the_import_are_deleted_there_too`, `setup_revert_hands_everything_back`; Task 6 `revert_never_deletes_what_aleph_still_holds`, `export_does_not_replace_an_item_with_another_label`, `an_update_in_gnome_keyring_is_followed`.
4. **Two gnome-keyrings over the same files, or apps that start one behind alephd's back** (activation, PAM's `auto_start`): revert refuses while one serves the session, and setup disables gnome-keyring's other routes in. → Task 2 `revert_refuses_while_gnome_keyring_runs`; the activation files in `gnome_keyring_hands_over_and_a_rerun_changes_nothing`.
5. **Tests that reach the real machine** (systemctl, sudo, `/etc/pam.d`, the real keyring files, a real alephd): none may. → the CLI test harness (a systemctl stand-in script, `ALEPH_SUDO=false`, its own HOME and XDG directories); the stub PAM stacks in Task 3.

## File Structure

```
crates/aleph-daemon/src/secret/session.rs  ClientDh (the client half of the DH session)
crates/aleph-daemon/src/import.rs          Importer (connect, fetch_all, follow), merge, Summary, the imported record
crates/aleph-daemon/src/export.rs          Private (alephd's own gnome-keyring), export, gnome_keyring_active
crates/aleph-daemon/src/daemon.rs          request_secrets_name, secret_service_owner
crates/aleph-daemon/src/{admin,keyring,main,error,paths,testing}.rs
crates/aleph-daemon/tests/gnome_keyring.rs
crates/aleph-cli/src/switchover.rs         switch_over, switch_back, Units (systemctl), Dirs, Record
crates/aleph-cli/src/system.rs             transform, inverse, apply, verify, roll_back, revert, Manifest
crates/aleph-cli/src/wizard.rs             autologin detection, Omarchy hook, lockoutAuth, sudo
crates/aleph-cli/src/{main,client}.rs     setup, setup --revert, import, system
crates/aleph-cli/tests/cli.rs; tests/fixtures/pam/{omarchy,omarchy-applied}/
packaging/systemd/alephd.service           BusName=io.aleph.Keyring
docs: spec (§6, §7), testing.md (+ emergency manual revert), README.md, DECISIONS.md (G2), omarchy-lock-hook.md
```

---

### Task 1: importing from gnome-keyring

**Interfaces:**
- Produces:
  - `secret::session::ClientDh::{new() -> Result<Self, SessionError>, public, finish(&[u8]) -> Result<Session, SessionError>}`
  - `import::{SECRETS_NAME, Fetched, FetchedCollection, Summary, merge(&mut Body, Vec<FetchedCollection>, &mut Summary), Importer::{connect(&Connection, Duration) -> Result<Option<Importer>>, fetch_all(&self, &mut Vec<String>) -> Result<Vec<FetchedCollection>>, follow(self, Arc<Keyring>, Arc<SecretService>)}}`
  - `daemon::{request_secrets_name(&Connection) -> zbus::Result<bool>, secret_service_owner(&Connection) -> String}`; `keyring::Status::secret_service: Option<String>`
  - Admin `ImportGnomeKeyring() -> s`; CLI `aleph import gnome-keyring`, `Client::import_gnome_keyring`
  - `testing::{daemon_on(Bus, bool) -> Daemon, GnomeKeyring::{start(&Bus, &str), store(&self, &str, &[(&str, &str)], &str), stop(self)}}`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-daemon/src/import.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fetched(label: &str, attrs: &[(&str, &str)], secret: &[u8]) -> Fetched {
        Fetched {
            label: label.into(),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            secret: SecretBytes::new(secret.to_vec()),
            content_type: "application/octet-stream".into(),
            created: 111,
            modified: 222,
        }
    }

    fn body() -> Body {
        Body::default()
    }

    /// Default collection to aleph's default; others by label (created);
    /// attributes, content type, and timestamps kept.
    #[test]
    fn items_arrive_with_everything_kept() {
        let mut b = body();
        let mut s = Summary::default();
        merge(
            &mut b,
            vec![
                FetchedCollection {
                    label: "Login".into(),
                    is_default: true,
                    items: vec![fetched(
                        "mail",
                        &[("xdg:schema", "org.x"), ("u", "a")],
                        b"pw",
                    )],
                },
                FetchedCollection {
                    label: "Work".into(),
                    is_default: false,
                    items: vec![fetched("vpn", &[("h", "v")], b"k")],
                },
            ],
            &mut s,
        );
        assert_eq!(s.imported, 2);
        let default = b.resolve_alias(aleph_core::model::DEFAULT_ALIAS).unwrap();
        let mail = &default.items[0];
        assert_eq!(mail.attributes["xdg:schema"], "org.x");
        assert_eq!(mail.content_type, "application/octet-stream");
        assert_eq!((mail.created, mail.modified), (111, 222));
        assert!(
            b.collections
                .iter()
                .any(|c| c.label == "Work" && c.items.len() == 1)
        );
    }

    /// A second import changes nothing; a different secret already here is
    /// a conflict, skipped and listed; duplicates within gnome-keyring all
    /// arrive.
    #[test]
    fn import_is_idempotent_and_never_overwrites() {
        let mut b = body();
        let one = || FetchedCollection {
            label: "Login".into(),
            is_default: true,
            items: vec![fetched("mail", &[("u", "a")], b"pw")],
        };
        merge(&mut b, vec![one()], &mut Summary::default());
        let mut s = Summary::default();
        merge(&mut b, vec![one()], &mut s);
        assert_eq!((s.imported, s.unchanged), (0, 1));
        let mut s = Summary::default();
        merge(
            &mut b,
            vec![FetchedCollection {
                label: "Login".into(),
                is_default: true,
                items: vec![
                    fetched("mail", &[("u", "a")], b"other"),
                    fetched("dup", &[("d", "1")], b"x"),
                    fetched("dup", &[("d", "1")], b"x"),
                ],
            }],
            &mut s,
        );
        assert_eq!(s.conflicts, ["mail (Login)"]);
        assert_eq!(s.imported, 2);
        let default = b.resolve_alias(aleph_core::model::DEFAULT_ALIAS).unwrap();
        assert_eq!(default.items[0].secret.expose(), b"pw");
        assert!(s.to_string().contains("mail (Login)"));
    }
}
```

Write `crates/aleph-daemon/tests/import.rs`:

```rust
//! Importing from a real gnome-keyring on a private bus (DECISIONS.md E1,
//! E2, E11): alephd queues behind it for `org.freedesktop.secrets`, reads
//! its items over an encrypted session, keeps following it, and takes the
//! name the moment gnome-keyring lets go.

use aleph_daemon::testing::*;

async fn client(address: &str) -> zbus::Connection {
    zbus::connection::Builder::address(address)
        .unwrap()
        .build()
        .await
        .unwrap()
}

async fn admin(c: &zbus::Connection, method: &str) -> zbus::Result<String> {
    c.call_method(
        Some(aleph_daemon::admin::BUS_NAME),
        aleph_daemon::admin::ADMIN_PATH,
        Some("io.aleph.Admin1"),
        method,
        &(),
    )
    .await?
    .body()
    .deserialize()
}

fn items_labelled(
    d: &Daemon,
    label: &str,
) -> Vec<(String, std::collections::BTreeMap<String, String>, Vec<u8>)> {
    d.keyring
        .read(|b| {
            b.collections
                .iter()
                .flat_map(|c| c.items.iter())
                .filter(|i| i.label == label)
                .map(|i| {
                    (
                        i.content_type.clone(),
                        i.attributes.clone(),
                        i.secret.expose().to_vec(),
                    )
                })
                .collect()
        })
        .unwrap()
}

async fn eventually(what: &str, mut ok: impl AsyncFnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !ok().await {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting: {what}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn items_move_over_and_the_name_changes_hands() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store(
        "Mail",
        &[
            ("xdg:schema", "org.example.Mail"),
            ("service", "mail"),
            ("user", "alice"),
        ],
        "s3cret",
    );
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    let status: serde_json::Value =
        serde_json::from_str(&admin(&c, "Status").await.unwrap()).unwrap();
    assert_eq!(status["secret_service"], "another program");

    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    assert!(summary.contains("Imported 1 item"), "{summary}");
    let mail = items_labelled(&d, "Mail");
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].1["user"], "alice");
    assert_eq!(mail[0].1["xdg:schema"], "org.example.Mail");
    assert_eq!(mail[0].2, b"s3cret");
    // Again: nothing new.
    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    assert!(
        summary.contains("Imported 0 item(s) from gnome-keyring (1 already here)"),
        "{summary}"
    );

    // Stored in gnome-keyring after the import: followed.
    gk.store("Later", &[("service", "later")], "stored later");
    eventually("the later item", async || {
        items_labelled(&d, "Later").len() == 1
    })
    .await;

    // gnome-keyring lets go: the name is alephd's at once.
    gk.stop();
    eventually("the name handoff", async || {
        aleph_daemon::daemon::secret_service_owner(&d.conn).await == "alephd"
    })
    .await;
    // And alephd serves the imported item to Secret Service clients.
    let found: Vec<zbus::zvariant::OwnedObjectPath> = c
        .call_method(
            Some("org.freedesktop.secrets"),
            "/org/freedesktop/secrets",
            Some("org.freedesktop.Secret.Service"),
            "SearchItems",
            &(std::collections::HashMap::from([("service", "mail")]),),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<(
            Vec<zbus::zvariant::OwnedObjectPath>,
            Vec<zbus::zvariant::OwnedObjectPath>,
        )>()
        .unwrap()
        .0;
    assert_eq!(found.len(), 1);
}

/// A locked gnome-keyring collection whose unlock prompt cannot be shown
/// (or is dismissed) is skipped with a message, not waited on forever.
#[tokio::test(flavor = "multi_thread")]
async fn a_collection_that_stays_locked_is_skipped_with_a_message() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Mail", &[("service", "mail")], "s3cret");
    let c = client(&address).await;
    c.call_method(
        Some("org.freedesktop.secrets"),
        "/org/freedesktop/secrets",
        Some("org.freedesktop.Secret.Service"),
        "Lock",
        &(vec![
            zbus::zvariant::ObjectPath::try_from("/org/freedesktop/secrets/collection/login")
                .unwrap(),
        ],),
    )
    .await
    .unwrap();
    let d = daemon_on(bus, true).await;
    let started = std::time::Instant::now();
    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    eprintln!("took {:?}: {summary}", started.elapsed());
    assert!(summary.contains("Imported 0"), "{summary}");
    assert!(summary.contains("locked"), "{summary}");
    assert!(items_labelled(&d, "Mail").is_empty());
}

/// Without gnome-keyring there is nothing to import, and nothing fails.
#[tokio::test(flavor = "multi_thread")]
async fn without_gnome_keyring_there_is_nothing_to_import() {
    let d = daemon(true, vec![]).await;
    let c = client(&d.bus.address).await;
    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    assert!(summary.contains("not running"), "{summary}");
}
```

Apply this patch with `git apply` (save it as `/tmp/t1-tests.patch`):

```diff
--- a/crates/aleph-cli/tests/cli.rs
+++ b/crates/aleph-cli/tests/cli.rs
@@ -344,3 +344,17 @@
     let (ok, _, err) = run(&d, &["restore", fifo.to_str().unwrap()], "").await;
     assert!(!ok && err.contains("not a regular file"), "{err}");
 }
+
+/// `aleph import gnome-keyring` says when there is nothing to import, and
+/// `aleph status` names who serves the Secret Service.
+#[tokio::test(flavor = "multi_thread")]
+async fn import_and_status_name_the_secret_service() {
+    let d = daemon(true, vec![]).await;
+    let (ok, out, err) = run(&d, &["import", "gnome-keyring"], "").await;
+    assert!(ok && out.contains("not running"), "{out}{err}");
+    let (ok, out, _) = run(&d, &["status"], "").await;
+    assert!(
+        ok && out.contains("secret service: served by alephd"),
+        "{out}"
+    );
+}
--- a/crates/aleph-daemon/src/lib.rs
+++ b/crates/aleph-daemon/src/lib.rs
@@ -4,6 +4,7 @@
 pub mod config;
 pub mod daemon;
 pub mod error;
+pub mod import;
 pub mod keyring;
 pub mod lockpolicy;
 pub mod pamsock;
--- a/crates/aleph-daemon/src/secret/session.rs
+++ b/crates/aleph-daemon/src/secret/session.rs
@@ -166,6 +166,18 @@
         assert_eq!(session.decrypt(&iv[..8], &ct), Err(SessionError::Decrypt));
     }
 
+    /// Our client half (the gnome-keyring import) and a server agree, and
+    /// a bad server value is refused.
+    #[test]
+    fn the_client_half_agrees_with_a_server() {
+        let client = ClientDh::new().unwrap();
+        let (server, server_public) = Session::open(DH, &client.public).unwrap();
+        let (iv, ct) = server.encrypt(b"from gnome-keyring").unwrap();
+        let session = client.finish(&server_public).unwrap();
+        assert_eq!(&**session.decrypt(&iv, &ct).unwrap(), b"from gnome-keyring");
+        assert!(ClientDh::new().unwrap().finish(&[1]).is_err());
+    }
+
     #[test]
     fn plain_passes_through_and_bad_inputs_are_refused() {
         let (plain, out) = Session::open(PLAIN, &[]).unwrap();
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon -p aleph-cli`
Expected: the build fails: `ClientDh`, the `import` module, `daemon_on`, `GnomeKeyring`, and `aleph import` do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-daemon/src/import.rs`:

```rust
//! Importing from gnome-keyring (spec §7 "Import"; DECISIONS.md E1, E2).
//!
//! alephd, queued behind gnome-keyring for `org.freedesktop.secrets`, reads
//! every collection and item through gnome-keyring's own Secret Service API
//! over an encrypted session (secrets never pass through the CLI), and
//! merges them into the vault:
//! - idempotent and never overwriting: an item already here (same
//!   collection, label, and attributes) with the same secret is left as it
//!   is; with a different secret it is a conflict, skipped and listed. Only
//!   items that existed before a merge count, so duplicates within
//!   gnome-keyring itself all arrive;
//! - content types, attributes (`xdg:schema` included), and timestamps are
//!   kept; the transient `session` collection is skipped;
//! - a locked collection is unlocked through gnome-keyring's own prompt; a
//!   dismissed (or unanswered) prompt skips that collection, and a re-run
//!   picks it up.
//!
//! After the first pass it keeps following gnome-keyring's item signals
//! (subscribed before listing) until the name changes hands, so nothing
//! stored in between is lost.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use aleph_core::{Body, Item, SecretBytes};
use futures_util::StreamExt;
use zbus::Connection;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::error::{Error, Result};
use crate::keyring::Keyring;
use crate::secret::service::SecretService;
use crate::secret::session::{ClientDh, DH, Session};

pub const SECRETS_NAME: &str = "org.freedesktop.secrets";
const SECRETS_PATH: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const PROMPT: &str = "org.freedesktop.Secret.Prompt";
/// The transient collection gnome-keyring keeps in memory only.
const SESSION_COLLECTION: &str = "/org/freedesktop/secrets/collection/session";

/// One item as read from gnome-keyring.
pub struct Fetched {
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: SecretBytes,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

/// One collection as read from gnome-keyring.
pub struct FetchedCollection {
    pub label: String,
    /// gnome-keyring's default collection (its items go to aleph's).
    pub is_default: bool,
    pub items: Vec<Fetched>,
}

/// What an import did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub imported: usize,
    pub unchanged: usize,
    /// Items skipped because a different secret is already here.
    pub conflicts: Vec<String>,
    /// Collections skipped, with the reason.
    pub skipped: Vec<String>,
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Imported {} item(s) from gnome-keyring ({} already here).",
            self.imported, self.unchanged
        )?;
        if !self.conflicts.is_empty() {
            write!(
                f,
                " Skipped, a different secret is already here: {}.",
                self.conflicts.join(", ")
            )?;
        }
        if !self.skipped.is_empty() {
            write!(f, " Not imported: {}.", self.skipped.join("; "))?;
        }
        Ok(())
    }
}

/// Merge `fetched` into `body` (see the module comment for the rules).
pub fn merge(body: &mut Body, fetched: Vec<FetchedCollection>, summary: &mut Summary) {
    for collection in fetched {
        let target = if collection.is_default {
            body.resolve_alias(aleph_core::model::DEFAULT_ALIAS)
                .map(|c| c.id)
        } else {
            body.collections
                .iter()
                .find(|c| c.label == collection.label)
                .map(|c| c.id)
        };
        let id = match target {
            Some(id) => id,
            None => {
                let c = aleph_core::Collection::new(collection.label.clone());
                let id = c.id;
                body.collections.push(c);
                id
            }
        };
        let target = body.collection_mut(id).expect("just found or created");
        // Only what was here before this merge counts.
        let before: Vec<(String, BTreeMap<String, String>, Vec<u8>)> = target
            .items
            .iter()
            .map(|i| {
                (
                    i.label.clone(),
                    i.attributes.clone(),
                    i.secret.expose().to_vec(),
                )
            })
            .collect();
        for f in collection.items {
            let same: Vec<_> = before
                .iter()
                .filter(|(l, a, _)| *l == f.label && *a == f.attributes)
                .collect();
            if same.iter().any(|(_, _, s)| s == f.secret.expose()) {
                summary.unchanged += 1;
                continue;
            }
            if !same.is_empty() {
                summary
                    .conflicts
                    .push(format!("{} ({})", f.label, collection.label));
                continue;
            }
            let mut item = Item::new(f.label, f.attributes, f.secret, f.content_type);
            item.created = f.created;
            item.modified = f.modified;
            target.upsert(item, false);
            summary.imported += 1;
        }
    }
}

fn gk(e: impl std::fmt::Display) -> Error {
    Error::Invalid(format!("reading gnome-keyring: {e}"))
}

/// A connection to gnome-keyring's Secret Service, with an open encrypted
/// session and its item signals already subscribed.
pub struct Importer {
    conn: Connection,
    owner: String,
    session: Session,
    session_path: OwnedObjectPath,
    events: zbus::MessageStream,
    prompt_timeout: Duration,
}

impl Importer {
    /// `None` if nothing else owns `org.freedesktop.secrets` (gnome-keyring
    /// is not running, or this daemon already owns the name).
    pub async fn connect(conn: &Connection, prompt_timeout: Duration) -> Result<Option<Self>> {
        let dbus = zbus::fdo::DBusProxy::new(conn).await.map_err(gk)?;
        let name = zbus::names::BusName::try_from(SECRETS_NAME).map_err(gk)?;
        let owner = match dbus.get_name_owner(name).await {
            Ok(owner) => owner.to_string(),
            Err(_) => return Ok(None),
        };
        if conn.unique_name().is_some_and(|me| me.as_str() == owner) {
            return Ok(None);
        }
        // Subscribe before listing: nothing stored meanwhile is missed.
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(owner.as_str())
            .map_err(gk)?
            .interface(COLLECTION)
            .map_err(gk)?
            .build();
        let events = zbus::MessageStream::for_match_rule(rule, conn, Some(256))
            .await
            .map_err(gk)?;
        let service = proxy(conn, &owner, SECRETS_PATH, SERVICE).await?;
        let dh = ClientDh::new().map_err(gk)?;
        let (output, session_path): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &(DH, Value::from(dh.public.clone())))
            .await
            .map_err(gk)?;
        let server_public: Vec<u8> = output.try_into().map_err(gk)?;
        let session = dh.finish(&server_public).map_err(gk)?;
        Ok(Some(Self {
            conn: conn.clone(),
            owner,
            session,
            session_path,
            events,
            prompt_timeout,
        }))
    }

    /// Every collection (but `session`) and item. Collections that stay
    /// locked are listed in `skipped` with the reason.
    pub async fn fetch_all(&self, skipped: &mut Vec<String>) -> Result<Vec<FetchedCollection>> {
        let service = proxy(&self.conn, &self.owner, SECRETS_PATH, SERVICE).await?;
        let paths: Vec<OwnedObjectPath> = service.get_property("Collections").await.map_err(gk)?;
        let default: OwnedObjectPath =
            service.call("ReadAlias", &("default",)).await.map_err(gk)?;
        let mut out = Vec::new();
        for path in paths {
            if path.as_str() == SESSION_COLLECTION {
                continue;
            }
            let c = proxy(&self.conn, &self.owner, path.as_str(), COLLECTION).await?;
            let label: String = c.get_property("Label").await.map_err(gk)?;
            let locked: bool = c.get_property("Locked").await.map_err(gk)?;
            if locked && !self.unlock(&service, &path).await? {
                skipped.push(format!(
                    "{label} (locked; its unlock was dismissed; run the import again to retry)"
                ));
                continue;
            }
            let items: Vec<OwnedObjectPath> = c.get_property("Items").await.map_err(gk)?;
            out.push(FetchedCollection {
                label,
                is_default: path == default,
                items: self.fetch_items(&items).await?,
            });
        }
        Ok(out)
    }

    /// Unlock one collection through gnome-keyring's prompt; `false` if the
    /// prompt was dismissed or not answered in time.
    async fn unlock(&self, service: &zbus::Proxy<'_>, path: &OwnedObjectPath) -> Result<bool> {
        let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
            .call("Unlock", &(vec![path.clone()],))
            .await
            .map_err(gk)?;
        if unlocked.contains(path) {
            return Ok(true);
        }
        if prompt.as_str() == "/" {
            return Ok(false);
        }
        let p = proxy(&self.conn, &self.owner, prompt.as_str(), PROMPT).await?;
        let mut completed = p.receive_signal("Completed").await.map_err(gk)?;
        if p.call_method("Prompt", &("",)).await.is_err() {
            return Ok(false);
        }
        match tokio::time::timeout(self.prompt_timeout, completed.next()).await {
            Ok(Some(msg)) => {
                let (dismissed, _): (bool, OwnedValue) = msg.body().deserialize().map_err(gk)?;
                Ok(!dismissed)
            }
            _ => Ok(false),
        }
    }

    async fn fetch_items(&self, items: &[OwnedObjectPath]) -> Result<Vec<Fetched>> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let service = proxy(&self.conn, &self.owner, SECRETS_PATH, SERVICE).await?;
        type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
        let secrets: HashMap<OwnedObjectPath, Secret> = service
            .call("GetSecrets", &(items.to_vec(), self.session_path.clone()))
            .await
            .map_err(gk)?;
        let mut out = Vec::new();
        for path in items {
            // (An item deleted meanwhile has no secret: skipped.)
            let Some((_, parameters, value, content_type)) = secrets.get(path) else {
                continue;
            };
            let i = proxy(&self.conn, &self.owner, path.as_str(), ITEM).await?;
            let attributes: HashMap<String, String> =
                i.get_property("Attributes").await.map_err(gk)?;
            let secret = self.session.decrypt(parameters, value).map_err(gk)?;
            out.push(Fetched {
                label: i.get_property("Label").await.map_err(gk)?,
                attributes: attributes.into_iter().collect(),
                secret: SecretBytes::new(secret.to_vec()),
                content_type: content_type.clone(),
                created: i.get_property("Created").await.unwrap_or(0),
                modified: i.get_property("Modified").await.unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Keep importing items gnome-keyring creates or changes until
    /// `org.freedesktop.secrets` changes hands (E1).
    pub async fn follow(mut self, keyring: Arc<Keyring>, secrets: Arc<SecretService>) {
        let Ok(dbus) = zbus::fdo::DBusProxy::new(&self.conn).await else {
            return;
        };
        let Ok(mut owner_changes) = dbus
            .receive_name_owner_changed_with_args(&[(0, SECRETS_NAME)])
            .await
        else {
            return;
        };
        let mut labels: HashMap<String, (String, bool)> = HashMap::new();
        loop {
            let msg = tokio::select! {
                _ = owner_changes.next() => return,
                msg = self.events.next() => match msg {
                    Some(Ok(msg)) => msg,
                    Some(Err(_)) => continue,
                    None => return,
                },
            };
            let header = msg.header();
            let member = header.member().map(|m| m.as_str().to_string());
            if !matches!(member.as_deref(), Some("ItemCreated" | "ItemChanged")) {
                continue;
            }
            let Some(collection) = header.path().map(|p| p.as_str().to_string()) else {
                continue;
            };
            let Ok(item) = msg.body().deserialize::<OwnedObjectPath>() else {
                continue;
            };
            if collection == SESSION_COLLECTION {
                continue;
            }
            if let Err(e) = self
                .import_one(&keyring, &mut labels, &collection, item)
                .await
            {
                tracing::warn!("following gnome-keyring: {e}");
                continue;
            }
            let _ = secrets.unlocked().await;
        }
    }

    async fn import_one(
        &self,
        keyring: &Arc<Keyring>,
        labels: &mut HashMap<String, (String, bool)>,
        collection: &str,
        item: OwnedObjectPath,
    ) -> Result<()> {
        if !labels.contains_key(collection) {
            let c = proxy(&self.conn, &self.owner, collection, COLLECTION).await?;
            let service = proxy(&self.conn, &self.owner, SECRETS_PATH, SERVICE).await?;
            let default: OwnedObjectPath =
                service.call("ReadAlias", &("default",)).await.map_err(gk)?;
            let label: String = c.get_property("Label").await.map_err(gk)?;
            labels.insert(
                collection.to_string(),
                (label, default.as_str() == collection),
            );
        }
        let (label, is_default) = labels[collection].clone();
        let items = self.fetch_items(&[item]).await?;
        let keyring = keyring.clone();
        let summary = tokio::task::spawn_blocking(move || {
            keyring.modify(|body| {
                let mut summary = Summary::default();
                merge(
                    body,
                    vec![FetchedCollection {
                        label,
                        is_default,
                        items,
                    }],
                    &mut summary,
                );
                Ok(summary)
            })
        })
        .await
        .map_err(gk)??;
        if !summary.conflicts.is_empty() {
            tracing::info!(
                "gnome-keyring changed an item after it was imported; kept aleph's: {}",
                summary.conflicts.join(", ")
            );
        }
        Ok(())
    }
}

async fn proxy(
    conn: &Connection,
    owner: &str,
    path: &str,
    interface: &'static str,
) -> Result<zbus::Proxy<'static>> {
    zbus::proxy::Builder::new(conn)
        .destination(owner.to_string())
        .and_then(|b| b.path(path.to_string()))
        .and_then(|b| b.interface(interface))
        .map(|b| b.cache_properties(CacheProperties::No))
        .map_err(gk)?
        .build()
        .await
        .map_err(gk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetched(label: &str, attrs: &[(&str, &str)], secret: &[u8]) -> Fetched {
        Fetched {
            label: label.into(),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            secret: SecretBytes::new(secret.to_vec()),
            content_type: "application/octet-stream".into(),
            created: 111,
            modified: 222,
        }
    }

    fn body() -> Body {
        Body::default()
    }

    /// Default collection to aleph's default; others by label (created);
    /// attributes, content type, and timestamps kept.
    #[test]
    fn items_arrive_with_everything_kept() {
        let mut b = body();
        let mut s = Summary::default();
        merge(
            &mut b,
            vec![
                FetchedCollection {
                    label: "Login".into(),
                    is_default: true,
                    items: vec![fetched(
                        "mail",
                        &[("xdg:schema", "org.x"), ("u", "a")],
                        b"pw",
                    )],
                },
                FetchedCollection {
                    label: "Work".into(),
                    is_default: false,
                    items: vec![fetched("vpn", &[("h", "v")], b"k")],
                },
            ],
            &mut s,
        );
        assert_eq!(s.imported, 2);
        let default = b.resolve_alias(aleph_core::model::DEFAULT_ALIAS).unwrap();
        let mail = &default.items[0];
        assert_eq!(mail.attributes["xdg:schema"], "org.x");
        assert_eq!(mail.content_type, "application/octet-stream");
        assert_eq!((mail.created, mail.modified), (111, 222));
        assert!(
            b.collections
                .iter()
                .any(|c| c.label == "Work" && c.items.len() == 1)
        );
    }

    /// A second import changes nothing; a different secret already here is
    /// a conflict, skipped and listed; duplicates within gnome-keyring all
    /// arrive.
    #[test]
    fn import_is_idempotent_and_never_overwrites() {
        let mut b = body();
        let one = || FetchedCollection {
            label: "Login".into(),
            is_default: true,
            items: vec![fetched("mail", &[("u", "a")], b"pw")],
        };
        merge(&mut b, vec![one()], &mut Summary::default());
        let mut s = Summary::default();
        merge(&mut b, vec![one()], &mut s);
        assert_eq!((s.imported, s.unchanged), (0, 1));
        let mut s = Summary::default();
        merge(
            &mut b,
            vec![FetchedCollection {
                label: "Login".into(),
                is_default: true,
                items: vec![
                    fetched("mail", &[("u", "a")], b"other"),
                    fetched("dup", &[("d", "1")], b"x"),
                    fetched("dup", &[("d", "1")], b"x"),
                ],
            }],
            &mut s,
        );
        assert_eq!(s.conflicts, ["mail (Login)"]);
        assert_eq!(s.imported, 2);
        let default = b.resolve_alias(aleph_core::model::DEFAULT_ALIAS).unwrap();
        assert_eq!(default.items[0].secret.expose(), b"pw");
        assert!(s.to_string().contains("mail (Login)"));
    }
}
```

Apply this patch with `git apply` (save it as `/tmp/t1-impl.patch`):

```diff
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -91,6 +91,7 @@
  "aleph-tpmd",
  "aleph-unlock",
  "cbc",
+ "enumflags2",
  "futures-util",
  "hkdf",
  "libc",
--- a/crates/aleph-cli/src/client.rs
+++ b/crates/aleph-cli/src/client.rs
@@ -35,6 +35,8 @@
     pub keyslots: Vec<SlotInfo>,
     #[serde(default)]
     pub rotation_pending: bool,
+    #[serde(default)]
+    pub secret_service: Option<String>,
 }
 
 /// One item, as the CLI shows it.
@@ -112,6 +114,16 @@
             .await
             .map_err(|e| format!("cannot reach alephd: {e}"))?;
         serde_json::from_str(&json).map_err(err)
+    }
+
+    /// Import gnome-keyring's items (alephd reads them itself); returns
+    /// the summary.
+    pub async fn import_gnome_keyring(&self) -> Result<String> {
+        self.admin()
+            .await?
+            .call("ImportGnomeKeyring", &())
+            .await
+            .map_err(|e| format!("import failed: {e}"))
     }
 
     pub async fn lock(&self) -> Result<()> {
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -26,12 +26,23 @@
     cmd: Cmd,
 }
 
+#[derive(Clone, Copy, clap::ValueEnum)]
+enum ImportSource {
+    /// gnome-keyring, while it still runs (its items stay there).
+    GnomeKeyring,
+}
+
 #[derive(Subcommand)]
 enum Cmd {
     /// Create the keyring (system integration comes in a later release).
     Setup,
     /// Show the keyring's state and keyslots.
     Status,
+    /// Import items from another keyring (alephd reads them itself).
+    Import {
+        #[arg(value_enum)]
+        source: ImportSource,
+    },
     Lock,
     Unlock,
     #[command(subcommand)]
@@ -201,6 +212,9 @@
                     (true, false) => "unlocked",
                 };
                 println!("keyring: {state}");
+                if let Some(owner) = &s.secret_service {
+                    println!("secret service: served by {owner}");
+                }
                 if let Some(why) = &s.untrusted {
                     println!("warning: the vault file was {why}; writes are refused");
                 }
@@ -217,6 +231,9 @@
                 print_slots(&s.keyslots);
             }
         }
+        Cmd::Import {
+            source: ImportSource::GnomeKeyring,
+        } => println!("{}", c.import_gnome_keyring().await?),
         Cmd::Lock => c.lock().await?,
         Cmd::Unlock => outcome(c.converse("Unlock", Args::None).await?)?,
         Cmd::Keyslot(k) => match k {
--- a/crates/aleph-daemon/Cargo.toml
+++ b/crates/aleph-daemon/Cargo.toml
@@ -16,6 +16,7 @@
 [dependencies]
 aes = "0.9"
 cbc = { version = "0.2", features = ["alloc"] }
+enumflags2 = "0.7"
 futures-util = { version = "0.3", default-features = false }
 hkdf.workspace = true
 num-bigint = "0.4"
--- a/crates/aleph-daemon/src/admin.rs
+++ b/crates/aleph-daemon/src/admin.rs
@@ -41,6 +41,9 @@
     Uuid::try_parse(id)
         .map_err(|_| zbus::fdo::Error::InvalidArgs(format!("not a keyslot id: {id:?}")))
 }
+
+/// How long an import waits for gnome-keyring's own unlock prompt.
+const IMPORT_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);
 
 /// The largest backup file read (a vault this size holds a great deal).
 const MAX_BACKUP: u64 = 64 * 1024 * 1024;
@@ -128,14 +131,56 @@
 #[interface(name = "io.aleph.Admin1")]
 impl Admin {
     /// The keyring's state as JSON (`keyring::Status`).
-    async fn status(&self) -> zbus::fdo::Result<String> {
+    async fn status(
+        &self,
+        #[zbus(connection)] conn: &zbus::Connection,
+    ) -> zbus::fdo::Result<String> {
         // Reads the vault header and asks the TPM helper: off the runtime.
         let keyring = self.keyring.clone();
-        let status = tokio::task::spawn_blocking(move || keyring.status())
+        let mut status = tokio::task::spawn_blocking(move || keyring.status())
             .await
             .map_err(failed)?
             .map_err(failed)?;
+        status.secret_service = Some(crate::daemon::secret_service_owner(conn).await);
         serde_json::to_string(&status).map_err(failed)
+    }
+
+    /// Import every gnome-keyring item (DECISIONS.md E1, E2) while
+    /// gnome-keyring still owns `org.freedesktop.secrets`, then keep
+    /// following it until the name changes hands. Returns the summary.
+    async fn import_gnome_keyring(
+        &self,
+        #[zbus(connection)] conn: &zbus::Connection,
+    ) -> zbus::fdo::Result<String> {
+        if self.keyring.is_locked() {
+            return Err(zbus::fdo::Error::Failed(
+                "the keyring is locked: unlock it first (`aleph unlock`)".into(),
+            ));
+        }
+        let Some(importer) = crate::import::Importer::connect(conn, IMPORT_PROMPT_TIMEOUT)
+            .await
+            .map_err(failed)?
+        else {
+            return Ok("gnome-keyring is not running: nothing to import.".into());
+        };
+        let mut summary = crate::import::Summary::default();
+        let fetched = importer
+            .fetch_all(&mut summary.skipped)
+            .await
+            .map_err(failed)?;
+        let keyring = self.keyring.clone();
+        let summary = tokio::task::spawn_blocking(move || {
+            keyring.modify(|body| {
+                crate::import::merge(body, fetched, &mut summary);
+                Ok(summary)
+            })
+        })
+        .await
+        .map_err(failed)?
+        .map_err(failed)?;
+        let _ = self.secrets.unlocked().await;
+        tokio::spawn(importer.follow(self.keyring.clone(), self.secrets.clone()));
+        Ok(summary.to_string())
     }
 
     async fn lock(&self) -> zbus::fdo::Result<()> {
--- a/crates/aleph-daemon/src/daemon.rs
+++ b/crates/aleph-daemon/src/daemon.rs
@@ -13,8 +13,43 @@
 use crate::prompt::Launcher;
 use crate::secret::service::SecretService;
 
+/// Queue for `org.freedesktop.secrets`: never replacing its owner (while
+/// gnome-keyring still runs, say) and never replaceable, so the bus hands
+/// the name over the moment its owner releases it and it is never unowned
+/// (DECISIONS.md E1). Returns whether this connection owns it now.
+pub async fn request_secrets_name(conn: &Connection) -> zbus::Result<bool> {
+    use enumflags2::BitFlag;
+    let reply = conn
+        .request_name_with_flags(
+            crate::import::SECRETS_NAME,
+            zbus::fdo::RequestNameFlags::empty(),
+        )
+        .await?;
+    Ok(matches!(
+        reply,
+        zbus::fdo::RequestNameReply::PrimaryOwner | zbus::fdo::RequestNameReply::AlreadyOwner
+    ))
+}
+
+/// Who owns `org.freedesktop.secrets` on `conn`'s bus, for `Status`:
+/// `alephd`, `another program`, or `nobody`.
+pub async fn secret_service_owner(conn: &Connection) -> String {
+    let Ok(dbus) = zbus::fdo::DBusProxy::new(conn).await else {
+        return "unknown".into();
+    };
+    let Ok(name) = zbus::names::BusName::try_from(crate::import::SECRETS_NAME) else {
+        return "unknown".into();
+    };
+    match dbus.get_name_owner(name).await {
+        Ok(owner) if conn.unique_name().is_some_and(|me| *me == owner) => "alephd".into(),
+        Ok(_) => "another program".into(),
+        Err(_) => "nobody".into(),
+    }
+}
+
 /// Serve the Secret Service and `io.aleph.Admin1` on `conn`, which should
-/// own `org.freedesktop.secrets` and `io.aleph.Keyring`.
+/// own `io.aleph.Keyring` (and then queue for `org.freedesktop.secrets`,
+/// [`request_secrets_name`]).
 pub async fn serve(
     conn: &Connection,
     keyring: Arc<Keyring>,
--- a/crates/aleph-daemon/src/keyring.rs
+++ b/crates/aleph-daemon/src/keyring.rs
@@ -96,6 +96,9 @@
     /// A password change replaced slots without rotating MK (FIDO2 slots
     /// need a touch): `aleph keyslot rotate-master` should follow.
     pub rotation_pending: bool,
+    /// Who owns `org.freedesktop.secrets` (`alephd`, `another program`,
+    /// `nobody`); filled in by the admin interface.
+    pub secret_service: Option<String>,
 }
 
 /// Answers a conversation accepts before giving up.
@@ -264,6 +267,7 @@
             tpm,
             keyslots,
             rotation_pending: inner.state.rotation_pending(),
+            secret_service: None,
         })
     }
 
--- a/crates/aleph-daemon/src/main.rs
+++ b/crates/aleph-daemon/src/main.rs
@@ -47,20 +47,24 @@
         config: config.clone(),
     });
     let conn = zbus::connection::Builder::session()
-        .and_then(|b| b.name(SECRETS_NAME))
         .and_then(|b| b.name(BUS_NAME))
         .map_err(|e| e.to_string())?
         .build()
         .await
-        .map_err(|e| {
-            format!("cannot own {SECRETS_NAME} on the session bus (is gnome-keyring still running?): {e}")
-        })?;
+        .map_err(|e| format!("cannot own {BUS_NAME} on the session bus: {e}"))?;
     let pam_socket = paths.pam_socket();
     let secrets =
         aleph_daemon::daemon::serve(&conn, keyring.clone(), launcher, config.clone(), paths)
             .await
             .map_err(|e| e.to_string())?;
-    tracing::info!("serving {SECRETS_NAME} and {BUS_NAME}");
+    // Queued behind gnome-keyring until it lets go (DECISIONS.md E1).
+    match aleph_daemon::daemon::request_secrets_name(&conn).await {
+        Ok(true) => tracing::info!("serving {SECRETS_NAME} and {BUS_NAME}"),
+        Ok(false) => tracing::info!(
+            "serving {BUS_NAME}; queued for {SECRETS_NAME}, which another program owns"
+        ),
+        Err(e) => return Err(format!("cannot request {SECRETS_NAME}: {e}")),
+    }
     // The lock policy: logind (sleep, screen lock) on the system bus, and
     // the idle timer. Without logind the rest still works.
     match zbus::Connection::system().await {
--- a/crates/aleph-daemon/src/secret/session.rs
+++ b/crates/aleph-daemon/src/secret/session.rs
@@ -65,6 +65,57 @@
     aleph_core::crypto::random_array::<N>().map_err(|_| SessionError::Random)
 }
 
+/// A random DH exponent in [2, p-2].
+fn exponent(p: &BigUint) -> Result<BigUint, SessionError> {
+    Ok(
+        BigUint::from_bytes_be(&*Zeroizing::new(random::<PRIME_LEN>()?)) % (p - BigUint::from(3u8))
+            + BigUint::from(2u8),
+    )
+}
+
+/// The session key from our exponent and the peer's public value (checked
+/// to be in range), as both sides derive it.
+fn derive(peer_bytes: &[u8], x: &BigUint, p: &BigUint) -> Result<Session, SessionError> {
+    let peer = BigUint::from_bytes_be(peer_bytes);
+    let one = BigUint::from(1u8);
+    if peer_bytes.len() > PRIME_LEN || peer <= one || peer >= p - &one {
+        return Err(SessionError::BadInput);
+    }
+    // The byte forms are zeroized; num-bigint cannot zeroize its own limbs
+    // (the exponent and shared value), which is accepted for an ephemeral
+    // per-session key.
+    let shared = Zeroizing::new(peer.modpow(x, p).to_bytes_be());
+    let mut ikm = Zeroizing::new([0u8; PRIME_LEN]);
+    ikm[PRIME_LEN - shared.len()..].copy_from_slice(&shared);
+    let mut key = Zeroizing::new([0u8; 16]);
+    Hkdf::<Sha256>::new(None, &*ikm)
+        .expand(&[], &mut *key)
+        .expect("16 bytes is a valid HKDF length");
+    Ok(Session::Dh { key })
+}
+
+/// The client half of a `dh-ietf1024-sha256-aes128-cbc-pkcs7` exchange,
+/// for alephd reading another Secret Service (the gnome-keyring import).
+pub struct ClientDh {
+    x: BigUint,
+    /// Our public value, the `OpenSession` input.
+    pub public: Vec<u8>,
+}
+
+impl ClientDh {
+    pub fn new() -> Result<Self, SessionError> {
+        let p = prime();
+        let x = exponent(&p)?;
+        let public = BigUint::from(2u8).modpow(&x, &p).to_bytes_be();
+        Ok(Self { x, public })
+    }
+
+    /// The session, from the server's `OpenSession` output.
+    pub fn finish(self, server_public: &[u8]) -> Result<Session, SessionError> {
+        derive(server_public, &self.x, &prime())
+    }
+}
+
 impl Session {
     /// Negotiate a session: returns it and the output for the client (our
     /// DH public value, or nothing for `plain`).
@@ -74,26 +125,9 @@
             PLAIN => Err(SessionError::BadInput),
             DH => {
                 let p = prime();
-                let peer = BigUint::from_bytes_be(input);
-                let one = BigUint::from(1u8);
-                if input.len() > PRIME_LEN || peer <= one || peer >= &p - &one {
-                    return Err(SessionError::BadInput);
-                }
-                let x = BigUint::from_bytes_be(&*Zeroizing::new(random::<PRIME_LEN>()?))
-                    % (&p - BigUint::from(3u8))
-                    + BigUint::from(2u8);
+                let x = exponent(&p)?;
                 let public = BigUint::from(2u8).modpow(&x, &p);
-                // The byte forms are zeroized; num-bigint cannot zeroize
-                // its own limbs (the exponent and shared value), which is
-                // accepted for an ephemeral per-session key.
-                let shared = Zeroizing::new(peer.modpow(&x, &p).to_bytes_be());
-                let mut ikm = Zeroizing::new([0u8; PRIME_LEN]);
-                ikm[PRIME_LEN - shared.len()..].copy_from_slice(&shared);
-                let mut key = Zeroizing::new([0u8; 16]);
-                Hkdf::<Sha256>::new(None, &*ikm)
-                    .expand(&[], &mut *key)
-                    .expect("16 bytes is a valid HKDF length");
-                Ok((Self::Dh { key }, public.to_bytes_be()))
+                Ok((derive(input, &x, &p)?, public.to_bytes_be()))
             }
             other => Err(SessionError::Unsupported(other.into())),
         }
--- a/crates/aleph-daemon/src/testing.rs
+++ b/crates/aleph-daemon/src/testing.rs
@@ -368,15 +368,7 @@
         create_with_password(&keyring);
     }
     let bus = bus();
-    let conn = zbus::connection::Builder::address(bus.address.as_str())
-        .unwrap()
-        .name("org.freedesktop.secrets")
-        .unwrap()
-        .name(crate::admin::BUS_NAME)
-        .unwrap()
-        .build()
-        .await
-        .unwrap();
+    let conn = connect_as_daemon(&bus).await;
     let launcher = Arc::new(InteractiveLauncher::new(prompts));
     let secrets = crate::daemon::serve(
         &conn,
@@ -387,6 +379,7 @@
     )
     .await
     .unwrap();
+    crate::daemon::request_secrets_name(&conn).await.unwrap();
     Daemon {
         secrets,
         keyring,
@@ -394,6 +387,170 @@
         conn,
         env,
     }
+}
+
+/// A connection owning `io.aleph.Keyring` on `bus` (the Secret Service
+/// name is requested, queued, once served).
+async fn connect_as_daemon(bus: &Bus) -> zbus::Connection {
+    zbus::connection::Builder::address(bus.address.as_str())
+        .unwrap()
+        .name(crate::admin::BUS_NAME)
+        .unwrap()
+        .build()
+        .await
+        .unwrap()
+}
+
+/// `daemon_with` on a bus something else may already serve the Secret
+/// Service on (gnome-keyring): alephd queues behind it.
+pub async fn daemon_on(bus: Bus, create: bool) -> Daemon {
+    let env = env();
+    let keyring = Arc::new(keyring_with(
+        &env,
+        Box::new(TpmClient::new(env.socket.clone())),
+        MockKeys::default(),
+        Box::new(Fixed(|p| p == PW)),
+    ));
+    if create {
+        create_with_password(&keyring);
+    }
+    let conn = connect_as_daemon(&bus).await;
+    let secrets = crate::daemon::serve(
+        &conn,
+        keyring.clone(),
+        Arc::new(InteractiveLauncher::new(vec![])),
+        Arc::new(std::sync::Mutex::new(crate::config::Config::default())),
+        env.paths.clone(),
+    )
+    .await
+    .unwrap();
+    crate::daemon::request_secrets_name(&conn).await.unwrap();
+    Daemon {
+        secrets,
+        keyring,
+        bus,
+        conn,
+        env,
+    }
+}
+
+/// A real gnome-keyring (secrets component) on `bus`, with a throwaway
+/// home and its login keyring unlocked with `password`. Killed on drop.
+pub struct GnomeKeyring {
+    child: std::process::Child,
+    address: String,
+    home: tempfile::TempDir,
+}
+
+impl GnomeKeyring {
+    pub fn start(bus: &Bus, password: &str) -> Self {
+        use std::io::Write;
+        let home = tempfile::tempdir().unwrap();
+        let run = home.path().join("run");
+        std::fs::create_dir_all(&run).unwrap();
+        std::fs::set_permissions(&run, std::os::unix::fs::PermissionsExt::from_mode(0o700))
+            .unwrap();
+        let mut child = self::gkr_command(&bus.address, home.path())
+            .args(["--foreground", "--components=secrets", "--unlock"])
+            .stdin(std::process::Stdio::piped())
+            .stdout(std::process::Stdio::null())
+            .stderr(std::process::Stdio::null())
+            .spawn()
+            .expect("gnome-keyring-daemon (Arch: pacman -S gnome-keyring)");
+        let mut stdin = child.stdin.take().unwrap();
+        stdin.write_all(password.as_bytes()).unwrap();
+        drop(stdin);
+        let gk = Self {
+            child,
+            address: bus.address.clone(),
+            home,
+        };
+        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
+        while !gk.owns_secrets() {
+            assert!(
+                std::time::Instant::now() < deadline,
+                "gnome-keyring did not start"
+            );
+            std::thread::sleep(std::time::Duration::from_millis(20));
+        }
+        gk
+    }
+
+    fn owns_secrets(&self) -> bool {
+        std::process::Command::new("busctl")
+            .args([
+                "--address",
+                &self.address,
+                "status",
+                "org.freedesktop.secrets",
+            ])
+            .stdout(std::process::Stdio::null())
+            .stderr(std::process::Stdio::null())
+            .status()
+            .is_ok_and(|s| s.success())
+    }
+
+    /// Store an item in gnome-keyring's default collection (`secret-tool`).
+    pub fn store(&self, label: &str, attributes: &[(&str, &str)], secret: &str) {
+        use std::io::Write;
+        let mut cmd = self::gkr_env(
+            std::process::Command::new("secret-tool"),
+            &self.address,
+            self.home.path(),
+        );
+        cmd.args(["store", "--label", label]);
+        for (k, v) in attributes {
+            cmd.args([*k, *v]);
+        }
+        let mut child = cmd
+            .stdin(std::process::Stdio::piped())
+            .stdout(std::process::Stdio::null())
+            .spawn()
+            .expect("secret-tool (Arch: pacman -S libsecret)");
+        child
+            .stdin
+            .take()
+            .unwrap()
+            .write_all(secret.as_bytes())
+            .unwrap();
+        assert!(child.wait().unwrap().success(), "secret-tool store failed");
+    }
+
+    /// Stop it (it releases `org.freedesktop.secrets`).
+    pub fn stop(mut self) {
+        let _ = self.child.kill();
+        let _ = self.child.wait();
+    }
+}
+
+impl Drop for GnomeKeyring {
+    fn drop(&mut self) {
+        let _ = self.child.kill();
+        let _ = self.child.wait();
+    }
+}
+
+fn gkr_command(address: &str, home: &std::path::Path) -> std::process::Command {
+    gkr_env(
+        std::process::Command::new("gnome-keyring-daemon"),
+        address,
+        home,
+    )
+}
+
+fn gkr_env(
+    mut cmd: std::process::Command,
+    address: &str,
+    home: &std::path::Path,
+) -> std::process::Command {
+    cmd.env("HOME", home)
+        .env("XDG_RUNTIME_DIR", home.join("run"))
+        .env("XDG_DATA_HOME", home.join("data"))
+        .env("XDG_CONFIG_HOME", home.join("config"))
+        .env("DBUS_SESSION_BUS_ADDRESS", address)
+        .env_remove("GNOME_KEYRING_CONTROL")
+        .env_remove("SSH_AUTH_SOCK");
+    cmd
 }
 
 /// A stand-in for logind on a test bus: it hands out sleep inhibitors
--- a/packaging/systemd/alephd.service
+++ b/packaging/systemd/alephd.service
@@ -5,7 +5,9 @@
 [Service]
 # Started by D-Bus activation (org.freedesktop.secrets, io.aleph.Keyring).
 Type=dbus
-BusName=org.freedesktop.secrets
+# (io.aleph.Keyring, not org.freedesktop.secrets: alephd may wait in the
+# queue for the latter while gnome-keyring still owns it.)
+BusName=io.aleph.Keyring
 ExecStart=/usr/lib/aleph/alephd
 Restart=on-failure
 # alephd holds the master key while unlocked: no core dumps (it also sets
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon -p aleph-cli && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 1 passed | ok. 11 passed | ok. 37 passed | ok. 3 passed | ok. 30 passed | ok. 3 passed | ok. 51 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **status names the owner** (`crates/aleph-daemon/src/admin.rs`), test `cargo test -p aleph-daemon --test gnome_keyring items_move_over`:

  replace

  ```rust
  status.secret_service = Some(crate::daemon::secret_service_owner(conn).await);
  ```

  with

  ```rust
  // (nothing)
  ```

- **a different secret here is a conflict, not overwritten** (`crates/aleph-daemon/src/import.rs`), test `cargo test -p aleph-daemon --lib import_is_idempotent`: replace `if !same.is_empty() {` with `if false {`.
- **the import keeps following gnome-keyring** (`crates/aleph-daemon/src/admin.rs`), test `cargo test -p aleph-daemon --test gnome_keyring items_move_over`: replace `tokio::spawn(importer.follow(` with `drop(importer.follow(`.
- **a collection that stays locked is skipped** (`crates/aleph-daemon/src/import.rs`), test `cargo test -p aleph-daemon --test gnome_keyring a_collection_that_stays_locked`: replace `if locked && !self.unlock(&service, &path).await? {` with `if false {`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/aleph-daemon crates/aleph-cli packaging/systemd/alephd.service
git commit -m "feat: import from gnome-keyring, queued for the Secret Service name" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: switchover and revert

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - `import::{ImportedItem, load_imported(&Path), record_imported(&Path, &[ImportedItem]), removed_since(&[ImportedItem], &Body)}`; `Summary::added`; `Importer::follow(self, Arc<Keyring>, Arc<SecretService>, PathBuf)`; `Paths::imported()`
  - `export::{gnome_keyring_active(&Connection) -> bool, Private::{start(&Path, &str), connect(&self)}, Report, export(&Connection, &str, &Body, &[ImportedItem]) -> Result<Report>}`
  - `Keyring::{export(&mut Channel, impl FnOnce(&str, Body) -> Result<String>) -> Result<()>, thaw()}`; `Error::Frozen`
  - Admin `RemovedSinceImport() -> as`, `ExportToGnomeKeyring(h, b)`, `ReleaseSecretService()`, `ThawWrites()`
  - CLI `switchover::{ACTIVATION, GNOME_UNITS, UnitState, Units, Systemctl, Dirs, Record, switch_over, switch_back}`; `aleph setup` (create, import, switch over), `aleph setup --revert`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-cli/src/switchover.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aleph_daemon::testing::{GnomeKeyring, bus, daemon_on};
    use std::sync::Mutex;

    /// systemd, as far as setup can tell: stopping gnome-keyring's service
    /// stops the real gnome-keyring on the test bus.
    struct FakeUnits {
        gk: Mutex<Option<GnomeKeyring>>,
        states: Mutex<BTreeMap<String, UnitState>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeUnits {
        fn new(gk: GnomeKeyring) -> Self {
            let s = |enabled: &str, active| UnitState {
                enabled: enabled.into(),
                active,
            };
            Self {
                gk: Mutex::new(Some(gk)),
                states: Mutex::new(BTreeMap::from([
                    (GNOME_UNITS[0].to_string(), s("static", true)),
                    (GNOME_UNITS[1].to_string(), s("enabled", true)),
                ])),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Units for FakeUnits {
        fn state(&self, unit: &str) -> Result<UnitState> {
            Ok(self.states.lock().unwrap()[unit].clone())
        }

        fn mask(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("mask {}", units.join(" ")));
            for u in units {
                self.states.lock().unwrap().get_mut(*u).unwrap().enabled = "masked".into();
            }
            Ok(())
        }

        fn stop(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("stop {}", units.join(" ")));
            for u in units {
                self.states.lock().unwrap().get_mut(*u).unwrap().active = false;
            }
            if let Some(gk) = self.gk.lock().unwrap().take() {
                gk.stop();
            }
            Ok(())
        }

        fn unmask(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("unmask {}", units.join(" ")));
            Ok(())
        }

        fn enable(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("enable {}", units.join(" ")));
            Ok(())
        }

        fn start(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("start {}", units.join(" ")));
            Ok(())
        }
    }

    /// Switching back removes only aleph's activation files and restores
    /// the units as they were before setup.
    #[tokio::test(flavor = "multi_thread")]
    async fn switching_back_restores_what_setup_changed() {
        let bus = bus();
        let address = bus.address.clone();
        let gk = GnomeKeyring::start(&bus, "login password");
        let _d = daemon_on(bus, true).await;
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs {
            data_home: home.path().join("data"),
            state_home: home.path().join("state"),
        };
        let units = FakeUnits::new(gk);
        let mut record = Record::load(&dirs).unwrap();
        switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        // Someone edited one activation file: it stays.
        let changed = dirs.services().join(ACTIVATION[1].0);
        std::fs::write(&changed, "edited").unwrap();
        units.calls.lock().unwrap().clear();
        let mut record = Record::load(&dirs).unwrap();
        let done = switch_back(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        assert!(!dirs.services().join(ACTIVATION[0].0).exists());
        assert!(changed.exists());
        assert!(
            done.iter().any(|d| d.contains("changed since setup")),
            "{done:?}"
        );
        assert_eq!(
            *units.calls.lock().unwrap(),
            [
                format!("unmask {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
                format!("enable {}", GNOME_UNITS[1]),
                format!("start {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
            ]
        );
        assert!(Record::load(&dirs).unwrap().units.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gnome_keyring_hands_over_and_a_rerun_changes_nothing() {
        let bus = bus();
        let address = bus.address.clone();
        let gk = GnomeKeyring::start(&bus, "login password");
        let d = daemon_on(bus, true).await;
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs {
            data_home: home.path().join("data"),
            state_home: home.path().join("state"),
        };
        let units = FakeUnits::new(gk);
        let mut record = Record::load(&dirs).unwrap();
        let done = switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        assert_eq!(done.len(), 4, "{done:?}");
        assert_eq!(
            aleph_daemon::daemon::secret_service_owner(&d.conn).await,
            "alephd"
        );
        for (name, contents) in ACTIVATION {
            assert_eq!(
                std::fs::read_to_string(dirs.services().join(name)).unwrap(),
                contents
            );
        }
        // The states before setup are what revert restores.
        let saved = Record::load(&dirs).unwrap();
        assert_eq!(saved.units[GNOME_UNITS[1]].enabled, "enabled");
        assert!(saved.units[GNOME_UNITS[0]].active);
        assert_eq!(
            *units.calls.lock().unwrap(),
            [
                format!("mask {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
                format!("stop {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
            ]
        );
        // Again: only the check.
        let mut record = Record::load(&dirs).unwrap();
        let done = switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        assert_eq!(done, ["alephd serves the Secret Service"]);
        assert_eq!(units.calls.lock().unwrap().len(), 2);
        assert_eq!(
            Record::load(&dirs).unwrap().units[GNOME_UNITS[1]].enabled,
            "enabled"
        );
    }

    /// Something still holding the name (gnome-keyring started outside
    /// systemd) is reported, not waited on forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_gnome_keyring_outside_systemd_is_reported() {
        let bus = bus();
        let address = bus.address.clone();
        let gk = GnomeKeyring::start(&bus, "login password");
        let _d = daemon_on(bus, true).await;
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs {
            data_home: home.path().join("data"),
            state_home: home.path().join("state"),
        };
        let units = FakeUnits::new(gk);
        // (systemd stops nothing: the fixture outlives the "stop".)
        let kept = units.gk.lock().unwrap().take();
        let mut record = Record::default();
        let err = switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap_err();
        assert!(err.contains("pkill"), "{err}");
        drop(kept);
    }
}
```

Write `crates/aleph-daemon/tests/gnome_keyring.rs`:

```rust
//! Importing from a real gnome-keyring on a private bus (DECISIONS.md E1,
//! E2, E11): alephd queues behind it for `org.freedesktop.secrets`, reads
//! its items over an encrypted session, keeps following it, and takes the
//! name the moment gnome-keyring lets go.

use aleph_daemon::testing::*;

async fn client(address: &str) -> zbus::Connection {
    zbus::connection::Builder::address(address)
        .unwrap()
        .build()
        .await
        .unwrap()
}

async fn admin(c: &zbus::Connection, method: &str) -> zbus::Result<String> {
    c.call_method(
        Some(aleph_daemon::admin::BUS_NAME),
        aleph_daemon::admin::ADMIN_PATH,
        Some("io.aleph.Admin1"),
        method,
        &(),
    )
    .await?
    .body()
    .deserialize()
}

fn items_labelled(
    d: &Daemon,
    label: &str,
) -> Vec<(String, std::collections::BTreeMap<String, String>, Vec<u8>)> {
    d.keyring
        .read(|b| {
            b.collections
                .iter()
                .flat_map(|c| c.items.iter())
                .filter(|i| i.label == label)
                .map(|i| {
                    (
                        i.content_type.clone(),
                        i.attributes.clone(),
                        i.secret.expose().to_vec(),
                    )
                })
                .collect()
        })
        .unwrap()
}

async fn eventually(what: &str, mut ok: impl AsyncFnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !ok().await {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting: {what}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn items_move_over_and_the_name_changes_hands() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store(
        "Mail",
        &[
            ("xdg:schema", "org.example.Mail"),
            ("service", "mail"),
            ("user", "alice"),
        ],
        "s3cret",
    );
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    let status: serde_json::Value =
        serde_json::from_str(&admin(&c, "Status").await.unwrap()).unwrap();
    assert_eq!(status["secret_service"], "another program");

    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    assert!(summary.contains("Imported 1 item"), "{summary}");
    let mail = items_labelled(&d, "Mail");
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].1["user"], "alice");
    assert_eq!(mail[0].1["xdg:schema"], "org.example.Mail");
    assert_eq!(mail[0].2, b"s3cret");
    // Again: nothing new.
    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    assert!(
        summary.contains("Imported 0 item(s) from gnome-keyring (1 already here)"),
        "{summary}"
    );

    // Stored in gnome-keyring after the import: followed.
    gk.store("Later", &[("service", "later")], "stored later");
    eventually("the later item", async || {
        items_labelled(&d, "Later").len() == 1
    })
    .await;

    // gnome-keyring lets go: the name is alephd's at once.
    gk.stop();
    eventually("the name handoff", async || {
        aleph_daemon::daemon::secret_service_owner(&d.conn).await == "alephd"
    })
    .await;
    // And alephd serves the imported item to Secret Service clients.
    let found: Vec<zbus::zvariant::OwnedObjectPath> = c
        .call_method(
            Some("org.freedesktop.secrets"),
            "/org/freedesktop/secrets",
            Some("org.freedesktop.Secret.Service"),
            "SearchItems",
            &(std::collections::HashMap::from([("service", "mail")]),),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<(
            Vec<zbus::zvariant::OwnedObjectPath>,
            Vec<zbus::zvariant::OwnedObjectPath>,
        )>()
        .unwrap()
        .0;
    assert_eq!(found.len(), 1);
}

/// A locked gnome-keyring collection whose unlock prompt cannot be shown
/// (or is dismissed) is skipped with a message, not waited on forever.
#[tokio::test(flavor = "multi_thread")]
async fn a_collection_that_stays_locked_is_skipped_with_a_message() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Mail", &[("service", "mail")], "s3cret");
    let c = client(&address).await;
    c.call_method(
        Some("org.freedesktop.secrets"),
        "/org/freedesktop/secrets",
        Some("org.freedesktop.Secret.Service"),
        "Lock",
        &(vec![
            zbus::zvariant::ObjectPath::try_from("/org/freedesktop/secrets/collection/login")
                .unwrap(),
        ],),
    )
    .await
    .unwrap();
    let d = daemon_on(bus, true).await;
    let started = std::time::Instant::now();
    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    eprintln!("took {:?}: {summary}", started.elapsed());
    assert!(summary.contains("Imported 0"), "{summary}");
    assert!(summary.contains("locked"), "{summary}");
    assert!(items_labelled(&d, "Mail").is_empty());
}

/// Without gnome-keyring there is nothing to import, and nothing fails.
#[tokio::test(flavor = "multi_thread")]
async fn without_gnome_keyring_there_is_nothing_to_import() {
    let d = daemon(true, vec![]).await;
    let c = client(&d.bus.address).await;
    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    assert!(summary.contains("not running"), "{summary}");
}

/// `ExportToGnomeKeyring` with a prompter answering `replies`: (ok, message).
async fn export(d: &Daemon, delete: bool, replies: Vec<FromPrompter>) -> (bool, Option<String>) {
    use std::os::fd::OwnedFd;
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let prompter = Interactive::new(replies);
    prompter.respond(ours);
    let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
    let c = client(&d.bus.address).await;
    c.call_method(
        Some(aleph_daemon::admin::BUS_NAME),
        aleph_daemon::admin::ADMIN_PATH,
        Some("io.aleph.Admin1"),
        "ExportToGnomeKeyring",
        &(fd, delete),
    )
    .await
    .unwrap();
    let sent = tokio::task::spawn_blocking(move || prompter.sent())
        .await
        .unwrap();
    match sent.last() {
        Some(ToPrompter::Done { ok, message }) => (*ok, message.clone()),
        other => panic!("the export did not finish: {other:?}"),
    }
}

fn add(d: &Daemon, collection: Option<&str>, label: &str, attrs: &[(&str, &str)], secret: &str) {
    d.keyring
        .modify(|b| {
            let id = match collection {
                None => {
                    b.resolve_alias(aleph_core::model::DEFAULT_ALIAS)
                        .unwrap()
                        .id
                }
                Some(name) => match b.collections.iter().find(|c| c.label == name) {
                    Some(c) => c.id,
                    None => {
                        let c = aleph_core::Collection::new(name);
                        let id = c.id;
                        b.collections.push(c);
                        id
                    }
                },
            };
            b.collection_mut(id).unwrap().upsert(
                aleph_core::Item::new(
                    label,
                    attrs
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                    aleph_core::SecretBytes::new(secret.as_bytes().to_vec()),
                    "text/plain",
                ),
                false,
            );
            Ok(())
        })
        .unwrap();
}

/// The number of items gnome-keyring on `conn`'s bus finds for `attrs`.
async fn found(conn: &zbus::Connection, attrs: &[(&str, &str)]) -> usize {
    let attrs: std::collections::HashMap<&str, &str> = attrs.iter().copied().collect();
    let (unlocked, locked): (
        Vec<zbus::zvariant::OwnedObjectPath>,
        Vec<zbus::zvariant::OwnedObjectPath>,
    ) = conn
        .call_method(
            Some("org.freedesktop.secrets"),
            "/org/freedesktop/secrets",
            Some("org.freedesktop.Secret.Service"),
            "SearchItems",
            &(attrs,),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    unlocked.len() + locked.len()
}

/// Everything goes back to gnome-keyring (a collection it lacks into its
/// default one) and is read back; writes pause until the revert ends or
/// they are resumed; a second export finds everything there.
#[tokio::test(flavor = "multi_thread")]
async fn items_are_copied_back_and_writes_pause() {
    let d = daemon(true, vec![]).await;
    add(&d, None, "Mail", &[("service", "mail")], "s3cret");
    add(&d, Some("Work"), "VPN", &[("service", "vpn")], "k3y");
    let (ok, message) = export(&d, false, vec![password(PW)]).await;
    let message = message.unwrap_or_default();
    assert!(ok, "{message}");
    assert!(message.contains("Copied 2 item(s)"), "{message}");
    assert!(message.contains("default collection"), "{message}");
    assert!(matches!(
        d.keyring.modify(|_| Ok(())),
        Err(aleph_daemon::Error::Frozen)
    ));
    admin(&client(&d.bus.address).await, "ThawWrites")
        .await
        .ok();
    d.keyring.modify(|_| Ok(())).unwrap();
    // Read back by a gnome-keyring of our own over the same files.
    let data_home = d.env.paths.data_dir.parent().unwrap().to_path_buf();
    {
        let gk = aleph_daemon::export::Private::start(&data_home, PW)
            .await
            .unwrap();
        let c = gk.connect().await.unwrap();
        assert_eq!(found(&c, &[("service", "mail")]).await, 1);
        assert_eq!(found(&c, &[("service", "vpn")]).await, 1);
    }
    let (ok, message) = export(&d, false, vec![password(PW)]).await;
    assert!(ok);
    assert!(message.unwrap().contains("2 already there"));
}

/// A login keyring that does not open with the login password (their
/// passwords differ) changes nothing, and writes are not paused.
#[tokio::test(flavor = "multi_thread")]
async fn a_login_keyring_that_does_not_unlock_changes_nothing() {
    let d = daemon(true, vec![]).await;
    add(&d, None, "Mail", &[("service", "mail")], "s3cret");
    let data_home = d.env.paths.data_dir.parent().unwrap().to_path_buf();
    drop(
        aleph_daemon::export::Private::start(&data_home, "another password")
            .await
            .unwrap(),
    );
    let (ok, message) = export(&d, false, vec![password(PW)]).await;
    assert!(!ok);
    assert!(message.unwrap().contains("did not unlock"));
    d.keyring.modify(|_| Ok(())).unwrap();
}

/// Revert does not run a second gnome-keyring over the same files.
#[tokio::test(flavor = "multi_thread")]
async fn revert_refuses_while_gnome_keyring_runs() {
    let bus = bus();
    let _gk = GnomeKeyring::start(&bus, "login password");
    let d = daemon_on(bus, true).await;
    use std::os::fd::OwnedFd;
    let (_ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
    let err = client(&d.bus.address)
        .await
        .call_method(
            Some(aleph_daemon::admin::BUS_NAME),
            aleph_daemon::admin::ADMIN_PATH,
            Some("io.aleph.Admin1"),
            "ExportToGnomeKeyring",
            &(fd, false),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("gnome-keyring is running"),
        "{err}"
    );
}

/// Items imported and deleted in aleph since are listed, and deleted in
/// gnome-keyring too when asked; the rest stays.
#[tokio::test(flavor = "multi_thread")]
async fn items_deleted_since_the_import_are_deleted_there_too() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Gone", &[("k", "gone")], "x");
    gk.store("Kept", &[("k", "kept")], "y");
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    admin(&c, "ImportGnomeKeyring").await.unwrap();
    d.keyring
        .modify(|b| {
            for col in &mut b.collections {
                col.items.retain(|i| i.label != "Gone");
            }
            Ok(())
        })
        .unwrap();
    let removed: Vec<String> = c
        .call_method(
            Some(aleph_daemon::admin::BUS_NAME),
            aleph_daemon::admin::ADMIN_PATH,
            Some("io.aleph.Admin1"),
            "RemovedSinceImport",
            &(),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(removed, ["Gone (Login)"]);
    // (Straight to the export, against the running gnome-keyring.)
    let body = d.keyring.read(|b| b.clone()).unwrap();
    let delete = aleph_daemon::import::removed_since(
        &aleph_daemon::import::load_imported(&d.env.paths.imported()),
        &body,
    );
    let report = aleph_daemon::export::export(&c, &address, &body, &delete)
        .await
        .unwrap();
    assert_eq!(
        (report.exported, report.unchanged, report.deleted),
        (0, 1, 1)
    );
    assert_eq!(found(&c, &[("k", "gone")]).await, 0);
    assert_eq!(found(&c, &[("k", "kept")]).await, 1);
}

/// Nobody can take the Secret Service name from alephd: it never allows
/// replacement, so even `ReplaceExisting` just queues.
#[tokio::test(flavor = "multi_thread")]
async fn the_name_cannot_be_taken_from_alephd() {
    let d = daemon(true, vec![]).await;
    let other = client(&d.bus.address).await;
    let reply = other
        .request_name_with_flags(
            "org.freedesktop.secrets",
            zbus::fdo::RequestNameFlags::ReplaceExisting.into(),
        )
        .await
        .unwrap();
    assert_eq!(reply, zbus::fdo::RequestNameReply::InQueue);
    assert_eq!(
        aleph_daemon::daemon::secret_service_owner(&d.conn).await,
        "alephd"
    );
}
```

Delete `crates/aleph-daemon/tests/import.rs` (`git rm crates/aleph-daemon/tests/import.rs`).

Apply this patch with `git apply` (save it as `/tmp/t2-tests.patch`):

```diff
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -7,6 +7,7 @@
 
 mod client;
 mod prompter;
+mod switchover;
 
 use std::collections::HashMap;
 use std::io::{IsTerminal, Read, Write};
--- a/crates/aleph-cli/tests/cli.rs
+++ b/crates/aleph-cli/tests/cli.rs
@@ -7,9 +7,16 @@
 use aleph_daemon::testing::*;
 
 fn aleph(d: &Daemon, args: &[&str]) -> Command {
+    // Never the real home or user manager: setup writes activation files
+    // and runs systemctl (`false`: no unit exists, and any change fails).
+    let home = d.env.paths.data_dir.parent().unwrap().join("home");
     let mut cmd = Command::new(env!("CARGO_BIN_EXE_aleph"));
     cmd.args(args)
         .env("DBUS_SESSION_BUS_ADDRESS", &d.bus.address)
+        .env("HOME", &home)
+        .env("XDG_DATA_HOME", home.join("data"))
+        .env("XDG_STATE_HOME", home.join("state"))
+        .env("ALEPH_SYSTEMCTL", "false")
         .env("ALEPH_NO_TTY", "1")
         .stdin(Stdio::piped())
         .stdout(Stdio::piped())
@@ -108,9 +115,15 @@
     assert!(out.contains("keyring: none"), "{out}");
     let log = setup(&d).await;
     assert!(log.contains("The keyring is ready."), "{log}");
-    assert!(
-        log.contains("not available yet"),
-        "setup should say what is missing: {log}"
+    // Then the import (no gnome-keyring here) and the switchover (alephd
+    // already serves the name); PAM is still by hand.
+    assert!(log.contains("gnome-keyring is not running"), "{log}");
+    assert!(log.contains("alephd serves the Secret Service"), "{log}");
+    assert!(log.contains("docs/testing.md"), "{log}");
+    let home = d.env.paths.data_dir.parent().unwrap().join("home");
+    assert!(
+        home.join("data/dbus-1/services/org.freedesktop.secrets.service")
+            .exists()
     );
     let (ok, out, _) = run(&d, &["status", "--json"], "").await;
     assert!(ok);
@@ -358,3 +371,44 @@
         "{out}"
     );
 }
+
+/// `aleph setup --revert` copies the keyring to gnome-keyring (the login
+/// password unlocks it), verifies it, and lets go of the Secret Service.
+#[tokio::test(flavor = "multi_thread")]
+async fn setup_revert_hands_everything_back() {
+    let d = daemon(true, vec![]).await;
+    run(&d, &["store", "--label", "Mail", "service=mail"], "s3cret").await;
+    let (ok, _, err) = run(&d, &["setup", "--revert"], &format!("{PW}\n")).await;
+    assert!(ok, "{err}");
+    assert!(err.contains("Copied 1 item(s)"), "{err}");
+    assert!(
+        err.contains("gnome-keyring serves the Secret Service again"),
+        "{err}"
+    );
+    assert_eq!(
+        aleph_daemon::daemon::secret_service_owner(&d.conn).await,
+        "nobody"
+    );
+    let data_home = d.env.paths.data_dir.parent().unwrap().to_path_buf();
+    let gk = aleph_daemon::export::Private::start(&data_home, PW)
+        .await
+        .unwrap();
+    let c = gk.connect().await.unwrap();
+    let (found, _): (
+        Vec<zbus::zvariant::OwnedObjectPath>,
+        Vec<zbus::zvariant::OwnedObjectPath>,
+    ) = c
+        .call_method(
+            Some("org.freedesktop.secrets"),
+            "/org/freedesktop/secrets",
+            Some("org.freedesktop.Secret.Service"),
+            "SearchItems",
+            &(std::collections::HashMap::from([("service", "mail")]),),
+        )
+        .await
+        .unwrap()
+        .body()
+        .deserialize()
+        .unwrap();
+    assert_eq!(found.len(), 1);
+}
--- a/crates/aleph-daemon/src/lib.rs
+++ b/crates/aleph-daemon/src/lib.rs
@@ -4,6 +4,7 @@
 pub mod config;
 pub mod daemon;
 pub mod error;
+pub mod export;
 pub mod import;
 pub mod keyring;
 pub mod lockpolicy;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon -p aleph-cli`
Expected: the build fails: the `export` module, `switchover`, and the revert admin methods do not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-cli/src/switchover.rs`:

```rust
//! Switching the session's Secret Service from gnome-keyring to alephd
//! (spec §6 "Startup and switchover"; DECISIONS.md E9, E10). User-level
//! only: D-Bus activation files, the bus's configuration, and systemd user
//! units. Every step checks the real state first, so a re-run does only
//! what is still undone.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, String>;

pub const SECRETS_NAME: &str = "org.freedesktop.secrets";
pub const ALEPH_NAME: &str = "io.aleph.Keyring";
/// gnome-keyring's user units (masked, then stopped).
pub const GNOME_UNITS: [&str; 2] = [
    "gnome-keyring-daemon.service",
    "gnome-keyring-daemon.socket",
];

/// User-level D-Bus activation files, which take precedence over the
/// system ones: the Secret Service name starts alephd, and gnome-keyring's
/// own names (which would start it directly, bypassing systemd) start
/// nothing.
pub const ACTIVATION: [(&str, &str); 3] = [
    (
        "org.freedesktop.secrets.service",
        "[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/usr/lib/aleph/alephd\nSystemdService=alephd.service\n",
    ),
    (
        "org.gnome.keyring.service",
        "# Disabled by aleph setup (aleph serves the Secret Service).\n[D-BUS Service]\nName=org.gnome.keyring\nExec=/bin/false\n",
    ),
    (
        "org.freedesktop.impl.portal.Secret.service",
        "# Disabled by aleph setup (aleph serves the Secret Service).\n[D-BUS Service]\nName=org.freedesktop.impl.portal.Secret\nExec=/bin/false\n",
    ),
];

/// A unit's state before setup changed it (for revert).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitState {
    /// `systemctl is-enabled` (enabled, disabled, static, masked, ...).
    pub enabled: String,
    pub active: bool,
}

/// systemd user units, as setup uses them.
pub trait Units {
    fn state(&self, unit: &str) -> Result<UnitState>;
    fn mask(&self, units: &[&str]) -> Result<()>;
    fn stop(&self, units: &[&str]) -> Result<()>;
    fn unmask(&self, units: &[&str]) -> Result<()>;
    fn enable(&self, units: &[&str]) -> Result<()>;
    fn start(&self, units: &[&str]) -> Result<()>;
}

/// The real thing: `systemctl --user` (`ALEPH_SYSTEMCTL` names another
/// program, for tests, which must never touch the real user manager).
pub struct Systemctl;

impl Systemctl {
    fn program() -> std::ffi::OsString {
        std::env::var_os("ALEPH_SYSTEMCTL").unwrap_or_else(|| "systemctl".into())
    }

    fn run(args: &[&str]) -> Result<String> {
        let out = std::process::Command::new(Self::program())
            .arg("--user")
            .args(args)
            .output()
            .map_err(|e| format!("systemctl: {e}"))?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn checked(args: &[&str]) -> Result<()> {
        let out = std::process::Command::new(Self::program())
            .arg("--user")
            .args(args)
            .output()
            .map_err(|e| format!("systemctl: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "systemctl --user {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

impl Units for Systemctl {
    fn state(&self, unit: &str) -> Result<UnitState> {
        // (Both commands exit non-zero for "disabled" or "inactive": their
        // output is what counts.)
        let enabled = Self::run(&["is-enabled", unit])?;
        let active = Self::run(&["is-active", unit])? == "active";
        Ok(UnitState {
            enabled: if enabled.is_empty() {
                "not-found".into()
            } else {
                enabled
            },
            active,
        })
    }

    fn mask(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["mask"], units].concat())
    }

    fn stop(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["stop"], units].concat())
    }

    fn unmask(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["unmask"], units].concat())
    }

    fn enable(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["enable"], units].concat())
    }

    fn start(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["start"], units].concat())
    }
}

/// Where setup's user-level files go.
pub struct Dirs {
    /// `$XDG_DATA_HOME` (activation files under `dbus-1/services`).
    pub data_home: PathBuf,
    /// `$XDG_STATE_HOME` (setup's record under `aleph`).
    pub state_home: PathBuf,
}

impl Dirs {
    pub fn from_env() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")?;
        let xdg = |var: &str, default: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(default))
        };
        Ok(Self {
            data_home: xdg("XDG_DATA_HOME", ".local/share"),
            state_home: xdg("XDG_STATE_HOME", ".local/state"),
        })
    }

    pub fn services(&self) -> PathBuf {
        self.data_home.join("dbus-1/services")
    }

    fn record(&self) -> PathBuf {
        self.state_home.join("aleph/setup.json")
    }
}

/// What setup records: only choices and what it must restore (E10: the
/// real state is checked on every run, never trusted from here).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Record {
    /// gnome-keyring's units as they were before setup first changed them.
    #[serde(default)]
    pub units: BTreeMap<String, UnitState>,
}

impl Record {
    pub fn load(dirs: &Dirs) -> Result<Self> {
        match std::fs::read(dirs.record()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("{}: {e}", dirs.record().display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", dirs.record().display())),
        }
    }

    pub fn save(&self, dirs: &Dirs) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&dirs.record(), &bytes)
    }
}

/// Write `path` through a temporary file and a rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or("no parent directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = path.with_extension("aleph-tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

async fn owner(bus: &zbus::Connection, name: &str) -> Option<String> {
    let dbus = zbus::fdo::DBusProxy::new(bus).await.ok()?;
    let name = zbus::names::BusName::try_from(name).ok()?;
    dbus.get_name_owner(name).await.ok().map(|o| o.to_string())
}

/// Hand the session's Secret Service to alephd (E9's order): activation
/// files and a bus reload; the prior unit states recorded (once); units
/// masked, then stopped; then the name's owner checked. Returns what was
/// done, one line per step.
pub async fn switch_over(
    bus: &zbus::Connection,
    units: &dyn Units,
    dirs: &Dirs,
    record: &mut Record,
) -> Result<Vec<String>> {
    let mut done = Vec::new();
    let services = dirs.services();
    let mut wrote = false;
    for (name, contents) in ACTIVATION {
        let path = services.join(name);
        if std::fs::read(&path).ok().as_deref() != Some(contents.as_bytes()) {
            write_atomic(&path, contents.as_bytes())?;
            wrote = true;
        }
    }
    if wrote {
        // dbus-broker does not notice new activation files by itself.
        bus.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "ReloadConfig",
            &(),
        )
        .await
        .map_err(|e| format!("reloading the bus configuration: {e}"))?;
        done.push(format!(
            "installed D-Bus activation files in {}",
            services.display()
        ));
    }
    let mut states = Vec::new();
    for unit in GNOME_UNITS {
        states.push((unit, units.state(unit)?));
    }
    if record.units.is_empty() {
        record.units = states
            .iter()
            .map(|(u, s)| (u.to_string(), s.clone()))
            .collect();
        record.save(dirs)?;
    }
    let to_mask: Vec<&str> = states
        .iter()
        .filter(|(_, s)| s.enabled != "masked" && s.enabled != "not-found")
        .map(|(u, _)| *u)
        .collect();
    if !to_mask.is_empty() {
        units.mask(&to_mask)?;
        done.push(format!("masked {}", to_mask.join(", ")));
    }
    let to_stop: Vec<&str> = states
        .iter()
        .filter(|(_, s)| s.active)
        .map(|(u, _)| *u)
        .collect();
    if !to_stop.is_empty() {
        units.stop(&to_stop)?;
        done.push("stopped gnome-keyring (its pkcs11 component goes away with it)".into());
    }
    // The bus hands the name to the queued alephd at once.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let aleph = owner(bus, ALEPH_NAME).await;
        let secrets = owner(bus, SECRETS_NAME).await;
        if aleph.is_some() && aleph == secrets {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err(
                "another program still owns org.freedesktop.secrets (gnome-keyring started outside systemd? end it with `pkill -x gnome-keyring-d`, then run setup again)"
                    .into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    done.push("alephd serves the Secret Service".into());
    Ok(done)
}

/// Give the Secret Service back to gnome-keyring, after a verified export
/// (E3's order): alephd's activation files removed (only if still ours)
/// and the bus reloaded; gnome-keyring's units unmasked and restored as
/// recorded. The caller then has alephd let go of the name, which the bus
/// hands to gnome-keyring, queued behind it.
pub async fn switch_back(
    bus: &zbus::Connection,
    units: &dyn Units,
    dirs: &Dirs,
    record: &mut Record,
) -> Result<Vec<String>> {
    let mut done = Vec::new();
    let services = dirs.services();
    let mut removed = false;
    for (name, contents) in ACTIVATION {
        let path = services.join(name);
        match std::fs::read(&path) {
            Ok(bytes) if bytes == contents.as_bytes() => {
                std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                removed = true;
            }
            Ok(_) => done.push(format!("left {} (changed since setup)", path.display())),
            Err(_) => {}
        }
    }
    if removed {
        bus.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "ReloadConfig",
            &(),
        )
        .await
        .map_err(|e| format!("reloading the bus configuration: {e}"))?;
        done.push(format!(
            "removed aleph's D-Bus activation files from {}",
            services.display()
        ));
    }
    let recorded: Vec<(String, UnitState)> = record
        .units
        .iter()
        .map(|(u, s)| (u.clone(), s.clone()))
        .collect();
    let mut unmask = Vec::new();
    let mut enable = Vec::new();
    let mut start = Vec::new();
    for (unit, before) in &recorded {
        let now = units.state(unit)?;
        if now.enabled == "masked" && before.enabled != "masked" {
            unmask.push(unit.as_str());
        }
        if before.enabled == "enabled" {
            enable.push(unit.as_str());
        }
        if before.active {
            start.push(unit.as_str());
        }
    }
    if !unmask.is_empty() {
        units.unmask(&unmask)?;
        done.push(format!("unmasked {}", unmask.join(", ")));
    }
    if !enable.is_empty() {
        units.enable(&enable)?;
    }
    if !start.is_empty() {
        units.start(&start)?;
        done.push("started gnome-keyring".into());
    }
    record.units.clear();
    record.save(dirs)?;
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aleph_daemon::testing::{GnomeKeyring, bus, daemon_on};
    use std::sync::Mutex;

    /// systemd, as far as setup can tell: stopping gnome-keyring's service
    /// stops the real gnome-keyring on the test bus.
    struct FakeUnits {
        gk: Mutex<Option<GnomeKeyring>>,
        states: Mutex<BTreeMap<String, UnitState>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeUnits {
        fn new(gk: GnomeKeyring) -> Self {
            let s = |enabled: &str, active| UnitState {
                enabled: enabled.into(),
                active,
            };
            Self {
                gk: Mutex::new(Some(gk)),
                states: Mutex::new(BTreeMap::from([
                    (GNOME_UNITS[0].to_string(), s("static", true)),
                    (GNOME_UNITS[1].to_string(), s("enabled", true)),
                ])),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Units for FakeUnits {
        fn state(&self, unit: &str) -> Result<UnitState> {
            Ok(self.states.lock().unwrap()[unit].clone())
        }

        fn mask(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("mask {}", units.join(" ")));
            for u in units {
                self.states.lock().unwrap().get_mut(*u).unwrap().enabled = "masked".into();
            }
            Ok(())
        }

        fn stop(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("stop {}", units.join(" ")));
            for u in units {
                self.states.lock().unwrap().get_mut(*u).unwrap().active = false;
            }
            if let Some(gk) = self.gk.lock().unwrap().take() {
                gk.stop();
            }
            Ok(())
        }

        fn unmask(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("unmask {}", units.join(" ")));
            Ok(())
        }

        fn enable(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("enable {}", units.join(" ")));
            Ok(())
        }

        fn start(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("start {}", units.join(" ")));
            Ok(())
        }
    }

    /// Switching back removes only aleph's activation files and restores
    /// the units as they were before setup.
    #[tokio::test(flavor = "multi_thread")]
    async fn switching_back_restores_what_setup_changed() {
        let bus = bus();
        let address = bus.address.clone();
        let gk = GnomeKeyring::start(&bus, "login password");
        let _d = daemon_on(bus, true).await;
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs {
            data_home: home.path().join("data"),
            state_home: home.path().join("state"),
        };
        let units = FakeUnits::new(gk);
        let mut record = Record::load(&dirs).unwrap();
        switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        // Someone edited one activation file: it stays.
        let changed = dirs.services().join(ACTIVATION[1].0);
        std::fs::write(&changed, "edited").unwrap();
        units.calls.lock().unwrap().clear();
        let mut record = Record::load(&dirs).unwrap();
        let done = switch_back(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        assert!(!dirs.services().join(ACTIVATION[0].0).exists());
        assert!(changed.exists());
        assert!(
            done.iter().any(|d| d.contains("changed since setup")),
            "{done:?}"
        );
        assert_eq!(
            *units.calls.lock().unwrap(),
            [
                format!("unmask {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
                format!("enable {}", GNOME_UNITS[1]),
                format!("start {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
            ]
        );
        assert!(Record::load(&dirs).unwrap().units.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gnome_keyring_hands_over_and_a_rerun_changes_nothing() {
        let bus = bus();
        let address = bus.address.clone();
        let gk = GnomeKeyring::start(&bus, "login password");
        let d = daemon_on(bus, true).await;
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs {
            data_home: home.path().join("data"),
            state_home: home.path().join("state"),
        };
        let units = FakeUnits::new(gk);
        let mut record = Record::load(&dirs).unwrap();
        let done = switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        assert_eq!(done.len(), 4, "{done:?}");
        assert_eq!(
            aleph_daemon::daemon::secret_service_owner(&d.conn).await,
            "alephd"
        );
        for (name, contents) in ACTIVATION {
            assert_eq!(
                std::fs::read_to_string(dirs.services().join(name)).unwrap(),
                contents
            );
        }
        // The states before setup are what revert restores.
        let saved = Record::load(&dirs).unwrap();
        assert_eq!(saved.units[GNOME_UNITS[1]].enabled, "enabled");
        assert!(saved.units[GNOME_UNITS[0]].active);
        assert_eq!(
            *units.calls.lock().unwrap(),
            [
                format!("mask {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
                format!("stop {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
            ]
        );
        // Again: only the check.
        let mut record = Record::load(&dirs).unwrap();
        let done = switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        assert_eq!(done, ["alephd serves the Secret Service"]);
        assert_eq!(units.calls.lock().unwrap().len(), 2);
        assert_eq!(
            Record::load(&dirs).unwrap().units[GNOME_UNITS[1]].enabled,
            "enabled"
        );
    }

    /// Something still holding the name (gnome-keyring started outside
    /// systemd) is reported, not waited on forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_gnome_keyring_outside_systemd_is_reported() {
        let bus = bus();
        let address = bus.address.clone();
        let gk = GnomeKeyring::start(&bus, "login password");
        let _d = daemon_on(bus, true).await;
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs {
            data_home: home.path().join("data"),
            state_home: home.path().join("state"),
        };
        let units = FakeUnits::new(gk);
        // (systemd stops nothing: the fixture outlives the "stop".)
        let kept = units.gk.lock().unwrap().take();
        let mut record = Record::default();
        let err = switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap_err();
        assert!(err.contains("pkill"), "{err}");
        drop(kept);
    }
}
```

Write `crates/aleph-daemon/src/export.rs`:

```rust
//! Copying the keyring back to gnome-keyring, for `aleph setup --revert`
//! (spec §6; DECISIONS.md E3).
//!
//! alephd runs its own gnome-keyring on a private bus over the keyring
//! files, after checking that none serves this session, and unlocks the
//! login keyring with the login password (which `pam_gnome_keyring` kept
//! in step in `passwd`). What to write is decided by comparison, not by
//! timestamp: every item missing there or different is written, then read
//! back on a fresh connection. The session never changes hands before that
//! verification passes.
//!
//! Collections gnome-keyring does not have go into its default collection
//! (creating one would need its own password prompt).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

use aleph_core::Body;
use zbus::Connection;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::error::{Error, Result};
use crate::import::{ImportedItem, SECRETS_NAME};
use crate::secret::session::{ClientDh, DH, Session};

const SECRETS_PATH: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";

fn gk(e: impl std::fmt::Display) -> Error {
    Error::Invalid(format!("gnome-keyring: {e}"))
}

/// Whether a gnome-keyring already serves this session: `org.gnome.keyring`
/// is owned, or the Secret Service name is held by someone other than this
/// connection. Revert then refuses, rather than run a second instance over
/// the same keyring files.
pub async fn gnome_keyring_active(session: &Connection) -> bool {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(session).await else {
        return false;
    };
    let owner = |name: &'static str| {
        let dbus = dbus.clone();
        async move {
            let name = zbus::names::BusName::try_from(name).ok()?;
            dbus.get_name_owner(name).await.ok().map(|o| o.to_string())
        }
    };
    let me = session.unique_name().map(|u| u.to_string());
    owner("org.gnome.keyring").await.is_some()
        || owner(SECRETS_NAME).await.is_some_and(|o| Some(o) != me)
}

/// A gnome-keyring (secrets component) alephd runs itself on a private
/// bus, over the keyring files in `data_home`; killed on drop.
pub struct Private {
    bus: std::process::Child,
    daemon: std::process::Child,
    pub address: String,
    _dirs: tempfile::TempDir,
}

impl Private {
    /// Start it and unlock the login keyring with `password`. Its home and
    /// runtime directory are throwaway; only `data_home` (holding
    /// `keyrings/`) is real.
    pub async fn start(data_home: &Path, password: &str) -> Result<Self> {
        use std::io::{BufRead, Write};
        let dirs = tempfile::tempdir().map_err(gk)?;
        let run = dirs.path().join("run");
        std::fs::create_dir_all(&run).map_err(gk)?;
        std::fs::set_permissions(&run, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(gk)?;
        let mut bus = std::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--nopidfile", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| gk(format!("dbus-daemon: {e}")))?;
        let mut address = String::new();
        std::io::BufReader::new(bus.stdout.take().expect("piped"))
            .read_line(&mut address)
            .map_err(gk)?;
        let address = address.trim().to_string();
        let daemon = std::process::Command::new("gnome-keyring-daemon")
            .args(["--foreground", "--components=secrets", "--unlock"])
            .env("HOME", dirs.path())
            .env("XDG_RUNTIME_DIR", &run)
            .env("XDG_DATA_HOME", data_home)
            .env("XDG_CONFIG_HOME", dirs.path().join("config"))
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .env_remove("GNOME_KEYRING_CONTROL")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let mut daemon = match daemon {
            Ok(d) => d,
            Err(e) => {
                let _ = bus.kill();
                let _ = bus.wait();
                return Err(gk(format!("gnome-keyring-daemon: {e}")));
            }
        };
        let mut stdin = daemon.stdin.take().expect("piped");
        let _ = stdin.write_all(password.as_bytes());
        drop(stdin);
        let private = Self {
            bus,
            daemon,
            address,
            _dirs: dirs,
        };
        let conn = private.connect().await?;
        let dbus = zbus::fdo::DBusProxy::new(&conn).await.map_err(gk)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let name = zbus::names::BusName::try_from(SECRETS_NAME).map_err(gk)?;
            if dbus.get_name_owner(name).await.is_ok() {
                return Ok(private);
            }
            if std::time::Instant::now() > deadline {
                return Err(gk("it did not start"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A new connection to its bus.
    pub async fn connect(&self) -> Result<Connection> {
        zbus::connection::Builder::address(self.address.as_str())
            .map_err(gk)?
            .build()
            .await
            .map_err(gk)
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        for child in [&mut self.daemon, &mut self.bus] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// What an export did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub exported: usize,
    pub unchanged: usize,
    pub deleted: usize,
    /// Items of collections gnome-keyring lacks, put in its default one.
    pub into_default: usize,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Copied {} item(s) to gnome-keyring and read each back ({} already there)",
            self.exported, self.unchanged
        )?;
        if self.into_default > 0 {
            write!(
                f,
                "; {} from collections gnome-keyring lacks went into its default collection",
                self.into_default
            )?;
        }
        if self.deleted > 0 {
            write!(
                f,
                "; deleted {} item(s) deleted in aleph since the import",
                self.deleted
            )?;
        }
        write!(f, ".")
    }
}

/// One gnome-keyring conversation: its service, an encrypted session.
struct Remote {
    conn: Connection,
    owner: String,
    session: Session,
    session_path: OwnedObjectPath,
}

impl Remote {
    async fn open(conn: &Connection) -> Result<Self> {
        let dbus = zbus::fdo::DBusProxy::new(conn).await.map_err(gk)?;
        let name = zbus::names::BusName::try_from(SECRETS_NAME).map_err(gk)?;
        let owner = dbus.get_name_owner(name).await.map_err(gk)?.to_string();
        let service = proxy(conn, &owner, SECRETS_PATH, SERVICE).await?;
        let dh = ClientDh::new().map_err(gk)?;
        let (output, session_path): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &(DH, Value::from(dh.public.clone())))
            .await
            .map_err(gk)?;
        let server_public: Vec<u8> = output.try_into().map_err(gk)?;
        Ok(Self {
            conn: conn.clone(),
            session: dh.finish(&server_public).map_err(gk)?,
            owner,
            session_path,
        })
    }

    async fn proxy(&self, path: &str, interface: &'static str) -> Result<zbus::Proxy<'static>> {
        proxy(&self.conn, &self.owner, path, interface).await
    }

    /// The items in `collection` with these attributes and label, with
    /// their secrets.
    async fn find(
        &self,
        collection: &OwnedObjectPath,
        attributes: &BTreeMap<String, String>,
        label: &str,
    ) -> Result<Vec<(OwnedObjectPath, Vec<u8>)>> {
        let c = self.proxy(collection.as_str(), COLLECTION).await?;
        let attrs: HashMap<&str, &str> = attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let paths: Vec<OwnedObjectPath> = c.call("SearchItems", &(attrs,)).await.map_err(gk)?;
        let mut out = Vec::new();
        for path in paths {
            let item = self.proxy(path.as_str(), ITEM).await?;
            let l: String = item.get_property("Label").await.map_err(gk)?;
            if l != label {
                continue;
            }
            let (_, parameters, value, _): (OwnedObjectPath, Vec<u8>, Vec<u8>, String) = item
                .call("GetSecret", &(self.session_path.clone(),))
                .await
                .map_err(gk)?;
            let secret = self.session.decrypt(&parameters, &value).map_err(gk)?;
            out.push((path, secret.to_vec()));
        }
        Ok(out)
    }
}

async fn proxy(
    conn: &Connection,
    owner: &str,
    path: &str,
    interface: &'static str,
) -> Result<zbus::Proxy<'static>> {
    zbus::proxy::Builder::new(conn)
        .destination(owner.to_string())
        .and_then(|b| b.path(path.to_string()))
        .and_then(|b| b.interface(interface))
        .map(|b| b.cache_properties(CacheProperties::No))
        .map_err(gk)?
        .build()
        .await
        .map_err(gk)
}

/// Write `body` into the gnome-keyring on `conn` (every item missing
/// there or different), delete the `delete` items there, then read every
/// written item back on a fresh connection to `address`.
pub async fn export(
    conn: &Connection,
    address: &str,
    body: &Body,
    delete: &[ImportedItem],
) -> Result<Report> {
    let remote = Remote::open(conn).await?;
    let service = remote.proxy(SECRETS_PATH, SERVICE).await?;
    let default: OwnedObjectPath = service.call("ReadAlias", &("default",)).await.map_err(gk)?;
    if default.as_str() == "/" {
        return Err(gk("it has no default collection"));
    }
    let locked: bool = remote
        .proxy(default.as_str(), COLLECTION)
        .await?
        .get_property("Locked")
        .await
        .map_err(gk)?;
    if locked {
        return Err(Error::Invalid(
            "gnome-keyring's login keyring did not unlock with your login password (its password may differ); nothing was changed".into(),
        ));
    }
    let mut by_label = HashMap::new();
    let paths: Vec<OwnedObjectPath> = service.get_property("Collections").await.map_err(gk)?;
    for path in paths {
        let label: String = remote
            .proxy(path.as_str(), COLLECTION)
            .await?
            .get_property("Label")
            .await
            .map_err(gk)?;
        by_label.entry(label).or_insert(path);
    }
    let aleph_default = body
        .resolve_alias(aleph_core::model::DEFAULT_ALIAS)
        .map(|c| c.id);
    let target_of = |id, label: &str, report: &mut Report| {
        if Some(id) == aleph_default {
            default.clone()
        } else if let Some(p) = by_label.get(label) {
            p.clone()
        } else {
            report.into_default += 1;
            default.clone()
        }
    };
    let mut report = Report::default();
    let mut written = Vec::new();
    for collection in &body.collections {
        for item in &collection.items {
            let target = target_of(collection.id, &collection.label, &mut report);
            let found = remote.find(&target, &item.attributes, &item.label).await?;
            if found.iter().any(|(_, s)| s == item.secret.expose()) {
                report.unchanged += 1;
                continue;
            }
            let (parameters, value) = remote.session.encrypt(item.secret.expose()).map_err(gk)?;
            let properties: HashMap<&str, Value> = HashMap::from([
                (
                    "org.freedesktop.Secret.Item.Label",
                    Value::from(item.label.clone()),
                ),
                (
                    "org.freedesktop.Secret.Item.Attributes",
                    Value::from(
                        item.attributes
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect::<HashMap<String, String>>(),
                    ),
                ),
            ]);
            let secret = (
                remote.session_path.clone(),
                parameters,
                value,
                item.content_type.clone(),
            );
            let (_, prompt): (OwnedObjectPath, OwnedObjectPath) = remote
                .proxy(target.as_str(), COLLECTION)
                .await?
                .call("CreateItem", &(properties, secret, true))
                .await
                .map_err(gk)?;
            if prompt.as_str() != "/" {
                return Err(gk("it asked for a prompt to store an item"));
            }
            report.exported += 1;
            written.push((target, item));
        }
    }
    for d in delete {
        let target = if d.is_default {
            default.clone()
        } else {
            by_label
                .get(&d.collection)
                .cloned()
                .unwrap_or(default.clone())
        };
        for (path, _) in remote.find(&target, &d.attributes, &d.label).await? {
            let _: OwnedObjectPath = remote
                .proxy(path.as_str(), ITEM)
                .await?
                .call("Delete", &())
                .await
                .map_err(gk)?;
            report.deleted += 1;
        }
    }
    // Read everything written back, on a fresh connection and session.
    let fresh = zbus::connection::Builder::address(address)
        .map_err(gk)?
        .build()
        .await
        .map_err(gk)?;
    let check = Remote::open(&fresh).await?;
    for (target, item) in written {
        let found = check.find(&target, &item.attributes, &item.label).await?;
        if !found.iter().any(|(_, s)| s == item.secret.expose()) {
            return Err(Error::Invalid(format!(
                "copying to gnome-keyring could not be verified ({}); nothing else was changed",
                item.label
            )));
        }
    }
    Ok(report)
}
```

Apply this patch with `git apply` (save it as `/tmp/t2-impl.patch`):

```diff
--- a/crates/aleph-cli/src/client.rs
+++ b/crates/aleph-cli/src/client.rs
@@ -106,6 +106,11 @@
             .map_err(err)
     }
 
+    /// The session bus connection.
+    pub fn bus(&self) -> &zbus::Connection {
+        &self.conn
+    }
+
     pub async fn status(&self) -> Result<Status> {
         let json: String = self
             .admin()
@@ -124,6 +129,35 @@
             .call("ImportGnomeKeyring", &())
             .await
             .map_err(|e| format!("import failed: {e}"))
+    }
+
+    /// Items imported from gnome-keyring and deleted in aleph since.
+    pub async fn removed_since_import(&self) -> Result<Vec<String>> {
+        self.admin()
+            .await?
+            .call("RemovedSinceImport", &())
+            .await
+            .map_err(err)
+    }
+
+    /// Let go of the Secret Service name (the end of a revert).
+    pub async fn release_secret_service(&self) -> Result<()> {
+        self.admin()
+            .await?
+            .call_method("ReleaseSecretService", &())
+            .await
+            .map_err(err)?;
+        Ok(())
+    }
+
+    /// Resume writes paused by an export (a revert that stopped part way).
+    pub async fn thaw_writes(&self) -> Result<()> {
+        self.admin()
+            .await?
+            .call_method("ThawWrites", &())
+            .await
+            .map_err(err)?;
+        Ok(())
     }
 
     pub async fn lock(&self) -> Result<()> {
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -35,8 +35,14 @@
 
 #[derive(Subcommand)]
 enum Cmd {
-    /// Create the keyring (system integration comes in a later release).
-    Setup,
+    /// Set up aleph: create the keyring, import from gnome-keyring, and take
+    /// over the Secret Service from it.
+    Setup {
+        /// Hand everything back to gnome-keyring (copying the keyring there
+        /// first); the aleph vault is left in place.
+        #[arg(long)]
+        revert: bool,
+    },
     /// Show the keyring's state and keyslots.
     Status,
     /// Import items from another keyring (alephd reads them itself).
@@ -177,31 +183,32 @@
     let c = Client::connect().await?;
     match cli.cmd {
         Cmd::Completions { .. } => unreachable!(),
-        Cmd::Setup => {
+        Cmd::Setup { revert: true } => revert(&c).await?,
+        Cmd::Setup { revert: false } => {
             let status = c.status().await?;
             if status.vault {
-                eprintln!("aleph: a keyring already exists (see `aleph status`)");
-                return Ok(ExitCode::SUCCESS);
-            }
-            let tpm = status.tpm.unwrap_or(false);
-            let first = if tpm {
-                "the TPM and your login password (recommended)"
+                eprintln!("aleph: a keyring already exists; checking the rest of setup");
             } else {
-                "your login password"
-            };
-            eprintln!("How should the keyring unlock?\n  1) {first}\n  2) a FIDO2 security key");
-            let mut term = prompter::Terminal::new();
-            let choice = term_line(&mut term, "Choice [1]: ")?;
-            let method = if choice.trim() == "2" {
-                "fido2"
-            } else {
-                "password"
-            };
-            outcome(c.converse("Create", Args::Str(method)).await?)?;
+                create_keyring(&c, status.tpm.unwrap_or(false)).await?;
+            }
+            // Import while gnome-keyring still serves the Secret Service
+            // (E1), then take over from it (E9).
+            if c.status().await?.locked {
+                outcome(c.converse("Unlock", Args::None).await?)?;
+            }
+            eprintln!("aleph: {}", c.import_gnome_keyring().await?);
+            let dirs = switchover::Dirs::from_env()?;
+            let mut record = switchover::Record::load(&dirs)?;
+            for step in
+                switchover::switch_over(c.bus(), &switchover::Systemctl, &dirs, &mut record).await?
+            {
+                eprintln!("aleph: {step}");
+            }
             eprintln!(
-                "aleph: note: setup does not yet set up login unlock (PAM), take over from gnome-keyring, or import its items: these are not available yet (see docs/testing.md for the PAM lines)"
+                "aleph: note: setup does not yet set up login unlock (PAM): see docs/testing.md for the lines"
             );
         }
+
         Cmd::Status => {
             let s = c.status().await?;
             if cli.json {
@@ -432,6 +439,72 @@
     Ok(())
 }
 
+/// `aleph setup --revert` (DECISIONS.md E3): copy the keyring back to
+/// gnome-keyring and verify it, then switch back and let go of the name.
+async fn revert(c: &Client) -> Result<()> {
+    let installed = std::env::var_os("PATH").is_some_and(|path| {
+        std::env::split_paths(&path).any(|d| d.join("gnome-keyring-daemon").is_file())
+    });
+    if !installed {
+        return Err(
+            "gnome-keyring is not installed: reverting would leave no Secret Service (Arch: pacman -S gnome-keyring)"
+                .into(),
+        );
+    }
+    let removed = c.removed_since_import().await?;
+    let mut delete = false;
+    if !removed.is_empty() {
+        eprintln!(
+            "aleph: imported from gnome-keyring and deleted in aleph since: {}",
+            removed.join(", ")
+        );
+        let mut term = prompter::Terminal::new();
+        let answer = term_line(&mut term, "Delete them from gnome-keyring too? [y/N] ")?;
+        delete = matches!(answer.trim(), "y" | "Y" | "yes");
+    }
+    outcome(
+        c.converse("ExportToGnomeKeyring", Args::Bool(delete))
+            .await?,
+    )?;
+    let dirs = switchover::Dirs::from_env()?;
+    let mut record = switchover::Record::load(&dirs)?;
+    let steps =
+        match switchover::switch_back(c.bus(), &switchover::Systemctl, &dirs, &mut record).await {
+            Ok(steps) => steps,
+            Err(e) => {
+                let _ = c.thaw_writes().await;
+                return Err(e);
+            }
+        };
+    for step in steps {
+        eprintln!("aleph: {step}");
+    }
+    c.release_secret_service().await?;
+    eprintln!(
+        "aleph: gnome-keyring serves the Secret Service again; the aleph vault is left in place"
+    );
+    Ok(())
+}
+
+/// Create the keyring, asking which unlock method to use.
+async fn create_keyring(c: &Client, tpm: bool) -> Result<()> {
+    let first = if tpm {
+        "the TPM and your login password (recommended)"
+    } else {
+        "your login password"
+    };
+    eprintln!("How should the keyring unlock?\n  1) {first}\n  2) a FIDO2 security key");
+    let mut term = prompter::Terminal::new();
+    let choice = term_line(&mut term, "Choice [1]: ")?;
+    let method = if choice.trim() == "2" {
+        "fido2"
+    } else {
+        "password"
+    };
+    outcome(c.converse("Create", Args::Str(method)).await?)?;
+    Ok(())
+}
+
 fn term_line(term: &mut prompter::Terminal, prompt: &str) -> Result<String> {
     term.line(prompt).map_err(|e| e.to_string())
 }
--- a/crates/aleph-daemon/Cargo.toml
+++ b/crates/aleph-daemon/Cargo.toml
@@ -11,7 +11,7 @@
 path = "src/main.rs"
 
 [features]
-testing = ["dep:aleph-tpmd", "dep:tempfile", "aleph-core/insecure-test-params"]
+testing = ["dep:aleph-tpmd", "aleph-core/insecure-test-params"]
 
 [dependencies]
 aes = "0.9"
@@ -39,7 +39,7 @@
 zbus = { version = "5", default-features = false, features = ["tokio"] }
 zeroize.workspace = true
 aleph-tpmd = { path = "../aleph-tpmd", features = ["testing"], optional = true }
-tempfile = { workspace = true, optional = true }
+tempfile.workspace = true
 
 [dev-dependencies]
 aleph-core = { path = "../aleph-core", features = ["insecure-test-params"] }
--- a/crates/aleph-daemon/src/admin.rs
+++ b/crates/aleph-daemon/src/admin.rs
@@ -178,9 +178,85 @@
         .await
         .map_err(failed)?
         .map_err(failed)?;
+        crate::import::record_imported(&self.paths.imported(), &summary.added).map_err(failed)?;
         let _ = self.secrets.unlocked().await;
-        tokio::spawn(importer.follow(self.keyring.clone(), self.secrets.clone()));
+        tokio::spawn(importer.follow(
+            self.keyring.clone(),
+            self.secrets.clone(),
+            self.paths.imported(),
+        ));
         Ok(summary.to_string())
+    }
+
+    /// Items imported from gnome-keyring and deleted in aleph since, as
+    /// "label (collection)" (revert offers to delete them there too).
+    async fn removed_since_import(&self) -> zbus::fdo::Result<Vec<String>> {
+        let imported = crate::import::load_imported(&self.paths.imported());
+        let removed = self
+            .keyring
+            .read(|b| crate::import::removed_since(&imported, b))
+            .map_err(failed)?;
+        Ok(removed
+            .into_iter()
+            .map(|i| format!("{} ({})", i.label, i.collection))
+            .collect())
+    }
+
+    /// Copy the keyring back to gnome-keyring for `aleph setup --revert`
+    /// (DECISIONS.md E3), deleting there the items deleted in aleph since
+    /// the import if `delete_removed`. Writes stay paused afterwards.
+    async fn export_to_gnome_keyring(
+        &self,
+        prompter: zbus::zvariant::OwnedFd,
+        delete_removed: bool,
+        #[zbus(connection)] conn: &zbus::Connection,
+    ) -> zbus::fdo::Result<()> {
+        if crate::export::gnome_keyring_active(conn).await {
+            return Err(zbus::fdo::Error::Failed(
+                "gnome-keyring is running in this session: revert runs its own over the keyring files; stop it first".into(),
+            ));
+        }
+        let data_home = self
+            .paths
+            .data_dir
+            .parent()
+            .ok_or_else(|| zbus::fdo::Error::Failed("no data directory".into()))?
+            .to_path_buf();
+        let imported = crate::import::load_imported(&self.paths.imported());
+        let handle = tokio::runtime::Handle::current();
+        self.converse(prompter, move |k, chan| {
+            k.export(chan, |password, body| {
+                let delete = if delete_removed {
+                    crate::import::removed_since(&imported, &body)
+                } else {
+                    Vec::new()
+                };
+                handle.block_on(async {
+                    let private = crate::export::Private::start(&data_home, password).await?;
+                    let conn = private.connect().await?;
+                    crate::export::export(&conn, &private.address, &body, &delete)
+                        .await
+                        .map(|r| r.to_string())
+                })
+            })
+        })
+    }
+
+    /// Let go of `org.freedesktop.secrets` (the end of a revert: the bus
+    /// hands it to gnome-keyring, queued behind).
+    async fn release_secret_service(
+        &self,
+        #[zbus(connection)] conn: &zbus::Connection,
+    ) -> zbus::fdo::Result<()> {
+        conn.release_name(crate::import::SECRETS_NAME)
+            .await
+            .map(|_| ())
+            .map_err(failed)
+    }
+
+    /// Resume writes paused by an export (a revert that stopped part way).
+    async fn thaw_writes(&self) {
+        self.keyring.thaw();
     }
 
     async fn lock(&self) -> zbus::fdo::Result<()> {
--- a/crates/aleph-daemon/src/error.rs
+++ b/crates/aleph-daemon/src/error.rs
@@ -74,6 +74,11 @@
     Sleeping,
 
     #[error(
+        "writes are paused while the keyring is copied back to gnome-keyring (aleph setup --revert)"
+    )]
+    Frozen,
+
+    #[error(
         "the recovery key just shown was not installed ({0}); discard it: your previous recovery key still works"
     )]
     RecoveryNotInstalled(Box<Error>),
--- a/crates/aleph-daemon/src/import.rs
+++ b/crates/aleph-daemon/src/import.rs
@@ -20,6 +20,7 @@
 //! stored in between is lost.
 
 use std::collections::{BTreeMap, HashMap};
+use std::path::{Path, PathBuf};
 use std::sync::Arc;
 use std::time::Duration;
 
@@ -59,6 +60,56 @@
     /// gnome-keyring's default collection (its items go to aleph's).
     pub is_default: bool,
     pub items: Vec<Fetched>,
+}
+
+/// An item an import added, as it was (for revert: items imported and
+/// deleted in aleph since are listed, E3).
+#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
+pub struct ImportedItem {
+    pub id: uuid::Uuid,
+    pub collection: String,
+    pub is_default: bool,
+    pub label: String,
+    pub attributes: BTreeMap<String, String>,
+}
+
+/// The items imported so far (`imported.json`).
+pub fn load_imported(path: &Path) -> Vec<ImportedItem> {
+    std::fs::read(path)
+        .ok()
+        .and_then(|b| serde_json::from_slice(&b).ok())
+        .unwrap_or_default()
+}
+
+/// Add `items` to the record.
+pub fn record_imported(path: &Path, items: &[ImportedItem]) -> Result<()> {
+    if items.is_empty() {
+        return Ok(());
+    }
+    let mut all = load_imported(path);
+    all.extend_from_slice(items);
+    let bytes = serde_json::to_vec_pretty(&all).map_err(gk)?;
+    if let Some(dir) = path.parent() {
+        std::fs::create_dir_all(dir)?;
+    }
+    let tmp = path.with_extension("tmp");
+    std::fs::write(&tmp, bytes)?;
+    std::fs::rename(&tmp, path)?;
+    Ok(())
+}
+
+/// Imported items no longer in `body` (deleted in aleph since).
+pub fn removed_since(imported: &[ImportedItem], body: &Body) -> Vec<ImportedItem> {
+    imported
+        .iter()
+        .filter(|i| {
+            !body
+                .collections
+                .iter()
+                .any(|c| c.items.iter().any(|x| x.id == i.id))
+        })
+        .cloned()
+        .collect()
 }
 
 /// What an import did.
@@ -70,6 +121,8 @@
     pub conflicts: Vec<String>,
     /// Collections skipped, with the reason.
     pub skipped: Vec<String>,
+    /// The items added (recorded for revert).
+    pub added: Vec<ImportedItem>,
 }
 
 impl std::fmt::Display for Summary {
@@ -142,10 +195,18 @@
                     .push(format!("{} ({})", f.label, collection.label));
                 continue;
             }
+            summary.added.push(ImportedItem {
+                id: uuid::Uuid::nil(),
+                collection: collection.label.clone(),
+                is_default: collection.is_default,
+                label: f.label.clone(),
+                attributes: f.attributes.clone(),
+            });
             let mut item = Item::new(f.label, f.attributes, f.secret, f.content_type);
             item.created = f.created;
             item.modified = f.modified;
-            target.upsert(item, false);
+            let id = target.upsert(item, false);
+            summary.added.last_mut().expect("just pushed").id = id;
             summary.imported += 1;
         }
     }
@@ -300,7 +361,12 @@
 
     /// Keep importing items gnome-keyring creates or changes until
     /// `org.freedesktop.secrets` changes hands (E1).
-    pub async fn follow(mut self, keyring: Arc<Keyring>, secrets: Arc<SecretService>) {
+    pub async fn follow(
+        mut self,
+        keyring: Arc<Keyring>,
+        secrets: Arc<SecretService>,
+        record: PathBuf,
+    ) {
         let Ok(dbus) = zbus::fdo::DBusProxy::new(&self.conn).await else {
             return;
         };
@@ -335,7 +401,7 @@
                 continue;
             }
             if let Err(e) = self
-                .import_one(&keyring, &mut labels, &collection, item)
+                .import_one(&keyring, &mut labels, &collection, item, &record)
                 .await
             {
                 tracing::warn!("following gnome-keyring: {e}");
@@ -351,6 +417,7 @@
         labels: &mut HashMap<String, (String, bool)>,
         collection: &str,
         item: OwnedObjectPath,
+        record: &Path,
     ) -> Result<()> {
         if !labels.contains_key(collection) {
             let c = proxy(&self.conn, &self.owner, collection, COLLECTION).await?;
@@ -383,6 +450,7 @@
         })
         .await
         .map_err(gk)??;
+        record_imported(record, &summary.added)?;
         if !summary.conflicts.is_empty() {
             tracing::info!(
                 "gnome-keyring changed an item after it was imported; kept aleph's: {}",
--- a/crates/aleph-daemon/src/keyring.rs
+++ b/crates/aleph-daemon/src/keyring.rs
@@ -169,6 +169,9 @@
     /// A vault has been here since this daemon started: deleting its files
     /// does not make this a new machine (custody proof, E7).
     seen_vault: std::sync::atomic::AtomicBool,
+    /// Writes are paused: the keyring is being copied back to
+    /// gnome-keyring (DECISIONS.md E3).
+    frozen: std::sync::atomic::AtomicBool,
 }
 
 fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
@@ -202,6 +205,7 @@
             last_access: Mutex::new(Instant::now()),
             sleeping: std::sync::atomic::AtomicBool::new(false),
             seen_vault: std::sync::atomic::AtomicBool::new(seen),
+            frozen: std::sync::atomic::AtomicBool::new(false),
         }
     }
 
@@ -292,6 +296,9 @@
     /// Change the body and write the vault. If `f` or the write fails, the
     /// in-memory body is restored, so memory never runs ahead of the file.
     pub fn modify<T>(&self, f: impl FnOnce(&mut Body) -> Result<T>) -> Result<T> {
+        if self.frozen.load(std::sync::atomic::Ordering::SeqCst) {
+            return Err(Error::Frozen);
+        }
         let mut inner = lock(&self.inner);
         *lock(&self.last_access) = Instant::now();
         let Inner {
@@ -365,6 +372,45 @@
                 Err(Error::Busy)
             }
         }
+    }
+
+    /// Copy the keyring back to gnome-keyring (`aleph setup --revert`,
+    /// DECISIONS.md E3): after the login password (checked with PAM; it
+    /// also unlocks gnome-keyring's login keyring), writes are paused and
+    /// `run` gets the password and a copy of the body. A failure resumes
+    /// writes; success leaves them paused until the revert ends (or
+    /// [`Keyring::thaw`]).
+    pub fn export(
+        &self,
+        chan: &mut Channel,
+        run: impl FnOnce(&str, Body) -> Result<String>,
+    ) -> Result<()> {
+        let _op = self.begin(chan)?;
+        converse(chan, |chan| {
+            chan.send(&ToPrompter::Begin {
+                purpose: Purpose::Reauth,
+                operation: "Copy the keyring back to gnome-keyring".into(),
+                caller: None,
+            })?;
+            if self.is_locked() {
+                return Err(Error::Locked);
+            }
+            let password = self.ask_password(chan)?;
+            self.frozen.store(true, std::sync::atomic::Ordering::SeqCst);
+            let result = self
+                .read(|b| b.clone())
+                .and_then(|body| run(&password, body));
+            if result.is_err() {
+                self.thaw();
+            }
+            result.map(Some)
+        })
+    }
+
+    /// Resume writes after an export (a revert that stopped part way).
+    pub fn thaw(&self) {
+        self.frozen
+            .store(false, std::sync::atomic::Ordering::SeqCst);
     }
 
     /// Unlock through the prompter.
--- a/crates/aleph-daemon/src/main.rs
+++ b/crates/aleph-daemon/src/main.rs
@@ -53,6 +53,10 @@
         .await
         .map_err(|e| format!("cannot own {BUS_NAME} on the session bus: {e}"))?;
     let pam_socket = paths.pam_socket();
+    let activation = paths
+        .data_dir
+        .parent()
+        .map(|data| data.join("dbus-1/services/org.freedesktop.secrets.service"));
     let secrets =
         aleph_daemon::daemon::serve(&conn, keyring.clone(), launcher, config.clone(), paths)
             .await
@@ -60,6 +64,12 @@
     // Queued behind gnome-keyring until it lets go (DECISIONS.md E1).
     match aleph_daemon::daemon::request_secrets_name(&conn).await {
         Ok(true) => tracing::info!("serving {SECRETS_NAME} and {BUS_NAME}"),
+        // After setup switched over, nothing else should hold it.
+        Ok(false) if activation.as_ref().is_some_and(|a| a.exists()) => {
+            tracing::warn!(
+                "another program owns {SECRETS_NAME} although aleph setup switched over (gnome-keyring started outside systemd?); alephd waits in the queue"
+            )
+        }
         Ok(false) => tracing::info!(
             "serving {BUS_NAME}; queued for {SECRETS_NAME}, which another program owns"
         ),
--- a/crates/aleph-daemon/src/paths.rs
+++ b/crates/aleph-daemon/src/paths.rs
@@ -82,6 +82,11 @@
         self.state_dir.join("vault-id")
     }
 
+    /// The items `aleph setup` imported from gnome-keyring (for revert).
+    pub fn imported(&self) -> PathBuf {
+        self.state_dir.join("imported.json")
+    }
+
     /// Where `pam_aleph` hands over the login password (§6).
     pub fn pam_socket(&self) -> PathBuf {
         self.runtime_dir.join("pam.sock")
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon -p aleph-cli && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 4 passed | ok. 12 passed | ok. 37 passed | ok. 3 passed | ok. 30 passed | ok. 8 passed | ok. 51 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **alephd queues, never replacing the owner** (`crates/aleph-daemon/src/daemon.rs`), test `cargo test -p aleph-daemon --test gnome_keyring the_name_cannot_be_taken_from_alephd`:

  replace

  ```rust
  zbus::fdo::RequestNameFlags::empty(),
  )
  ```

  with

  ```rust
  zbus::fdo::RequestNameFlags::AllowReplacement.into(),
  )
  ```

- **writes pause during an export** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test gnome_keyring items_are_copied_back`:

  replace

  ```rust
  if self.frozen.load(std::sync::atomic::Ordering::SeqCst) {
  return Err(Error::Frozen);
  ```

  with

  ```rust
  if false {
  return Err(Error::Frozen);
  ```

- **a failed export resumes writes** (`crates/aleph-daemon/src/keyring.rs`), test `cargo test -p aleph-daemon --test gnome_keyring a_login_keyring_that_does_not_unlock`:

  replace

  ```rust
  if result.is_err() {
      self.thaw();
  }
  ```

  with

  ```rust
  // (nothing)
  ```

- **revert refuses while gnome-keyring runs** (`crates/aleph-daemon/src/admin.rs`), test `cargo test -p aleph-daemon --test gnome_keyring revert_refuses_while_gnome_keyring_runs`: replace `if crate::export::gnome_keyring_active(conn).await {` with `if false {`.
- **items already in gnome-keyring are not rewritten** (`crates/aleph-daemon/src/export.rs`), test `cargo test -p aleph-daemon --test gnome_keyring items_are_copied_back`:

  replace

  ```rust
  if found.iter().any(|(_, s)| s == item.secret.expose()) {
  report.unchanged += 1;
  ```

  with

  ```rust
  if false {
  report.unchanged += 1;
  ```

- **items deleted since the import are deleted there** (`crates/aleph-daemon/src/export.rs`), test `cargo test -p aleph-daemon --test gnome_keyring items_deleted_since_the_import`: replace `for d in delete {` with `for d in &delete[..0] {`.
- **the unit states before setup are recorded once** (`crates/aleph-cli/src/switchover.rs`), test `cargo test -p aleph-cli --bin aleph gnome_keyring_hands_over`:

  replace

  ```rust
  if record.units.is_empty() {
  record.units = states
  ```

  with

  ```rust
  if true {
  record.units = states
  ```

- **switching back removes only aleph's files** (`crates/aleph-cli/src/switchover.rs`), test `cargo test -p aleph-cli --bin aleph switching_back_restores`: replace `Ok(bytes) if bytes == contents.as_bytes() => {` with `Ok(_) if true => {`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/aleph-daemon crates/aleph-cli
git commit -m "feat: switch over from gnome-keyring, and revert" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: the root side: PAM

**Interfaces:**
- Produces: `system::{AUTH, SESSION, PASSWORD, Service, Removed, Edit, transform(Service, &str) -> Result<Edit>, inverse(&str, &[Removed]) -> Option<String>, Root, Manifest, apply(&Root) -> Result<Report>, roll_back(&Root, &[Service]), revert(&Root) -> Result<Vec<String>>, authenticate(&Path, &str, &str, &str), verify(&Root, &str, &str), writable_binary_warning()}`; CLI `aleph system apply --user <u> | verify --user <u> | revert`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-cli/src/system.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(dir: &str, name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/pam")
                .join(dir)
                .join(name),
        )
        .unwrap()
    }

    /// The stock Omarchy files become the applied ones; applying again
    /// changes nothing; the inverse gives back the stock files exactly.
    #[test]
    fn transforms_match_the_fixtures_are_idempotent_and_invert() {
        for service in Service::ALL {
            let stock = fixture("omarchy", service.file());
            let edit = transform(service, &stock).unwrap();
            assert_eq!(
                edit.text,
                fixture("omarchy-applied", service.file()),
                "{service:?}"
            );
            let again = transform(service, &edit.text).unwrap();
            assert_eq!(again.text, edit.text, "{service:?}");
            assert!(again.removed.is_empty());
            assert_eq!(
                inverse(&edit.text, &edit.removed).unwrap(),
                stock,
                "{service:?}"
            );
        }
    }

    /// Only the expected lines move: gnome-keyring's go from sddm and
    /// sddm-autologin, and stay in passwd.
    #[test]
    fn gnome_keyring_lines_go_only_from_the_login_services() {
        let e = transform(Service::Passwd, &fixture("omarchy", "passwd")).unwrap();
        assert!(e.text.contains("pam_gnome_keyring.so"));
        assert!(e.removed.is_empty());
        let e = transform(
            Service::SddmAutologin,
            &fixture("omarchy", "sddm-autologin"),
        )
        .unwrap();
        assert!(!e.text.contains("pam_gnome_keyring.so"));
        assert!(!e.text.contains("pam_aleph.so"));
        assert_eq!(e.removed.len(), 2);
    }

    fn tree() -> (tempfile::TempDir, Root) {
        let dir = tempfile::tempdir().unwrap();
        let pam_dir = dir.path().join("pam.d");
        std::fs::create_dir_all(&pam_dir).unwrap();
        for service in Service::ALL {
            std::fs::write(
                pam_dir.join(service.file()),
                fixture("omarchy", service.file()),
            )
            .unwrap();
        }
        let root = Root {
            pam_dir,
            state_dir: dir.path().join("state"),
            owner: unsafe { libc::getuid() },
        };
        (dir, root)
    }

    /// Apply edits everything and records it; revert restores every file
    /// byte for byte and leaves no backups or manifest behind.
    #[test]
    fn apply_then_revert_restores_every_file_exactly() {
        let (_dir, root) = tree();
        let report = apply(&root).unwrap();
        assert_eq!(report.changed.len(), 4);
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy-applied", service.file())
            );
        }
        assert!(apply(&root).unwrap().changed.is_empty());
        let done = revert(&root).unwrap();
        assert_eq!(done.len(), 4, "{done:?}");
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
            assert!(!root.backup(service).exists());
        }
        assert!(!root.manifest_path().exists());
    }

    /// A file changed since apply keeps the change: aleph's lines come out
    /// by the inverse; one whose anchors are gone is left alone.
    #[test]
    fn revert_after_an_edit_keeps_the_edit_or_leaves_the_file() {
        let (_dir, root) = tree();
        apply(&root).unwrap();
        let passwd = root.pam_dir.join("passwd");
        let mut text = std::fs::read_to_string(&passwd).unwrap();
        text.push_str("# a local change\n");
        std::fs::write(&passwd, &text).unwrap();
        let sddm = root.pam_dir.join("sddm");
        std::fs::write(
            &sddm,
            "#%PAM-1.0\nauth required pam_deny.so\n-auth      optional  pam_aleph.so\n",
        )
        .unwrap();
        let done = revert(&root).unwrap();
        let passwd_now = std::fs::read_to_string(&passwd).unwrap();
        assert!(passwd_now.contains("# a local change"));
        assert!(!passwd_now.contains("pam_aleph"));
        assert!(
            std::fs::read_to_string(&sddm)
                .unwrap()
                .contains("pam_aleph")
        );
        assert!(done.iter().any(|d| d.contains("left alone")), "{done:?}");
    }

    /// Files not owned by the required owner (root) are left for the user,
    /// unchanged.
    #[test]
    fn files_not_owned_by_root_are_manual() {
        let (_dir, mut root) = tree();
        root.owner = root.owner.wrapping_add(1);
        let report = apply(&root).unwrap();
        assert!(report.changed.is_empty());
        assert_eq!(report.manual.len(), 4);
        assert!(
            report.manual[0].contains("is not owned by uid"),
            "{:?}",
            report.manual
        );
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
        }
    }

    /// A failed check puts every changed file back exactly, and forgets it.
    #[test]
    fn roll_back_restores_the_changed_files() {
        let (_dir, root) = tree();
        let report = apply(&root).unwrap();
        roll_back(&root, &report.changed).unwrap();
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
            assert!(!root.backup(service).exists());
        }
        assert!(!root.manifest_path().exists());
    }

    /// A symlinked service is left for the user, with the lines to add.
    #[test]
    fn a_symlinked_service_is_manual() {
        let (dir, root) = tree();
        let real = dir.path().join("real-passwd");
        std::fs::rename(root.pam_dir.join("passwd"), &real).unwrap();
        std::os::unix::fs::symlink(&real, root.pam_dir.join("passwd")).unwrap();
        let report = apply(&root).unwrap();
        assert!(
            report
                .manual
                .iter()
                .any(|m| m.contains("symlink") && m.contains(PASSWORD))
        );
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            fixture("omarchy", "passwd")
        );
    }

    /// The transformed lock-screen and login stacks, through real
    /// Linux-PAM: the right password passes and a wrong one fails, with
    /// aleph's line in place (jumps intact). pam_unix is replaced by a
    /// password check, pam_faillock (root-only) by pam_permit, and
    /// pam_aleph points at a socket that does not exist, so nothing can
    /// reach a real daemon.
    #[test]
    fn the_transformed_stacks_run_through_real_pam() {
        let dir = tempfile::tempdir().unwrap();
        let check = dir.path().join("check");
        std::fs::write(&check, "#!/bin/sh\nread -r p\n[ \"$p\" = hunter2 ]\n").unwrap();
        std::fs::set_permissions(&check, std::fs::Permissions::from_mode(0o755)).unwrap();
        let unix = format!("pam_exec.so expose_authtok quiet {}", check.display());
        let aleph = format!(
            "pam_aleph.so socket={}",
            dir.path().join("none.sock").display()
        );
        let stub = |text: String| {
            text.lines()
                .map(|l| {
                    if l.contains("pam_unix.so") {
                        l.replace("pam_unix.so try_first_pass nullok", &unix)
                    } else if l.contains("pam_faillock.so") {
                        let w = words(l);
                        format!("{} {} pam_permit.so", w[0], w[1])
                    } else {
                        l.replace("pam_aleph.so", &aleph)
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        };
        for service in VERIFIED {
            std::fs::write(
                dir.path().join(service.file()),
                stub(fixture("omarchy-applied", service.file())),
            )
            .unwrap();
        }
        std::fs::write(
            dir.path().join("system-login"),
            format!("auth required {unix}\naccount required pam_permit.so\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("system-local-login"),
            "account required pam_permit.so\n",
        )
        .unwrap();
        let user = std::env::var("USER").unwrap();
        for service in VERIFIED {
            authenticate(dir.path(), service.file(), &user, "hunter2").unwrap();
            assert!(authenticate(dir.path(), service.file(), &user, "wrong").is_err());
        }
    }

    /// Real Linux-PAM: a stack that accepts the password passes, one that
    /// does not fails (stub stacks: never pam_aleph here, which could reach
    /// a real daemon).
    #[test]
    fn authenticate_runs_real_pam() {
        let dir = tempfile::tempdir().unwrap();
        let check = dir.path().join("check");
        std::fs::write(&check, "#!/bin/sh\nread -r p\n[ \"$p\" = hunter2 ]\n").unwrap();
        std::fs::set_permissions(&check, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            dir.path().join("ok"),
            format!(
                "auth required pam_exec.so expose_authtok quiet {}\n",
                check.display()
            ),
        )
        .unwrap();
        let user = std::env::var("USER").unwrap();
        authenticate(dir.path(), "ok", &user, "hunter2").unwrap();
        let err = authenticate(dir.path(), "ok", &user, "wrong").unwrap_err();
        assert!(err.starts_with("ok:"), "{err}");
    }
}
```

Write `crates/aleph-cli/tests/fixtures/pam/omarchy-applied/omarchy-lock-password`:

```
#%PAM-1.0
auth       required                    pam_faillock.so preauth silent deny=10 unlock_time=120
-auth      [success=2 default=ignore]  pam_systemd_home.so
auth       [success=1 default=bad]     pam_unix.so try_first_pass nullok
auth       [default=die]               pam_faillock.so authfail deny=10 unlock_time=120
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so authsucc
-auth      optional  pam_aleph.so
account    include                     system-local-login
```

Write `crates/aleph-cli/tests/fixtures/pam/omarchy-applied/passwd`:

```
#%PAM-1.0
auth		include		system-auth
account		include		system-auth
password	include		system-auth
-password  optional  pam_aleph.so
password	optional	pam_gnome_keyring.so
```

Write `crates/aleph-cli/tests/fixtures/pam/omarchy-applied/sddm`:

```
#%PAM-1.0

auth        include     system-login
-auth      optional  pam_aleph.so
-auth       optional    pam_kwallet5.so

account     include     system-login

password    include     system-login

session     optional    pam_keyinit.so          force revoke
session     include     system-login
-session   optional  pam_aleph.so
-session    optional    pam_kwallet5.so         auto_start
```

Write `crates/aleph-cli/tests/fixtures/pam/omarchy-applied/sddm-autologin`:

```
#%PAM-1.0
auth        required    pam_env.so
auth        required    pam_shells.so
auth        required    pam_nologin.so
auth        required    pam_permit.so
auth        required    pam_faillock.so authsucc
-auth       optional    pam_kwallet5.so
account     include     system-local-login
password    include     system-local-login
session     include     system-local-login
-session    optional    pam_kwallet5.so auto_start
```

Write `crates/aleph-cli/tests/fixtures/pam/omarchy/omarchy-lock-password`:

```
#%PAM-1.0
auth       required                    pam_faillock.so preauth silent deny=10 unlock_time=120
-auth      [success=2 default=ignore]  pam_systemd_home.so
auth       [success=1 default=bad]     pam_unix.so try_first_pass nullok
auth       [default=die]               pam_faillock.so authfail deny=10 unlock_time=120
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so authsucc
account    include                     system-local-login
```

Write `crates/aleph-cli/tests/fixtures/pam/omarchy/passwd`:

```
#%PAM-1.0
auth		include		system-auth
account		include		system-auth
password	include		system-auth
password	optional	pam_gnome_keyring.so
```

Write `crates/aleph-cli/tests/fixtures/pam/omarchy/sddm`:

```
#%PAM-1.0

auth        include     system-login
auth        optional    pam_gnome_keyring.so
-auth       optional    pam_kwallet5.so

account     include     system-login

password    include     system-login

session     optional    pam_keyinit.so          force revoke
session     include     system-login
-session    optional    pam_gnome_keyring.so    auto_start
-session    optional    pam_kwallet5.so         auto_start
```

Write `crates/aleph-cli/tests/fixtures/pam/omarchy/sddm-autologin`:

```
#%PAM-1.0
auth        required    pam_env.so
auth        required    pam_shells.so
auth        required    pam_nologin.so
auth        required    pam_permit.so
auth        required    pam_faillock.so authsucc
-auth       optional    pam_gnome_keyring.so
-auth       optional    pam_kwallet5.so
account     include     system-local-login
password    include     system-local-login
session     include     system-local-login
-session    optional    pam_gnome_keyring.so auto_start
-session    optional    pam_kwallet5.so auto_start
```

Apply this patch with `git apply` (save it as `/tmp/t3-tests.patch`):

```diff
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -8,6 +8,7 @@
 mod client;
 mod prompter;
 mod switchover;
+mod system;
 
 use std::collections::HashMap;
 use std::io::{IsTerminal, Read, Write};
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-cli --bin aleph`
Expected: the build fails: the `system` module does not exist yet.

- [ ] **Step 3: Implement**

Write `crates/aleph-cli/src/system.rs`:

```rust
//! The root side of setup: `sudo aleph system apply | verify | revert`
//! (spec §6 "PAM integration"; DECISIONS.md E4–E6).
//!
//! Small on purpose: it reads no user configuration, no D-Bus, and no
//! user-writable paths. Each edit is a pure text transformation of one PAM
//! service, written atomically; `apply` then runs the edited stacks
//! through real Linux-PAM and restores the originals at once if one fails.
//! Everything is recorded in a root-owned manifest, so `revert` undoes
//! exactly that: byte for byte from the `.aleph-orig` backup if the file
//! is still what `apply` wrote, else by the inverse transformation if it
//! applies cleanly, else not at all (with what to remove by hand).

use std::collections::BTreeMap;
use std::ffi::{CString, c_char, c_int, c_void};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, String>;

/// aleph's lines, each with a `-` prefix: a missing module is skipped
/// silently (a missing `include`d file could fail the whole service).
pub const AUTH: &str = "-auth      optional  pam_aleph.so";
pub const SESSION: &str = "-session   optional  pam_aleph.so";
pub const PASSWORD: &str = "-password  optional  pam_aleph.so";

/// The PAM services setup edits (spec §6's table). `system-login`,
/// `system-auth`, `login`, and the rest are never edited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// The graphical login.
    Sddm,
    /// Autologin: only gnome-keyring's lines go (it has no password).
    SddmAutologin,
    /// Omarchy's lock screen.
    LockPassword,
    Passwd,
}

impl Service {
    pub const ALL: [Service; 4] = [
        Service::Sddm,
        Service::SddmAutologin,
        Service::LockPassword,
        Service::Passwd,
    ];

    pub fn file(self) -> &'static str {
        match self {
            Self::Sddm => "sddm",
            Self::SddmAutologin => "sddm-autologin",
            Self::LockPassword => "omarchy-lock-password",
            Self::Passwd => "passwd",
        }
    }

    fn from_file(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.file() == name)
    }
}

/// A line a transformation removed, and the line it followed (for the
/// inverse).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    pub after: Option<String>,
    pub line: String,
}

/// A transformed service file.
#[derive(Debug, PartialEq, Eq)]
pub struct Edit {
    pub text: String,
    pub removed: Vec<Removed>,
}

fn words(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

fn module_is(line: &str, module: &str) -> bool {
    !line.trim_start().starts_with('#')
        && words(line)
            .iter()
            .any(|w| *w == module || w.ends_with(&format!("/{module}")))
}

fn starts(line: &str, prefix: &[&str]) -> bool {
    words(line).starts_with(prefix)
}

/// Insert `ours` after the first line matching `anchor`, unless an
/// equivalent line is already there.
fn insert_after(
    lines: &mut Vec<String>,
    anchor: impl Fn(&str) -> bool,
    ours: &str,
    service: Service,
) -> Result<()> {
    if lines.iter().any(|l| words(l) == words(ours)) {
        return Ok(());
    }
    let at = lines.iter().position(|l| anchor(l)).ok_or_else(|| {
        format!(
            "{}: the expected line is missing; add `{ours}` by hand",
            service.file()
        )
    })?;
    lines.insert(at + 1, ours.to_string());
    Ok(())
}

/// Transform `text` for `service`: idempotent (an applied file comes back
/// unchanged, with nothing removed).
pub fn transform(service: Service, text: &str) -> Result<Edit> {
    let mut lines: Vec<String> = Vec::new();
    let mut removed = Vec::new();
    let drop_gnome = matches!(service, Service::Sddm | Service::SddmAutologin);
    for line in text.lines() {
        if drop_gnome && module_is(line, "pam_gnome_keyring.so") {
            removed.push(Removed {
                after: lines.last().cloned(),
                line: line.to_string(),
            });
        } else {
            lines.push(line.to_string());
        }
    }
    match service {
        Service::Sddm => {
            insert_after(
                &mut lines,
                |l| starts(l, &["auth", "include", "system-login"]),
                AUTH,
                service,
            )?;
            insert_after(
                &mut lines,
                |l| starts(l, &["session", "include", "system-login"]),
                SESSION,
                service,
            )?;
        }
        Service::SddmAutologin => {}
        Service::LockPassword => {
            // After the last auth line (`pam_faillock authsucc`): only a
            // password pam_unix accepted ever reaches aleph.
            if !lines.iter().any(|l| words(l) == words(AUTH)) {
                let last = lines
                    .iter()
                    .rposition(|l| starts(l, &["auth"]) || starts(l, &["-auth"]))
                    .ok_or_else(|| {
                        format!("{}: no auth lines; add `{AUTH}` by hand", service.file())
                    })?;
                lines.insert(last + 1, AUTH.to_string());
            }
        }
        Service::Passwd => insert_after(
            &mut lines,
            |l| starts(l, &["password", "include", "system-auth"]),
            PASSWORD,
            service,
        )?,
    }
    let mut out = lines.join("\n");
    if text.ends_with('\n') || !text.is_empty() {
        out.push('\n');
    }
    Ok(Edit { text: out, removed })
}

/// Undo `transform` on `text`: aleph's lines removed and the removed lines
/// put back after the lines they followed. `None` if that does not apply
/// cleanly (a line to put back no longer has its anchor).
pub fn inverse(text: &str, removed: &[Removed]) -> Option<String> {
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| {
            let w = words(l);
            w != words(AUTH) && w != words(SESSION) && w != words(PASSWORD)
        })
        .map(str::to_string)
        .collect();
    for r in removed {
        if lines.contains(&r.line) {
            continue;
        }
        let at = match &r.after {
            None => 0,
            Some(after) => lines.iter().rposition(|l| l == after)? + 1,
        };
        lines.insert(at, r.line.clone());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    Some(out)
}

/// Where the root side works (tests use a temporary tree and their own
/// uid as the required owner).
pub struct Root {
    /// `/etc/pam.d`.
    pub pam_dir: PathBuf,
    /// `/var/lib/aleph`, holding the manifest.
    pub state_dir: PathBuf,
    /// The owner every edited file must have (root).
    pub owner: u32,
}

impl Root {
    pub fn system() -> Self {
        Self {
            pam_dir: "/etc/pam.d".into(),
            state_dir: "/var/lib/aleph".into(),
            owner: 0,
        }
    }

    fn manifest_path(&self) -> PathBuf {
        self.state_dir.join("manifest.json")
    }

    fn backup(&self, service: Service) -> PathBuf {
        self.pam_dir.join(format!("{}.aleph-orig", service.file()))
    }
}

/// What `apply` did to one file (the manifest's entry).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    /// The file as `apply` wrote it.
    pub applied: String,
    pub removed: Vec<Removed>,
    /// Whether an `.aleph-orig` backup holds the file from before.
    pub backup: bool,
}

/// Everything setup did as root (`/var/lib/aleph/manifest.json`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub files: BTreeMap<String, Applied>,
}

impl Manifest {
    pub fn load(root: &Root) -> Result<Self> {
        match std::fs::read(root.manifest_path()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("the manifest: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", root.manifest_path().display())),
        }
    }

    fn save(&self, root: &Root) -> Result<()> {
        if self.files.is_empty() {
            return match std::fs::remove_file(root.manifest_path()) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            };
        }
        std::fs::create_dir_all(&root.state_dir).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&root.manifest_path(), &bytes, 0o644, None)
    }
}

/// Why a file is left for the user to edit (E6): not a regular file owned
/// by `owner` (a symlink, a NixOS-managed file, ...).
fn not_ordinary(path: &Path, owner: u32) -> Option<String> {
    match std::fs::symlink_metadata(path) {
        Err(e) => Some(format!("{}: {e}", path.display())),
        Ok(m) if m.file_type().is_symlink() => Some(format!("{} is a symlink", path.display())),
        Ok(m) if !m.is_file() => Some(format!("{} is not a regular file", path.display())),
        Ok(m) if m.uid() != owner => {
            Some(format!("{} is not owned by uid {owner}", path.display()))
        }
        Ok(_) => None,
    }
}

/// Write `path` atomically: a temporary file in the same directory, fsync,
/// the given mode and owner, rename, then fsync the directory.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32, owner: Option<(u32, u32)>) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or("no directory")?;
    let name = path.file_name().ok_or("no file name")?.to_string_lossy();
    let tmp = dir.join(format!(".{name}.aleph-tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| e.to_string())?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(|e| e.to_string())?;
    }
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| e.to_string())
}

/// What `apply` changed, and what it left for the user.
#[derive(Debug, Default)]
pub struct Report {
    pub changed: Vec<Service>,
    /// Files not ordinary, with what to add by hand.
    pub manual: Vec<String>,
}

/// Apply every transformation (E4). Files that are not ordinary put that
/// service in manual mode (E6); missing ones are skipped.
pub fn apply(root: &Root) -> Result<Report> {
    let mut manifest = Manifest::load(root)?;
    let mut report = Report::default();
    for service in Service::ALL {
        let path = root.pam_dir.join(service.file());
        if !path.exists() && std::fs::symlink_metadata(&path).is_err() {
            continue;
        }
        if let Some(why) = not_ordinary(&path, root.owner) {
            report
                .manual
                .push(format!("{why}: {}", manual_lines(service)));
            continue;
        }
        let original =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let edit = transform(service, &original)?;
        if edit.text == original {
            // (Already applied, by an earlier run or by hand: recorded so
            // revert can take the lines out again.)
            manifest
                .files
                .entry(service.file().to_string())
                .or_insert(Applied {
                    applied: original,
                    removed: Vec::new(),
                    backup: false,
                });
            continue;
        }
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let mode = meta.mode() & 0o7777;
        let owner = Some((meta.uid(), meta.gid()));
        let backup = root.backup(service);
        if !backup.exists() {
            write_atomic(&backup, original.as_bytes(), mode, owner)?;
        }
        write_atomic(&path, edit.text.as_bytes(), mode, owner)?;
        let removed = match manifest.files.get(service.file()) {
            // (A re-run keeps what the first run removed.)
            Some(prev) if edit.removed.is_empty() => prev.removed.clone(),
            _ => edit.removed,
        };
        manifest.files.insert(
            service.file().to_string(),
            Applied {
                applied: edit.text,
                removed,
                backup: true,
            },
        );
        report.changed.push(service);
    }
    manifest.save(root)?;
    Ok(report)
}

fn manual_lines(service: Service) -> String {
    match service {
        Service::Sddm => format!(
            "add `{AUTH}` after `auth include system-login` and `{SESSION}` after `session include system-login`, and remove the pam_gnome_keyring lines"
        ),
        Service::SddmAutologin => "remove the pam_gnome_keyring lines".into(),
        Service::LockPassword => format!("add `{AUTH}` after the last auth line"),
        Service::Passwd => format!("add `{PASSWORD}` after `password include system-auth`"),
    }
}

/// Put back the files `apply` changed (a failed verification): each from
/// its backup, byte for byte; their manifest entries go.
pub fn roll_back(root: &Root, services: &[Service]) -> Result<()> {
    let mut manifest = Manifest::load(root)?;
    for service in services {
        let backup = root.backup(*service);
        let path = root.pam_dir.join(service.file());
        let bytes = std::fs::read(&backup).map_err(|e| format!("{}: {e}", backup.display()))?;
        let meta = std::fs::metadata(&backup).map_err(|e| e.to_string())?;
        write_atomic(
            &path,
            &bytes,
            meta.mode() & 0o7777,
            Some((meta.uid(), meta.gid())),
        )?;
        let _ = std::fs::remove_file(&backup);
        manifest.files.remove(service.file());
    }
    manifest.save(root)
}

/// Undo what the manifest records (E4's conditional revert). Returns one
/// line per file.
pub fn revert(root: &Root) -> Result<Vec<String>> {
    let mut manifest = Manifest::load(root)?;
    let mut done = Vec::new();
    let names: Vec<String> = manifest.files.keys().cloned().collect();
    for name in names {
        let entry = manifest.files[&name].clone();
        let Some(service) = Service::from_file(&name) else {
            continue;
        };
        let path = root.pam_dir.join(&name);
        if let Some(why) = not_ordinary(&path, root.owner) {
            done.push(format!("{why}: left alone; {}", undo_lines(service)));
            manifest.files.remove(&name);
            continue;
        }
        let current =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let (mode, owner) = (meta.mode() & 0o7777, Some((meta.uid(), meta.gid())));
        let backup = root.backup(service);
        if current == entry.applied && entry.backup && backup.exists() {
            let bytes = std::fs::read(&backup).map_err(|e| e.to_string())?;
            write_atomic(&path, &bytes, mode, owner)?;
            let _ = std::fs::remove_file(&backup);
            done.push(format!("{}: restored from its backup", path.display()));
        } else if let Some(text) = inverse(&current, &entry.removed) {
            if text != current {
                write_atomic(&path, text.as_bytes(), mode, owner)?;
            }
            let _ = std::fs::remove_file(&backup);
            done.push(format!(
                "{}: aleph's lines taken out (the file changed since setup; the rest is kept)",
                path.display()
            ));
        } else {
            done.push(format!(
                "{}: changed since setup and left alone; {}",
                path.display(),
                undo_lines(service)
            ));
        }
        manifest.files.remove(&name);
    }
    manifest.save(root)?;
    Ok(done)
}

fn undo_lines(service: Service) -> String {
    match service {
        Service::SddmAutologin => "put back the pam_gnome_keyring lines if you want them".into(),
        Service::Sddm => {
            "remove the pam_aleph lines and put back the pam_gnome_keyring lines".into()
        }
        _ => "remove the pam_aleph line".into(),
    }
}

// ---- verification through real Linux-PAM

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
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    fn pam_strerror(handle: *mut c_void, errnum: c_int) -> *const c_char;
}

/// Answers every hidden prompt with the password in `appdata`.
extern "C" fn answer(
    n: c_int,
    msgs: *mut *const Message,
    out: *mut *mut Response,
    appdata: *mut c_void,
) -> c_int {
    // SAFETY: PAM passes `n` messages and our appdata (a live CString);
    // responses are calloc'd and answers strdup'd, as PAM frees them.
    unsafe {
        let password = appdata.cast::<c_char>();
        let responses =
            libc::calloc(n as usize, std::mem::size_of::<Response>()).cast::<Response>();
        if responses.is_null() {
            return 5; // PAM_BUF_ERR
        }
        for i in 0..n as usize {
            if (**msgs.add(i)).style == PAM_PROMPT_ECHO_OFF {
                (*responses.add(i)).resp = libc::strdup(password);
            }
        }
        *out = responses;
    }
    PAM_SUCCESS
}

/// Authenticate `user` with `password` through `service` in `confdir`,
/// as the display manager or the lock screen would.
pub fn authenticate(confdir: &Path, service: &str, user: &str, password: &str) -> Result<()> {
    let service_c = CString::new(service).map_err(|e| e.to_string())?;
    let user_c = CString::new(user).map_err(|e| e.to_string())?;
    let dir = CString::new(confdir.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
    let password = zeroize::Zeroizing::new(CString::new(password).map_err(|e| e.to_string())?);
    let conv = Conv {
        conv: answer,
        appdata: password.as_ptr() as *mut c_void,
    };
    let mut h = std::ptr::null_mut();
    // SAFETY: valid strings and conversation for the handle's lifetime;
    // the handle is ended before they drop.
    unsafe {
        let r = pam_start_confdir(
            service_c.as_ptr(),
            user_c.as_ptr(),
            &conv,
            dir.as_ptr(),
            &mut h,
        );
        if r != PAM_SUCCESS {
            return Err(format!("{service}: pam_start failed ({r})"));
        }
        let r = pam_authenticate(h, 0);
        let why = std::ffi::CStr::from_ptr(pam_strerror(h, r))
            .to_string_lossy()
            .into_owned();
        pam_end(h, r);
        if r != PAM_SUCCESS {
            return Err(format!("{service}: {why}"));
        }
    }
    Ok(())
}

/// The services `verify` runs: the lock screen, then the login (never
/// `passwd`, which would change the password).
pub const VERIFIED: [Service; 2] = [Service::LockPassword, Service::Sddm];

/// Check the edited stacks with a real login (E4): each verified service
/// present authenticates `user` with `password`.
pub fn verify(root: &Root, user: &str, password: &str) -> Result<()> {
    for service in VERIFIED {
        if root.pam_dir.join(service.file()).exists() {
            authenticate(&root.pam_dir, service.file(), user, password)?;
        }
    }
    Ok(())
}

/// A warning if this binary could be replaced by a user (the root side
/// runs as `sudo <this binary>`).
pub fn writable_binary_warning() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let meta = std::fs::metadata(&exe).ok()?;
    (meta.uid() != 0 || meta.mode() & 0o022 != 0).then(|| {
        format!(
            "warning: {} is not a root-owned, root-only-writable file; running it as root trusts whoever can write it",
            exe.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(dir: &str, name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/pam")
                .join(dir)
                .join(name),
        )
        .unwrap()
    }

    /// The stock Omarchy files become the applied ones; applying again
    /// changes nothing; the inverse gives back the stock files exactly.
    #[test]
    fn transforms_match_the_fixtures_are_idempotent_and_invert() {
        for service in Service::ALL {
            let stock = fixture("omarchy", service.file());
            let edit = transform(service, &stock).unwrap();
            assert_eq!(
                edit.text,
                fixture("omarchy-applied", service.file()),
                "{service:?}"
            );
            let again = transform(service, &edit.text).unwrap();
            assert_eq!(again.text, edit.text, "{service:?}");
            assert!(again.removed.is_empty());
            assert_eq!(
                inverse(&edit.text, &edit.removed).unwrap(),
                stock,
                "{service:?}"
            );
        }
    }

    /// Only the expected lines move: gnome-keyring's go from sddm and
    /// sddm-autologin, and stay in passwd.
    #[test]
    fn gnome_keyring_lines_go_only_from_the_login_services() {
        let e = transform(Service::Passwd, &fixture("omarchy", "passwd")).unwrap();
        assert!(e.text.contains("pam_gnome_keyring.so"));
        assert!(e.removed.is_empty());
        let e = transform(
            Service::SddmAutologin,
            &fixture("omarchy", "sddm-autologin"),
        )
        .unwrap();
        assert!(!e.text.contains("pam_gnome_keyring.so"));
        assert!(!e.text.contains("pam_aleph.so"));
        assert_eq!(e.removed.len(), 2);
    }

    fn tree() -> (tempfile::TempDir, Root) {
        let dir = tempfile::tempdir().unwrap();
        let pam_dir = dir.path().join("pam.d");
        std::fs::create_dir_all(&pam_dir).unwrap();
        for service in Service::ALL {
            std::fs::write(
                pam_dir.join(service.file()),
                fixture("omarchy", service.file()),
            )
            .unwrap();
        }
        let root = Root {
            pam_dir,
            state_dir: dir.path().join("state"),
            owner: unsafe { libc::getuid() },
        };
        (dir, root)
    }

    /// Apply edits everything and records it; revert restores every file
    /// byte for byte and leaves no backups or manifest behind.
    #[test]
    fn apply_then_revert_restores_every_file_exactly() {
        let (_dir, root) = tree();
        let report = apply(&root).unwrap();
        assert_eq!(report.changed.len(), 4);
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy-applied", service.file())
            );
        }
        assert!(apply(&root).unwrap().changed.is_empty());
        let done = revert(&root).unwrap();
        assert_eq!(done.len(), 4, "{done:?}");
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
            assert!(!root.backup(service).exists());
        }
        assert!(!root.manifest_path().exists());
    }

    /// A file changed since apply keeps the change: aleph's lines come out
    /// by the inverse; one whose anchors are gone is left alone.
    #[test]
    fn revert_after_an_edit_keeps_the_edit_or_leaves_the_file() {
        let (_dir, root) = tree();
        apply(&root).unwrap();
        let passwd = root.pam_dir.join("passwd");
        let mut text = std::fs::read_to_string(&passwd).unwrap();
        text.push_str("# a local change\n");
        std::fs::write(&passwd, &text).unwrap();
        let sddm = root.pam_dir.join("sddm");
        std::fs::write(
            &sddm,
            "#%PAM-1.0\nauth required pam_deny.so\n-auth      optional  pam_aleph.so\n",
        )
        .unwrap();
        let done = revert(&root).unwrap();
        let passwd_now = std::fs::read_to_string(&passwd).unwrap();
        assert!(passwd_now.contains("# a local change"));
        assert!(!passwd_now.contains("pam_aleph"));
        assert!(
            std::fs::read_to_string(&sddm)
                .unwrap()
                .contains("pam_aleph")
        );
        assert!(done.iter().any(|d| d.contains("left alone")), "{done:?}");
    }

    /// Files not owned by the required owner (root) are left for the user,
    /// unchanged.
    #[test]
    fn files_not_owned_by_root_are_manual() {
        let (_dir, mut root) = tree();
        root.owner = root.owner.wrapping_add(1);
        let report = apply(&root).unwrap();
        assert!(report.changed.is_empty());
        assert_eq!(report.manual.len(), 4);
        assert!(
            report.manual[0].contains("is not owned by uid"),
            "{:?}",
            report.manual
        );
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
        }
    }

    /// A failed check puts every changed file back exactly, and forgets it.
    #[test]
    fn roll_back_restores_the_changed_files() {
        let (_dir, root) = tree();
        let report = apply(&root).unwrap();
        roll_back(&root, &report.changed).unwrap();
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
            assert!(!root.backup(service).exists());
        }
        assert!(!root.manifest_path().exists());
    }

    /// A symlinked service is left for the user, with the lines to add.
    #[test]
    fn a_symlinked_service_is_manual() {
        let (dir, root) = tree();
        let real = dir.path().join("real-passwd");
        std::fs::rename(root.pam_dir.join("passwd"), &real).unwrap();
        std::os::unix::fs::symlink(&real, root.pam_dir.join("passwd")).unwrap();
        let report = apply(&root).unwrap();
        assert!(
            report
                .manual
                .iter()
                .any(|m| m.contains("symlink") && m.contains(PASSWORD))
        );
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            fixture("omarchy", "passwd")
        );
    }

    /// The transformed lock-screen and login stacks, through real
    /// Linux-PAM: the right password passes and a wrong one fails, with
    /// aleph's line in place (jumps intact). pam_unix is replaced by a
    /// password check, pam_faillock (root-only) by pam_permit, and
    /// pam_aleph points at a socket that does not exist, so nothing can
    /// reach a real daemon.
    #[test]
    fn the_transformed_stacks_run_through_real_pam() {
        let dir = tempfile::tempdir().unwrap();
        let check = dir.path().join("check");
        std::fs::write(&check, "#!/bin/sh\nread -r p\n[ \"$p\" = hunter2 ]\n").unwrap();
        std::fs::set_permissions(&check, std::fs::Permissions::from_mode(0o755)).unwrap();
        let unix = format!("pam_exec.so expose_authtok quiet {}", check.display());
        let aleph = format!(
            "pam_aleph.so socket={}",
            dir.path().join("none.sock").display()
        );
        let stub = |text: String| {
            text.lines()
                .map(|l| {
                    if l.contains("pam_unix.so") {
                        l.replace("pam_unix.so try_first_pass nullok", &unix)
                    } else if l.contains("pam_faillock.so") {
                        let w = words(l);
                        format!("{} {} pam_permit.so", w[0], w[1])
                    } else {
                        l.replace("pam_aleph.so", &aleph)
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        };
        for service in VERIFIED {
            std::fs::write(
                dir.path().join(service.file()),
                stub(fixture("omarchy-applied", service.file())),
            )
            .unwrap();
        }
        std::fs::write(
            dir.path().join("system-login"),
            format!("auth required {unix}\naccount required pam_permit.so\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("system-local-login"),
            "account required pam_permit.so\n",
        )
        .unwrap();
        let user = std::env::var("USER").unwrap();
        for service in VERIFIED {
            authenticate(dir.path(), service.file(), &user, "hunter2").unwrap();
            assert!(authenticate(dir.path(), service.file(), &user, "wrong").is_err());
        }
    }

    /// Real Linux-PAM: a stack that accepts the password passes, one that
    /// does not fails (stub stacks: never pam_aleph here, which could reach
    /// a real daemon).
    #[test]
    fn authenticate_runs_real_pam() {
        let dir = tempfile::tempdir().unwrap();
        let check = dir.path().join("check");
        std::fs::write(&check, "#!/bin/sh\nread -r p\n[ \"$p\" = hunter2 ]\n").unwrap();
        std::fs::set_permissions(&check, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            dir.path().join("ok"),
            format!(
                "auth required pam_exec.so expose_authtok quiet {}\n",
                check.display()
            ),
        )
        .unwrap();
        let user = std::env::var("USER").unwrap();
        authenticate(dir.path(), "ok", &user, "hunter2").unwrap();
        let err = authenticate(dir.path(), "ok", &user, "wrong").unwrap_err();
        assert!(err.starts_with("ok:"), "{err}");
    }
}
```

Apply this patch with `git apply` (save it as `/tmp/t3-impl.patch`):

```diff
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -26,6 +26,25 @@
     json: bool,
     #[command(subcommand)]
     cmd: Cmd,
+}
+
+#[derive(Subcommand)]
+enum SystemCmd {
+    /// Add aleph to the login, lock-screen, and passwd PAM services, then
+    /// check the login and lock screen with a real login (undone at once
+    /// if that fails).
+    Apply {
+        /// Whose login password checks the edited services.
+        #[arg(long)]
+        user: String,
+    },
+    /// Check the login and lock-screen services with a real login.
+    Verify {
+        #[arg(long)]
+        user: String,
+    },
+    /// Undo what `apply` did (only what it did).
+    Revert,
 }
 
 #[derive(Clone, Copy, clap::ValueEnum)]
@@ -46,6 +65,9 @@
     },
     /// Show the keyring's state and keyslots.
     Status,
+    /// The root side of setup (run with sudo): login and screen unlock.
+    #[command(subcommand)]
+    System(SystemCmd),
     /// Import items from another keyring (alephd reads them itself).
     Import {
         #[arg(value_enum)]
@@ -181,9 +203,13 @@
         clap_complete::generate(shell, &mut Cli::command(), "aleph", &mut std::io::stdout());
         return Ok(ExitCode::SUCCESS);
     }
+    // The root side: no session bus, no user configuration.
+    if let Cmd::System(action) = cli.cmd {
+        return run_system(action).map(|()| ExitCode::SUCCESS);
+    }
     let c = Client::connect().await?;
     match cli.cmd {
-        Cmd::Completions { .. } => unreachable!(),
+        Cmd::Completions { .. } | Cmd::System(_) => unreachable!(),
         Cmd::Setup { revert: true } => revert(&c).await?,
         Cmd::Setup { revert: false } => {
             let status = c.status().await?;
@@ -440,6 +466,66 @@
     Ok(())
 }
 
+/// `aleph system ...`, as root (DECISIONS.md E4–E6).
+fn run_system(action: SystemCmd) -> Result<()> {
+    if unsafe { libc::geteuid() } != 0 {
+        return Err("run it as root: sudo aleph system ...".into());
+    }
+    if let Some(w) = system::writable_binary_warning() {
+        eprintln!("aleph: {w}");
+    }
+    let root = system::Root::system();
+    match action {
+        SystemCmd::Apply { user } => {
+            if std::path::Path::new("/etc/NIXOS").exists() {
+                eprintln!(
+                    "aleph: NixOS manages /etc/pam.d: add to your configuration, for each of the login and lock-screen services,
+  security.pam.services.<name>.text lines: `{}` (and for the login `{}`; for passwd `{}`)",
+                    system::AUTH,
+                    system::SESSION,
+                    system::PASSWORD
+                );
+                return Ok(());
+            }
+            let report = system::apply(&root)?;
+            for m in &report.manual {
+                eprintln!("aleph: by hand: {m}");
+            }
+            if report.changed.is_empty() {
+                eprintln!("aleph: the PAM services were already set up");
+                return Ok(());
+            }
+            let password = zeroize::Zeroizing::new(
+                rpassword::prompt_password(format!(
+                    "Login password for {user} (checks the login and lock screen once): "
+                ))
+                .map_err(|e| e.to_string())?,
+            );
+            if let Err(e) = system::verify(&root, &user, &password) {
+                system::roll_back(&root, &report.changed)?;
+                return Err(format!(
+                    "the check failed ({e}); the PAM changes were undone"
+                ));
+            }
+            eprintln!("aleph: login and screen unlock now reach aleph");
+        }
+        SystemCmd::Verify { user } => {
+            let password = zeroize::Zeroizing::new(
+                rpassword::prompt_password(format!("Login password for {user}: "))
+                    .map_err(|e| e.to_string())?,
+            );
+            system::verify(&root, &user, &password)?;
+            eprintln!("aleph: the login and lock-screen services accept the password");
+        }
+        SystemCmd::Revert => {
+            for line in system::revert(&root)? {
+                eprintln!("aleph: {line}");
+            }
+        }
+    }
+    Ok(())
+}
+
 /// `aleph setup --revert` (DECISIONS.md E3): copy the keyring back to
 /// gnome-keyring and verify it, then switch back and let go of the name.
 async fn revert(c: &Client) -> Result<()> {
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-cli && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 13 passed | ok. 12 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **gnome-keyring's lines stay in passwd** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph gnome_keyring_lines_go_only`: replace `let drop_gnome = matches!(service, Service::Sddm | Service::SddmAutologin);` with `let drop_gnome = true;`.
- **revert restores byte for byte only an unchanged file** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph revert_after_an_edit`: replace `if current == entry.applied && entry.backup && backup.exists() {` with `if entry.backup && backup.exists() {`.
- **a symlinked service is manual** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph a_symlinked_service_is_manual`: replace `Ok(m) if m.file_type().is_symlink() => Some(format!("{} is a symlink", path.display())),` with `(nothing)`.
- **files not owned by root are manual** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph files_not_owned_by_root_are_manual`: replace `Ok(m) if m.uid() != owner => {` with `Ok(m) if false => {`.
- **a failed check puts the files back** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph roll_back_restores`:

  replace

  ```rust
  write_atomic(&path, &bytes, meta.mode() & 0o7777, Some((meta.uid(), meta.gid())))?;
  let _ = std::fs::remove_file(&backup);
  manifest.files.remove(service.file());
  ```

  with

  ```rust
  let _ = std::fs::remove_file(&backup);
  manifest.files.remove(service.file());
  ```


- [ ] **Step 6: Commit**

```bash
git add crates/aleph-cli
git commit -m "feat(cli): aleph system, the root side of setup" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 4: the wizard

**Interfaces:**
- Consumes: Tasks 2 and 3.
- Produces: `wizard::{SddmConfig, autologin_user(&SddmConfig) -> Option<String>, OMARCHY_HOOK, install_omarchy_hook(&Path), remove_omarchy_hook(&Path), run_as_root(&[&str]), lockout_value(), LOCKOUT_COMMAND, set_lockout_auth(&str)}`; `switchover::Dirs::config_home`; the full `aleph setup` and `setup --revert`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-cli/src/wizard.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path) -> SddmConfig {
        SddmConfig {
            dirs: vec![dir.join("lib"), dir.join("etc")],
            main: dir.join("sddm.conf"),
        }
    }

    /// Later files win; every file in a directory counts (a `.disabled`
    /// one too); an empty user means none.
    #[test]
    fn autologin_follows_sddm_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let c = config(dir.path());
        std::fs::create_dir_all(dir.path().join("lib")).unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        assert_eq!(autologin_user(&c), None);
        std::fs::write(
            dir.path().join("etc/autologin.conf.disabled"),
            "[Autologin]\nUser=kyle\nSession=hyprland\n",
        )
        .unwrap();
        assert_eq!(autologin_user(&c).as_deref(), Some("kyle"));
        std::fs::write(dir.path().join("etc/zz.conf"), "[Autologin]\nUser=\n").unwrap();
        assert_eq!(autologin_user(&c), None);
        std::fs::write(dir.path().join("sddm.conf"), "[Autologin]\nUser = alice\n").unwrap();
        assert_eq!(autologin_user(&c).as_deref(), Some("alice"));
        // Another section's User is not autologin.
        std::fs::write(dir.path().join("sddm.conf"), "[Users]\nUser=bob\n").unwrap();
        assert_eq!(autologin_user(&c), None);
    }

    /// The hook goes in only for Omarchy users, once, and revert removes
    /// it only while it is still ours.
    #[test]
    fn the_omarchy_hook_is_installed_once_and_removed_only_if_ours() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(install_omarchy_hook(dir.path()).unwrap(), None);
        std::fs::create_dir_all(dir.path().join("omarchy")).unwrap();
        let path = install_omarchy_hook(dir.path()).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), OMARCHY_HOOK);
        assert_eq!(install_omarchy_hook(dir.path()).unwrap(), None);
        std::fs::write(&path, "edited\n").unwrap();
        assert_eq!(remove_omarchy_hook(dir.path()).unwrap(), None);
        assert!(path.exists());
        std::fs::write(&path, OMARCHY_HOOK).unwrap();
        assert_eq!(remove_omarchy_hook(dir.path()).unwrap(), Some(path.clone()));
        assert!(!path.exists());
    }

    #[test]
    fn a_lockout_value_is_32_base32_characters_in_groups() {
        let v = lockout_value().unwrap();
        assert_eq!(v.len(), 39);
        assert!(v.split('-').all(|g| g.len() == 4));
        assert_ne!(v, lockout_value().unwrap());
    }
}
```

Apply this patch with `git apply` (save it as `/tmp/t4-tests.patch`):

```diff
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -9,6 +9,7 @@
 mod prompter;
 mod switchover;
 mod system;
+mod wizard;
 
 use std::collections::HashMap;
 use std::io::{IsTerminal, Read, Write};
--- a/crates/aleph-cli/src/switchover.rs
+++ b/crates/aleph-cli/src/switchover.rs
@@ -468,6 +468,7 @@
         let dirs = Dirs {
             data_home: home.path().join("data"),
             state_home: home.path().join("state"),
+            config_home: home.path().join("config"),
         };
         let units = FakeUnits::new(gk);
         let mut record = Record::load(&dirs).unwrap();
@@ -514,6 +515,7 @@
         let dirs = Dirs {
             data_home: home.path().join("data"),
             state_home: home.path().join("state"),
+            config_home: home.path().join("config"),
         };
         let units = FakeUnits::new(gk);
         let mut record = Record::load(&dirs).unwrap();
@@ -572,6 +574,7 @@
         let dirs = Dirs {
             data_home: home.path().join("data"),
             state_home: home.path().join("state"),
+            config_home: home.path().join("config"),
         };
         let units = FakeUnits::new(gk);
         // (systemd stops nothing: the fixture outlives the "stop".)
--- a/crates/aleph-cli/tests/cli.rs
+++ b/crates/aleph-cli/tests/cli.rs
@@ -7,8 +7,9 @@
 use aleph_daemon::testing::*;
 
 fn aleph(d: &Daemon, args: &[&str]) -> Command {
-    // Never the real home or user manager: setup writes activation files
-    // and runs systemctl (`false`: no unit exists, and any change fails).
+    // Never the real home, user manager, or sudo: setup writes activation
+    // files, runs systemctl (`false`: no unit exists, and any change
+    // fails), and offers the root side through sudo (`false`: it fails).
     let home = d.env.paths.data_dir.parent().unwrap().join("home");
     let mut cmd = Command::new(env!("CARGO_BIN_EXE_aleph"));
     cmd.args(args)
@@ -16,7 +17,9 @@
         .env("HOME", &home)
         .env("XDG_DATA_HOME", home.join("data"))
         .env("XDG_STATE_HOME", home.join("state"))
+        .env("XDG_CONFIG_HOME", home.join("config"))
         .env("ALEPH_SYSTEMCTL", "false")
+        .env("ALEPH_SUDO", "false")
         .env("ALEPH_NO_TTY", "1")
         .stdin(Stdio::piped())
         .stdout(Stdio::piped())
@@ -115,11 +118,14 @@
     assert!(out.contains("keyring: none"), "{out}");
     let log = setup(&d).await;
     assert!(log.contains("The keyring is ready."), "{log}");
-    // Then the import (no gnome-keyring here) and the switchover (alephd
-    // already serves the name); PAM is still by hand.
+    // Then the import (no gnome-keyring here), the switchover (alephd
+    // already serves the name), and the root side, which fails here (the
+    // tests' sudo is `false`) and says how to run it later.
+    assert!(log.contains("TPM: usable"), "{log}");
     assert!(log.contains("gnome-keyring is not running"), "{log}");
     assert!(log.contains("alephd serves the Secret Service"), "{log}");
-    assert!(log.contains("docs/testing.md"), "{log}");
+    assert!(log.contains("sudo aleph system apply --user"), "{log}");
+    assert!(log.contains("setup is done"), "{log}");
     let home = d.env.paths.data_dir.parent().unwrap().join("home");
     assert!(
         home.join("data/dbus-1/services/org.freedesktop.secrets.service")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-cli`
Expected: the build fails: the `wizard` module does not exist yet (and the setup test expects the new steps).

- [ ] **Step 3: Implement**

Write `crates/aleph-cli/src/wizard.rs`:

```rust
//! The parts of the setup wizard around the switchover (spec §7 `aleph
//! setup`; DECISIONS.md E5, D9, G1): autologin detection, Omarchy's lock
//! hook, the TPM's lockoutAuth, and running the root side through sudo.

use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, String>;

/// SDDM's configuration, in the order it applies it (later wins).
pub struct SddmConfig {
    /// Directories whose files are read in name order: SDDM's own, then
    /// the administrator's.
    pub dirs: Vec<PathBuf>,
    /// The main file, read last.
    pub main: PathBuf,
}

impl SddmConfig {
    pub fn system() -> Self {
        Self {
            dirs: vec![
                "/usr/lib/sddm/sddm.conf.d".into(),
                "/etc/sddm.conf.d".into(),
            ],
            main: "/etc/sddm.conf".into(),
        }
    }
}

/// The user SDDM logs in automatically, if any (E5: advisory; it only
/// picks the default unlock method and the summary). Every file in the
/// directories counts, not only `*.conf`: SDDM may read them all, so a
/// renamed `autologin.conf.disabled` is not trusted to be off.
pub fn autologin_user(config: &SddmConfig) -> Option<String> {
    let mut files = Vec::new();
    for dir in &config.dirs {
        let mut in_dir: Vec<PathBuf> = std::fs::read_dir(dir)
            .map(|d| {
                d.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_file())
                    .collect()
            })
            .unwrap_or_default();
        in_dir.sort();
        files.extend(in_dir);
    }
    files.push(config.main.clone());
    let mut user = None;
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let mut section = String::new();
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_string();
            } else if section == "Autologin"
                && let Some((key, value)) = line.split_once('=')
                && key.trim() == "User"
            {
                user = Some(value.trim().to_string());
            }
        }
    }
    user.filter(|u| !u.is_empty())
}

/// The hook Omarchy's lock runs once it calls `omarchy-hook lock` (G1).
pub const OMARCHY_HOOK: &str =
    "# Installed by aleph setup: lock the keyring with the screen.\naleph lock\n";

fn omarchy_hook(config_home: &Path) -> PathBuf {
    config_home.join("omarchy/hooks/lock.d/aleph")
}

/// Install the lock hook if this is an Omarchy user (`omarchy/` in the
/// configuration directory); returns its path if it was just installed.
pub fn install_omarchy_hook(config_home: &Path) -> Result<Option<PathBuf>> {
    if !config_home.join("omarchy").is_dir() {
        return Ok(None);
    }
    let path = omarchy_hook(config_home);
    if std::fs::read(&path).ok().as_deref() == Some(OMARCHY_HOOK.as_bytes()) {
        return Ok(None);
    }
    let dir = path.parent().expect("has a parent");
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(&path, OMARCHY_HOOK).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(path))
}

/// Remove the hook if it is still ours (revert); returns its path if so.
pub fn remove_omarchy_hook(config_home: &Path) -> Result<Option<PathBuf>> {
    let path = omarchy_hook(config_home);
    if std::fs::read(&path).ok().as_deref() != Some(OMARCHY_HOOK.as_bytes()) {
        return Ok(None);
    }
    std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(path))
}

/// The program that runs the root side (`sudo`; `ALEPH_SUDO` names another,
/// for tests, which must never run the real one).
fn sudo() -> std::ffi::OsString {
    std::env::var_os("ALEPH_SUDO").unwrap_or_else(|| "sudo".into())
}

/// Run `args` as root through sudo, on the terminal (sudo asks for the
/// password there).
pub fn run_as_root(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(sudo())
        .args(args)
        .status()
        .map_err(|e| format!("sudo: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`sudo {}` failed", args.join(" ")))
    }
}

/// A lockoutAuth value: 32 characters of base32 (160 random bits), in
/// groups of four.
pub fn lockout_value() -> Result<String> {
    use std::io::Read;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("randomness: {e}"))?;
    let chars: Vec<char> = bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % 32] as char)
        .collect();
    Ok(chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-"))
}

/// The command that sets lockoutAuth, reading the value on standard input
/// so it never appears in `argv` or shell history (D9).
pub const LOCKOUT_COMMAND: [&str; 4] = ["tpm2_changeauth", "-c", "lockout", "file:-"];

/// Set the TPM's lockoutAuth to `value` through sudo.
pub fn set_lockout_auth(value: &str) -> Result<()> {
    use std::io::Write;
    let mut child = std::process::Command::new(sudo())
        .args(LOCKOUT_COMMAND)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("sudo: {e}"))?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(value.as_bytes())
        .map_err(|e| e.to_string())?;
    let status = child.wait().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("tpm2_changeauth failed (lockoutAuth may already be set)".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path) -> SddmConfig {
        SddmConfig {
            dirs: vec![dir.join("lib"), dir.join("etc")],
            main: dir.join("sddm.conf"),
        }
    }

    /// Later files win; every file in a directory counts (a `.disabled`
    /// one too); an empty user means none.
    #[test]
    fn autologin_follows_sddm_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let c = config(dir.path());
        std::fs::create_dir_all(dir.path().join("lib")).unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        assert_eq!(autologin_user(&c), None);
        std::fs::write(
            dir.path().join("etc/autologin.conf.disabled"),
            "[Autologin]\nUser=kyle\nSession=hyprland\n",
        )
        .unwrap();
        assert_eq!(autologin_user(&c).as_deref(), Some("kyle"));
        std::fs::write(dir.path().join("etc/zz.conf"), "[Autologin]\nUser=\n").unwrap();
        assert_eq!(autologin_user(&c), None);
        std::fs::write(dir.path().join("sddm.conf"), "[Autologin]\nUser = alice\n").unwrap();
        assert_eq!(autologin_user(&c).as_deref(), Some("alice"));
        // Another section's User is not autologin.
        std::fs::write(dir.path().join("sddm.conf"), "[Users]\nUser=bob\n").unwrap();
        assert_eq!(autologin_user(&c), None);
    }

    /// The hook goes in only for Omarchy users, once, and revert removes
    /// it only while it is still ours.
    #[test]
    fn the_omarchy_hook_is_installed_once_and_removed_only_if_ours() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(install_omarchy_hook(dir.path()).unwrap(), None);
        std::fs::create_dir_all(dir.path().join("omarchy")).unwrap();
        let path = install_omarchy_hook(dir.path()).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), OMARCHY_HOOK);
        assert_eq!(install_omarchy_hook(dir.path()).unwrap(), None);
        std::fs::write(&path, "edited\n").unwrap();
        assert_eq!(remove_omarchy_hook(dir.path()).unwrap(), None);
        assert!(path.exists());
        std::fs::write(&path, OMARCHY_HOOK).unwrap();
        assert_eq!(remove_omarchy_hook(dir.path()).unwrap(), Some(path.clone()));
        assert!(!path.exists());
    }

    #[test]
    fn a_lockout_value_is_32_base32_characters_in_groups() {
        let v = lockout_value().unwrap();
        assert_eq!(v.len(), 39);
        assert!(v.split('-').all(|g| g.len() == 4));
        assert_ne!(v, lockout_value().unwrap());
    }
}
```

Apply this patch with `git apply` (save it as `/tmp/t4-impl.patch`):

```diff
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -214,10 +214,25 @@
         Cmd::Setup { revert: true } => revert(&c).await?,
         Cmd::Setup { revert: false } => {
             let status = c.status().await?;
+            let tpm = status.tpm.unwrap_or(false);
+            eprintln!(
+                "aleph: TPM: {}",
+                match status.tpm {
+                    Some(true) => "usable",
+                    Some(false) => "not usable (a login-password keyslot is used instead)",
+                    None => "busy (could not check now)",
+                }
+            );
+            let autologin = wizard::autologin_user(&wizard::SddmConfig::system());
+            if let Some(user) = &autologin {
+                eprintln!(
+                    "aleph: SDDM logs {user} in automatically: there is no password at login, so the keyring stays locked until first use, then asks for a security key or your login password"
+                );
+            }
             if status.vault {
                 eprintln!("aleph: a keyring already exists; checking the rest of setup");
             } else {
-                create_keyring(&c, status.tpm.unwrap_or(false)).await?;
+                create_keyring(&c, tpm, autologin.is_some()).await?;
             }
             // Import while gnome-keyring still serves the Secret Service
             // (E1), then take over from it (E9).
@@ -232,9 +247,33 @@
             {
                 eprintln!("aleph: {step}");
             }
-            eprintln!(
-                "aleph: note: setup does not yet set up login unlock (PAM): see docs/testing.md for the lines"
-            );
+            if let Some(hook) = wizard::install_omarchy_hook(&dirs.config_home)? {
+                eprintln!(
+                    "aleph: installed {}: the keyring locks with the screen once Omarchy's lock runs `omarchy-hook lock`",
+                    hook.display()
+                );
+            }
+            let mut term = prompter::Terminal::new();
+            if tpm {
+                offer_lockout_auth(&mut term)?;
+            }
+            // The root side comes last, and is optional (E10).
+            let user = std::env::var("USER").map_err(|_| "USER is not set")?;
+            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
+            let exe = exe.to_string_lossy();
+            let apply = [exe.as_ref(), "system", "apply", "--user", user.as_str()];
+            let answer = ask(
+                &mut term,
+                "Set up login and screen unlock now (runs sudo)? [Y/n] ",
+            )?;
+            if matches!(answer.trim(), "" | "y" | "Y" | "yes") {
+                if let Err(e) = wizard::run_as_root(&apply) {
+                    eprintln!("aleph: {e}; run `sudo aleph system apply --user {user}` later");
+                }
+            } else {
+                eprintln!("aleph: later: `sudo aleph system apply --user {user}`");
+            }
+            eprintln!("aleph: setup is done (`aleph status` shows the keyring)");
         }
 
         Cmd::Status => {
@@ -547,7 +586,7 @@
             removed.join(", ")
         );
         let mut term = prompter::Terminal::new();
-        let answer = term_line(&mut term, "Delete them from gnome-keyring too? [y/N] ")?;
+        let answer = ask(&mut term, "Delete them from gnome-keyring too? [y/N] ")?;
         delete = matches!(answer.trim(), "y" | "Y" | "yes");
     }
     outcome(
@@ -567,34 +606,98 @@
     for step in steps {
         eprintln!("aleph: {step}");
     }
+    if let Some(hook) = wizard::remove_omarchy_hook(&dirs.config_home)? {
+        eprintln!("aleph: removed {}", hook.display());
+    }
     c.release_secret_service().await?;
     eprintln!(
         "aleph: gnome-keyring serves the Secret Service again; the aleph vault is left in place"
     );
+    // The root side last (E3).
+    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
+    let exe = exe.to_string_lossy();
+    if let Err(e) = wizard::run_as_root(&[exe.as_ref(), "system", "revert"]) {
+        eprintln!("aleph: {e}; run `sudo aleph system revert` to undo the PAM changes");
+    }
     Ok(())
 }
 
-/// Create the keyring, asking which unlock method to use.
-async fn create_keyring(c: &Client, tpm: bool) -> Result<()> {
+/// Offer to set the TPM's lockoutAuth (D9): shown once, typed back, then
+/// set through sudo from standard input; declined, the command is printed.
+fn offer_lockout_auth(term: &mut prompter::Terminal) -> Result<()> {
+    let command = format!(
+        "sudo {} (the value on standard input)",
+        wizard::LOCKOUT_COMMAND.join(" ")
+    );
+    let answer = ask(
+        term,
+        "Protect the TPM's dictionary-attack lockout with a password of its own (recommended if nobody set one)? [y/N] ",
+    )?;
+    if !matches!(answer.trim(), "y" | "Y" | "yes") {
+        eprintln!("aleph: later: {command}");
+        return Ok(());
+    }
+    let value = zeroize::Zeroizing::new(wizard::lockout_value()?);
+    eprintln!(
+        "\nThe TPM lockout password. Keep it with your recovery key; it is needed only to clear a dictionary-attack lockout:\n\n    {}\n",
+        value.as_str()
+    );
+    let typed = zeroize::Zeroizing::new(term_line(term, "Type it back to confirm: ")?);
+    if typed.trim().to_uppercase() != value.as_str() {
+        eprintln!(
+            "aleph: that does not match; the lockout password was not set (later: {command})"
+        );
+        return Ok(());
+    }
+    if let Err(e) = wizard::set_lockout_auth(&value) {
+        eprintln!("aleph: {e}");
+    }
+    Ok(())
+}
+
+/// Create the keyring, asking which unlock method to use (a security key
+/// by default with autologin, where no login password unlocks it).
+async fn create_keyring(c: &Client, tpm: bool, autologin: bool) -> Result<()> {
     let first = if tpm {
-        "the TPM and your login password (recommended)"
+        "the TPM and your login password"
     } else {
         "your login password"
     };
-    eprintln!("How should the keyring unlock?\n  1) {first}\n  2) a FIDO2 security key");
+    let (default, first, second) = if autologin {
+        (
+            "2",
+            first.to_string(),
+            "a FIDO2 security key (recommended with autologin)",
+        )
+    } else {
+        (
+            "1",
+            format!("{first} (recommended)"),
+            "a FIDO2 security key",
+        )
+    };
+    eprintln!("How should the keyring unlock?\n  1) {first}\n  2) {second}");
     let mut term = prompter::Terminal::new();
-    let choice = term_line(&mut term, "Choice [1]: ")?;
-    let method = if choice.trim() == "2" {
-        "fido2"
-    } else {
-        "password"
+    let choice = term_line(&mut term, &format!("Choice [{default}]: "))?;
+    let choice = match choice.trim() {
+        "" => default,
+        other => other,
     };
+    let method = if choice == "2" { "fido2" } else { "password" };
     outcome(c.converse("Create", Args::Str(method)).await?)?;
     Ok(())
 }
 
 fn term_line(term: &mut prompter::Terminal, prompt: &str) -> Result<String> {
     term.line(prompt).map_err(|e| e.to_string())
+}
+
+/// A question with a default: no more input (end of file) takes it.
+fn ask(term: &mut prompter::Terminal, prompt: &str) -> Result<String> {
+    match term.line(prompt) {
+        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(String::new()),
+        other => other.map_err(|e| e.to_string()),
+    }
 }
 
 /// A keyslot id from its full form or a unique prefix (as `status` shows).
--- a/crates/aleph-cli/src/switchover.rs
+++ b/crates/aleph-cli/src/switchover.rs
@@ -136,6 +136,8 @@
     pub data_home: PathBuf,
     /// `$XDG_STATE_HOME` (setup's record under `aleph`).
     pub state_home: PathBuf,
+    /// `$XDG_CONFIG_HOME` (Omarchy's hooks).
+    pub config_home: PathBuf,
 }
 
 impl Dirs {
@@ -152,6 +154,7 @@
         Ok(Self {
             data_home: xdg("XDG_DATA_HOME", ".local/share"),
             state_home: xdg("XDG_STATE_HOME", ".local/state"),
+            config_home: xdg("XDG_CONFIG_HOME", ".config"),
         })
     }
 
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-cli && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 16 passed | ok. 12 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **every file in SDDM's directories counts** (`crates/aleph-cli/src/wizard.rs`), test `cargo test -p aleph-cli --bin aleph autologin_follows_sddm_precedence`: replace `.filter(|p| p.is_file())` with `.filter(|p| p.extension().is_some_and(|e| e == "conf"))`.
- **later SDDM files win** (`crates/aleph-cli/src/wizard.rs`), test `cargo test -p aleph-cli --bin aleph autologin_follows_sddm_precedence`: replace `user = Some(value.trim().to_string());` with `user = user.or(Some(value.trim().to_string()));`.
- **the Omarchy hook is removed only if ours** (`crates/aleph-cli/src/wizard.rs`), test `cargo test -p aleph-cli --bin aleph the_omarchy_hook_is_installed_once`:

  replace

  ```rust
  if std::fs::read(&path).ok().as_deref() != Some(OMARCHY_HOOK.as_bytes()) {
      return Ok(None);
  }
  std::fs::remove_file
  ```

  with

  ```rust
  std::fs::remove_file
  ```

- **an unanswered question takes its default** (`crates/aleph-cli/src/main.rs`), test `cargo test -p aleph-cli --test cli setup_creates_the_keyring`:

  replace

  ```rust
  Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(String::new()),
  ```

  with

  ```rust
  // (nothing)
  ```

- **a failed sudo does not fail setup** (`crates/aleph-cli/src/main.rs`), test `cargo test -p aleph-cli --test cli setup_creates_the_keyring`: replace `if let Err(e) = wizard::run_as_root(&apply) {` with `if let Err(e) = wizard::run_as_root(&apply).map_err(|e| -> String { panic!("{e}") }) {`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-cli
git commit -m "feat(cli): the setup wizard" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 5: spec, docs, decisions

**Interfaces:**
- Consumes: everything above (documentation only).

- [ ] **Step 1: Update the documents**

Apply this patch with `git apply` (save it as `/tmp/t5-docs.patch`):

~~~~diff
--- a/DECISIONS.md
+++ b/DECISIONS.md
@@ -8,6 +8,41 @@
 made directly are marked as such.
 
 ## 2026-09-27: Plan 4c (setup), design
+
+### G2. Calls made while prototyping Plan 4c
+
+Each to be weighed by the plan's reviewers:
+- **Import needs the vault unlocked** and no aleph prompter: gnome-keyring
+  asks for its own locked collections through its own prompt (a dismissed
+  one is skipped and listed), so the admin call just returns a summary.
+- **What import added is recorded** (`imported.json`: id, collection,
+  label, attributes), so revert can list items deleted in aleph since.
+- **Revert's export needs the login password** (checked with PAM): it
+  unlocks gnome-keyring's login keyring, which `pam_gnome_keyring` kept in
+  step in `passwd` (E4). If it does not open with it, nothing changes.
+- **"No gnome-keyring runs" is checked on the bus** (`org.gnome.keyring`
+  owned, or the Secret Service name held by another), not by listing
+  processes; the private instance gets a throwaway home and runtime
+  directory, and only the keyring data directory is real.
+- **Collections gnome-keyring lacks go into its default collection** on
+  revert: creating one would need gnome-keyring's own password prompt.
+- **E3's order holds as reviewed:** gnome-keyring, started while alephd
+  holds the name, waits and takes it once alephd lets go (checked with
+  the real gnome-keyring).
+- **`aleph export gnome-keyring` is not a command:** export happens only
+  in `setup --revert` (with the write freeze and the private instance).
+- **Wizard defaults:** a question left unanswered (end of input) takes its
+  default; the root step defaults to yes, and a failed or declined sudo
+  does not fail setup (it says how to run it later); with autologin the
+  default unlock method is a security key.
+- **`aleph system verify` runs the lock-screen and login stacks** (never
+  `passwd`, which would change the password).
+- **Tests never reach the real system:** `ALEPH_SYSTEMCTL` and
+  `ALEPH_SUDO` name stand-ins, and the CLI tests run with their own home.
+- **Observed on this machine:** autologin detection (every file in
+  `/etc/sddm.conf.d`, E5) reports `autologin.conf.disabled`'s user; if
+  SDDM does read it, that file still turns autologin on.
+
 
 ### G1. Omarchy's screen lock reaches alephd through an upstream `lock` hook — owner's decision
 
--- a/README.md
+++ b/README.md
@@ -13,9 +13,12 @@
 [`docs/superpowers/specs/2026-09-26-aleph-design.md`](docs/superpowers/specs/2026-09-26-aleph-design.md).
 
 Login and screen unlock (`pam_aleph`), `passwd` changes, and locking on
-sleep, screen lock, or idle are in place (Plan 4a). `aleph setup` does not
-yet edit PAM, take over from gnome-keyring, or import its items (Plan 4c):
-see [docs/testing.md](docs/testing.md) for the lines to add by hand. If
+sleep, screen lock, or idle are in place (Plan 4a). `aleph setup` creates the
+keyring,
+imports gnome-keyring's items, takes over the Secret Service from it, and
+(with `sudo aleph system apply`) sets up login and screen unlock; `aleph
+setup --revert` hands everything back (Plan 4c; see
+[docs/testing.md](docs/testing.md), including an emergency manual revert). If
 the login password is changed outside aleph, the next unlock asks for the
 previous one to update the TPM keyslot. `aleph backup` and `aleph restore`
 (with the recovery key, from `.bak`, or accepting a rolled-back file) are
--- a/docs/omarchy-lock-hook.md
+++ b/docs/omarchy-lock-hook.md
@@ -0,0 +1,24 @@
+# Proposed Omarchy change: a `lock` hook
+
+aleph locks its keyring when the screen locks. On Omarchy every lock (the
+key binding, the menu, and the idle service) runs `omarchy-system-lock`,
+which does not tell logind, so aleph cannot see it. Omarchy already runs
+user hooks (`omarchy-hook <name>` runs `~/.config/omarchy/hooks/<name>`
+and `~/.config/omarchy/hooks/<name>.d/*`), so a `lock` hook lets any
+program react, the way the script already locks 1Password.
+
+The change, in `bin/omarchy-system-lock`, right after the screen is
+locked:
+
+```bash
+omarchy-shell lock lock >/dev/null
+
+# Let user hooks react to the lock (e.g. lock password managers).
+omarchy-hook lock &
+```
+
+(`&`: a slow hook must never delay the lock.)
+
+`aleph setup` installs `~/.config/omarchy/hooks/lock.d/aleph`, which runs
+`aleph lock`; it does nothing until Omarchy runs the hook (DECISIONS.md
+G1).
--- a/docs/superpowers/specs/2026-09-26-aleph-design.md
+++ b/docs/superpowers/specs/2026-09-26-aleph-design.md
@@ -671,28 +671,52 @@
 
 ### Startup and switchover from gnome-keyring
 
-- Runs as a systemd user service `alephd.service`, with `alephd.socket`
-  owning `$XDG_RUNTIME_DIR/aleph/pam.sock` (mode `0600`). It is started by
-  D-Bus activation for `org.freedesktop.secrets`, or by socket activation
-  from PAM.
-- `aleph setup` (Arch/Omarchy):
-  1. checks `aleph-tpmd` `Status` and reports it (§5)
-  2. installs the user D-Bus activation file in
-     `$XDG_DATA_HOME/dbus-1/services/`, which takes precedence over
-     gnome-keyring's system file
-  3. masks gnome-keyring's user units
-  4. backs up and edits PAM (below)
-  5. imports gnome-keyring items while gnome-keyring still runs
-
-  It detects SDDM autologin and configures first-use mode instead of login
-  unlock.
-- `aleph setup --revert`:
-  1. exports every aleph item created or modified since setup into
-     gnome-keyring, through its Secret Service API after restarting it
-  2. verifies the export
-  3. only then restores the backed-up PAM files and units
-
-  If the export fails, revert stops and nothing changes.
+- Runs as a systemd user service `alephd.service` (`BusName=io.aleph.Keyring`),
+  with `alephd.socket` owning `$XDG_RUNTIME_DIR/aleph/pam.sock` (mode
+  `0600`). It is started by D-Bus activation for `org.freedesktop.secrets`
+  or `io.aleph.Keyring`, or by socket activation from PAM.
+- **The Secret Service name is queued for, never taken** (DECISIONS.md
+  E1): alephd owns `io.aleph.Keyring` and requests
+  `org.freedesktop.secrets` without `ReplaceExisting` or
+  `AllowReplacement`, so while gnome-keyring runs alephd waits in the
+  queue, and the bus hands the name over the moment gnome-keyring lets go
+  (the name is never unowned). `aleph status` says who serves it. After
+  setup switched over, a queued alephd logs a warning.
+- `aleph setup` (Arch/Omarchy), each step checking the real state, so a
+  re-run does only what is still undone (E10):
+  1. reports the TPM (§5) and detects SDDM autologin (E5: advisory; it
+     picks the default unlock method and the summary)
+  2. creates the vault (§7), if there is none
+  3. imports gnome-keyring's items while it still serves the Secret
+     Service, and keeps following it until the name changes hands (E1,
+     E2)
+  4. switches over, user-level only (E9): D-Bus activation files in
+     `$XDG_DATA_HOME/dbus-1/services/` (the Secret Service name starts
+     alephd; `org.gnome.keyring` and `org.freedesktop.impl.portal.Secret`
+     start nothing), a bus `ReloadConfig`, gnome-keyring's user units
+     recorded (once), masked, and stopped, then the name's owner checked.
+     gnome-keyring's pkcs11 component goes away with it.
+  5. installs Omarchy's lock hook (G1), and offers to set the TPM's
+     lockoutAuth (D9)
+  6. last and optional, the root side through sudo: `sudo aleph system
+     apply --user <you>` (below); declined or failed, setup says how to
+     run it later
+- `aleph setup --revert` (E3), refused if gnome-keyring is not installed:
+  1. lists items imported from gnome-keyring and deleted in aleph since,
+     offering to delete them there too
+  2. with the login password, alephd pauses writes and runs its own
+     gnome-keyring on a private bus over the keyring files (after checking
+     that none serves the session), writes every item missing there or
+     different (collections it lacks go into its default collection), and
+     reads each back on a fresh connection
+  3. only then: the activation files removed (if still aleph's) and the
+     bus reloaded; gnome-keyring's units unmasked and restored as
+     recorded; the Omarchy hook removed; alephd lets go of the name, which
+     the bus hands to gnome-keyring
+  4. last, `sudo aleph system revert`
+
+  If the export fails, nothing changes and writes resume. The aleph vault
+  is left in place.
 
 ### PAM integration
 
@@ -709,8 +733,8 @@
   -password  optional  pam_aleph.so
   ```
 
-- **Which services get them**, with setup editing each and keeping a
-  backup (Plan 4c; by hand until then, `docs/testing.md`):
+- **Which services get them**, edited by `sudo aleph system apply` (E4),
+  each keeping an `.aleph-orig` backup:
 
   | Service | Change |
   |---|---|
@@ -794,9 +818,10 @@
   whether MK is `mlock`ed, TPM usability, keyslots with stale marks),
   `Lock`, `Unlock`, `Create`, `EnrollTpm`, `EnrollFido2`,
   `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`, `RetryKeyslot`,
-  `GetConfig`, `SetConfig`, (Plan 4b) `Backup`, `Recover`,
-  `RestoreBackup`, `RestoreFromBak`, `AcceptRollback`, and (Plan 4c)
-  `ImportGnomeKeyring`, `ExportToGnomeKeyring`.
+  `GetConfig`, `SetConfig`, `Backup`, `Recover`, `RestoreBackup`,
+  `RestoreFromBak`, `AcceptRollback`, `ImportGnomeKeyring`,
+  `RemovedSinceImport`, `ExportToGnomeKeyring`, `ReleaseSecretService`,
+  `ThawWrites`. `Status` also names who owns `org.freedesktop.secrets`.
 - **Methods that need the user take a prompter:** one end of a
   socketpair, passed as a Unix fd, speaking the prompter protocol. The
   CLI answers it in the terminal, `aleph-gui` in its windows. The call
@@ -900,7 +925,7 @@
 aleph delete attr=val…
 aleph ls [collection]
 aleph import gnome-keyring
-aleph export gnome-keyring
+sudo aleph system apply --user <you> | verify --user <you> | revert
 aleph config get|set <key> [value]
 aleph backup [--force] <path>
 aleph restore [--from-bak | --accept-rollback] [<path>]
@@ -918,11 +943,27 @@
   5. live import from gnome-keyring
   6. system changes (sudo)
 
-  Plan 3 implements steps 1, 2, and 4 (creating the vault) and says that
-  the rest is not available yet; Plan 4c adds 3, 5, and 6.
+  Export to gnome-keyring happens only as part of `setup --revert`.
 - **Import** reads every collection and item through the Secret Service
-  API while gnome-keyring still owns the bus name. That covers everything
-  shown in Seahorse's Passwords view.
+  API while gnome-keyring still owns the bus name, over an encrypted
+  session (alephd reads them itself; secrets never pass through the CLI).
+  That covers everything shown in Seahorse's Passwords view. It needs the
+  vault unlocked; locked gnome-keyring collections ask through
+  gnome-keyring's own prompt, and are skipped (with a message) if it is
+  dismissed. It is idempotent and never overwrites (E2); what it added is
+  recorded in `$XDG_STATE_HOME/aleph/imported.json` for revert.
+- **`sudo aleph system apply --user <you>`** edits the PAM services above
+  as pure text transformations, atomically, refusing symlinks, files that
+  are not regular, and files not owned by root (manual mode: it prints
+  what to add; E6), then authenticates `<you>` through the edited
+  lock-screen and login stacks with real Linux-PAM, the password asked
+  once; a failure restores the originals at once. What it did is recorded
+  in `/var/lib/aleph/manifest.json`. `revert` restores each file byte for
+  byte if it is still what `apply` wrote, else takes aleph's lines out if
+  that applies cleanly, else leaves it and says what to remove. It reads
+  no user configuration or D-Bus, and warns if its own binary is not
+  root-owned and root-only-writable. On NixOS it prints the configuration
+  to add instead.
 - **`aleph backup <path>`** writes a re-headered copy containing **only
   the recovery slot**, with its MK wrap. It also warns that generic backups
   of `~/.local/share/aleph/` contain every slot, including
--- a/docs/testing.md
+++ b/docs/testing.md
@@ -127,29 +127,29 @@
    stored for the user ("Store the password only for this user"), lock,
    reconnect, and unlock when asked: the connection must come up without
    asking for the Wi-Fi password again.
-6. **Login and screen unlock** (Plan 4a; setup's PAM edits come in 4c, so
-   by hand for now, keeping backups):
-   - `install -Dm755 target/debug/libpam_aleph.so /usr/lib/security/pam_aleph.so`
-   - `/etc/pam.d/sddm`: `-auth optional pam_aleph.so` after `auth include
-     system-login`, and `-session optional pam_aleph.so` after `session
-     include system-login` (remove the `pam_gnome_keyring` lines)
-   - `/etc/pam.d/omarchy-lock-password`: `-auth optional pam_aleph.so` at
-     the end
-   - `/etc/pam.d/passwd`: `-password optional pam_aleph.so` after `password
-     include system-auth`
-   - Never edit `system-login`, `system-auth`, or `login`: a TTY login is
-     the way back in if something goes wrong (keep a root shell open while
-     editing, and try the lock screen before walking away)
-   - `systemctl --user enable --now alephd.socket` (with the units under
-     `~/.config/systemd/user/`)
-
-   Then: log out and in (the vault is unlocked at login, no prompt); lock
-   the screen with a locker that calls `loginctl lock-session` (not
-   Omarchy's own lock, which does not yet reach alephd; `aleph lock` stands
-   in for it) and check `aleph status` says locked, then unlock the screen
-   (unlocked, with no prompt); `passwd`
-   (the TPM slot's id changes; with a FIDO2 slot, `aleph status` asks for
-   `aleph keyslot rotate-master`); suspend and resume (locked).
+6. **Setup and login unlock** (Plan 4c), on a test account with
+   gnome-keyring running and a few items in it (Seahorse):
+   - `aleph setup`: it reports the TPM, creates the keyring, imports the
+     items (`secret-tool lookup` finds them through aleph), switches over
+     (`aleph status` says alephd serves the Secret Service;
+     `systemctl --user is-enabled gnome-keyring-daemon.socket` says
+     masked), and offers the root step: answer yes, and `sudo` runs
+     `aleph system apply`, which asks the login password once and checks
+     the lock screen and the login with it.
+   - Keep a root shell open until the lock screen has been tried: a TTY
+     login is the way back in (`system-login`, `system-auth`, and `login`
+     are never edited).
+   - Log out and in (the vault is unlocked at login, no prompt); lock the
+     screen, then unlock it (unlocked, no prompt); `passwd` (the TPM
+     slot's id changes); suspend and resume (locked). With Omarchy's lock,
+     the vault locks with the screen only once Omarchy runs
+     `omarchy-hook lock` (DECISIONS.md G1); until then idle and sleep lock
+     it.
+   - `aleph setup` again changes nothing.
+   - `aleph setup --revert`: it asks the login password, copies
+     everything back, and gnome-keyring serves the Secret Service again
+     (with the items stored in aleph meanwhile); `sudo aleph system
+     revert` restores the PAM files byte for byte.
 7. `aleph status` shows the keyslots; `journalctl --user` (or the
    terminal) shows no secrets.
 8. **Backup and restore** (Plan 4b):
@@ -176,3 +176,22 @@
 
 Record the results, and the libsecret, Chromium, and NetworkManager
 versions, in `hardware-log.md`.
+
+## Emergency manual revert
+
+If login or the lock screen misbehaves after `sudo aleph system apply`,
+from a TTY (Ctrl-Alt-F3) or a root shell:
+
+1. `sudo aleph system revert`; or by hand, for each of `sddm`,
+   `sddm-autologin`, `omarchy-lock-password`, and `passwd` in
+   `/etc/pam.d/`: `mv <name>.aleph-orig <name>` (a missing backup means
+   the file was never changed), then `rm /var/lib/aleph/manifest.json`.
+2. As the user: `rm ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
+   ~/.local/share/dbus-1/services/org.gnome.keyring.service
+   ~/.local/share/dbus-1/services/org.freedesktop.impl.portal.Secret.service`,
+   then `systemctl --user unmask gnome-keyring-daemon.service
+   gnome-keyring-daemon.socket` and `systemctl --user start
+   gnome-keyring-daemon.socket`.
+3. Items stored in aleph since setup stay in its vault
+   (`~/.local/share/aleph`); `aleph setup --revert` copies them back once
+   alephd runs again (`aleph restore` if the vault itself needs recovery).
~~~~

- [ ] **Step 2: Run the tests, clippy, and fmt**

Run: `cargo test -q && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 16 passed | ok. 12 passed | ok. 59 passed | ok. 1 passed | ok. 29 passed | ok. 11 passed | ok. 1 passed | ok. 37 passed | ok. 3 passed | ok. 30 passed | ok. 8 passed | ok. 51 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed | ok. 3 passed | ok. 3 passed | ok. 6 passed | ok. 5 passed | ok. 21 passed | ok. 5 passed | ok. 1 passed | ok. 1 passed | ok. 2 passed | ok. 23 passed | ok. 9 passed | ok. 7 passed | ok. 6 passed | ok. 3 passed | ok. 1 passed.

- [ ] **Step 3: Commit**

```bash
git add docs README.md DECISIONS.md
git commit -m "docs: spec, testing, README, and decisions for setup" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 6: the pre-execution review's fixes

**Interfaces:**
- Consumes: Tasks 1–5 (DECISIONS.md G3 has the findings this task answers).
- Produces: `system::apply_checked(&Root, &str, &str, impl Fn(&Root, &str, &str) -> Result<()>) -> Result<Report>`; `wizard::lockout_matches(&str, &str) -> bool`; `import::merge_following(&mut Body, Vec<FetchedCollection>, &mut Summary, &HashSet<Uuid>)`, `Summary::updated`; `export::PRIVATE_BUS_CONFIG`; Admin `ClaimSecretService() -> b`; `switchover::{Record::revert_phase, SWITCHED_BACK}`

- [ ] **Step 1: Write the failing tests**

Apply this patch with `git apply` (save it as `/tmp/t6-tests.patch`):

```diff
--- a/crates/aleph-cli/src/system.rs
+++ b/crates/aleph-cli/src/system.rs
@@ -756,6 +756,105 @@
             assert!(!root.backup(service).exists());
         }
         assert!(!root.manifest_path().exists());
+    }
+
+    /// One service that cannot be transformed (its anchor is gone) is left
+    /// for the user; the others are still applied and recorded, so revert
+    /// undoes them.
+    #[test]
+    fn a_service_without_its_anchor_is_manual_and_the_rest_recorded() {
+        let (_dir, root) = tree();
+        std::fs::write(
+            root.pam_dir.join("passwd"),
+            "#%PAM-1.0\npassword required pam_unix.so\n",
+        )
+        .unwrap();
+        let report = apply(&root).unwrap();
+        assert_eq!(report.changed.len(), 3);
+        assert!(
+            report.manual.iter().any(|m| m.contains("passwd")),
+            "{:?}",
+            report.manual
+        );
+        revert(&root).unwrap();
+        for service in [Service::Sddm, Service::SddmAutologin, Service::LockPassword] {
+            assert_eq!(
+                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
+                fixture("omarchy", service.file())
+            );
+        }
+    }
+
+    /// A crash after the files were written but before the manifest: a
+    /// re-run trusts the backup (the original), and revert restores it.
+    #[test]
+    fn a_crash_before_the_manifest_keeps_the_original() {
+        let (_dir, root) = tree();
+        apply(&root).unwrap();
+        std::fs::remove_file(root.manifest_path()).unwrap();
+        apply(&root).unwrap();
+        revert(&root).unwrap();
+        for service in Service::ALL {
+            assert_eq!(
+                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
+                fixture("omarchy", service.file()),
+                "{service:?}"
+            );
+        }
+    }
+
+    /// A backup left from long ago (no manifest entry) is not trusted: the
+    /// backup is the file as it is now.
+    #[test]
+    fn a_stale_backup_is_replaced_by_the_current_file() {
+        let (_dir, root) = tree();
+        let passwd = root.pam_dir.join("passwd");
+        std::fs::write(root.backup(Service::Passwd), "#%PAM-1.0\nold\n").unwrap();
+        let mut current = fixture("omarchy", "passwd");
+        current.push_str("auth required pam_u2f.so\n");
+        std::fs::write(&passwd, &current).unwrap();
+        apply(&root).unwrap();
+        revert(&root).unwrap();
+        assert_eq!(std::fs::read_to_string(&passwd).unwrap(), current);
+    }
+
+    /// A file revert leaves alone loses its backup too (it is stale now).
+    #[test]
+    fn a_file_left_alone_by_revert_loses_its_backup() {
+        let (_dir, root) = tree();
+        apply(&root).unwrap();
+        let sddm = root.pam_dir.join("sddm");
+        std::fs::write(
+            &sddm,
+            "#%PAM-1.0\nauth required pam_deny.so\n-auth      optional  pam_aleph.so\n",
+        )
+        .unwrap();
+        revert(&root).unwrap();
+        assert!(!root.backup(Service::Sddm).exists());
+    }
+
+    /// The check runs whenever something is recorded (a re-run after an
+    /// interrupted check too), and a failure puts every recorded file back.
+    #[test]
+    fn a_checked_apply_rolls_back_on_failure_even_on_a_rerun() {
+        let (_dir, root) = tree();
+        let fail = |_: &Root, _: &str, _: &str| -> Result<()> { Err("no".into()) };
+        let pass = |_: &Root, _: &str, _: &str| -> Result<()> { Ok(()) };
+        // First run: applied, then the check is interrupted (not run).
+        apply(&root).unwrap();
+        let err = apply_checked(&root, "u", "pw", fail).unwrap_err();
+        assert!(err.contains("undone"), "{err}");
+        for service in Service::ALL {
+            assert_eq!(
+                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
+                fixture("omarchy", service.file())
+            );
+        }
+        apply_checked(&root, "u", "pw", pass).unwrap();
+        assert_eq!(
+            std::fs::read_to_string(root.pam_dir.join("passwd")).unwrap(),
+            fixture("omarchy-applied", "passwd")
+        );
     }
 
     /// A symlinked service is left for the user, with the lines to add.
--- a/crates/aleph-cli/src/wizard.rs
+++ b/crates/aleph-cli/src/wizard.rs
@@ -220,6 +220,14 @@
     }
 
     #[test]
+    fn a_lockout_value_matches_however_it_is_typed() {
+        let v = "ABCD-EFGH-2345";
+        assert!(lockout_matches(v, "abcd efgh 2345"));
+        assert!(lockout_matches(v, "ABCDEFGH2345"));
+        assert!(!lockout_matches(v, "ABCDEFGH2346"));
+    }
+
+    #[test]
     fn a_lockout_value_is_32_base32_characters_in_groups() {
         let v = lockout_value().unwrap();
         assert_eq!(v.len(), 39);
--- a/crates/aleph-cli/tests/cli.rs
+++ b/crates/aleph-cli/tests/cli.rs
@@ -8,9 +8,20 @@
 
 fn aleph(d: &Daemon, args: &[&str]) -> Command {
     // Never the real home, user manager, or sudo: setup writes activation
-    // files, runs systemctl (`false`: no unit exists, and any change
+    // files, runs systemctl (a stand-in: no unit exists, and any change
     // fails), and offers the root side through sudo (`false`: it fails).
     let home = d.env.paths.data_dir.parent().unwrap().join("home");
+    let systemctl = home.join("systemctl");
+    if !systemctl.exists() {
+        use std::os::unix::fs::PermissionsExt;
+        std::fs::create_dir_all(&home).unwrap();
+        std::fs::write(
+            &systemctl,
+            "#!/bin/sh\ncase \"$2\" in\n  is-enabled) echo not-found ;;\n  is-active) echo inactive ;;\n  *) exit 1 ;;\nesac\n",
+        )
+        .unwrap();
+        std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755)).unwrap();
+    }
     let mut cmd = Command::new(env!("CARGO_BIN_EXE_aleph"));
     cmd.args(args)
         .env("DBUS_SESSION_BUS_ADDRESS", &d.bus.address)
@@ -18,7 +29,7 @@
         .env("XDG_DATA_HOME", home.join("data"))
         .env("XDG_STATE_HOME", home.join("state"))
         .env("XDG_CONFIG_HOME", home.join("config"))
-        .env("ALEPH_SYSTEMCTL", "false")
+        .env("ALEPH_SYSTEMCTL", &systemctl)
         .env("ALEPH_SUDO", "false")
         .env("ALEPH_NO_TTY", "1")
         .stdin(Stdio::piped())
@@ -418,3 +429,57 @@
         .unwrap();
     assert_eq!(found.len(), 1);
 }
+
+/// A revert that stopped after switching back (a Ctrl-C, a failed
+/// release) resumes at the release on a re-run: no second export.
+#[tokio::test(flavor = "multi_thread")]
+async fn a_revert_rerun_after_switching_back_goes_straight_to_the_release() {
+    let d = daemon(true, vec![]).await;
+    let home = d.env.paths.data_dir.parent().unwrap().join("home");
+    std::fs::create_dir_all(home.join("state/aleph")).unwrap();
+    std::fs::write(
+        home.join("state/aleph/setup.json"),
+        r#"{"units":{},"revert_phase":"switched-back"}"#,
+    )
+    .unwrap();
+    let (ok, _, err) = run(&d, &["setup", "--revert"], "").await;
+    assert!(ok, "{err}");
+    assert!(!err.contains("Copied"), "{err}");
+    assert!(
+        err.contains("gnome-keyring serves the Secret Service again"),
+        "{err}"
+    );
+}
+
+/// A gnome-keyring collection that stayed locked stops setup before the
+/// switchover (its items would be out of reach afterwards), unless the
+/// user says to go on.
+#[tokio::test(flavor = "multi_thread")]
+async fn skipped_collections_stop_setup_before_the_switchover() {
+    let bus = bus();
+    let gk = GnomeKeyring::start(&bus, "login password");
+    gk.store("Mail", &[("service", "mail")], "s3cret");
+    let c = zbus::connection::Builder::address(bus.address.as_str())
+        .unwrap()
+        .build()
+        .await
+        .unwrap();
+    c.call_method(
+        Some("org.freedesktop.secrets"),
+        "/org/freedesktop/secrets",
+        Some("org.freedesktop.Secret.Service"),
+        "Lock",
+        &(vec![
+            zbus::zvariant::ObjectPath::try_from("/org/freedesktop/secrets/collection/login")
+                .unwrap(),
+        ],),
+    )
+    .await
+    .unwrap();
+    let d = daemon_on(bus, true).await;
+    let (ok, _, err) = run(&d, &["setup"], "").await;
+    assert!(ok, "{err}");
+    assert!(err.contains("Not imported"), "{err}");
+    assert!(!err.contains("alephd serves the Secret Service"), "{err}");
+    drop(gk);
+}
--- a/crates/aleph-daemon/tests/gnome_keyring.rs
+++ b/crates/aleph-daemon/tests/gnome_keyring.rs
@@ -400,3 +400,102 @@
         "alephd"
     );
 }
+
+/// An item imported, deleted in aleph, and stored again (same label and
+/// attributes) is not deleted from gnome-keyring by revert; its new secret
+/// is what gnome-keyring ends up with.
+#[tokio::test(flavor = "multi_thread")]
+async fn revert_never_deletes_what_aleph_still_holds() {
+    let bus = bus();
+    let address = bus.address.clone();
+    let gk = GnomeKeyring::start(&bus, "login password");
+    gk.store("Mail", &[("k", "mail")], "old");
+    let d = daemon_on(bus, true).await;
+    let c = client(&address).await;
+    admin(&c, "ImportGnomeKeyring").await.unwrap();
+    d.keyring
+        .modify(|b| {
+            for col in &mut b.collections {
+                col.items.retain(|i| i.label != "Mail");
+            }
+            Ok(())
+        })
+        .unwrap();
+    add(&d, None, "Mail", &[("k", "mail")], "new");
+    let body = d.keyring.read(|b| b.clone()).unwrap();
+    let delete = aleph_daemon::import::removed_since(
+        &aleph_daemon::import::load_imported(&d.env.paths.imported()),
+        &body,
+    );
+    assert_eq!(delete.len(), 1);
+    let report = aleph_daemon::export::export(&c, &address, &body, &delete)
+        .await
+        .unwrap();
+    assert_eq!(report.deleted, 0);
+    assert_eq!(found(&c, &[("k", "mail")]).await, 1);
+    // (The secret there is the new one: export verified it.)
+    assert_eq!(report.exported, 1);
+}
+
+/// An item in gnome-keyring with the same attributes but another label is
+/// a different item: export adds aleph's beside it, never over it.
+#[tokio::test(flavor = "multi_thread")]
+async fn export_does_not_replace_an_item_with_another_label() {
+    let bus = bus();
+    let address = bus.address.clone();
+    let gk = GnomeKeyring::start(&bus, "login password");
+    gk.store("Theirs", &[("k", "same")], "theirs");
+    let d = daemon_on(bus, true).await;
+    let c = client(&address).await;
+    add(&d, None, "Ours", &[("k", "same")], "ours");
+    let body = d.keyring.read(|b| b.clone()).unwrap();
+    aleph_daemon::export::export(&c, &address, &body, &[])
+        .await
+        .unwrap();
+    assert_eq!(found(&c, &[("k", "same")]).await, 2);
+}
+
+/// A secret gnome-keyring changes after the import (a token refresh) is
+/// followed into aleph, for the items the import brought.
+#[tokio::test(flavor = "multi_thread")]
+async fn an_update_in_gnome_keyring_is_followed() {
+    let bus = bus();
+    let address = bus.address.clone();
+    let gk = GnomeKeyring::start(&bus, "login password");
+    gk.store("Token", &[("k", "token")], "v1");
+    let d = daemon_on(bus, true).await;
+    let c = client(&address).await;
+    admin(&c, "ImportGnomeKeyring").await.unwrap();
+    gk.store("Token", &[("k", "token")], "v2");
+    eventually("the updated secret", async || {
+        items_labelled(&d, "Token")
+            .first()
+            .is_some_and(|(_, _, s)| s == b"v2")
+    })
+    .await;
+    assert_eq!(items_labelled(&d, "Token").len(), 1);
+}
+
+/// `ClaimSecretService` queues for the name (setup calls it once its
+/// activation file is in place).
+#[tokio::test(flavor = "multi_thread")]
+async fn claiming_the_name_queues_behind_gnome_keyring() {
+    let bus = bus();
+    let address = bus.address.clone();
+    let _gk = GnomeKeyring::start(&bus, "login password");
+    let d = daemon_on(bus, true).await;
+    let c = client(&address).await;
+    c.call_method(
+        Some(aleph_daemon::admin::BUS_NAME),
+        aleph_daemon::admin::ADMIN_PATH,
+        Some("io.aleph.Admin1"),
+        "ClaimSecretService",
+        &(),
+    )
+    .await
+    .unwrap();
+    assert_eq!(
+        aleph_daemon::daemon::secret_service_owner(&d.conn).await,
+        "another program"
+    );
+}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon -p aleph-cli`
Expected: the build fails: `apply_checked` and `lockout_matches` do not exist yet (and the new export, follow, revert, and setup tests would fail).

- [ ] **Step 3: Implement**

Apply this patch with `git apply` (save it as `/tmp/t6-impl.patch`):

```diff
--- a/DECISIONS.md
+++ b/DECISIONS.md
@@ -8,6 +8,56 @@
 made directly are marked as such.
 
 ## 2026-09-27: Plan 4c (setup), design
+
+### G3. The pre-execution review of the Plan 4c document: fixes adopted
+
+No path was found where the PAM edits make a correct password fail or a
+wrong one pass. The safety net around them, and revert, had gaps; each
+fixed with a test that failed first:
+- **A service that cannot be transformed** stopped `apply` part way, with
+  edits unrecorded. Every transformation is computed first (a missing
+  anchor is manual mode), and each manifest entry is saved before its
+  file is replaced.
+- **A crash before the manifest** lost the original on a re-run; a re-run
+  now trusts the backup. **A stale backup** (no manifest entry) could
+  later bring back an old file; it is rewritten from the current file,
+  and revert drops the backup of a file it leaves alone.
+- **An interrupted password prompt skipped the check for good.** The
+  password is asked before anything changes, and the check runs whenever
+  anything is recorded; a failure rolls back everything recorded.
+- **Revert deleted items aleph still held** (deleted and stored again), or
+  let gnome-keyring's replace (attributes only) take an item with another
+  label. Deletions come first and skip what aleph holds; a differing item
+  is updated in place; new items never replace.
+- **A revert that stopped after switching back got stuck** with writes
+  paused; it records its phase and resumes at the release, and writes
+  resume on every failure.
+- **alephd could take the Secret Service back after a revert** (started by
+  `pam.sock` with `pam_aleph` still in place): it claims the name only
+  while setup's activation file exists; setup asks it to claim once it
+  has written the file (`ClaimSecretService`).
+- **Skipping the root step** leaves sddm's `pam_gnome_keyring auto_start`,
+  which can start gnome-keyring behind alephd: setup says so, and the
+  hardware checklist checks it.
+- **A locked gnome-keyring collection** would be stranded by the
+  switchover: setup stops before it unless the user says to go on.
+
+Minor fixes adopted: gnome-keyring's updates to imported items are
+followed until the switchover; item signals are taken before the name
+change; the write freeze is checked under the keyring's lock; a failing
+`systemctl` is an error, never a recorded "not-found" (the CLI tests use
+a stand-in script); private and test buses have no service directories
+(no real prompter can start); sudo is `/usr/bin/sudo`, and the
+user-writable-binary warning comes before it; revert unlocks a locked
+vault first; the lockout value may be typed without dashes; the emergency
+manual revert no longer claims a missing backup means an unchanged file,
+and reloads the bus.
+
+Rulings on the rest: revert says what to remove rather than showing a
+diff (E4's "diff"); on NixOS the user-level unit masking still happens
+(it works there; E6 said it would be skipped); the lock screen, which
+runs as the user, is checked by hand (the root-side check runs as root).
+
 
 ### G2. Calls made while prototyping Plan 4c
 
--- a/crates/aleph-cli/src/main.rs
+++ b/crates/aleph-cli/src/main.rs
@@ -239,7 +239,21 @@
             if c.status().await?.locked {
                 outcome(c.converse("Unlock", Args::None).await?)?;
             }
-            eprintln!("aleph: {}", c.import_gnome_keyring().await?);
+            let summary = c.import_gnome_keyring().await?;
+            eprintln!("aleph: {summary}");
+            if summary.contains("Not imported:") {
+                let mut term = prompter::Terminal::new();
+                let answer = ask(
+                    &mut term,
+                    "Those collections stay in gnome-keyring, out of reach once aleph takes over (until `aleph setup --revert`). Take over anyway? [y/N] ",
+                )?;
+                if !matches!(answer.trim(), "y" | "Y" | "yes") {
+                    eprintln!(
+                        "aleph: stopped before taking over: unlock them in gnome-keyring (Seahorse), then run `aleph setup` again"
+                    );
+                    return Ok(ExitCode::SUCCESS);
+                }
+            }
             let dirs = switchover::Dirs::from_env()?;
             let mut record = switchover::Record::load(&dirs)?;
             for step in
@@ -269,9 +283,11 @@
             if matches!(answer.trim(), "" | "y" | "Y" | "yes") {
                 if let Err(e) = wizard::run_as_root(&apply) {
                     eprintln!("aleph: {e}; run `sudo aleph system apply --user {user}` later");
+                    eprintln!("aleph: {ROOT_STEP_PENDING}");
                 }
             } else {
                 eprintln!("aleph: later: `sudo aleph system apply --user {user}`");
+                eprintln!("aleph: {ROOT_STEP_PENDING}");
             }
             eprintln!("aleph: setup is done (`aleph status` shows the keyring)");
         }
@@ -506,6 +522,9 @@
     Ok(())
 }
 
+/// What stays until the root step runs.
+const ROOT_STEP_PENDING: &str = "until then, logging in does not unlock the keyring, and the login's PAM service can still start gnome-keyring behind aleph";
+
 /// `aleph system ...`, as root (DECISIONS.md E4–E6).
 fn run_system(action: SystemCmd) -> Result<()> {
     if unsafe { libc::geteuid() } != 0 {
@@ -527,25 +546,17 @@
                 );
                 return Ok(());
             }
-            let report = system::apply(&root)?;
-            for m in &report.manual {
-                eprintln!("aleph: by hand: {m}");
-            }
-            if report.changed.is_empty() {
-                eprintln!("aleph: the PAM services were already set up");
-                return Ok(());
-            }
+            // Asked before anything changes: nothing is ever left edited
+            // and unchecked.
             let password = zeroize::Zeroizing::new(
                 rpassword::prompt_password(format!(
                     "Login password for {user} (checks the login and lock screen once): "
                 ))
                 .map_err(|e| e.to_string())?,
             );
-            if let Err(e) = system::verify(&root, &user, &password) {
-                system::roll_back(&root, &report.changed)?;
-                return Err(format!(
-                    "the check failed ({e}); the PAM changes were undone"
-                ));
+            let report = system::apply_checked(&root, &user, &password, system::verify)?;
+            for m in &report.manual {
+                eprintln!("aleph: by hand: {m}");
             }
             eprintln!("aleph: login and screen unlock now reach aleph");
         }
@@ -578,38 +589,63 @@
                 .into(),
         );
     }
-    let removed = c.removed_since_import().await?;
-    let mut delete = false;
-    if !removed.is_empty() {
-        eprintln!(
-            "aleph: imported from gnome-keyring and deleted in aleph since: {}",
-            removed.join(", ")
-        );
-        let mut term = prompter::Terminal::new();
-        let answer = ask(&mut term, "Delete them from gnome-keyring too? [y/N] ")?;
-        delete = matches!(answer.trim(), "y" | "Y" | "yes");
-    }
-    outcome(
-        c.converse("ExportToGnomeKeyring", Args::Bool(delete))
-            .await?,
-    )?;
+    if c.status().await?.locked {
+        outcome(c.converse("Unlock", Args::None).await?)?;
+    }
     let dirs = switchover::Dirs::from_env()?;
     let mut record = switchover::Record::load(&dirs)?;
-    let steps =
-        match switchover::switch_back(c.bus(), &switchover::Systemctl, &dirs, &mut record).await {
+    // A revert that stopped after switching back resumes at the release
+    // (gnome-keyring runs by then, and a second export would be refused).
+    if record.revert_phase.as_deref() != Some(switchover::SWITCHED_BACK) {
+        let removed = c.removed_since_import().await?;
+        let mut delete = false;
+        if !removed.is_empty() {
+            eprintln!(
+                "aleph: imported from gnome-keyring and deleted in aleph since: {}",
+                removed.join(", ")
+            );
+            let mut term = prompter::Terminal::new();
+            let answer = ask(&mut term, "Delete them from gnome-keyring too? [y/N] ")?;
+            delete = matches!(answer.trim(), "y" | "Y" | "yes");
+        }
+        outcome(
+            c.converse("ExportToGnomeKeyring", Args::Bool(delete))
+                .await?,
+        )?;
+        let steps = match switchover::switch_back(
+            c.bus(),
+            &switchover::Systemctl,
+            &dirs,
+            &mut record,
+        )
+        .await
+        {
             Ok(steps) => steps,
             Err(e) => {
                 let _ = c.thaw_writes().await;
                 return Err(e);
             }
         };
-    for step in steps {
-        eprintln!("aleph: {step}");
-    }
-    if let Some(hook) = wizard::remove_omarchy_hook(&dirs.config_home)? {
-        eprintln!("aleph: removed {}", hook.display());
-    }
-    c.release_secret_service().await?;
+        for step in steps {
+            eprintln!("aleph: {step}");
+        }
+        record.revert_phase = Some(switchover::SWITCHED_BACK.into());
+        if let Err(e) = record.save(&dirs) {
+            let _ = c.thaw_writes().await;
+            return Err(e);
+        }
+    }
+    match wizard::remove_omarchy_hook(&dirs.config_home) {
+        Ok(Some(hook)) => eprintln!("aleph: removed {}", hook.display()),
+        Ok(None) => {}
+        Err(e) => eprintln!("aleph: {e}"),
+    }
+    if let Err(e) = c.release_secret_service().await {
+        let _ = c.thaw_writes().await;
+        return Err(e);
+    }
+    record.revert_phase = None;
+    record.save(&dirs)?;
     eprintln!(
         "aleph: gnome-keyring serves the Secret Service again; the aleph vault is left in place"
     );
@@ -643,7 +679,7 @@
         value.as_str()
     );
     let typed = zeroize::Zeroizing::new(term_line(term, "Type it back to confirm: ")?);
-    if typed.trim().to_uppercase() != value.as_str() {
+    if !wizard::lockout_matches(&value, &typed) {
         eprintln!(
             "aleph: that does not match; the lockout password was not set (later: {command})"
         );
--- a/crates/aleph-cli/src/switchover.rs
+++ b/crates/aleph-cli/src/switchover.rs
@@ -66,13 +66,24 @@
         std::env::var_os("ALEPH_SYSTEMCTL").unwrap_or_else(|| "systemctl".into())
     }
 
+    /// A query's answer. (`is-enabled` and `is-active` exit non-zero for
+    /// "disabled" or "inactive": their output is what counts; no output is
+    /// a failure, never a state to record.)
     fn run(args: &[&str]) -> Result<String> {
         let out = std::process::Command::new(Self::program())
             .arg("--user")
             .args(args)
             .output()
             .map_err(|e| format!("systemctl: {e}"))?;
-        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
+        let answer = String::from_utf8_lossy(&out.stdout).trim().to_string();
+        if answer.is_empty() {
+            return Err(format!(
+                "systemctl --user {}: {}",
+                args.join(" "),
+                String::from_utf8_lossy(&out.stderr).trim()
+            ));
+        }
+        Ok(answer)
     }
 
     fn checked(args: &[&str]) -> Result<()> {
@@ -95,17 +106,9 @@
 
 impl Units for Systemctl {
     fn state(&self, unit: &str) -> Result<UnitState> {
-        // (Both commands exit non-zero for "disabled" or "inactive": their
-        // output is what counts.)
-        let enabled = Self::run(&["is-enabled", unit])?;
-        let active = Self::run(&["is-active", unit])? == "active";
         Ok(UnitState {
-            enabled: if enabled.is_empty() {
-                "not-found".into()
-            } else {
-                enabled
-            },
-            active,
+            enabled: Self::run(&["is-enabled", unit])?,
+            active: Self::run(&["is-active", unit])? == "active",
         })
     }
 
@@ -174,7 +177,14 @@
     /// gnome-keyring's units as they were before setup first changed them.
     #[serde(default)]
     pub units: BTreeMap<String, UnitState>,
-}
+    /// How far an unfinished revert got ([`SWITCHED_BACK`]: only the
+    /// release is left).
+    #[serde(default, skip_serializing_if = "Option::is_none")]
+    pub revert_phase: Option<String>,
+}
+
+/// A revert's phase once gnome-keyring's routes are restored.
+pub const SWITCHED_BACK: &str = "switched-back";
 
 impl Record {
     pub fn load(dirs: &Dirs) -> Result<Self> {
@@ -243,6 +253,17 @@
             services.display()
         ));
     }
+    // The running alephd queues for the name now (it claims it at start
+    // only while this activation file exists).
+    bus.call_method(
+        Some(ALEPH_NAME),
+        "/io/aleph/Admin",
+        Some("io.aleph.Admin1"),
+        "ClaimSecretService",
+        &(),
+    )
+    .await
+    .map_err(|e| format!("asking alephd to queue for the Secret Service: {e}"))?;
     let mut states = Vec::new();
     for unit in GNOME_UNITS {
         states.push((unit, units.state(unit)?));
--- a/crates/aleph-cli/src/system.rs
+++ b/crates/aleph-cli/src/system.rs
@@ -320,6 +320,9 @@
 pub fn apply(root: &Root) -> Result<Report> {
     let mut manifest = Manifest::load(root)?;
     let mut report = Report::default();
+    // Every transformation first: a service that cannot be transformed (its
+    // anchor gone) is left for the user, and nothing half-done is written.
+    let mut plans = Vec::new();
     for service in Service::ALL {
         let path = root.pam_dir.join(service.file());
         if !path.exists() && std::fs::symlink_metadata(&path).is_err() {
@@ -331,46 +334,99 @@
                 .push(format!("{why}: {}", manual_lines(service)));
             continue;
         }
-        let original =
+        let current =
             std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
-        let edit = transform(service, &original)?;
-        if edit.text == original {
-            // (Already applied, by an earlier run or by hand: recorded so
-            // revert can take the lines out again.)
-            manifest
-                .files
-                .entry(service.file().to_string())
-                .or_insert(Applied {
-                    applied: original,
-                    removed: Vec::new(),
-                    backup: false,
-                });
+        match transform(service, &current) {
+            Ok(edit) => plans.push((service, path, current, edit)),
+            Err(e) => report.manual.push(e),
+        }
+    }
+    for (service, path, current, edit) in plans {
+        let name = service.file().to_string();
+        let backup = root.backup(service);
+        let known = manifest.files.get(&name).cloned();
+        if edit.text == current {
+            // Already applied: by an earlier run, by a run cut short before
+            // its manifest (then the backup holds the original), or by hand.
+            if known.is_none() {
+                let (has_backup, removed) = match std::fs::read_to_string(&backup) {
+                    Ok(original) => (
+                        true,
+                        transform(service, &original)
+                            .map(|e| e.removed)
+                            .unwrap_or_default(),
+                    ),
+                    Err(_) => (false, Vec::new()),
+                };
+                manifest.files.insert(
+                    name,
+                    Applied {
+                        applied: current,
+                        removed,
+                        backup: has_backup,
+                    },
+                );
+                manifest.save(root)?;
+            }
             continue;
         }
         let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
         let mode = meta.mode() & 0o7777;
         let owner = Some((meta.uid(), meta.gid()));
-        let backup = root.backup(service);
-        if !backup.exists() {
-            write_atomic(&backup, original.as_bytes(), mode, owner)?;
-        }
-        write_atomic(&path, edit.text.as_bytes(), mode, owner)?;
-        let removed = match manifest.files.get(service.file()) {
+        // With no record of this file, a backup lying there is stale: the
+        // backup is the file as it is now.
+        if known.is_none() || !backup.exists() {
+            write_atomic(&backup, current.as_bytes(), mode, owner)?;
+        }
+        let removed = match known {
             // (A re-run keeps what the first run removed.)
-            Some(prev) if edit.removed.is_empty() => prev.removed.clone(),
+            Some(prev) if edit.removed.is_empty() => prev.removed,
             _ => edit.removed,
         };
+        // Recorded before the file is replaced: a crash in between leaves a
+        // record revert can work from.
         manifest.files.insert(
-            service.file().to_string(),
+            name,
             Applied {
-                applied: edit.text,
+                applied: edit.text.clone(),
                 removed,
                 backup: true,
             },
         );
+        manifest.save(root)?;
+        write_atomic(&path, edit.text.as_bytes(), mode, owner)?;
         report.changed.push(service);
     }
-    manifest.save(root)?;
+    Ok(report)
+}
+
+/// Apply, then check the login and lock screen with `check` (real
+/// Linux-PAM: [`verify`]) whenever anything is recorded, a re-run after an
+/// interrupted check included; a failure puts every recorded file back from
+/// its backup.
+pub fn apply_checked(
+    root: &Root,
+    user: &str,
+    password: &str,
+    check: impl Fn(&Root, &str, &str) -> Result<()>,
+) -> Result<Report> {
+    let report = apply(root)?;
+    let manifest = Manifest::load(root)?;
+    if manifest.files.is_empty() {
+        return Ok(report);
+    }
+    if let Err(e) = check(root, user, password) {
+        let recorded: Vec<Service> = manifest
+            .files
+            .iter()
+            .filter(|(_, a)| a.backup)
+            .filter_map(|(name, _)| Service::from_file(name))
+            .collect();
+        roll_back(root, &recorded)?;
+        return Err(format!(
+            "the check failed ({e}); the PAM changes were undone"
+        ));
+    }
     Ok(report)
 }
 
@@ -443,6 +499,9 @@
                 path.display()
             ));
         } else {
+            // (Its backup is stale now: a later apply must not bring it
+            // back.)
+            let _ = std::fs::remove_file(&backup);
             done.push(format!(
                 "{}: changed since setup and left alone; {}",
                 path.display(),
--- a/crates/aleph-cli/src/wizard.rs
+++ b/crates/aleph-cli/src/wizard.rs
@@ -103,12 +103,16 @@
 /// The program that runs the root side (`sudo`; `ALEPH_SUDO` names another,
 /// for tests, which must never run the real one).
 fn sudo() -> std::ffi::OsString {
-    std::env::var_os("ALEPH_SUDO").unwrap_or_else(|| "sudo".into())
+    std::env::var_os("ALEPH_SUDO").unwrap_or_else(|| "/usr/bin/sudo".into())
 }
 
 /// Run `args` as root through sudo, on the terminal (sudo asks for the
 /// password there).
 pub fn run_as_root(args: &[&str]) -> Result<()> {
+    // Before sudo: running a user-writable binary as root trusts its writer.
+    if let Some(w) = crate::system::writable_binary_warning() {
+        eprintln!("aleph: {w}");
+    }
     let status = std::process::Command::new(sudo())
         .args(args)
         .status()
@@ -138,6 +142,17 @@
         .map(|c| c.iter().collect::<String>())
         .collect::<Vec<_>>()
         .join("-"))
+}
+
+/// Whether `typed` is the lockout value, however it was grouped or cased.
+pub fn lockout_matches(value: &str, typed: &str) -> bool {
+    let norm = |s: &str| {
+        s.chars()
+            .filter(|c| !c.is_whitespace() && *c != '-')
+            .map(|c| c.to_ascii_uppercase())
+            .collect::<String>()
+    };
+    !typed.trim().is_empty() && norm(value) == norm(typed)
 }
 
 /// The command that sets lockoutAuth, reading the value on standard input
--- a/crates/aleph-daemon/src/admin.rs
+++ b/crates/aleph-daemon/src/admin.rs
@@ -242,6 +242,17 @@
         })
     }
 
+    /// Queue for `org.freedesktop.secrets` (setup calls it once its
+    /// activation file is in place). Returns whether alephd owns it now.
+    async fn claim_secret_service(
+        &self,
+        #[zbus(connection)] conn: &zbus::Connection,
+    ) -> zbus::fdo::Result<bool> {
+        crate::daemon::request_secrets_name(conn)
+            .await
+            .map_err(failed)
+    }
+
     /// Let go of `org.freedesktop.secrets` (the end of a revert: the bus
     /// hands it to gnome-keyring, queued behind).
     async fn release_secret_service(
--- a/crates/aleph-daemon/src/export.rs
+++ b/crates/aleph-daemon/src/export.rs
@@ -54,6 +54,22 @@
         || owner(SECRETS_NAME).await.is_some_and(|o| Some(o) != me)
 }
 
+/// A private session bus's configuration: no service directories, so
+/// nothing (a prompter, a second gnome-keyring) is ever started on it.
+pub const PRIVATE_BUS_CONFIG: &str = r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
+ "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
+<busconfig>
+  <type>session</type>
+  <listen>unix:tmpdir=/tmp</listen>
+  <auth>EXTERNAL</auth>
+  <policy context="default">
+    <allow send_destination="*" eavesdrop="true"/>
+    <allow eavesdrop="true"/>
+    <allow own="*"/>
+  </policy>
+</busconfig>
+"#;
+
 /// A gnome-keyring (secrets component) alephd runs itself on a private
 /// bus, over the keyring files in `data_home`; killed on drop.
 pub struct Private {
@@ -74,8 +90,11 @@
         std::fs::create_dir_all(&run).map_err(gk)?;
         std::fs::set_permissions(&run, std::os::unix::fs::PermissionsExt::from_mode(0o700))
             .map_err(gk)?;
+        let config = dirs.path().join("bus.conf");
+        std::fs::write(&config, PRIVATE_BUS_CONFIG).map_err(gk)?;
         let mut bus = std::process::Command::new("dbus-daemon")
-            .args(["--session", "--nofork", "--nopidfile", "--print-address=1"])
+            .arg(format!("--config-file={}", config.display()))
+            .args(["--nofork", "--nopidfile", "--print-address=1"])
             .stdout(std::process::Stdio::piped())
             .stderr(std::process::Stdio::null())
             .spawn()
@@ -316,6 +335,37 @@
         }
     };
     let mut report = Report::default();
+    // Deletions first, and never of an item aleph still holds (one deleted
+    // and stored again with the same label and attributes).
+    let held = |label: &str, attributes: &BTreeMap<String, String>| {
+        body.collections.iter().any(|c| {
+            c.items
+                .iter()
+                .any(|i| i.label == label && i.attributes == *attributes)
+        })
+    };
+    for d in delete {
+        if held(&d.label, &d.attributes) {
+            continue;
+        }
+        let target = if d.is_default {
+            default.clone()
+        } else {
+            by_label
+                .get(&d.collection)
+                .cloned()
+                .unwrap_or(default.clone())
+        };
+        for (path, _) in remote.find(&target, &d.attributes, &d.label).await? {
+            let _: OwnedObjectPath = remote
+                .proxy(path.as_str(), ITEM)
+                .await?
+                .call("Delete", &())
+                .await
+                .map_err(gk)?;
+            report.deleted += 1;
+        }
+    }
     let mut written = Vec::new();
     for collection in &body.collections {
         for item in &collection.items {
@@ -323,6 +373,28 @@
             let found = remote.find(&target, &item.attributes, &item.label).await?;
             if found.iter().any(|(_, s)| s == item.secret.expose()) {
                 report.unchanged += 1;
+                continue;
+            }
+            // The same item there with another secret: updated in place
+            // (gnome-keyring's own replace matches attributes only, and
+            // would take an item with another label).
+            if let Some((path, _)) = found.first() {
+                let (parameters, value) =
+                    remote.session.encrypt(item.secret.expose()).map_err(gk)?;
+                let secret = (
+                    remote.session_path.clone(),
+                    parameters,
+                    value,
+                    item.content_type.clone(),
+                );
+                remote
+                    .proxy(path.as_str(), ITEM)
+                    .await?
+                    .call_method("SetSecret", &(secret,))
+                    .await
+                    .map_err(gk)?;
+                report.exported += 1;
+                written.push((target, item));
                 continue;
             }
             let (parameters, value) = remote.session.encrypt(item.secret.expose()).map_err(gk)?;
@@ -350,7 +422,7 @@
             let (_, prompt): (OwnedObjectPath, OwnedObjectPath) = remote
                 .proxy(target.as_str(), COLLECTION)
                 .await?
-                .call("CreateItem", &(properties, secret, true))
+                .call("CreateItem", &(properties, secret, false))
                 .await
                 .map_err(gk)?;
             if prompt.as_str() != "/" {
@@ -358,25 +430,6 @@
             }
             report.exported += 1;
             written.push((target, item));
-        }
-    }
-    for d in delete {
-        let target = if d.is_default {
-            default.clone()
-        } else {
-            by_label
-                .get(&d.collection)
-                .cloned()
-                .unwrap_or(default.clone())
-        };
-        for (path, _) in remote.find(&target, &d.attributes, &d.label).await? {
-            let _: OwnedObjectPath = remote
-                .proxy(path.as_str(), ITEM)
-                .await?
-                .call("Delete", &())
-                .await
-                .map_err(gk)?;
-            report.deleted += 1;
         }
     }
     // Read everything written back, on a fresh connection and session.
@@ -390,7 +443,7 @@
         let found = check.find(&target, &item.attributes, &item.label).await?;
         if !found.iter().any(|(_, s)| s == item.secret.expose()) {
             return Err(Error::Invalid(format!(
-                "copying to gnome-keyring could not be verified ({}); nothing else was changed",
+                "copying to gnome-keyring could not be verified ({}); the session was not handed over",
                 item.label
             )));
         }
--- a/crates/aleph-daemon/src/import.rs
+++ b/crates/aleph-daemon/src/import.rs
@@ -117,6 +117,8 @@
 pub struct Summary {
     pub imported: usize,
     pub unchanged: usize,
+    /// Imported items gnome-keyring changed since (followed).
+    pub updated: usize,
     /// Items skipped because a different secret is already here.
     pub conflicts: Vec<String>,
     /// Collections skipped, with the reason.
@@ -146,8 +148,23 @@
     }
 }
 
+/// An item already in the target collection: id, label, attributes, secret.
+type Before = (uuid::Uuid, String, BTreeMap<String, String>, Vec<u8>);
+
 /// Merge `fetched` into `body` (see the module comment for the rules).
 pub fn merge(body: &mut Body, fetched: Vec<FetchedCollection>, summary: &mut Summary) {
+    merge_following(body, fetched, summary, &std::collections::HashSet::new());
+}
+
+/// `merge`, where a different secret for an item in `updatable` (one the
+/// import brought, followed until the switchover) updates it instead of
+/// being a conflict: gnome-keyring still owns it then.
+pub fn merge_following(
+    body: &mut Body,
+    fetched: Vec<FetchedCollection>,
+    summary: &mut Summary,
+    updatable: &std::collections::HashSet<uuid::Uuid>,
+) {
     for collection in fetched {
         let target = if collection.is_default {
             body.resolve_alias(aleph_core::model::DEFAULT_ALIAS)
@@ -169,11 +186,12 @@
         };
         let target = body.collection_mut(id).expect("just found or created");
         // Only what was here before this merge counts.
-        let before: Vec<(String, BTreeMap<String, String>, Vec<u8>)> = target
+        let before: Vec<Before> = target
             .items
             .iter()
             .map(|i| {
                 (
+                    i.id,
                     i.label.clone(),
                     i.attributes.clone(),
                     i.secret.expose().to_vec(),
@@ -183,10 +201,19 @@
         for f in collection.items {
             let same: Vec<_> = before
                 .iter()
-                .filter(|(l, a, _)| *l == f.label && *a == f.attributes)
+                .filter(|(_, l, a, _)| *l == f.label && *a == f.attributes)
                 .collect();
-            if same.iter().any(|(_, _, s)| s == f.secret.expose()) {
+            if same.iter().any(|(_, _, _, s)| s == f.secret.expose()) {
                 summary.unchanged += 1;
+                continue;
+            }
+            if let Some((id, ..)) = same.iter().find(|(id, ..)| updatable.contains(id))
+                && let Some(item) = target.items.iter_mut().find(|i| i.id == *id)
+            {
+                item.secret = f.secret;
+                item.content_type = f.content_type;
+                item.modified = f.modified.max(aleph_core::model::now());
+                summary.updated += 1;
                 continue;
             }
             if !same.is_empty() {
@@ -378,13 +405,16 @@
         };
         let mut labels: HashMap<String, (String, bool)> = HashMap::new();
         loop {
+            // (Item signals first: one sent just before gnome-keyring let
+            // go is still taken.)
             let msg = tokio::select! {
-                _ = owner_changes.next() => return,
+                biased;
                 msg = self.events.next() => match msg {
                     Some(Ok(msg)) => msg,
                     Some(Err(_)) => continue,
                     None => return,
                 },
+                _ = owner_changes.next() => return,
             };
             let header = msg.header();
             let member = header.member().map(|m| m.as_str().to_string());
@@ -433,10 +463,12 @@
         let (label, is_default) = labels[collection].clone();
         let items = self.fetch_items(&[item]).await?;
         let keyring = keyring.clone();
+        let updatable: std::collections::HashSet<uuid::Uuid> =
+            load_imported(record).into_iter().map(|i| i.id).collect();
         let summary = tokio::task::spawn_blocking(move || {
             keyring.modify(|body| {
                 let mut summary = Summary::default();
-                merge(
+                merge_following(
                     body,
                     vec![FetchedCollection {
                         label,
@@ -444,6 +476,7 @@
                         items,
                     }],
                     &mut summary,
+                    &updatable,
                 );
                 Ok(summary)
             })
--- a/crates/aleph-daemon/src/keyring.rs
+++ b/crates/aleph-daemon/src/keyring.rs
@@ -296,10 +296,11 @@
     /// Change the body and write the vault. If `f` or the write fails, the
     /// in-memory body is restored, so memory never runs ahead of the file.
     pub fn modify<T>(&self, f: impl FnOnce(&mut Body) -> Result<T>) -> Result<T> {
+        let mut inner = lock(&self.inner);
+        // (Under the lock: no write slips past an export's snapshot.)
         if self.frozen.load(std::sync::atomic::Ordering::SeqCst) {
             return Err(Error::Frozen);
         }
-        let mut inner = lock(&self.inner);
         *lock(&self.last_access) = Instant::now();
         let Inner {
             store,
@@ -396,9 +397,14 @@
                 return Err(Error::Locked);
             }
             let password = self.ask_password(chan)?;
-            self.frozen.store(true, std::sync::atomic::Ordering::SeqCst);
-            let result = self
-                .read(|b| b.clone())
+            // The freeze and the snapshot under one lock.
+            let body = {
+                let inner = lock(&self.inner);
+                self.frozen.store(true, std::sync::atomic::Ordering::SeqCst);
+                inner.vault.as_ref().map(|v| v.body().clone())
+            };
+            let result = body
+                .ok_or(Error::Locked)
                 .and_then(|body| run(&password, body));
             if result.is_err() {
                 self.thaw();
--- a/crates/aleph-daemon/src/main.rs
+++ b/crates/aleph-daemon/src/main.rs
@@ -61,8 +61,22 @@
         aleph_daemon::daemon::serve(&conn, keyring.clone(), launcher, config.clone(), paths)
             .await
             .map_err(|e| e.to_string())?;
-    // Queued behind gnome-keyring until it lets go (DECISIONS.md E1).
-    match aleph_daemon::daemon::request_secrets_name(&conn).await {
+    // Queued behind gnome-keyring until it lets go (DECISIONS.md E1), and
+    // only while setup's activation file is in place: before setup (which
+    // claims it through the admin interface) and after a revert, the
+    // Secret Service is gnome-keyring's.
+    let claim = activation.as_ref().is_some_and(|a| a.exists());
+    if !claim {
+        tracing::info!(
+            "serving {BUS_NAME}; not claiming {SECRETS_NAME} (aleph setup has not switched over)"
+        );
+    }
+    match if claim {
+        aleph_daemon::daemon::request_secrets_name(&conn).await
+    } else {
+        Ok(true)
+    } {
+        Ok(true) if !claim => {}
         Ok(true) => tracing::info!("serving {SECRETS_NAME} and {BUS_NAME}"),
         // After setup switched over, nothing else should hold it.
         Ok(false) if activation.as_ref().is_some_and(|a| a.exists()) => {
--- a/crates/aleph-daemon/src/testing.rs
+++ b/crates/aleph-daemon/src/testing.rs
@@ -308,6 +308,7 @@
 pub struct Bus {
     child: std::process::Child,
     pub address: String,
+    _config: tempfile::TempDir,
 }
 
 impl Drop for Bus {
@@ -318,8 +319,14 @@
 }
 
 pub fn bus() -> Bus {
+    // (No service directories: nothing, a real prompter included, is ever
+    // started on a test bus.)
+    let dir = tempfile::tempdir().unwrap();
+    let config = dir.path().join("bus.conf");
+    std::fs::write(&config, crate::export::PRIVATE_BUS_CONFIG).unwrap();
     let mut child = std::process::Command::new("dbus-daemon")
-        .args(["--session", "--nofork", "--nopidfile", "--print-address=1"])
+        .arg(format!("--config-file={}", config.display()))
+        .args(["--nofork", "--nopidfile", "--print-address=1"])
         .stdout(std::process::Stdio::piped())
         .stderr(std::process::Stdio::null())
         .spawn()
@@ -333,6 +340,7 @@
     Bus {
         child,
         address: line.trim().to_string(),
+        _config: dir,
     }
 }
 
--- a/docs/superpowers/specs/2026-09-26-aleph-design.md
+++ b/docs/superpowers/specs/2026-09-26-aleph-design.md
@@ -680,8 +680,12 @@
   `org.freedesktop.secrets` without `ReplaceExisting` or
   `AllowReplacement`, so while gnome-keyring runs alephd waits in the
   queue, and the bus hands the name over the moment gnome-keyring lets go
-  (the name is never unowned). `aleph status` says who serves it. After
-  setup switched over, a queued alephd logs a warning.
+  (the name is never unowned). alephd claims it only while setup's
+  activation file exists (setup asks the running alephd to claim it once
+  it has written that file): before setup, and after a revert, the Secret
+  Service stays gnome-keyring's even if `pam.sock` starts alephd.
+  `aleph status` says who serves it. After setup switched over, a queued
+  alephd logs a warning.
 - `aleph setup` (Arch/Omarchy), each step checking the real state, so a
   re-run does only what is still undone (E10):
   1. reports the TPM (§5) and detects SDDM autologin (E5: advisory; it
@@ -700,7 +704,12 @@
      lockoutAuth (D9)
   6. last and optional, the root side through sudo: `sudo aleph system
      apply --user <you>` (below); declined or failed, setup says how to
-     run it later
+     run it later, and that until then logging in does not unlock the
+     keyring and the login's PAM service can still start gnome-keyring
+
+  A gnome-keyring collection that stayed locked (its unlock dismissed)
+  stops setup before step 4, unless the user says to go on: its items
+  would be out of reach once aleph takes over.
 - `aleph setup --revert` (E3), refused if gnome-keyring is not installed:
   1. lists items imported from gnome-keyring and deleted in aleph since,
      offering to delete them there too
@@ -715,8 +724,11 @@
      the bus hands to gnome-keyring
   4. last, `sudo aleph system revert`
 
-  If the export fails, nothing changes and writes resume. The aleph vault
-  is left in place.
+  If the export fails, nothing changes and writes resume. A revert that
+  stops after step 3's switch back resumes at the release on a re-run.
+  Items deleted in aleph since the import are deleted in gnome-keyring
+  only if aleph holds no item with the same label and attributes (one
+  deleted and stored again). The aleph vault is left in place.
 
 ### PAM integration
 
@@ -958,9 +970,14 @@
   what to add; E6), then authenticates `<you>` through the edited
   lock-screen and login stacks with real Linux-PAM, the password asked
   once; a failure restores the originals at once. What it did is recorded
-  in `/var/lib/aleph/manifest.json`. `revert` restores each file byte for
-  byte if it is still what `apply` wrote, else takes aleph's lines out if
-  that applies cleanly, else leaves it and says what to remove. It reads
+  in `/var/lib/aleph/manifest.json`, each entry saved before its file is
+  replaced. The login password is asked before anything changes, and the
+  check runs whenever anything is recorded (a re-run after an interrupted
+  check too). `revert` restores each file byte for byte if it is still
+  what `apply` wrote, else takes aleph's lines out if that applies
+  cleanly, else leaves it (dropping its backup) and says what to remove.
+  A backup without a manifest entry is not trusted: it is rewritten from
+  the file as it is. It reads
   no user configuration or D-Bus, and warns if its own binary is not
   root-owned and root-only-writable. On NixOS it prints the configuration
   to add instead.
--- a/docs/testing.md
+++ b/docs/testing.md
@@ -146,6 +146,13 @@
      `omarchy-hook lock` (DECISIONS.md G1); until then idle and sleep lock
      it.
    - `aleph setup` again changes nothing.
+   - If the root step was skipped: log out and in, and check that no
+     `gnome-keyring-daemon` runs (`pgrep -a gnome-keyring`) and that
+     `aleph status` still says alephd serves the Secret Service (sddm's
+     `pam_gnome_keyring auto_start` can start one).
+   - `sudo aleph system apply` runs the login password through the login
+     and lock-screen stacks as root: after it, check the lock screen
+     itself (it runs as you) before walking away.
    - `aleph setup --revert`: it asks the login password, copies
      everything back, and gnome-keyring serves the Secret Service again
      (with the items stored in aleph meanwhile); `sudo aleph system
@@ -184,12 +191,17 @@
 
 1. `sudo aleph system revert`; or by hand, for each of `sddm`,
    `sddm-autologin`, `omarchy-lock-password`, and `passwd` in
-   `/etc/pam.d/`: `mv <name>.aleph-orig <name>` (a missing backup means
-   the file was never changed), then `rm /var/lib/aleph/manifest.json`.
+   `/etc/pam.d/`: `mv <name>.aleph-orig <name>` where a backup exists;
+   where none does, take out the `pam_aleph` lines by hand (and, in `sddm`
+   and `sddm-autologin`, put back the `pam_gnome_keyring` lines). Then
+   `rm /var/lib/aleph/manifest.json`.
 2. As the user: `rm ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
    ~/.local/share/dbus-1/services/org.gnome.keyring.service
    ~/.local/share/dbus-1/services/org.freedesktop.impl.portal.Secret.service`,
-   then `systemctl --user unmask gnome-keyring-daemon.service
+   `busctl --user call org.freedesktop.DBus /org/freedesktop/DBus
+   org.freedesktop.DBus ReloadConfig` (dbus-broker does not notice
+   removed activation files by itself), then `systemctl --user unmask
+   gnome-keyring-daemon.service
    gnome-keyring-daemon.socket` and `systemctl --user start
    gnome-keyring-daemon.socket`.
 3. Items stored in aleph since setup stay in its vault
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected (one entry per test binary, in cargo's order): ok. 22 passed | ok. 14 passed | ok. 59 passed | ok. 1 passed | ok. 29 passed | ok. 11 passed | ok. 1 passed | ok. 37 passed | ok. 3 passed | ok. 30 passed | ok. 12 passed | ok. 51 passed | ok. 1 passed | ok. 5 passed | ok. 2 passed | ok. 9 passed | ok. 17 passed | ok. 3 passed | ok. 3 passed | ok. 6 passed | ok. 5 passed | ok. 21 passed | ok. 5 passed | ok. 1 passed | ok. 1 passed | ok. 2 passed | ok. 23 passed | ok. 9 passed | ok. 7 passed | ok. 6 passed | ok. 3 passed | ok. 1 passed.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL (a hang counts: stop it after a few minutes), then undo the change, `touch` the file, and see the test pass again:

- **an item already here is unchanged** (`crates/aleph-daemon/src/import.rs`), test `cargo test -p aleph-daemon --lib import_is_idempotent`: replace `if same.iter().any(|(_, _, _, s)| s == f.secret.expose()) {` with `if false {`.
- **a service without its anchor is manual** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph a_service_without_its_anchor`:

  replace

  ```rust
  Err(e) => report.manual.push(e),
  }
  ```

  with

  ```rust
  Err(e) => return Err(e),
  }
  ```

- **a re-run trusts the backup** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph a_crash_before_the_manifest`: replace `let (has_backup, removed) = match std::fs::read_to_string(&backup) {` with `let (has_backup, removed) = match std::fs::read_to_string("/nonexistent/aleph") {`.
- **a stale backup is rewritten** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph a_stale_backup_is_replaced`: replace `if known.is_none() || !backup.exists() {` with `if !backup.exists() {`.
- **a file left alone loses its backup** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph a_file_left_alone_by_revert`:

  replace

  ```rust
  let _ = std::fs::remove_file(&backup);
  done.push(format!(
      "{}: changed since setup and left alone
  ```

  with

  ```rust
  done.push(format!(
  "{}: changed since setup and left alone
  ```

- **a failed check rolls back everything recorded** (`crates/aleph-cli/src/system.rs`), test `cargo test -p aleph-cli --bin aleph a_checked_apply_rolls_back`: replace `roll_back(root, &recorded)?;` with `roll_back(root, &report.changed)?;`.
- **the lockout value may be typed any way** (`crates/aleph-cli/src/wizard.rs`), test `cargo test -p aleph-cli --bin aleph a_lockout_value_matches`: replace `.filter(|c| !c.is_whitespace() && *c != '-')` with `.filter(|_| true)`.
- **revert never deletes what aleph holds** (`crates/aleph-daemon/src/export.rs`), test `cargo test -p aleph-daemon --test gnome_keyring revert_never_deletes_what_aleph_still_holds`: replace `if held(&d.label, &d.attributes) {` with `if false {`.
- **export never replaces another item** (`crates/aleph-daemon/src/export.rs`), test `cargo test -p aleph-daemon --test gnome_keyring export_does_not_replace_an_item_with_another_label`: replace `.call("CreateItem", &(properties, secret, false))` with `.call("CreateItem", &(properties, secret, true))`.
- **gnome-keyring's updates are followed** (`crates/aleph-daemon/src/import.rs`), test `cargo test -p aleph-daemon --test gnome_keyring an_update_in_gnome_keyring_is_followed`: replace `.find(|(id, ..)| updatable.contains(id))` with `.find(|_| false)`.
- **a revert resumes at the release** (`crates/aleph-cli/src/main.rs`), test `cargo test -p aleph-cli --test cli a_revert_rerun_after_switching_back`: replace `if record.revert_phase.as_deref() != Some(switchover::SWITCHED_BACK) {` with `if true {`.
- **skipped collections stop setup** (`crates/aleph-cli/src/main.rs`), test `cargo test -p aleph-cli --test cli skipped_collections_stop_setup`: replace `if summary.contains("Not imported:") {` with `if false {`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-daemon crates/aleph-cli docs DECISIONS.md
git commit -m "fix: the pre-execution review's findings for setup" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```
