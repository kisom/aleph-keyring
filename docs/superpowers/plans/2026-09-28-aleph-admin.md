# aleph manager admin page (Plan 5d) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The manager's `ADMIN` page: alephd's status and keyslots, and, each with alephd's own re-authentication, adding a TPM or security-key slot, removing or retrying a slot, rotating the master key, issuing a new recovery key, and writing a backup through the XDG portal's save dialog.

**Architecture:** No alephd change: every method exists. `aleph-gui` gains store requests (`Status` and one per operation), an `admin_page.rs` (model and drawing, like `settings_page.rs`), a `filepicker.rs` (`FilePicker` trait, the `rfd` portal implementation, a fake), and a `task.rs`. In `manager.rs`, `pending`, `saving_settings` and `save_after_unlock` fold into one state machine (`running` and `waiting`, over `Running` and `Job`) that the reveal guard, the settings Save and the admin operations share: the unlock-first step, the embedded confirmation, the interruption wording, and what runs on finish.

**Tech Stack:** Rust 2024, zbus, egui/eframe 0.36, egui_kittest (window tests and PNG snapshots), `rfd` (XDG-portal backend, new), serde_json, tempfile (tests).

**Spec:** `docs/superpowers/specs/2026-09-28-aleph-admin-design.md` (read it first). Extends `docs/superpowers/specs/2026-09-28-aleph-settings-design.md` (Plan 5c: the Save flow this plan generalizes) and `docs/superpowers/specs/2026-09-28-aleph-manager-design.md`.

## Global Constraints

- Rebase and fast-forward only; never a merge commit. Do not push: the owner confirms pushes.
- Commit trailer, on every commit: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (use the trailer the session's system reminder gives if it differs). Commit messages go on the command line in **single** quotes (`-m '...'`, no apostrophes): AGENTS.md rule 7.
- AGENTS.md: no piping or heredocs into an interpreter, no nested quoting; edit files with the editor tools.
- Tests never reach the real system: no `systemctl`, `sudo`, `/etc/pam.d`, the real keyring, the real alephd, the real display, the session bus, the clipboard, **or the real XDG portal** (tests use the fake `FilePicker`; the real one is exercised only by the owner's manual check). `gui.toml` and backup files are only ever written under `tempfile` directories in tests.
- aleph is live on this host: do not restart alephd, reinstall, or edit live units. The owner runs `make install`; you never run `sudo`.
- Build in the worktree's own `target/`; never put a `CARGO_TARGET_DIR` under `/tmp` (disk quota). After removing a worktree that shares a target, `cargo clean -p <pkg>` for each workspace package.
- Keep the FIDO2 PIN out of every command, file and message.
- **The behaviour the Plan 5c tests pin does not change** (Task 2 is a refactor: every existing test passes untouched, snapshots included).
- Copy rules (verbatim):
  - the sealed banner above the page's actions: `VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST`
  - REMOVE asks: `Remove keyslot '<label>'? This rotates the master key. The key can no longer unlock the vault.`
  - NEW RECOVERY KEY asks: `The current recovery key stops working as soon as the new one is issued.`
  - Status texts on success: `KEYSLOT ADDED`, `KEYSLOT REMOVED`, `MASTER KEY ROTATED`, `NEW RECOVERY KEY ISSUED`, `BACKED UP :: <path> (it opens only with your recovery key)`
  - the STATUS header is `STATUS  // alephd`; the section headers are `KEYSLOTS` and `KEEPING IT SAFE`
  - the touch-alone warning: `anyone holding the key can unlock`
  - warnings: `writes refused: <reason>; see alephctl restore --accept-rollback`, `a password change is pending: rotate the master key`
- Restore, recover, `--from-bak` and `--accept-rollback` are NOT in the manager (they stay in `alephctl restore`).
- Backup files: created with create-new and mode `0600`, never overwritten; an existing non-empty file is refused with "choose a new name"; the manager removes a file it created if it is still empty when the operation ends by any route.
- Logs name operations only: no slot labels, no paths, no keys. The manager never holds, copies or clipboards the recovery key.
- Code style: match the surrounding code (parenthesised asides in comments, `//!` module docs that cite the spec, no `unwrap` outside tests). `make gate` (fmt, clippy `-D warnings`, the full suite) must pass at the end of every task that says so.

## Review Focus

Each line has a test in the task named after it.

1. **A backup file left behind or destroyed**: a cancelled, refused, interrupted or failed backup must leave no empty file the manager created; a pre-existing non-empty file must be neither overwritten nor removed; a pre-existing empty file that is used must not be deleted afterwards if it was not created by the manager. (Task 6)
2. **The portal is missing versus the dialog cancelled**: no owner for `org.freedesktop.portal.Desktop` means the typed-path field, a closed dialog with an owner means nothing happens; a path inside aleph's own directory is refused by alephd and shows its reason. (Tasks 1, 6)
3. **The refactor's regressions**: a reveal, a settings save, an interrupted save, a dismissed unlock, a save after focus loss: all as before. (Task 2, by the existing tests; plus new unit tests on the wording)
4. **Two operations at once**: pressing another action while one waits for the unlock or runs must start nothing, and a dismissed unlock must run nothing (and a later unlock by something else must not resume it). (Task 5)
5. **A stale slot list**: after every operation, including a refused or interrupted one, and after a lock, an unlock or the link returning, STATUS is read again, so a removed slot is gone and a pending rotation shows. (Task 5)

---

## File Structure

- Create `crates/aleph-gui/src/task.rs`: `Want`, `Job`, `AdminOp`, `Running`, `BackupTarget` and the wording each kind uses. No egui, no store.
- Create `crates/aleph-gui/src/filepicker.rs`: `FilePicker`, `Pick`, `Portal` (real), `portal_present`, and the test fake.
- Create `crates/aleph-gui/src/admin_page.rs`: `AdminState`, `Ask`, `Link`, the pure status text, and the drawing of the page, the Yes/No steps and the typed-path field.
- Modify `crates/aleph-gui/src/store.rs`: `AdminStatus`, `SlotInfo`, the new requests and `StoreEvent::Status`.
- Modify `crates/aleph-gui/src/manager.rs`: the state-machine refactor, `Page::Admin`, the wiring. It should end no more than modestly longer.
- Modify `crates/aleph-gui/src/lib.rs`, `crates/aleph-gui/Cargo.toml` (and the workspace `Cargo.toml` if it lists dependencies), `crates/aleph-gui/src/main.rs` (unchanged unless the picker needs wiring).
- Tests: `crates/aleph-gui/tests/store.rs`, `tests/manager.rs`, new `tests/filepicker.rs`.
- Docs: `docs/testing.md`, `DECISIONS.md`, the main spec (§7's Admin bullet), the manager spec (the table row), the admin spec status.

---

### Task 1: The `rfd` dependency spike and the `FilePicker`

**Files:**
- Modify: `crates/aleph-gui/Cargo.toml` (and workspace `Cargo.toml` if dependencies are listed there)
- Create: `crates/aleph-gui/src/filepicker.rs`
- Modify: `crates/aleph-gui/src/lib.rs` (`pub mod filepicker;`)
- Test: `crates/aleph-gui/tests/filepicker.rs`

**Interfaces:**
- Consumes: zbus (already a dependency), the aleph-daemon test harness (`aleph_daemon::testing::bus`).
- Produces:
  - `pub enum Pick { Unavailable, Cancelled, Chosen(PathBuf) }`
  - `pub trait FilePicker { fn start(&self, suggested: String, dir: Option<PathBuf>) -> std::sync::mpsc::Receiver<Pick>; }` (the dialog runs elsewhere; the window polls the receiver each frame).
  - `pub struct Portal;` (`FilePicker`; the real `rfd` XDG-portal dialog on its own thread, `Unavailable` when no portal owns its bus name).
  - `pub async fn portal_present(address: Option<&str>) -> bool` (whether `org.freedesktop.portal.Desktop` has an owner on the given bus address, else the session bus).
  - `pub struct Fixed(pub Vec<Pick>)`-style fake: `pub struct Fake { picks: std::sync::Mutex<Vec<Pick>>, pub asked: std::sync::Mutex<Vec<(String, Option<PathBuf>)>> }` with `Fake::new(picks: Vec<Pick>)`; `start` pops the next pick (or `Cancelled` if none) into an already-filled receiver and records what was asked.

- [ ] **Step 1: Add the dependency and read what it costs (the spike)**

In `crates/aleph-gui/Cargo.toml`, `[dependencies]`:

```toml
rfd = { version = "0.15", default-features = false, features = ["xdg-portal", "tokio"] }
```

(Use the newest `rfd` that resolves; if 0.15 does not, take the current release and note the version in the report. If the workspace keeps versions in `[workspace.dependencies]`, follow that pattern.) Then run:

```
cargo tree -p aleph-gui -i zbus
cargo tree -p aleph-gui -d
cargo tree -p aleph-gui -i async-std
cargo tree -p aleph-gui -i gtk
```

Expected: one zbus version (the workspace's), no `async-std`, no `gtk`/`glib`. **If a second zbus major version appears, or `async-std`, `gtk` or `glib` is pulled in, do not go further: write what you found (the commands and their output) into the report and stop with status `NEEDS_CONTEXT`.** The controller rules on the feature set (for example `default-features = false` with only `xdg-portal` and `tokio`, or a different `ashpd` pin) and records it as a `Ruling:`. A second copy of `tokio` with the same major version is fine. Also record `cargo build -p aleph-gui` time and that it still builds.

- [ ] **Step 2: Write the failing tests**

Create `crates/aleph-gui/tests/filepicker.rs`:

```rust
//! The file picker: whether the portal is there is decided by its bus
//! name's owner (`rfd` cannot tell "no portal" from "cancelled"), and the
//! fake the window tests use.

use std::path::PathBuf;

use aleph_gui::filepicker::{Fake, FilePicker, Pick, portal_present};

#[tokio::test(flavor = "multi_thread")]
async fn the_portal_is_present_only_when_its_name_has_an_owner() {
    let bus = aleph_daemon::testing::bus();
    assert!(!portal_present(Some(&bus.address)).await);
    let _owner = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.portal.Desktop")
        .unwrap()
        .build()
        .await
        .unwrap();
    assert!(portal_present(Some(&bus.address)).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_bus_at_all_is_no_portal() {
    assert!(!portal_present(Some("unix:path=/nonexistent/aleph-test-bus")).await);
}

#[test]
fn the_fake_answers_in_order_and_remembers_what_was_asked() {
    let fake = Fake::new(vec![
        Pick::Chosen(PathBuf::from("/tmp/x.aleph")),
        Pick::Cancelled,
    ]);
    let rx = fake.start("a.aleph".into(), Some(PathBuf::from("/home/u")));
    assert_eq!(rx.recv().unwrap(), Pick::Chosen(PathBuf::from("/tmp/x.aleph")));
    assert_eq!(fake.start("b.aleph".into(), None).recv().unwrap(), Pick::Cancelled);
    // (Nothing left: a cancel.)
    assert_eq!(fake.start("c.aleph".into(), None).recv().unwrap(), Pick::Cancelled);
    assert_eq!(
        fake.asked.lock().unwrap().clone(),
        vec![
            ("a.aleph".to_string(), Some(PathBuf::from("/home/u"))),
            ("b.aleph".to_string(), None),
            ("c.aleph".to_string(), None),
        ]
    );
}
```

(`Pick` must derive `Debug, PartialEq, Eq, Clone`. If `aleph_daemon::testing::bus()` is not reachable from `aleph-gui`'s tests, use how `tests/store.rs` gets its bus; it uses `aleph_daemon::testing` already.)

- [ ] **Step 3: Run them and watch them fail**

Add `pub mod filepicker;` to `lib.rs`. Run: `cargo test -p aleph-gui --test filepicker`
Expected: compile error, `unresolved import aleph_gui::filepicker::Fake`.

- [ ] **Step 4: Implement `filepicker.rs`**

```rust
//! Where a backup goes (the admin spec, "BACK UP…"): the XDG portal's
//! save dialog, through `rfd`, on a thread of its own so the window never
//! waits for it. `rfd` cannot tell "there is no portal" from "the person
//! cancelled", so whether the portal is there is decided first, by the
//! owner of `org.freedesktop.portal.Desktop` on the session bus.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::Mutex;

const PORTAL: &str = "org.freedesktop.portal.Desktop";

/// What the save dialog came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pick {
    /// No portal to ask (or the dialog could not start): the window shows a
    /// typed-path field instead.
    Unavailable,
    Cancelled,
    Chosen(PathBuf),
}

pub trait FilePicker {
    /// Ask where to save a file called `suggested`, starting in `dir`. The
    /// answer arrives on the receiver (the window polls it each frame).
    fn start(&self, suggested: String, dir: Option<PathBuf>) -> Receiver<Pick>;
}

/// Whether the portal has an owner on the bus at `address` (the session
/// bus if `None`). Any failure to ask is "no".
pub async fn portal_present(address: Option<&str>) -> bool {
    let conn = match address {
        Some(a) => match zbus::connection::Builder::address(a) {
            Ok(b) => b.build().await,
            Err(e) => Err(e),
        },
        None => zbus::Connection::session().await,
    };
    let Ok(conn) = conn else {
        return false;
    };
    let Ok(dbus) = zbus::fdo::DBusProxy::new(&conn).await else {
        return false;
    };
    let Ok(name) = zbus::names::BusName::try_from(PORTAL) else {
        return false;
    };
    dbus.name_has_owner(name).await.unwrap_or(false)
}

/// The real dialog.
pub struct Portal;

impl FilePicker for Portal {
    fn start(&self, suggested: String, dir: Option<PathBuf>) -> Receiver<Pick> {
        let (tx, rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("aleph-save-dialog".into())
            .spawn({
                let tx = tx.clone();
                move || {
                    let _ = tx.send(pick(&suggested, dir.as_deref()));
                }
            });
        if spawned.is_err() {
            let _ = tx.send(Pick::Unavailable);
        }
        rx
    }
}

fn pick(suggested: &str, dir: Option<&std::path::Path>) -> Pick {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Pick::Unavailable;
    };
    rt.block_on(async {
        if !portal_present(None).await {
            return Pick::Unavailable;
        }
        let mut dialog = rfd::AsyncFileDialog::new()
            .set_title("Save the aleph backup")
            .set_file_name(suggested);
        if let Some(dir) = dir {
            dialog = dialog.set_directory(dir);
        }
        match dialog.save_file().await {
            Some(handle) => Pick::Chosen(handle.path().to_path_buf()),
            None => Pick::Cancelled,
        }
    })
}

/// A picker for the tests: answers from a list, in order (a cancel once it
/// runs out), and remembers what it was asked.
pub struct Fake {
    picks: Mutex<Vec<Pick>>,
    pub asked: Mutex<Vec<(String, Option<PathBuf>)>>,
}

impl Fake {
    pub fn new(mut picks: Vec<Pick>) -> Self {
        picks.reverse();
        Self {
            picks: Mutex::new(picks),
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl FilePicker for Fake {
    fn start(&self, suggested: String, dir: Option<PathBuf>) -> Receiver<Pick> {
        self.asked.lock().unwrap().push((suggested, dir));
        let next = self.picks.lock().unwrap().pop().unwrap_or(Pick::Cancelled);
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(next);
        rx
    }
}
```

(`rfd`'s builder methods used: `AsyncFileDialog::new`, `.set_title`, `.set_file_name`, `.set_directory`, `.save_file().await -> Option<FileHandle>`, `FileHandle::path`. If the crate's API differs in the version you resolved, adjust and say so in the report. The real `Portal` is not tested here: it needs a real portal.)

- [ ] **Step 5: Run and watch it pass**

Run: `cargo test -p aleph-gui --test filepicker && cargo clippy -p aleph-gui --all-targets -- -D warnings`
Expected: PASS (3 tests), clippy clean.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add Cargo.toml Cargo.lock crates/aleph-gui
git commit -m 'feat(gui): a FilePicker for the backup dialog, with the rfd XDG portal behind it' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

(Include `Cargo.lock` if the repo tracks it.)

---

### Task 2: One state machine for reveal, settings save and (later) admin operations

**Files:**
- Create: `crates/aleph-gui/src/task.rs`
- Modify: `crates/aleph-gui/src/lib.rs` (`pub mod task;`)
- Modify: `crates/aleph-gui/src/manager.rs`
- Test: unit tests in `task.rs`; every existing test must pass untouched

**Interfaces:**
- Consumes: `Request::SetConfigs`, `Form::changes`, `Values`.
- Produces:
  - `task::Want { Show, Copy, Edit }` (moved from `manager.rs`; `manager` re-exports it: `pub use crate::task::Want;`).
  - `task::Job` (only `Settings` in this task; Task 5 adds `Admin(AdminOp)`), with
    - `request_name(&self) -> &'static str`
    - `may_not_have_gone_through(&self) -> &'static str`
    - `may_not_have_been_done(&self) -> &'static str`
    - `nothing(&self) -> &'static str`
    - `unlock_missed(&self) -> &'static str`
    - `cancelled(&self) -> String`
    - `refused(&self, message: &str) -> String`
  - `task::Running { Reveal { path: String, want: Want }, Job(Job) }`.
  - In `Manager`: `running: Option<Running>` (the confirmation on screen is for this) and `waiting: Option<Job>` (SAVE pressed while sealed: it asked alephd to unlock and starts when the vault is open) replace `pending`, `saving_settings` and `save_after_unlock`. New private methods `start_job(&mut self, ctx, job: Job)` and `begin(&mut self, ctx, job: Job)`; `resume_save` becomes `resume_job`; `save_interrupted` takes `&Job`.

- [ ] **Step 1: Write the failing unit tests**

Create `crates/aleph-gui/src/task.rs` with the module doc and only these tests (the code comes in Step 3):

```rust
//! What the manager's confirmation is for (the admin spec,
//! "Architecture"): a reveal, a settings save, and (Plan 5d) an admin
//! operation share one path: the unlock-first step for a sealed vault, the
//! embedded confirmation, the wording after an interruption, and what
//! happens on finish. The words each kind uses are here, so
//! `manager.rs` never branches on the kind to say something.

#[cfg(test)]
mod tests {
    use super::*;

    /// The words the Plan 5c tests pin for a settings save.
    #[test]
    fn a_settings_save_keeps_its_words() {
        let j = Job::Settings;
        assert_eq!(j.request_name(), "save the settings");
        assert_eq!(j.may_not_have_gone_through(), "the save may not have gone through");
        assert_eq!(j.may_not_have_been_done(), "the settings may not have been saved");
        assert_eq!(j.nothing(), "nothing was saved");
        assert_eq!(j.unlock_missed(), "the settings were not saved");
        assert_eq!(j.cancelled(), "cancelled: nothing was saved");
        assert_eq!(j.refused("boom"), "not saved: boom");
    }
}
```

- [ ] **Step 2: Run it and watch it fail**

Add `pub mod task;` to `lib.rs`. Run: `cargo test -p aleph-gui --lib task::`
Expected: compile errors: `Job` not found.

- [ ] **Step 3: Implement `task.rs`**

Above the tests:

```rust
/// What a fetched secret is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    Show,
    Copy,
    Edit,
}

/// Work that needs alephd's confirmation, and an open vault for it.
#[derive(Debug)]
pub enum Job {
    /// The VAULT settings' SAVE (the changes are read from the form when it
    /// starts).
    Settings,
}

impl Job {
    /// The store request's name (`Request::name`), as `Done` reports it.
    pub fn request_name(&self) -> &'static str {
        match self {
            Self::Settings => "save the settings",
        }
    }

    /// After a lock or a lost link ended it: alephd may have gone ahead.
    pub fn may_not_have_gone_through(&self) -> &'static str {
        match self {
            Self::Settings => "the save may not have gone through",
        }
    }

    /// After the window or the confirmation ended early.
    pub fn may_not_have_been_done(&self) -> &'static str {
        match self {
            Self::Settings => "the settings may not have been saved",
        }
    }

    /// What is true when the person cancelled, or the unlock did not come.
    pub fn nothing(&self) -> &'static str {
        match self {
            Self::Settings => "nothing was saved",
        }
    }

    /// The vault opened, but there was nothing left to do.
    pub fn unlock_missed(&self) -> &'static str {
        match self {
            Self::Settings => "the settings were not saved",
        }
    }

    pub fn cancelled(&self) -> String {
        format!("cancelled: {}", self.nothing())
    }

    /// alephd ended the conversation without success, with its message.
    pub fn refused(&self, message: &str) -> String {
        match self {
            Self::Settings => format!("not saved: {message}"),
        }
    }
}

/// What the confirmation on screen is for.
#[derive(Debug)]
pub enum Running {
    /// Show, copy or edit a secret: fetched once the guard confirms.
    Reveal { path: String, want: Want },
    Job(Job),
}
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p aleph-gui --lib task::`
Expected: PASS (1 test).

- [ ] **Step 5: Rewire `manager.rs`**

Make each of these edits (read the function first; the surrounding code is as in the repo):

1. **Imports and `Want`.** Delete `pub enum Want { Show, Copy, Edit }` and its doc comment. Add `pub use crate::task::Want;` and `use crate::task::{Job, Running};` beside the other `use crate::...` lines.

2. **Fields.** Delete `pending: Option<(String, Want)>` (and its doc), `saving_settings: bool` and `save_after_unlock: bool` (and their docs) from `struct Manager`, and their initialisers from `new`. Add:

```rust
    /// What the confirmation on screen is for.
    running: Option<Running>,
    /// SAVE was pressed while the vault was locked: it asked alephd to
    /// unlock, and starts (with the edits as they are then) once it is open.
    waiting: Option<Job>,
```

   and in `new`: `running: None, waiting: None,`.

3. **`start_confirm`:** replace `self.pending = Some((path, want));` with `self.running = Some(Running::Reveal { path, want });`.

4. **`start_save` becomes `start_job`, and `begin` is new.** Replace `start_save` with:

```rust
    /// Start `job`'s confirmation in the window and send its request: alephd
    /// converses on the other end of the socketpair.
    fn start_job(&mut self, ctx: &egui::Context, job: Job) {
        let Some(theirs) = self.open_confirm(ctx) else {
            return;
        };
        let request = match &job {
            Job::Settings => Request::SetConfigs(
                theirs.into(),
                self.form().map(Form::changes).unwrap_or_default(),
            ),
        };
        self.running = Some(Running::Job(job));
        self.store.request(request);
    }

    /// Run `job`: at once, or (the vault sealed, which alephd's
    /// re-authentication refuses) after asking alephd to unlock. Nothing
    /// starts while another job runs or waits.
    fn begin(&mut self, ctx: &egui::Context, job: Job) {
        if self.running.is_some() || self.waiting.is_some() {
            return;
        }
        match self.vault {
            Vault::Locked => {
                self.waiting = Some(job);
                self.store.request(Request::Unlock);
            }
            Vault::Unlocked(_) => self.start_job(ctx, job),
            _ => {}
        }
    }
```

5. **`exit`:** in the `if self.confirm.is_some() { self.end_confirm(); self.saving_settings = false; }` block replace `self.saving_settings = false;` with `self.running = None;`.

6. **`save_interrupted`** takes the job:

```rust
    /// A save was cut short (a lock, alephd gone, the window left, the
    /// confirmation closed with no answer): alephd may have gone ahead, so
    /// what it holds is read again, under the edits.
    fn save_interrupted(&mut self, job: &Job) {
        match job {
            Job::Settings => {
                if matches!(self.values, Values::Ready(_)) {
                    self.rebase_on_config = Rebase::Due;
                }
            }
        }
    }
```

7. **`sealed`:** replace

```rust
        self.pending = None;
        self.end_confirm();
        if std::mem::take(&mut self.saving_settings) {
            let why = match now {
                Vault::Locked => "the vault locked",
                _ => "alephd went away",
            };
            self.status = Some(format!("{why}: the save may not have gone through"));
            self.save_interrupted();
        }
```

   with

```rust
        self.end_confirm();
        // (A reveal's confirmation just ends; a job's says it may have gone
        // through.)
        if let Some(Running::Job(job)) = self.running.take() {
            let why = match now {
                Vault::Locked => "the vault locked",
                _ => "alephd went away",
            };
            self.status = Some(format!("{why}: {}", job.may_not_have_gone_through()));
            self.save_interrupted(&job);
        }
```

8. **`take_events`, the `Vault` arm:** replace the `if !up && self.save_after_unlock { .. }` block with

```rust
                    if !up && let Some(job) = self.waiting.take() {
                        // (No `Done` comes for an unlock that alephd went away
                        // in: the waiting job is dropped here.)
                        self.status = Some(format!("alephd went away: {}", job.nothing()));
                    }
```

9. **`take_events`, the `Done` arm:** replace the three `if request == ...` blocks (`unlock`, `read the settings`, `save the settings`) with

```rust
                    if request == "unlock"
                        && self.waiting.is_some()
                        && (error.is_some() || dismissed)
                        && let Some(job) = self.waiting.take()
                    {
                        // (A job waiting for the unlock is dropped; the edits
                        // stay. A successful unlock keeps it: `resume_job` runs
                        // when the vault event shows it open.)
                        self.status = Some(match &error {
                            Some(e) => format!("cannot unlock: {e}; {}", job.nothing()),
                            None => format!("the unlock was dismissed: {}", job.nothing()),
                        });
                        continue;
                    }
                    if request == "read the settings" {
                        // (The VAULT section shows why, with RETRY.)
                        continue;
                    }
                    if let Some(Running::Job(job)) = &self.running
                        && request == job.request_name()
                    {
                        if let Some(e) = error {
                            self.end_confirm();
                            self.running = None;
                            self.status = Some(format!("cannot {request}: {e}"));
                        }
                        continue;
                    }
```

   (`cannot save the settings: {e}` is what the old code said, so the text is unchanged.)

10. **`frame`, the focus-loss block:** replace

```rust
            self.pending = None;
            if std::mem::take(&mut self.saving_settings) {
                self.status =
                    Some("the window lost focus: the settings may not have been saved".into());
                self.save_interrupted();
            }
```

    with

```rust
            if let Some(Running::Job(job)) = self.running.take() {
                self.status = Some(format!(
                    "the window lost focus: {}",
                    job.may_not_have_been_done()
                ));
                self.save_interrupted(&job);
            }
            self.running = None;
```

    and rename the call `self.resume_save(&ui.ctx().clone());` to `self.resume_job(&ui.ctx().clone());`.

11. **`resume_save` becomes `resume_job`.** Replace the whole function (keep its doc, changing "A save" to "A job"):

```rust
    fn resume_job(&mut self, ctx: &egui::Context) {
        if self.waiting.is_none() || !matches!(self.vault, Vault::Unlocked(_)) {
            return;
        }
        if !ctx.input(|i| i.focused) {
            // (Focus coming back draws a frame; this is a fallback.)
            ctx.request_repaint_after(Duration::from_millis(250));
            return;
        }
        let Some(job) = self.waiting.take() else {
            return;
        };
        let ready = match &job {
            Job::Settings => matches!(
                &self.values,
                Values::Ready(f) if self.page == Page::Settings && f.edited() && f.valid()
            ),
        };
        if !ready {
            // (Not silently: the edits stay, for another SAVE.)
            self.status = Some(format!("the vault unlocked: {}", job.unlock_missed()));
            return;
        }
        self.start_job(ctx, job);
    }
```

12. **`vault_settings`:** in the `VaultView { .. }` literal use `unlocking: matches!(self.waiting, Some(Job::Settings)),` and `unlocked_waiting_focus: matches!(self.waiting, Some(Job::Settings)) && matches!(self.vault, Vault::Unlocked(_)),`. In the `match action`:

```rust
            Some(VaultAction::Cancel) => {
                if let Values::Ready(form) = &mut self.values {
                    form.cancel();
                }
                if matches!(self.waiting, Some(Job::Settings)) {
                    self.waiting = None;
                }
            }
            Some(VaultAction::Save) => {
                if matches!(self.values, Values::Ready(_)) {
                    // (`begin`: unlock first if sealed, then confirm.)
                    self.begin(&ui.ctx().clone(), Job::Settings);
                }
            }
```

13. **`confirming`:** replace the glance line's condition `if self.pending.is_some() {` with `if matches!(self.running, Some(Running::Reveal { .. })) {`, and replace everything inside `if app.closed { .. }` after `self.end_confirm();` (the `if std::mem::take(&mut self.saving_settings) { .. } else if let Some((path, want)) = self.pending.take() && .. { .. }` chain) with

```rust
            match self.running.take() {
                Some(Running::Job(job)) => self.job_finished(job, finished, now),
                Some(Running::Reveal { path, want }) if finished.is_some_and(|(ok, _)| ok) => {
                    self.reauth.confirmed(now);
                    self.fetch(path, want);
                }
                _ => {}
            }
```

    and add, after `confirming`:

```rust
    /// A job's confirmation closed: `finished` is what alephd ended it with
    /// (`None`: closed with no `Done`, which may mean it went ahead).
    fn job_finished(&mut self, job: Job, finished: Option<(bool, Option<String>)>, now: Instant) {
        match (job, finished) {
            (job, None) => {
                self.status = Some(format!(
                    "the confirmation ended early: {}",
                    job.may_not_have_been_done()
                ));
                self.save_interrupted(&job);
            }
            (Job::Settings, Some((true, _))) => {
                // (The same proof as a reveal's; and read again.)
                self.reauth.confirmed(now);
                self.status = Some("SETTINGS SAVED".into());
                self.values = Values::Unknown;
            }
            (job, Some((false, message))) => {
                self.status = Some(match message {
                    Some(m) => job.refused(&m),
                    None => job.cancelled(),
                });
            }
        }
    }
```

- [ ] **Step 6: Prove nothing is left of the old fields, and the suite is unchanged**

Run: `grep -n "saving_settings\|save_after_unlock\|self.pending\|pending:" crates/aleph-gui/src/manager.rs`
Expected: no output (the `Manager.saving` field and `rotation_pending` are different words and are not matched).

Run: `cargo test -p aleph-gui && cargo clippy -p aleph-gui --all-targets -- -D warnings`
Expected: everything passes with **no test or snapshot changed** (`git status` shows only `task.rs`, `lib.rs`, `manager.rs`). `screens::a_held_password_is_sent_once_the_back_off_ends` may flake (timing): rerun it alone and say so.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add crates/aleph-gui
git commit -m 'refactor(gui): one state machine for the reveal, the settings save and later admin jobs' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 3: The store reads the status and runs the admin operations

**Files:**
- Modify: `crates/aleph-gui/src/store.rs`
- Modify: `crates/aleph-gui/Cargo.toml` (`serde_json` if it is not already a dependency)
- Test: `crates/aleph-gui/tests/store.rs`

**Interfaces:**
- Consumes: alephd's `Status() -> s` (JSON), `EnrollTpm(h)`, `EnrollFido2(h, b)`, `RemoveKeyslot(h, s)`, `RetryKeyslot(s)`, `RotateMaster(h)`, `ReissueRecoveryKey(h)`, `Backup(h, h)`.
- Produces:
  - `store::SlotInfo { id: String, label: String, kind: String, created: u64, stale: bool }` and `store::AdminStatus { vault: bool, locked: bool, untrusted: Option<String>, memory_locked: Option<bool>, tpm: Option<bool>, keyslots: Vec<SlotInfo>, rotation_pending: bool, secret_service: Option<String> }` (both `Clone, Debug, PartialEq, Eq, Deserialize`; missing fields default; unknown fields ignored).
  - `Request::Status` (name `"read the status"`); `Request::AddTpm(OwnedFd)` (`"add the TPM slot"`); `Request::AddFido2(OwnedFd, bool)` (`"add the security key"`); `Request::RemoveKeyslot(OwnedFd, String)` (`"remove the keyslot"`); `Request::RetryKeyslot(String)` (`"retry the keyslot"`); `Request::RotateMaster(OwnedFd)` (`"rotate the master key"`); `Request::ReissueRecovery(OwnedFd)` (`"issue a new recovery key"`); `Request::Backup(OwnedFd, OwnedFd)` (prompter, file; `"back up"`). None is `changes()`.
  - `StoreEvent::Status(Result<AdminStatus, String>)`, sent for `Request::Status` only (a `Done` follows either way).

- [ ] **Step 1: Write the failing store tests**

In `crates/aleph-gui/tests/store.rs` add (using the file's existing `Probe`, `daemon`, `password`, `PW`, `Interactive`, `UnixStream`, `BTreeMap` imports; add what is missing):

```rust
/// Run one conversational request against alephd with a scripted prompter
/// answering `replies`; the request's `Done` and what the prompter was sent.
async fn converse(
    store: &mut Probe,
    name: &str,
    make: impl FnOnce(std::os::fd::OwnedFd) -> Request,
    replies: Vec<FromPrompter>,
) -> (Option<String>, Vec<aleph_daemon::testing::ToPrompter>) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let prompter = Interactive::new(replies);
    prompter.respond(ours);
    store.request(make(theirs.into()));
    let (error, _) = store.done(name).await;
    let sent = tokio::task::spawn_blocking(move || prompter.sent())
        .await
        .unwrap();
    (error, sent)
}

async fn status(store: &mut Probe) -> aleph_gui::store::AdminStatus {
    store.request(Request::Status);
    store
        .until(|e| match e {
            StoreEvent::Status(Ok(s)) => Some(s.clone()),
            _ => None,
        })
        .await
}

fn finished_ok(sent: &[aleph_daemon::testing::ToPrompter]) -> bool {
    matches!(
        sent.last(),
        Some(aleph_daemon::testing::ToPrompter::Done { ok: true, .. })
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_status_is_read_with_its_keyslots() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    let s = status(&mut store).await;
    assert!(s.vault && !s.locked, "{s:?}");
    assert!(!s.keyslots.is_empty(), "{s:?}");
    assert!(s.keyslots.iter().any(|k| k.kind == "recovery"), "{s:?}");
    assert!(s.keyslots.iter().all(|k| !k.id.is_empty() && !k.stale), "{s:?}");
    assert_eq!(store.done("read the status").await, (None, false));
}

#[tokio::test(flavor = "multi_thread")]
async fn without_alephd_reading_the_status_fails() {
    let bus = aleph_daemon::testing::bus();
    let mut store = Probe::new(&bus.address);
    store.request(Request::Status);
    store
        .until(|e| matches!(e, StoreEvent::Status(Err(_))).then_some(()))
        .await;
    assert!(store.done("read the status").await.0.is_some());
}

/// A slot is added and removed again, each with one confirmation.
#[tokio::test(flavor = "multi_thread")]
async fn a_tpm_slot_is_added_and_removed() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    let before = status(&mut store).await.keyslots.len();
    let (error, sent) = converse(&mut store, "add the TPM slot", Request::AddTpm, vec![password(PW)]).await;
    assert_eq!(error, None);
    assert!(finished_ok(&sent), "{sent:?}");
    let after = status(&mut store).await;
    assert_eq!(after.keyslots.len(), before + 1, "{after:?}");
    let added = after
        .keyslots
        .iter()
        .find(|k| k.kind == "tpm")
        .expect("the new TPM slot")
        .id
        .clone();
    let (error, sent) = converse(
        &mut store,
        "remove the keyslot",
        |fd| Request::RemoveKeyslot(fd, added.clone()),
        vec![password(PW)],
    )
    .await;
    assert_eq!(error, None);
    assert!(finished_ok(&sent), "{sent:?}");
    assert_eq!(status(&mut store).await.keyslots.len(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_master_key_is_rotated_and_the_recovery_key_reissued() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    let (error, sent) = converse(&mut store, "rotate the master key", Request::RotateMaster, vec![password(PW)]).await;
    assert_eq!(error, None);
    assert!(finished_ok(&sent), "{sent:?}");
    let (error, sent) = converse(&mut store, "issue a new recovery key", Request::ReissueRecovery, vec![password(PW)]).await;
    assert_eq!(error, None);
    assert!(finished_ok(&sent), "{sent:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn retrying_a_slot_needs_no_conversation() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    let id = status(&mut store).await.keyslots[0].id.clone();
    store.request(Request::RetryKeyslot(id));
    assert_eq!(store.done("retry the keyslot").await, (None, false));
}

/// A backup goes into the file the window opened; one inside aleph's own
/// directory is refused by alephd, before any question.
#[tokio::test(flavor = "multi_thread")]
async fn a_backup_is_written_into_the_file_it_is_given() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("backup.aleph");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let (error, sent) = converse(
        &mut store,
        "back up",
        |fd| Request::Backup(fd, file.into()),
        vec![password(PW)],
    )
    .await;
    assert_eq!(error, None);
    assert!(finished_ok(&sent), "{sent:?}");
    assert!(std::fs::metadata(&path).unwrap().len() > 0);

    let inside = d.env.paths.data_dir.join("copy");
    std::fs::create_dir_all(&d.env.paths.data_dir).unwrap();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&inside)
        .unwrap();
    let (_ours, theirs) = UnixStream::pair().unwrap();
    store.request(Request::Backup(theirs.into(), file.into()));
    let (error, _) = store.done("back up").await;
    assert!(error.unwrap().contains("inside"), "refused");
}

#[test]
fn admin_requests_are_not_followed_by_a_listing() {
    let fd = || std::os::unix::net::UnixStream::pair().unwrap().0.into();
    for r in [
        Request::Status,
        Request::AddTpm(fd()),
        Request::AddFido2(fd(), true),
        Request::RemoveKeyslot(fd(), "id".into()),
        Request::RetryKeyslot("id".into()),
        Request::RotateMaster(fd()),
        Request::ReissueRecovery(fd()),
        Request::Backup(fd(), fd()),
    ] {
        assert!(!r.changes(), "{}", r.name());
    }
}
```

(These tests drive real alephd; adjust only the scripted replies if a conversation asks something the plan did not expect: `Interactive` also confirms any recovery key it is shown. `FromPrompter` is imported in this file already for other tests; if not, add it to the `aleph_daemon::testing` import. If `EnrollTpm` cannot run in this harness (look at how `crates/aleph-daemon/tests/admin.rs` or `tests/keyring.rs` drive `enroll_tpm`), do what those tests do and say so in the report.)

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p aleph-gui --test store status`
Expected: compile errors: no variant `Status` on `Request`.

- [ ] **Step 3: Implement**

In `store.rs`:

1. Imports: `use serde::Deserialize;` (add `serde` and `serde_json` to `[dependencies]` in `crates/aleph-gui/Cargo.toml` if absent; they are workspace crates).

2. After `SETTINGS_KEYS`:

```rust
/// One keyslot, as alephd's status lists it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct SlotInfo {
    pub id: String,
    pub label: String,
    /// `tpm`, `fido2`, `recovery`, `login-password`, or an unknown type.
    pub kind: String,
    /// Seconds since the epoch.
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub stale: bool,
}

/// alephd's status (`alephctl status`), as the admin page shows it. What
/// this version does not know is ignored; what is missing is the default.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct AdminStatus {
    pub vault: bool,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub untrusted: Option<String>,
    #[serde(default)]
    pub memory_locked: Option<bool>,
    #[serde(default)]
    pub tpm: Option<bool>,
    #[serde(default)]
    pub keyslots: Vec<SlotInfo>,
    #[serde(default)]
    pub rotation_pending: bool,
    #[serde(default)]
    pub secret_service: Option<String>,
}
```

3. In `enum Request`, after `SetConfigs(..)`:

```rust
    /// Read alephd's status (`StoreEvent::Status`).
    Status,
    /// The admin page's operations. Those that converse take the
    /// prompter's end of a socketpair (alephd asks for the confirmation on
    /// it, and the window answers on the other end).
    AddTpm(OwnedFd),
    AddFido2(OwnedFd, bool),
    RemoveKeyslot(OwnedFd, String),
    /// Try a stale keyslot again (no conversation).
    RetryKeyslot(String),
    RotateMaster(OwnedFd),
    ReissueRecovery(OwnedFd),
    /// A backup: the prompter's end, and the new file (opened by the
    /// caller) it is written into.
    Backup(OwnedFd, OwnedFd),
```

4. `changes()`: extend the `matches!` with `| Self::Status | Self::AddTpm(_) | Self::AddFido2(..) | Self::RemoveKeyslot(..) | Self::RetryKeyslot(_) | Self::RotateMaster(_) | Self::ReissueRecovery(_) | Self::Backup(..)` inside the `!matches!(self, ...)` list. `name()`: add

```rust
            Self::Status => "read the status",
            Self::AddTpm(_) => "add the TPM slot",
            Self::AddFido2(..) => "add the security key",
            Self::RemoveKeyslot(..) => "remove the keyslot",
            Self::RetryKeyslot(_) => "retry the keyslot",
            Self::RotateMaster(_) => "rotate the master key",
            Self::ReissueRecovery(_) => "issue a new recovery key",
            Self::Backup(..) => "back up",
```

5. In `enum StoreEvent`, after `Config(..)`:

```rust
    /// alephd's status (`Request::Status`), or why it could not be read (a
    /// `Done` follows either way).
    Status(Result<AdminStatus, String>),
```

6. In `Client::handle`, after the `Request::SetConfigs` arm:

```rust
            Request::Status => {
                let json: String = self
                    .admin()
                    .await?
                    .call("Status", &())
                    .await
                    .map_err(err)?;
                let status: AdminStatus = serde_json::from_str(&json).map_err(err)?;
                Ok((false, Some(StoreEvent::Status(Ok(status)))))
            }
            Request::AddTpm(fd) => self.converse("EnrollTpm", (zbus::zvariant::OwnedFd::from(fd),)).await,
            Request::AddFido2(fd, touch_only) => {
                self.converse("EnrollFido2", (zbus::zvariant::OwnedFd::from(fd), touch_only))
                    .await
            }
            Request::RemoveKeyslot(fd, id) => {
                self.converse("RemoveKeyslot", (zbus::zvariant::OwnedFd::from(fd), id))
                    .await
            }
            Request::RetryKeyslot(id) => self.converse("RetryKeyslot", (id,)).await,
            Request::RotateMaster(fd) => {
                self.converse("RotateMaster", (zbus::zvariant::OwnedFd::from(fd),))
                    .await
            }
            Request::ReissueRecovery(fd) => {
                self.converse("ReissueRecoveryKey", (zbus::zvariant::OwnedFd::from(fd),))
                    .await
            }
            Request::Backup(fd, file) => {
                self.converse(
                    "Backup",
                    (
                        zbus::zvariant::OwnedFd::from(fd),
                        zbus::zvariant::OwnedFd::from(file),
                    ),
                )
                .await
            }
```

   and next to `admin()` add the shared caller:

```rust
    /// Call an admin method that takes no answer back: `Done` reports the
    /// call (alephd refused it, or accepted it); a conversation's outcome
    /// arrives on its socket.
    async fn converse<B>(
        &self,
        method: &str,
        body: B,
    ) -> Result<(bool, Option<StoreEvent>), String>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        self.admin()
            .await?
            .call::<_, _, ()>(method, &body)
            .await
            .map_err(err)?;
        Ok((false, None))
    }
```

   (If the `serde::Serialize + zbus::zvariant::DynamicType` bounds are not what zbus 5 wants for `call`'s body in this version, use `zbus::zvariant::Type + serde::Serialize`, as the compiler asks.)

7. In `run`, next to `let reading = matches!(&r, Request::Config);` add `let reading_status = matches!(&r, Request::Status);` and in the `Err(e)` branch after the `if reading { .. }` block:

```rust
                            if reading_status {
                                emit.send(StoreEvent::Status(Err(e.clone())));
                            }
```

- [ ] **Step 4: Run and watch them pass**

Run: `cargo test -p aleph-gui --test store && cargo clippy -p aleph-gui --all-targets -- -D warnings`
Expected: PASS (all store tests, including the seven new ones); clippy clean. `manager.rs` needs a placeholder `StoreEvent::Status(_) => {}` arm in `take_events` to keep the match exhaustive (Task 5 replaces it with the real arm: say so in the report and leave a comment).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/aleph-gui
git commit -m 'feat(gui): the store reads alephd status and runs the admin operations' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 4: The admin page's model and drawing

**Files:**
- Create: `crates/aleph-gui/src/admin_page.rs`
- Modify: `crates/aleph-gui/src/lib.rs` (`pub mod admin_page;`)
- Test: unit tests in `admin_page.rs`

**Interfaces:**
- Consumes: `store::{AdminStatus, SlotInfo}`, `theme::Palette`, `manager::date`.
- Produces (all `pub`, in `aleph_gui::admin_page`):
  - `enum AdminState { Unknown, Loading, Failed(String), Ready(AdminStatus) }` with `is_stale(&self) -> bool` (`Failed`, or `Ready`: what a link's return re-reads).
  - `enum Link { Up, Connecting, Down(String) }`.
  - `enum Ask { Remove { id: String, label: String }, NewRecoveryKey }` with `text(&self) -> String`.
  - `struct StatusText { pub facts: [String; 2], pub warnings: Vec<Warning>, pub owner_foreign: bool }`, `struct Warning { pub text: String, pub rotate_now: bool }`, `fn status_text(s: &AdminStatus) -> StatusText`.
  - `struct RowButtons { pub remove: bool, pub retry: bool }`, `fn row_buttons(slot: &SlotInfo) -> RowButtons`.
  - `fn suggested_backup_name(date: &str) -> String` (`aleph-backup-<date>.aleph`).
  - `struct AdminView { pub link: Link, pub sealed: bool, pub waiting: bool }`
  - `enum AdminAction { Reload, RotateNow, AddTpm, AddFido2 { touch_only: bool }, Remove { id: String, label: String }, Retry(String), RotateMaster, NewRecoveryKey, BackUp, TypePath }`
  - `fn admin_section(ui, p: &Palette, state: &AdminState, view: &AdminView, touch_alone: &mut bool) -> Option<AdminAction>`
  - `fn ask_section(ui, p, ask: &Ask) -> Option<bool>` (`Some(true)` Yes, `Some(false)` No)
  - `enum BackupField { Go, Cancel }`, `fn backup_field(ui, p, path: &mut String, error: Option<&str>) -> Option<BackupField>`
  - `const SEALED_NOTE: &str = "VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST"`, `const NEW_KEY_ASK: &str`, `const TOUCH_WARNING: &str = "anyone holding the key can unlock"`.
  - Accessible names (used by Task 5 and 6 tests): `Remove keyslot <label>`, `Retry keyslot <label>`; buttons `ROTATE NOW`, `+ TPM`, `+ SECURITY KEY`, `ROTATE MASTER KEY`, `NEW RECOVERY KEY`, `BACK UP…`, `type a path instead`, `RETRY`, `No`, `Yes`; checkbox `touch alone`; the backup path text field `Backup path`, its buttons `BACK UP` and `CANCEL`.

- [ ] **Step 1: Write the failing tests**

Create `crates/aleph-gui/src/admin_page.rs` with the module doc and only the tests:

```rust
//! The ADMIN page (the admin spec, "The screen"): what STATUS says, which
//! buttons a slot gets, the Yes/No steps, and the drawing. It never touches
//! the store or the window: `manager.rs` wires the effects.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{AdminStatus, SlotInfo};

    fn slot(id: &str, label: &str, kind: &str, stale: bool) -> SlotInfo {
        SlotInfo {
            id: id.into(),
            label: label.into(),
            kind: kind.into(),
            created: 1_790_553_600,
            stale,
        }
    }

    fn status() -> AdminStatus {
        AdminStatus {
            vault: true,
            locked: false,
            untrusted: None,
            memory_locked: Some(true),
            tpm: Some(true),
            keyslots: vec![
                slot("1", "tpm", "tpm", false),
                slot("2", "yubikey", "fido2", false),
                slot("3", "recovery", "recovery", false),
                slot("4", "login password", "login-password", true),
            ],
            rotation_pending: false,
            secret_service: Some("alephd".into()),
        }
    }

    #[test]
    fn status_says_the_facts_and_only_the_warnings_that_are_true() {
        let t = status_text(&status());
        assert_eq!(t.facts[0], "vault  unlocked · secret service  alephd");
        assert_eq!(t.facts[1], "TPM  usable · master key  locked in RAM");
        assert!(t.warnings.is_empty());
        assert!(!t.owner_foreign);

        let mut s = status();
        s.locked = true;
        s.memory_locked = None;
        s.tpm = None;
        s.untrusted = Some("rolled back to an older version".into());
        s.rotation_pending = true;
        s.secret_service = Some("another program".into());
        let t = status_text(&s);
        assert_eq!(t.facts[0], "vault  locked · secret service  another program");
        assert_eq!(t.facts[1], "TPM  busy · master key  —");
        assert!(t.owner_foreign);
        assert_eq!(
            t.warnings,
            vec![
                Warning {
                    text: "writes refused: rolled back to an older version; see alephctl restore --accept-rollback".into(),
                    rotate_now: false
                },
                Warning {
                    text: "a password change is pending: rotate the master key".into(),
                    rotate_now: true
                },
            ]
        );
        let mut s = status();
        s.vault = false;
        s.tpm = Some(false);
        s.secret_service = None;
        let t = status_text(&s);
        assert_eq!(t.facts[0], "vault  none · secret service  unknown");
        assert!(t.facts[1].starts_with("TPM  unavailable"));
    }

    #[test]
    fn slots_get_the_buttons_that_fit() {
        let s = status();
        let b = |i: usize| row_buttons(&s.keyslots[i]);
        assert_eq!((b(0).remove, b(0).retry), (true, false));
        assert_eq!((b(1).remove, b(1).retry), (true, false));
        // The recovery slot is replaced, not removed.
        assert_eq!((b(2).remove, b(2).retry), (false, false));
        assert_eq!((b(3).remove, b(3).retry), (true, true));
        // A slot of a kind this version does not know can still be removed.
        assert!(row_buttons(&slot("9", "odd", "quantum", false)).remove);
    }

    #[test]
    fn the_yes_no_steps_use_the_agreed_words() {
        assert_eq!(
            Ask::Remove {
                id: "2".into(),
                label: "yubikey".into()
            }
            .text(),
            "Remove keyslot 'yubikey'? This rotates the master key. The key can no longer unlock the vault."
        );
        assert_eq!(
            Ask::NewRecoveryKey.text(),
            "The current recovery key stops working as soon as the new one is issued."
        );
    }

    #[test]
    fn the_backup_suggestion_names_the_day() {
        assert_eq!(suggested_backup_name("2026-09-28"), "aleph-backup-2026-09-28.aleph");
    }

    #[test]
    fn a_failed_or_known_state_is_stale_and_a_loading_one_is_not() {
        assert!(AdminState::Failed("x".into()).is_stale());
        assert!(AdminState::Ready(status()).is_stale());
        assert!(!AdminState::Loading.is_stale());
        assert!(!AdminState::Unknown.is_stale());
    }
}
```

- [ ] **Step 2: Run it and watch it fail**

Add `pub mod admin_page;` to `lib.rs`. Run: `cargo test -p aleph-gui --lib admin_page`
Expected: compile errors: `status_text`, `Ask`, `Warning`, ... not found.

- [ ] **Step 3: Implement the model**

Above the tests in `admin_page.rs`:

```rust
use egui::{RichText, TextEdit};

use crate::store::{AdminStatus, SlotInfo};
use crate::theme::Palette;

pub const SEALED_NOTE: &str = "VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST";
pub const NEW_KEY_ASK: &str =
    "The current recovery key stops working as soon as the new one is issued.";
pub const TOUCH_WARNING: &str = "anyone holding the key can unlock";

/// The page's status, as far as it has come.
#[derive(Debug)]
pub enum AdminState {
    /// Not asked for yet (or nothing worth keeping when the link went).
    Unknown,
    Loading,
    Failed(String),
    Ready(AdminStatus),
}

impl AdminState {
    /// What a link's return, or a lock or unlock, reads again.
    pub fn is_stale(&self) -> bool {
        matches!(self, Self::Failed(_) | Self::Ready(_))
    }
}

/// How alephd can be reached now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    Up,
    Connecting,
    Down(String),
}

/// The Yes/No steps before the two irreversible operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    Remove { id: String, label: String },
    NewRecoveryKey,
}

impl Ask {
    pub fn text(&self) -> String {
        match self {
            Self::Remove { label, .. } => format!(
                "Remove keyslot '{label}'? This rotates the master key. The key can no longer unlock the vault."
            ),
            Self::NewRecoveryKey => NEW_KEY_ASK.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub text: String,
    /// Offers ROTATE NOW beside it.
    pub rotate_now: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusText {
    pub facts: [String; 2],
    pub warnings: Vec<Warning>,
    /// Another program owns the Secret Service: shown in the warning colour.
    pub owner_foreign: bool,
}

/// What STATUS says (`alephctl status`, in two lines and the warnings that
/// are true).
pub fn status_text(s: &AdminStatus) -> StatusText {
    let vault = match (s.vault, s.locked) {
        (false, _) => "none",
        (true, true) => "locked",
        (true, false) => "unlocked",
    };
    let owner = s.secret_service.as_deref().unwrap_or("unknown");
    let tpm = match s.tpm {
        Some(true) => "usable",
        Some(false) => "unavailable",
        None => "busy",
    };
    let memory = match s.memory_locked {
        Some(true) => "locked in RAM",
        Some(false) => "not locked in RAM",
        None => "—",
    };
    let mut warnings = Vec::new();
    if let Some(why) = &s.untrusted {
        warnings.push(Warning {
            text: format!("writes refused: {why}; see alephctl restore --accept-rollback"),
            rotate_now: false,
        });
    }
    if s.rotation_pending {
        warnings.push(Warning {
            text: "a password change is pending: rotate the master key".into(),
            rotate_now: true,
        });
    }
    StatusText {
        facts: [
            format!("vault  {vault} · secret service  {owner}"),
            format!("TPM  {tpm} · master key  {memory}"),
        ],
        warnings,
        owner_foreign: owner == "another program",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowButtons {
    pub remove: bool,
    pub retry: bool,
}

/// A slot's buttons: REMOVE on all but the recovery slot (NEW RECOVERY KEY
/// replaces that one), RETRY on a stale one.
pub fn row_buttons(slot: &SlotInfo) -> RowButtons {
    RowButtons {
        remove: slot.kind != "recovery",
        retry: slot.stale,
    }
}

pub fn suggested_backup_name(date: &str) -> String {
    format!("aleph-backup-{date}.aleph")
}
```

- [ ] **Step 4: Run and watch it pass**

Run: `cargo test -p aleph-gui --lib admin_page`
Expected: PASS (5 tests).

- [ ] **Step 5: The drawing**

Append (above `#[cfg(test)]`), then `cargo build -p aleph-gui`:

```rust
/// What the page is allowed to do now.
pub struct AdminView {
    pub link: Link,
    /// The vault is locked: every action unlocks it first (and says so).
    pub sealed: bool,
    /// An action is waiting for the unlock: the buttons wait too.
    pub waiting: bool,
}

/// What the person asked of the page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminAction {
    /// Read the status again (after a failed read).
    Reload,
    /// ROTATE NOW, beside the pending-rotation warning.
    RotateNow,
    AddTpm,
    AddFido2 { touch_only: bool },
    Remove { id: String, label: String },
    Retry(String),
    RotateMaster,
    NewRecoveryKey,
    BackUp,
    /// "type a path instead": the backup's typed-path field.
    TypePath,
}

fn header(ui: &mut egui::Ui, p: &Palette, text: &str) {
    ui.label(RichText::new(text).strong().color(p.accent));
    ui.add_space(6.0);
}

/// A button whose accessible name is `name` (for the rows, where the same
/// word repeats).
fn named_button(ui: &mut egui::Ui, text: &str, name: String, enabled: bool) -> bool {
    let r = ui.add_enabled(enabled, egui::Button::new(text));
    ui.ctx()
        .accesskit_node_builder(r.id, move |n| n.set_label(name));
    r.clicked()
}

/// The page: STATUS, KEYSLOTS, KEEPING IT SAFE.
pub fn admin_section(
    ui: &mut egui::Ui,
    p: &Palette,
    state: &AdminState,
    view: &AdminView,
    touch_alone: &mut bool,
) -> Option<AdminAction> {
    let mut action = None;
    header(ui, p, "STATUS  // alephd");
    let up = view.link == Link::Up;
    match state {
        AdminState::Failed(why) => {
            ui.label(RichText::new(crate::conversation::shown(why, 200)).color(p.error));
            if ui.button("RETRY").clicked() {
                action = Some(AdminAction::Reload);
            }
            return action;
        }
        AdminState::Unknown | AdminState::Loading => {
            match &view.link {
                Link::Up => ui.label("LOADING…"),
                Link::Connecting => ui.label("CONNECTING…"),
                Link::Down(why) => {
                    ui.label(RichText::new("LINK DOWN").strong().color(p.error));
                    ui.label(crate::conversation::shown(why, 200))
                }
            };
            return None;
        }
        AdminState::Ready(_) => {}
    }
    let AdminState::Ready(s) = state else {
        return None;
    };
    if !up {
        ui.label(RichText::new("LINK DOWN: alephd cannot be reached").color(p.error));
    }
    let text = status_text(s);
    for (i, line) in text.facts.iter().enumerate() {
        let colour = if i == 0 && text.owner_foreign {
            p.warning
        } else {
            p.foreground
        };
        ui.label(RichText::new(line).color(colour));
    }
    let enabled = up && s.vault && !view.waiting;
    for w in &text.warnings {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("! {}", w.text)).color(p.warning));
            if w.rotate_now && ui.add_enabled(enabled, egui::Button::new("ROTATE NOW")).clicked()
            {
                action = Some(AdminAction::RotateNow);
            }
        });
    }
    if !s.vault {
        ui.add_space(8.0);
        ui.label("no vault: run `alephctl setup`");
        return action;
    }
    ui.add_space(12.0);
    header(ui, p, "KEYSLOTS");
    if view.sealed {
        ui.label(RichText::new(SEALED_NOTE).strong().color(p.warning));
    }
    for slot in &s.keyslots {
        ui.horizontal(|ui| {
            ui.label(&slot.label);
            ui.label(RichText::new(&slot.kind).color(p.muted));
            ui.label(RichText::new(crate::manager::date(slot.created)).color(p.muted));
            let b = row_buttons(slot);
            if slot.stale {
                ui.label(RichText::new("STALE").color(p.warning));
            }
            if b.retry
                && named_button(ui, "RETRY", format!("Retry keyslot {}", slot.label), up)
            {
                action = Some(AdminAction::Retry(slot.id.clone()));
            }
            if b.remove
                && named_button(ui, "REMOVE", format!("Remove keyslot {}", slot.label), enabled)
            {
                action = Some(AdminAction::Remove {
                    id: slot.id.clone(),
                    label: slot.label.clone(),
                });
            }
        });
    }
    ui.horizontal(|ui| {
        if ui.add_enabled(enabled, egui::Button::new("+ TPM")).clicked() {
            action = Some(AdminAction::AddTpm);
        }
        if ui
            .add_enabled(enabled, egui::Button::new("+ SECURITY KEY"))
            .clicked()
        {
            action = Some(AdminAction::AddFido2 {
                touch_only: *touch_alone,
            });
        }
        ui.checkbox(touch_alone, "touch alone");
    });
    if *touch_alone {
        ui.label(RichText::new(TOUCH_WARNING).small().color(p.warning));
    }
    ui.add_space(12.0);
    header(ui, p, "KEEPING IT SAFE");
    ui.horizontal(|ui| {
        if ui
            .add_enabled(enabled, egui::Button::new("ROTATE MASTER KEY"))
            .clicked()
        {
            action = Some(AdminAction::RotateMaster);
        }
        if ui
            .add_enabled(enabled, egui::Button::new("NEW RECOVERY KEY"))
            .clicked()
        {
            action = Some(AdminAction::NewRecoveryKey);
        }
        if ui.add_enabled(enabled, egui::Button::new("BACK UP…")).clicked() {
            action = Some(AdminAction::BackUp);
        }
        if ui
            .add_enabled(enabled, egui::Button::new("type a path instead").small())
            .clicked()
        {
            action = Some(AdminAction::TypePath);
        }
    });
    if view.waiting {
        ui.label("waiting for the unlock…");
    }
    action
}

/// A Yes/No step: No first, and focused (the default). `Some(true)` is Yes.
pub fn ask_section(ui: &mut egui::Ui, p: &Palette, ask: &Ask) -> Option<bool> {
    ui.label(RichText::new(ask.text()).color(p.warning));
    ui.add_space(8.0);
    let mut answer = None;
    ui.horizontal(|ui| {
        let no = ui.button("No");
        no.request_focus();
        if no.clicked() {
            answer = Some(false);
        }
        if ui.button("Yes").clicked() {
            answer = Some(true);
        }
    });
    answer
}

/// What the person did in the typed-path field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupField {
    Go,
    Cancel,
}

/// The fallback for the save dialog: a path to type (`error` says why the
/// last one was refused).
pub fn backup_field(
    ui: &mut egui::Ui,
    p: &Palette,
    path: &mut String,
    error: Option<&str>,
) -> Option<BackupField> {
    header(ui, p, "BACK UP  // a new file");
    let r = ui.add(
        TextEdit::singleline(path)
            .hint_text("path_")
            .desired_width(f32::INFINITY),
    );
    ui.ctx()
        .accesskit_node_builder(r.id, |n| n.set_label("Backup path"));
    if let Some(e) = error {
        ui.label(RichText::new(crate::conversation::shown(e, 200)).small().color(p.warning));
    }
    let mut out = None;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(!path.trim().is_empty(), egui::Button::new("BACK UP"))
            .clicked()
        {
            out = Some(BackupField::Go);
        }
        if ui.button("CANCEL").clicked() {
            out = Some(BackupField::Cancel);
        }
    });
    out
}
```

(`Palette` fields used: `accent`, `warning`, `error`, `muted`, `foreground`: all exist. `conversation::shown` and `manager::date` are `pub`. In `accesskit_node_builder(.., |n| n.set_label(..))` pass an owned `String`/`&'static str` as the existing code does.)

- [ ] **Step 6: Build, lint, and commit**

Run: `cargo test -p aleph-gui --lib && cargo clippy -p aleph-gui --all-targets -- -D warnings`
Expected: PASS, clean.

```bash
cargo fmt --all
git add crates/aleph-gui
git commit -m 'feat(gui): the admin page model and drawing' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 5: The ADMIN page in the manager: status, slots and the operations

**Files:**
- Modify: `crates/aleph-gui/src/task.rs` (`Job::Admin`, `AdminOp`)
- Modify: `crates/aleph-gui/src/manager.rs`
- Test: `crates/aleph-gui/tests/manager.rs`

**Interfaces:**
- Consumes: Task 2's `Job`, `Running`, `begin`, `start_job`, `resume_job`; Task 3's requests and `StoreEvent::Status`; Task 4's page.
- Produces:
  - `task::AdminOp { AddTpm, AddFido2 { touch_only: bool }, Remove { id: String, label: String }, RotateMaster, NewRecoveryKey }` with `request_name(&self) -> &'static str` and `done_text(&self) -> String` and `request(&self, prompter: std::os::fd::OwnedFd) -> Request`. (Task 6 adds `Backup`.)
  - `Job::Admin(AdminOp)`, with all `Job` wording methods extended: admin words are `the operation may not have gone through`, `nothing was changed`, `the operation was not run`, `cancelled: nothing was changed`, `not done: <message>`.
  - `manager::Page::Admin`; sidebar entry `ADMIN` (third, after `SETTINGS`).
  - `Manager` fields `admin: AdminState`, `ask: Option<Ask>`, `touch_alone: bool`.

- [ ] **Step 1: Write the failing window tests**

In `crates/aleph-gui/tests/manager.rs` add imports as needed (`aleph_gui::store::{AdminStatus, SlotInfo}`, `aleph_gui::manager::Page`), then at the end, before `snapshots`:

```rust
// --- ADMIN ---

fn slot(id: &str, label: &str, kind: &str, stale: bool) -> SlotInfo {
    SlotInfo {
        id: id.into(),
        label: label.into(),
        kind: kind.into(),
        created: 1_790_553_600,
        stale,
    }
}

fn admin_status() -> AdminStatus {
    AdminStatus {
        vault: true,
        locked: false,
        untrusted: None,
        memory_locked: Some(true),
        tpm: Some(true),
        keyslots: vec![
            slot("1", "tpm", "tpm", false),
            slot("2", "yubikey", "fido2", false),
            slot("3", "recovery", "recovery", false),
            slot("4", "login password", "login-password", true),
        ],
        rotation_pending: false,
        secret_service: Some("alephd".into()),
    }
}

/// Open ADMIN and answer the status read.
fn open_admin(h: &mut Window, store: &Fake, status: AdminStatus) {
    h.get_by_label("ADMIN").click();
    frames(h);
    assert!(matches!(only(store.take()), Request::Status));
    store.send(StoreEvent::Status(Ok(status)));
    frames(h);
}

fn done(request: &'static str, error: Option<&str>) -> StoreEvent {
    StoreEvent::Done {
        request,
        error: error.map(String::from),
        dismissed: false,
    }
}

#[test]
fn admin_reads_the_status_once_and_shows_it() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("ADMIN").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
    h.get_by_label("LOADING…");
    frames(&mut h);
    assert!(store.take().is_empty(), "not asked again while it is on its way");
    store.send(StoreEvent::Status(Ok(admin_status())));
    frames(&mut h);
    h.get_by_label("vault  unlocked · secret service  alephd");
    h.get_by_label("TPM  usable · master key  locked in RAM");
    assert_eq!(h.state().page(), Page::Admin);
    // Leaving and returning reads it again (there are no edits to keep).
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    h.get_by_label("ADMIN").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}

#[test]
fn slots_get_their_buttons() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("Remove keyslot tpm");
    h.get_by_label("Remove keyslot yubikey");
    h.get_by_label("Remove keyslot login password");
    assert!(h.query_by_label("Remove keyslot recovery").is_none());
    h.get_by_label("Retry keyslot login password");
    assert!(h.query_by_label("Retry keyslot tpm").is_none());
    h.get_by_label("STALE");
}

#[test]
fn warnings_show_only_when_true_and_rotating_now_rotates() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    assert!(h.query_by_label_contains("writes refused").is_none());
    assert!(h.query_by_label_contains("a password change is pending").is_none());
    let mut s = admin_status();
    s.untrusted = Some("rolled back to an older version".into());
    s.rotation_pending = true;
    // (Read again: leave and return.)
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    open_admin(&mut h, &store, s);
    h.get_by_label_contains("writes refused: rolled back to an older version");
    h.get_by_label_contains("a password change is pending");
    h.get_by_label("ROTATE NOW").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::RotateMaster(_)));
}

/// Operations that go straight to alephd's confirmation, each with the
/// request that fits.
#[test]
fn the_plain_actions_send_their_requests() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("+ TPM").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::AddTpm(_)));
    end_confirmation(&mut h, &store, "add the TPM slot");

    h.get_by_label("+ SECURITY KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::AddFido2(_, false)));
    end_confirmation(&mut h, &store, "add the security key");

    h.get_by_label("touch alone").click();
    frames(&mut h);
    h.get_by_label("anyone holding the key can unlock");
    h.get_by_label("+ SECURITY KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::AddFido2(_, true)));
    end_confirmation(&mut h, &store, "add the security key");

    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::RotateMaster(_)));
}

/// Cancel the confirmation on screen (alephd's side is gone) and let the
/// window settle back to the page: the status read follows an interrupted
/// operation.
fn end_confirmation(h: &mut Window, store: &Fake, _name: &'static str) {
    // (Escape at alephd's question, as a person cancels.)
    settle(h);
    h.key_press(egui::Key::Escape);
    settle(h);
    store.take();
    frames(h);
}

#[test]
fn remove_asks_first_with_no_the_default() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("Remove keyslot yubikey").click();
    frames(&mut h);
    assert!(store.take().is_empty(), "nothing before Yes");
    h.get_by_label(
        "Remove keyslot 'yubikey'? This rotates the master key. The key can no longer unlock the vault.",
    );
    h.get_by_label("No").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    h.get_by_label("Remove keyslot yubikey").click();
    frames(&mut h);
    h.get_by_label("Yes").click();
    frames(&mut h);
    match only(store.take()) {
        Request::RemoveKeyslot(_, id) => assert_eq!(id, "2"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_new_recovery_key_asks_first() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("NEW RECOVERY KEY").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    h.get_by_label("The current recovery key stops working as soon as the new one is issued.");
    h.get_by_label("Yes").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::ReissueRecovery(_)));
}

#[test]
fn retrying_a_slot_is_immediate_and_reads_the_status_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("Retry keyslot login password").click();
    frames(&mut h);
    match only(store.take()) {
        Request::RetryKeyslot(id) => assert_eq!(id, "4"),
        other => panic!("{other:?}"),
    }
    store.send(done("retry the keyslot", None));
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}

/// A sealed vault: status shows, the note says every action unlocks first,
/// and an action asks for the unlock, then its confirmation.
#[test]
fn a_sealed_vault_unlocks_first() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST");
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    h.get_by_label("waiting for the unlock…");
    // Nothing else starts while it waits.
    h.get_by_label("+ TPM").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    store.send(done("unlock", None));
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    let requests = store.take();
    assert!(
        requests.iter().any(|r| matches!(r, Request::RotateMaster(_))),
        "{requests:?}"
    );
    assert!(!requests.iter().any(|r| matches!(r, Request::AddTpm(_))));
}

/// (Review Focus 4.) A dismissed unlock runs nothing, and a later unlock by
/// something else does not resume it.
#[test]
fn a_dismissed_unlock_runs_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(StoreEvent::Done {
        request: "unlock",
        error: None,
        dismissed: true,
    });
    frames(&mut h);
    h.get_by_label_contains("nothing was changed");
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    let requests = store.take();
    assert!(
        !requests.iter().any(|r| matches!(r, Request::RotateMaster(_))),
        "{requests:?}"
    );
}

/// (Review Focus 5.) A refusal says why, changes nothing, and the status is
/// read again.
#[test]
fn a_refused_operation_says_why_and_reads_the_status_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::RotateMaster(_)));
    store.send(done(
        "rotate the master key",
        Some("would leave only the recovery slot"),
    ));
    frames(&mut h);
    h.get_by_label_contains("cannot rotate the master key: would leave only the recovery slot");
    assert!(matches!(only(store.take()), Request::Status));
}

/// (Review Focus 5.) A lock during the confirmation may have let the
/// operation through: it says so, and the status is read again.
#[test]
fn a_lock_during_an_operation_may_have_let_it_through() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    let _ = only(store.take());
    store.send(StoreEvent::Vault(Vault::Locked));
    settle(&mut h);
    h.get_by_label_contains("the operation may not have gone through");
    let requests = store.take();
    assert!(
        requests.iter().any(|r| matches!(r, Request::Status)),
        "{requests:?}"
    );
}

#[test]
fn a_successful_operation_says_so_and_reads_the_status_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    let Request::RotateMaster(fd) = only(store.take()) else {
        panic!("no rotation");
    };
    let alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(alephd.join().unwrap());
    settle(&mut h);
    h.get_by_label_contains("MASTER KEY ROTATED");
    assert!(matches!(only(store.take()), Request::Status));
}

#[test]
fn with_no_vault_the_page_says_so_and_offers_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    let mut s = admin_status();
    s.vault = false;
    s.keyslots.clear();
    open_admin(&mut h, &store, s);
    h.get_by_label_contains("no vault: run `alephctl setup`");
    assert!(h.query_by_label("+ TPM").is_none());
}

#[test]
fn with_alephd_down_the_page_waits_for_the_link() {
    let (mut h, store, _) = window(
        ThemeChoice::Neon,
        Vault::Unreachable("org.freedesktop.secrets has no owner".into()),
    );
    h.get_by_label("ADMIN").click();
    frames(&mut h);
    assert!(store.take().is_empty(), "nothing to ask");
    h.get_by_label("LINK DOWN");
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}

#[test]
fn a_failed_status_read_says_why_and_can_be_retried() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("ADMIN").click();
    frames(&mut h);
    store.take();
    store.send(StoreEvent::Status(Err("no reply from alephd".into())));
    frames(&mut h);
    h.get_by_label_contains("no reply from alephd");
    h.get_by_label("RETRY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}

/// A lock or unlock changes what STATUS says (locked, memory-locked): it
/// is read again.
#[test]
fn a_lock_or_unlock_reads_the_status_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}
```

(Note on `end_confirmation`: Escape in the embedded prompter is how the other tests cancel a confirmation; if the harness needs the password field focused first, use `h.get_by_label("Login password").focus()` before pressing Escape, as `a_cancelled_confirmation_saves_nothing` does in `tests/manager.rs`.)

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p aleph-gui --test manager admin`
Expected: compile errors: `Page::Admin` missing, `Request::Status` handling absent in the manager (the placeholder arm), `page()` cannot be `Page::Admin`.

- [ ] **Step 3: `task.rs` — the admin operations**

Add `use std::os::fd::OwnedFd;` and `use crate::store::Request;` at the top of `task.rs` and:

```rust
/// One admin operation (the admin spec, "The screen").
#[derive(Debug)]
pub enum AdminOp {
    AddTpm,
    AddFido2 { touch_only: bool },
    Remove { id: String, label: String },
    RotateMaster,
    NewRecoveryKey,
}

impl AdminOp {
    /// The store request's name (`Request::name`).
    pub fn request_name(&self) -> &'static str {
        match self {
            Self::AddTpm => "add the TPM slot",
            Self::AddFido2 { .. } => "add the security key",
            Self::Remove { .. } => "remove the keyslot",
            Self::RotateMaster => "rotate the master key",
            Self::NewRecoveryKey => "issue a new recovery key",
        }
    }

    /// What the status line says when it went through.
    pub fn done_text(&self) -> String {
        match self {
            Self::AddTpm | Self::AddFido2 { .. } => "KEYSLOT ADDED",
            Self::Remove { .. } => "KEYSLOT REMOVED",
            Self::RotateMaster => "MASTER KEY ROTATED",
            Self::NewRecoveryKey => "NEW RECOVERY KEY ISSUED",
        }
        .into()
    }

    /// The store request, conversing on `prompter`.
    pub fn request(&self, prompter: OwnedFd) -> Request {
        match self {
            Self::AddTpm => Request::AddTpm(prompter),
            Self::AddFido2 { touch_only } => Request::AddFido2(prompter, *touch_only),
            Self::Remove { id, .. } => Request::RemoveKeyslot(prompter, id.clone()),
            Self::RotateMaster => Request::RotateMaster(prompter),
            Self::NewRecoveryKey => Request::ReissueRecovery(prompter),
        }
    }
}
```

Extend `Job` with `Admin(AdminOp)` and each method with an arm:

```rust
    // request_name:
    Self::Admin(op) => op.request_name(),
    // may_not_have_gone_through:
    Self::Admin(_) => "the operation may not have gone through",
    // may_not_have_been_done:
    Self::Admin(_) => "the operation may not have gone through",
    // nothing:
    Self::Admin(_) => "nothing was changed",
    // unlock_missed:
    Self::Admin(_) => "the operation was not run",
    // refused:
    Self::Admin(_) => format!("not done: {message}"),
```

Add unit tests to `task.rs`:

```rust
    #[test]
    fn an_admin_job_has_its_own_words() {
        let j = Job::Admin(AdminOp::RotateMaster);
        assert_eq!(j.request_name(), "rotate the master key");
        assert_eq!(j.nothing(), "nothing was changed");
        assert_eq!(j.cancelled(), "cancelled: nothing was changed");
        assert_eq!(j.refused("no"), "not done: no");
        assert_eq!(j.may_not_have_gone_through(), "the operation may not have gone through");
        assert_eq!(AdminOp::RotateMaster.done_text(), "MASTER KEY ROTATED");
        assert_eq!(AdminOp::AddFido2 { touch_only: true }.done_text(), "KEYSLOT ADDED");
        assert_eq!(
            AdminOp::Remove { id: "1".into(), label: "x".into() }.done_text(),
            "KEYSLOT REMOVED"
        );
        assert_eq!(AdminOp::NewRecoveryKey.done_text(), "NEW RECOVERY KEY ISSUED");
    }
```

- [ ] **Step 4: `manager.rs` — the page and the wiring**

1. Imports: `use crate::admin_page::{self, AdminAction, AdminState, AdminView, Ask, Link};`, `use crate::task::{AdminOp, Job, Running};`.

2. `enum Page { Secrets, Settings, Admin }`.

3. Fields (`struct Manager`, and `new`):

```rust
    /// The ADMIN page's status: read when the page opens, and again after
    /// every operation, lock, unlock and return of the link.
    admin: AdminState,
    /// A Yes/No step before REMOVE or NEW RECOVERY KEY.
    ask: Option<Ask>,
    /// The "touch alone" checkbox for a new security key.
    touch_alone: bool,
```

   with `admin: AdminState::Unknown, ask: None, touch_alone: false,` in `new`.

4. `start_job`'s `request` match gains `Job::Admin(op) => op.request(theirs.into()),`. `save_interrupted`'s match gains

```rust
            Job::Admin(_) => self.admin = AdminState::Unknown,
```

   (an interrupted operation may have gone through: the status is read again). `resume_job`'s `ready` match gains

```rust
            Job::Admin(_) => self.page == Page::Admin,
```

   `job_finished` gains, before the `(job, Some((false, message)))` arm:

```rust
            (Job::Admin(op), Some((true, _))) => {
                self.reauth.confirmed(now);
                self.status = Some(op.done_text());
                self.admin = AdminState::Unknown;
            }
```

   and in the `(job, Some((false, message)))` arm, after setting the status, add `if matches!(job, Job::Admin(_)) { self.admin = AdminState::Unknown; }` — but `job` is moved into `job.refused`? It is borrowed there; do `let admin = matches!(job, Job::Admin(_));` first.

5. `take_events`:
   - In the `Vault` arm, after the existing `if up && !was_up { .. }` block:

```rust
                    // (The link went: what it was reading may never come; the
                    // link came back, or the vault locked or unlocked: what
                    // STATUS says has changed.)
                    if !up && matches!(self.admin, AdminState::Loading) {
                        self.admin = AdminState::Unknown;
                    }
                    let opened = matches!(self.vault, Vault::Unlocked(_));
                    let was_open = was_unlocked;
                    if (up && !was_up || opened != was_open) && self.admin.is_stale() {
                        self.admin = AdminState::Unknown;
                    }
```

     with `let was_unlocked = matches!(self.vault, Vault::Unlocked(_));` captured next to `was_up` **before** `self.vault = v;`.
   - Replace Task 3's placeholder `StoreEvent::Status(_) => {}` with

```rust
                StoreEvent::Status(result) => {
                    // (Only the answer being waited for.)
                    if matches!(self.admin, AdminState::Loading) {
                        self.admin = match result {
                            Ok(s) => AdminState::Ready(s),
                            Err(e) => AdminState::Failed(e),
                        };
                    }
                }
```

   - In the `Done` arm, after the `if request == "read the settings" { continue; }` block add:

```rust
                    if request == "read the status" {
                        // (The page shows why, with RETRY.)
                        continue;
                    }
                    if request == "retry the keyslot" {
                        match error {
                            Some(e) => self.status = Some(format!("cannot {request}: {e}")),
                            None => self.admin = AdminState::Unknown,
                        }
                        continue;
                    }
```

     and in the job branch (`if let Some(Running::Job(job)) = &self.running && request == job.request_name()`), read `let admin = matches!(job, Job::Admin(_));` before the inner `if let Some(e) = error`, and inside it add `if admin { self.admin = AdminState::Unknown; }`.

6. The nav and the page. In `frame`, the nav's list becomes `[(Page::Secrets, "SECRETS"), (Page::Settings, "SETTINGS"), (Page::Admin, "ADMIN")]`. Where the page switch is handled (`if let Some(page) = go { .. }`), add for the new page:

```rust
            if page == Page::Admin && self.page != Page::Admin {
                // (No edits to keep: read it again.)
                if self.admin.is_stale() {
                    self.admin = AdminState::Unknown;
                }
                self.ask = None;
            }
```

   inside the existing branch that changes pages (keep the Settings branch as it is). The `match self.page` gains `Page::Admin => self.admin_screen(ui, &p, now),`. Add `self.ask_status();` right after `self.ask_config();` in `frame`.

7. New methods (near `settings_screen`):

```rust
    /// Ask alephd for its status when the page needs it.
    fn ask_status(&mut self) {
        let up = matches!(self.vault, Vault::Locked | Vault::Unlocked(_));
        if self.page == Page::Admin && up && matches!(self.admin, AdminState::Unknown) {
            self.admin = AdminState::Loading;
            self.store.request(Request::Status);
        }
    }

    fn admin_screen(&mut self, ui: &mut egui::Ui, p: &Palette, now: Instant) {
        egui::CentralPanel::default().show(ui, |ui| {
            self.status_line(ui, p);
            if self.confirm.is_some() {
                self.confirming(ui, now);
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| self.admin_body(ui, p));
        });
    }

    fn link(&self) -> Link {
        match &self.vault {
            Vault::Connecting => Link::Connecting,
            Vault::Unreachable(why) => Link::Down(why.clone()),
            _ => Link::Up,
        }
    }

    fn admin_body(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let ctx = ui.ctx().clone();
        if let Some(ask) = self.ask.clone() {
            match admin_page::ask_section(ui, p, &ask) {
                Some(true) => {
                    self.ask = None;
                    let op = match ask {
                        Ask::Remove { id, label } => AdminOp::Remove { id, label },
                        Ask::NewRecoveryKey => AdminOp::NewRecoveryKey,
                    };
                    self.begin(&ctx, Job::Admin(op));
                }
                Some(false) => self.ask = None,
                None => {}
            }
            return;
        }
        let view = AdminView {
            link: self.link(),
            sealed: matches!(self.vault, Vault::Locked),
            waiting: matches!(self.waiting, Some(Job::Admin(_))),
        };
        let action = admin_page::admin_section(ui, p, &self.admin, &view, &mut self.touch_alone);
        match action {
            None => {}
            Some(AdminAction::Reload) => self.admin = AdminState::Unknown,
            Some(AdminAction::Retry(id)) => self.store.request(Request::RetryKeyslot(id)),
            Some(AdminAction::Remove { id, label }) => self.ask = Some(Ask::Remove { id, label }),
            Some(AdminAction::NewRecoveryKey) => self.ask = Some(Ask::NewRecoveryKey),
            Some(AdminAction::AddTpm) => self.begin(&ctx, Job::Admin(AdminOp::AddTpm)),
            Some(AdminAction::AddFido2 { touch_only }) => {
                self.begin(&ctx, Job::Admin(AdminOp::AddFido2 { touch_only }))
            }
            Some(AdminAction::RotateMaster | AdminAction::RotateNow) => {
                self.begin(&ctx, Job::Admin(AdminOp::RotateMaster))
            }
            // (Task 6: the backup.)
            Some(AdminAction::BackUp | AdminAction::TypePath) => {}
        }
    }
```

8. `exit`: nothing changes (EXIT's warning is about the settings form only).

- [ ] **Step 5: Run and iterate until the new tests pass**

Run: `cargo test -p aleph-gui --test manager admin`
Expected: PASS for every test in Step 1. Likely snags, in order:
1. A `get_by_label` finds two nodes (a label and a button with the same text): give one of them a distinct accessible name (as `named_button` does), keeping the visible text.
2. A test that clicks `Yes` finds the `Yes` of nothing: the Yes/No step draws instead of the page; frames after the click.
3. `end_confirmation`'s Escape needs the embedded prompter focused (see the note in Step 1).

- [ ] **Step 6: Regenerate the manager snapshots and look at one**

The sidebar gained `ADMIN`, so every manager snapshot differs. Run:
`UPDATE_SNAPSHOTS=1 cargo test -p aleph-gui --test manager snapshots`, then `cargo test -p aleph-gui --test manager`.
Expected: the second run PASSES. Read `crates/aleph-gui/tests/snapshots/manager_item_neon.png` and check the nav shows `SECRETS` (selected), `SETTINGS`, `ADMIN`, and LOCK and EXIT still pinned at the bottom.

- [ ] **Step 7: Run everything and commit**

Run: `cargo test -p aleph-gui && cargo clippy -p aleph-gui --all-targets -- -D warnings`
Expected: PASS, clean (`screens::a_held_password_is_sent_once_the_back_off_ends` may flake: rerun it alone and say so).

```bash
cargo fmt --all
git add crates/aleph-gui
git commit -m 'feat(gui): the ADMIN page: status, keyslots and the custody operations' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 6: BACK UP…: the save dialog, the typed path, and the file's care

**Files:**
- Modify: `crates/aleph-gui/src/task.rs` (`BackupTarget`, `AdminOp::Backup`)
- Modify: `crates/aleph-gui/src/manager.rs`
- Test: unit tests in `task.rs`; window tests in `crates/aleph-gui/tests/manager.rs`

**Interfaces:**
- Consumes: Task 1's `FilePicker`, `Pick`, `Fake`, `Portal`; Task 5's page, `begin`, `Job::Admin`; Task 4's `backup_field`, `suggested_backup_name`.
- Produces:
  - `task::BackupTarget { pub path: PathBuf, file: std::fs::File, created: bool }` with `BackupTarget::open(path: &Path) -> Result<Self, String>` (create-new with mode `0600`; if the file exists, it is used only when empty, and never removed afterwards; an existing non-empty file is refused with `"<path> already exists and is not empty: choose a new name"`), `BackupTarget::file(&self) -> std::io::Result<std::fs::File>` (a clone for the request), and `impl Drop` that removes the file **only if the manager created it and it is still empty**.
  - `AdminOp::Backup(BackupTarget)`: `request_name` `"back up"`, `done_text` `BACKED UP :: <path> (it opens only with your recovery key)`, `request` builds `Request::Backup(prompter, file.into())` (the file clone is made when the request is built; a failure to clone shows as a status and starts nothing: `AdminOp::request` returns `Result<Request, String>`; adjust Task 5's `start_job` accordingly: on `Err(e)` end the confirmation, set the status, and return).
  - `Manager::with_file_picker(self, Box<dyn FilePicker>) -> Self` (default: `Portal`).

- [ ] **Step 1: Write the failing unit tests**

In `task.rs`, `mod tests`:

```rust
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_backup_file_is_new_private_and_removed_while_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.aleph");
        let t = BackupTarget::open(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        drop(t);
        // Still empty when it is dropped: the manager made it, so it goes.
        assert!(!path.exists());
    }

    #[test]
    fn a_written_backup_stays() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.aleph");
        let t = BackupTarget::open(&path).unwrap();
        (&t.file().unwrap()).write_all(b"x").unwrap();
        drop(t);
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }

    /// (Review Focus 1.) Somebody else's file is neither overwritten nor
    /// removed; an empty one they made is used and left in place.
    #[test]
    fn an_existing_file_is_not_overwritten_or_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mine.aleph");
        std::fs::write(&path, b"precious").unwrap();
        let e = BackupTarget::open(&path).err().unwrap();
        assert!(e.contains("already exists") && e.contains("choose a new name"), "{e}");
        assert_eq!(std::fs::read(&path).unwrap(), b"precious");

        let empty = dir.path().join("empty.aleph");
        std::fs::write(&empty, b"").unwrap();
        let t = BackupTarget::open(&empty).unwrap();
        drop(t);
        assert!(empty.exists(), "not made by the manager: not removed");
    }

    #[test]
    fn a_backup_says_where_it_went() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.aleph");
        let t = BackupTarget::open(&path).unwrap();
        let op = AdminOp::Backup(t);
        assert_eq!(op.request_name(), "back up");
        assert_eq!(
            op.done_text(),
            format!("BACKED UP :: {} (it opens only with your recovery key)", path.display())
        );
    }
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p aleph-gui --lib task::`
Expected: compile errors: `BackupTarget` not found.

- [ ] **Step 3: `task.rs` — `BackupTarget` and `AdminOp::Backup`**

Add `use std::path::{Path, PathBuf};` and:

```rust
/// A backup's new file, opened by the manager (alephd writes into it
/// through the descriptor it is handed). If the manager made the file and it
/// is still empty when this is dropped (the backup was cancelled, refused,
/// or cut short), it is removed: a half-made backup never sits at the path.
#[derive(Debug)]
pub struct BackupTarget {
    pub path: PathBuf,
    file: std::fs::File,
    created: bool,
}

impl BackupTarget {
    /// Create `path` (create-new, mode 0600). A file already there is used
    /// only if it is empty (and is then left in place when it is dropped);
    /// one with content is refused, never overwritten.
    pub fn open(path: &Path) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).mode(0o600);
        let (file, created) = match options.clone().create_new(true).open(path) {
            Ok(f) => (f, true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let f = options
                    .open(path)
                    .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
                let meta = f
                    .metadata()
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                if !meta.is_file() || meta.len() > 0 {
                    return Err(format!(
                        "{} already exists and is not empty: choose a new name",
                        path.display()
                    ));
                }
                (f, false)
            }
            Err(e) => return Err(format!("cannot create {}: {e}", path.display())),
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
            created,
        })
    }

    /// A handle on the same file, for the request.
    pub fn file(&self) -> std::io::Result<std::fs::File> {
        self.file.try_clone()
    }
}

impl Drop for BackupTarget {
    fn drop(&mut self) {
        if self.created && self.file.metadata().is_ok_and(|m| m.len() == 0) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
```

Extend `AdminOp` with `Backup(BackupTarget)`: `request_name` → `"back up"`; `done_text` → `format!("BACKED UP :: {} (it opens only with your recovery key)", t.path.display())`; and change `request` to return `Result<Request, String>`:

```rust
    pub fn request(&self, prompter: OwnedFd) -> Result<Request, String> {
        Ok(match self {
            Self::AddTpm => Request::AddTpm(prompter),
            Self::AddFido2 { touch_only } => Request::AddFido2(prompter, *touch_only),
            Self::Remove { id, .. } => Request::RemoveKeyslot(prompter, id.clone()),
            Self::RotateMaster => Request::RotateMaster(prompter),
            Self::NewRecoveryKey => Request::ReissueRecovery(prompter),
            Self::Backup(t) => Request::Backup(
                prompter,
                t.file()
                    .map_err(|e| format!("cannot use the backup file: {e}"))?
                    .into(),
            ),
        })
    }
```

Task 5's `start_job` then handles the `Err`:

```rust
        let request = match &job {
            Job::Settings => Request::SetConfigs(..),
            Job::Admin(op) => match op.request(theirs.into()) {
                Ok(r) => r,
                Err(e) => {
                    self.end_confirm();
                    self.status = Some(e);
                    return;
                }
            },
        };
```

- [ ] **Step 4: Run and watch the unit tests pass**

Run: `cargo test -p aleph-gui --lib task::`
Expected: PASS (5 tests).

- [ ] **Step 5: Write the failing window tests**

In `tests/manager.rs`, add a window builder that takes a picker, then the tests. Add `use aleph_gui::filepicker::{Fake as Picker, Pick};`.

```rust
/// A window whose save dialog is `picks` (a fake), on the ADMIN page.
fn backup_window(picks: Vec<Pick>) -> (Window, Fake, std::sync::Arc<Picker>) {
    let picker = std::sync::Arc::new(Picker::new(picks));
    let handle = picker.clone();
    let (mut h, store, _) = window_with(ThemeChoice::Neon, vault(), SIZE, move |m| {
        m.with_file_picker(Box::new(handle))
    });
    open_admin(&mut h, &store, admin_status());
    (h, store, picker)
}
```

(`FilePicker` must be implemented for `Arc<Fake>`; add `impl<T: FilePicker + ?Sized> FilePicker for std::sync::Arc<T>` in `filepicker.rs`, delegating to the inner value, in this task.)

```rust
fn backup_request(store: &Fake) -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    match only(store.take()) {
        Request::Backup(fd, file) => (fd, file),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_chosen_path_gets_a_private_new_file_and_a_confirmation() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, picker) = backup_window(vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    // The dialog was asked for a dated suggestion.
    let asked = picker.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].0.starts_with("aleph-backup-") && asked[0].0.ends_with(".aleph"), "{asked:?}");
    let (fd, file) = backup_request(&store);
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    // alephd writes into the file and confirms.
    let alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(alephd.join().unwrap());
    {
        use std::io::Write;
        (&std::fs::File::from(file)).write_all(b"backup").unwrap();
    }
    settle(&mut h);
    h.get_by_label_contains(&format!(
        "BACKED UP :: {} (it opens only with your recovery key)",
        path.display()
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"backup");
    assert!(matches!(only(store.take()), Request::Status));
}

/// (Review Focus 1.) A cancelled confirmation leaves no empty file behind.
#[test]
fn a_cancelled_backup_removes_the_empty_file_it_made() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, _) = backup_window(vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    let (fd, file) = backup_request(&store);
    assert!(path.exists());
    drop(fd);
    drop(file);
    settle(&mut h);
    assert!(!path.exists(), "an empty file the manager made stays behind");
}

/// (Review Focus 1.) A file with content is refused and left alone.
#[test]
fn an_existing_file_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.aleph");
    std::fs::write(&path, b"precious").unwrap();
    let (mut h, store, _) = backup_window(vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(store.take().is_empty(), "nothing asked of alephd");
    h.get_by_label_contains("choose a new name");
    assert_eq!(std::fs::read(&path).unwrap(), b"precious");
}

#[test]
fn a_closed_dialog_does_nothing() {
    let (mut h, store, _) = backup_window(vec![Pick::Cancelled]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(store.take().is_empty());
    assert!(h.query_by_label("Backup path").is_none());
}

/// (Review Focus 2.) No portal: the typed-path field, prefilled, refusing an
/// existing file, and working.
#[test]
fn without_a_portal_the_path_is_typed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("typed.aleph");
    let (mut h, store, _) = backup_window(vec![Pick::Unavailable]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(store.take().is_empty());
    h.get_by_label("Backup path");
    // (Prefilled with the dated name; replace it with ours.)
    h.get_by_label("Backup path").focus();
    frames(&mut h);
    for _ in 0..200 {
        h.key_press(egui::Key::Backspace);
    }
    frames(&mut h);
    type_into(&mut h, "Backup path", path.to_str().unwrap());
    h.get_by_label("BACK UP").click();
    settle(&mut h);
    let (_fd, _file) = backup_request(&store);
    assert!(path.exists());
}

#[test]
fn type_a_path_instead_opens_the_field_and_cancel_closes_it() {
    let (mut h, store, picker) = backup_window(vec![]);
    h.get_by_label("type a path instead").click();
    frames(&mut h);
    h.get_by_label("Backup path");
    assert!(picker.asked.lock().unwrap().is_empty(), "no dialog");
    h.get_by_label("CANCEL").click();
    frames(&mut h);
    assert!(h.query_by_label("Backup path").is_none());
    assert!(store.take().is_empty());
}

/// (Review Focus 2.) alephd refuses a path inside its own directory: the
/// reason shows, and the empty file goes.
#[test]
fn a_refused_backup_says_why_and_removes_the_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inside.aleph");
    let (mut h, store, _) = backup_window(vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    let (_fd, file) = backup_request(&store);
    drop(file);
    store.send(done("back up", Some("a backup cannot go inside /home/u/.local/share/aleph")));
    settle(&mut h);
    h.get_by_label_contains("cannot back up: a backup cannot go inside");
    assert!(!path.exists());
}

/// A sealed vault: the path is chosen and the file made first, then alephd
/// unlocks, then the confirmation.
#[test]
fn a_sealed_vault_unlocks_first_for_a_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let picker = std::sync::Arc::new(Picker::new(vec![Pick::Chosen(path.clone())]));
    let handle = picker.clone();
    let (mut h, store, _) = window_with(ThemeChoice::Neon, Vault::Locked, SIZE, move |m| {
        m.with_file_picker(Box::new(handle))
    });
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    assert!(path.exists(), "the file is made before the unlock");
    store.send(done("unlock", None));
    store.send(StoreEvent::Vault(vault()));
    settle(&mut h);
    assert!(store
        .take()
        .iter()
        .any(|r| matches!(r, Request::Backup(..))));
}

/// A dismissed unlock removes the file it had made.
#[test]
fn a_dismissed_unlock_removes_the_backup_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let picker = std::sync::Arc::new(Picker::new(vec![Pick::Chosen(path.clone())]));
    let handle = picker.clone();
    let (mut h, store, _) = window_with(ThemeChoice::Neon, Vault::Locked, SIZE, move |m| {
        m.with_file_picker(Box::new(handle))
    });
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(StoreEvent::Done {
        request: "unlock",
        error: None,
        dismissed: true,
    });
    settle(&mut h);
    assert!(!path.exists());
}
```

- [ ] **Step 6: Run them and watch them fail**

Run: `cargo test -p aleph-gui --test manager backup`
Expected: compile error: no method `with_file_picker`.

- [ ] **Step 7: `manager.rs` — the backup flow**

1. Imports: `use crate::filepicker::{FilePicker, Pick, Portal};`, `use crate::task::BackupTarget;`, `use std::sync::mpsc::Receiver;` (if not imported).

2. Fields (`struct Manager` and `new`):

```rust
    /// Where the save dialog comes from (the tests use a fake).
    picker: Box<dyn FilePicker>,
    /// A save dialog that is open: its answer, polled each frame.
    picking: Option<Receiver<Pick>>,
    /// The typed-path field (no portal, or "type a path instead"), and why
    /// the last path was refused.
    backup_path: Option<String>,
    backup_error: Option<String>,
```

   with `picker: Box::new(Portal), picking: None, backup_path: None, backup_error: None,` in `new`, and

```rust
    /// Use another save dialog (the tests' fake).
    pub fn with_file_picker(mut self, picker: Box<dyn FilePicker>) -> Self {
        self.picker = picker;
        self
    }
```

3. In `admin_body`, replace the `// (Task 6: the backup.)` arm with

```rust
            Some(AdminAction::BackUp) => self.pick_backup(&ctx),
            Some(AdminAction::TypePath) => self.type_backup_path(),
```

   and at the top of `admin_body` (before the `ask` handling), the typed-path field:

```rust
        if let Some(mut path) = self.backup_path.take() {
            match admin_page::backup_field(ui, p, &mut path, self.backup_error.as_deref()) {
                Some(admin_page::BackupField::Go) => self.backup_to(&ctx, path.trim()),
                Some(admin_page::BackupField::Cancel) => self.backup_error = None,
                None => self.backup_path = Some(path),
            }
            return;
        }
```

4. The new methods:

```rust
    /// Today's date (UTC), for the suggested file name.
    fn today() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        date(secs)
    }

    /// The suggested backup path, for the typed-path field: in the home
    /// directory (or the working one).
    fn suggested_path(&self) -> String {
        let name = admin_page::suggested_backup_name(&Self::today());
        match &self.home {
            Some(home) => home.join(name).display().to_string(),
            None => name,
        }
    }

    /// BACK UP…: ask the portal where to save it. The answer is polled each
    /// frame (`poll_picker`), so the window never waits for the dialog.
    fn pick_backup(&mut self, ctx: &egui::Context) {
        if self.picking.is_some() || self.running.is_some() || self.waiting.is_some() {
            return;
        }
        self.backup_error = None;
        let suggested = admin_page::suggested_backup_name(&Self::today());
        self.picking = Some(self.picker.start(suggested, self.home.clone()));
        ctx.request_repaint();
    }

    /// "type a path instead": the typed-path field, prefilled.
    fn type_backup_path(&mut self) {
        if self.running.is_none() && self.waiting.is_none() {
            self.backup_error = None;
            self.backup_path = Some(self.suggested_path());
        }
    }

    /// The dialog's answer, if it has come.
    fn poll_picker(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.picking else {
            return;
        };
        match rx.try_recv() {
            Ok(Pick::Chosen(path)) => {
                self.picking = None;
                self.backup_to(ctx, &path.display().to_string());
            }
            Ok(Pick::Cancelled) => self.picking = None,
            Ok(Pick::Unavailable) => {
                // (No portal to ask: the person types the path.)
                self.picking = None;
                self.backup_path = Some(self.suggested_path());
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
            // (The dialog's thread ended with no answer.)
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.picking = None;
                self.backup_path = Some(self.suggested_path());
            }
        }
    }

    /// Make the backup's file at `path` and run the backup (unlocking first
    /// if the vault is sealed). A path that cannot be used says why and
    /// leaves the typed-path field open.
    fn backup_to(&mut self, ctx: &egui::Context, path: &str) {
        match BackupTarget::open(std::path::Path::new(path)) {
            Ok(target) => {
                self.backup_error = None;
                self.backup_path = None;
                self.begin(ctx, Job::Admin(AdminOp::Backup(target)));
            }
            Err(e) => {
                self.status = Some(e.clone());
                self.backup_error = Some(e);
                self.backup_path = Some(path.to_string());
            }
        }
    }
```

   (`date` is this file's own `pub fn date`.) Call `self.poll_picker(&ui.ctx().clone());` in `frame` right after `self.resume_job(..)`.

5. **The file must go when a waiting job is dropped.** `BackupTarget` removes itself in `Drop`, so every route that drops the `Job` (`self.waiting.take()` on a dismissed or failed unlock, on `!up`, `self.running.take()` on cancel or interruption, the job value dropped at the end of `job_finished`) cleans up. Check that **no path keeps a `Job::Admin(Backup)` alive after its operation ended** (for example a clone or a stored copy): there is none in this plan, and the tests above prove it.

6. On leaving the ADMIN page, forget the field: in the page-switch branch that Task 5 added, also set `self.backup_path = None; self.backup_error = None;`.

- [ ] **Step 8: Run and iterate until the tests pass**

Run: `cargo test -p aleph-gui`
Expected: PASS. Likely snags: the fake picker's answer arrives at once, so one `settle` after the click is enough; `BACK UP` (the field's button) and `BACK UP…` (the page's) are different labels; the file handle `drop` order in `a_cancelled_backup_removes_the_empty_file_it_made` (the manager holds its own copy of the file until the job drops: the `settle` after `drop(fd)` lets the socket close and `job_finished` run).

- [ ] **Step 9: Commit**

```bash
cargo fmt --all && cargo clippy -p aleph-gui --all-targets -- -D warnings
git add crates/aleph-gui
git commit -m 'feat(gui): BACK UP: the portal save dialog, the typed-path fallback, and the care of the file' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 7: Snapshots, manual checks, decisions, the gate

**Files:**
- Modify: `crates/aleph-gui/tests/manager.rs` (`snapshots`)
- Create: new PNGs under `crates/aleph-gui/tests/snapshots/`
- Modify: `docs/testing.md`, `DECISIONS.md`
- Modify: `docs/superpowers/specs/2026-09-26-aleph-design.md` (§7's Admin bullet), `docs/superpowers/specs/2026-09-28-aleph-manager-design.md` (the 5d row), `docs/superpowers/specs/2026-09-28-aleph-admin-design.md` (Status)

**Interfaces:**
- Consumes: everything above; the helpers `window`, `window_with`, `open_admin`, `admin_status`, `backup_window`, `settle`, `frames`, `only`.
- Produces: snapshots `manager_admin_{neon,omarchy}`, `manager_admin_sealed_{..}`, `manager_admin_warnings_{..}`, `manager_admin_ask_{..}`, `manager_admin_path_{..}`; the manual checks; the decisions.

- [ ] **Step 1: Add the views to `snapshots`**

Inside the per-theme loop of `snapshots()` (after the settings shots), matching how those are written (`shot(&mut h, "name")`):

```rust
        // ADMIN: the page, sealed, with warnings, a Yes/No step, the typed path.
        let (mut h, store, _) = window(theme, vault());
        open_admin(&mut h, &store, admin_status());
        shot(&mut h, "admin");
        h.get_by_label("Remove keyslot yubikey").click();
        frames(&mut h);
        shot(&mut h, "admin_ask");
        let (mut h, store, _) = window(theme, Vault::Locked);
        open_admin(&mut h, &store, admin_status());
        shot(&mut h, "admin_sealed");
        let (mut h, store, _) = window(theme, vault());
        let mut s = admin_status();
        s.untrusted = Some("rolled back to an older version".into());
        s.rotation_pending = true;
        s.secret_service = Some("another program".into());
        open_admin(&mut h, &store, s);
        shot(&mut h, "admin_warnings");
        let (mut h, store, _) = window(theme, vault());
        open_admin(&mut h, &store, admin_status());
        h.get_by_label("type a path instead").click();
        frames(&mut h);
        shot(&mut h, "admin_path");
```

(The date is not part of any of these views except the slot rows' created dates, which are fixed in the fixture and rendered by `date()`. The typed-path field is prefilled with today's date in the suggested name: to keep the snapshot stable, make `backup_path` shots type a fixed path first, or drop `admin_path`'s prefill by setting the field with `type_into(.., "/home/u/aleph-backup.aleph")` after clearing; do whichever is simpler and say which.)

- [ ] **Step 2: Generate, then look at every new image**

Run: `UPDATE_SNAPSHOTS=1 cargo test -p aleph-gui --test manager snapshots; cargo test -p aleph-gui --test manager snapshots`
Expected: the second run PASSES. Read each new PNG in `crates/aleph-gui/tests/snapshots/manager_admin*_neon.png` and check: the STATUS header reads `STATUS  // alephd`; the two fact lines and, in `admin_warnings`, both warnings and ROTATE NOW, and the foreign owner in the warning colour; the slot rows (REMOVE on tpm, yubikey and login password, none on recovery; STALE and RETRY on the login-password row); `+ TPM`, `+ SECURITY KEY`, `touch alone`; the three custody buttons and `type a path instead`; `admin_sealed` shows `VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST` above the slot rows; `admin_ask` shows the REMOVE wording with No and Yes; `admin_path` shows the path field with BACK UP and CANCEL. Nothing clipped at 900 x 560 (the page scrolls). Fix the layout (smallest change), regenerate, and say so in the report.

- [ ] **Step 3: The manual checks**

Append to `docs/testing.md`, after "The manager's settings (Plan 5c)":

```markdown
### The manager's admin page (Plan 5d)

After `make && make install`, on the account aleph serves, with the test
YubiKey plugged in. Keep the terminal open with `alephctl status` to
compare.

1. Open the manager, then ADMIN: the STATUS lines and the slot list match
   `alephctl status` and `alephctl keyslot list`.
2. `+ SECURITY KEY`: alephd's confirmation opens in the window (PIN, touch);
   afterwards `KEYSLOT ADDED` and the new slot in the list. Try a wrong PIN
   once: it says so and costs one retry.
3. REMOVE the key just added: the Yes/No step first (No leaves it); Yes, then
   the confirmation; `KEYSLOT REMOVED`, the slot gone.
4. `+ TPM` (only if a TPM slot is missing), then REMOVE it again.
5. ROTATE MASTER KEY: one confirmation, `MASTER KEY ROTATED`; the vault
   still unlocks (`alephctl lock`, then unlock).
6. NEW RECOVERY KEY: the Yes/No step, the confirmation, the new key shown
   once; write it down (the old one stops working), type two groups back;
   `NEW RECOVERY KEY ISSUED`.
7. BACK UP…: the portal's save dialog opens with `aleph-backup-<date>.aleph`;
   save into a new file: `BACKED UP :: <path>`; the file is mode 600 and not
   empty. Repeat with an existing file: "choose a new name", the file
   untouched. Cancel the dialog: nothing happens.
8. Stop the portal (`systemctl --user stop xdg-desktop-portal.service`,
   after noting whether it was running), then BACK UP…: the typed-path
   field appears, prefilled; a new path works. Start the portal again.
9. `alephctl lock`, then ADMIN: STATUS and the slots show; the banner
   `VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST`; press ROTATE MASTER
   KEY: alephd's unlock window opens, then the confirmation (two proofs).
   Dismiss the unlock on a second try: `nothing was changed`.
10. Stop alephd (`systemctl --user stop alephd.service alephd.socket`, then
    start them): while it is down the page says LINK DOWN; it reads again
    when the link returns.
```

- [ ] **Step 4: Decisions and specs**

1. `DECISIONS.md`: read the last section for the numbering and style, then add a Plan 5d section with the admin spec's "Decisions" list (six lines) verbatim in the file's style.
2. Main spec `2026-09-26-aleph-design.md` §7: the "Admin (Plan 5d)" bullet becomes: "**Admin (Plan 5d):** status, keyslots (add TPM or security key, remove, retry), master-key rotation, recovery-key reissue and backup, through alephd's own re-authentication. Restore, recover, `--from-bak` and `--accept-rollback` stay in `alephctl restore`."
3. Manager spec `2026-09-28-aleph-manager-design.md`: the 5d row of the plan table gets the same scope wording (restore excluded).
4. Admin spec: change `Status:` to `Approved; implemented by docs/superpowers/plans/2026-09-28-aleph-admin.md`.

- [ ] **Step 5: The gate**

Run: `make gate` (in the background, output to a file under the session scratchpad; read its tail). Expected: fmt, clippy `-D warnings`, the whole workspace suite PASS. Known timing-flaky: `screens::a_held_password_is_sent_once_the_back_off_ends` (rerun it alone, then the gate once more). If a run fails with `Disk quota exceeded` in `/tmp`, that is the machine's `/tmp` filling with build output: free space you created and rerun, and say so.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m 'docs,test(gui): snapshots of the admin page, manual checks, decisions' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

## Self-review

**Spec coverage.**
- Scope (status, keyslots add/remove/retry, rotate, reissue, backup; restore excluded): Tasks 3, 5, 6; docs Task 7.
- alephd unchanged: no task touches it (the store tests in Task 3 run against the real one).
- Store requests and `AdminStatus`/`SlotInfo`: Task 3. `Status` refresh rules (page open, after every operation, lock/unlock, link return; no timer): Task 5 (`ask_status`, Vault arm, `Done`/`job_finished`, `save_interrupted`).
- One task state machine, shared by reveal, settings and admin: Task 2 (refactor) and Task 5 (`Job::Admin`); the 5c tests guard it.
- Screen: STATUS (facts, two warnings, no-vault text, ROTATE NOW), KEYSLOTS (rows, REMOVE not on recovery, RETRY on stale, adds, touch-alone warning), KEEPING IT SAFE: Tasks 4–5. Sealed banner and unlock-first, RETRY not unlocking: Tasks 4–5. Yes/No steps with No default and the exact words: Tasks 4–5. NEW RECOVERY KEY via the embedded prompter screen: Task 5 (no manager code touches the key).
- BACK UP… (portal dialog, dated suggestion, create-new 0600, existing non-empty refused, unlock first, `BACKED UP` text; portal decided by bus-name owner; typed-path fallback; "type a path instead"; dialog on its own thread): Tasks 1, 6.
- Errors (status read fails + RETRY; link down; refusals; backup cleanup; interruption wording; nothing silent): Tasks 5–6.
- Security (manager decides nothing; recovery key never held; 0600, never overwritten; logs name operations only): Tasks 3, 5, 6 (no new logging beyond `Request::name`).
- Dependency spike with the stop rule: Task 1, Step 1.
- Testing list, snapshots, manual checks: Tasks 1–7.

**Placeholders.** None. Where an API could not be checked without compiling (`rfd`'s builder names, zbus `call` bounds, `Escape` in the embedded prompter, the fake picker behind `Arc`), the step says what to change and to record it.

**Type consistency.** `Job::{Settings, Admin}`, `AdminOp::{AddTpm, AddFido2, Remove, RotateMaster, NewRecoveryKey, Backup}`, `Running::{Reveal, Job}`, `Manager::{running, waiting, begin, start_job, resume_job, job_finished, save_interrupted(&Job)}`, `AdminState`, `Ask`, `Link`, `AdminView`, `AdminAction`, `BackupField`, `FilePicker::start`, `Pick`, `BackupTarget::{open, file}`, `Request::{Status, AddTpm, AddFido2, RemoveKeyslot, RetryKeyslot, RotateMaster, ReissueRecovery, Backup}` and the request names (`"read the status"`, `"add the TPM slot"`, `"add the security key"`, `"remove the keyslot"`, `"retry the keyslot"`, `"rotate the master key"`, `"issue a new recovery key"`, `"back up"`) are used identically in every task that names them. `AdminOp::request` is `-> Request` in Task 5 and `-> Result<Request, String>` from Task 6 (Task 6 says to change Task 5's `start_job` with it).
