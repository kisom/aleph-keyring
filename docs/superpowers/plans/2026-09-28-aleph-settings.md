# aleph manager settings (Plan 5c) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The manager's `SETTINGS` screen: a VAULT section (alephd's `config.toml`: lock on suspend, lock on screen lock, idle lock, prompt timeout) saved with one confirmation, and a DISPLAY section (`gui.toml`: theme, scanlines, reveal hold) that applies at once.

**Architecture:** alephd gains an admin method `SetConfigs(prompter, a{ss})` that checks every pair, re-authenticates once, applies all pairs to the live configuration and saves once. `aleph-gui` gains store requests `Config` and `SetConfigs`, a writable `gui.toml` (`Settings::save`, new `reveal_hold`), a form model with presets and typed-minute checking (`settings_page.rs`), and a `Page::Settings` screen in the manager that draws the confirmation in the window as the reveal guard does.

**Tech Stack:** Rust 2024, zbus (D-Bus, `a{ss}` as `BTreeMap<String, String>`), egui/eframe 0.36, egui_kittest (window tests and PNG snapshots), toml 1 (serde), tempfile (tests).

**Spec:** `docs/superpowers/specs/2026-09-28-aleph-settings-design.md` (read it first; commit `f93fd6a` corrects it: **Save needs an unlocked vault, so a locked one is unlocked first**, because alephd's `Keyring::reauth` returns `Error::Locked` on a locked vault). Extends `docs/superpowers/specs/2026-09-28-aleph-manager-design.md` and `docs/superpowers/specs/2026-09-26-aleph-design.md` §7.

## Global Constraints

- Rebase and fast-forward only; never a merge commit. Do not push: the owner confirms pushes.
- Commit trailer, on every commit: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (use the trailer the session's system reminder gives if it differs).
- Commit messages go on the command line in **single** quotes (`-m '...'`, no apostrophes in the text): AGENTS.md rule 7 (backticks in double quotes execute).
- Tests never reach the real system: no `systemctl`, `sudo`, `/etc/pam.d`, the real keyring, the real alephd, the real display, the session bus, or the clipboard. `gui.toml` is only ever written under a `tempfile` directory in tests.
- aleph is live on this host: do not restart alephd, reinstall, or edit live units. The user runs `make install`; you never run `sudo`.
- After removing a worktree used for this plan, run `cargo clean -p <pkg>` for each workspace package (`cargo metadata --no-deps` lists them): the target dir is shared.
- Keep the FIDO2 PIN out of every command, file and message.
- Copy rules (verbatim): the line above Save is "Saving asks you to confirm it is you, once (a FIDO2 touch or your login password)."; the DISPLAY header is "DISPLAY  // gui · changes apply now"; the VAULT header is "VAULT  // alephd"; the prompt-timeout error is "whole minutes, 1 to 1440"; the suspend warning is "the master key can reach a hibernation image unless swap is encrypted"; the locked note, beside the buttons while the vault is locked, is "VAULT SEALED :: SAVE WILL UNLOCK FIRST"; success is `SETTINGS SAVED`.
- `prompt.program` is not in the manager. The manager sends only the keys that changed.
- Values: prompt timeout 1 to 86 400 s (typed: 1 to 1440 whole minutes); idle lock 0 (Off) or more (typed: whole minutes, 0 or more); reveal hold 0 to 3600 s (default 300, a larger value in the file is read as 3600).
- Code style: match the surrounding code (comments in parentheses for asides, `//!` module docs that cite the spec, no `unwrap` outside tests). `make gate` (fmt, clippy `-D warnings`, the full suite) must pass at the end of every task that says so.

## Review Focus

Each line has a test in the task named after it.

1. **Another program changes the configuration while the form is open** (`alephctl config set`): `SetConfigs` must apply the pairs to alephd's live configuration as it is then, not to a copy read earlier, so an unrelated earlier change survives. (Task 1)
2. **The configuration file cannot be written** (a read-only directory): the live configuration must stay as it was and the conversation must end `Done { ok: false }`. (Task 1)
3. **Typed minutes that look like numbers but are not**: empty, `0` for the prompt timeout, ` 15 ` (spaces), `+5`, `-1`, `1e3`, `１５` (full-width digits), and one so large that `× 60` would overflow: all rejected, none panics. (Task 4)
4. **A hand-edited `gui.toml`**: `reveal_hold` above 3600, a value that is not a preset, and a broken file: read as 3600, shown as `Custom (N s)`, and never overwritten. (Tasks 2, 6)
5. **The vault locks, the window loses focus, or alephd refuses, while the confirmation is on screen; or the unlock Save asked for is dismissed**: the edits stay, the window says nothing was saved, and Save cannot fire twice (and a later unlock by something else does not resume a dropped save). (Task 5)

---

## File Structure

- Modify `crates/aleph-daemon/src/config.rs`: `Config::set_many` (all or none).
- Modify `crates/aleph-daemon/src/admin.rs`: `SetConfigs`.
- Modify `crates/aleph-daemon/tests/admin.rs`: `SetConfigs` tests through a scripted prompter.
- Modify `crates/aleph-gui/src/settings.rs`: `Serialize`, `reveal_hold`, `save`, `reset`, one shared reader.
- Modify `crates/aleph-gui/src/reauth.rs`: the hold is an argument, not a constant.
- Modify `crates/aleph-gui/src/store.rs`: `Request::Config`, `Request::SetConfigs`, `StoreEvent::Config`, `SETTINGS_KEYS`, an `admin()` proxy helper.
- Modify `crates/aleph-gui/tests/store.rs`: the two requests against a real alephd on a private bus.
- Create `crates/aleph-gui/src/settings_page.rs`: the form model (`Kind`, `Choice`, `Timeout`, `Form`, `Values`), the presets, and the drawing (`vault_section`, `display_section`). No store or manager access.
- Modify `crates/aleph-gui/src/lib.rs`: `pub mod settings_page;`.
- Modify `crates/aleph-gui/src/manager.rs`: `Page`, the nav, `secrets()` (the old screen body), `settings_screen()`, the load/save/confirm wiring, the DISPLAY effects.
- Modify `crates/aleph-gui/src/main.rs`: give the manager the `gui.toml` path and its load warning.
- Modify `crates/aleph-gui/tests/manager.rs`, `tests/screens.rs`, `src/theme.rs` (test): `Settings { .. }` literals gain `..Settings::default()`; new window tests and snapshots.
- Modify `docs/testing.md`, `DECISIONS.md`, the manager spec, the main spec §6/§7, the settings spec status.

---

### Task 1: alephd `SetConfigs`

**Files:**
- Modify: `crates/aleph-daemon/src/config.rs` (add `set_many` after `set`, and its tests)
- Modify: `crates/aleph-daemon/src/admin.rs` (add `set_configs` after `set_config`)
- Test: `crates/aleph-daemon/tests/admin.rs`

**Interfaces:**
- Consumes: `Config::set(&mut self, key: &str, value: &str) -> Result<()>`; `Keyring::with_reauth(chan, operation, f)`; `Admin::converse`.
- Produces: `Config::set_many(&mut self, values: &BTreeMap<String, String>) -> Result<()>` (all or none; an empty map is an error); D-Bus `io.aleph.Admin1.SetConfigs(prompter: h, values: a{ss})` — refuses an empty map or any bad pair before asking; re-authenticates once with the operation text `Set k = v, k2 = v2` (key order); on success applies to the *live* configuration, saves once, ends the conversation with `Done { ok: true, message: None }`.

- [ ] **Step 1: Write the failing unit test for `set_many`**

Add to `mod tests` in `crates/aleph-daemon/src/config.rs`:

```rust
    #[test]
    fn set_many_applies_all_or_none() {
        use std::collections::BTreeMap;
        let pairs = |p: &[(&str, &str)]| -> BTreeMap<String, String> {
            p.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        let mut c = Config::default();
        let before = c.clone();
        // One bad value: nothing changes, not even the good pair.
        assert!(
            c.set_many(&pairs(&[("lock.idle_timeout", "900"), ("prompt.timeout", "0")]))
                .is_err()
        );
        assert_eq!(c, before);
        // An unknown key too, and an empty map.
        assert!(c.set_many(&pairs(&[("lock.idel", "1")])).is_err());
        assert!(c.set_many(&BTreeMap::new()).is_err());
        assert_eq!(c, before);
        c.set_many(&pairs(&[
            ("lock.idle_timeout", "900"),
            ("prompt.timeout", "600"),
            ("lock.on_suspend", "false"),
        ]))
        .unwrap();
        assert_eq!(
            (c.lock.idle_timeout, c.prompt.timeout, c.lock.on_suspend),
            (900, 600, false)
        );
    }
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test -p aleph-daemon --lib config::tests::set_many`
Expected: compile error, `no method named set_many found for struct Config`.

- [ ] **Step 3: Implement `set_many`**

In `config.rs`, add `use std::collections::BTreeMap;` to the imports and, after `fn set`:

```rust
    /// Every pair, or none: on an error `self` is unchanged. An empty map
    /// is an error (there is nothing to confirm).
    pub fn set_many(&mut self, values: &BTreeMap<String, String>) -> Result<()> {
        if values.is_empty() {
            return Err(Error::Config("no settings to change".into()));
        }
        let mut next = self.clone();
        for (key, value) in values {
            next.set(key, value)?;
        }
        *self = next;
        Ok(())
    }
```

- [ ] **Step 4: Run it and watch it pass**

Run: `cargo test -p aleph-daemon --lib config::tests::set_many`
Expected: PASS (1 test).

- [ ] **Step 5: Write the failing admin tests**

In `crates/aleph-daemon/tests/admin.rs` add `use std::collections::BTreeMap;` at the top, then after `setting_config_reauthenticates_and_saves`:

```rust
/// `SetConfigs` with a prompter answering `replies`; what it was sent.
async fn converse_configs(
    d: &Daemon,
    values: &[(&str, &str)],
    replies: Vec<FromPrompter>,
) -> Vec<ToPrompter> {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let prompter = Interactive::new(replies);
    prompter.respond(ours);
    let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
    admin(d)
        .await
        .call_method("SetConfigs", &(fd, map(values)))
        .await
        .unwrap();
    tokio::task::spawn_blocking(move || prompter.sent())
        .await
        .unwrap()
}

fn map(values: &[(&str, &str)]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

async fn get_config(d: &Daemon, key: &str) -> String {
    admin(d).await.call("GetConfig", &(key,)).await.unwrap()
}

/// Several settings change with one confirmation: one `Begin`, one
/// question, the operation naming every change in key order.
#[tokio::test(flavor = "multi_thread")]
async fn several_settings_change_with_one_confirmation() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    let sent = converse_configs(
        &d,
        &[
            ("prompt.timeout", "600"),
            ("lock.on_suspend", "false"),
            ("lock.idle_timeout", "900"),
        ],
        vec![password(PW)],
    )
    .await;
    assert!(done(&sent).0, "{sent:?}");
    let begins: Vec<&ToPrompter> = sent
        .iter()
        .filter(|m| matches!(m, ToPrompter::Begin { .. }))
        .collect();
    assert_eq!(begins.len(), 1, "{sent:?}");
    assert!(matches!(
        begins[0],
        ToPrompter::Begin { operation, .. }
            if operation
                == "Set lock.idle_timeout = 900, lock.on_suspend = false, prompt.timeout = 600"
    ));
    assert_eq!(
        sent.iter()
            .filter(|m| matches!(m, ToPrompter::Ask { .. }))
            .count(),
        1,
        "{sent:?}"
    );
    // No closing message: the window would hold its confirmation open.
    assert_eq!(done(&sent), (true, None));
    assert_eq!(get_config(&d, "lock.idle_timeout").await, "900");
    assert_eq!(get_config(&d, "lock.on_suspend").await, "false");
    assert_eq!(get_config(&d, "prompt.timeout").await, "600");
    let saved = Config::load(&d.paths.config_file).unwrap();
    assert_eq!(
        (saved.lock.idle_timeout, saved.lock.on_suspend, saved.prompt.timeout),
        (900, false, 600)
    );
}

/// A declined confirmation writes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_declined_confirmation_changes_no_setting() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    let sent = converse_configs(
        &d,
        &[("lock.idle_timeout", "900")],
        vec![FromPrompter::Cancel {}],
    )
    .await;
    assert!(!done(&sent).0, "{sent:?}");
    assert_eq!(get_config(&d, "lock.idle_timeout").await, "0");
    assert!(!d.paths.config_file.exists());
}

/// One bad pair, or none at all, is refused before any question.
#[tokio::test(flavor = "multi_thread")]
async fn a_bad_pair_or_an_empty_map_is_refused_before_any_question() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    for values in [
        &[("lock.idle_timeout", "900"), ("prompt.timeout", "0")][..],
        &[("lock.idel", "1")][..],
        &[][..],
    ] {
        let (_ours, theirs) = UnixStream::pair().unwrap();
        let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
        assert!(
            admin(&d)
                .await
                .call_method("SetConfigs", &(fd, map(values)))
                .await
                .is_err(),
            "{values:?}"
        );
    }
    // (Not even the good pair of the first call was applied.)
    assert_eq!(get_config(&d, "lock.idle_timeout").await, "0");
    assert!(!d.paths.config_file.exists());
}

/// Re-authentication needs the vault open, so a locked one refuses.
#[tokio::test(flavor = "multi_thread")]
async fn settings_are_not_saved_while_the_vault_is_locked() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    admin(&d).await.call_method("Lock", &()).await.unwrap();
    let sent = converse_configs(&d, &[("lock.idle_timeout", "900")], vec![]).await;
    assert!(!done(&sent).0, "{sent:?}");
    assert_eq!(get_config(&d, "lock.idle_timeout").await, "0");
    assert!(!d.paths.config_file.exists());
}

/// (Review Focus 1.) The pairs go onto the live configuration as it is
/// when the confirmation ends: a change made by another call in between
/// (`alephctl config set`, say) is not put back.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_call_keeps_an_earlier_change() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    converse(
        &d,
        "SetConfig",
        &["lock.idle_timeout", "900"],
        vec![password(PW)],
    )
    .await;
    let sent = converse_configs(&d, &[("prompt.timeout", "600")], vec![password(PW)]).await;
    assert!(done(&sent).0, "{sent:?}");
    assert_eq!(get_config(&d, "lock.idle_timeout").await, "900");
    assert_eq!(get_config(&d, "prompt.timeout").await, "600");
    let saved = Config::load(&d.paths.config_file).unwrap();
    assert_eq!((saved.lock.idle_timeout, saved.prompt.timeout), (900, 600));
}

/// (Review Focus 2.) A file that cannot be written leaves the live
/// configuration as it was, and the conversation ends in failure.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_save_leaves_the_live_configuration_alone() {
    use std::os::unix::fs::PermissionsExt;
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    let dir = d.paths.config_file.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let sent = converse_configs(&d, &[("lock.idle_timeout", "900")], vec![password(PW)]).await;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!done(&sent).0, "{sent:?}");
    assert_eq!(get_config(&d, "lock.idle_timeout").await, "0");
    assert!(!d.paths.config_file.exists());
}
```

- [ ] **Step 6: Run them and watch them fail**

Run: `cargo test -p aleph-daemon --test admin setting`
Expected: the new tests FAIL (`SetConfigs` unknown method: `call_method(...).unwrap()` panics with an `UnknownMethod` error); `setting_config_reauthenticates_and_saves` still passes. If `a_failed_save_leaves_the_live_configuration_alone` passes even after Step 7's implementation but fails to make the directory unwritable (running as root), note it in the ledger and skip that one test with `if unsafe { libc::geteuid() } == 0 { return; }` (libc is already a dependency of the workspace; add it to `[dev-dependencies]` only if it is not).

- [ ] **Step 7: Implement `SetConfigs`**

In `crates/aleph-daemon/src/admin.rs` add `use std::collections::BTreeMap;` to the imports and, after `set_config`:

```rust
    /// Change several settings on one confirmation (the manager's SAVE):
    /// every pair is checked before anything is asked, and all are applied
    /// to the live configuration and saved once, or none is.
    async fn set_configs(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        values: BTreeMap<String, String>,
    ) -> zbus::fdo::Result<()> {
        // Reject a bad key or value (or nothing at all) now.
        self.config
            .lock()
            .unwrap()
            .clone()
            .set_many(&values)
            .map_err(failed)?;
        let operation = format!(
            "Set {}",
            values
                .iter()
                .map(|(k, v)| format!("{k} = {v}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let (config, file) = (self.config.clone(), self.paths.config_file.clone());
        self.converse(prompter, move |k, chan| {
            k.with_reauth(chan, &operation, || {
                // (The configuration as it is now, not the copy checked above:
                // a change made meanwhile stays.)
                let mut current = config.lock().unwrap();
                let mut next = current.clone();
                next.set_many(&values)?;
                next.save(&file)?;
                *current = next;
                // (Keys only, never values.)
                tracing::info!(
                    "settings changed: {}",
                    values.keys().cloned().collect::<Vec<_>>().join(", ")
                );
                // (No message: the manager's confirmation would stay up for it.)
                Ok(None)
            })
        })
    }
```

- [ ] **Step 8: Run the tests and watch them pass**

Run: `cargo test -p aleph-daemon --test admin && cargo test -p aleph-daemon --lib config::`
Expected: all PASS (including the six new admin tests and `set_many_applies_all_or_none`).

- [ ] **Step 9: Commit**

```bash
cargo fmt --all && cargo clippy -p aleph-daemon --all-targets -- -D warnings
git add crates/aleph-daemon
git commit -m 'feat(alephd): SetConfigs changes several settings on one confirmation' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 2: `gui.toml` is writable, and the reveal hold is a setting

**Files:**
- Modify: `crates/aleph-gui/src/settings.rs`
- Modify: `crates/aleph-gui/src/reauth.rs`
- Modify: `crates/aleph-gui/src/manager.rs` (one call site: `want`)
- Modify (compile fixes): `crates/aleph-gui/tests/manager.rs:111`, `crates/aleph-gui/tests/screens.rs:54`, `crates/aleph-gui/src/theme.rs:292`
- Test: unit tests in `settings.rs` and `reauth.rs`

**Interfaces:**
- Consumes: `toml` and `serde` (already dependencies).
- Produces:
  - `Settings { theme: ThemeChoice, scanlines: bool, reveal_hold: u64 }` — `Serialize + Deserialize`; `reveal_hold` in seconds, default `DEFAULT_REVEAL_HOLD` (300), read clamped to `MAX_REVEAL_HOLD` (3600).
  - `pub const MAX_REVEAL_HOLD: u64 = 3600; pub const DEFAULT_REVEAL_HOLD: u64 = 300;`
  - `Settings::load(path) -> (Settings, Option<String>)` (unchanged behavior).
  - `Settings::save(&self, path: &Path) -> Result<(), String>` — atomic (temp file, rename, creates the directory); **refuses (Err) if the file exists and does not read as settings**, leaving it untouched.
  - `Settings::reset(path: &Path) -> Result<(), String>` — writes the defaults over whatever is there (the broken-file button).
  - `Reauth::needed(&self, now: Instant, hold: Duration) -> bool` (`hold == 0`: always true); `Reauth::confirmed(&mut self, now)`; `Reauth::forget(&mut self)`. The `HOLD` constant is removed.

- [ ] **Step 1: Write the failing settings tests**

Replace the two `Settings {` literals' need first: in `settings.rs` `mod tests`, change `settings_are_read_and_typos_warned_about`'s expected value to

```rust
            Settings {
                theme: ThemeChoice::Neon,
                scanlines: false,
                ..Settings::default()
            }
```

and add:

```rust
    #[test]
    fn the_reveal_hold_defaults_to_five_minutes_and_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gui.toml");
        assert_eq!(Settings::load(&file).0.reveal_hold, 300);
        for (text, want) in [
            ("reveal_hold = 900\n", 900),
            ("reveal_hold = 0\n", 0),
            ("reveal_hold = 3600\n", 3600),
            // (A larger value, hand-edited, is read as the largest.)
            ("reveal_hold = 99999\n", 3600),
            ("scanlines = false\n", 300),
        ] {
            std::fs::write(&file, text).unwrap();
            assert_eq!(Settings::load(&file).0.reveal_hold, want, "{text}");
        }
        std::fs::write(&file, "reveal_hold = -1\n").unwrap();
        assert!(Settings::load(&file).1.is_some());
    }

    #[test]
    fn saved_settings_read_back_and_the_directory_is_made() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("aleph/gui.toml");
        let s = Settings {
            theme: ThemeChoice::Neon,
            scanlines: false,
            reveal_hold: 900,
        };
        s.save(&file).unwrap();
        assert_eq!(Settings::load(&file), (s.clone(), None));
        // Saving again over a good file is fine.
        Settings { reveal_hold: 0, ..s }.save(&file).unwrap();
        assert_eq!(Settings::load(&file).0.reveal_hold, 0);
    }

    /// (Review Focus 4.) A file that does not read as settings is the
    /// owner's to fix: saving never overwrites it.
    #[test]
    fn a_broken_file_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gui.toml");
        std::fs::write(&file, "scanline = false\n# my note\n").unwrap();
        let e = Settings::default().save(&file).unwrap_err();
        assert!(e.contains("gui.toml") && e.contains("scanline"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "scanline = false\n# my note\n"
        );
        // Reset is the way out: it writes the defaults.
        Settings::reset(&file).unwrap();
        assert_eq!(Settings::load(&file), (Settings::default(), None));
    }
```

- [ ] **Step 2: Write the failing reauth test**

Replace the test in `reauth.rs` with:

```rust
    #[test]
    fn a_confirmation_holds_for_the_setting_and_not_past_a_lock() {
        let t = Instant::now();
        let hold = Duration::from_secs(300);
        let mut r = Reauth::default();
        assert!(r.needed(t, hold));
        r.confirmed(t);
        assert!(!r.needed(t + Duration::from_secs(299), hold));
        assert!(r.needed(t + hold, hold));
        // A shorter hold applies at once, to a confirmation already given.
        assert!(r.needed(t + Duration::from_secs(120), Duration::from_secs(60)));
        // Zero: every time, even right after a confirmation.
        assert!(r.needed(t, Duration::ZERO));
        r.confirmed(t);
        r.forget();
        assert!(r.needed(t, hold));
    }
```

- [ ] **Step 3: Run them and watch them fail**

Run: `cargo test -p aleph-gui --lib settings:: reauth::`
Expected: compile errors (`no field reveal_hold`, `save`/`reset` missing, `needed` takes 1 argument).

- [ ] **Step 4: Implement `settings.rs`**

Replace the top of the file through `impl Settings { .. load .. }` with:

```rust
//! The GUI's own settings, `~/.config/aleph/gui.toml` (spec §7 "Theme";
//! the settings spec for the reveal hold and for writing the file).
//!
//! A file of their own: alephd's `config.toml` refuses unknown keys, and
//! alephd has no use for these.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    /// The current Omarchy theme where there is one, else Aleph neon.
    #[default]
    Auto,
    /// Aleph neon everywhere.
    Neon,
}

/// The longest a confirmation may hold, in seconds (an hour).
pub const MAX_REVEAL_HOLD: u64 = 3600;
/// How long one holds unless the file says otherwise (5 minutes).
pub const DEFAULT_REVEAL_HOLD: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub theme: ThemeChoice,
    /// The scanline overlay (off anyway when reduced motion is asked for).
    pub scanlines: bool,
    /// Seconds a confirmation lets secrets be shown without another; 0 is
    /// every time. A larger value in the file is read as
    /// [`MAX_REVEAL_HOLD`].
    #[serde(deserialize_with = "capped_hold")]
    pub reveal_hold: u64,
}

fn capped_hold<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    Ok(u64::deserialize(d)?.min(MAX_REVEAL_HOLD))
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::Auto,
            scanlines: true,
            reveal_hold: DEFAULT_REVEAL_HOLD,
        }
    }
}

impl Settings {
    /// The file's settings; the defaults if it is missing, and (with a
    /// warning) if it is unreadable: a prompt must still open.
    pub fn load(path: &Path) -> (Self, Option<String>) {
        match Self::read(path) {
            Ok(s) => (s, None),
            Err(e) => (Self::default(), Some(format!("{e} (using the defaults)"))),
        }
    }

    /// The file's settings, the defaults if it does not exist, and an
    /// error naming the file if it cannot be read as settings.
    fn read(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Write the settings. A file that does not read as settings is never
    /// overwritten (the owner fixes it, or resets it). Comments in the
    /// file are lost: the whole file is rewritten.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        Self::read(path)?;
        self.write(path)
    }

    /// The defaults, over whatever is there (the broken-file button).
    pub fn reset(path: &Path) -> Result<(), String> {
        Self::default().write(path)
    }

    /// Atomically: a temp file, then a rename; the directory is created.
    fn write(&self, path: &Path) -> Result<(), String> {
        let at = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
        let dir = path.parent().ok_or_else(|| at(&"no directory"))?;
        std::fs::create_dir_all(dir).map_err(|e| at(&e))?;
        let text = toml::to_string(self).map_err(|e| at(&e))?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text).map_err(|e| at(&e))?;
        std::fs::rename(&tmp, path).map_err(|e| at(&e))
    }
}
```

(Leave `path()`, `config_home()`, `home()`, `reduced_motion()`, `animations_off` as they are.)

- [ ] **Step 5: Implement `reauth.rs`**

```rust
//! The reveal guard's clock (the manager spec, "What each action does"):
//! a confirmation holds for the `reveal_hold` setting (5 minutes unless
//! changed; 0 asks every time), and not past a lock. A guard against a
//! glance, not security: any program running as the user can read secrets.

use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct Reauth {
    confirmed: Option<Instant>,
}

impl Reauth {
    /// Whether showing or copying needs a confirmation first, when one
    /// holds for `hold` (read at each check: a shorter hold ends an older
    /// confirmation at once).
    pub fn needed(&self, now: Instant, hold: Duration) -> bool {
        hold.is_zero()
            || self
                .confirmed
                .is_none_or(|at| now.duration_since(at) >= hold)
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

(Keep the test module from Step 2.)

- [ ] **Step 6: Fix the call site and the literals**

In `manager.rs` `fn want`: `if self.reauth.needed(now, Duration::from_secs(self.settings.reveal_hold)) {`.

Add `..Settings::default()` to the three literals: `tests/manager.rs` (`window_sized`: `Settings { theme, scanlines: true, ..Settings::default() }`), `tests/screens.rs:54`, and `theme.rs:292` (`neon_setting`). Grep for any other: `grep -rn "Settings {" crates`.

- [ ] **Step 7: Run and watch it pass**

Run: `cargo test -p aleph-gui --lib && cargo test -p aleph-gui --test manager --test screens`
Expected: PASS. (`snapshots` in `tests/manager.rs` still passes: nothing drawn changed.)

- [ ] **Step 8: Commit**

```bash
cargo fmt --all && cargo clippy -p aleph-gui --all-targets -- -D warnings
git add crates/aleph-gui
git commit -m 'feat(gui): gui.toml is writable and the reveal hold is a setting' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 3: The store reads and saves settings

**Files:**
- Modify: `crates/aleph-gui/src/store.rs`
- Test: `crates/aleph-gui/tests/store.rs`

**Interfaces:**
- Consumes: alephd's `GetConfig(key) -> s` and `SetConfigs(h, a{ss})` (Task 1).
- Produces:
  - `pub const SETTINGS_KEYS: [&str; 4] = ["lock.on_suspend", "lock.on_screen_lock", "lock.idle_timeout", "prompt.timeout"];`
  - `Request::Config` (name `"read the settings"`); `Request::SetConfigs(OwnedFd, BTreeMap<String, String>)` (name `"save the settings"`). Neither is `changes()`.
  - `StoreEvent::Config(Result<BTreeMap<String, String>, String>)`: the four keys' values, or the reason. Sent for `Request::Config` only, always followed by the usual `Done`.
  - For `SetConfigs` the store's `Done` reports the *call* (`error: Some(..)` if alephd refused before asking); the confirmation's outcome arrives on the socket.

- [ ] **Step 1: Write the failing store tests**

In `crates/aleph-gui/tests/store.rs`, add `use std::os::unix::net::UnixStream;` if absent, and after `reauth_converses_on_the_windows_socket`:

```rust
/// The four VAULT settings are read; a save runs on the window's socket
/// with one confirmation and changes alephd's configuration and file.
#[tokio::test(flavor = "multi_thread")]
async fn settings_are_read_and_saved_through_alephd() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    let read = |store: &mut Probe| {
        store.request(Request::Config);
    };
    read(&mut store);
    let values = store
        .until(|e| match e {
            StoreEvent::Config(Ok(v)) => Some(v.clone()),
            _ => None,
        })
        .await;
    assert_eq!(values.len(), 4, "{values:?}");
    assert_eq!(values["lock.idle_timeout"], "0");
    assert_eq!(values["prompt.timeout"], "300");
    assert_eq!(values["lock.on_suspend"], "true");
    assert_eq!(store.done("read the settings").await, (None, false));

    let (ours, theirs) = UnixStream::pair().unwrap();
    let prompter = Interactive::new(vec![password(PW)]);
    prompter.respond(ours);
    store.request(Request::SetConfigs(
        theirs.into(),
        BTreeMap::from([
            ("lock.idle_timeout".to_string(), "900".to_string()),
            ("lock.on_suspend".to_string(), "false".to_string()),
        ]),
    ));
    assert_eq!(store.done("save the settings").await.0, None);
    let sent = tokio::task::spawn_blocking(move || prompter.sent())
        .await
        .unwrap();
    assert!(
        matches!(
            sent.last(),
            Some(aleph_daemon::testing::ToPrompter::Done { ok: true, message: None })
        ),
        "{sent:?}"
    );
    read(&mut store);
    let values = store
        .until(|e| match e {
            StoreEvent::Config(Ok(v)) => Some(v.clone()),
            _ => None,
        })
        .await;
    assert_eq!(values["lock.idle_timeout"], "900");
    assert_eq!(values["lock.on_suspend"], "false");
    assert_eq!(values["prompt.timeout"], "300");
    let saved = aleph_daemon::config::Config::load(&d.env.paths.config_file).unwrap();
    assert_eq!(saved.lock.idle_timeout, 900);
}

/// A bad value is refused by alephd before it asks anything: the call's
/// `Done` carries the reason, and nothing changed.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_settings_save_says_why() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    let (_ours, theirs) = UnixStream::pair().unwrap();
    store.request(Request::SetConfigs(
        theirs.into(),
        BTreeMap::from([("prompt.timeout".to_string(), "0".to_string())]),
    ));
    let (error, dismissed) = store.done("save the settings").await;
    assert!(error.unwrap().contains("prompt.timeout"), "refused");
    assert!(!dismissed);
    assert!(!d.env.paths.config_file.exists());
}

/// Without alephd the read fails with a reason (and the window retries).
#[tokio::test(flavor = "multi_thread")]
async fn without_alephd_reading_the_settings_fails() {
    let bus = aleph_daemon::testing::bus();
    let mut store = Probe::new(&bus.address);
    store.request(Request::Config);
    store
        .until(|e| matches!(e, StoreEvent::Config(Err(_))).then_some(()))
        .await;
    assert!(store.done("read the settings").await.0.is_some());
}

#[test]
fn settings_requests_are_not_followed_by_a_listing() {
    assert!(!Request::Config.changes());
    let (ours, _theirs) = UnixStream::pair().unwrap();
    assert!(!Request::SetConfigs(ours.into(), BTreeMap::new()).changes());
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p aleph-gui --test store settings`
Expected: compile error: no variant `Config` on `Request` / `StoreEvent`.

- [ ] **Step 3: Implement**

In `store.rs`:

1. After the `ADMIN` const add:

```rust
/// The settings the manager's VAULT section shows (alephd's keys).
pub const SETTINGS_KEYS: [&str; 4] = [
    "lock.on_suspend",
    "lock.on_screen_lock",
    "lock.idle_timeout",
    "prompt.timeout",
];
```

2. In `enum Request`, after `Reauth(OwnedFd)`:

```rust
    /// Read the four VAULT settings from alephd (`StoreEvent::Config`).
    Config,
    /// Change settings: alephd checks them, then converses on this end of
    /// a socketpair (one confirmation for all); the window answers on the
    /// other. Only the keys that changed are sent.
    SetConfigs(OwnedFd, BTreeMap<String, String>),
```

3. `changes()`: `!matches!(self, Self::Secret(_) | Self::Reauth(_) | Self::Config | Self::SetConfigs(..))`; `name()`: `Self::Config => "read the settings"`, `Self::SetConfigs(..) => "save the settings"`.

4. In `enum StoreEvent`, after `SecretFailed`:

```rust
    /// The four VAULT settings (`Request::Config`), or why they could not
    /// be read (a `Done` follows either way).
    Config(Result<BTreeMap<String, String>, String>),
```

5. In `impl Client`, add before `handle`:

```rust
    /// alephd's admin interface.
    async fn admin(&self) -> Result<zbus::Proxy<'static>, String> {
        zbus::proxy::Builder::<zbus::Proxy>::new(&self.conn)
            .destination(ADMIN_NAME)
            .map_err(err)?
            .path(ADMIN_PATH)
            .map_err(err)?
            .interface(ADMIN)
            .map_err(err)?
            .build()
            .await
            .map_err(err)
    }
```

6. Replace the body of `Request::Reauth(fd) => { .. }` with

```rust
            Request::Reauth(fd) => {
                self.admin()
                    .await?
                    .call::<_, _, ()>("Reauth", &(zbus::zvariant::OwnedFd::from(fd),))
                    .await
                    .map_err(err)?;
                Ok((false, None))
            }
            Request::Config => {
                let admin = self.admin().await?;
                let mut values = BTreeMap::new();
                for key in SETTINGS_KEYS {
                    let v: String = admin.call("GetConfig", &(key,)).await.map_err(err)?;
                    values.insert(key.to_string(), v);
                }
                Ok((false, Some(StoreEvent::Config(Ok(values)))))
            }
            Request::SetConfigs(fd, values) => {
                self.admin()
                    .await?
                    .call::<_, _, ()>(
                        "SetConfigs",
                        &(zbus::zvariant::OwnedFd::from(fd), values),
                    )
                    .await
                    .map_err(err)?;
                Ok((false, None))
            }
```

7. In `run`, next to `let fetching = ...` add `let reading = matches!(&r, Request::Config);` and in the `Err(e)` branch, after the `if let Some(path) = fetching { .. }` block:

```rust
                            if reading {
                                emit.send(StoreEvent::Config(Err(e.clone())));
                            }
```

- [ ] **Step 4: Run and watch it pass**

Run: `cargo test -p aleph-gui --test store`
Expected: all PASS (existing tests and the four new ones).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy -p aleph-gui --all-targets -- -D warnings
git add crates/aleph-gui
git commit -m 'feat(gui): the store reads settings and saves them on one confirmation' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 4: The settings form model (presets and typed minutes)

**Files:**
- Create: `crates/aleph-gui/src/settings_page.rs` (model only in this task; drawing is added in Tasks 5 and 6)
- Modify: `crates/aleph-gui/src/lib.rs` (`pub mod settings_page;` after `pub mod settings;`)
- Test: unit tests in `settings_page.rs`

**Interfaces:**
- Consumes: `store::SETTINGS_KEYS` values as a `BTreeMap<String, String>`.
- Produces (all `pub`, in `aleph_gui::settings_page`):
  - `enum Kind { Idle, Prompt, Reveal }`; `Kind::presets() -> &'static [u64]` (seconds); `Kind::custom_minutes() -> bool`.
  - `const IDLE_PRESETS, PROMPT_PRESETS, REVEAL_PRESETS: &[u64]`; `const PROMPT_MAX_MINUTES: u64 = 1440`.
  - `fn describe(kind: Kind, secs: u64) -> String`: `Off`, `Every time`, `5 min`, `4 h`, `Custom (7 min)`, `Custom (90 s)`.
  - `enum Choice { Preset(u64), Kept, Custom }`.
  - `struct Timeout { pub kind, pub choice: Choice, pub typed: String, .. }` with `Timeout::new(kind, read_secs)`, `read() -> u64`, `kept_text() -> Option<String>`, `choose_custom(&mut self)`, `value() -> Result<u64, String>` (seconds), `error() -> Option<String>` (only for a non-empty bad entry), `edited() -> bool`, `reset(&mut self)`.
  - `struct Form { pub on_suspend: bool, pub on_screen_lock: bool, pub idle: Timeout, pub prompt: Timeout, .. }` with `Form::from_values(&BTreeMap<String,String>) -> Result<Form, String>`, `changes() -> BTreeMap<String,String>` (only the keys that changed, only valid ones), `valid() -> bool`, `edited() -> bool`, `cancel(&mut self)`.
  - `enum Values { Unknown, Loading, Failed(String), Ready(Form) }`.
  - `const SUSPEND_WARNING`, `SAVE_NOTE`, `LOCKED_NOTE` (the verbatim copy from Global Constraints).

- [ ] **Step 1: Write the failing tests**

Create `crates/aleph-gui/src/settings_page.rs` with the module doc and only the tests (the code comes in Step 3):

```rust
//! The SETTINGS screen (the settings spec, "The screen"): what the VAULT
//! controls hold, the presets, the checking of typed minutes, and the
//! drawing of both sections. It never touches the store or the window:
//! `manager.rs` wires the effects.

use std::collections::BTreeMap;

#[cfg(test)]
mod tests {
    use super::*;

    fn values(idle: &str, prompt: &str, suspend: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("lock.on_suspend".to_string(), suspend.to_string()),
            ("lock.on_screen_lock".to_string(), "true".to_string()),
            ("lock.idle_timeout".to_string(), idle.to_string()),
            ("prompt.timeout".to_string(), prompt.to_string()),
        ])
    }

    fn form(idle: &str, prompt: &str) -> Form {
        Form::from_values(&values(idle, prompt, "true")).unwrap()
    }

    fn typed(kind: Kind, text: &str) -> Result<u64, String> {
        let mut t = Timeout::new(kind, 300);
        t.choose_custom();
        t.typed = text.to_string();
        t.value()
    }

    #[test]
    fn words_for_presets_and_other_values() {
        assert_eq!(describe(Kind::Idle, 0), "Off");
        assert_eq!(describe(Kind::Idle, 900), "15 min");
        assert_eq!(describe(Kind::Idle, 3600), "60 min");
        assert_eq!(describe(Kind::Idle, 14_400), "4 h");
        assert_eq!(describe(Kind::Idle, 7200), "Custom (120 min)");
        assert_eq!(describe(Kind::Idle, 90), "Custom (90 s)");
        assert_eq!(describe(Kind::Prompt, 60), "1 min");
        assert_eq!(describe(Kind::Reveal, 0), "Every time");
        assert_eq!(describe(Kind::Reveal, 300), "5 min");
        assert_eq!(describe(Kind::Reveal, 45), "Custom (45 s)");
    }

    #[test]
    fn a_read_value_is_a_preset_or_kept() {
        let f = form("900", "300");
        assert_eq!(f.idle.choice, Choice::Preset(900));
        assert_eq!(f.prompt.choice, Choice::Preset(300));
        let f = form("7200", "90");
        assert_eq!(f.idle.choice, Choice::Kept);
        assert_eq!(f.idle.kept_text().as_deref(), Some("Custom (120 min)"));
        assert_eq!(f.prompt.kept_text().as_deref(), Some("Custom (90 s)"));
        // Kept is not an edit, and is never sent.
        assert!(!f.edited());
        assert!(f.changes().is_empty());
        assert_eq!(f.idle.value(), Ok(7200));
    }

    #[test]
    fn only_what_changed_is_sent() {
        let mut f = form("0", "300");
        assert!(!f.edited());
        f.idle.choice = Choice::Preset(900);
        f.on_suspend = false;
        assert!(f.edited() && f.valid());
        assert_eq!(
            f.changes(),
            BTreeMap::from([
                ("lock.idle_timeout".to_string(), "900".to_string()),
                ("lock.on_suspend".to_string(), "false".to_string()),
            ])
        );
        // Put back by hand: not an edit any more.
        f.idle.choice = Choice::Preset(0);
        f.on_suspend = true;
        assert!(!f.edited());
        assert!(f.changes().is_empty());
    }

    #[test]
    fn cancel_puts_the_read_values_back() {
        let mut f = form("900", "300");
        f.idle.choose_custom();
        f.idle.typed = "20".into();
        f.on_screen_lock = false;
        assert!(f.edited());
        f.cancel();
        assert!(!f.edited());
        assert_eq!(f.idle.choice, Choice::Preset(900));
        assert!(f.on_screen_lock);
    }

    #[test]
    fn typed_minutes_are_whole_and_in_range() {
        assert_eq!(typed(Kind::Idle, "0"), Ok(0));
        assert_eq!(typed(Kind::Idle, "20"), Ok(1200));
        assert_eq!(typed(Kind::Idle, " 15 "), Ok(900));
        assert_eq!(typed(Kind::Prompt, "1"), Ok(60));
        assert_eq!(typed(Kind::Prompt, "1440"), Ok(86_400));
        let prompt_bad = "whole minutes, 1 to 1440";
        for bad in ["0", "1441", "-1", "+5", "1e3", "1.5", "1 5", "x", "１５", ""] {
            assert_eq!(typed(Kind::Prompt, bad), Err(prompt_bad.to_string()), "{bad:?}");
        }
        // (Review Focus 3.) Too large to multiply, or to parse: refused, no panic.
        let huge = (u64::MAX / 60 + 1).to_string();
        assert!(typed(Kind::Idle, &huge).is_err());
        assert!(typed(Kind::Idle, "99999999999999999999999").is_err());
        assert_eq!(
            typed(Kind::Idle, "x"),
            Err("whole minutes, 0 or more".to_string())
        );
    }

    #[test]
    fn a_bad_entry_disables_saving_and_an_empty_one_only_waits() {
        let mut f = form("0", "300");
        f.prompt.choose_custom();
        // Just chosen: empty. Nothing to complain about yet, but not valid.
        assert_eq!(f.prompt.error(), None);
        assert!(!f.valid());
        assert!(f.edited());
        f.prompt.typed = "1441".into();
        assert_eq!(f.prompt.error().as_deref(), Some("whole minutes, 1 to 1440"));
        assert!(!f.valid());
        f.prompt.typed = "20".into();
        assert_eq!(f.prompt.error(), None);
        assert!(f.valid());
        assert_eq!(f.changes()["prompt.timeout"], "1200");
    }

    #[test]
    fn a_reply_that_cannot_be_read_is_an_error_naming_the_key() {
        let mut v = values("0", "300", "true");
        v.insert("lock.idle_timeout".into(), "soon".into());
        let e = Form::from_values(&v).unwrap_err();
        assert!(e.contains("lock.idle_timeout"), "{e}");
        let mut v = values("0", "300", "maybe");
        assert!(Form::from_values(&v).unwrap_err().contains("lock.on_suspend"));
        v.remove("prompt.timeout");
        assert!(Form::from_values(&v).is_err());
    }
}
```

- [ ] **Step 2: Run it and watch it fail**

Add `pub mod settings_page;` to `lib.rs` (after `pub mod settings;`).
Run: `cargo test -p aleph-gui --lib settings_page`
Expected: compile errors: `Form`, `Timeout`, `Kind`, `describe`, `Choice` not found.

- [ ] **Step 3: Implement the model**

Add above `#[cfg(test)]` in `settings_page.rs`:

```rust
pub const SUSPEND: &str = "lock.on_suspend";
pub const SCREEN_LOCK: &str = "lock.on_screen_lock";
pub const IDLE: &str = "lock.idle_timeout";
pub const PROMPT: &str = "prompt.timeout";

pub const IDLE_PRESETS: &[u64] = &[0, 300, 900, 1800, 3600, 14_400];
pub const PROMPT_PRESETS: &[u64] = &[60, 300, 900, 1800];
pub const REVEAL_PRESETS: &[u64] = &[0, 60, 300, 900, 1800, 3600];
/// alephd's cap on the prompt timeout (86 400 s), in minutes.
pub const PROMPT_MAX_MINUTES: u64 = 1440;

pub const SUSPEND_WARNING: &str =
    "the master key can reach a hibernation image unless swap is encrypted";
pub const SAVE_NOTE: &str = "Saving asks you to confirm it is you, once (a FIDO2 touch or your login password).";
pub const LOCKED_NOTE: &str = "VAULT SEALED :: SAVE WILL UNLOCK FIRST";

/// Which duration a control sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// alephd's idle lock; 0 is off.
    Idle,
    /// How long alephd's questions wait.
    Prompt,
    /// How long a confirmation lets secrets be shown (gui.toml); 0 is every time.
    Reveal,
}

impl Kind {
    /// The list's fixed choices, in seconds.
    pub fn presets(self) -> &'static [u64] {
        match self {
            Self::Idle => IDLE_PRESETS,
            Self::Prompt => PROMPT_PRESETS,
            Self::Reveal => REVEAL_PRESETS,
        }
    }

    /// Whether the list has a "Custom…" entry (the reveal hold has none).
    pub fn custom_minutes(self) -> bool {
        self != Self::Reveal
    }

    /// The whole minutes a typed entry may be, and the words for a bad one.
    fn bounds(self) -> (u64, u64, &'static str) {
        match self {
            // (Up to what `× 60` holds: alephd takes any number of seconds.)
            Self::Idle => (0, u64::MAX / 60, "whole minutes, 0 or more"),
            Self::Prompt => (1, PROMPT_MAX_MINUTES, "whole minutes, 1 to 1440"),
            Self::Reveal => (0, 60, "whole minutes, 0 to 60"),
        }
    }
}

/// A value in words: a preset's name, else `Custom (N min)` or, if it is
/// not whole minutes, `Custom (N s)`.
pub fn describe(kind: Kind, secs: u64) -> String {
    match (kind, secs) {
        (Kind::Idle, 0) => "Off".into(),
        (Kind::Reveal, 0) => "Every time".into(),
        (Kind::Idle, 14_400) => "4 h".into(),
        _ if kind.presets().contains(&secs) => format!("{} min", secs / 60),
        _ if secs % 60 == 0 => format!("Custom ({} min)", secs / 60),
        _ => format!("Custom ({secs} s)"),
    }
}

/// What a duration control is set to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    Preset(u64),
    /// The value read, when it is not a preset: kept unless changed.
    Kept,
    /// Whole minutes, typed.
    Custom,
}

/// One duration control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timeout {
    pub kind: Kind,
    pub choice: Choice,
    /// The minutes typed, while `choice` is `Custom`.
    pub typed: String,
    read: u64,
}

impl Timeout {
    pub fn new(kind: Kind, read: u64) -> Self {
        let choice = if kind.presets().contains(&read) {
            Choice::Preset(read)
        } else {
            Choice::Kept
        };
        Self {
            kind,
            choice,
            typed: String::new(),
            read,
        }
    }

    /// The seconds alephd holds.
    pub fn read(&self) -> u64 {
        self.read
    }

    /// The list's entry for the value read, if it is not a preset.
    pub fn kept_text(&self) -> Option<String> {
        (!self.kind.presets().contains(&self.read)).then(|| describe(self.kind, self.read))
    }

    /// Pick "Custom…": an empty field to type the minutes into.
    pub fn choose_custom(&mut self) {
        if self.choice != Choice::Custom {
            self.choice = Choice::Custom;
            self.typed.clear();
        }
    }

    /// The seconds the control stands for, or the words for a bad entry.
    pub fn value(&self) -> Result<u64, String> {
        match &self.choice {
            Choice::Preset(s) => Ok(*s),
            Choice::Kept => Ok(self.read),
            Choice::Custom => {
                let (low, high, words) = self.kind.bounds();
                let t = self.typed.trim();
                let whole = !t.is_empty() && t.chars().all(|c| c.is_ascii_digit());
                match t.parse::<u64>() {
                    Ok(n) if whole && (low..=high).contains(&n) => Ok(n * 60),
                    _ => Err(words.into()),
                }
            }
        }
    }

    /// What to say under the field: only for something typed, and bad.
    pub fn error(&self) -> Option<String> {
        if self.choice == Choice::Custom && !self.typed.trim().is_empty() {
            self.value().err()
        } else {
            None
        }
    }

    /// Whether it differs from what was read (a bad entry is an edit).
    pub fn edited(&self) -> bool {
        !self.value().is_ok_and(|v| v == self.read)
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.kind, self.read);
    }
}

/// The VAULT section's controls, and what was read (so that only what
/// changed is sent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    pub on_suspend: bool,
    pub on_screen_lock: bool,
    pub idle: Timeout,
    pub prompt: Timeout,
    read_suspend: bool,
    read_screen_lock: bool,
}

impl Form {
    /// From alephd's four values; an error names the one that is wrong.
    pub fn from_values(values: &BTreeMap<String, String>) -> Result<Self, String> {
        let get = |key: &str| {
            values
                .get(key)
                .ok_or_else(|| format!("alephd did not send {key}"))
        };
        let flag = |key: &str| match get(key)?.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(format!("{key}: expected true or false, not {other:?}")),
        };
        let secs = |key: &str| {
            get(key)?
                .parse::<u64>()
                .map_err(|_| format!("{key}: expected a number of seconds"))
        };
        let (suspend, screen_lock) = (flag(SUSPEND)?, flag(SCREEN_LOCK)?);
        Ok(Self {
            on_suspend: suspend,
            on_screen_lock: screen_lock,
            idle: Timeout::new(Kind::Idle, secs(IDLE)?),
            prompt: Timeout::new(Kind::Prompt, secs(PROMPT)?),
            read_suspend: suspend,
            read_screen_lock: screen_lock,
        })
    }

    /// Whether every duration is a usable value (Save waits for it).
    pub fn valid(&self) -> bool {
        self.idle.value().is_ok() && self.prompt.value().is_ok()
    }

    /// Whether anything differs from what was read.
    pub fn edited(&self) -> bool {
        self.on_suspend != self.read_suspend
            || self.on_screen_lock != self.read_screen_lock
            || self.idle.edited()
            || self.prompt.edited()
    }

    /// The keys that changed, as alephd takes them (only valid ones).
    pub fn changes(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        if self.on_suspend != self.read_suspend {
            out.insert(SUSPEND.to_string(), self.on_suspend.to_string());
        }
        if self.on_screen_lock != self.read_screen_lock {
            out.insert(SCREEN_LOCK.to_string(), self.on_screen_lock.to_string());
        }
        for (key, t) in [(IDLE, &self.idle), (PROMPT, &self.prompt)] {
            if let Ok(v) = t.value()
                && v != t.read()
            {
                out.insert(key.to_string(), v.to_string());
            }
        }
        out
    }

    /// Put back what was read.
    pub fn cancel(&mut self) {
        self.on_suspend = self.read_suspend;
        self.on_screen_lock = self.read_screen_lock;
        self.idle.reset();
        self.prompt.reset();
    }
}

/// The VAULT section's data, as far as it has come.
#[derive(Debug)]
pub enum Values {
    /// Not asked for yet (or nothing worth keeping when the link went).
    Unknown,
    Loading,
    Failed(String),
    Ready(Form),
}
```

(Formatting note: `SAVE_NOTE` is over 100 columns; `cargo fmt` leaves string literals alone.)

- [ ] **Step 4: Run and watch it pass**

Run: `cargo test -p aleph-gui --lib settings_page`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy -p aleph-gui --all-targets -- -D warnings
git add crates/aleph-gui
git commit -m 'feat(gui): the settings form model, presets and typed minutes' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 5: The SETTINGS screen, VAULT section

**Files:**
- Modify: `crates/aleph-gui/src/settings_page.rs` (add drawing: `VaultView`, `VaultAction`, `vault_section`, `named_combo`, `timeout_row`)
- Modify: `crates/aleph-gui/src/manager.rs`
- Test: `crates/aleph-gui/tests/manager.rs`

**Interfaces:**
- Consumes: `Request::Config`, `Request::SetConfigs`, `StoreEvent::Config`, `Form`, `Values` (Tasks 3, 4); `Reauth::confirmed`.
- Produces:
  - `settings_page::VaultView { pub enabled: bool, pub sealed: bool, pub unlocking: bool }`, `enum VaultAction { Save, Cancel }`, `fn vault_section(ui: &mut egui::Ui, p: &Palette, form: &mut Form, view: &VaultView) -> Option<VaultAction>`; `fn header(ui, p, text)`.
  - `manager::Page { Secrets, Settings }` (`Copy + PartialEq + Debug`), `Manager::page()`, `Manager::form() -> Option<&Form>`.
  - Window behavior: nav `SECRETS` / `SETTINGS`; `Request::Config` is sent once when SETTINGS is shown with the link up and no values; a Save sends one `Request::SetConfigs(fd, changes)` and draws the confirmation in the window; success sets the status `SETTINGS SAVED`, starts the reveal window and re-reads; failure or cancel keeps the edits.
  - Accessible names used by the tests: checkboxes `Lock on suspend`, `Lock on screen lock`; combos `Idle lock: <selected>` and `Prompt timeout: <selected>`; text fields `Idle lock minutes` and `Prompt timeout minutes`; buttons `SAVE`, `CANCEL`, `RETRY`.

- [ ] **Step 1: Write the failing window tests**

In `crates/aleph-gui/tests/manager.rs`:

1. Change `window_sized` into a wrapper over a new `window_with`:

```rust
fn window_sized(theme: ThemeChoice, v: Vault, size: [f32; 2]) -> (Window, Fake, Clip) {
    window_with(theme, v, size, |m| m)
}

/// A window whose manager `configure` may change before it first draws.
fn window_with(
    theme: ThemeChoice,
    v: Vault,
    size: [f32; 2],
    configure: impl FnOnce(Manager<Fake, Clip>) -> Manager<Fake, Clip>,
) -> (Window, Fake, Clip) {
    let settings = Settings {
        theme,
        scanlines: true,
        ..Settings::default()
    };
    window_full(settings, v, size, configure)
}

/// `window_with`, from whole settings (a reveal hold, say).
fn window_full(
    settings: Settings,
    v: Vault,
    size: [f32; 2],
    configure: impl FnOnce(Manager<Fake, Clip>) -> Manager<Fake, Clip>,
) -> (Window, Fake, Clip) {
    let store = Fake::default();
    let clip = Clip::default();
    let home = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/home");
    let mut m = configure(Manager::new(
        store.clone(),
        clip.clone(),
        settings,
        Some(home),
        true,
    ));
    m.confirm_guard = Duration::ZERO;
    let palette = m.palette.clone();
    store.send(StoreEvent::Vault(v));
    let mut h = Harness::builder()
        .with_size(egui::Vec2::from(size))
        .build_ui_state(|ui, m: &mut Manager<Fake, Clip>| m.frame(ui), m);
    aleph_gui::theme::apply(&h.ctx, &palette);
    frames(&mut h);
    (h, store, clip)
}
```

(`window_full` is the old body of `window_sized`, with `configure` applied to the manager and `settings` passed in.)

2. Add helpers and tests at the end of the file, before `snapshots`:

```rust
// --- SETTINGS ---

fn config(idle: &str, prompt: &str, suspend: &str) -> StoreEvent {
    StoreEvent::Config(Ok(BTreeMap::from([
        ("lock.on_suspend".to_string(), suspend.to_string()),
        ("lock.on_screen_lock".to_string(), "true".to_string()),
        ("lock.idle_timeout".to_string(), idle.to_string()),
        ("prompt.timeout".to_string(), prompt.to_string()),
    ])))
}

/// Open SETTINGS, answer the read with the given values.
fn open_settings(h: &mut Window, store: &Fake, idle: &str, prompt: &str, suspend: &str) {
    h.get_by_label("SETTINGS").click();
    frames(h);
    assert!(matches!(only(store.take()), Request::Config));
    store.send(config(idle, prompt, suspend));
    frames(h);
}

/// Pick `option` in the list called `control` (its label ends with the
/// selected value: `Idle lock: 15 min`).
fn pick(h: &mut Window, control: &str, option: &str) {
    h.get_by_label_contains(&format!("{control}:")).click();
    frames(h);
    h.get_by_label(option).click();
    frames(h);
}

fn press(h: &mut Window, label: &str, key: egui::Key, times: usize) {
    h.get_by_label(label).focus();
    frames(h);
    for _ in 0..times {
        h.key_press(key);
        frames(h);
    }
}

fn saved_map(fd_and_map: Request) -> (std::os::fd::OwnedFd, BTreeMap<String, String>) {
    match fd_and_map {
        Request::SetConfigs(fd, map) => (fd, map),
        other => panic!("{other:?}"),
    }
}

#[test]
fn settings_are_asked_for_once_and_shown() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Config));
    h.get_by_label("LOADING…");
    frames(&mut h);
    // (Not asked again while it is on its way.)
    assert!(store.take().is_empty());
    store.send(config("900", "300", "true"));
    frames(&mut h);
    h.get_by_label("Lock on suspend");
    h.get_by_label("Lock on screen lock");
    h.get_by_label("Idle lock: 15 min");
    h.get_by_label("Prompt timeout: 5 min");
    h.get_by_label_contains("Saving asks you to confirm it is you, once");
    // (Unlocked: nothing to say about a seal.)
    assert!(h.query_by_label("VAULT SEALED :: SAVE WILL UNLOCK FIRST").is_none());
    assert_eq!(h.state().page(), aleph_gui::manager::Page::Settings);
}

/// One SAVE, one confirmation, only the changed keys (Review Focus 5:
/// and one request: the page shows the confirmation, not the button).
#[test]
fn an_edit_is_saved_with_one_confirmation_and_only_the_changed_keys() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    pick(&mut h, "Prompt timeout", "30 min");
    h.get_by_label("Lock on screen lock").click();
    frames(&mut h);
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (fd, map) = saved_map(only(store.take()));
    assert_eq!(
        map,
        BTreeMap::from([
            ("lock.idle_timeout".to_string(), "900".to_string()),
            ("lock.on_screen_lock".to_string(), "false".to_string()),
            ("prompt.timeout".to_string(), "1800".to_string()),
        ])
    );
    // The confirmation is in the window; the form is not (no second Save).
    assert!(h.query_by_label("SAVE").is_none());
    let alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(alephd.join().unwrap());
    settle(&mut h);
    h.get_by_label_contains("SETTINGS SAVED");
    // Read again, and the reveal window opened: it is the same proof.
    assert!(matches!(only(store.take()), Request::Config));
    assert!(!h.state().reauth.needed(Instant::now(), Duration::from_secs(300)));
    store.send(config("900", "1800", "true"));
    frames(&mut h);
    assert!(!h.state().form().unwrap().edited());
}

#[test]
fn cancel_puts_the_read_values_back() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    assert!(h.state().form().unwrap().edited());
    h.get_by_label("CANCEL").click();
    frames(&mut h);
    assert!(!h.state().form().unwrap().edited());
    h.get_by_label("Idle lock: Off");
    assert!(store.take().is_empty());
}

#[test]
fn a_bad_custom_value_shows_why_and_cannot_be_saved() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Prompt timeout", "Custom…");
    // Chosen, still empty: nothing said yet, and nothing to save.
    assert!(h.query_by_label("whole minutes, 1 to 1440").is_none());
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    type_into(&mut h, "Prompt timeout minutes", "1441");
    h.get_by_label("whole minutes, 1 to 1440");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    // Fixed as typed: the message goes and SAVE works.
    press(&mut h, "Prompt timeout minutes", egui::Key::Backspace, 4);
    type_into(&mut h, "Prompt timeout minutes", "20");
    assert!(h.query_by_label("whole minutes, 1 to 1440").is_none());
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (_fd, map) = saved_map(only(store.take()));
    assert_eq!(map, BTreeMap::from([("prompt.timeout".to_string(), "1200".to_string())]));
}

#[test]
fn a_value_that_is_not_a_preset_is_shown_and_kept() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "7200", "90", "true");
    h.get_by_label("Idle lock: Custom (120 min)");
    h.get_by_label("Prompt timeout: Custom (90 s)");
    // Nothing edited: Save has nothing to send.
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(store.take().is_empty());
}

#[test]
fn the_suspend_warning_shows_while_it_is_off() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    assert!(h.query_by_label_contains("hibernation image").is_none());
    h.get_by_label("Lock on suspend").click();
    frames(&mut h);
    h.get_by_label_contains("the master key can reach a hibernation image unless swap is encrypted");
    h.get_by_label("Lock on suspend").click();
    frames(&mut h);
    assert!(h.query_by_label_contains("hibernation image").is_none());
}

#[test]
fn unsaved_edits_are_kept_across_screens() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    h.get_by_label("GitHub token");
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    assert!(store.take().is_empty(), "read again");
    h.get_by_label("Idle lock: 15 min");
    assert!(h.state().form().unwrap().edited());
}

/// A locked vault: the values show, Save says it will unlock first, asks
/// alephd to unlock, and confirms and saves once the vault is open.
#[test]
fn a_locked_vault_says_save_unlocks_first_and_then_saves() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("VAULT SEALED :: SAVE WILL UNLOCK FIRST");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    // Only the unlock, so far: no confirmation until the vault is open.
    assert!(matches!(only(store.take()), Request::Unlock));
    h.get_by_label("waiting for the unlock…");
    store.send(StoreEvent::Done {
        request: "unlock",
        error: None,
        dismissed: false,
    });
    frames(&mut h);
    assert!(store.take().is_empty(), "the vault is not open yet");
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    let (_fd, map) = saved_map(only(store.take()));
    assert_eq!(
        map,
        BTreeMap::from([("lock.idle_timeout".to_string(), "900".to_string())])
    );
}

/// A dismissed (or failed) unlock saves nothing and leaves the edits; a
/// vault unlocked later, by anything else, does not resume the save.
#[test]
fn a_dismissed_unlock_saves_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(StoreEvent::Done {
        request: "unlock",
        error: None,
        dismissed: true,
    });
    frames(&mut h);
    h.get_by_label_contains("nothing was saved");
    h.get_by_label("Idle lock: 15 min");
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    assert!(store.take().is_empty(), "nothing asked for the save");
    // (And the note is gone with the seal.)
    assert!(h.query_by_label("VAULT SEALED :: SAVE WILL UNLOCK FIRST").is_none());
}

#[test]
fn with_alephd_down_the_settings_wait_for_the_link() {
    let (mut h, store, _) = window(
        ThemeChoice::Neon,
        Vault::Unreachable("org.freedesktop.secrets has no owner".into()),
    );
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    assert!(store.take().is_empty(), "nothing to ask");
    h.get_by_label("LINK DOWN");
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Config));
}

#[test]
fn a_failed_read_says_why_and_can_be_retried() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    store.take();
    store.send(StoreEvent::Config(Err("no reply from alephd".into())));
    frames(&mut h);
    h.get_by_label_contains("no reply from alephd");
    h.get_by_label("RETRY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Config));
}

/// A save alephd refuses (before it asks) keeps the edits and says why.
#[test]
fn a_refused_save_keeps_the_edits_and_says_why() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (_fd, _) = saved_map(only(store.take()));
    store.send(StoreEvent::Done {
        request: "save the settings",
        error: Some("prompt.timeout must be 1 to 86400 seconds, not \"0\"".into()),
        dismissed: false,
    });
    frames(&mut h);
    h.get_by_label_contains("cannot save the settings");
    h.get_by_label("Idle lock: 15 min");
    assert!(h.state().form().unwrap().edited());
}

/// (Review Focus 5.) A confirmation that is cancelled saves nothing and
/// leaves the edits.
#[test]
fn a_cancelled_confirmation_saves_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (fd, _) = saved_map(only(store.take()));
    drop(fd);
    settle(&mut h);
    h.get_by_label_contains("nothing was saved");
    assert!(store.take().is_empty(), "no re-read: nothing changed");
    h.get_by_label("Idle lock: 15 min");
}

/// (Review Focus 5.) The vault locking under a confirmation ends it and
/// says nothing was saved.
#[test]
fn a_lock_during_the_confirmation_saves_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (_fd, _) = saved_map(only(store.take()));
    store.send(StoreEvent::Vault(Vault::Locked));
    settle(&mut h);
    h.get_by_label_contains("nothing was saved");
    h.get_by_label("Idle lock: 15 min");
    assert!(h.state().form().unwrap().edited());
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p aleph-gui --test manager settings`
Expected: compile errors (`Page`, `page()`, `form()` missing).

- [ ] **Step 3: Drawing in `settings_page.rs`**

Add these imports at the top of `settings_page.rs`: `use egui::{RichText, TextEdit};` and `use crate::theme::Palette;`. Add (above the tests):

```rust
/// A section's header line.
pub fn header(ui: &mut egui::Ui, p: &Palette, text: &str) {
    ui.label(RichText::new(text).strong().color(p.accent));
    ui.add_space(6.0);
}

/// What the VAULT section is allowed to do now.
pub struct VaultView {
    /// The controls work (alephd can be reached).
    pub enabled: bool,
    /// The vault is locked: Save will unlock it first (and says so).
    pub sealed: bool,
    /// An unlock asked for by Save is under way: Save waits for it.
    pub unlocking: bool,
}

/// What the person asked of the VAULT section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultAction {
    Save,
    Cancel,
}

/// A drop-down list whose accessible name is `name: selected` (so a
/// screen reader, and the tests, hear what is chosen).
fn named_combo(ui: &mut egui::Ui, name: &str, selected: &str, body: impl FnOnce(&mut egui::Ui)) {
    let r = egui::ComboBox::from_id_salt(name)
        .selected_text(selected)
        .show_ui(ui, body);
    let label = format!("{name}: {selected}");
    ui.ctx()
        .accesskit_node_builder(r.response.id, move |n| n.set_label(label));
}

/// One duration row: the list, and the minutes field beside it while
/// "Custom…" is chosen, with its message under.
fn timeout_row(ui: &mut egui::Ui, p: &Palette, name: &str, t: &mut Timeout) {
    ui.horizontal(|ui| {
        ui.label(name);
        let selected = match &t.choice {
            Choice::Preset(s) => describe(t.kind, *s),
            Choice::Kept => describe(t.kind, t.read()),
            Choice::Custom => "Custom…".to_string(),
        };
        let kind = t.kind;
        let kept = t.kept_text();
        named_combo(ui, name, &selected, |ui| {
            for &s in kind.presets() {
                ui.selectable_value(&mut t.choice, Choice::Preset(s), describe(kind, s));
            }
            if let Some(text) = kept {
                ui.selectable_value(&mut t.choice, Choice::Kept, text);
            }
            if kind.custom_minutes()
                && ui
                    .selectable_label(t.choice == Choice::Custom, "Custom…")
                    .clicked()
            {
                t.choose_custom();
            }
        });
        if t.choice == Choice::Custom {
            let r = ui.add(
                TextEdit::singleline(&mut t.typed)
                    .hint_text("minutes")
                    .desired_width(70.0),
            );
            let field = format!("{name} minutes");
            ui.ctx()
                .accesskit_node_builder(r.id, move |n| n.set_label(field));
            ui.label("min");
        }
    });
    if let Some(e) = t.error() {
        ui.label(RichText::new(e).small().color(p.warning));
    }
}

/// The VAULT section's form. `Save` and `Cancel` are returned, never done
/// here.
pub fn vault_section(
    ui: &mut egui::Ui,
    p: &Palette,
    form: &mut Form,
    view: &VaultView,
) -> Option<VaultAction> {
    ui.add_enabled_ui(view.enabled, |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut form.on_suspend, "Lock on suspend");
            ui.label(RichText::new("(also covers hibernate)").small().color(p.muted));
        });
        ui.checkbox(&mut form.on_screen_lock, "Lock on screen lock");
        timeout_row(ui, p, "Idle lock", &mut form.idle);
        timeout_row(ui, p, "Prompt timeout", &mut form.prompt);
    });
    if !form.on_suspend {
        ui.label(RichText::new(SUSPEND_WARNING).color(p.warning));
    }
    ui.add_space(8.0);
    ui.label(RichText::new(SAVE_NOTE).small().color(p.muted));
    if view.sealed {
        // (Beside the buttons, and not small: what Save will do first.)
        ui.label(RichText::new(LOCKED_NOTE).strong().color(p.warning));
    }
    let mut action = None;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(view.enabled && form.edited(), egui::Button::new("CANCEL"))
            .clicked()
        {
            action = Some(VaultAction::Cancel);
        }
        let ready = view.enabled && !view.unlocking && form.edited() && form.valid();
        if ui.add_enabled(ready, egui::Button::new("SAVE")).clicked() {
            action = Some(VaultAction::Save);
        }
        if view.unlocking {
            ui.label("waiting for the unlock…");
        }
    });
    action
}
```

(`Palette` has `accent`, `warning`, `muted`; check `theme.rs` if a name differs. If `ui.selectable_label` is absent in egui 0.36, use `ui.add(egui::Button::selectable(t.choice == Choice::Custom, "Custom…"))`, as `manager.rs` does for the list.)

- [ ] **Step 4: Wire the manager**

In `manager.rs`:

1. Imports: `use crate::settings_page::{self, Form, Values, VaultAction, VaultView};`.

2. Below `Want` add:

```rust
/// Which screen the window shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Secrets,
    Settings,
}
```

3. Fields (in `struct Manager`, after `watch`): 

```rust
    page: Page,
    /// The VAULT section's values: kept across screens, so edits stay.
    values: Values,
    /// The confirmation on screen is for a settings save, not a reveal.
    saving_settings: bool,
    /// SAVE was pressed while the vault was locked: it asked alephd to
    /// unlock, and saves (with the edits as they are then) once it is open.
    save_after_unlock: bool,
```

and in `new`: `page: Page::Secrets, values: Values::Unknown, saving_settings: false, save_after_unlock: false,`. Add accessors:

```rust
    pub fn page(&self) -> Page {
        self.page
    }

    /// The VAULT form, once read.
    pub fn form(&self) -> Option<&Form> {
        match &self.values {
            Values::Ready(f) => Some(f),
            _ => None,
        }
    }
```

4. Split `start_confirm`:

```rust
    /// Open the confirmation in this window: the prompter's end of a new
    /// socketpair (for alephd), or `None` (with the reason in the status).
    fn open_confirm(&mut self, ctx: &egui::Context) -> Option<UnixStream> {
        let Ok((ours, theirs)) = UnixStream::pair() else {
            self.status = Some("cannot start the confirmation".into());
            return None;
        };
        let Ok(reader) = ours.try_clone() else {
            self.status = Some("cannot start the confirmation".into());
            return None;
        };
        // (Each message from alephd wakes the window: with animations off
        // nothing else draws the next frame.)
        let wake = ctx.clone();
        let Ok(events) = crate::link::spawn_reader(reader, move || wake.request_repaint()) else {
            self.status = Some("cannot start the confirmation".into());
            return None;
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
        Some(theirs)
    }

    fn start_confirm(&mut self, ctx: &egui::Context, path: String, want: Want) {
        let Some(theirs) = self.open_confirm(ctx) else {
            return;
        };
        self.pending = Some((path, want));
        self.store.request(Request::Reauth(theirs.into()));
    }

    /// Save the changed VAULT settings: one confirmation for all of them.
    fn start_save(&mut self, ctx: &egui::Context, changes: BTreeMap<String, String>) {
        let Some(theirs) = self.open_confirm(ctx) else {
            return;
        };
        self.saving_settings = true;
        self.store.request(Request::SetConfigs(theirs.into(), changes));
    }
```

5. `sealed()`: after `self.end_confirm();` add

```rust
        if std::mem::take(&mut self.saving_settings) {
            self.status = Some("the vault locked: nothing was saved".into());
        }
```

6. `take_events`, `StoreEvent::Vault(v)` arm: before `self.vault = v;` add `let was_up = matches!(self.vault, Vault::Locked | Vault::Unlocked(_));` and after it:

```rust
                    let up = matches!(self.vault, Vault::Locked | Vault::Unlocked(_));
                    if !up && matches!(self.values, Values::Loading) {
                        self.values = Values::Unknown;
                    }
                    if up && !was_up {
                        // (The link is back: read again, unless there are
                        // edits, which stay.)
                        let again = match &self.values {
                            Values::Failed(_) => true,
                            Values::Ready(f) => !f.edited(),
                            _ => false,
                        };
                        if again {
                            self.values = Values::Unknown;
                        }
                    }
```

Add arms:

```rust
                StoreEvent::Config(result) => {
                    // (Only the answer being waited for.)
                    if matches!(self.values, Values::Loading) {
                        self.values = match result.and_then(|v| Form::from_values(&v)) {
                            Ok(form) => Values::Ready(form),
                            Err(e) => Values::Failed(e),
                        };
                    }
                }
```

and change the `StoreEvent::Done { request, error, .. } =>` arm's pattern to `StoreEvent::Done { request, error, dismissed } =>` (`dismissed` is used below; the arm's old code ignores it with `..` no longer) and add at the top of its body, before `let save = ...`:

```rust
                    if request == "unlock" && self.save_after_unlock && (error.is_some() || dismissed) {
                        // (A save waiting for the unlock is dropped; the edits stay.
                        // A successful unlock keeps it: `resume_save` runs when the
                        // vault event shows it open.)
                        self.save_after_unlock = false;
                        self.status = Some(match &error {
                            Some(e) => format!("cannot unlock: {e}; nothing was saved"),
                            None => "the unlock was dismissed: nothing was saved".into(),
                        });
                        continue;
                    }
                    if request == "read the settings" {
                        // (The VAULT section shows why, with RETRY.)
                        continue;
                    }
                    if request == "save the settings" {
                        if let Some(e) = error {
                            self.end_confirm();
                            self.saving_settings = false;
                            self.status = Some(format!("cannot save the settings: {e}"));
                        }
                        continue;
                    }
```

7. `frame`: in the focus-loss block add, after `self.pending = None;`:

```rust
            if std::mem::take(&mut self.saving_settings) {
                self.status = Some("the window lost focus: nothing was saved".into());
            }
```

Replace from `self.take_events();` through the end of the `match self.vault.clone() {..}` block with:

```rust
        self.take_events();
        self.resume_save(&ui.ctx().clone());
        self.ask_config();
        let p = self.palette.clone();
        let mut go = None;
        egui::Panel::left("aleph-nav")
            .exact_size(130.0)
            .resizable(false)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("ALEPH").strong().color(p.accent));
                ui.label(RichText::new("// VAULT").small().color(p.accent));
                ui.add_space(16.0);
                // (Not while a confirmation runs: it is drawn in the page.)
                ui.add_enabled_ui(self.confirm.is_none(), |ui| {
                    for (page, name) in [(Page::Secrets, "SECRETS"), (Page::Settings, "SETTINGS")]
                    {
                        let picked = self.page == page;
                        if ui
                            .add(Button::selectable(picked, RichText::new(name).strong()))
                            .clicked()
                        {
                            go = Some(page);
                        }
                    }
                });
            });
        if let Some(page) = go {
            self.page = page;
        }
        match self.page {
            Page::Secrets => self.secrets(ui, &p, now),
            Page::Settings => self.settings_screen(ui, &p, now),
        }
```

and add, right after `frame`:

```rust
    /// The secrets screen: the vault's state, or its folders and items.
    fn secrets(&mut self, ui: &mut egui::Ui, p: &Palette, now: Instant) {
        match self.vault.clone() {
            Vault::Unlocked(collections) => self.unlocked(ui, p, &collections, now),
            other => {
                // (the old `other => { egui::CentralPanel::default()... }` body,
                // unchanged, with `&p` and `p` as `p`)
            }
        }
    }
```

Move the old `other => {..}` arm body verbatim into it (it uses `p` as `&p`; adjust to `p`).

8. The Settings screen and helpers:

```rust
    /// A save that waited for the unlock (SAVE pressed while sealed): now
    /// that the vault is open, confirm and save what is in the form. Not
    /// if the form went (another screen, nothing left to save).
    fn resume_save(&mut self, ctx: &egui::Context) {
        if !self.save_after_unlock || !matches!(self.vault, Vault::Unlocked(_)) {
            return;
        }
        self.save_after_unlock = false;
        let changes = match &self.values {
            Values::Ready(f) if self.page == Page::Settings && f.edited() && f.valid() => {
                f.changes()
            }
            _ => return,
        };
        self.start_save(ctx, changes);
    }

    /// Ask alephd for the VAULT values when the screen needs them.
    fn ask_config(&mut self) {
        let up = matches!(self.vault, Vault::Locked | Vault::Unlocked(_));
        if self.page == Page::Settings && up && matches!(self.values, Values::Unknown) {
            self.values = Values::Loading;
            self.store.request(Request::Config);
        }
    }

    fn settings_screen(&mut self, ui: &mut egui::Ui, p: &Palette, now: Instant) {
        egui::CentralPanel::default().show(ui, |ui| {
            self.status_line(ui, p);
            if self.confirm.is_some() {
                self.confirming(ui, now);
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.vault_settings(ui, p);
            });
        });
    }

    fn vault_settings(&mut self, ui: &mut egui::Ui, p: &Palette) {
        settings_page::header(ui, p, "VAULT  // alephd");
        let up = matches!(self.vault, Vault::Locked | Vault::Unlocked(_));
        let sealed = matches!(self.vault, Vault::Locked);
        let mut action = None;
        match &mut self.values {
            Values::Ready(form) => {
                if !up {
                    ui.label(RichText::new("LINK DOWN: alephd cannot be reached").color(p.error));
                }
                let view = VaultView {
                    enabled: up,
                    sealed,
                    unlocking: self.save_after_unlock,
                };
                action = settings_page::vault_section(ui, p, form, &view);
            }
            Values::Failed(why) => {
                ui.label(RichText::new(shown(why, 200)).color(p.error));
                if ui.button("RETRY").clicked() {
                    self.values = Values::Unknown;
                }
            }
            Values::Unknown | Values::Loading => {
                if up {
                    ui.label("LOADING…");
                } else if let Vault::Unreachable(why) = &self.vault {
                    ui.label(RichText::new("LINK DOWN").strong().color(p.error));
                    ui.label(shown(why, 200));
                } else {
                    ui.label("CONNECTING…");
                }
            }
        }
        match action {
            Some(VaultAction::Cancel) => {
                if let Values::Ready(form) = &mut self.values {
                    form.cancel();
                }
                self.save_after_unlock = false;
            }
            Some(VaultAction::Save) => {
                if sealed {
                    // (Confirming needs the vault open: unlock first, and
                    // save when it is; `resume_save`.)
                    self.save_after_unlock = true;
                    self.store.request(Request::Unlock);
                } else if let Values::Ready(form) = &self.values {
                    let changes = form.changes();
                    self.start_save(&ui.ctx().clone(), changes);
                }
            }
            None => {}
        }
    }
```

(`p.error` exists: used for LINK DOWN in the old code.)

9. `confirming`: replace the body from `let Some(app) = ...` through the end with

```rust
    fn confirming(&mut self, ui: &mut egui::Ui, now: Instant) {
        let Some(app) = self.confirm.as_mut() else {
            return;
        };
        if self.pending.is_some() {
            // (What the guard is worth: spec §6.)
            ui.label(
                RichText::new(
                    "Any program running as you can read secrets; this only guards against a glance.",
                )
                .small()
                .color(self.palette.foreground.gamma_multiply(0.7)),
            );
        }
        app.frame(ui);
        if app.closed {
            let (ok, message) = match &app.ui.conversation.screen {
                Screen::Finished { ok, message } => (*ok, message.clone()),
                _ => (false, None),
            };
            self.end_confirm();
            if std::mem::take(&mut self.saving_settings) {
                if ok {
                    // (The same proof as a reveal's; and read again.)
                    self.reauth.confirmed(now);
                    self.status = Some("SETTINGS SAVED".into());
                    self.values = Values::Unknown;
                } else {
                    self.status.get_or_insert(match message {
                        Some(m) => format!("not saved: {m}"),
                        None => "cancelled: nothing was saved".into(),
                    });
                }
            } else if let Some((path, want)) = self.pending.take()
                && ok
            {
                self.reauth.confirmed(now);
                self.fetch(path, want);
            }
        }
    }
```

(If `status.get_or_insert` leaves an old, unrelated status in place, replace with `self.status = Some(..)`: a refusal's `Done` handler sets its own status afterwards either way. Choose the plain assignment if a test shows a stale message.)

- [ ] **Step 5: Run and iterate until the new tests pass**

Run: `cargo test -p aleph-gui --test manager settings`
Expected: PASS for the tests in Step 1. Known likely snags, in order:
1. `pick` cannot find the option: after the combo opens the option label is `15 min` — if two nodes match, use `h.get_all_by_label(option).last().unwrap().click()` in `pick`.
2. `h.get_by_label("LOADING…")` needs the first frame after the click; keep `frames`.
3. If `type_into` on `Prompt timeout minutes` appends to an old value, the field starts empty by design (`choose_custom` clears).

- [ ] **Step 6: Regenerate the manager's snapshots and look at one**

The nav changed, so every manager snapshot differs.
Run: `UPDATE_SNAPSHOTS=1 cargo test -p aleph-gui --test manager snapshots; cargo test -p aleph-gui --test manager`
Expected: the second run PASSES. Read `crates/aleph-gui/tests/snapshots/manager_item_neon.png` and check that the left nav shows `SECRETS` (selected) and `SETTINGS` and nothing else moved.

- [ ] **Step 7: Run everything in the crate**

Run: `cargo test -p aleph-gui`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
cargo fmt --all && cargo clippy -p aleph-gui --all-targets -- -D warnings
git add crates/aleph-gui
git commit -m 'feat(gui): the SETTINGS screen and its VAULT section' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 6: The DISPLAY section

**Files:**
- Modify: `crates/aleph-gui/src/settings_page.rs` (`DisplayView`, `DisplayAction`, `display_section`)
- Modify: `crates/aleph-gui/src/manager.rs` (`settings_file`, `display_broken`, `with_settings_file`, `settings()`, `apply_display`, the section in `settings_screen`)
- Modify: `crates/aleph-gui/src/main.rs`
- Test: `crates/aleph-gui/tests/manager.rs`

**Interfaces:**
- Consumes: `Settings::save`, `Settings::reset`, `Settings::load`, `MAX_REVEAL_HOLD` (Task 2); `named_combo`, `describe`, `Kind::Reveal`, `header` (Tasks 4, 5); `theme::resolve`, `theme::apply`.
- Produces:
  - `settings_page::DisplayView { pub broken: Option<String>, pub still: bool }`; `enum DisplayAction { Theme(ThemeChoice), Scanlines(bool), Reveal(u64), Reset }`; `fn display_section(ui, p, settings: &Settings, view: &DisplayView) -> Option<DisplayAction>`.
  - `Manager::with_settings_file(self, file: Option<PathBuf>, broken: Option<String>) -> Self`; `Manager::settings(&self) -> &Settings`.
  - Names: radios `Auto`, `Neon`; checkbox `Scanlines`; combo `Reveal confirmation lasts: <selected>`; buttons `RESET TO DEFAULTS`.

- [ ] **Step 1: Write the failing window tests**

In `tests/manager.rs`, after the VAULT tests:

```rust
/// A window whose gui.toml is `dir/aleph/gui.toml`.
fn display_window(
    theme: ThemeChoice,
    file: std::path::PathBuf,
    broken: Option<&str>,
) -> (Window, Fake) {
    let broken = broken.map(String::from);
    let (h, store, _) = window_with(theme, vault(), SIZE, move |m| {
        m.with_settings_file(Some(file), broken)
    });
    (h, store)
}

fn gui_toml(file: &std::path::Path) -> Settings {
    Settings::load(file).0
}

/// DISPLAY needs no confirmation and no Save: each change is written at
/// once and takes effect at once.
#[test]
fn display_changes_are_written_and_apply_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("aleph/gui.toml");
    let (mut h, store) = display_window(ThemeChoice::Auto, file.clone(), None);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    store.take();
    let before = h.state().palette.clone();
    h.get_by_label("Neon").click();
    frames(&mut h);
    assert_eq!(h.state().settings().theme, ThemeChoice::Neon);
    assert_ne!(h.state().palette.accent, before.accent, "re-themed at once");
    assert_eq!(gui_toml(&file).theme, ThemeChoice::Neon);
    h.get_by_label("Scanlines").click();
    frames(&mut h);
    assert!(!h.state().settings().scanlines);
    assert!(!gui_toml(&file).scanlines);
    h.get_by_label("Reveal confirmation lasts: 5 min");
    pick(&mut h, "Reveal confirmation lasts", "Every time");
    assert_eq!(gui_toml(&file).reveal_hold, 0);
    // "Every time": even a confirmation just given does not hold.
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    // (The only request is the confirmation SHOW now asks for: nothing
    // DISPLAY did asked alephd for anything.)
    assert!(matches!(only(store.take()), Request::Reauth(_)));
}

/// (Review Focus 4.) A hold in the file that is not a preset is shown as it
/// is and stays until another is picked.
#[test]
fn a_reveal_hold_that_is_not_a_preset_is_shown_and_kept() {
    let settings = Settings {
        theme: ThemeChoice::Neon,
        reveal_hold: 45,
        ..Settings::default()
    };
    let (mut h, _store, _) = window_full(settings, vault(), SIZE, |m| m);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label("Reveal confirmation lasts: Custom (45 s)");
    pick(&mut h, "Reveal confirmation lasts", "15 min");
    h.get_by_label("Reveal confirmation lasts: 15 min");
    assert_eq!(h.state().settings().reveal_hold, 900);
}

#[test]
fn a_broken_gui_toml_is_shown_and_never_overwritten_until_reset() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("gui.toml");
    std::fs::write(&file, "scanline = false\n# mine\n").unwrap();
    let broken = format!("{}: unknown field `scanline` (using the defaults)", file.display());
    let (mut h, _store) = display_window(ThemeChoice::Neon, file.clone(), Some(&broken));
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label_contains("unknown field `scanline`");
    // The controls are disabled: a click changes nothing.
    h.get_by_label("Auto").click();
    h.get_by_label("Scanlines").click();
    frames(&mut h);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "scanline = false\n# mine\n"
    );
    h.get_by_label("RESET TO DEFAULTS").click();
    frames(&mut h);
    assert_eq!(Settings::load(&file), (Settings::default(), None));
    assert!(h.query_by_label_contains("unknown field").is_none());
    // Working now.
    h.get_by_label("Scanlines").click();
    frames(&mut h);
    assert!(!gui_toml(&file).scanlines);
}

/// A file that cannot be written says so, and the change holds for this run.
#[test]
fn a_failed_write_says_so_and_the_change_holds() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").unwrap();
    let (mut h, _store) = display_window(ThemeChoice::Auto, blocker.join("gui.toml"), None);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label("Neon").click();
    frames(&mut h);
    h.get_by_label_contains("not saved");
    assert_eq!(h.state().settings().theme, ThemeChoice::Neon);
}
```

- [ ] **Step 2: Run them and watch them fail**

Run: `cargo test -p aleph-gui --test manager display settings_are`
Expected: compile errors (`with_settings_file`, `settings()` missing).

- [ ] **Step 3: Drawing in `settings_page.rs`**

Add `use crate::settings::{Settings, ThemeChoice};` and:

```rust
/// What the DISPLAY section is allowed to do now.
pub struct DisplayView {
    /// gui.toml did not read as settings: its error (the controls wait).
    pub broken: Option<String>,
    /// Reduced motion is asked for, so scanlines are off whatever is set.
    pub still: bool,
}

/// What the person changed in the DISPLAY section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayAction {
    Theme(ThemeChoice),
    Scanlines(bool),
    Reveal(u64),
    Reset,
}

pub fn display_section(
    ui: &mut egui::Ui,
    p: &Palette,
    s: &Settings,
    view: &DisplayView,
) -> Option<DisplayAction> {
    let mut action = None;
    header(ui, p, "DISPLAY  // gui · changes apply now");
    if let Some(why) = &view.broken {
        ui.label(RichText::new(crate::conversation::shown(why, 300)).color(p.error));
        if ui.button("RESET TO DEFAULTS").clicked() {
            action = Some(DisplayAction::Reset);
        }
    }
    ui.add_enabled_ui(view.broken.is_none(), |ui| {
        ui.horizontal(|ui| {
            ui.label("Theme");
            for (choice, name) in [(ThemeChoice::Auto, "Auto"), (ThemeChoice::Neon, "Neon")] {
                if ui.radio(s.theme == choice, name).clicked() && s.theme != choice {
                    action = Some(DisplayAction::Theme(choice));
                }
            }
        });
        ui.horizontal(|ui| {
            let mut on = s.scanlines;
            if ui.checkbox(&mut on, "Scanlines").changed() {
                action = Some(DisplayAction::Scanlines(on));
            }
            if view.still {
                ui.label(
                    RichText::new("(off: reduced motion is asked for)")
                        .small()
                        .color(p.muted),
                );
            }
        });
        ui.horizontal(|ui| {
            ui.label("Reveal confirmation lasts");
            let mut hold = s.reveal_hold;
            let selected = describe(Kind::Reveal, hold);
            named_combo(ui, "Reveal confirmation lasts", &selected, |ui| {
                for &secs in REVEAL_PRESETS {
                    ui.selectable_value(&mut hold, secs, describe(Kind::Reveal, secs));
                }
                if !REVEAL_PRESETS.contains(&s.reveal_hold) {
                    ui.selectable_value(&mut hold, s.reveal_hold, describe(Kind::Reveal, s.reveal_hold));
                }
            });
            if hold != s.reveal_hold {
                action = Some(DisplayAction::Reveal(hold));
            }
        });
    });
    action
}
```

Two things to check while compiling: `conversation::shown` is `pub` (the manager imports it: yes) and `Palette` has `error`. The visible label `Reveal confirmation lasts` and the combo's name `Reveal confirmation lasts: 5 min` differ, so `get_by_label` finds one node each.

- [ ] **Step 4: Manager wiring**

In `manager.rs`:

1. `use crate::settings_page::{DisplayAction, DisplayView};` (add to the existing `settings_page` import).
2. Fields: `settings_file: Option<PathBuf>, display_broken: Option<String>,` (both `None` in `new`).
3. Methods:

```rust
    /// Where gui.toml is, and why it could not be read (if it could not):
    /// DISPLAY writes there, and waits for a reset when it is broken.
    pub fn with_settings_file(mut self, file: Option<PathBuf>, broken: Option<String>) -> Self {
        self.settings_file = file;
        self.display_broken = broken;
        self
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// A DISPLAY change: in effect now, and written to gui.toml. A write
    /// that fails is said so; the change holds for this run.
    fn apply_display(&mut self, ctx: &egui::Context, action: DisplayAction) {
        match action {
            DisplayAction::Theme(t) => self.settings.theme = t,
            DisplayAction::Scanlines(on) => self.settings.scanlines = on,
            DisplayAction::Reveal(secs) => self.settings.reveal_hold = secs,
            DisplayAction::Reset => {
                self.settings = Settings::default();
                let done = match &self.settings_file {
                    Some(file) => Settings::reset(file),
                    None => Ok(()),
                };
                match done {
                    Ok(()) => self.display_broken = None,
                    Err(e) => self.status = Some(format!("not reset: {e}")),
                }
                self.palette = theme::resolve(&self.settings, self.home.as_deref());
                theme::apply(ctx, &self.palette);
                return;
            }
        }
        self.palette = theme::resolve(&self.settings, self.home.as_deref());
        theme::apply(ctx, &self.palette);
        let written = match &self.settings_file {
            Some(file) => self.settings.save(file),
            None => Err("no configuration directory".to_string()),
        };
        if let Err(e) = written {
            self.status = Some(format!(
                "not saved: {e} (the change holds until the window closes)"
            ));
        }
    }
```

4. In `settings_screen`, after `self.vault_settings(ui, p);` inside the scroll area:

```rust
                ui.add_space(16.0);
                ui.separator();
                let view = DisplayView {
                    broken: self.display_broken.clone(),
                    still: self.still,
                };
                if let Some(a) = settings_page::display_section(ui, p, &self.settings, &view) {
                    self.apply_display(&ui.ctx().clone(), a);
                }
```

- [ ] **Step 5: `main.rs`**

In `manage()` replace `let (settings, still, home) = look();` with

```rust
    let file = settings::config_home().map(|dir| settings::path(&dir));
    let (settings, broken) = match &file {
        Some(f) => settings::Settings::load(f),
        None => (settings::Settings::default(), None),
    };
    if let Some(w) = &broken {
        eprintln!("aleph-gui: {w}");
    }
    let (still, home) = (settings::reduced_motion(), settings::home());
```

and after `manager::Manager::new(..)` add `.with_settings_file(file, broken)`:

```rust
            let mut app =
                manager::Manager::new(store, clipboard::Wayland::default(), settings, home, still)
                    .with_settings_file(file, broken);
```

Delete `fn look()` (now unused; clippy flags dead code). Check `tests/binary.rs` still passes.

- [ ] **Step 6: Run and iterate**

Run: `cargo test -p aleph-gui`
Expected: PASS. If clicking a disabled widget in `a_broken_gui_toml...` panics in kittest, replace those two clicks with a check that the nodes are disabled: `assert!(h.get_by_label("Neon").accesskit_node().is_disabled())`.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all && cargo clippy -p aleph-gui --all-targets -- -D warnings
git add crates/aleph-gui
git commit -m 'feat(gui): the DISPLAY section, written to gui.toml at once' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 7: Snapshots, documents, the gate

**Files:**
- Modify: `crates/aleph-gui/tests/manager.rs` (`snapshots`)
- Create: new PNGs under `crates/aleph-gui/tests/snapshots/`
- Modify: `docs/testing.md`, `DECISIONS.md`
- Modify: `docs/superpowers/specs/2026-09-28-aleph-manager-design.md`, `docs/superpowers/specs/2026-09-26-aleph-design.md`, `docs/superpowers/specs/2026-09-28-aleph-settings-design.md`

**Interfaces:**
- Consumes: everything above.
- Produces: snapshots `manager_settings_{neon,omarchy}`, `manager_settings_custom_{..}`, `manager_settings_locked_{..}`, `manager_settings_confirm_{..}`, `manager_settings_broken_{..}`; the manual checks; the recorded decisions.

- [ ] **Step 1: Add the views to `snapshots`**

Inside the per-theme loop of `snapshots()` (after the `unreachable` shot):

```rust
        // SETTINGS: the form, a bad entry, locked, the confirmation, a broken file.
        let dir = tempfile::tempdir().unwrap();
        let (mut h, store, _) = window_with(theme, vault(), SIZE, {
            let file = dir.path().join("gui.toml");
            move |m| m.with_settings_file(Some(file), None)
        });
        open_settings(&mut h, &store, "900", "300", "false");
        shot(&mut h, "settings");
        pick(&mut h, "Prompt timeout", "Custom…");
        type_into(&mut h, "Prompt timeout minutes", "1441");
        shot(&mut h, "settings_custom");
        pick(&mut h, "Idle lock", "30 min");
        h.get_by_label("SAVE").click();
        frames(&mut h);
        let (fd, _) = saved_map(only(store.take()));
        let alephd = std::thread::spawn(move || {
            let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
            chan.send(&ToPrompter::Begin {
                purpose: Purpose::Reauth,
                operation: "Set lock.idle_timeout = 1800".into(),
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
        shot(&mut h, "settings_confirm");
        drop(chan);
        let (mut h, store, _) = window(theme, Vault::Locked);
        open_settings(&mut h, &store, "0", "300", "true");
        shot(&mut h, "settings_locked");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gui.toml");
        let (mut h, _) = display_window(
            theme,
            file,
            Some("gui.toml: unknown field `scanline`, expected one of `theme`, `scanlines`, `reveal_hold` (using the defaults)"),
        );
        h.get_by_label("SETTINGS").click();
        frames(&mut h);
        shot(&mut h, "settings_broken");
```

(`settings_custom` has the bad entry `1441` *and* the idle pick after it; if the shot must show the error, take it before `pick(.. "Idle lock" ..)` as written.)

- [ ] **Step 2: Generate, then look at every new image**

Run: `UPDATE_SNAPSHOTS=1 cargo test -p aleph-gui --test manager snapshots; cargo test -p aleph-gui --test manager snapshots`
Expected: the second run PASSES. Read each new PNG in `crates/aleph-gui/tests/snapshots/manager_settings*_neon.png` and check: the VAULT and DISPLAY headers read exactly as in Global Constraints; the suspend warning shows in `settings` (suspend is off there); `settings_custom` shows `whole minutes, 1 to 1440` under the field; `settings_locked` shows the note `VAULT SEALED :: SAVE WILL UNLOCK FIRST` beside the buttons; `settings_confirm` shows the password screen with no form behind it; `settings_broken` shows the error and RESET TO DEFAULTS with the controls dimmed. Nothing clipped at 900 × 560; fix the layout (spacing, `ScrollArea`) if it is, and regenerate.

- [ ] **Step 3: The manual checks**

Append to `docs/testing.md` (after the "The manager (Plan 5b)" list; same style):

```markdown
### The manager's settings (Plan 5c)

After `make && make install`, on the account aleph serves. Write down
`alephctl config get lock.idle_timeout` and `prompt.timeout` first; put
them back at the end.

1. Open the manager, then SETTINGS: the four VAULT values match
   `alephctl config get lock.on_suspend`, `lock.on_screen_lock`,
   `lock.idle_timeout`, `prompt.timeout`.
2. Idle lock: 5 min and prompt timeout: 15 min, then SAVE: one
   confirmation (login password or key touch), then `SETTINGS SAVED`;
   `alephctl config get` shows 300 and 900. Nothing was restarted.
3. Idle lock 5 min: leave the keyring untouched for 5 minutes
   (`alephctl status` shows `locked` afterwards). Set it back to Off.
4. Change three settings at once: one confirmation only.
5. Custom… for the prompt timeout: `0`, `1441`, `abc` each show
   `whole minutes, 1 to 1440` at once and Save stays off; `20` saves as
   1200 s.
6. Turn Lock on suspend off: the hibernation warning shows; turn it on
   again before leaving.
7. Cancel the confirmation (Cancel, or Escape): nothing changes
   (`alephctl config get`), the edits stay on screen.
8. `alephctl lock`, then SETTINGS: the values show and DISPLAY works; beside
   the buttons `VAULT SEALED :: SAVE WILL UNLOCK FIRST`. Edit something and
   SAVE: alephd's unlock window opens; after it, the confirmation opens
   (a second proof) and then `SETTINGS SAVED`. Repeat, and dismiss the
   unlock: `nothing was saved`, the edits stay.
9. `alephctl config set lock.idle_timeout 60` while the form is open with
   another value edited: SAVE sends only the edited key (the idle lock stays 60).
10. DISPLAY: Theme Neon/Auto and Scanlines switch at once and
    `~/.config/aleph/gui.toml` follows; "Every time" asks at every SHOW
    (even right after a confirmation); a SAVE in VAULT starts the 5-minute
    reveal window (SHOW right after: no second confirmation).
11. Hand-edit gui.toml to `scanline = false`: DISPLAY shows the file's error
    and RESET TO DEFAULTS; nothing is written until it is reset or fixed.
12. Stop alephd (`systemctl --user stop alephd.service alephd.socket`, then
    start them): while it is down VAULT says LINK DOWN; it reads again
    when the link returns.
```

- [ ] **Step 4: Decisions and specs**

1. `DECISIONS.md`: read its last section for the numbering and style, then add a section for Plan 5c with the settings spec's "Decisions" list (six lines: one Save/one confirmation through `SetConfigs`; DISPLAY applies at once; `prompt.program` not in the manager; the reveal hold is a setting, presets and default; idle/prompt are presets plus custom minutes checked as typed; a save also starts the reveal window) and one more: "**Saving VAULT unlocks a locked vault first**: alephd's re-authentication refuses a locked one, so Save (marked `VAULT SEALED :: SAVE WILL UNLOCK FIRST` while sealed) asks alephd to unlock, then confirms: two proofs. A dismissed unlock saves nothing."
2. Main spec `2026-09-26-aleph-design.md`: in the Admin interface list add `SetConfigs` beside `SetConfig`, and add `SetConfigs` to the re-authentication list; grep `gui.toml` there and add `reveal_hold` (seconds; default 300; at most 3600) next to `theme` and `scanlines`, and say the manager writes the file.
3. Manager spec `2026-09-28-aleph-manager-design.md`: the sidebar lists `SECRETS` and `SETTINGS`; "a confirmation holds for 5 minutes" becomes "for the `reveal_hold` setting (default 5 minutes)".
4. Settings spec: change `Status:` to `Approved; implemented by docs/superpowers/plans/2026-09-28-aleph-settings.md`.

- [ ] **Step 5: The gate**

Run: `make gate`
Expected: fmt, clippy `-D warnings` and the whole suite PASS. If `aleph-core` `golden` fails with NotFound after a worktree was removed, run `cargo clean -p <pkg>` for each workspace package and rerun.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m 'docs,test(gui): snapshots of the settings screen, manual checks, decisions' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

## Self-review

**Spec coverage.**
- alephd `SetConfigs` (empty refused, checked before asking, one `with_reauth`, key-ordered operation text, live config, one save, all or none, `SetConfig` kept): Task 1.
- Manager sends only changed keys: Tasks 4 (`Form::changes`), 5 (test).
- `gui.toml` writable (`Serialize`, `reveal_hold`, cap, atomic `save`, broken never overwritten, comments lost): Task 2.
- Store `Config`/`SetConfigs`: Task 3. (`Done` semantics corrected in the spec, `f93fd6a`.)
- `settings_page.rs`: Tasks 4–6. `reauth.rs` setting-driven: Task 2. A save starts the reveal window: Task 5.
- Screen: nav; VAULT loading/values/Save-Cancel enable/presets/custom/kept/warning/note/confirmation drawn in the window/`SETTINGS SAVED`/edits kept/disabled while busy/LINK DOWN: Task 5. DISPLAY header, theme, scanlines (+ reduced-motion note), reveal choices with `Custom (N s)`, broken file with reset, write failure: Task 6.
- Errors: failed read + Retry, refused save keeps edits, failed gui.toml write: Tasks 5–6.
- Security/logging (keys only): Task 1 (`tracing::info!` names keys). Testing list: all covered; snapshots both themes and manual checks: Task 7.
- **Locked-vault correction** (spec commit `f93fd6a`, and the unlock-first change after it): Save marked `VAULT SEALED :: SAVE WILL UNLOCK FIRST`, unlocking first, confirming, saving; a dismissed unlock saves nothing: Task 5.

**Placeholders.** None. Two spots name a fallback for an egui/kittest API that could not be checked without running it (`ui.selectable_label`, clicking a disabled widget, `get_all_by_label` in `pick`): each gives the exact replacement.

**Type consistency.** `Request::Config`, `Request::SetConfigs(OwnedFd, BTreeMap<String,String>)`, `StoreEvent::Config(Result<BTreeMap<..>, String>)`, `Form::from_values/changes/edited/valid/cancel`, `Timeout::{new, read, kept_text, choose_custom, value, error, edited, reset}`, `Values::{Unknown, Loading, Failed, Ready}`, `Page`, `VaultView`, `VaultAction`, `DisplayView`, `DisplayAction`, `Reauth::needed(now, hold)`, `Settings::{load, save, reset}`, `Manager::{page, form, settings, with_settings_file}` are named the same in every task that uses them. Request names: `"read the settings"` / `"save the settings"` in Tasks 3, 5.
