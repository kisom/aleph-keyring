# The Prompter Implementation Plan (Plan 5a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a locked keyring asks for the login password or a security key in a small window (`aleph-gui prompt`) whenever an application needs a secret, instead of waiting for `alephctl unlock`.

**Architecture:**
- **alephd** already starts `<prompt.program> prompt` with one end of a socketpair as `ALEPH_PROMPT_FD` and speaks `aleph-prompt-proto` over it (Plan 3). It now starts it on the session's *current* Wayland display, read at each launch from the systemd user manager's environment: alephd is often started by `pam_aleph` during login, before the compositor exists, so its own environment has no display.
- **`aleph-gui`** is a new crate: a pure conversation state machine (what the window shows, which answers it may send), a reader thread on the socket, a theme (Omarchy's `colors.toml`, followed live, or Aleph neon), and an eframe window with app_id `aleph-prompt` drawing one screen per protocol message.
- **Setup** offers a Hyprland window rule (float, center, pin, keep focus), included from `~/.config/hypr/hyprland.lua`; revert takes it out. `packaging/install.sh` installs `aleph-gui` and the rule.

**Tech Stack:** Rust 1.98; eframe/egui 0.36 (glow renderer, Wayland only); egui_kittest 0.36 (screens driven through AccessKit, snapshots rendered with wgpu); notify 8; zbus 5 (the user manager's `Environment`); Hyprland's Lua configuration.

**Spec:** `docs/superpowers/specs/2026-09-26-aleph-design.md` revision 2 (§6 "Prompter orchestration", §7 "GUI": Theme and Prompter, §8 installs, §9 "GUI" testing). Decisions: `DECISIONS.md` H1 (the split, the owner's) and H2 (calls made while prototyping; Task 6 adds both). Task 6 updates the spec.

**Plan series:** 1–4c (done) → **5a the prompter (this plan)** → 5b the manager window → 6 packaging and CI.

**Base:** `master` (with Plan 4c and its fixes).

**Prerequisites** (once per machine), beyond the earlier plans':
- `lua` (`luac`): Task 5 checks the Hyprland files are valid Lua (Arch: `pacman -S lua`).
- A wgpu adapter for the snapshot tests: any Mesa or vendor Vulkan/GL driver; on a headless machine, Mesa's software Vulkan (`vulkan-swrast`).
- `wayland` and `libxkbcommon` (build and run; present on any Wayland desktop).

## Decisions made while prototyping

Every task was prototyped on a clone of `master` and the whole gate run (`make gate`: fmt, clippy `-D warnings`, the full suite) green; the code below is that prototype's, verbatim. The properties below were each checked by reverting them (the "teeth" step of the owning task). `DECISIONS.md` H2 lists these calls for the reviewers.

- **The display comes from the user manager** (`org.freedesktop.systemd1.Manager.Environment`, read uncached at each launch, 2 s limit), and only when the manager cannot be asked from alephd's own environment. No `WAYLAND_DISPLAY` there means no graphical session now: no prompter, and the prompt waits for an unlock from elsewhere (§4), as before. The journal says which reason stopped a prompter (no display, or `aleph-gui` not installed).
- **The GUI's settings are their own file,** `~/.config/aleph/gui.toml` (`theme = "auto" | "neon"`, `scanlines = true|false`): alephd's `config.toml` refuses unknown keys, and alephd has no use for them. An unreadable file warns (stderr) and uses the defaults: a prompt must still open.
- **Reduced motion** is GNOME's `enable-animations = false` (`gsettings`), the setting GTK apps and the portal share; absent `gsettings`, not requested. It turns off the scanlines, spinners, and egui's animations. Scanlines are static lines, drawn over everything.
- **Omarchy's palette:** `background`, `foreground`, and `accent` are required; `dark_background` (fields), `selection`, `muted`, `red` (errors), `yellow` (warnings), and `mode` are used when present, blends otherwise. A file that does not parse falls back to Aleph neon. Omarchy rewrites the theme's files in place: the watcher follows `~/.local/state/omarchy/current` recursively.
- **The conversation is strict:** the first message must be `Begin`; the recovery-key question is refused (answered `Cancel`, nothing typed) outside a `Recover` conversation; one answer per question; `Cancel` any time. A `Done` without a message closes the window, with one it stays until closed; alephd closing the socket closes it too. A window that cannot open sends `Cancel` at once and exits 1, so alephd never waits out the prompt timeout.
- **Text from other programs** (collection labels in confirmations, process names, key names, errors) is shown on one line per item, control characters replaced, and cut at 80 characters (names, the title) or 400 (questions, errors, messages): it can neither draw a fake prompt inside the real one nor push the buttons out of view.
- **The window** is 460×300 logical pixels, not resizable, titled `aleph`. Escape cancels (closes, once over); Enter answers (a confirmation's default; "Use security key" when it is the only method). During a typed-password back-off the password is held (a countdown shows) while a security key can still be used.
- **Hyprland:** only the Lua configuration (Omarchy's) gets the offer. Setup appends `pcall(dofile, "/usr/share/aleph/hyprland/aleph-prompt.lua")` (with a comment line) in place, so a symlinked dotfile stays a symlink and an uninstalled aleph never breaks Hyprland's configuration; revert removes exactly that. The rule floats, centers, pins, and keeps the keyboard on the prompt (`stay_focused`) so a password is never typed into another window; the prompt always ends (answer, Escape, or the prompt timeout).
- **The terminal prompter's comment** claimed the GUI offers "skip" while waiting for a key: the protocol has no such answer. Cancel ends the operation in both.

## Global Constraints

- Rust stable 1.98, edition 2024; every crate `license = "Apache-2.0"` (workspace).
- `eframe` and `egui` 0.36 with `default-features = false, features = ["default_fonts", "glow", "wayland"]` for eframe; `egui_kittest` 0.36 with `["snapshot", "wgpu"]` (dev only); `notify` 8.
- **Exact names:** the program `aleph-gui`, run as `aleph-gui prompt`; app_id `aleph-prompt`; `ALEPH_PROMPT_FD`; `~/.config/aleph/gui.toml`; `/usr/share/aleph/hyprland/aleph-prompt.lua`; `~/.config/hypr/hyprland.lua`; the Omarchy theme at `~/.local/state/omarchy/current/theme/colors.toml`.
- Secrets travel only over the prompter socket; typed secrets live in `Zeroizing<String>` and are moved (never copied) into the answer. Never log or print a secret, and never quote a malformed message (it may hold one).
- Tests never open a window on the real display (kittest renders offscreen; the binary tests name a Wayland socket that does not exist), never ask the real user manager (a stand-in on a private bus), and never touch the real system, as in earlier plans.
- aleph is live on the development machine: do not restart alephd, reinstall, or edit installed units while executing; the manual checks (Task 6) are the owner's.
- `cargo fmt` default; `cargo clippy --all-targets -- -D warnings` clean after every task.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

## Review Focus

1. **The prompt opens without the keyboard** (behind a fullscreen window, on another monitor, or before the rule is included), and a password is typed into another window. → the rule's `stay_focused` and setup's offer: Task 5 `the_hyprland_files_are_lua` (the rule names the app_id), `setup_adds_the_prompts_window_rule_to_hyprland_once`; the window taking focus itself: Task 4 `after_a_wrong_password_the_field_is_ready_again`. Focus on the real desktop is a manual check (Task 6, testing.md).
2. **alephd started before the compositor** (PAM at login, SDDM autologin at boot) must still show the prompt once the desktop is up. → Task 1 `the_display_is_read_from_the_user_manager_at_each_launch`, `a_launched_prompter_talks_over_its_inherited_socket`, `no_display_starts_no_prompter`.
3. **Text from other programs** (a collection label, a process name) must not fake prompt lines or hide the buttons. → Task 2 `shown_text_has_no_line_breaks_and_is_cut`; Task 4 snapshot `confirm_long_label_*`.
4. **The conversation ends under the window** (alephd restarts, the prompt times out, the keyring is unlocked elsewhere): the window must close or say why, never sit waiting. → Task 4 `alephd_going_away_closes_the_window`, `done_closes_unless_there_is_a_message`, `without_a_display_it_cancels`.
5. **A retry** after a wrong password, and a TPM or attempt back-off: the field is cleared and focused again, and a password is not sent before it may be tried. → Task 2 `a_password_waits_out_the_back_off_but_a_key_does_not`; Task 4 `after_a_wrong_password_the_field_is_ready_again`, `a_password_is_held_during_the_back_off`.

## File Structure

```
crates/aleph-daemon/src/display.rs        Session (trait), OwnEnvironment, UserManager (the user manager's environment)
crates/aleph-daemon/src/{prompt,main,lib}.rs  ProgramLauncher starts the prompter on the session's display
crates/aleph-daemon/tests/{display,launcher}.rs
crates/aleph-gui/Cargo.toml
crates/aleph-gui/src/lib.rs
crates/aleph-gui/src/conversation.rs      Conversation, Screen, Action, shown: the protocol without drawing
crates/aleph-gui/src/link.rs              take_from_env, spawn_reader, send: the socket
crates/aleph-gui/src/settings.rs          Settings (gui.toml), reduced_motion
crates/aleph-gui/src/theme.rs             Palette, neon, parse_colors, resolve, visuals, apply, paint_scanlines
crates/aleph-gui/src/screens.rs           PromptUi: one screen per message, clicks and keys to Actions
crates/aleph-gui/src/app.rs               PromptApp: messages in, answers out, closing, the theme watcher
crates/aleph-gui/src/main.rs              aleph-gui prompt
crates/aleph-gui/tests/{screens,binary}.rs; tests/fixtures/colors.toml; tests/home/…/colors.toml; tests/snapshots/*.png
crates/aleph-cli/src/wizard.rs            the Hyprland include
crates/aleph-cli/src/{main,prompter}.rs   setup's offer, revert's removal
crates/aleph-cli/tests/cli.rs
packaging/hyprland/aleph-prompt.lua; packaging/install.sh; .gitignore
docs: spec (§6, §7, §8, §9), DECISIONS.md (H1, H2), testing.md, README.md
```

---

### Task 1: alephd starts the prompter on the session's display

**Files:**
- Create: `crates/aleph-daemon/src/display.rs`, `crates/aleph-daemon/tests/display.rs`
- Modify: `crates/aleph-daemon/src/lib.rs`, `crates/aleph-daemon/src/prompt.rs` (`ProgramLauncher`), `crates/aleph-daemon/src/main.rs`, `crates/aleph-daemon/tests/launcher.rs`

**Interfaces:**
- Produces:
  - `display::Session` (trait, `Send + Sync`): `fn wayland_display(&self) -> Option<String>`
  - `display::OwnEnvironment` (alephd's own `WAYLAND_DISPLAY`)
  - `display::UserManager { pub conn: zbus::Connection, pub runtime: tokio::runtime::Handle }` (blocks; call from blocking threads only)
  - `prompt::ProgramLauncher { pub config: Arc<Mutex<Config>>, pub session: Arc<dyn display::Session> }`; the child gets `WAYLAND_DISPLAY` set to the session's display

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-daemon/src/display.rs` with only its tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_managers_environment_wins_over_alephds_own() {
        let env = vec![
            "PATH=/usr/bin".to_string(),
            "WAYLAND_DISPLAY=wayland-1".into(),
        ];
        assert_eq!(
            choose(Some(&env), Some("wayland-0".into())),
            Some("wayland-1".into())
        );
        // No display in the session now (logged out): none, even if alephd
        // started with one.
        assert_eq!(choose(Some(&env[..1]), Some("wayland-0".into())), None);
        // The manager could not be asked: alephd's own.
        assert_eq!(
            choose(None, Some("wayland-0".into())),
            Some("wayland-0".into())
        );
        assert_eq!(choose(Some(&["WAYLAND_DISPLAY=".to_string()]), None), None);
    }
}
```

and add the module to `crates/aleph-daemon/src/lib.rs`, after `pub mod daemon;`:

```rust
pub mod display;
```

Write `crates/aleph-daemon/tests/display.rs`:

```rust
//! The prompter's display comes from the user manager's environment, read
//! at each launch (a stand-in `org.freedesktop.systemd1` on a private bus:
//! the real manager is never asked).

use std::sync::{Arc, Mutex};

use aleph_daemon::display::{Session, UserManager};

struct Manager(Arc<Mutex<Vec<String>>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Manager {
    #[zbus(property)]
    fn environment(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

async fn connect(bus: &aleph_daemon::testing::Bus) -> zbus::Connection {
    zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap()
}

/// The display the compositor exported after alephd started is the one
/// used, and a change is seen at the next launch.
#[tokio::test(flavor = "multi_thread")]
async fn the_display_is_read_from_the_user_manager_at_each_launch() {
    let bus = aleph_daemon::testing::bus();
    let env = Arc::new(Mutex::new(vec!["PATH=/usr/bin".to_string()]));
    let _manager = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.systemd1")
        .unwrap()
        .serve_at("/org/freedesktop/systemd1", Manager(env.clone()))
        .unwrap()
        .build()
        .await
        .unwrap();
    let session = Arc::new(UserManager {
        conn: connect(&bus).await,
        runtime: tokio::runtime::Handle::current(),
    });
    let ask = |s: Arc<UserManager>| tokio::task::spawn_blocking(move || s.wayland_display());
    assert_eq!(ask(session.clone()).await.unwrap(), None);
    env.lock().unwrap().push("WAYLAND_DISPLAY=wayland-7".into());
    assert_eq!(ask(session).await.unwrap(), Some("wayland-7".into()));
}
```

Replace `crates/aleph-daemon/tests/launcher.rs` with (the prompter script now also checks `WAYLAND_DISPLAY`; the test no longer sets the process environment):

```rust
//! `ProgramLauncher` against a real child process.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use aleph_daemon::config::Config;
use aleph_daemon::prompt::{FromPrompter, Launcher, ProgramLauncher, ToPrompter};

/// A fixed session display.
struct Display(Option<&'static str>);

impl aleph_daemon::display::Session for Display {
    fn wayland_display(&self) -> Option<String> {
        self.0.map(Into::into)
    }
}

/// The prompter gets its socket as `ALEPH_PROMPT_FD` (inheritable in the
/// child, though close-on-exec in the daemon) and the session's display as
/// `WAYLAND_DISPLAY`, and the conversation runs over it.
#[test]
fn a_launched_prompter_talks_over_its_inherited_socket() {
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("prompter");
    std::fs::write(
        &program,
        "#!/bin/sh\n[ \"$1\" = prompt ] || exit 2\n[ \"$WAYLAND_DISPLAY\" = wayland-7 ] || exit 3\nread -r line <&\"$ALEPH_PROMPT_FD\"\nprintf '{\"type\":\"confirm\",\"yes\":true}\\n' >&\"$ALEPH_PROMPT_FD\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = Config::default();
    config.prompt.program = program.display().to_string();
    config.prompt.timeout = 10;
    let launcher = ProgramLauncher {
        config: Arc::new(Mutex::new(config.clone())),
        session: Arc::new(Display(Some("wayland-7"))),
    };
    let mut chan = launcher.launch().unwrap();
    let reply = chan
        .ask(&ToPrompter::Confirm {
            text: "ok?".into(),
            default: false,
        })
        .unwrap();
    assert_eq!(reply, FromPrompter::Confirm { yes: true });
}

/// No display in the session: no prompter is started (the prompt waits
/// for an unlock from elsewhere).
#[test]
fn no_display_starts_no_prompter() {
    let dir = tempfile::tempdir().unwrap();
    let ran = dir.path().join("ran");
    let program = dir.path().join("prompter");
    std::fs::write(&program, format!("#!/bin/sh\ntouch {}\n", ran.display())).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = Config::default();
    config.prompt.program = program.display().to_string();
    let launcher = ProgramLauncher {
        config: Arc::new(Mutex::new(config)),
        session: Arc::new(Display(None)),
    };
    assert!(matches!(
        launcher.launch(),
        Err(aleph_daemon::Error::NoPrompter)
    ));
    assert!(!ran.exists());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-daemon --lib display`
Expected: the build fails: `choose`, `Session`, and `UserManager` do not exist.

- [ ] **Step 3: Implement**

Put this above the tests in `crates/aleph-daemon/src/display.rs`:

```rust
//! Which display a prompter opens on (spec §6 "Prompter orchestration").
//!
//! alephd's own environment is fixed when it starts, and it often starts
//! before the compositor: `pam_aleph` activates it during login, before
//! Hyprland has run (and exported `WAYLAND_DISPLAY` to the user manager).
//! So at each launch the display is read from the user manager's current
//! environment, where the compositor puts it (`systemctl --user
//! import-environment`), and only if the manager cannot be asked from
//! alephd's own.

use std::time::Duration;

/// Where a prompter's display comes from.
pub trait Session: Send + Sync {
    /// The session's Wayland display (`WAYLAND_DISPLAY`), if it has one now.
    fn wayland_display(&self) -> Option<String>;
}

/// alephd's own environment.
pub struct OwnEnvironment;

impl Session for OwnEnvironment {
    fn wayland_display(&self) -> Option<String> {
        std::env::var("WAYLAND_DISPLAY")
            .ok()
            .filter(|v| !v.is_empty())
    }
}

/// The systemd user manager's environment (its `Environment` property,
/// read fresh at each launch), falling back to alephd's own when the
/// manager cannot be asked.
pub struct UserManager {
    pub conn: zbus::Connection,
    pub runtime: tokio::runtime::Handle,
}

/// How long the manager may take to answer.
const ASK: Duration = Duration::from_secs(2);

impl Session for UserManager {
    /// Blocks: called from blocking threads (prompts run on them), never
    /// from async code.
    fn wayland_display(&self) -> Option<String> {
        let manager = self.runtime.block_on(async {
            tokio::time::timeout(ASK, manager_environment(&self.conn))
                .await
                .ok()?
                .map_err(|e| tracing::debug!("the user manager's environment: {e}"))
                .ok()
        });
        choose(manager.as_deref(), OwnEnvironment.wayland_display())
    }
}

async fn manager_environment(conn: &zbus::Connection) -> zbus::Result<Vec<String>> {
    // Not cached: systemd does not signal changes to it.
    let proxy: zbus::Proxy = zbus::proxy::Builder::new(conn)
        .destination("org.freedesktop.systemd1")?
        .path("/org/freedesktop/systemd1")?
        .interface("org.freedesktop.systemd1.Manager")?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    proxy.get_property("Environment").await
}

/// The manager's word when it answered (no display there means none now,
/// whatever alephd started with); alephd's own otherwise.
fn choose(manager: Option<&[String]>, own: Option<String>) -> Option<String> {
    match manager {
        Some(env) => env
            .iter()
            .find_map(|kv| kv.strip_prefix("WAYLAND_DISPLAY="))
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        None => own,
    }
}
```

In `crates/aleph-daemon/src/prompt.rs`, replace

```rust
/// Runs `<program> prompt` with its end of a socketpair as
/// `ALEPH_PROMPT_FD` (via `std::process::Command`: fork and exec, with only
/// an `fcntl` between them, never a bare fork).
pub struct ProgramLauncher {
    /// Read at each launch, so `prompt.program` and `prompt.timeout`
    /// changes apply to the next prompt without a restart.
    pub config: std::sync::Arc<std::sync::Mutex<crate::config::Config>>,
}

impl Launcher for ProgramLauncher {
    fn launch(&self) -> Result<Channel> {
        if std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return Err(Error::NoPrompter);
        }
```

with

```rust
/// Runs `<program> prompt` with its end of a socketpair as
/// `ALEPH_PROMPT_FD` (via `std::process::Command`: fork and exec, with only
/// an `fcntl` between them, never a bare fork), on the session's current
/// Wayland display.
pub struct ProgramLauncher {
    /// Read at each launch, so `prompt.program` and `prompt.timeout`
    /// changes apply to the next prompt without a restart.
    pub config: std::sync::Arc<std::sync::Mutex<crate::config::Config>>,
    /// Where the display comes from (the user manager, in alephd).
    pub session: std::sync::Arc<dyn crate::display::Session>,
}

impl Launcher for ProgramLauncher {
    fn launch(&self) -> Result<Channel> {
        let Some(display) = self.session.wayland_display() else {
            tracing::info!("no prompter: the session has no Wayland display");
            return Err(Error::NoPrompter);
        };
```

replace

```rust
        command.arg("prompt").env("ALEPH_PROMPT_FD", fd.to_string());
```

with

```rust
        command
            .arg("prompt")
            .env("ALEPH_PROMPT_FD", fd.to_string())
            .env("WAYLAND_DISPLAY", display);
```

and replace

```rust
            Err(e) if e.kind() == ErrorKind::NotFound => Err(Error::NoPrompter),
```

with

```rust
            Err(e) if e.kind() == ErrorKind::NotFound => {
                tracing::info!("no prompter: {program} is not installed");
                Err(Error::NoPrompter)
            }
```

In `crates/aleph-daemon/src/main.rs`, add `use aleph_daemon::display::UserManager;` after `use aleph_daemon::config::Config;`, and move the launcher after the bus connection, giving it the user manager. Replace

```rust
    let launcher = Arc::new(ProgramLauncher {
        config: config.clone(),
    });
    let conn = zbus::connection::Builder::session()
        .and_then(|b| b.name(BUS_NAME))
        .map_err(|e| e.to_string())?
        .build()
        .await
        .map_err(|e| format!("cannot own {BUS_NAME} on the session bus: {e}"))?;
```

with

```rust
    let conn = zbus::connection::Builder::session()
        .and_then(|b| b.name(BUS_NAME))
        .map_err(|e| e.to_string())?
        .build()
        .await
        .map_err(|e| format!("cannot own {BUS_NAME} on the session bus: {e}"))?;
    let launcher = Arc::new(ProgramLauncher {
        config: config.clone(),
        session: Arc::new(UserManager {
            conn: conn.clone(),
            runtime: tokio::runtime::Handle::current(),
        }),
    });
```

(Prompts run on blocking threads: `SecretService` runs each in `spawn_blocking`, and `Keyring::unlock_prompting` is called from there, so `Handle::block_on` inside `UserManager` is allowed.)

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-daemon --lib display && cargo test -q -p aleph-daemon --test display --test launcher && cargo test -q -p aleph-daemon && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `ok. 1 passed` (the unit test; the rest filtered), then `ok. 1 passed` (display) and `ok. 2 passed` (launcher), then every aleph-daemon test binary ok.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL, then undo the change and see it pass again:

- **the child gets the session's display** (`crates/aleph-daemon/src/prompt.rs`), test `cargo test -p aleph-daemon --test launcher`: replace `.env("WAYLAND_DISPLAY", display);` with `;let _ = display;` (the prompter script exits 3; the conversation fails).
- **the manager's environment is read** (`crates/aleph-daemon/src/display.rs`), test `env -u WAYLAND_DISPLAY cargo test -p aleph-daemon --test display`: replace `choose(manager.as_deref(), OwnEnvironment.wayland_display())` with `{ let _ = manager; OwnEnvironment.wayland_display() }`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-daemon
git commit -m "fix: alephd starts the prompter on the session's current display" -m "alephd is often started by pam_aleph during login, before the compositor exports WAYLAND_DISPLAY: the display now comes from the user manager's environment at each launch." -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 2: `aleph-gui`: the conversation and the socket

**Files:**
- Create: `crates/aleph-gui/Cargo.toml`, `crates/aleph-gui/src/lib.rs`, `crates/aleph-gui/src/conversation.rs`, `crates/aleph-gui/src/link.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Produces:
  - `conversation::Screen` (enum): `Working`, `Ask { methods: Vec<Method>, error: Option<String>, retry_at: Option<Instant> }`, `OldPassword { error }`, `Pin { key: String, error }`, `InsertKey { key }`, `Touch { key }`, `Confirm { text: String, default: bool }`, `RecoveryKey { error }`, `ShowRecoveryKey { key: Secret, check: [usize; 2], error, checking: bool }`, `Finished { ok: bool, message: Option<String> }`
  - `conversation::Action` (enum): `Password(Secret)`, `Fido2`, `Pin(Secret)`, `Confirm(bool)`, `RecoveryKey(Secret)`, `RecoveryKeyWritten`, `RecoveryCheck([Secret; 2])`, `Cancel`, `Close`
  - `conversation::Conversation { pub purpose: Option<Purpose>, pub operation: String, pub caller: Option<Caller>, pub screen: Screen }` with `new()`, `finished() -> bool`, `receive(&mut self, ToPrompter, Instant) -> Option<FromPrompter>` (an answer to send at once: a refusal), `act(&mut self, Action, Instant) -> Option<FromPrompter>`
  - `conversation::shown(&str, usize) -> String`
  - `link::Event` (enum): `Message(ToPrompter)`, `Closed`, `Broken(String)`; `link::take_from_env() -> Result<UnixStream, String>`; `link::spawn_reader(UnixStream, impl Fn() + Send + 'static) -> io::Result<Receiver<Event>>`; `link::send(&UnixStream, &FromPrompter) -> io::Result<()>`

- [ ] **Step 1: Write the failing tests**

Add the crate to the workspace: in `Cargo.toml`, replace `"crates/pam_aleph"]` with `"crates/pam_aleph", "crates/aleph-gui"]`.

Write `crates/aleph-gui/Cargo.toml`:

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
eframe = { version = "0.36", default-features = false, features = ["default_fonts", "glow", "wayland"] }
egui = "0.36"
libc.workspace = true
notify = "8"
serde.workspace = true
serde_json.workspace = true
toml = "1"
zeroize.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

Write `crates/aleph-gui/src/lib.rs`:

```rust
//! `aleph-gui`: the aleph keyring's prompter (spec §7), started by alephd
//! as `aleph-gui prompt`. (The manager window comes with Plan 5b.)

pub mod conversation;
pub mod link;
```

Write `crates/aleph-gui/src/conversation.rs` with only its tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn begun(purpose: Purpose) -> Conversation {
        let mut c = Conversation::new();
        assert_eq!(
            c.receive(
                ToPrompter::Begin {
                    purpose,
                    operation: "Unlock the keyring".into(),
                    caller: None,
                },
                Instant::now(),
            ),
            None
        );
        c
    }

    fn ask(methods: Vec<Method>, retry_after: Option<u64>) -> ToPrompter {
        ToPrompter::Ask {
            methods,
            error: None,
            retry_after,
        }
    }

    #[test]
    fn a_password_answers_the_question_once() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        c.receive(ask(vec![Method::Password], None), now);
        let reply = c.act(Action::Password(Secret::new("pw")), now);
        assert_eq!(
            reply,
            Some(FromPrompter::Password {
                password: Secret::new("pw")
            })
        );
        assert_eq!(c.screen, Screen::Working);
        // A second answer to the same question is not sent.
        assert_eq!(c.act(Action::Password(Secret::new("pw")), now), None);
    }

    /// Only the methods offered can answer.
    #[test]
    fn a_method_not_offered_does_not_answer() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        c.receive(ask(vec![Method::Password], None), now);
        assert_eq!(c.act(Action::Fido2, now), None);
        c.receive(ask(vec![Method::Fido2], None), now);
        assert_eq!(c.act(Action::Password(Secret::new("pw")), now), None);
        assert_eq!(c.act(Action::Fido2, now), Some(FromPrompter::Fido2 {}));
    }

    /// While a typed password must wait, it is not sent; a key can still
    /// be used.
    #[test]
    fn a_password_waits_out_the_back_off_but_a_key_does_not() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        c.receive(ask(vec![Method::Password, Method::Fido2], Some(30)), now);
        assert_eq!(c.act(Action::Password(Secret::new("pw")), now), None);
        let later = now + Duration::from_secs(30);
        assert!(c.act(Action::Password(Secret::new("pw")), later).is_some());
        c.receive(ask(vec![Method::Password, Method::Fido2], Some(30)), now);
        assert_eq!(c.act(Action::Fido2, now), Some(FromPrompter::Fido2 {}));
    }

    /// Cancel is always possible, even with no question (waiting for a
    /// key or a touch), and ends the conversation.
    #[test]
    fn cancel_is_sent_while_waiting_for_a_key() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        c.receive(
            ToPrompter::InsertKey {
                key: "yubikey".into(),
            },
            now,
        );
        assert_eq!(c.act(Action::Fido2, now), None);
        assert_eq!(c.act(Action::Cancel, now), Some(FromPrompter::Cancel {}));
        assert!(c.finished());
        assert_eq!(c.act(Action::Cancel, now), None);
    }

    /// The recovery key is only ever asked in a recovery conversation
    /// (spec §5); anywhere else the question is refused unanswered.
    #[test]
    fn the_recovery_key_is_refused_outside_a_recovery() {
        let now = Instant::now();
        let mut c = begun(Purpose::Unlock);
        let reply = c.receive(ToPrompter::RecoveryKey { error: None }, now);
        assert_eq!(reply, Some(FromPrompter::Cancel {}));
        assert!(matches!(c.screen, Screen::Finished { ok: false, .. }));

        let mut c = begun(Purpose::Recover);
        assert_eq!(
            c.receive(ToPrompter::RecoveryKey { error: None }, now),
            None
        );
        assert_eq!(
            c.act(Action::RecoveryKey(Secret::new("K")), now),
            Some(FromPrompter::RecoveryKey {
                key: Secret::new("K")
            })
        );
    }

    /// Text from other programs (a collection label, a process name) can
    /// neither break lines nor run on.
    #[test]
    fn shown_text_has_no_line_breaks_and_is_cut() {
        assert_eq!(shown("a\nb\tc", 10), "a b c");
        assert_eq!(shown(&"x".repeat(500), 5), "xxxxx…");
        assert_eq!(shown("ééé", 2), "éé…");
        let mut c = begun(Purpose::Reauth);
        c.receive(
            ToPrompter::Confirm {
                text: format!("Delete the collection '{}\n\nUnlock'?", "w".repeat(1000)),
                default: false,
            },
            Instant::now(),
        );
        let Screen::Confirm { text, .. } = &c.screen else {
            panic!("{:?}", c.screen)
        };
        assert!(!text.contains('\n'));
        assert!(text.chars().count() <= TEXT + 1);
    }

    #[test]
    fn a_question_before_begin_is_refused() {
        let mut c = Conversation::new();
        let reply = c.receive(ask(vec![Method::Password], None), Instant::now());
        assert_eq!(reply, Some(FromPrompter::Cancel {}));
        assert!(c.finished());
    }

    /// The new recovery key is shown first; the check comes after "written
    /// down", and only then answers.
    #[test]
    fn the_recovery_check_follows_the_key() {
        let now = Instant::now();
        let mut c = begun(Purpose::Create);
        c.receive(
            ToPrompter::ShowRecoveryKey {
                key: Secret::new("ABCD-EFGH"),
                check: [2, 9],
                error: None,
            },
            now,
        );
        let groups = || [Secret::new("a"), Secret::new("b")];
        assert_eq!(c.act(Action::RecoveryCheck(groups()), now), None);
        assert_eq!(c.act(Action::RecoveryKeyWritten, now), None);
        assert!(matches!(
            c.screen,
            Screen::ShowRecoveryKey { checking: true, .. }
        ));
        assert_eq!(
            c.act(Action::RecoveryCheck(groups()), now),
            Some(FromPrompter::RecoveryCheck { groups: groups() })
        );
    }

    #[test]
    fn done_finishes_with_its_message() {
        let mut c = begun(Purpose::Unlock);
        c.receive(
            ToPrompter::Done {
                ok: true,
                message: Some("note".into()),
            },
            Instant::now(),
        );
        assert_eq!(
            c.screen,
            Screen::Finished {
                ok: true,
                message: Some("note".into())
            }
        );
        // Nothing more is taken once it is over.
        assert_eq!(
            c.receive(ask(vec![Method::Password], None), Instant::now()),
            None
        );
    }
}
```

Write `crates/aleph-gui/src/link.rs` with only its tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aleph_prompt_proto::Secret;
    use std::io::{BufRead, BufReader};
    use std::time::Duration;

    #[test]
    fn messages_arrive_in_order_then_closed() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let rx = spawn_reader(ours, || {}).unwrap();
        theirs
            .write_all(
                b"{\"type\":\"touch\",\"key\":\"a\"}\n{\"type\":\"done\",\"ok\":true,\"message\":null}\n",
            )
            .unwrap();
        drop(theirs);
        let t = Duration::from_secs(5);
        assert!(matches!(
            rx.recv_timeout(t).unwrap(),
            Event::Message(ToPrompter::Touch { .. })
        ));
        assert!(matches!(
            rx.recv_timeout(t).unwrap(),
            Event::Message(ToPrompter::Done { ok: true, .. })
        ));
        assert!(matches!(rx.recv_timeout(t).unwrap(), Event::Closed));
    }

    /// A malformed message ends the link without quoting it (it may be a
    /// recovery key with a wrong field).
    #[test]
    fn a_malformed_message_is_not_quoted() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let rx = spawn_reader(ours, || {}).unwrap();
        theirs
            .write_all(b"{\"type\":\"show_recovery_key\",\"key\":\"SECRET-KEY\"}\n")
            .unwrap();
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Broken(m) => assert!(!m.contains("SECRET"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_over_long_message_breaks_the_link() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let rx = spawn_reader(ours, || {}).unwrap();
        let writer = std::thread::spawn(move || {
            let _ = theirs.write_all(&vec![b'x'; MAX_LINE + 10]);
            theirs
        });
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Event::Broken(m) => assert!(m.contains("too long"), "{m}"),
            other => panic!("{other:?}"),
        }
        drop(writer.join());
    }

    #[test]
    fn an_answer_is_one_line() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        send(
            &ours,
            &FromPrompter::Pin {
                pin: Secret::new("1234"),
            },
        )
        .unwrap();
        let mut line = String::new();
        BufReader::new(theirs).read_line(&mut line).unwrap();
        assert_eq!(line, "{\"type\":\"pin\",\"pin\":\"1234\"}\n");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-gui --lib`
Expected: the build fails: `Conversation`, `Screen`, `Action`, `shown`, `spawn_reader`, `send`, and `Event` do not exist.

- [ ] **Step 3: Implement**

Put this above the tests in `crates/aleph-gui/src/conversation.rs`:

```rust
//! One prompter conversation with `alephd` (spec §6 "Prompter
//! orchestration"), without any drawing: what the window shows, and which
//! answers it may send.
//!
//! alephd sends [`ToPrompter`] messages; the ones that need a reply get
//! exactly one [`FromPrompter`], and `Cancel` may be sent at any time. The
//! conversation starts with `Begin` and ends with `Done`.

use std::time::{Duration, Instant};

use aleph_prompt_proto::{Caller, FromPrompter, Method, Purpose, Secret, ToPrompter};

/// What the window shows.
#[derive(Debug, PartialEq)]
pub enum Screen {
    /// Before the first question, and after an answer until the next
    /// message (alephd is checking it).
    Working,
    /// Choose a method: the login password and/or a security key.
    Ask {
        methods: Vec<Method>,
        error: Option<String>,
        /// When a typed password can be tried again (a TPM or attempt
        /// back-off); until then only a security key can be used.
        retry_at: Option<Instant>,
    },
    /// The login password changed without aleph: the previous one.
    OldPassword {
        error: Option<String>,
    },
    Pin {
        key: String,
        error: Option<String>,
    },
    InsertKey {
        key: String,
    },
    Touch {
        key: String,
    },
    Confirm {
        text: String,
        default: bool,
    },
    /// The recovery key (a recovery conversation only).
    RecoveryKey {
        error: Option<String>,
    },
    /// A new recovery key, shown once; then two of its groups are typed
    /// back (`checking`).
    ShowRecoveryKey {
        key: Secret,
        check: [usize; 2],
        error: Option<String>,
        checking: bool,
    },
    /// The conversation is over.
    Finished {
        ok: bool,
        message: Option<String>,
    },
}

/// What the person did.
#[derive(Debug, PartialEq)]
pub enum Action {
    Password(Secret),
    Fido2,
    Pin(Secret),
    Confirm(bool),
    RecoveryKey(Secret),
    /// "I have written it down": show the check.
    RecoveryKeyWritten,
    RecoveryCheck([Secret; 2]),
    Cancel,
    /// Close the window once the conversation is over.
    Close,
}

/// The longest text shown for a title, a key's or a caller's name.
const NAME: usize = 80;
/// The longest question, error, or closing message shown.
const TEXT: usize = 400;

/// Text from alephd as shown: control characters (newlines included)
/// become spaces, and it is cut to `max` characters. Collection labels and
/// process names come from other programs; they must not be able to draw
/// a fake prompt inside the real one, or push its buttons out of view.
pub fn shown(s: &str, max: usize) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.trim();
    match clean.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…", &clean[..cut]),
        None => clean.to_string(),
    }
}

fn shown_opt(s: Option<String>, max: usize) -> Option<String> {
    s.map(|s| shown(&s, max))
}

pub struct Conversation {
    pub purpose: Option<Purpose>,
    pub operation: String,
    pub caller: Option<Caller>,
    pub screen: Screen,
    /// A question is waiting for its one answer.
    awaiting: bool,
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new()
    }
}

impl Conversation {
    pub fn new() -> Self {
        Self {
            purpose: None,
            operation: String::new(),
            caller: None,
            screen: Screen::Working,
            awaiting: false,
        }
    }

    pub fn finished(&self) -> bool {
        matches!(self.screen, Screen::Finished { .. })
    }

    /// Take a message from alephd. Returns an answer to send at once, if
    /// the message must be refused (a recovery-key question outside a
    /// recovery conversation, anything before `Begin`).
    pub fn receive(&mut self, msg: ToPrompter, now: Instant) -> Option<FromPrompter> {
        if self.finished() {
            return None;
        }
        let begun = self.purpose.is_some();
        let refuse = |this: &mut Self, why: &str| {
            this.screen = Screen::Finished {
                ok: false,
                message: Some(why.into()),
            };
            this.awaiting = false;
            Some(FromPrompter::Cancel {})
        };
        let needs_reply = msg.needs_reply();
        self.screen = match msg {
            ToPrompter::Begin {
                purpose,
                operation,
                caller,
            } => {
                if begun {
                    return refuse(self, "alephd started a second conversation");
                }
                self.purpose = Some(purpose);
                self.operation = shown(&operation, NAME);
                self.caller = caller.map(|c| Caller {
                    name: shown_opt(c.name, NAME),
                    pid: c.pid,
                });
                Screen::Working
            }
            _ if !begun => return refuse(self, "alephd skipped the start of the conversation"),
            // Keeping the root credential off routine prompts makes fake
            // prompts less useful for phishing (spec §5).
            ToPrompter::RecoveryKey { .. } if self.purpose != Some(Purpose::Recover) => {
                return refuse(
                    self,
                    "alephd asked for the recovery key outside a recovery; nothing was sent",
                );
            }
            ToPrompter::RecoveryKey { error } => Screen::RecoveryKey {
                error: shown_opt(error, TEXT),
            },
            ToPrompter::Ask {
                methods,
                error,
                retry_after,
            } => Screen::Ask {
                methods,
                error: shown_opt(error, TEXT),
                retry_at: retry_after
                    .filter(|s| *s > 0)
                    .map(|s| now + Duration::from_secs(s)),
            },
            ToPrompter::OldPassword { error } => Screen::OldPassword {
                error: shown_opt(error, TEXT),
            },
            ToPrompter::Fido2Pin { key, error } => Screen::Pin {
                key: shown(&key, NAME),
                error: shown_opt(error, TEXT),
            },
            ToPrompter::InsertKey { key } => Screen::InsertKey {
                key: shown(&key, NAME),
            },
            ToPrompter::Touch { key } => Screen::Touch {
                key: shown(&key, NAME),
            },
            ToPrompter::Confirm { text, default } => Screen::Confirm {
                text: shown(&text, TEXT),
                default,
            },
            ToPrompter::ShowRecoveryKey { key, check, error } => Screen::ShowRecoveryKey {
                key,
                check,
                error: shown_opt(error, TEXT),
                checking: false,
            },
            ToPrompter::Done { ok, message } => Screen::Finished {
                ok,
                message: shown_opt(message, TEXT),
            },
        };
        self.awaiting = needs_reply;
        None
    }

    /// Act on what the person did. Returns the answer to send, if the
    /// action answers the question on screen (or cancels).
    pub fn act(&mut self, action: Action, now: Instant) -> Option<FromPrompter> {
        if self.finished() {
            return None;
        }
        if action == Action::Cancel {
            self.awaiting = false;
            self.screen = Screen::Finished {
                ok: false,
                message: None,
            };
            return Some(FromPrompter::Cancel {});
        }
        if !self.awaiting {
            return None;
        }
        let reply = match (&mut self.screen, action) {
            (
                Screen::Ask {
                    methods, retry_at, ..
                },
                Action::Password(password),
            ) if methods.contains(&Method::Password) && retry_at.is_none_or(|at| now >= at) => {
                FromPrompter::Password { password }
            }
            (Screen::Ask { methods, .. }, Action::Fido2) if methods.contains(&Method::Fido2) => {
                FromPrompter::Fido2 {}
            }
            (Screen::OldPassword { .. }, Action::Password(password)) => {
                FromPrompter::Password { password }
            }
            (Screen::Pin { .. }, Action::Pin(pin)) => FromPrompter::Pin { pin },
            (Screen::Confirm { .. }, Action::Confirm(yes)) => FromPrompter::Confirm { yes },
            (Screen::RecoveryKey { .. }, Action::RecoveryKey(key)) => {
                FromPrompter::RecoveryKey { key }
            }
            (Screen::ShowRecoveryKey { checking, .. }, Action::RecoveryKeyWritten) => {
                *checking = true;
                return None;
            }
            (Screen::ShowRecoveryKey { checking: true, .. }, Action::RecoveryCheck(groups)) => {
                FromPrompter::RecoveryCheck { groups }
            }
            _ => return None,
        };
        self.awaiting = false;
        self.screen = Screen::Working;
        Some(reply)
    }
}
```

Put this above the tests in `crates/aleph-gui/src/link.rs`:

```rust
//! The prompter's end of the socketpair alephd spawned it with
//! (`ALEPH_PROMPT_FD`): one JSON message per line each way.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender, channel};

use aleph_prompt_proto::{FromPrompter, MAX_LINE, ToPrompter};
use zeroize::{Zeroize, Zeroizing};

/// What the reader thread passes on.
#[derive(Debug)]
pub enum Event {
    Message(ToPrompter),
    /// alephd closed its end (the conversation is over, or it exited).
    Closed,
    /// Unreadable input; the conversation cannot go on.
    Broken(String),
}

/// Take the socket named by `ALEPH_PROMPT_FD` (removing the variable, so
/// nothing this process starts learns of it). Refuses anything but a
/// socket above standard error, and marks it close-on-exec.
pub fn take_from_env() -> Result<UnixStream, String> {
    let value = std::env::var("ALEPH_PROMPT_FD")
        .map_err(|_| "ALEPH_PROMPT_FD is not set: alephd starts the prompter".to_string())?;
    // SAFETY: single-threaded at this point (called first thing in main).
    unsafe { std::env::remove_var("ALEPH_PROMPT_FD") };
    let fd: RawFd = value
        .trim()
        .parse()
        .map_err(|_| format!("ALEPH_PROMPT_FD is not a descriptor: {value:?}"))?;
    if fd <= 2 {
        return Err(format!("ALEPH_PROMPT_FD {fd} is a standard stream"));
    }
    // SAFETY: fstat and fcntl only inspect and flag the descriptor; a
    // closed or foreign number fails the checks and is never adopted.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return Err(format!("ALEPH_PROMPT_FD {fd} is not open"));
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Err(format!("ALEPH_PROMPT_FD {fd} is not a socket"));
        }
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(format!("ALEPH_PROMPT_FD {fd}: cannot set close-on-exec"));
        }
        Ok(UnixStream::from(OwnedFd::from_raw_fd(fd)))
    }
}

/// Read alephd's messages on a thread, passing each on and calling `wake`
/// (the window repaints) after every event.
pub fn spawn_reader(
    stream: UnixStream,
    wake: impl Fn() + Send + 'static,
) -> std::io::Result<Receiver<Event>> {
    let (tx, rx) = channel();
    stream.set_nonblocking(false)?;
    std::thread::Builder::new()
        .name("alephd-link".into())
        .spawn(move || read_loop(stream, &tx, &wake))?;
    Ok(rx)
}

fn read_loop(mut stream: UnixStream, tx: &Sender<Event>, wake: &dyn Fn()) {
    // Allocated once at its full size, never grown; consumed bytes are
    // wiped (a message may carry a new recovery key).
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_LINE + 1));
    loop {
        if let Some(i) = buf.iter().position(|&b| b == b'\n') {
            let parsed: Result<ToPrompter, _> = serde_json::from_slice(&buf[..i]);
            let len = buf.len();
            buf.copy_within(i + 1.., 0);
            buf[len - i - 1..].zeroize();
            buf.truncate(len - i - 1);
            let event = match parsed {
                Ok(msg) => Event::Message(msg),
                // Never quote it: it may hold a secret.
                Err(e) => Event::Broken(format!("bad message from alephd ({:?})", e.classify())),
            };
            let broken = matches!(event, Event::Broken(_));
            if tx.send(event).is_err() {
                return;
            }
            wake();
            if broken {
                return;
            }
            continue;
        }
        if buf.len() > MAX_LINE {
            let _ = tx.send(Event::Broken("message from alephd too long".into()));
            wake();
            return;
        }
        let start = buf.len();
        buf.resize(MAX_LINE + 1, 0);
        let read = stream.read(&mut buf[start..]);
        buf.truncate(start + *read.as_ref().unwrap_or(&0));
        match read {
            Ok(0) => {
                let _ = tx.send(Event::Closed);
                wake();
                return;
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => {
                let _ = tx.send(Event::Closed);
                wake();
                return;
            }
        }
    }
}

/// Send one answer.
pub fn send(mut stream: &UnixStream, reply: &FromPrompter) -> std::io::Result<()> {
    // Zeroizing: answers carry passwords, PINs, and recovery groups.
    let mut line = Zeroizing::new(serde_json::to_vec(reply).map_err(std::io::Error::other)?);
    line.push(b'\n');
    stream.write_all(&line)
}
```

(`take_from_env` is tested through the binary in Task 4: it changes the process environment.)

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-gui --lib && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `ok. 13 passed` (9 conversation, 4 link).

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below in `crates/aleph-gui/src/conversation.rs`, run `cargo test -q -p aleph-gui --lib` and see the named test FAIL, then undo it:

- **the recovery key only in a recovery** (`the_recovery_key_is_refused_outside_a_recovery`): replace `ToPrompter::RecoveryKey { .. } if self.purpose != Some(Purpose::Recover) => {` with `ToPrompter::RecoveryKey { .. } if false => {`.
- **the back-off holds a password** (`a_password_waits_out_the_back_off_but_a_key_does_not`): replace `&& retry_at.is_none_or(|at| now >= at) =>` with `=>`.
- **one line, cut** (`shown_text_has_no_line_breaks_and_is_cut`): replace `.map(|c| if c.is_control() { ' ' } else { c })` with `.map(|c| c)`.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/aleph-gui
git commit -m "feat(gui): the prompter's conversation and its socket" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 3: `aleph-gui`: settings and theme

**Files:**
- Create: `crates/aleph-gui/src/settings.rs`, `crates/aleph-gui/src/theme.rs`, `crates/aleph-gui/tests/fixtures/colors.toml`
- Modify: `crates/aleph-gui/src/lib.rs`

**Interfaces:**
- Produces:
  - `settings::ThemeChoice` (`Auto` default, `Neon`); `settings::Settings { pub theme: ThemeChoice, pub scanlines: bool }` with `Default` (auto, scanlines on) and `load(&Path) -> (Settings, Option<String>)` (the warning); `settings::{path(&Path) -> PathBuf, config_home() -> Option<PathBuf>, home() -> Option<PathBuf>, reduced_motion() -> bool}`
  - `theme::Palette { pub dark: bool, pub background, pub field, pub foreground, pub muted, pub accent, pub selection, pub error, pub warning: Color32, pub monospace: bool }` (`Clone, Debug, PartialEq`); `theme::{neon() -> Palette, omarchy_colors(&Path) -> PathBuf, omarchy_current(&Path) -> PathBuf, parse_colors(&str) -> Result<Palette, String>, resolve(&Settings, Option<&Path>) -> Palette, visuals(&Palette) -> egui::Visuals, apply(&egui::Context, &Palette), paint_scanlines(&egui::Context, &Palette)}`

- [ ] **Step 1: Write the failing tests**

Write `crates/aleph-gui/tests/fixtures/colors.toml` (Omarchy's Nord theme, as Omarchy 4 writes it):

```toml
mode = "dark"

accent = "#81a1c1"
selection = "#434c5e"
muted = "#4c566a"

background = "#2e3440"
dark_background = "#222730"
darker_background = "#191c23"
lighter_background = "#3b4252"

foreground = "#d8dee9"
dark_foreground = "#667080"
light_foreground = "#adb5c4"
bright_foreground = "#d8dee9"

red = "#bf616a"
yellow = "#ebcb8b"
orange = "#d5967a"
green = "#a3be8c"
cyan = "#88c0d0"
blue = "#81a1c1"
magenta = "#b48ead"
brown = "#6a4b3d"

bright_red = "#bf616a"
bright_yellow = "#ebcb8b"
bright_green = "#a3be8c"
bright_cyan = "#8fbcbb"
bright_blue = "#81a1c1"
bright_magenta = "#b48ead"
```

In `crates/aleph-gui/src/lib.rs`, replace

```rust
pub mod conversation;
pub mod link;
```

with

```rust
pub mod conversation;
pub mod link;
pub mod settings;
pub mod theme;
```

Write `crates/aleph-gui/src/settings.rs` with only its tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Settings::load(&dir.path().join("gui.toml")),
            (Settings::default(), None)
        );
    }

    #[test]
    fn settings_are_read_and_typos_warned_about() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gui.toml");
        std::fs::write(&file, "theme = \"neon\"\nscanlines = false\n").unwrap();
        assert_eq!(
            Settings::load(&file).0,
            Settings {
                theme: ThemeChoice::Neon,
                scanlines: false
            }
        );
        std::fs::write(&file, "scanline = false\n").unwrap();
        let (s, warning) = Settings::load(&file);
        assert_eq!(s, Settings::default());
        assert!(warning.unwrap().contains("scanline"));
    }

    #[test]
    fn only_false_turns_animations_off() {
        assert!(animations_off("false\n"));
        assert!(!animations_off("true\n"));
        assert!(!animations_off(""));
    }
}
```

Write `crates/aleph-gui/src/theme.rs` with only its tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const NORD: &str = include_str!("../tests/fixtures/colors.toml");

    #[test]
    fn an_omarchy_theme_file_maps_to_a_palette() {
        let p = parse_colors(NORD).unwrap();
        assert!(p.dark);
        assert_eq!(p.background, Color32::from_rgb(0x2e, 0x34, 0x40));
        assert_eq!(p.accent, Color32::from_rgb(0x81, 0xa1, 0xc1));
        assert_eq!(p.field, Color32::from_rgb(0x22, 0x27, 0x30));
        assert_eq!(p.error, Color32::from_rgb(0xbf, 0x61, 0x6a));
        assert!(!p.monospace);
    }

    #[test]
    fn only_the_three_base_colors_are_required() {
        let p = parse_colors(
            "mode = \"light\"\nbackground = \"#ffffff\"\nforeground = \"#000000\"\naccent = \"#0000ff\"\n",
        )
        .unwrap();
        assert!(!p.dark);
        assert_eq!(p.muted, Color32::from_rgb(0x80, 0x80, 0x80));
        assert!(
            parse_colors("background = \"#fff\"\nforeground = \"#000000\"\naccent = \"#0000ff\"\n")
                .is_err()
        );
        assert!(parse_colors("foreground = \"#000000\"\n").is_err());
    }

    #[test]
    fn auto_follows_omarchy_and_falls_back_to_neon() {
        let home = tempfile::tempdir().unwrap();
        let auto = Settings::default();
        assert_eq!(resolve(&auto, Some(home.path())), neon());
        let file = omarchy_colors(home.path());
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, NORD).unwrap();
        assert_eq!(
            resolve(&auto, Some(home.path())),
            parse_colors(NORD).unwrap()
        );
        let neon_setting = Settings {
            theme: ThemeChoice::Neon,
            ..Settings::default()
        };
        assert_eq!(resolve(&neon_setting, Some(home.path())), neon());
        // A broken file is not fatal.
        std::fs::write(&file, "background = 3").unwrap();
        assert_eq!(resolve(&auto, Some(home.path())), neon());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-gui --lib`
Expected: the build fails: `Settings`, `ThemeChoice`, `animations_off`, `parse_colors`, `resolve`, `neon`, and `omarchy_colors` do not exist.

- [ ] **Step 3: Implement**

Put this above the tests in `crates/aleph-gui/src/settings.rs`:

```rust
//! The GUI's own settings, `~/.config/aleph/gui.toml` (spec §7 "Theme").
//!
//! A file of their own: alephd's `config.toml` refuses unknown keys, and
//! alephd has no use for these.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    /// The current Omarchy theme where there is one, else Aleph neon.
    #[default]
    Auto,
    /// Aleph neon everywhere.
    Neon,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub theme: ThemeChoice,
    /// The scanline overlay (off anyway when reduced motion is asked for).
    pub scanlines: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::Auto,
            scanlines: true,
        }
    }
}

impl Settings {
    /// The file's settings; the defaults if it is missing, and (with a
    /// warning) if it is unreadable: a prompt must still open.
    pub fn load(path: &Path) -> (Self, Option<String>) {
        match std::fs::read_to_string(path) {
            Ok(text) => match toml::from_str(&text) {
                Ok(s) => (s, None),
                Err(e) => (
                    Self::default(),
                    Some(format!("{}: {e} (using the defaults)", path.display())),
                ),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Self::default(), None),
            Err(e) => (
                Self::default(),
                Some(format!("{}: {e} (using the defaults)", path.display())),
            ),
        }
    }
}

/// Where the settings live: `$XDG_CONFIG_HOME/aleph/gui.toml`.
pub fn path(config_home: &Path) -> PathBuf {
    config_home.join("aleph/gui.toml")
}

/// `$XDG_CONFIG_HOME`, or `~/.config`.
pub fn config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home().map(|h| h.join(".config")))
}

pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Whether the desktop asks for reduced motion: GNOME's
/// `enable-animations` setting, which GTK and the portal share, read
/// through `gsettings` (absent: not asked).
pub fn reduced_motion() -> bool {
    std::process::Command::new("gsettings")
        .args(["get", "org.gnome.desktop.interface", "enable-animations"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .is_ok_and(|o| o.status.success() && animations_off(&String::from_utf8_lossy(&o.stdout)))
}

fn animations_off(gsettings_output: &str) -> bool {
    gsettings_output.trim() == "false"
}
```

Put this above the tests in `crates/aleph-gui/src/theme.rs`:

```rust
//! Colors and fonts (spec §7 "Theme"): the current Omarchy theme where
//! there is one (`~/.local/state/omarchy/current/theme/colors.toml`,
//! followed live), else Aleph neon; and the optional scanline overlay.

use std::path::{Path, PathBuf};

use egui::{Color32, Stroke, Visuals};
use serde::Deserialize;

use crate::settings::{Settings, ThemeChoice};

#[derive(Clone, Debug, PartialEq)]
pub struct Palette {
    pub dark: bool,
    pub background: Color32,
    /// Input fields.
    pub field: Color32,
    pub foreground: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub selection: Color32,
    pub error: Color32,
    pub warning: Color32,
    /// Everything in monospace (Aleph neon).
    pub monospace: bool,
}

/// Aleph neon: near-black, neon cyan and magenta, monospace.
pub fn neon() -> Palette {
    Palette {
        dark: true,
        background: Color32::from_rgb(0x0a, 0x0a, 0x12),
        field: Color32::from_rgb(0x04, 0x04, 0x08),
        foreground: Color32::from_rgb(0xd6, 0xf8, 0xff),
        muted: Color32::from_rgb(0x5a, 0x6a, 0x80),
        accent: Color32::from_rgb(0x00, 0xf0, 0xff),
        selection: Color32::from_rgb(0xff, 0x2b, 0xd6),
        error: Color32::from_rgb(0xff, 0x38, 0x60),
        warning: Color32::from_rgb(0xff, 0xd2, 0x3f),
        monospace: true,
    }
}

/// Omarchy's theme file under `home`.
pub fn omarchy_colors(home: &Path) -> PathBuf {
    home.join(".local/state/omarchy/current/theme/colors.toml")
}

/// The directory to watch for theme switches (Omarchy rewrites the
/// theme's files in place).
pub fn omarchy_current(home: &Path) -> PathBuf {
    home.join(".local/state/omarchy/current")
}

#[derive(Deserialize)]
struct ColorsToml {
    mode: Option<String>,
    background: String,
    foreground: String,
    accent: String,
    dark_background: Option<String>,
    selection: Option<String>,
    muted: Option<String>,
    red: Option<String>,
    yellow: Option<String>,
}

fn hex(s: &str) -> Result<Color32, String> {
    let h = s.trim().strip_prefix('#').unwrap_or(s.trim());
    if h.len() != 6 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("not a #rrggbb color: {s:?}"));
    }
    let v = u32::from_str_radix(h, 16).map_err(|e| e.to_string())?;
    Ok(Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8))
}

/// An Omarchy `colors.toml`: `background`, `foreground`, and `accent` are
/// required; the rest fall back to blends of those. Other keys (the ANSI
/// colors Omarchy also lists) are ignored.
pub fn parse_colors(text: &str) -> Result<Palette, String> {
    let c: ColorsToml = toml::from_str(text).map_err(|e| e.to_string())?;
    let background = hex(&c.background)?;
    let foreground = hex(&c.foreground)?;
    let accent = hex(&c.accent)?;
    let or = |v: &Option<String>, fallback: Color32| -> Result<Color32, String> {
        v.as_deref().map(hex).unwrap_or(Ok(fallback))
    };
    let dark = c.mode.as_deref() != Some("light");
    let field = or(&c.dark_background, blend(background, Color32::BLACK, 0.25))?;
    Ok(Palette {
        dark,
        background,
        field,
        foreground,
        muted: or(&c.muted, blend(foreground, background, 0.5))?,
        accent,
        selection: or(&c.selection, blend(accent, background, 0.5))?,
        error: or(&c.red, Color32::from_rgb(0xe0, 0x6c, 0x75))?,
        warning: or(&c.yellow, Color32::from_rgb(0xe5, 0xc0, 0x7b))?,
        monospace: false,
    })
}

fn blend(a: Color32, b: Color32, t: f32) -> Color32 {
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

/// The palette the settings ask for: with `auto`, Omarchy's when its file
/// reads, Aleph neon otherwise.
pub fn resolve(settings: &Settings, home: Option<&Path>) -> Palette {
    match (settings.theme, home) {
        (ThemeChoice::Auto, Some(home)) => std::fs::read_to_string(omarchy_colors(home))
            .ok()
            .and_then(|t| parse_colors(&t).ok())
            .unwrap_or_else(neon),
        _ => neon(),
    }
}

/// egui's visuals for a palette.
pub fn visuals(p: &Palette) -> Visuals {
    let mut v = if p.dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    v.override_text_color = Some(p.foreground);
    v.panel_fill = p.background;
    v.window_fill = p.background;
    v.extreme_bg_color = p.field;
    v.text_edit_bg_color = Some(p.field);
    v.faint_bg_color = p.field;
    v.hyperlink_color = p.accent;
    v.error_fg_color = p.error;
    v.warn_fg_color = p.warning;
    v.selection.bg_fill = p.selection;
    v.selection.stroke = Stroke::new(1.0, p.foreground);
    let w = &mut v.widgets;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.muted);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.foreground);
    for state in [&mut w.inactive, &mut w.hovered, &mut w.active, &mut w.open] {
        state.fg_stroke = Stroke::new(1.0, p.foreground);
    }
    w.inactive.bg_fill = p.field;
    w.inactive.weak_bg_fill = p.field;
    w.inactive.bg_stroke = Stroke::new(1.0, p.muted);
    w.hovered.bg_fill = p.field;
    w.hovered.weak_bg_fill = p.field;
    w.hovered.bg_stroke = Stroke::new(1.0, p.accent);
    w.active.bg_fill = p.selection;
    w.active.weak_bg_fill = p.selection;
    w.active.bg_stroke = Stroke::new(1.5, p.accent);
    v
}

/// Apply a palette: visuals, and monospace everywhere for Aleph neon.
pub fn apply(ctx: &egui::Context, p: &Palette) {
    ctx.set_visuals(visuals(p));
    let mut fonts = egui::FontDefinitions::default();
    if p.monospace {
        let mono = fonts.families[&egui::FontFamily::Monospace].clone();
        fonts.families.insert(egui::FontFamily::Proportional, mono);
    }
    ctx.set_fonts(fonts);
}

/// Faint horizontal lines over everything, every third pixel. Static:
/// nothing moves.
pub fn paint_scanlines(ctx: &egui::Context, p: &Palette) {
    let painter = ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::new("aleph-scanlines"),
    ));
    let rect = ctx.content_rect();
    let shade = if p.dark {
        Color32::from_black_alpha(60)
    } else {
        Color32::from_black_alpha(18)
    };
    let mut y = rect.top();
    while y < rect.bottom() {
        painter.hline(rect.x_range(), y, Stroke::new(1.0, shade));
        y += 3.0;
    }
}
```

- [ ] **Step 4: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-gui --lib && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `ok. 19 passed`.

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run `cargo test -q -p aleph-gui --lib` and see the named test FAIL, then undo it:

- **a broken theme file falls back** (`theme.rs`, `auto_follows_omarchy_and_falls_back_to_neon`): replace `.and_then(|t| parse_colors(&t).ok())` with `.map(|t| parse_colors(&t).unwrap())`.
- **typos in gui.toml are reported** (`settings.rs`, `settings_are_read_and_typos_warned_about`): replace `#[serde(deny_unknown_fields, default)]` with `#[serde(default)]`.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-gui
git commit -m "feat(gui): settings, the Omarchy theme, and Aleph neon" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 4: `aleph-gui prompt`: the window

**Files:**
- Create: `crates/aleph-gui/src/screens.rs`, `crates/aleph-gui/src/app.rs`, `crates/aleph-gui/src/main.rs`, `crates/aleph-gui/tests/screens.rs`, `crates/aleph-gui/tests/binary.rs`, `crates/aleph-gui/tests/home/.local/state/omarchy/current/theme/colors.toml`, `crates/aleph-gui/tests/snapshots/*.png` (generated)
- Modify: `crates/aleph-gui/Cargo.toml` (dev-dependencies), `crates/aleph-gui/src/lib.rs`, `.gitignore`

**Interfaces:**
- Consumes: Task 2's `Conversation`, `Screen`, `Action`, `link::{Event, spawn_reader, send, take_from_env}`; Task 3's `Settings`, `Palette`, `theme::{resolve, apply, paint_scanlines, omarchy_current}`, `settings::{config_home, path, home, reduced_motion}`
- Produces:
  - `screens::SIZE: [f32; 2]` (460×300); `screens::PromptUi { pub conversation, pub palette, pub still, pub secret: Zeroizing<String>, pub groups: [Zeroizing<String>; 2], pub show_recovery_key }` with `new(Palette, bool)`, `screen_changed()`, `show(&mut self, &mut egui::Ui, Instant) -> Option<Action>`
  - `app::PromptApp { pub ui: PromptUi, pub closed: bool, .. }` with `new(UnixStream, Receiver<Event>, Settings, Option<PathBuf>, bool) -> Self`, `watch_theme(&mut self, &egui::Context)`, `frame(&mut self, &mut egui::Ui)`; `impl eframe::App`
  - the binary `aleph-gui prompt` (exit 2: usage or no usable `ALEPH_PROMPT_FD`; exit 1: the window could not open, after sending `Cancel`)

- [ ] **Step 1: Write the failing tests**

In `crates/aleph-gui/Cargo.toml`, replace

```toml
[dev-dependencies]
tempfile.workspace = true
```

with

```toml
[dev-dependencies]
egui_kittest = { version = "0.36", features = ["snapshot", "wgpu"] }
tempfile.workspace = true
```

In `crates/aleph-gui/src/lib.rs`, replace

```rust
pub mod conversation;
pub mod link;
pub mod settings;
pub mod theme;
```

with

```rust
pub mod app;
pub mod conversation;
pub mod link;
pub mod screens;
pub mod settings;
pub mod theme;
```

Give the screen tests a home with the Omarchy theme (so `auto` resolves to it): copy the fixture,

```bash
mkdir -p crates/aleph-gui/tests/home/.local/state/omarchy/current/theme
cp crates/aleph-gui/tests/fixtures/colors.toml crates/aleph-gui/tests/home/.local/state/omarchy/current/theme/colors.toml
```

Replace `.gitignore` with:

```
/target
# egui_kittest writes these next to a failing snapshot.
*.new.png
*.diff.png
```

Write `crates/aleph-gui/tests/screens.rs`:

```rust
//! The prompter's screens, driven as a person would (egui_kittest), and a
//! snapshot of each in both themes (spec §9 "GUI").

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use aleph_gui::app::PromptApp;
use aleph_gui::link;
use aleph_gui::settings::{Settings, ThemeChoice};
use aleph_prompt_proto::{Caller, FromPrompter, Method, Purpose, Secret, ToPrompter};
use egui::Key;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

/// alephd's side of a conversation with a prompt window.
struct Daemon {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Daemon {
    fn say(&mut self, msg: &ToPrompter) {
        let mut line = serde_json::to_vec(msg).unwrap();
        line.push(b'\n');
        self.stream.write_all(&line).unwrap();
    }

    /// The next answer (failing after 5 s rather than hang).
    fn heard(&mut self) -> FromPrompter {
        self.stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("an answer");
        serde_json::from_str(&line).unwrap()
    }

    /// Nothing was sent (within a short wait).
    fn heard_nothing(&mut self) -> bool {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut line = String::new();
        let silent = self.reader.read_line(&mut line).is_err();
        self.stream.set_read_timeout(None).unwrap();
        silent
    }
}

fn window(theme: ThemeChoice) -> (Harness<'static, PromptApp>, Daemon) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let events = link::spawn_reader(ours.try_clone().unwrap(), || {}).unwrap();
    let settings = Settings {
        theme,
        scanlines: true,
    };
    // A fixed home: auto reads the Omarchy fixture from it.
    let home = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/home");
    let app = PromptApp::new(ours, events, settings, Some(home), true);
    let palette = app.ui.palette.clone();
    let harness = Harness::builder()
        .with_size(egui::Vec2::from(aleph_gui::screens::SIZE))
        .build_ui_state(|ui, app: &mut PromptApp| app.frame(ui), app);
    aleph_gui::theme::apply(&harness.ctx, &palette);
    let reader = BufReader::new(theirs.try_clone().unwrap());
    (
        harness,
        Daemon {
            stream: theirs,
            reader,
        },
    )
}

/// Deliver what alephd said (the reader thread is asynchronous).
fn settle(h: &mut Harness<'static, PromptApp>) {
    for _ in 0..40 {
        h.step();
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Focus a field and type into it (kittest types into the focused widget).
fn type_into(h: &mut Harness<'static, PromptApp>, label: &str, text: &str) {
    h.get_by_label(label).focus();
    frames(h);
    h.get_by_label(label).type_text(text);
    frames(h);
}

/// A few frames (some screens repaint on a timer: `run` would not settle).
fn frames(h: &mut Harness<'static, PromptApp>) {
    h.run_steps(4);
}

fn begin(d: &mut Daemon, purpose: Purpose, operation: &str) {
    d.say(&ToPrompter::Begin {
        purpose,
        operation: operation.into(),
        caller: Some(Caller {
            name: Some("secret-tool".into()),
            pid: Some(4242),
        }),
    });
}

fn ask(methods: Vec<Method>, error: Option<&str>, retry_after: Option<u64>) -> ToPrompter {
    ToPrompter::Ask {
        methods,
        error: error.map(Into::into),
        retry_after,
    }
}

#[test]
fn a_typed_password_and_enter_answer_the_question() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password], None, None));
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(Key::Enter);
    frames(&mut h);
    assert_eq!(
        d.heard(),
        FromPrompter::Password {
            password: Secret::new("hunter2")
        }
    );
    // The field is cleared once sent.
    assert!(h.state().ui.secret.is_empty());
}

#[test]
fn the_security_key_button_answers_fido2() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password, Method::Fido2], None, None));
    settle(&mut h);
    h.get_by_label("Use security key").click();
    frames(&mut h);
    assert_eq!(d.heard(), FromPrompter::Fido2 {});
}

/// Escape cancels, and the window closes.
#[test]
fn escape_cancels_and_closes() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::Touch {
        key: "yubikey".into(),
    });
    settle(&mut h);
    h.key_press(Key::Escape);
    frames(&mut h);
    assert_eq!(d.heard(), FromPrompter::Cancel {});
    assert!(h.state().closed);
}

/// Enter gives the confirmation's default (no, unless alephd says yes).
#[test]
fn enter_gives_the_confirmation_default() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Reauth, "Delete the collection 'work'?");
    d.say(&ToPrompter::Confirm {
        text: "Delete the collection 'work' and all its items?".into(),
        default: false,
    });
    settle(&mut h);
    h.key_press(Key::Enter);
    frames(&mut h);
    assert_eq!(d.heard(), FromPrompter::Confirm { yes: false });
}

/// During a back-off the password is not sent, even with Enter.
#[test]
fn a_password_is_held_during_the_back_off() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(
        vec![Method::Password],
        Some("too many attempts"),
        Some(60),
    ));
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(Key::Enter);
    frames(&mut h);
    assert!(d.heard_nothing());
}

/// The recovery key is refused outside a recovery (spec §5), unanswered.
#[test]
fn a_recovery_key_question_outside_recovery_is_cancelled() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::RecoveryKey { error: None });
    settle(&mut h);
    assert_eq!(d.heard(), FromPrompter::Cancel {});
}

/// The new recovery key is shown, then two groups typed back.
#[test]
fn the_recovery_key_is_shown_then_checked() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Create, "Create the keyring");
    d.say(&ToPrompter::ShowRecoveryKey {
        key: Secret::new(KEY),
        check: [3, 11],
        error: None,
    });
    settle(&mut h);
    h.get_by_label("I have written it down").click();
    frames(&mut h);
    type_into(&mut h, "Group 3 of your recovery key", "CCCC");
    type_into(&mut h, "Group 11 of your recovery key", "LLLL");
    frames(&mut h);
    h.get_by_label("Continue").click();
    frames(&mut h);
    let got = d.heard();
    assert_eq!(
        got,
        FromPrompter::RecoveryCheck {
            groups: [Secret::new("CCCC"), Secret::new("LLLL")]
        }
    );
}

/// alephd ending the conversation closes the window; a message stays up
/// until read.
#[test]
fn done_closes_unless_there_is_a_message() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::Done {
        ok: true,
        message: None,
    });
    settle(&mut h);
    assert!(h.state().closed);

    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ToPrompter::Done {
        ok: false,
        message: Some("The keyring was unlocked meanwhile.".into()),
    });
    drop(d);
    settle(&mut h);
    assert!(!h.state().closed);
    h.get_by_label("Close").click();
    frames(&mut h);
    assert!(h.state().closed);
}

/// alephd going away (restarted, killed) closes the window.
#[test]
fn alephd_going_away_closes_the_window() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password], None, None));
    settle(&mut h);
    assert!(!h.state().closed);
    drop(d);
    settle(&mut h);
    assert!(h.state().closed);
}

/// After a wrong password the field is empty and has the focus again: the
/// next password is typed straight in.
#[test]
fn after_a_wrong_password_the_field_is_ready_again() {
    let (mut h, mut d) = window(ThemeChoice::Neon);
    begin(&mut d, Purpose::Unlock, "Unlock the keyring");
    d.say(&ask(vec![Method::Password], None, None));
    settle(&mut h);
    type_into(&mut h, "Login password", "wrong");
    h.key_press(Key::Enter);
    frames(&mut h);
    assert!(matches!(d.heard(), FromPrompter::Password { .. }));
    d.say(&ask(vec![Method::Password], Some("wrong password"), None));
    settle(&mut h);
    assert!(h.state().ui.secret.is_empty());
    // No click, no focus call: the field took the focus itself.
    h.get_by_label("Login password").type_text("right");
    frames(&mut h);
    h.key_press(Key::Enter);
    frames(&mut h);
    assert_eq!(
        d.heard(),
        FromPrompter::Password {
            password: Secret::new("right")
        }
    );
}

const KEY: &str = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-KKKK-LLLL-MMMM-NNNN-PPPP";

/// Every screen, in both themes.
#[test]
fn snapshots() {
    let screens: Vec<(&str, Purpose, Vec<ToPrompter>)> = vec![
        (
            "ask_password",
            Purpose::Unlock,
            vec![ask(vec![Method::Password], None, None)],
        ),
        (
            "ask_both_error",
            Purpose::Unlock,
            vec![ask(
                vec![Method::Password, Method::Fido2],
                Some("wrong password"),
                None,
            )],
        ),
        (
            "ask_key",
            Purpose::Unlock,
            vec![ask(vec![Method::Fido2], None, None)],
        ),
        (
            "ask_back_off",
            Purpose::Unlock,
            vec![ask(
                vec![Method::Password, Method::Fido2],
                Some("too many attempts"),
                Some(30),
            )],
        ),
        (
            "old_password",
            Purpose::Unlock,
            vec![ToPrompter::OldPassword { error: None }],
        ),
        (
            "pin",
            Purpose::Unlock,
            vec![ToPrompter::Fido2Pin {
                key: "yubikey".into(),
                error: Some("wrong PIN (4 tries left)".into()),
            }],
        ),
        (
            "insert_key",
            Purpose::Unlock,
            vec![ToPrompter::InsertKey {
                key: "yubikey".into(),
            }],
        ),
        (
            "touch",
            Purpose::Unlock,
            vec![ToPrompter::Touch {
                key: "yubikey".into(),
            }],
        ),
        (
            "confirm",
            Purpose::Reauth,
            vec![ToPrompter::Confirm {
                text: "Delete the collection 'work' and all its items?".into(),
                default: false,
            }],
        ),
        (
            "recovery_key",
            Purpose::Recover,
            vec![ToPrompter::RecoveryKey { error: None }],
        ),
        (
            "show_recovery_key",
            Purpose::Create,
            vec![ToPrompter::ShowRecoveryKey {
                key: Secret::new(KEY),
                check: [3, 11],
                error: None,
            }],
        ),
        (
            "confirm_long_label",
            Purpose::Reauth,
            vec![ToPrompter::Confirm {
                text: format!(
                    "Delete the collection '{}' and all its items?",
                    "w".repeat(600)
                ),
                default: false,
            }],
        ),
        (
            "finished_message",
            Purpose::Unlock,
            vec![ToPrompter::Done {
                ok: false,
                message: Some("The keyring was unlocked meanwhile.".into()),
            }],
        ),
    ];
    let mut failures = Vec::new();
    for (theme, suffix) in [(ThemeChoice::Neon, "neon"), (ThemeChoice::Auto, "omarchy")] {
        for (name, purpose, msgs) in &screens {
            let (mut h, mut d) = window(theme);
            begin(
                &mut d,
                *purpose,
                match purpose {
                    Purpose::Unlock => "Unlock the keyring",
                    Purpose::Reauth => "Delete the collection 'work'?",
                    Purpose::Create => "Create the keyring",
                    Purpose::Recover => "Recover the keyring",
                },
            );
            for m in msgs {
                d.say(m);
            }
            settle(&mut h);
            if let Err(e) = h.try_snapshot(format!("{name}_{suffix}")) {
                failures.push(e.to_string());
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
```

Write `crates/aleph-gui/tests/binary.rs`:

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
    // SAFETY: dup2 is async-signal-safe; it only duplicates the
    // descriptor in the child (the copy is inheritable).
    unsafe {
        c.pre_exec(move || {
            if libc::dup2(fd, 10) < 0 {
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
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("usage"), "{}", stderr(&o));
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

/// With no display to open, it cancels at once rather than leave alephd
/// waiting out the prompt timeout.
#[test]
fn without_a_display_it_cancels() {
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
    BufReader::new(ours).read_line(&mut line).unwrap();
    assert_eq!(line, "{\"type\":\"cancel\"}\n");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-gui --test screens --test binary`
Expected: the build fails: the `app` and `screens` modules and the `aleph-gui` binary do not exist.

- [ ] **Step 3: Implement**

Write `crates/aleph-gui/src/screens.rs`:

```rust
//! Drawing the prompter's screens (spec §7 "Prompter"), and turning
//! clicks and keys into [`Action`]s. No I/O here: the window (`app.rs`)
//! sends what `show` returns.

use std::time::{Duration, Instant};

use aleph_prompt_proto::{Method, Purpose, Secret};
use egui::{Align, Button, Key, Layout, RichText, TextEdit};
use zeroize::Zeroizing;

use crate::conversation::{Action, Conversation, Screen};
use crate::theme::Palette;

/// The window's fixed size.
pub const SIZE: [f32; 2] = [460.0, 300.0];

/// The prompter's state between frames: the conversation and what is
/// being typed.
pub struct PromptUi {
    pub conversation: Conversation,
    pub palette: Palette,
    /// No spinners (reduced motion).
    pub still: bool,
    /// What is typed. Zeroized on drop; moved (never copied) into the
    /// answer. (egui keeps its own copies while editing: spec §4 "Memory
    /// hygiene", not guaranteed.)
    pub secret: Zeroizing<String>,
    pub groups: [Zeroizing<String>; 2],
    pub show_recovery_key: bool,
    /// Which screen the fields were last focused for (focus moves to the
    /// field once per screen).
    focused_for: u64,
    screen_number: u64,
}

impl PromptUi {
    pub fn new(palette: Palette, still: bool) -> Self {
        Self {
            conversation: Conversation::new(),
            palette,
            still,
            secret: Zeroizing::default(),
            groups: Default::default(),
            show_recovery_key: false,
            focused_for: u64::MAX,
            screen_number: 0,
        }
    }

    /// A new message arrived (the screen changed): clear what was typed
    /// and move focus again.
    pub fn screen_changed(&mut self) {
        self.screen_number += 1;
        self.secret = Zeroizing::default();
        self.groups = Default::default();
        self.show_recovery_key = false;
    }

    fn take_secret(&mut self) -> Secret {
        Secret::new(std::mem::take(&mut *self.secret))
    }

    /// Draw the current screen; returns what the person did, if anything.
    pub fn show(&mut self, ui: &mut egui::Ui, now: Instant) -> Option<Action> {
        let escape = ui.input(|i| i.key_pressed(Key::Escape));
        let enter = ui.input(|i| i.key_pressed(Key::Enter));
        let focus = self.focused_for != self.screen_number;
        self.focused_for = self.screen_number;
        let p = self.palette.clone();
        let body = egui::Frame::central_panel(ui.style())
            .inner_margin(18.0)
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                self.header(ui, &p);
                ui.add_space(10.0);
                self.body(ui, &p, now, focus, enter)
            })
            .inner;
        if escape && !self.conversation.finished() {
            return Some(Action::Cancel);
        }
        if escape {
            return Some(Action::Close);
        }
        body
    }

    fn header(&self, ui: &mut egui::Ui, p: &Palette) {
        let c = &self.conversation;
        ui.label(RichText::new("aleph").small().color(p.accent));
        let title = if c.operation.is_empty() {
            "aleph keyring"
        } else {
            c.operation.as_str()
        };
        ui.add(egui::Label::new(RichText::new(title).heading().strong()).truncate());
        if let Some(caller) = &c.caller {
            let who = match (&caller.name, caller.pid) {
                (Some(n), Some(pid)) => format!("Requested by {n} (pid {pid})"),
                (Some(n), None) => format!("Requested by {n}"),
                (None, Some(pid)) => format!("Requested by pid {pid}"),
                (None, None) => String::new(),
            };
            if !who.is_empty() {
                ui.label(
                    RichText::new(who)
                        .small()
                        .color(p.foreground.gamma_multiply(0.7)),
                );
            }
        }
    }

    fn error(ui: &mut egui::Ui, p: &Palette, error: &Option<String>) {
        if let Some(e) = error {
            ui.label(RichText::new(e).color(p.error));
        }
    }

    /// The screen's main button: filled with the accent while it can be
    /// used, plain (and faded) while it cannot.
    fn primary(p: &Palette, text: &str, enabled: bool, ui: &mut egui::Ui) -> bool {
        let button = if enabled {
            Button::new(RichText::new(text).color(p.background).strong()).fill(p.accent)
        } else {
            Button::new(text)
        };
        ui.add_enabled(enabled, button).clicked()
    }

    /// A masked, single-line secret field; true when Enter was pressed in it.
    fn secret_field(
        ui: &mut egui::Ui,
        text: &mut String,
        label: &str,
        masked: bool,
        focus: bool,
    ) -> bool {
        let l = ui.label(label);
        let r = ui
            .add(
                TextEdit::singleline(text)
                    .password(masked)
                    .desired_width(f32::INFINITY),
            )
            .labelled_by(l.id);
        if focus {
            r.request_focus();
        }
        r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
    }

    /// Buttons along the bottom, right to left: `Cancel` last.
    fn buttons(
        ui: &mut egui::Ui,
        add: impl FnOnce(&mut egui::Ui) -> Option<Action>,
    ) -> Option<Action> {
        let mut out = None;
        ui.with_layout(Layout::bottom_up(Align::Max), |ui| {
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    out = add(ui);
                    if ui.button("Cancel").clicked() {
                        out = Some(Action::Cancel);
                    }
                });
            });
        });
        out
    }

    fn spinner(&self, ui: &mut egui::Ui, text: &str) {
        ui.horizontal(|ui| {
            if !self.still {
                ui.spinner();
            }
            ui.label(text);
        });
    }

    fn body(
        &mut self,
        ui: &mut egui::Ui,
        p: &Palette,
        now: Instant,
        focus: bool,
        enter: bool,
    ) -> Option<Action> {
        let unlocking = self.conversation.purpose == Some(Purpose::Unlock);
        // (Split borrows: the screen is read while the fields are edited.)
        let screen = std::mem::replace(&mut self.conversation.screen, Screen::Working);
        let action = match &screen {
            Screen::Working => {
                self.spinner(ui, "Checking…");
                Self::buttons(ui, |_| None)
            }
            Screen::Ask {
                methods,
                error,
                retry_at,
            } => {
                Self::error(ui, p, error);
                let password = methods.contains(&Method::Password);
                let key = methods.contains(&Method::Fido2);
                let wait = retry_at
                    .map(|at| at.saturating_duration_since(now))
                    .filter(|d| !d.is_zero());
                let mut submit = false;
                if password {
                    submit =
                        Self::secret_field(ui, &mut self.secret, "Login password", true, focus);
                    if let Some(d) = wait {
                        ui.label(
                            RichText::new(format!(
                                "Try the password again in {} s",
                                d.as_secs() + 1
                            ))
                            .color(p.warning),
                        );
                        ui.ctx().request_repaint_after(Duration::from_millis(250));
                    }
                } else {
                    ui.label("Use your security key.");
                }
                let ready = password && wait.is_none() && !self.secret.is_empty();
                let label = if unlocking { "Unlock" } else { "Continue" };
                let mut clicked = None;
                let bar = Self::buttons(ui, |ui| {
                    if password && Self::primary(p, label, ready, ui) {
                        clicked = Some(true);
                    }
                    if key {
                        let b = if password {
                            ui.button("Use security key")
                        } else {
                            ui.add(
                                Button::new(
                                    RichText::new("Use security key")
                                        .color(p.background)
                                        .strong(),
                                )
                                .fill(p.accent),
                            )
                        };
                        if b.clicked() {
                            clicked = Some(false);
                        }
                    }
                    None
                });
                bar.or(match clicked {
                    Some(true) => Some(Action::Password(self.take_secret())),
                    Some(false) => Some(Action::Fido2),
                    None if submit && ready => Some(Action::Password(self.take_secret())),
                    None if !password && key && enter => Some(Action::Fido2),
                    None => None,
                })
            }
            Screen::OldPassword { error } => {
                ui.label(
                    "Your login password was changed outside aleph. Enter the previous one to \
                     update the TPM keyslot (a wrong one costs a TPM attempt).",
                );
                Self::error(ui, p, error);
                let submit = Self::secret_field(
                    ui,
                    &mut self.secret,
                    "Previous login password",
                    true,
                    focus,
                );
                self.secret_answer(ui, p, submit, Action::Password)
            }
            Screen::Pin { key, error } => {
                Self::error(ui, p, error);
                let submit = Self::secret_field(
                    ui,
                    &mut self.secret,
                    &format!("PIN for {key}"),
                    true,
                    focus,
                );
                self.secret_answer(ui, p, submit, Action::Pin)
            }
            Screen::InsertKey { key } => {
                self.spinner(ui, &format!("Insert {key}."));
                Self::buttons(ui, |_| None)
            }
            Screen::Touch { key } => {
                self.spinner(ui, &format!("Touch {key} now."));
                Self::buttons(ui, |_| None)
            }
            Screen::Confirm { text, default } => {
                ui.label(text.as_str());
                let mut answer = None;
                let bar = Self::buttons(ui, |ui| {
                    // (Right to left: "Yes" rightmost.)
                    let yes = ui.button("Yes");
                    let no = ui.button("No");
                    if focus {
                        if *default {
                            yes.request_focus()
                        } else {
                            no.request_focus()
                        }
                    }
                    if yes.clicked() {
                        answer = Some(true);
                    } else if no.clicked() {
                        answer = Some(false);
                    }
                    None
                });
                // (Cancel means no, too; Enter gives the default.)
                bar.or(answer.or(enter.then_some(*default)).map(Action::Confirm))
            }
            Screen::RecoveryKey { error } => {
                Self::error(ui, p, error);
                let submit = Self::secret_field(
                    ui,
                    &mut self.secret,
                    "Recovery key (14 groups of 4)",
                    !self.show_recovery_key,
                    focus,
                );
                ui.checkbox(&mut self.show_recovery_key, "Show what I type");
                self.secret_answer(ui, p, submit, Action::RecoveryKey)
            }
            Screen::ShowRecoveryKey {
                key,
                error,
                checking: false,
                ..
            } => {
                Self::error(ui, p, error);
                ui.label(
                    "Your new recovery key. Write it down and keep it somewhere safe: it is shown \
                     only this once, and it is the only way back in if every other method is lost.",
                );
                ui.add_space(6.0);
                key_grid(ui, p, key.expose());
                let mut done = false;
                let bar = Self::buttons(ui, |ui| {
                    done = Self::primary(p, "I have written it down", true, ui);
                    None
                });
                bar.or(done.then_some(Action::RecoveryKeyWritten))
            }
            Screen::ShowRecoveryKey {
                check,
                error,
                checking: true,
                ..
            } => {
                Self::error(ui, p, error);
                let [a, b] = &mut self.groups;
                let first = Self::secret_field(
                    ui,
                    a,
                    &format!("Group {} of your recovery key", check[0]),
                    false,
                    focus,
                );
                let second = Self::secret_field(
                    ui,
                    b,
                    &format!("Group {} of your recovery key", check[1]),
                    false,
                    false,
                );
                let ready = !a.is_empty() && !b.is_empty();
                let mut clicked = false;
                let bar = Self::buttons(ui, |ui| {
                    clicked = Self::primary(p, "Continue", ready, ui);
                    None
                });
                bar.or(((clicked || first || second) && ready).then(|| {
                    let [a, b] = &mut self.groups;
                    Action::RecoveryCheck([
                        Secret::new(std::mem::take(&mut **a)),
                        Secret::new(std::mem::take(&mut **b)),
                    ])
                }))
            }
            Screen::Finished { ok, message } => {
                let text = message
                    .as_deref()
                    .unwrap_or(if *ok { "Done." } else { "Stopped." });
                let color = if *ok { p.foreground } else { p.error };
                ui.label(RichText::new(text).color(color));
                let mut close = false;
                ui.with_layout(Layout::bottom_up(Align::Max), |ui| {
                    close = Self::primary(p, "Close", true, ui);
                });
                (close || enter).then_some(Action::Close)
            }
        };
        self.conversation.screen = screen;
        action
    }

    /// The primary button (and Enter in the field) for a one-secret screen.
    fn secret_answer(
        &mut self,
        ui: &mut egui::Ui,
        p: &Palette,
        submit: bool,
        make: fn(Secret) -> Action,
    ) -> Option<Action> {
        let ready = !self.secret.is_empty();
        let mut clicked = false;
        let bar = Self::buttons(ui, |ui| {
            clicked = Self::primary(p, "Continue", ready, ui);
            None
        });
        bar.or(((clicked || submit) && ready).then(|| make(self.take_secret())))
    }
}

/// The recovery key as a grid of numbered groups, 7 to a row.
fn key_grid(ui: &mut egui::Ui, p: &Palette, key: &str) {
    let groups: Vec<&str> = key.split('-').collect();
    egui::Grid::new("recovery-key")
        .spacing([10.0, 2.0])
        .show(ui, |ui| {
            for (r, chunk) in groups.chunks(7).enumerate() {
                for (i, _) in chunk.iter().enumerate() {
                    ui.label(
                        RichText::new(format!("{}", r * 7 + i + 1))
                            .small()
                            .color(p.muted),
                    );
                }
                ui.end_row();
                for g in chunk {
                    ui.label(RichText::new(*g).monospace().size(16.0).color(p.foreground));
                }
                ui.end_row();
            }
        });
}
```

Write `crates/aleph-gui/src/app.rs`:

```rust
//! The prompt window: alephd's messages in, the person's answers out.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::Instant;

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
    theme_changed: Arc<AtomicBool>,
    _watcher: Option<notify::RecommendedWatcher>,
    /// The window was told to close.
    pub closed: bool,
}

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
            theme_changed: Arc::default(),
            _watcher: None,
            closed: false,
        }
    }

    /// Re-theme live when the Omarchy theme changes (spec §7).
    pub fn watch_theme(&mut self, ctx: &egui::Context) {
        use notify::Watcher;
        let Some(home) = &self.home else { return };
        let flag = self.theme_changed.clone();
        let ctx = ctx.clone();
        let watcher = notify::recommended_watcher(move |_: notify::Result<notify::Event>| {
            flag.store(true, Ordering::SeqCst);
            ctx.request_repaint();
        });
        if let Ok(mut w) = watcher
            && w.watch(
                &theme::omarchy_current(home),
                notify::RecursiveMode::Recursive,
            )
            .is_ok()
        {
            self._watcher = Some(w);
        }
    }

    fn close(&mut self, ctx: &egui::Context) {
        if !self.closed {
            self.closed = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
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
        if self.theme_changed.swap(false, Ordering::SeqCst) {
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
                Event::Broken(why) => {
                    eprintln!("aleph-gui: {why}");
                    self.reply(&ctx, FromPrompter::Cancel {});
                }
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.closed {
            // Closed by the window manager.
            if !self.ui.conversation.finished() {
                let _ = link::send(&self.stream, &FromPrompter::Cancel {});
            }
            self.closed = true;
        }
        if let crate::conversation::Screen::Finished { message: None, .. } =
            self.ui.conversation.screen
        {
            self.close(&ctx);
        }
        if self.closed {
            return;
        }
        let action = self.ui.show(ui, now);
        if self.scanlines {
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

Write `crates/aleph-gui/src/main.rs`:

```rust
//! `aleph-gui prompt`: the prompter alephd starts, with its end of a
//! socketpair as `ALEPH_PROMPT_FD` (spec §6 "Prompter orchestration").

use std::process::ExitCode;

use aleph_gui::{app, link, screens, settings};
use aleph_prompt_proto::FromPrompter;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["prompt"] => prompt(),
        _ => {
            eprintln!(
                "usage: aleph-gui prompt   (alephd starts it; the manager window comes later)"
            );
            ExitCode::from(2)
        }
    }
}

fn prompt() -> ExitCode {
    // First, while single-threaded: the variable is removed.
    let stream = match link::take_from_env() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aleph-gui: {e}");
            return ExitCode::from(2);
        }
    };
    let Ok(answer) = stream.try_clone() else {
        eprintln!("aleph-gui: cannot use the prompter socket");
        return ExitCode::FAILURE;
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
            // Tell alephd now rather than leave it waiting out the timeout.
            eprintln!("aleph-gui: cannot open the prompt window: {e}");
            let _ = link::send(&answer, &FromPrompter::Cancel {});
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 4: Generate the snapshots and look at every one**

Run: `UPDATE_SNAPSHOTS=1 cargo test -q -p aleph-gui --test screens snapshots`
Expected: `ok. 1 passed`, and 26 files in `crates/aleph-gui/tests/snapshots/`: `{ask_password, ask_both_error, ask_key, ask_back_off, old_password, pin, insert_key, touch, confirm, confirm_long_label, recovery_key, show_recovery_key, finished_message}_{neon, omarchy}.png`.

Open every one. Each must show the `aleph` label, the title, and "Requested by secret-tool (pid 4242)"; text legible against its background in both themes; the buttons along the bottom right, none clipped (`confirm_long_label_*`: the label is cut with "…" and the buttons still show, "No" focused); the primary button filled with the accent only when it can be used (`ask_password_*`: "Unlock" plain until something is typed); `show_recovery_key_*`: 14 numbered groups in two rows of 7. Fix and regenerate until they do. (Snapshots are compared pixel by pixel on this machine; another GPU or driver may render text slightly differently: regenerate there, and review the images as above.)

- [ ] **Step 5: Run the tests, clippy, and fmt**

Run: `cargo test -q -p aleph-gui && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: `ok. 19 passed` (lib), `ok. 0 passed` (the binary's unit tests), `ok. 3 passed` (binary), `ok. 11 passed` (screens).

- [ ] **Step 6: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL, then undo it:

- **the field takes the focus on a new screen** (`screens.rs`), test `cargo test -q -p aleph-gui --test screens after_a_wrong_password`: replace `let focus = self.focused_for != self.screen_number;` with `let focus = false;`.
- **alephd closing closes the window** (`app.rs`), test `cargo test -q -p aleph-gui --test screens alephd_going_away`: replace the body of the `Event::Closed =>` arm (the `if !matches!(…) { self.close(&ctx); }` block) with `{}`.
- **no window: cancel at once** (`main.rs`), test `cargo test -q -p aleph-gui --test binary without_a_display`: replace `let _ = link::send(&answer, &FromPrompter::Cancel {});` with `let _ = &answer;`.
- **only a socket is adopted** (`link.rs`), test `cargo test -q -p aleph-gui --test binary anything_but_a_socket`: replace `if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {` with `if false {`.

- [ ] **Step 7: Commit**

```bash
git add .gitignore crates/aleph-gui
git commit -m "feat(gui): aleph-gui prompt, the unlock window" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 5: the Hyprland rule, setup, and install

**Files:**
- Create: `packaging/hyprland/aleph-prompt.lua`
- Modify: `crates/aleph-cli/src/wizard.rs`, `crates/aleph-cli/src/main.rs` (setup, revert), `crates/aleph-cli/src/prompter.rs` (a comment), `crates/aleph-cli/tests/cli.rs`, `packaging/install.sh`

**Interfaces:**
- Produces: `wizard::{HYPRLAND_RULE_FILE, HYPRLAND_INCLUDE, hyprland_config(&Path) -> Option<PathBuf>, hyprland_rule_included(&Path) -> bool, include_hyprland_rule(&Path) -> Result<bool>, remove_hyprland_rule(&Path) -> Result<Option<PathBuf>>}`

- [ ] **Step 1: Write the failing tests**

In `crates/aleph-cli/src/wizard.rs`, add these tests to `mod tests`, before `fn a_lockout_value_matches_however_it_is_typed`:

```rust
    /// The include goes in once, after what is there, and revert takes out
    /// exactly what setup added.
    #[test]
    fn the_hyprland_include_is_added_once_and_removed_exactly() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(hyprland_config(dir.path()), None);
        assert_eq!(remove_hyprland_rule(dir.path()).unwrap(), None);
        let config = dir.path().join("hypr/hyprland.lua");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        let original = "require(\"hypr.bindings\")\n-- mine\n";
        std::fs::write(&config, original).unwrap();
        assert_eq!(hyprland_config(dir.path()), Some(config.clone()));
        assert!(include_hyprland_rule(&config).unwrap());
        assert!(!include_hyprland_rule(&config).unwrap());
        let text = std::fs::read_to_string(&config).unwrap();
        assert!(text.starts_with(original), "{text}");
        assert_eq!(text.matches(HYPRLAND_INCLUDE).count(), 1);
        assert!(hyprland_rule_included(&config));
        assert_eq!(
            remove_hyprland_rule(dir.path()).unwrap(),
            Some(config.clone())
        );
        assert_eq!(std::fs::read_to_string(&config).unwrap(), original);
        // An unfinished last line is ended, and stays ended.
        std::fs::write(&config, "-- mine").unwrap();
        include_hyprland_rule(&config).unwrap();
        remove_hyprland_rule(dir.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "-- mine\n");
    }

    /// A symlinked configuration (a dotfiles repository) stays a symlink.
    #[test]
    fn a_symlinked_hyprland_config_stays_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("dotfiles.lua");
        std::fs::write(&real, "-- mine\n").unwrap();
        let config = dir.path().join("hypr/hyprland.lua");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, &config).unwrap();
        include_hyprland_rule(&config).unwrap();
        assert!(config.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(
            std::fs::read_to_string(&real)
                .unwrap()
                .contains(HYPRLAND_INCLUDE)
        );
        remove_hyprland_rule(dir.path()).unwrap();
        assert!(config.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "-- mine\n");
    }

    /// The include names the file the package installs, and both are valid
    /// Lua (`luac -p`; Hyprland would refuse the whole configuration).
    #[test]
    fn the_hyprland_files_are_lua() {
        assert!(HYPRLAND_INCLUDE.contains(HYPRLAND_RULE_FILE));
        let dir = tempfile::tempdir().unwrap();
        let include = dir.path().join("include.lua");
        std::fs::write(&include, HYPRLAND_INCLUDE).unwrap();
        let rule = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packaging/hyprland/aleph-prompt.lua"
        );
        for file in [include.as_path(), Path::new(rule)] {
            let out = std::process::Command::new("luac")
                .arg("-p")
                .arg(file)
                .output()
                .expect("luac (Arch: pacman -S lua)");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let text = std::fs::read_to_string(rule).unwrap();
        assert!(text.contains("\"^aleph-prompt$\""), "{text}");
    }
```

In `crates/aleph-cli/tests/cli.rs`, in `setup_revert_hands_everything_back`, replace

```rust
    let d = daemon(true, vec![]).await;
    run(&d, &["store", "--label", "Mail", "service=mail"], "s3cret").await;
    let (ok, _, err) = run(&d, &["setup", "--revert"], &format!("{PW}\n")).await;
    assert!(ok, "{err}");
```

with

```rust
    let d = daemon(true, vec![]).await;
    run(&d, &["store", "--label", "Mail", "service=mail"], "s3cret").await;
    let hypr = d
        .env
        .paths
        .data_dir
        .parent()
        .unwrap()
        .join("home/config/hypr");
    std::fs::create_dir_all(&hypr).unwrap();
    let include = "\n-- Added by alephctl setup: float aleph's unlock prompt.\npcall(dofile, \"/usr/share/aleph/hyprland/aleph-prompt.lua\")\n";
    std::fs::write(hypr.join("hyprland.lua"), format!("-- mine\n{include}")).unwrap();
    let (ok, _, err) = run(&d, &["setup", "--revert"], &format!("{PW}\n")).await;
    assert!(ok, "{err}");
    assert_eq!(
        std::fs::read_to_string(hypr.join("hyprland.lua")).unwrap(),
        "-- mine\n"
    );
```

and add at the end of the file:

```rust
/// On Hyprland (Lua configuration), setup offers the prompt's window rule
/// and adds it once; unanswered, the offer takes its default (yes).
#[tokio::test(flavor = "multi_thread")]
async fn setup_adds_the_prompts_window_rule_to_hyprland_once() {
    let d = daemon(false, vec![]).await;
    let hypr = d
        .env
        .paths
        .data_dir
        .parent()
        .unwrap()
        .join("home/config/hypr");
    std::fs::create_dir_all(&hypr).unwrap();
    std::fs::write(hypr.join("hyprland.lua"), "-- mine\n").unwrap();
    let log = setup(&d).await;
    assert!(log.contains("Float the unlock prompt"), "{log}");
    let text = std::fs::read_to_string(hypr.join("hyprland.lua")).unwrap();
    assert!(text.starts_with("-- mine\n"), "{text}");
    assert_eq!(
        text.matches("pcall(dofile, \"/usr/share/aleph/hyprland/aleph-prompt.lua\")")
            .count(),
        1
    );
    // A re-run neither asks again nor adds it twice.
    let (ok, _, log) = run(&d, &["setup"], "").await;
    assert!(ok, "{log}");
    assert!(!log.contains("Float the unlock prompt"), "{log}");
    assert_eq!(
        std::fs::read_to_string(hypr.join("hyprland.lua")).unwrap(),
        text
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -q -p aleph-cli`
Expected: the build fails: `hyprland_config`, `include_hyprland_rule`, `remove_hyprland_rule`, `hyprland_rule_included`, `HYPRLAND_INCLUDE`, and `HYPRLAND_RULE_FILE` do not exist.

- [ ] **Step 3: Implement**

Write `packaging/hyprland/aleph-prompt.lua`:

```lua
-- aleph's unlock prompt (alephd starts it as `aleph-gui prompt`): float it
-- in the middle of the screen, on every workspace, and keep the keyboard on
-- it while it is open, so a password is never typed into another window.
-- (It closes itself: answered, cancelled with Escape, or timed out.)
-- `alephctl setup` offers to include this from ~/.config/hypr/hyprland.lua.
hl.window_rule({
  match = { class = "^aleph-prompt$" },
  float = true,
  center = true,
  pin = true,
  stay_focused = true,
})
```

In `crates/aleph-cli/src/wizard.rs`, add before `/// The program that runs the root side`:

```rust
/// The window rule the package installs for the prompter (spec §7
/// "Prompter": float, center, pin).
pub const HYPRLAND_RULE_FILE: &str = "/usr/share/aleph/hyprland/aleph-prompt.lua";

/// What setup adds to `hyprland.lua`. Through `pcall`, so a missing file
/// (aleph uninstalled) never breaks Hyprland's configuration.
pub const HYPRLAND_INCLUDE: &str = "\n-- Added by alephctl setup: float aleph's unlock prompt.\n\
     pcall(dofile, \"/usr/share/aleph/hyprland/aleph-prompt.lua\")\n";

/// The user's Hyprland configuration, if it is the Lua kind (Omarchy's).
pub fn hyprland_config(config_home: &Path) -> Option<PathBuf> {
    let path = config_home.join("hypr/hyprland.lua");
    path.is_file().then_some(path)
}

pub fn hyprland_rule_included(config: &Path) -> bool {
    std::fs::read_to_string(config).is_ok_and(|t| t.contains(HYPRLAND_INCLUDE))
}

/// Append the include (once), ending the file's last line first if it is
/// unfinished. Appended in place: a symlinked dotfile stays a symlink.
pub fn include_hyprland_rule(config: &Path) -> Result<bool> {
    use std::io::Write;
    let text = std::fs::read_to_string(config).map_err(|e| format!("{}: {e}", config.display()))?;
    if text.contains(HYPRLAND_INCLUDE) {
        return Ok(false);
    }
    let sep = if text.is_empty() || text.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    std::fs::OpenOptions::new()
        .append(true)
        .open(config)
        .and_then(|mut f| f.write_all(format!("{sep}{HYPRLAND_INCLUDE}").as_bytes()))
        .map_err(|e| format!("{}: {e}", config.display()))?;
    Ok(true)
}

/// Take the include out again (revert), leaving the rest of the file as
/// setup found it (with its last line ended); returns the file's path if
/// the include was there.
pub fn remove_hyprland_rule(config_home: &Path) -> Result<Option<PathBuf>> {
    let Some(config) = hyprland_config(config_home) else {
        return Ok(None);
    };
    let text =
        std::fs::read_to_string(&config).map_err(|e| format!("{}: {e}", config.display()))?;
    let Some(at) = text.find(HYPRLAND_INCLUDE) else {
        return Ok(None);
    };
    let rest = format!("{}{}", &text[..at], &text[at + HYPRLAND_INCLUDE.len()..]);
    // (Written through a symlink, like the append.)
    std::fs::write(&config, rest).map_err(|e| format!("{}: {e}", config.display()))?;
    Ok(Some(config))
}
```

In `crates/aleph-cli/src/main.rs` (setup), replace

```rust
            let mut term = prompter::Terminal::new();
            if tpm {
                offer_lockout_auth(&mut term)?;
            }
```

with

```rust
            let mut term = prompter::Terminal::new();
                let answer = ask(
                    &mut term,
                    "Those collections stay in gnome-keyring, out of reach once aleph takes over (until `alephctl setup --revert`). Take over anyway? [y/N] ",
                )?;
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    eprintln!(
                        "alephctl: stopped before taking over: unlock them in gnome-keyring (Seahorse), then run `alephctl setup` again"
                    );
                    return Ok(ExitCode::SUCCESS);
                }
            }
            let dirs = switchover::Dirs::from_env()?;
            let mut record = switchover::Record::load(&dirs)?;
            for step in
                switchover::switch_over(c.bus(), &switchover::Systemctl, &dirs, &mut record).await?
            {
                eprintln!("alephctl: {step}");
            }
            if let Some(hook) = wizard::install_omarchy_hook(&dirs.config_home)? {
                eprintln!(
                    "alephctl: installed {}: the keyring locks with the screen once Omarchy's lock runs `omarchy-hook lock`",
                    hook.display()
                );
            }
            let mut term = prompter::Terminal::new();
            if let Some(config) = wizard::hyprland_config(&dirs.config_home)
                && !wizard::hyprland_rule_included(&config)
            {
                let answer = ask(
                    &mut term,
                    "Float the unlock prompt in the middle of the screen in Hyprland (adds two lines to hyprland.lua)? [Y/n] ",
                )?;
                if matches!(answer.trim(), "" | "y" | "Y" | "yes") {
                    wizard::include_hyprland_rule(&config)?;
                    eprintln!(
                        "alephctl: {} now includes {}",
                        config.display(),
                        wizard::HYPRLAND_RULE_FILE
                    );
                }
            }
            if tpm {
                offer_lockout_auth(&mut term)?;
            }
```

and in the revert, after

```rust
    match wizard::remove_omarchy_hook(&dirs.config_home) {
        Ok(Some(hook)) => eprintln!("alephctl: removed {}", hook.display()),
        Ok(None) => {}
        Err(e) => eprintln!("alephctl: {e}"),
    }
```

add

```rust
    match wizard::remove_hyprland_rule(&dirs.config_home) {
        Ok(Some(config)) => eprintln!(
            "alephctl: took the prompt's window rule out of {}",
            config.display()
        ),
        Ok(None) => {}
        Err(e) => eprintln!("alephctl: {e}"),
    }
```

In `crates/aleph-cli/src/prompter.rs`, replace

```rust
            // (The terminal cannot skip one key while waiting; Ctrl-C ends the
            // whole operation. The GUI prompter offers "skip".)
```

with

```rust
            // (Ctrl-C ends the whole operation, as Cancel does in the GUI.)
```

In `packaging/install.sh`: add `"$R/aleph-gui"` to the list of files checked (after `"$R/aleph-tpmd"`); after `install -Dm755 "$R/alephctl" /usr/bin/alephctl` add

```sh
    install -Dm755 "$R/aleph-gui" /usr/bin/aleph-gui
```

after `install -Dm644 packaging/pam/aleph-check /etc/pam.d/aleph-check` add

```sh
    install -Dm644 packaging/hyprland/aleph-prompt.lua /usr/share/aleph/hyprland/aleph-prompt.lua
```

in `uninstall`, replace

```sh
    rm -f /usr/bin/alephctl /usr/lib/aleph/alephd /usr/lib/aleph/aleph-tpmd \
```

with

```sh
    rm -f /usr/bin/alephctl /usr/bin/aleph-gui /usr/lib/aleph/alephd /usr/lib/aleph/aleph-tpmd \
        /usr/share/aleph/hyprland/aleph-prompt.lua \
```

and replace `    rmdir /usr/lib/aleph 2>/dev/null || true` with

```sh
    rmdir /usr/lib/aleph /usr/share/aleph/hyprland /usr/share/aleph 2>/dev/null || true
```

- [ ] **Step 4: Run the tests, clippy, fmt, and the whole gate**

Run: `cargo test -q -p aleph-cli && make gate`
Expected: `ok. 30 passed` (alephctl's unit tests) and `ok. 16 passed` (cli), then `make gate` exits 0 (`sh -n packaging/install.sh` included).

- [ ] **Step 5: Confirm the tests have teeth**

Make each change below, run its test and see it FAIL, then undo it:

- **the include goes in once** (`wizard.rs`), test `cargo test -q -p aleph-cli --bin alephctl hyprland`: replace `    if text.contains(HYPRLAND_INCLUDE) {\n        return Ok(false);\n    }` in `include_hyprland_rule` with nothing.
- **appended in place** (`wizard.rs`), test `cargo test -q -p aleph-cli --bin alephctl a_symlinked_hyprland`: replace the `OpenOptions` append with `std::fs::remove_file(config).and_then(|()| std::fs::write(config, format!("{text}{sep}{HYPRLAND_INCLUDE}")))`.
- **revert takes it out** (`main.rs`), test `cargo test -q -p aleph-cli --test cli setup_revert_hands`: delete the `remove_hyprland_rule` match.

- [ ] **Step 6: Commit**

```bash
git add crates/aleph-cli packaging
git commit -m "feat: setup offers the prompt's Hyprland window rule; install aleph-gui" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

### Task 6: spec, docs, decisions

**Files:**
- Modify: `docs/superpowers/specs/2026-09-26-aleph-design.md`, `DECISIONS.md`, `docs/testing.md`, `README.md`

- [ ] **Step 1: Update the spec**

In §6 "Prompter orchestration", replace

```markdown
- With no Wayland display, Secret Service prompts wait (§4), and
  `alephctl unlock` unlocks in the terminal, in the style of
  `systemd-ask-password`. With `ALEPH_NO_TTY=1` its answers are lines of
  standard input (scripts, tests).
```

with

```markdown
- **The display:** the prompter runs on the session's current Wayland
  display, read at each launch from the systemd user manager's
  environment (where the compositor exports it). alephd itself is often
  started before the compositor (by `pam_aleph` during login), so its own
  environment is used only when the manager cannot be asked
  (DECISIONS.md H2).
- With no Wayland display, Secret Service prompts wait (§4), and
  `alephctl unlock` unlocks in the terminal, in the style of
  `systemd-ask-password`. With `ALEPH_NO_TTY=1` its answers are lines of
  standard input (scripts, tests).
```

In §7 "Theme", replace

```markdown
- The scanline overlay is an independent toggle, on by default, and
  disabled automatically when reduced motion is requested.
```

with

```markdown
- The scanline overlay is an independent toggle, on by default, and
  disabled automatically when reduced motion is requested (GNOME's
  `enable-animations` set to false, which also stops spinners and
  animations).
- The GUI's settings are in `~/.config/aleph/gui.toml`: `theme = "auto"`
  (Omarchy's where there is one, else Aleph neon) or `"neon"`, and
  `scanlines = true|false`.
```

In §7 "Prompter", replace

```markdown
- The recovery key is never requested here, except inside the explicit
  "Recover…" flow.
- The package ships a Hyprland snippet (float, center, pin, focus) that
  setup offers to include.
```

with

```markdown
- The recovery key is never requested here, except inside the explicit
  "Recover…" flow: asked for in any other conversation, the prompter
  refuses without showing a field.
- Text from other programs (collection labels, process names) is shown
  on one line and cut short, so it can neither draw a fake prompt inside
  the real one nor push the buttons out of view.
- If no window can open, the prompter cancels at once; when alephd ends
  the conversation, the window closes (a closing message stays until it
  is read).
- The package ships a Hyprland window rule,
  `/usr/share/aleph/hyprland/aleph-prompt.lua` (float, center, pin, and
  keep the keyboard on the prompt while it is open), which setup offers
  to include from `~/.config/hypr/hyprland.lua` (through `pcall`, so an
  uninstalled aleph never breaks Hyprland's configuration); revert
  removes it.
```

In §8's install list, replace

```markdown
    - `alephctl` to `/usr/bin`; `alephd` and `aleph-tpmd` to
      `/usr/lib/aleph/`
```

with

```markdown
    - `alephctl` and `aleph-gui` to `/usr/bin`; `alephd` and `aleph-tpmd`
      to `/usr/lib/aleph/`
```

and replace

```markdown
    - `/usr/share/aleph/hypr/aleph.conf`
```

with

```markdown
    - `/usr/share/aleph/hyprland/aleph-prompt.lua`
```

In §9, replace

```markdown
- **GUI:** `egui_kittest` snapshots of every prompter screen in both
  themes, and `colors.toml` parsing tests.
```

with

```markdown
- **GUI:** `egui_kittest` snapshots of every prompter screen in both
  themes (rendered with wgpu: the tests need a GPU driver, or Mesa's
  software Vulkan), the screens driven through AccessKit as a person
  would (typing, Enter, Escape, clicks), `colors.toml` parsing tests, and
  the binary's handling of `ALEPH_PROMPT_FD` and of a missing display.
```

- [ ] **Step 2: Add the decisions**

In `DECISIONS.md`, insert after the introduction (before `## 2026-09-27: Plan 4c (setup), design`):

```markdown
## 2026-09-28: Plan 5a (the prompter), design

### H2. Calls made while prototyping Plan 5a

For the reviewers; each is argued in the plan
(`docs/superpowers/plans/2026-09-28-aleph-prompter.md`, "Decisions made
while prototyping") and pinned by a test that was seen to fail without it.

- **The prompter's display comes from the user manager.** alephd is often
  started by `pam_aleph` during login, before Hyprland exists; its own
  environment then never has `WAYLAND_DISPLAY`, and every prompt would wait
  for `alephctl unlock` until alephd restarted. At each launch alephd reads
  the systemd user manager's `Environment` (uncached, 2 s limit), where the
  compositor exports the display, and uses its own environment only when
  the manager cannot be asked. No display there means no graphical session
  now, and the prompt waits (§4), as before.
- **`~/.config/aleph/gui.toml`** holds the GUI's settings (`theme = "auto" |
  "neon"`, `scanlines`): alephd's `config.toml` refuses unknown keys and
  has no use for them. An unreadable file warns and uses the defaults.
- **Reduced motion** is GNOME's `enable-animations = false`, read with
  `gsettings` (absent: not requested). It turns off scanlines, spinners, and
  animations; the scanlines themselves never move.
- **Omarchy's palette:** `background`, `foreground`, and `accent` are
  required; the other keys are used when present, blends otherwise; a file
  that does not parse means Aleph neon. The watcher follows
  `~/.local/state/omarchy/current` recursively (Omarchy rewrites the
  theme's files in place).
- **A strict conversation:** `Begin` first; the recovery-key question is
  refused outside a recovery conversation (answered `Cancel`, no field
  shown); one answer per question; `Cancel` at any time. A window that
  cannot open cancels at once (alephd would otherwise wait out the prompt
  timeout); alephd closing the socket closes the window; a closing message
  stays until it is read.
- **Text from other programs** (collection labels, process names, key
  names, errors) is shown one line per item and cut at 80 or 400
  characters.
- **Hyprland:** only the Lua configuration (Omarchy's) gets setup's offer;
  the include is `pcall(dofile, …)`, appended in place (a symlinked dotfile
  stays one) and removed exactly by revert. The rule floats, centers, pins,
  and keeps the keyboard on the prompt (`stay_focused`), so a password is
  never typed into another window; the prompt always ends (an answer,
  Escape, or `prompt.timeout`). A `hyprland.conf` user adds the rule by
  hand. The spec's `/usr/share/aleph/hypr/aleph.conf` becomes
  `/usr/share/aleph/hyprland/aleph-prompt.lua`.
- **Snapshot tests render with wgpu:** they need a GPU driver or Mesa's
  software Vulkan, and are regenerated (and looked at) on a new machine.
- **The terminal prompter's comment** said the GUI offers "skip" while
  waiting for a key; the protocol has no such answer, and the comment now
  says Cancel ends the operation in both.

### H1. Plan 5 is split: 5a the prompter, 5b the manager — owner's decision

After the first real setup, the missing graphical prompt was the gap met
every day: SDDM logs the owner in automatically, so after each boot the
keyring is locked, and applications asking for a secret waited for
`alephctl unlock` ("no prompter" in alephd's journal). Plan 5a is the
prompter alone (`aleph-gui prompt`, the Hyprland rule, setup's offer);
Plan 5b is the manager window (items, keyslots, settings, import and
export, "Recover…", the `.desktop` file and icons), which nothing waits on.
```

- [ ] **Step 3: Update testing.md and the README**

In `docs/testing.md`, in the automated requirements list, after the `dbus`/`libsecret` bullet, add:

```markdown
- **A GPU driver** (or Mesa's software Vulkan, `vulkan-swrast`, headless)
  and **`lua`** (`luac`): the prompter's snapshot tests render with wgpu,
  and setup's Hyprland include is checked with `luac -p`. The snapshots
  are compared pixel by pixel; on another machine, regenerate them with
  `UPDATE_SNAPSHOTS=1 cargo test -p aleph-gui --test screens` and look at
  every image before committing.
```

and extend the Arch and Nix lines: replace

```markdown
- Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`.
  Nix: `swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`.
```

with

```markdown
- Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret lua`.
  Nix: `swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret lua`.
```

In "alephd with real clients", replace step 3,

```markdown
3. `alephctl lock`, then `secret-tool lookup service aleph-check`: it waits
   (no graphical prompter yet). In the other terminal, `alephctl unlock`: the
   lookup then prints the secret.
```

with

```markdown
3. `alephctl lock`, then `secret-tool lookup service aleph-check`: the
   prompt window opens, floating in the middle of the screen with the
   keyboard on its password field. Type the login password: the lookup
   prints the secret. Again with a wrong password (the error shows, the
   field is empty and still has the keyboard), with Escape (the lookup
   ends without a secret), and from a fullscreen window (the prompt still
   gets the keyboard). With a security key enrolled: "Use security key",
   then the PIN and touch screens. Switch the Omarchy theme while a prompt
   is open: it re-themes. Without a graphical session (a text console,
   `WAYLAND_DISPLAY` unset), the lookup waits, and `alephctl unlock` in
   another terminal ends it.
```

and in step 4 (Chromium) replace `` `alephctl unlock` when it waits `` with `unlock in the prompt`.

After step 6 add:

```markdown
7. **After a reboot with SDDM autologin** (Plan 5a): the first
   application that wants a secret (or `secret-tool lookup service
   aleph-check`) opens the prompt, although alephd started before
   Hyprland.
```

In `README.md`, add a row to the Crates table after `aleph-cli`:

```markdown
| `aleph-gui` | `aleph-gui prompt`: the unlock prompt `alephd` opens (the manager window comes later) |
```

and in "Development", replace

```markdown
Tests need `swtpm`, `tpm2-tools`, `tpm2-tss`, `libfido2`, `pam`, `dbus`
and `libsecret` (Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam
dbus libsecret`). Hardware tests are opt-in;
see [docs/testing.md](docs/testing.md).
```

with

```markdown
Tests need `swtpm`, `tpm2-tools`, `tpm2-tss`, `libfido2`, `pam`, `dbus`,
`libsecret` and `lua`, and a GPU driver for the prompter's snapshots
(Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret
lua`). Hardware tests are opt-in; see [docs/testing.md](docs/testing.md).
```

- [ ] **Step 4: Check the documents**

Run: `grep -n "hypr/aleph.conf\|no graphical prompter yet\|offers \"skip\"" -r docs README.md crates || echo clean`
Expected: `clean`.
Run: `make gate`
Expected: exit 0.

- [ ] **Step 5: Commit**

```bash
git add docs DECISIONS.md README.md
git commit -m "docs: Plan 5a, the prompter (spec, decisions H1 and H2, testing)" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Hand over the manual checks**

The manual checks (testing.md "alephd with real clients" steps 3 and 7) need the installed build on the owner's live session (`make && make install` restarts alephd, which locks the keyring). Do not run them; list them for the owner, who records the results in `docs/hardware-log.md`.
