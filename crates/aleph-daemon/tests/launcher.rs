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
