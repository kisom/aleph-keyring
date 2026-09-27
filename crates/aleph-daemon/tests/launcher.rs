//! `ProgramLauncher` against a real child process (its own test binary:
//! it sets `WAYLAND_DISPLAY` for the whole process).

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use aleph_daemon::config::Config;
use aleph_daemon::prompt::{FromPrompter, Launcher, ProgramLauncher, ToPrompter};

/// The prompter gets its socket as `ALEPH_PROMPT_FD` (inheritable in the
/// child, though close-on-exec in the daemon) and the conversation runs
/// over it.
#[test]
fn a_launched_prompter_talks_over_its_inherited_socket() {
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("prompter");
    std::fs::write(
        &program,
        "#!/bin/sh\n[ \"$1\" = prompt ] || exit 2\nread -r line <&\"$ALEPH_PROMPT_FD\"\nprintf '{\"type\":\"confirm\",\"yes\":true}\\n' >&\"$ALEPH_PROMPT_FD\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    // SAFETY: this test binary has a single test; nothing reads the
    // environment concurrently.
    unsafe { std::env::set_var("WAYLAND_DISPLAY", "wayland-test") };
    let mut config = Config::default();
    config.prompt.program = program.display().to_string();
    config.prompt.timeout = 10;
    let launcher = ProgramLauncher {
        config: Arc::new(Mutex::new(config)),
    };
    let mut chan = launcher.launch().unwrap();
    let reply = chan
        .ask(&ToPrompter::Confirm { text: "ok?".into() })
        .unwrap();
    assert_eq!(reply, FromPrompter::Confirm { yes: true });
}
