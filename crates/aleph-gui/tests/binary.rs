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
