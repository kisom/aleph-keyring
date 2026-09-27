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
