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
