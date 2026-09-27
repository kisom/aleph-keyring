use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use aleph_tpm_proto::{Failure, Request, Response, Secret, read_frame, write_frame};
use aleph_tpmd::testing::SwTpm;

/// A helper serving `n` connections on a socket in a temp directory.
fn serve(
    sw: &SwTpm,
    n: usize,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::thread::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let helper = Arc::new(sw.helper());
    let handle = std::thread::spawn(move || {
        for _ in 0..n {
            let (stream, _) = listener.accept().unwrap();
            let _ = aleph_tpmd::server::serve_connection(&helper, stream);
        }
    });
    (dir, path, handle)
}

fn call(path: &std::path::Path, request: &Request) -> Response {
    let mut s = UnixStream::connect(path).unwrap();
    write_frame(&mut s, request).unwrap();
    read_frame(&mut s).unwrap()
}

#[test]
fn a_client_seals_and_unseals_over_the_socket_as_itself() {
    let sw = SwTpm::start();
    let (_dir, path, server) = serve(&sw, 2);
    let Response::Sealed { object, kek } = call(
        &path,
        &Request::Seal {
            secret: Secret(b"pw".to_vec()),
        },
    ) else {
        panic!("seal failed")
    };
    let Response::Unsealed { kek: back } = call(
        &path,
        &Request::Unseal {
            object,
            secret: Secret(b"pw".to_vec()),
        },
    ) else {
        panic!("unseal failed")
    };
    assert_eq!(kek, back);
    server.join().unwrap();
}

/// The uid comes from the kernel: an object sealed over the socket (as the
/// real uid) does not open for any other uid handled directly.
#[test]
fn the_socket_binds_objects_to_the_callers_real_uid() {
    let sw = SwTpm::start();
    let (_dir, path, server) = serve(&sw, 1);
    let Response::Sealed { object, .. } = call(
        &path,
        &Request::Seal {
            secret: Secret(b"pw".to_vec()),
        },
    ) else {
        panic!("seal failed")
    };
    server.join().unwrap();
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let helper = sw.helper();
    let other = helper.handle(
        me.wrapping_add(1),
        Request::Unseal {
            object: object.clone(),
            secret: Secret(b"pw".to_vec()),
        },
    );
    assert!(matches!(
        other,
        Response::Failed(Failure::AuthFailed | Failure::WrongUser)
    ));
    assert!(matches!(
        helper.handle(
            me,
            Request::Unseal {
                object,
                secret: Secret(b"pw".to_vec())
            }
        ),
        Response::Unsealed { .. }
    ));
}

#[test]
fn a_garbage_frame_gets_a_malformed_reply() {
    let sw = SwTpm::start();
    let (_dir, path, server) = serve(&sw, 1);
    let mut s = UnixStream::connect(&path).unwrap();
    s.write_all(&4u32.to_be_bytes()).unwrap();
    s.write_all(b"\xff\xff\xff\xff").unwrap();
    let reply: Response = read_frame(&mut s).unwrap();
    assert!(matches!(reply, Response::Failed(Failure::Malformed(_))));
    server.join().unwrap();
}

/// A uid outside the policy is refused before the helper reads anything,
/// so such uids (a user's subuid range can hold thousands) cannot occupy
/// connection threads for the request deadline.
#[test]
fn a_non_login_uid_is_refused_without_waiting_for_its_request() {
    use aleph_tpmd::server::Policy;
    use std::time::{Duration, Instant};

    let sw = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&path).unwrap();
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let others = Policy {
        uid_min: me.wrapping_add(1),
        uid_max: me.wrapping_add(1),
    };
    let helper = Arc::new(sw.helper_with(others));
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, helper));
    let t = Instant::now();
    let mut s = UnixStream::connect(&path).unwrap();
    let reply: Response = read_frame(&mut s).unwrap();
    assert_eq!(reply, Response::Failed(Failure::NotPermitted));
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
}

/// A client trickling its request a byte at a time (which a per-read
/// timeout would never catch) is cut off at the request deadline; while
/// it holds its uid's slot, a second connection from the same uid is told
/// `Busy` at once rather than queued behind it.
#[test]
fn a_trickling_client_is_cut_off_and_does_not_queue_others() {
    use aleph_tpmd::server::REQUEST_DEADLINE;
    use std::time::{Duration, Instant};

    let sw = SwTpm::start();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let helper = Arc::new(sw.helper());
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, helper));

    let start = Instant::now();
    let mut slow = UnixStream::connect(&path).unwrap();
    slow.write_all(&100u32.to_be_bytes()).unwrap();
    let mut trickle = slow.try_clone().unwrap();
    std::thread::spawn(move || {
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(200));
            if trickle.write_all(b"\xa0").is_err() {
                break;
            }
        }
    });
    std::thread::sleep(Duration::from_millis(200));

    let t = Instant::now();
    assert_eq!(
        call(&path, &Request::Status {}),
        Response::Failed(Failure::Busy)
    );
    assert!(t.elapsed() < Duration::from_millis(500));

    let reply: Response = read_frame(&mut slow).unwrap();
    assert!(
        matches!(reply, Response::Failed(Failure::Malformed(_))),
        "{reply:?}"
    );
    let cut_off = start.elapsed();
    assert!(
        cut_off >= REQUEST_DEADLINE && cut_off < REQUEST_DEADLINE + Duration::from_secs(1),
        "{cut_off:?}"
    );
    assert!(matches!(
        call(&path, &Request::Status {}),
        Response::Status(_)
    ));
}
