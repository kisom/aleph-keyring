//! The built module, loaded by real Linux-PAM from a private service
//! directory (`pam_start_confdir`). `pam_exec expose_authtok` stands in for
//! `pam_unix`: it obtains the password through the test's conversation and
//! sets `PAM_AUTHTOK`, which an application cannot set itself.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use aleph_pam_proto::{Password, Reply, Request};

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
    fn pam_open_session(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
}

/// Answers every hidden prompt with "hunter2".
extern "C" fn conversation(
    n: c_int,
    msgs: *mut *const Message,
    out: *mut *mut Response,
    _: *mut c_void,
) -> c_int {
    // SAFETY: PAM passes `n` messages; responses are calloc'd, answers
    // strdup'd, as PAM frees them with free().
    unsafe {
        let responses =
            libc::calloc(n as usize, std::mem::size_of::<Response>()).cast::<Response>();
        for i in 0..n as usize {
            if (**msgs.add(i)).style == PAM_PROMPT_ECHO_OFF {
                (*responses.add(i)).resp = libc::strdup(c"hunter2".as_ptr());
            }
        }
        *out = responses;
    }
    PAM_SUCCESS
}

/// The built module (next to the test binary's directory).
fn module() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let deps = exe.parent().unwrap();
    [
        deps.join("libpam_aleph.so"),
        deps.parent().unwrap().join("libpam_aleph.so"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .expect("libpam_aleph.so is built with the tests")
}

/// A service file in `dir` stacking pam_exec, then pam_aleph.
fn service(dir: &Path, socket: &Path) {
    let m = module();
    let arg = format!("socket={}", socket.display());
    let text = format!(
        "auth     optional pam_exec.so expose_authtok quiet /usr/bin/cat\n\
         auth     optional {m} {arg}\n\
         auth     required pam_permit.so\n\
         session  optional {m} {arg}\n\
         session  required pam_permit.so\n",
        m = m.display()
    );
    std::fs::write(dir.join("aleph-test"), text).unwrap();
}

/// A daemon answering every request `ok`, reporting each on `tx`.
fn daemon(listener: UnixListener, tx: mpsc::Sender<Request>) {
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let mut s = s.unwrap();
            let mut header = [0u8; 4];
            s.read_exact(&mut header).unwrap();
            let mut payload = vec![0u8; aleph_pam_proto::payload_len(header).unwrap()];
            s.read_exact(&mut payload).unwrap();
            let reply = Reply {
                ok: true,
                message: "unlocked".into(),
            };
            s.write_all(&reply.encode().unwrap()).unwrap();
            tx.send(Request::decode(&payload).unwrap()).unwrap();
        }
    });
}

/// Run auth, then (after `between`) session open, through real PAM.
fn login(dir: &Path, between: impl FnOnce()) -> (c_int, c_int) {
    let user = CString::new(std::env::var("USER").expect("USER")).unwrap();
    let confdir = CString::new(dir.to_str().unwrap()).unwrap();
    let conv = Conv {
        conv: conversation,
        appdata: std::ptr::null_mut(),
    };
    let mut h = std::ptr::null_mut();
    // SAFETY: valid strings and conversation for the handle's lifetime.
    unsafe {
        assert_eq!(
            pam_start_confdir(
                c"aleph-test".as_ptr(),
                user.as_ptr(),
                &conv,
                confdir.as_ptr(),
                &mut h
            ),
            PAM_SUCCESS
        );
        let auth = pam_authenticate(h, 0);
        between();
        let session = pam_open_session(h, 0);
        pam_end(h, PAM_SUCCESS);
        (auth, session)
    }
}

fn unlock() -> Request {
    Request::Unlock {
        password: Password::new(b"hunter2"),
    }
}

/// With the daemon up (a screen locker), the password goes out at auth.
#[test]
fn with_the_daemon_up_the_password_goes_out_at_auth() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pam.sock");
    service(dir.path(), &socket);
    let (tx, rx) = mpsc::channel();
    daemon(UnixListener::bind(&socket).unwrap(), tx);
    let (auth, session) = login(dir.path(), || {
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), unlock());
    });
    assert_eq!((auth, session), (PAM_SUCCESS, PAM_SUCCESS));
    // Once only: nothing more at session open.
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
}

/// At login the user's daemon is not up yet: the password is kept and
/// goes out at session open.
#[test]
fn at_login_the_password_goes_out_at_session_open() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pam.sock");
    service(dir.path(), &socket);
    let (tx, rx) = mpsc::channel();
    let (auth, session) = login(dir.path(), || {
        daemon(UnixListener::bind(&socket).unwrap(), tx);
    });
    assert_eq!((auth, session), (PAM_SUCCESS, PAM_SUCCESS));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), unlock());
}

/// No daemon at all: the login still succeeds, promptly.
#[test]
fn without_a_daemon_login_goes_on() {
    let dir = tempfile::tempdir().unwrap();
    service(dir.path(), &dir.path().join("pam.sock"));
    let t = std::time::Instant::now();
    let (auth, session) = login(dir.path(), || {});
    assert_eq!((auth, session), (PAM_SUCCESS, PAM_SUCCESS));
    assert!(t.elapsed() < Duration::from_secs(2));
}
