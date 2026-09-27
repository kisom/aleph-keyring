//! Delivering one request to `pam.sock` as the target user.
//!
//! The module runs inside another program, often as root (the display
//! manager, `passwd`), sometimes as the user (the screen locker). The
//! request is sent from a forked child that first drops to the user's
//! uid and gid (only when running as root), so the daemon's
//! `SO_PEERCRED` check sees the user and root never writes into a
//! user-controlled socket path. The parent waits at most the timeout, then
//! kills the child.
//!
//! The host program may be multithreaded, so the child calls only
//! async-signal-safe functions: everything (the socket address, the
//! request frame) is prepared before `fork`, and the child never
//! allocates. Writes use `MSG_NOSIGNAL`, so a daemon that hangs up cannot
//! kill the child with `SIGPIPE`, and `alarm` bounds the child even if the
//! parent is gone.
//!
//! The child closes every descriptor it inherited but its report pipe, and
//! resets `SIGALRM` so the backstop works whatever the host did with it.
//!
//! The host's `SIGCHLD` handling is never touched (it is process-wide, and
//! the host may be reaping its own children): the child reports its result
//! as one byte on a pipe, the parent waits on the pipe with the timeout,
//! kills through a pidfd (never a pid the host may have reaped and the
//! kernel reused), and reaps through the pidfd, ignoring `ECHILD` if the
//! host got there first.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// Whom to deliver as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

/// How a delivery ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The daemon did what was asked.
    Accepted,
    /// The daemon answered, but refused or failed (see its journal).
    Refused,
    /// No daemon listening at the socket.
    Unreachable,
    /// Could not become the target user.
    NoPrivileges,
    /// No answer within the timeout.
    TimedOut,
    /// Anything else (a malformed answer, a failed fork).
    Failed,
}

// What the child reports (one byte on the pipe, and its exit code).
const ACCEPTED: u8 = 0;
const REFUSED: u8 = 10;
const UNREACHABLE: u8 = 11;
const NO_PRIVILEGES: u8 = 12;
const FAILED: u8 = 13;

/// The largest reply read (a reply is a short status message).
const REPLY_MAX: usize = 1024;

/// The target user of `name`, from the password database.
pub fn target(name: &str) -> Option<Target> {
    let name = CString::new(name).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut out = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call; `buf` outlives it.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    (rc == 0 && !out.is_null()).then_some(Target {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
    })
}

/// Send `frame` (a whole request frame) to the socket at `socket` as
/// `target`, and wait at most `timeout` for the answer.
pub fn deliver(target: Target, socket: &Path, frame: &[u8], timeout: Duration) -> Outcome {
    let Some(addr) = sockaddr(socket) else {
        return Outcome::Unreachable;
    };
    let secs = timeout.as_secs().max(1) as libc::c_uint;
    let tv = libc::timeval {
        tv_sec: timeout.as_secs().max(1) as libc::time_t,
        tv_usec: 0,
    };
    let mut pipe = [0; 2];
    // SAFETY: pipe2 fills the array.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Outcome::Failed;
    }
    let [report, reporter] = pipe;
    // SAFETY: the child runs only `child`, which calls async-signal-safe
    // functions on memory prepared before the fork, and never returns.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Nothing can panic in `child`; if something ever did, the forked
        // copy must exit, never unwind back into the host's PAM stack.
        let _exit = ExitOnUnwind(reporter);
        unsafe {
            libc::close(report);
            child(target, &addr, frame, &tv, secs, reporter)
        }
    }
    // SAFETY: closing our copy of the child's end.
    unsafe { libc::close(reporter) };
    if pid < 0 {
        unsafe { libc::close(report) };
        return Outcome::Failed;
    }
    // SAFETY: pidfd_open on our fresh child (it cannot have been reaped
    // yet unless it already exited, in which case the pipe says so).
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as libc::c_int;
    let outcome = wait(report, timeout);
    // SAFETY: signalling and reaping our own child, through its pidfd.
    unsafe {
        if pidfd >= 0 {
            if outcome == Outcome::TimedOut {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd,
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
            let mut info: libc::siginfo_t = std::mem::zeroed();
            // (ECHILD: the host reaped it, or ignores SIGCHLD. Either is fine.)
            libc::waitid(libc::P_PIDFD, pidfd as libc::id_t, &mut info, libc::WEXITED);
            libc::close(pidfd);
        } else {
            // No pidfd (an old kernel, a seccomp'd host, no descriptors
            // left): the pid, then. The child is ours and not yet reaped
            // unless the host reaps children itself.
            if outcome == Outcome::TimedOut {
                libc::kill(pid, libc::SIGKILL);
            }
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
        libc::close(report);
    }
    outcome
}

/// In the forked child: exit (reporting a failure) if unwinding, rather
/// than return into the host.
struct ExitOnUnwind(libc::c_int);

impl Drop for ExitOnUnwind {
    fn drop(&mut self) {
        // SAFETY: only ever dropped in the forked child.
        unsafe { finish(self.0, FAILED) }
    }
}

fn sockaddr(path: &Path) -> Option<libc::sockaddr_un> {
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return None;
    }
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    Some(addr)
}

/// The child's report, read from its pipe within `timeout`.
fn wait(report: libc::c_int, timeout: Duration) -> Outcome {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let mut pfd = libc::pollfd {
            fd: report,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(i32::MAX as u128) as i32) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            return Outcome::TimedOut;
        }
        let mut code = [0u8; 1];
        // SAFETY: reading one byte into a local.
        let got = unsafe { libc::read(report, code.as_mut_ptr().cast(), 1) };
        return match (got, code[0]) {
            (1, ACCEPTED) => Outcome::Accepted,
            (1, REFUSED) => Outcome::Refused,
            (1, UNREACHABLE) => Outcome::Unreachable,
            (1, NO_PRIVILEGES) => Outcome::NoPrivileges,
            // A child that died without a word (alarm, crash).
            _ => Outcome::Failed,
        };
    }
}

/// Report `code` on the pipe and exit with it.
///
/// # Safety
///
/// Only in the forked child.
unsafe fn finish(reporter: libc::c_int, code: u8) -> ! {
    unsafe {
        libc::write(reporter, (&raw const code).cast(), 1);
        libc::_exit(i32::from(code))
    }
}

/// The forked child: become the user, send, read the answer, report.
///
/// # Safety
///
/// Called only in a freshly forked child. Uses only async-signal-safe
/// calls, allocates nothing, and never returns.
unsafe fn child(
    target: Target,
    addr: &libc::sockaddr_un,
    frame: &[u8],
    tv: &libc::timeval,
    secs: libc::c_uint,
    reporter: libc::c_int,
) -> ! {
    unsafe {
        // The host's descriptors (sockets, devices) are not the child's
        // business: close all but the report pipe.
        if reporter > 3 {
            libc::syscall(libc::SYS_close_range, 3u32, (reporter - 1) as u32, 0u32);
        }
        libc::syscall(libc::SYS_close_range, (reporter + 1) as u32, u32::MAX, 0u32);
        // The host may ignore, catch, or block SIGALRM: the backstop needs
        // its default action.
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGALRM, &dfl, std::ptr::null_mut());
        let mut alrm: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut alrm);
        libc::sigaddset(&mut alrm, libc::SIGALRM);
        libc::sigprocmask(libc::SIG_UNBLOCK, &alrm, std::ptr::null_mut());
        libc::alarm(secs + 1);
        // Root drops to the user (groups, then gid, then uid); anyone else
        // must already be the user.
        if libc::geteuid() == 0
            && (libc::setgroups(1, &target.gid) != 0
                || libc::setgid(target.gid) != 0
                || libc::setuid(target.uid) != 0)
        {
            finish(reporter, NO_PRIVILEGES);
        }
        if libc::getuid() != target.uid || libc::geteuid() != target.uid {
            finish(reporter, NO_PRIVILEGES);
        }
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            finish(reporter, FAILED);
        }
        let tvp = (tv as *const libc::timeval).cast();
        let tvlen = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, tvp, tvlen);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, tvp, tvlen);
        if libc::connect(
            fd,
            (addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        ) != 0
        {
            finish(reporter, UNREACHABLE);
        }
        let mut sent = 0;
        while sent < frame.len() {
            let n = libc::send(
                fd,
                frame.as_ptr().add(sent).cast(),
                frame.len() - sent,
                libc::MSG_NOSIGNAL,
            );
            if n <= 0 {
                finish(reporter, FAILED);
            }
            sent += n as usize;
        }
        let mut reply = [0u8; REPLY_MAX];
        let mut got = 0;
        while got < REPLY_MAX {
            let n = libc::recv(fd, reply.as_mut_ptr().add(got).cast(), REPLY_MAX - got, 0);
            if n <= 0 {
                break;
            }
            got += n as usize;
            if let Some(ok) = aleph_pam_proto::reply_ok(reply.get_unchecked(..got)) {
                finish(reporter, if ok { ACCEPTED } else { REFUSED });
            }
        }
        finish(reporter, FAILED)
    }
}
