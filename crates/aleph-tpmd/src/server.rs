//! Request handling and the socket loop.
//!
//! The caller's uid comes only from `SO_PEERCRED`, and only login uids
//! are served ([`Policy`]). Each connection gets its own thread (at most
//! [`MAX_CONNECTIONS`]) and must deliver its whole request within
//! [`REQUEST_DEADLINE`], so a slow or idle client cannot hold the helper;
//! a uid may have one connection in flight at a time, so one user cannot
//! take every thread. Only the TPM itself is serialized.

use std::collections::HashSet;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aleph_tpm_proto::{Failure, Request, Response, Secret, read_frame, write_frame};

use crate::limiter::{RateLimiter, reserve_threshold, window};
use crate::tpm::{Tpm, TpmError};

/// How long a client has to deliver its whole request.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(2);
/// How long a client may take to read the reply.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections served at once; more are refused with `Busy`.
pub const MAX_CONNECTIONS: usize = 64;

/// Which uids the helper serves: login users only (system accounts have
/// no business sealing secrets, and each served uid is a DA budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub uid_min: u32,
    pub uid_max: u32,
}

impl Policy {
    /// `UID_MIN`/`UID_MAX` from `login.defs` text, defaulting to the
    /// shadow-utils values 1000 and 60000. Values may be decimal, `0x`
    /// hex, or `0` octal, as shadow accepts.
    pub fn from_login_defs(text: &str) -> Self {
        let mut policy = Self {
            uid_min: 1000,
            uid_max: 60000,
        };
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let (Some(key), Some(value)) = (words.next(), words.next()) else {
                continue;
            };
            let Some(value) = parse_c_integer(value) else {
                continue;
            };
            match key {
                "UID_MIN" => policy.uid_min = value,
                "UID_MAX" => policy.uid_max = value,
                _ => {}
            }
        }
        policy
    }

    /// The system's policy, from `/etc/login.defs` (defaults if absent).
    pub fn system() -> Self {
        Self::from_login_defs(
            &std::fs::read_to_string(Path::new("/etc/login.defs")).unwrap_or_default(),
        )
    }

    /// Every uid (tests, which run as arbitrary users).
    pub fn allow_all() -> Self {
        Self {
            uid_min: 0,
            uid_max: u32::MAX,
        }
    }

    /// Login uids, plus systemd-homed's range (regular users too).
    pub fn allows(&self, uid: u32) -> bool {
        (self.uid_min..=self.uid_max).contains(&uid) || HOMED_UIDS.contains(&uid)
    }
}

/// systemd-homed allocates regular users' uids here.
pub const HOMED_UIDS: std::ops::RangeInclusive<u32> = 60001..=60513;

/// A number as `strtoul(_, _, 0)` reads it.
fn parse_c_integer(text: &str) -> Option<u32> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if text.len() > 1 && text.starts_with('0') {
        u32::from_str_radix(&text[1..], 8).ok()
    } else {
        text.parse().ok()
    }
}

pub struct Helper {
    tpm: Mutex<Tpm>,
    limiter: Mutex<RateLimiter>,
    policy: Policy,
    in_flight: Mutex<HashSet<u32>>,
    connections: AtomicUsize,
}

/// A slot in the connection count, released on drop (even if the
/// connection's thread panics).
struct Connection<'a>(&'a AtomicUsize);

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A uid's in-flight slot, released on drop.
pub struct Claim<'a> {
    helper: &'a Helper,
    uid: u32,
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        lock(&self.helper.in_flight).remove(&self.uid);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Helper {
    pub fn new(tpm: Tpm, policy: Policy) -> Self {
        Self {
            tpm: Mutex::new(tpm),
            limiter: Mutex::new(RateLimiter::default()),
            policy,
            in_flight: Mutex::new(HashSet::new()),
            connections: AtomicUsize::new(0),
        }
    }

    /// Whether `uid` may use the helper at all.
    pub fn admits(&self, uid: u32) -> bool {
        self.policy.allows(uid)
    }

    /// Take `uid`'s in-flight slot, or `None` if it already has a request
    /// in progress.
    pub fn claim(&self, uid: u32) -> Option<Claim<'_>> {
        // Not `then_some`: that would build (and drop) a Claim even when
        // the insert fails, releasing the other request's slot.
        if lock(&self.in_flight).insert(uid) {
            Some(Claim { helper: self, uid })
        } else {
            None
        }
    }

    /// Handle one request from `uid` (as reported by the kernel).
    pub fn handle(&self, uid: u32, request: Request) -> Response {
        self.handle_at(uid, request, Instant::now())
    }

    /// `handle` with an explicit clock, for tests.
    pub fn handle_at(&self, uid: u32, request: Request, now: Instant) -> Response {
        if !self.policy.allows(uid) {
            return Response::Failed(Failure::NotPermitted);
        }
        let mut tpm = lock(&self.tpm);
        match request {
            Request::Seal { secret } => {
                // A slot on a TPM whose whole budget is the reserve could
                // never be opened: refuse it now rather than at unlock.
                match tpm.da_counters() {
                    Ok((_, max, recovery)) if recovery > 0 && reserve_threshold(max) == 0 => {
                        return Response::Failed(Failure::Exhausted);
                    }
                    Ok(_) => {}
                    Err(e) => return Response::Failed(failure(e)),
                }
                match tpm.seal(uid, &secret.0) {
                    Ok((object, kek)) => Response::Sealed {
                        object,
                        kek: Secret(kek.to_vec()),
                    },
                    Err(e) => Response::Failed(failure(e)),
                }
            }
            Request::Unseal { object, secret } => {
                let (failed, max, recovery) = match tpm.da_counters() {
                    Ok(c) => c,
                    Err(e) => return Response::Failed(failure(e)),
                };
                let window = window(recovery);
                let mut limiter = lock(&self.limiter);
                if limiter.blocked(uid, now, window) {
                    return Response::Failed(Failure::RateLimited);
                }
                // Never spend the TPM's reserve: that is what keeps aleph
                // from ever locking the TPM out. A recovery time of zero
                // turns dictionary-attack counting off: nothing to protect.
                if recovery > 0 && failed >= reserve_threshold(max) {
                    return Response::Failed(Failure::Exhausted);
                }
                match tpm.unseal(uid, &object, &secret.0) {
                    Ok(kek) => Response::Unsealed {
                        kek: Secret(kek.to_vec()),
                    },
                    Err(e) => {
                        // (A Lockout reply needs no counting: the reserve
                        // check above already refuses long before it.)
                        if matches!(e, TpmError::AuthFailed | TpmError::WrongUser) {
                            limiter.record_failure(uid, now, window);
                        }
                        Response::Failed(failure(e))
                    }
                }
            }
            Request::Status {} => match tpm.status() {
                Ok(s) => Response::Status(s),
                Err(e) => Response::Failed(failure(e)),
            },
        }
    }
}

fn failure(e: TpmError) -> Failure {
    match e {
        TpmError::AuthFailed => Failure::AuthFailed,
        TpmError::Lockout => Failure::Lockout,
        TpmError::WrongUser => Failure::WrongUser,
        TpmError::ParentMismatch => Failure::ParentMismatch,
        TpmError::NoParent => Failure::NoParent,
        TpmError::Malformed(m) => Failure::Malformed(m),
        TpmError::Unavailable(m) | TpmError::Tpm(m) => Failure::Tpm(m),
    }
}

/// The connected peer's uid, from the kernel.
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes given.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Reads that fail once `deadline` passes, however the client paces its
/// bytes (a per-read timeout alone lets a byte-a-second client stay).
struct DeadlineReader<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(remaining))?;
        (&*self.stream).read(buf)
    }
}

/// Serve one connection: one request, one response.
pub fn serve_connection(helper: &Helper, mut stream: UnixStream) -> io::Result<()> {
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let uid = peer_uid(&stream)?;
    // Before reading anything: uids outside the policy (a user's subuid
    // range, say, where one user has thousands) must not hold threads.
    if !helper.admits(uid) {
        return reply(&mut stream, &Response::Failed(Failure::NotPermitted));
    }
    let Some(_claim) = helper.claim(uid) else {
        return reply(&mut stream, &Response::Failed(Failure::Busy));
    };
    let mut reader = DeadlineReader {
        stream: &stream,
        deadline: Instant::now() + REQUEST_DEADLINE,
    };
    let response = match read_frame::<Request>(&mut reader) {
        Ok(request) => helper.handle(uid, request),
        Err(e) => Response::Failed(Failure::Malformed(e.to_string())),
    };
    reply(&mut stream, &response)
}

fn reply(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    write_frame(stream, response).map_err(io::Error::other)
}

/// Accept connections forever, each on its own thread. Per-connection
/// errors are logged and do not stop the helper.
pub fn serve(listener: &UnixListener, helper: Arc<Helper>) -> ! {
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) => {
                eprintln!("aleph-tpmd: accept error: {e}");
                continue;
            }
        };
        if helper.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            helper.connections.fetch_sub(1, Ordering::SeqCst);
            let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
            let _ = reply(&mut stream, &Response::Failed(Failure::Busy));
            continue;
        }
        let spawned = std::thread::Builder::new().spawn({
            let helper = Arc::clone(&helper);
            move || {
                let _slot = Connection(&helper.connections);
                if let Err(e) = serve_connection(&helper, stream) {
                    eprintln!("aleph-tpmd: connection error: {e}");
                }
            }
        });
        if let Err(e) = spawned {
            // The closure (and with it the stream) was dropped unrun.
            helper.connections.fetch_sub(1, Ordering::SeqCst);
            eprintln!("aleph-tpmd: cannot spawn a connection thread: {e}");
        }
    }
}
