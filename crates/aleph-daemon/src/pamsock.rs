//! `pam.sock` (spec §6 "PAM integration"): where `pam_aleph` hands over
//! the login password.
//!
//! - **Who may connect:** only the daemon's own uid (`SO_PEERCRED`).
//!   `pam_aleph` connects from a child that dropped to the user's uid.
//! - **What arrives:** one request per connection (`aleph-pam-proto`),
//!   within [`REQUEST_TIMEOUT`]. `Unlock` carries a password the login
//!   stack accepted (a login, or unlocking the screen) and opens the vault;
//!   `ChangePassword` comes from `passwd` and replaces the password
//!   keyslots. Both are still checked with PAM where PAM can check
//!   (`Keyring::unlock_with_login_password`, `change_login_password`).
//! - **Rate limiting:** at most [`crate::password::TYPED_FAILURES`] rejected
//!   passwords per [`crate::password::TYPED_WINDOW`], which bounds
//!   same-user guessing through the socket. Refusals that say nothing
//!   about the password (busy, rate-limited) do not count. Requests still
//!   being answered count too, so parallel connections cannot get past the
//!   limit, and at most that many are in flight at once.
//! - **The listener** is the descriptor named `pam` that `alephd.socket`
//!   passes (systemd socket activation), or is bound here when not
//!   activated (tests, manual runs).

use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aleph_pam_proto::{Reply, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keyring::Keyring;
use crate::password::{TYPED_FAILURES, TypedLimiter};
use crate::secret::service::SecretService;

/// How long a client has to send its request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The first descriptor systemd passes (`SD_LISTEN_FDS_START`).
const LISTEN_FDS_START: RawFd = 3;

/// The name `alephd.socket` gives it (`FileDescriptorName=`).
const FD_NAME: &str = "pam";

/// The listening socket: the one `alephd.socket` passed, if this process
/// was socket-activated, else a fresh one bound at `path` (its directory
/// created 0700, the socket 0600, a leftover socket replaced).
pub fn listener(path: &Path) -> Result<UnixListener> {
    if let Some(l) = activated() {
        return Ok(l);
    }
    let dir = path
        .parent()
        .ok_or(Error::Environment("the PAM socket path has no directory"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    match std::fs::symlink_metadata(path) {
        // A leftover of a stopped daemon is replaced; a socket something
        // still serves (`alephd.socket`, another alephd) is not.
        Ok(m) if m.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(Error::Invalid(format!(
                    "{} is served by another process (alephd.socket?)",
                    path.display()
                )));
            }
            std::fs::remove_file(path)?
        }
        Ok(_) => {
            return Err(Error::Invalid(format!(
                "{} exists and is not a socket",
                path.display()
            )));
        }
        Err(_) => {}
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// The socket systemd passed: `LISTEN_PID` is us, and the descriptor
/// `LISTEN_FDNAMES` calls `pam` (or the only one, if unnamed) is a Unix
/// stream socket. Made close-on-exec, so no prompter inherits it.
fn activated() -> Option<UnixListener> {
    let pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    let fds: usize = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if pid != std::process::id() || fds < 1 {
        return None;
    }
    let index = match std::env::var("LISTEN_FDNAMES") {
        Ok(names) => names.split(':').position(|n| n == FD_NAME)?,
        Err(_) if fds == 1 => 0,
        Err(_) => return None,
    };
    if index >= fds {
        return None;
    }
    let fd = LISTEN_FDS_START + RawFd::try_from(index).ok()?;
    // SAFETY: plain syscalls on a descriptor number; nothing is dereferenced
    // but locals.
    unsafe {
        let mut ty: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut alen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut ty).cast(),
            &mut len,
        ) != 0
            || ty != libc::SOCK_STREAM
            || libc::getsockname(fd, (&raw mut addr).cast(), &mut alen) != 0
            || i32::from(addr.ss_family) != libc::AF_UNIX
        {
            return None;
        }
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        // SAFETY: systemd handed this descriptor to us, and nothing else
        // owns it.
        Some(UnixListener::from_raw_fd(fd))
    }
}

/// Serve `pam.sock` until the listener fails.
pub async fn serve(
    listener: UnixListener,
    keyring: Arc<Keyring>,
    secrets: Arc<SecretService>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let limits = Arc::new(Mutex::new(Limits::default()));
    // SAFETY: getuid cannot fail.
    let own_uid = unsafe { libc::getuid() };
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            // (Out of descriptors, say: keep serving once it passes.)
            Err(e) => {
                tracing::warn!("pam.sock: accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }
        };
        let (keyring, secrets, limits) = (keyring.clone(), secrets.clone(), limits.clone());
        tokio::spawn(async move {
            match stream.peer_cred() {
                Ok(c) if c.uid() == own_uid => {}
                Ok(c) => {
                    tracing::warn!(
                        uid = c.uid(),
                        "refused a pam.sock connection from another user"
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!("pam.sock: no peer credentials: {e}");
                    return;
                }
            }
            if let Err(e) = handle(stream, keyring, secrets, limits).await {
                tracing::info!("pam.sock: {e}");
            }
        });
    }
}

/// Rejected passwords lately, and requests being answered now.
#[derive(Default)]
struct Limits {
    failures: TypedLimiter,
    in_flight: usize,
}

async fn handle(
    mut stream: tokio::net::UnixStream,
    keyring: Arc<Keyring>,
    secrets: Arc<SecretService>,
    limits: Arc<Mutex<Limits>>,
) -> std::io::Result<()> {
    let request = match tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await {
        Ok(r) => r?,
        Err(_) => return Err(std::io::Error::other("no request in time")),
    };
    let reply = answer(request, &keyring, &limits).await;
    if reply.ok {
        tracing::info!("pam.sock: {}", reply.message);
    } else {
        // (An outside password change shows here, as well as at the next
        // interactive unlock.)
        tracing::warn!("pam.sock: {}", reply.message);
    }
    // Answer first: the lock screen or the display manager is waiting, and
    // bringing the Secret Service objects up to date can take a while.
    let frame = reply.encode().map_err(std::io::Error::other)?;
    let written = stream.write_all(&frame).await;
    if !keyring.is_locked() {
        let _ = secrets.unlocked().await;
    }
    written
}

async fn read_request(stream: &mut tokio::net::UnixStream) -> std::io::Result<Request> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len = aleph_pam_proto::payload_len(header).map_err(std::io::Error::other)?;
    let mut payload = Zeroizing::new(vec![0u8; len]);
    stream.read_exact(&mut payload).await?;
    Request::decode(&payload).map_err(std::io::Error::other)
}

/// Carry out one request (on a blocking thread: it may wait for the TPM,
/// or for a running conversation to end).
async fn answer(request: Request, keyring: &Arc<Keyring>, limits: &Arc<Mutex<Limits>>) -> Reply {
    let now = Instant::now();
    let refused = {
        let mut l = limits.lock().unwrap();
        if let Some(wait) = l.failures.blocked(now) {
            Some(format!(
                "too many failed requests; retry in {} s",
                wait.as_secs().max(1)
            ))
        } else if l.failures.recent(now) + l.in_flight >= TYPED_FAILURES {
            Some("too many requests at once; retry shortly".to_string())
        } else {
            l.in_flight += 1;
            None
        }
    };
    if let Some(message) = refused {
        return Reply { ok: false, message };
    }
    let keyring = keyring.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<String> {
        let text = |p: &aleph_pam_proto::Password| {
            std::str::from_utf8(p.expose())
                .map(|s| Zeroizing::new(s.to_string()))
                .map_err(|_| Error::Invalid("the password is not UTF-8".into()))
        };
        match request {
            Request::Unlock { password } => {
                keyring.unlock_with_login_password(&text(&password)?)?;
                Ok("unlocked".into())
            }
            Request::ChangePassword { old, new } => {
                keyring.change_login_password(&text(&old)?, &text(&new)?)
            }
        }
    })
    .await
    .unwrap_or_else(|e| Err(Error::Invalid(format!("request failed: {e}"))));
    let mut l = limits.lock().unwrap();
    l.in_flight -= 1;
    match result {
        Ok(message) => Reply { ok: true, message },
        Err(e) => {
            // Only a rejected password counts: a busy or rate-limited TPM
            // must not lock real logins out.
            if matches!(
                e,
                Error::WrongPassword | Error::PasswordChanged | Error::Stale(_) | Error::Invalid(_)
            ) {
                l.failures.record_failure(now);
            }
            Reply {
                ok: false,
                message: e.to_string(),
            }
        }
    }
}
