//! `aleph-tpmd` entry point.
//!
//! Normally socket-activated by systemd (`aleph-tpmd.socket`), receiving
//! the listening socket as fd 3 (`LISTEN_FDS=1`, `LISTEN_PID` = our pid).
//! For development: `aleph-tpmd --socket <path>` binds its own socket.
//! The TPM is chosen by `ALEPH_TCTI`/`TPM2TOOLS_TCTI`, default
//! `device:/dev/tpmrm0`.

use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::process::ExitCode;
use std::sync::Arc;

use aleph_tpmd::server::Policy;
use aleph_tpmd::{Helper, Tpm};

const SD_LISTEN_FDS_START: i32 = 3;

fn listener() -> std::io::Result<UnixListener> {
    let mut args = std::env::args().skip(1);
    if let (Some(flag), Some(path)) = (args.next(), args.next())
        && flag == "--socket"
    {
        let _ = std::fs::remove_file(&path);
        return UnixListener::bind(path);
    }
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        == Some(std::process::id());
    let fds = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|n| n.parse::<i32>().ok());
    if pid_ok && fds == Some(1) {
        // SAFETY: systemd passed exactly one listening socket at fd 3, and
        // nothing else in this process owns it.
        return Ok(unsafe { UnixListener::from_raw_fd(SD_LISTEN_FDS_START) });
    }
    Err(std::io::Error::other(
        "not socket-activated; run under aleph-tpmd.socket or pass --socket <path>",
    ))
}

fn main() -> ExitCode {
    // No core dumps and no ptrace by same-uid processes: this process
    // holds KEKs in memory. (The unit also sets LimitCORE=0.)
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) has no memory-safety preconditions.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    let listener = match listener() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("aleph-tpmd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let tpm = match Tpm::open_default() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("aleph-tpmd: {e}");
            return ExitCode::FAILURE;
        }
    };
    aleph_tpmd::server::serve(&listener, Arc::new(Helper::new(tpm, Policy::system())))
}
