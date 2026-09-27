//! TPM keyslots through `aleph-tpmd` (spec §5). This side never touches
//! the TPM: it sends the login password to the helper over its socket and
//! gets a KEK back. The helper binds every object to our uid, which it
//! reads from the socket.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use aleph_core::{Kek, TpmSlot};
use aleph_tpm_proto::{
    Failure, Request, Response, SealedObject, Secret, Status, read_frame, write_frame,
};

use crate::error::{Error, Result};

/// Where `aleph-tpmd.socket` listens.
pub const DEFAULT_SOCKET: &str = "/run/aleph/tpm.sock";
/// How long to wait for the helper (a real TPM can take a second or two).
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// How long to keep retrying while the helper answers `Busy` (it holds a
/// uid's slot for at most its 2 s request deadline plus the TPM work).
pub const BUSY_RETRY: Duration = Duration::from_secs(5);
const BUSY_PAUSE: Duration = Duration::from_millis(50);

pub struct TpmClient {
    socket: PathBuf,
}

impl TpmClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// `ALEPH_TPM_SOCKET`, else [`DEFAULT_SOCKET`].
    pub fn from_env() -> Self {
        Self::new(std::env::var("ALEPH_TPM_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.into()))
    }

    /// Seal a fresh KEK under the login password. Returns the KEK and the
    /// slot parameters to store in the vault.
    pub fn seal(&self, password: &[u8]) -> Result<(Kek, TpmSlot)> {
        if password.is_empty() {
            return Err(Error::SecretRequired);
        }
        match self.call(&Request::Seal {
            secret: Secret(password.to_vec()),
        })? {
            Response::Sealed { object, kek } => Ok((to_kek(&kek)?, to_slot(object)?)),
            other => Err(unexpected(other)),
        }
    }

    /// Unseal a slot's KEK with the login password.
    pub fn unseal(&self, slot: &TpmSlot, password: &[u8]) -> Result<Kek> {
        if password.is_empty() {
            return Err(Error::SecretRequired);
        }
        let object = SealedObject {
            public: slot.public.clone(),
            private: slot.private.clone(),
            auth_salt: slot.auth_salt.to_vec(),
            srk_name: slot.srk_name.clone(),
        };
        match self.call(&Request::Unseal {
            object,
            secret: Secret(password.to_vec()),
        })? {
            Response::Unsealed { kek } => to_kek(&kek),
            other => Err(unexpected(other)),
        }
    }

    /// TPM state for `aleph setup`.
    pub fn status(&self) -> Result<Status> {
        match self.call(&Request::Status {})? {
            Response::Status(s) => Ok(s),
            other => Err(unexpected(other)),
        }
    }

    /// One request, retried while the helper says `Busy`.
    fn call(&self, request: &Request) -> Result<Response> {
        let deadline = std::time::Instant::now() + BUSY_RETRY;
        loop {
            let response = self.call_once(request)?;
            if response != Response::Failed(Failure::Busy) || std::time::Instant::now() >= deadline
            {
                return Ok(response);
            }
            std::thread::sleep(BUSY_PAUSE);
        }
    }

    fn call_once(&self, request: &Request) -> Result<Response> {
        let unavailable = |e: &dyn std::fmt::Display| Error::TpmUnavailable(e.to_string());
        let stream = UnixStream::connect(&self.socket).map_err(|e| unavailable(&e))?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .map_err(|e| unavailable(&e))?;
        stream
            .set_write_timeout(Some(TIMEOUT))
            .map_err(|e| unavailable(&e))?;
        exchange(stream, request)
    }
}

/// Send `request` and read the reply.
fn exchange(mut stream: UnixStream, request: &Request) -> Result<Response> {
    let unavailable = |e: &dyn std::fmt::Display| Error::TpmUnavailable(e.to_string());
    if let Err(e) = write_frame(&mut stream, request) {
        // The helper may refuse at once (Busy, NotPermitted) and close
        // before reading the request, so the write fails (EPIPE). Its reply
        // is already in our receive buffer: read that first.
        return read_frame(&mut stream).map_err(|_| unavailable(&e));
    }
    read_frame(&mut stream).map_err(|e| unavailable(&e))
}

fn to_kek(secret: &Secret) -> Result<Kek> {
    Ok(Kek::try_init(|buf| {
        if secret.0.len() != buf.len() {
            return Err(aleph_core::Error::UnwrapFailed);
        }
        buf.copy_from_slice(&secret.0);
        Ok(())
    })?)
}

fn to_slot(object: SealedObject) -> Result<TpmSlot> {
    let auth_salt = object
        .auth_salt
        .as_slice()
        .try_into()
        .map_err(|_| Error::TpmSlotMalformed("auth_salt must be 16 bytes".into()))?;
    Ok(TpmSlot {
        public: object.public,
        private: object.private,
        auth_salt,
        srk_name: object.srk_name,
    })
}

fn unexpected(response: Response) -> Error {
    match response {
        Response::Failed(f) => match f {
            Failure::AuthFailed => Error::TpmAuthFailed,
            Failure::Lockout => Error::TpmLockout,
            Failure::RateLimited { retry_after } => Error::TpmRateLimited {
                retry_after: Duration::from_secs(retry_after.into()),
            },
            Failure::Busy => Error::TpmBusy,
            Failure::Exhausted { retry_after } => Error::TpmExhausted {
                retry_after: retry_after.map(|s| Duration::from_secs(s.into())),
            },
            Failure::NotPermitted => Error::TpmNotPermitted,
            Failure::WrongUser => Error::TpmWrongUser,
            Failure::ParentMismatch => Error::TpmParentMismatch,
            Failure::NoParent => Error::TpmNoParent,
            Failure::Malformed(m) => Error::TpmSlotMalformed(m),
            Failure::Tpm(m) => Error::Tpm(m),
        },
        other => Error::Tpm(format!("unexpected reply from aleph-tpmd: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aleph_tpm_proto::Secret;

    /// A helper that refuses and closes before reading the request: our
    /// write fails, but its reply is still read (under load this read as
    /// "helper unreachable" instead of `Busy`, which the caller retries).
    #[test]
    fn a_refusal_sent_before_our_request_is_still_read() {
        let (ours, mut theirs) = UnixStream::pair().unwrap();
        write_frame(&mut theirs, &Response::Failed(Failure::Busy)).unwrap();
        drop(theirs);
        let request = Request::Seal {
            secret: Secret(b"pw".to_vec()),
        };
        assert_eq!(
            exchange(ours, &request).unwrap(),
            Response::Failed(Failure::Busy)
        );
    }
}
