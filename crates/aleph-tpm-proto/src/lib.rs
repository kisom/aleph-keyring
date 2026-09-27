//! The `aleph-tpmd` wire protocol (spec §5, "The helper").
//!
//! One request and one response per connection turn, each a frame: a
//! big-endian `u32` length followed by exactly that many bytes of CBOR.
//! Frames are capped at [`MAX_FRAME`] and decoded strictly (one item, no
//! trailing bytes), because the helper reads frames from any local user.
//!
//! The helper learns the caller's uid from the socket (`SO_PEERCRED`),
//! never from the message.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Largest accepted frame. Real requests are well under 4 KiB.
pub const MAX_FRAME: usize = 64 * 1024;

/// A secret carried in a message (a login password, or a KEK): zeroized
/// on drop, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

/// The TPM-side parameters of a sealed KEK, as stored in a vault keyslot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedObject {
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub auth_salt: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub srk_name: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    /// Generate a fresh KEK and seal it to the caller's uid and `secret`.
    Seal { secret: Secret },
    /// Unseal a KEK previously sealed for the caller.
    Unseal {
        object: SealedObject,
        secret: Secret,
    },
    /// Report TPM and helper state. (An empty struct variant rather than a
    /// unit variant: serde's internally tagged unit variants ignore extra
    /// fields even with `deny_unknown_fields`.)
    Status {},
}

/// Which parent key sealed objects are created under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Parent {
    /// aleph's own primary (ECC P-256, AES-256-CFB), re-created per use.
    AlephPrimary,
    /// The persistent TCG SRK at 0x81000001 (AES-128-CFB), used when
    /// `ownerAuth` is set.
    PersistentSrk,
    /// Neither is usable: TPM enrollment is refused.
    Unavailable,
}

/// `Status` reply: what setup shows the user (spec §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub parent: Parent,
    pub owner_auth_set: bool,
    pub lockout_auth_set: bool,
    pub in_lockout: bool,
    /// Failed authorizations before lockout (TPM2_PT_MAX_AUTH_FAIL).
    pub max_tries: u32,
    /// Seconds for one failure to be forgotten (TPM2_PT_LOCKOUT_INTERVAL).
    pub recovery_time: u32,
    /// Seconds before lockout auth may be retried (TPM2_PT_LOCKOUT_RECOVERY).
    pub lockout_recovery: u32,
    /// Current failure count (TPM2_PT_LOCKOUT_COUNTER).
    pub failed_tries: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "kind", content = "detail", rename_all = "kebab-case")]
pub enum Failure {
    #[error("the TPM rejected the password")]
    AuthFailed,
    #[error("the TPM is in dictionary-attack lockout")]
    Lockout,
    #[error("too many failed attempts from this user; wait for the TPM's recovery time")]
    RateLimited,
    /// Transient: this user already has a request in progress, or the
    /// helper is at its connection limit. Retry shortly.
    #[error("the TPM helper is busy; retry shortly")]
    Busy,
    /// The TPM's shared failure budget is spent (the rest is kept for
    /// disk unlock), or the TPM allows too few failures for aleph to use.
    /// Lasts until the TPM forgets failures, one per recovery time.
    #[error("the TPM is not accepting password attempts now; try later or use another method")]
    Exhausted,
    #[error("this user may not use the TPM helper (not a login uid)")]
    NotPermitted,
    #[error("this sealed object belongs to another user")]
    WrongUser,
    #[error("the TPM's parent key does not match this slot (different TPM or tampering)")]
    ParentMismatch,
    #[error("no usable parent key (ownerAuth set and no persistent SRK)")]
    NoParent,
    #[error("malformed request: {0}")]
    Malformed(String),
    #[error("TPM error: {0}")]
    Tpm(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    Sealed { object: SealedObject, kek: Secret },
    Unsealed { kek: Secret },
    Status(Status),
    Failed(Failure),
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    #[error("malformed frame: {0}")]
    Malformed(String),
}

/// Write one message as a frame.
pub fn write_frame<T: Serialize>(w: &mut impl Write, msg: &T) -> Result<(), FrameError> {
    let mut body = zeroize::Zeroizing::new(Vec::new());
    ciborium::into_writer(msg, &mut *body).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Read one frame and decode it strictly. The length is checked before
/// anything is allocated.
pub fn read_frame<T: serde::de::DeserializeOwned>(r: &mut impl Read) -> Result<T, FrameError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = zeroize::Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut body)?;
    let mut cursor = std::io::Cursor::new(body.as_slice());
    let msg =
        ciborium::from_reader(&mut cursor).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if cursor.position() != len as u64 {
        return Err(FrameError::Malformed("trailing data in frame".into()));
    }
    Ok(msg)
}
#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> SealedObject {
        SealedObject {
            public: vec![1, 2],
            private: vec![3],
            auth_salt: vec![4; 16],
            srk_name: vec![5; 34],
        }
    }

    fn round_trip<T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
        msg: T,
    ) {
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).unwrap();
        assert_eq!(read_frame::<T>(&mut buf.as_slice()).unwrap(), msg);
    }

    #[test]
    fn every_message_round_trips() {
        round_trip(Request::Seal {
            secret: Secret(b"pw".to_vec()),
        });
        round_trip(Request::Unseal {
            object: object(),
            secret: Secret(b"pw".to_vec()),
        });
        round_trip(Request::Status {});
        round_trip(Response::Sealed {
            object: object(),
            kek: Secret(vec![9; 32]),
        });
        round_trip(Response::Unsealed {
            kek: Secret(vec![9; 32]),
        });
        round_trip(Response::Status(Status {
            parent: Parent::AlephPrimary,
            owner_auth_set: false,
            lockout_auth_set: false,
            in_lockout: false,
            max_tries: 32,
            recovery_time: 600,
            lockout_recovery: 86400,
            failed_tries: 0,
        }));
        for f in [
            Failure::AuthFailed,
            Failure::Lockout,
            Failure::RateLimited,
            Failure::Busy,
            Failure::Exhausted,
            Failure::NotPermitted,
            Failure::WrongUser,
            Failure::ParentMismatch,
            Failure::NoParent,
            Failure::Malformed("x".into()),
            Failure::Tpm("y".into()),
        ] {
            round_trip(Response::Failed(f));
        }
    }

    #[test]
    fn oversized_length_is_rejected_before_allocating() {
        let mut buf = (u32::MAX).to_be_bytes().to_vec();
        buf.extend([0u8; 8]);
        assert!(matches!(
            read_frame::<Request>(&mut buf.as_slice()),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn trailing_bytes_and_truncation_are_rejected() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Request::Status {}).unwrap();
        let mut padded = buf.clone();
        padded[3] += 1; // claim one more byte
        padded.push(0);
        assert!(matches!(
            read_frame::<Request>(&mut padded.as_slice()),
            Err(FrameError::Malformed(_))
        ));
        let truncated = &buf[..buf.len() - 1];
        assert!(matches!(
            read_frame::<Request>(&mut &truncated[..]),
            Err(FrameError::Io(_))
        ));
    }

    #[test]
    fn unknown_fields_and_ops_are_rejected() {
        use ciborium::Value;
        let encode = |v: &Value| {
            let mut body = Vec::new();
            ciborium::into_writer(v, &mut body).unwrap();
            let mut buf = (body.len() as u32).to_be_bytes().to_vec();
            buf.extend(body);
            buf
        };
        let extra = Value::Map(vec![
            (Value::Text("op".into()), Value::Text("status".into())),
            (Value::Text("uid".into()), Value::Integer(0.into())),
        ]);
        assert!(read_frame::<Request>(&mut encode(&extra).as_slice()).is_err());
        let unknown = Value::Map(vec![(
            Value::Text("op".into()),
            Value::Text("clear".into()),
        )]);
        assert!(read_frame::<Request>(&mut encode(&unknown).as_slice()).is_err());
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let r = Request::Seal {
            secret: Secret(b"hunter2".to_vec()),
        };
        assert!(!format!("{r:?}").contains("hunter2"));
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_frames_never_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
            let _ = read_frame::<Request>(&mut bytes.as_slice());
            let _ = read_frame::<Response>(&mut bytes.as_slice());
        }
    }
}
