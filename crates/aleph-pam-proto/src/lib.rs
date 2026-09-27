//! The protocol between `pam_aleph` and `alephd`'s `pam.sock` (spec §6
//! "PAM integration"): one request and one reply per connection.
//!
//! Each message is a frame: a big-endian `u32` payload length, then the
//! payload. A payload is a tag byte followed by fields, each a big-endian
//! `u16` length and that many bytes. Decoding is strict: a short, long, or
//! unknown payload is an error.
//!
//! Deliberately tiny, with no dependency but `zeroize`: the PAM module
//! runs inside other programs (the display manager, the screen locker,
//! `passwd`) and must stay small. [`reply_ok`] reads a reply without
//! allocating, for the module's forked child.

use zeroize::Zeroizing;

/// The longest payload either side accepts (passwords are far smaller).
pub const MAX_FRAME: usize = 4096;

const UNLOCK: u8 = 1;
const CHANGE_PASSWORD: u8 = 2;
const REPLY_OK: u8 = 0x10;
const REPLY_FAILED: u8 = 0x11;

/// A password in a message: zeroized on drop, never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Password(Zeroizing<Vec<u8>>);

impl Password {
    pub fn new(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// The login stack accepted this password: a login, or unlocking the
    /// screen.
    Unlock { password: Password },
    /// `passwd` changed the login password from `old` to `new`.
    ChangePassword { old: Password, new: Password },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub ok: bool,
    /// What happened, for the module's log (never a secret).
    pub message: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    TooLong,
    Truncated,
    Trailing,
    UnknownTag(u8),
    NotUtf8,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong => write!(f, "message longer than {MAX_FRAME} bytes"),
            Self::Truncated => f.write_str("message truncated"),
            Self::Trailing => f.write_str("trailing bytes after the message"),
            Self::UnknownTag(t) => write!(f, "unknown message type {t}"),
            Self::NotUtf8 => f.write_str("reply message is not UTF-8"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Frame `payload`: its length, then the payload itself.
fn frame(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() > MAX_FRAME {
        return Err(Error::TooLong);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(4 + payload.len()));
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::TooLong)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Reads the fields of a payload, strictly.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn next(&mut self) -> Result<&'a [u8]> {
        let [a, b, rest @ ..] = self.0 else {
            return Err(Error::Truncated);
        };
        let len = usize::from(u16::from_be_bytes([*a, *b]));
        if rest.len() < len {
            return Err(Error::Truncated);
        }
        let (value, rest) = rest.split_at(len);
        self.0 = rest;
        Ok(value)
    }

    fn end(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Trailing)
        }
    }
}

/// The payload length a frame header announces, if acceptable.
pub fn payload_len(header: [u8; 4]) -> Result<usize> {
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(Error::TooLong);
    }
    Ok(len)
}

impl Request {
    /// The whole frame, ready to write.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        // Sized up front: growing would free copies of the password.
        let size = match self {
            Self::Unlock { password } => 1 + 2 + password.expose().len(),
            Self::ChangePassword { old, new } => 1 + 4 + old.expose().len() + new.expose().len(),
        };
        let mut payload = Zeroizing::new(Vec::with_capacity(1 + 2 + size));
        match self {
            Self::Unlock { password } => {
                payload.push(UNLOCK);
                field(&mut payload, password.expose())?;
            }
            Self::ChangePassword { old, new } => {
                payload.push(CHANGE_PASSWORD);
                field(&mut payload, old.expose())?;
                field(&mut payload, new.expose())?;
            }
        }
        frame(&payload)
    }

    /// A payload (the bytes after the frame header).
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let Some((&tag, rest)) = payload.split_first() else {
            return Err(Error::Truncated);
        };
        let mut fields = Fields(rest);
        let request = match tag {
            UNLOCK => Self::Unlock {
                password: Password::new(fields.next()?),
            },
            CHANGE_PASSWORD => Self::ChangePassword {
                old: Password::new(fields.next()?),
                new: Password::new(fields.next()?),
            },
            t => return Err(Error::UnknownTag(t)),
        };
        fields.end()?;
        Ok(request)
    }
}

impl Reply {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut payload = vec![if self.ok { REPLY_OK } else { REPLY_FAILED }];
        field(&mut payload, self.message.as_bytes())?;
        frame(&payload)
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let Some((&tag, rest)) = payload.split_first() else {
            return Err(Error::Truncated);
        };
        let ok = match tag {
            REPLY_OK => true,
            REPLY_FAILED => false,
            t => return Err(Error::UnknownTag(t)),
        };
        let mut fields = Fields(rest);
        let message = std::str::from_utf8(fields.next()?)
            .map_err(|_| Error::NotUtf8)?
            .to_string();
        fields.end()?;
        Ok(Self { ok, message })
    }
}

/// Whether a whole reply frame says "ok", without allocating (the PAM
/// module's forked child may call only async-signal-safe code). `None` if
/// the frame is not a complete reply.
pub fn reply_ok(frame: &[u8]) -> Option<bool> {
    let (header, payload) = frame.split_first_chunk::<4>()?;
    let len = payload_len(*header).ok()?;
    if payload.len() != len {
        return None;
    }
    match *payload.first()? {
        REPLY_OK => Some(true),
        REPLY_FAILED => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(frame: &[u8]) -> &[u8] {
        let len = payload_len(frame[..4].try_into().unwrap()).unwrap();
        assert_eq!(frame.len(), 4 + len);
        &frame[4..]
    }

    #[test]
    fn requests_and_replies_round_trip() {
        for r in [
            Request::Unlock {
                password: Password::new(b"hunter2"),
            },
            Request::ChangePassword {
                old: Password::new(b"old"),
                new: Password::new("n\u{e9}w".as_bytes()),
            },
        ] {
            let frame = r.encode().unwrap();
            assert_eq!(Request::decode(payload(&frame)).unwrap(), r);
        }
        for r in [
            Reply {
                ok: true,
                message: "unlocked".into(),
            },
            Reply {
                ok: false,
                message: "the vault is locked".into(),
            },
        ] {
            let frame = r.encode().unwrap();
            assert_eq!(reply_ok(&frame), Some(r.ok));
            assert_eq!(Reply::decode(payload(&frame)).unwrap(), r);
        }
    }

    #[test]
    fn malformed_payloads_are_refused() {
        assert_eq!(Request::decode(&[]), Err(Error::Truncated));
        assert_eq!(Request::decode(&[9]), Err(Error::UnknownTag(9)));
        assert_eq!(
            Request::decode(&[UNLOCK, 0, 5, b'a']),
            Err(Error::Truncated)
        );
        assert_eq!(
            Request::decode(&[UNLOCK, 0, 1, b'a', 0]),
            Err(Error::Trailing)
        );
        assert_eq!(Reply::decode(&[REPLY_OK, 0, 1, 0xff]), Err(Error::NotUtf8));
        assert_eq!(
            payload_len((MAX_FRAME as u32 + 1).to_be_bytes()),
            Err(Error::TooLong)
        );
        let long = Request::Unlock {
            password: Password::new(&[b'x'; MAX_FRAME]),
        };
        assert_eq!(long.encode().unwrap_err(), Error::TooLong);
        assert_eq!(reply_ok(&[0, 0, 0, 2, REPLY_OK]), None);
    }

    #[test]
    fn passwords_are_never_printed() {
        let r = Request::ChangePassword {
            old: Password::new(b"hunter2"),
            new: Password::new(b"hunter3"),
        };
        let shown = format!("{r:?}");
        assert!(!shown.contains("hunter"), "{shown}");
    }
}
