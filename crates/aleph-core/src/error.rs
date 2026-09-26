use uuid::Uuid;

/// Everything that can go wrong opening, unlocking, or writing a vault.
///
/// Variants deliberately do not distinguish "wrong key" from "tampered
/// ciphertext": an AEAD failure is reported the same way in both cases.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not an aleph vault (bad magic)")]
    BadMagic,

    #[error("vault format version {0} is not supported")]
    UnsupportedVersion(u32),

    #[error("malformed vault: {0}")]
    Malformed(String),

    #[error("no keyslot with id {0}")]
    NoSuchKeyslot(Uuid),

    #[error("keyslot {0} is not a password-type (Argon2id) slot")]
    WrongSlotType(Uuid),

    #[error("keyslot could not be unlocked (wrong secret or tampered slot)")]
    UnwrapFailed,

    #[error("vault header failed authentication")]
    HeaderTampered,

    #[error("vault body failed authentication")]
    BodyTampered,

    #[error("refusing to remove the last keyslot")]
    LastKeyslot,

    #[error("master key rotation needs a KEK for keyslot {0}")]
    MissingKek(Uuid),

    #[error("the KEK supplied for keyslot {0} does not unlock it")]
    WrongKek(Uuid),

    #[error("invalid recovery key: {0}")]
    InvalidRecoveryKey(&'static str),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("system randomness unavailable")]
    Random,
}

pub type Result<T> = std::result::Result<T, Error>;
