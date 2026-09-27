use std::time::Duration;

/// Daemon errors. Their messages are shown to users (CLI, prompter), so
/// they say what happened and, where there is one, what to do.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] aleph_core::Error),

    #[error(transparent)]
    Unlock(#[from] aleph_unlock::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Environment(&'static str),

    #[error("another alephd already owns this vault")]
    AlreadyRunning,

    #[error("no vault yet; run `aleph setup`")]
    NoVault,

    #[error("a vault already exists")]
    VaultExists,

    #[error("the vault is locked")]
    Locked,

    #[error("wrong password")]
    WrongPassword,

    #[error(
        "the TPM keyslot '{0}' no longer accepts your password (was it changed?); it is marked stale: re-enroll it with `aleph keyslot add tpm`"
    )]
    Stale(String),

    #[error("too many wrong passwords; retry in {} s", .retry_after.as_secs())]
    TooManyAttempts { retry_after: Duration },

    #[error(
        "cannot check passwords: /etc/pam.d/aleph-check is missing (`aleph setup` installs it)"
    )]
    PasswordCheckUnavailable,

    #[error("password check failed: {0}")]
    PasswordCheck(String),

    #[error("no enrolled method could unlock the vault{}", .0.as_deref().map(|m| format!(": {m}")).unwrap_or_default())]
    NoMethodWorked(Option<String>),

    #[error("cancelled")]
    Cancelled,

    #[error("the prompter failed: {0}")]
    Prompt(String),

    #[error("no prompter is available (no graphical session?); run `aleph unlock` in a terminal")]
    NoPrompter,

    #[error(
        "the vault file was {0}; writes are refused until you confirm it (`aleph restore --accept-rollback`)"
    )]
    Untrusted(&'static str),

    #[error("no such keyslot {0}")]
    NoSuchKeyslot(uuid::Uuid),

    #[error("the recovery slot cannot be removed")]
    RecoverySlotRequired,

    #[error("that would leave only the recovery key; add another unlock method first")]
    LastMethod,

    #[error("no such item or collection")]
    NotFound,

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("invalid request: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;
