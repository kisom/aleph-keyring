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
        "the TPM keyslot '{0}' no longer accepts your login password (was it changed?) and is marked stale; unlock again and give your previous password when asked, to update it"
    )]
    Stale(String),

    #[error(
        "your login password no longer opens the TPM keyslot (was it changed without aleph?); your previous password can update it"
    )]
    PasswordChanged,

    #[error("too many wrong passwords; retry in {} s", .retry_after.as_secs())]
    TooManyAttempts { retry_after: Duration },

    #[error(
        "cannot check passwords: /etc/pam.d/aleph-check is missing (install it from aleph's packaging/pam/aleph-check)"
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

    #[error("timed out waiting for a security key")]
    KeyTimeout,

    #[error("another operation is in progress; finish or cancel it first")]
    Busy,

    #[error(
        "the recovery key just shown was not installed ({0}); discard it: your previous recovery key still works"
    )]
    RecoveryNotInstalled(Box<Error>),

    #[error("no prompter is available (no graphical session?); run `aleph unlock` in a terminal")]
    NoPrompter,

    #[error(
        "the vault file was {0}; it stays read-only until the change is accepted, which this version cannot do yet (if you have the newer vault file, put it back)"
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Stale-slot advice is read while the vault is locked, so it must not
    /// send the user to commands that need it unlocked (re-enrolling) or
    /// that only repeat the failure (`keyslot retry`); what works then is
    /// the previous password, which updates the slot (§5).
    #[test]
    fn stale_advice_works_while_locked() {
        for advice in [
            Error::Stale("tpm".into()).to_string(),
            Error::PasswordChanged.to_string(),
        ] {
            assert!(advice.contains("previous password"), "{advice}");
            assert!(!advice.contains("re-enroll it with"), "{advice}");
            assert!(!advice.contains("keyslot retry"), "{advice}");
        }
    }

    /// Final-review minor 11: advice names only what exists now (`aleph
    /// restore` does not yet, and `aleph setup` only creates the vault).
    #[test]
    fn advice_names_only_what_exists() {
        let rollback = Error::Untrusted("rolled back to an older version").to_string();
        assert!(!rollback.contains("aleph restore"), "{rollback}");
        let pam = Error::PasswordCheckUnavailable.to_string();
        assert!(!pam.contains("aleph setup"), "{pam}");
        assert!(pam.contains("packaging/pam/aleph-check"), "{pam}");
    }
}
