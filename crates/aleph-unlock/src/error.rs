/// Errors from producing a KEK with a hardware unlock method.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] aleph_core::Error),

    #[error("cannot reach aleph-tpmd ({0}); is aleph-tpmd.socket enabled?")]
    TpmUnavailable(String),

    #[error("the TPM rejected the password")]
    TpmAuthFailed,

    #[error("the TPM is in dictionary-attack lockout; wait and retry")]
    TpmLockout,

    #[error("too many failed TPM attempts; retry in {} s", retry_after.as_secs())]
    TpmRateLimited { retry_after: std::time::Duration },

    /// The helper stayed busy (another request from this user, or its
    /// connection limit) through the client's retries.
    #[error("the TPM helper is busy; try again")]
    TpmBusy,

    /// The TPM's shared failure budget is spent (aleph keeps the rest for
    /// disk unlock), or the TPM allows too few failures for aleph to use.
    /// Not a reason to mark the slot stale.
    #[error("the TPM is not accepting password attempts now; try later or use another method")]
    TpmExhausted {
        /// `None`: waiting will not help (this TPM allows too few failures).
        retry_after: Option<std::time::Duration>,
    },

    #[error("aleph-tpmd serves login users only")]
    TpmNotPermitted,

    #[error("this TPM slot belongs to another user")]
    TpmWrongUser,

    #[error("this TPM slot was sealed on a different TPM (or its parent key changed)")]
    TpmParentMismatch,

    #[error("the TPM has no usable parent key (ownerAuth set, no persistent SRK)")]
    TpmNoParent,

    #[error("TPM slot is malformed: {0}")]
    TpmSlotMalformed(String),

    #[error("a password is required")]
    SecretRequired,

    #[error("TPM error: {0}")]
    Tpm(String),

    #[error("no FIDO2 security key is connected")]
    Fido2NoDevice,

    #[error("more than one FIDO2 key is connected; leave only the one to enroll")]
    Fido2MultipleDevices,

    #[error("this FIDO2 key does not support the hmac-secret extension")]
    Fido2Unsupported,

    #[error(
        "this FIDO2 key has neither a PIN nor built-in verification; set a PIN (fido2-token -S) or enroll touch-only"
    )]
    Fido2PinNotSet,

    #[error("FIDO2 built-in verification (fingerprint) failed")]
    Fido2UvInvalid,

    #[error("the FIDO2 operation was declined on the key")]
    Fido2Denied,

    #[error(
        "this FIDO2 key returns the same secret with and without its PIN/UV (a CTAP 2.0 key), so a PIN would not protect the slot; use a CTAP 2.1 key or enroll touch-only"
    )]
    Fido2NoUvSeparation,

    #[error("FIDO2 PIN is required")]
    Fido2PinRequired,

    #[error("FIDO2 PIN was rejected")]
    Fido2PinInvalid,

    #[error("FIDO2 key is PIN-blocked; reset it or use another method")]
    Fido2PinBlocked,

    #[error("no connected FIDO2 key holds this credential")]
    Fido2NoCredential,

    #[error("FIDO2 operation timed out waiting for touch")]
    Fido2Timeout,

    #[error("FIDO2 error: {0}")]
    Fido2(String),
}

pub type Result<T> = std::result::Result<T, Error>;
