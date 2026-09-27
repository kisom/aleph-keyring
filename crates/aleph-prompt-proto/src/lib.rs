//! The protocol between `alephd` and a prompter (spec §6 "Prompter
//! orchestration"): one JSON object per line over a socketpair. Shared by
//! the daemon, the `aleph` CLI (its terminal prompter), and `aleph-gui`.
//!
//! A conversation starts with [`ToPrompter::Begin`] and ends with
//! [`ToPrompter::Done`]. Messages for which [`ToPrompter::needs_reply`] is
//! true expect exactly one [`FromPrompter`] answer; the prompter may send
//! `Cancel` at any time.

use serde::{Deserialize, Serialize};

/// Longest line either side accepts.
pub const MAX_LINE: usize = 16 * 1024;

/// A secret string in a message: zeroized on drop, never printed.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Unlock the vault.
    Unlock,
    /// Prove an enrolled method again before a sensitive operation.
    Reauth,
    /// Create the vault.
    Create,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// The login password (TPM or login-password slots).
    Password,
    /// A FIDO2 security key.
    Fido2,
}

/// Who asked, for display only (it can be spoofed).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub name: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToPrompter {
    Begin {
        purpose: Purpose,
        /// What is being done, e.g. "Unlock the keyring" or "Remove keyslot 'yubikey'".
        operation: String,
        caller: Option<Caller>,
    },
    /// Choose one of `methods` (reply `Password` or `Fido2`).
    Ask {
        methods: Vec<Method>,
        error: Option<String>,
        /// Seconds until trying again can succeed, when known.
        retry_after: Option<u64>,
    },
    /// The key `key` needs its PIN (reply `Pin`).
    Fido2Pin {
        key: String,
        error: Option<String>,
    },
    /// Waiting for a FIDO2 key to be plugged in.
    InsertKey {
        key: String,
    },
    /// Touch the key `key` now.
    Touch {
        key: String,
    },
    /// Reply `Confirm`.
    Confirm {
        text: String,
    },
    /// Show the new recovery key once; reply `RecoveryCheck` with the
    /// groups at the 1-based positions in `check`.
    ShowRecoveryKey {
        key: Secret,
        check: [usize; 2],
        error: Option<String>,
    },
    Done {
        ok: bool,
        message: Option<String>,
    },
}

impl ToPrompter {
    pub fn needs_reply(&self) -> bool {
        matches!(
            self,
            Self::Ask { .. }
                | Self::Fido2Pin { .. }
                | Self::Confirm { .. }
                | Self::ShowRecoveryKey { .. }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FromPrompter {
    Password { password: Secret },
    Fido2 {},
    Pin { pin: Secret },
    Confirm { yes: bool },
    RecoveryCheck { groups: [Secret; 2] },
    Cancel {},
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_and_reject_unknown_fields() {
        let msgs = [
            ToPrompter::Ask {
                methods: vec![Method::Password, Method::Fido2],
                error: Some("wrong password".into()),
                retry_after: Some(30),
            },
            ToPrompter::ShowRecoveryKey {
                key: Secret::new("ABCD-EFGH"),
                check: [2, 9],
                error: None,
            },
        ];
        for m in msgs {
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<ToPrompter>(&json).unwrap(), m);
        }
        assert!(serde_json::from_str::<FromPrompter>(r#"{"type":"cancel","x":1}"#).is_err());
        let p: FromPrompter =
            serde_json::from_str(r#"{"type":"password","password":"hunter2"}"#).unwrap();
        assert!(!format!("{p:?}").contains("hunter2"));
    }
}
