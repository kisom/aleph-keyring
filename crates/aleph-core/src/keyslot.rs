//! Keyslots: one wrapped copy of the master key per unlock method.
//!
//! `aleph-core` only stores slot parameters. Turning them into a `Kek`
//! (talking to the TPM, a FIDO2 key, or running Argon2id on user input)
//! is `aleph-unlock`'s job, except for the Argon2 slots, whose KEK
//! derivation lives in `kdf` so recovery works without any hardware.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::NONCE_LEN;
use crate::kdf::{Argon2Params, SALT_LEN};
use crate::key::WrappedKey;

/// How a TPM slot's sealed object is authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TpmAuth {
    None,
    Pin,
    LoginPassword,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmSlot {
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    pub auth: TpmAuth,
    /// PCR indices the seal is bound to; empty means no PCR policy.
    pub pcrs: Vec<u8>,
    /// Hash bank for `pcrs`, e.g. `"sha256"`. `None` when `pcrs` is empty.
    pub pcr_bank: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fido2Slot {
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    #[serde(with = "serde_bytes")]
    pub salt: [u8; 32],
    pub uv_required: bool,
    pub pin_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Slot {
    #[serde(with = "serde_bytes")]
    pub salt: [u8; SALT_LEN],
    pub params: Argon2Params,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "slot_type", rename_all = "kebab-case")]
pub enum SlotKind {
    Tpm(TpmSlot),
    Fido2(Fido2Slot),
    RecoveryKey(Argon2Slot),
    Passphrase(Argon2Slot),
    LoginPassword(Argon2Slot),
}

/// The three keyslot types whose KEK comes from Argon2id over a secret
/// the user types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Argon2Kind {
    RecoveryKey,
    Passphrase,
    LoginPassword,
}

impl SlotKind {
    pub fn argon2(kind: Argon2Kind, slot: Argon2Slot) -> Self {
        match kind {
            Argon2Kind::RecoveryKey => SlotKind::RecoveryKey(slot),
            Argon2Kind::Passphrase => SlotKind::Passphrase(slot),
            Argon2Kind::LoginPassword => SlotKind::LoginPassword(slot),
        }
    }

    /// The Argon2 parameters if this is a password-type slot.
    pub fn as_argon2(&self) -> Option<&Argon2Slot> {
        match self {
            SlotKind::RecoveryKey(s) | SlotKind::Passphrase(s) | SlotKind::LoginPassword(s) => {
                Some(s)
            }
            SlotKind::Tpm(_) | SlotKind::Fido2(_) => None,
        }
    }

    /// Stable name, bound into the wrapped key's AAD.
    pub fn type_name(&self) -> &'static str {
        match self {
            SlotKind::Tpm(_) => "tpm",
            SlotKind::Fido2(_) => "fido2",
            SlotKind::RecoveryKey(_) => "recovery-key",
            SlotKind::Passphrase(_) => "passphrase",
            SlotKind::LoginPassword(_) => "login-password",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyslot {
    pub id: Uuid,
    pub label: String,
    pub created: u64,
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "serde_bytes")]
    pub wrapped_mk: Vec<u8>,
    pub kind: SlotKind,
}

impl Keyslot {
    pub fn wrapped(&self) -> WrappedKey {
        WrappedKey {
            nonce: self.nonce,
            ciphertext: self.wrapped_mk.clone(),
        }
    }

    /// AAD binding a wrapped master key to this vault, this slot id, and
    /// this slot type, so it cannot be transplanted elsewhere.
    pub fn aad(vault_id: Uuid, slot_id: Uuid, kind: &SlotKind) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + 16);
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(slot_id.as_bytes());
        aad.extend_from_slice(kind.type_name().as_bytes());
        aad
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_differs_by_vault_slot_and_type() {
        let (v, s) = (Uuid::new_v4(), Uuid::new_v4());
        let argon = Argon2Slot {
            salt: [0; SALT_LEN],
            params: Argon2Params::INSECURE_TEST,
        };
        let a = Keyslot::aad(v, s, &SlotKind::RecoveryKey(argon.clone()));
        assert_ne!(
            a,
            Keyslot::aad(Uuid::new_v4(), s, &SlotKind::RecoveryKey(argon.clone()))
        );
        assert_ne!(
            a,
            Keyslot::aad(v, Uuid::new_v4(), &SlotKind::RecoveryKey(argon.clone()))
        );
        assert_ne!(a, Keyslot::aad(v, s, &SlotKind::Passphrase(argon)));
    }

    #[test]
    fn slot_kind_serializes_with_slot_type_tag() {
        let kind = SlotKind::RecoveryKey(Argon2Slot {
            salt: [0; SALT_LEN],
            params: Argon2Params::INSECURE_TEST,
        });
        let mut buf = Vec::new();
        ciborium::into_writer(&kind, &mut buf).unwrap();
        let value: ciborium::Value = ciborium::from_reader(buf.as_slice()).unwrap();
        let map = value.as_map().unwrap();
        let tag = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("slot_type"))
            .unwrap();
        assert_eq!(tag.1.as_text(), Some("recovery-key"));
    }
}
