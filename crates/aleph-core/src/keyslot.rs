//! Keyslots: one wrapped copy of the master key per unlock method.
//!
//! `aleph-core` stores slot parameters and does the wrapping. Producing a
//! hardware slot's KEK (TPM, FIDO2) is `aleph-unlock`'s job. The recovery
//! slot (X-Wing) and the login-password slot (Argon2id) are handled here,
//! so recovery works without any hardware.
//!
//! In the header each keyslot is stored as its own CBOR byte string. A slot
//! whose `slot_type` this build does not know is kept as those exact bytes
//! and re-emitted unchanged (spec §4, forward compatibility).

use ciborium::Value;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::NONCE_LEN;
use crate::error::{Error, Result};
use crate::kdf::{Argon2Params, SALT_LEN};
use crate::key::WrappedKey;

/// A 32-byte random KEK sealed by `aleph-tpmd`, bound to the caller's uid
/// and the login password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmSlot {
    #[serde(with = "serde_bytes")]
    pub public: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub private: Vec<u8>,
    /// Per-slot salt for the auth-value derivation.
    #[serde(with = "serde_bytes")]
    pub auth_salt: [u8; 16],
    /// Name of the parent key the object was sealed under; `aleph-tpmd`
    /// verifies it before salting a session with that key.
    #[serde(with = "serde_bytes")]
    pub srk_name: Vec<u8>,
}

/// A FIDO2 `hmac-secret` credential. The RP ID is the constant `"aleph"`
/// and deliberately not stored (it would be read from an unauthenticated
/// header before unlock).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fido2Slot {
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub salt: [u8; 32],
    pub uv_required: bool,
    pub pin_required: bool,
}

/// The recovery recipient: MK is wrapped under `HKDF(ss)`, where `ss` is
/// encapsulated to `xwing_pk`. Re-wrapping needs only the public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySlot {
    #[serde(with = "serde_bytes")]
    pub xwing_pk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub xwing_ct: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    Recovery(RecoverySlot),
    LoginPassword(Argon2Slot),
}

/// The `slot_type` strings this build understands.
pub const KNOWN_SLOT_TYPES: [&str; 4] = ["tpm", "fido2", "recovery", "login-password"];

impl SlotKind {
    /// Stable name, bound into the wrapped key's AAD.
    pub fn type_name(&self) -> &'static str {
        match self {
            SlotKind::Tpm(_) => "tpm",
            SlotKind::Fido2(_) => "fido2",
            SlotKind::Recovery(_) => "recovery",
            SlotKind::LoginPassword(_) => "login-password",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// A keyslot of a type this build does not understand, kept verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownSlot {
    /// The slot's exact encoded bytes, re-emitted unchanged on write.
    pub raw: Vec<u8>,
    /// Best-effort metadata for display; `None` if absent or malformed.
    pub id: Option<Uuid>,
    pub label: Option<String>,
    pub slot_type: String,
}

/// One entry of the header's keyslot list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotEntry {
    Known(Keyslot),
    Unknown(UnknownSlot),
}

impl SlotEntry {
    /// Decode one slot's bytes. A known `slot_type` must parse strictly
    /// (unknown fields are an error); an unknown one is preserved.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let malformed = |m: &str| Error::Malformed(format!("keyslot: {m}"));
        let mut cursor = std::io::Cursor::new(raw);
        let value: Value =
            ciborium::from_reader(&mut cursor).map_err(|e| malformed(&e.to_string()))?;
        if cursor.position() != raw.len() as u64 {
            return Err(malformed("trailing data"));
        }
        let map = value.as_map().ok_or_else(|| malformed("not a map"))?;
        let field = |name: &str| {
            map.iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .map(|(_, v)| v)
        };
        let slot_type = field("kind")
            .and_then(Value::as_map)
            .and_then(|kind| kind.iter().find(|(k, _)| k.as_text() == Some("slot_type")))
            .and_then(|(_, v)| v.as_text())
            .ok_or_else(|| malformed("missing kind.slot_type"))?
            .to_string();
        if KNOWN_SLOT_TYPES.contains(&slot_type.as_str()) {
            let slot: Keyslot = value
                .deserialized()
                .map_err(|e| malformed(&e.to_string()))?;
            return Ok(SlotEntry::Known(slot));
        }
        Ok(SlotEntry::Unknown(UnknownSlot {
            raw: raw.to_vec(),
            id: field("id")
                .and_then(Value::as_bytes)
                .and_then(|b| Uuid::from_slice(b).ok()),
            label: field("label").and_then(Value::as_text).map(str::to_string),
            slot_type,
        }))
    }

    /// Encode for the header: known slots freshly, unknown ones verbatim.
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            SlotEntry::Known(slot) => {
                let mut buf = Vec::new();
                ciborium::into_writer(slot, &mut buf)
                    .map_err(|e| Error::Malformed(e.to_string()))?;
                Ok(buf)
            }
            SlotEntry::Unknown(u) => Ok(u.raw.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_slot() -> Keyslot {
        Keyslot {
            id: Uuid::new_v4(),
            label: "recovery".into(),
            created: 1,
            nonce: [0; NONCE_LEN],
            wrapped_mk: vec![1, 2, 3],
            kind: SlotKind::Recovery(RecoverySlot {
                xwing_pk: vec![4; 8],
                xwing_ct: vec![5; 8],
            }),
        }
    }

    fn encode_value(v: &Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).unwrap();
        buf
    }

    #[test]
    fn aad_differs_by_vault_slot_and_type() {
        let (v, s) = (Uuid::new_v4(), Uuid::new_v4());
        let rec = recovery_slot().kind;
        let a = Keyslot::aad(v, s, &rec);
        assert_ne!(a, Keyslot::aad(Uuid::new_v4(), s, &rec));
        assert_ne!(a, Keyslot::aad(v, Uuid::new_v4(), &rec));
        let lp = SlotKind::LoginPassword(Argon2Slot {
            salt: [0; SALT_LEN],
            params: Argon2Params::INSECURE_TEST,
        });
        assert_ne!(a, Keyslot::aad(v, s, &lp));
    }

    #[test]
    fn known_slot_round_trips_and_is_tagged() {
        let slot = recovery_slot();
        let entry = SlotEntry::Known(slot.clone());
        let raw = entry.encode().unwrap();
        assert_eq!(SlotEntry::decode(&raw).unwrap(), entry);
        let value: Value = ciborium::from_reader(raw.as_slice()).unwrap();
        let kind = value
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("kind"))
            .unwrap();
        let tag = kind
            .1
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("slot_type"))
            .unwrap();
        assert_eq!(tag.1.as_text(), Some("recovery"));
    }

    #[test]
    fn unknown_slot_type_is_preserved_byte_for_byte() {
        let id = Uuid::new_v4();
        let v = Value::Map(vec![
            (
                Value::Text("id".into()),
                Value::Bytes(id.as_bytes().to_vec()),
            ),
            (Value::Text("label".into()), Value::Text("future".into())),
            (
                Value::Text("kind".into()),
                Value::Map(vec![
                    (
                        Value::Text("slot_type".into()),
                        Value::Text("quantum-dot".into()),
                    ),
                    (Value::Text("whatever".into()), Value::Integer(7.into())),
                ]),
            ),
        ]);
        let raw = encode_value(&v);
        let entry = SlotEntry::decode(&raw).unwrap();
        let SlotEntry::Unknown(u) = &entry else {
            panic!("expected unknown")
        };
        assert_eq!(u.slot_type, "quantum-dot");
        assert_eq!(u.id, Some(id));
        assert_eq!(u.label.as_deref(), Some("future"));
        assert_eq!(entry.encode().unwrap(), raw);
    }

    #[test]
    fn known_slot_type_with_unknown_field_is_rejected() {
        let slot = recovery_slot();
        let raw = SlotEntry::Known(slot).encode().unwrap();
        let mut v: Value = ciborium::from_reader(raw.as_slice()).unwrap();
        v.as_map_mut()
            .unwrap()
            .push((Value::Text("surprise".into()), Value::Bool(true)));
        assert!(matches!(
            SlotEntry::decode(&encode_value(&v)),
            Err(Error::Malformed(_))
        ));

        // Also inside `kind`, where the tag is stripped before the variant
        // struct sees the remaining fields.
        let mut v: Value = ciborium::from_reader(raw.as_slice()).unwrap();
        let kind = v
            .as_map_mut()
            .unwrap()
            .iter_mut()
            .find(|(k, _)| k.as_text() == Some("kind"))
            .unwrap();
        kind.1
            .as_map_mut()
            .unwrap()
            .push((Value::Text("uv_marker".into()), Value::Bool(true)));
        assert!(matches!(
            SlotEntry::decode(&encode_value(&v)),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn trailing_bytes_after_a_slot_are_malformed() {
        let mut raw = SlotEntry::Known(recovery_slot()).encode().unwrap();
        raw.push(0);
        assert!(matches!(SlotEntry::decode(&raw), Err(Error::Malformed(_))));
    }

    fn arb_value() -> impl proptest::strategy::Strategy<Value = Value> {
        use proptest::prelude::*;
        let leaf = prop_oneof![
            any::<i64>().prop_map(|i| Value::Integer(i.into())),
            any::<bool>().prop_map(Value::Bool),
            ".{0,8}".prop_map(Value::Text),
            proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
            Just(Value::Null),
        ];
        leaf.prop_recursive(3, 16, 4, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                proptest::collection::vec((".{0,8}".prop_map(Value::Text), inner), 0..4)
                    .prop_map(Value::Map),
            ]
        })
    }

    proptest::proptest! {
        /// Slot maps with plausible structure (known and unknown types,
        /// arbitrary field values) never panic, and whatever decodes as a
        /// known slot re-encodes to something that decodes identically.
        #[test]
        fn structured_slot_maps_never_panic(
            slot_type in proptest::prop_oneof![
                proptest::strategy::Just("tpm".to_string()),
                proptest::strategy::Just("fido2".to_string()),
                proptest::strategy::Just("recovery".to_string()),
                proptest::strategy::Just("login-password".to_string()),
                "[a-z-]{0,12}",
            ],
            kind_fields in proptest::collection::vec((
                proptest::prop_oneof![
                    proptest::strategy::Just("public".to_string()),
                    proptest::strategy::Just("salt".to_string()),
                    proptest::strategy::Just("xwing_pk".to_string()),
                    ".{0,10}",
                ],
                arb_value(),
            ), 0..6),
            top in proptest::collection::vec((
                proptest::prop_oneof![
                    proptest::strategy::Just("id".to_string()),
                    proptest::strategy::Just("nonce".to_string()),
                    proptest::strategy::Just("wrapped_mk".to_string()),
                    ".{0,10}",
                ],
                arb_value(),
            ), 0..7),
        ) {
            let mut kind = vec![(Value::Text("slot_type".into()), Value::Text(slot_type))];
            kind.extend(kind_fields.into_iter().map(|(k, v)| (Value::Text(k), v)));
            let mut map: Vec<(Value, Value)> =
                top.into_iter().map(|(k, v)| (Value::Text(k), v)).collect();
            map.push((Value::Text("kind".into()), Value::Map(kind)));
            if let Ok(entry) = SlotEntry::decode(&encode_value(&Value::Map(map))) {
                let again = SlotEntry::decode(&entry.encode().unwrap()).unwrap();
                proptest::prop_assert_eq!(again, entry);
            }
        }
    }

    #[test]
    fn slot_without_a_type_is_malformed() {
        let v = Value::Map(vec![(Value::Text("id".into()), Value::Bytes(vec![0; 16]))]);
        assert!(matches!(
            SlotEntry::decode(&encode_value(&v)),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            SlotEntry::decode(&[0xff]),
            Err(Error::Malformed(_))
        ));
    }
}
