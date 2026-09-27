//! Shared fixtures for aleph-core integration tests.
#![allow(dead_code)] // each test binary uses a different subset

use std::collections::BTreeMap;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{Argon2Params, Item, RecoveryKey, SecretBytes, UnlockedVault};
use ciborium::Value;
use uuid::Uuid;

pub const PASSWORD: &[u8] = b"correct horse";

pub const FAST: Argon2Params = Argon2Params::INSECURE_TEST;

/// A vault with a recovery slot, a login-password slot, and one item.
/// Returns `(vault, recovery key, recovery slot id, password slot id)`.
pub fn sample() -> (UnlockedVault, RecoveryKey, Uuid, Uuid) {
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::generate().unwrap();
    let rec = v
        .add_recovery_slot("recovery", &rk.recipient().public_key())
        .unwrap();
    let pw = v.add_login_password_slot("login", PASSWORD, FAST).unwrap();
    let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
    let attrs = BTreeMap::from([("service".to_string(), "github".to_string())]);
    v.body_mut().collection_mut(login).unwrap().upsert(
        Item::new(
            "GitHub token",
            attrs,
            SecretBytes::new(b"ghp_secret".to_vec()),
            "text/plain",
        ),
        false,
    );
    (v, rk, rec, pw)
}

pub fn first_secret(v: &UnlockedVault) -> Vec<u8> {
    v.body().resolve_alias(DEFAULT_ALIAS).unwrap().items[0]
        .secret
        .expose()
        .to_vec()
}

/// Decode the file's outer CBOR array (after the magic), let `f` edit it,
/// re-encode.
pub fn edit_outer(bytes: &[u8], f: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut value: Value = ciborium::from_reader(&bytes[6..]).unwrap();
    f(match &mut value {
        Value::Array(a) => a,
        _ => panic!("vault is a CBOR array"),
    });
    let mut out = bytes[..6].to_vec();
    ciborium::into_writer(&value, &mut out).unwrap();
    out
}

/// Decode the header (outer element 1, a byte string holding a CBOR map),
/// let `f` edit it, re-encode. Simulates an attacker rewriting the header.
pub fn edit_header(bytes: &[u8], f: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    edit_outer(bytes, |outer| {
        let mut header: Value =
            ciborium::from_reader(outer[1].as_bytes().unwrap().as_slice()).unwrap();
        f(match &mut header {
            Value::Map(m) => m,
            _ => panic!("header is a CBOR map"),
        });
        outer[1] = Value::Bytes(encode(&header));
    })
}

/// Decode each keyslot (a byte string holding a CBOR map), let `f` edit
/// the list of decoded maps, re-encode them into the header.
pub fn edit_slots(bytes: &[u8], f: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    edit_header(bytes, |h| {
        let Value::Array(raw) = field(h, "keyslots") else {
            panic!("keyslots is an array")
        };
        let mut slots: Vec<Value> = raw
            .iter()
            .map(|b| ciborium::from_reader(b.as_bytes().unwrap().as_slice()).unwrap())
            .collect();
        f(&mut slots);
        *raw = slots.iter().map(|s| Value::Bytes(encode(s))).collect();
    })
}

pub fn encode(v: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).unwrap();
    buf
}

pub fn field<'a>(map: &'a mut [(Value, Value)], name: &str) -> &'a mut Value {
    &mut map
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(name))
        .unwrap()
        .1
}
