mod common;

use std::collections::BTreeMap;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{Error, Item, LockedVault, SecretBytes, UnlockedVault};
use ciborium::Value;
use common::*;
use proptest::prelude::*;
use uuid::Uuid;

#[test]
fn round_trip_through_bytes_with_either_slot() {
    let (v, rk, rec, pass) = sample();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert_eq!(locked.keyslots().len(), 2);
    assert_eq!(
        first_secret(&locked.unlock_argon2(rec, rk.as_bytes()).unwrap()),
        b"ghp_secret"
    );
    assert_eq!(
        first_secret(&locked.unlock_argon2(pass, PASSPHRASE).unwrap()),
        b"ghp_secret"
    );
}

#[test]
fn wrong_secret_is_unwrap_failed() {
    let (v, _, rec, pass) = sample();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        locked.unlock_argon2(pass, b"wrong"),
        Err(Error::UnwrapFailed)
    ));
    assert!(matches!(
        locked.unlock_argon2(rec, &[0u8; 32]),
        Err(Error::UnwrapFailed)
    ));
    assert!(matches!(
        locked.unlock_argon2(Uuid::new_v4(), b"x"),
        Err(Error::NoSuchKeyslot(_))
    ));
}

#[test]
fn bad_magic_and_future_versions_are_rejected() {
    let (v, ..) = sample();
    let bytes = v.to_bytes().unwrap();
    let mut bad = bytes.clone();
    bad[0] = b'X';
    assert!(matches!(
        LockedVault::from_bytes(&bad),
        Err(Error::BadMagic)
    ));
    let future = edit_outer(&bytes, |a| a[0] = Value::Integer(2.into()));
    assert!(matches!(
        LockedVault::from_bytes(&future),
        Err(Error::UnsupportedVersion(2))
    ));
}

#[test]
fn trailing_bytes_and_extra_elements_are_rejected() {
    let (v, ..) = sample();
    let bytes = v.to_bytes().unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(matches!(
        LockedVault::from_bytes(&trailing),
        Err(Error::Malformed(_))
    ));
    let extra = edit_outer(&bytes, |a| a.push(Value::Null));
    assert!(matches!(
        LockedVault::from_bytes(&extra),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn deleting_a_keyslot_from_the_file_is_detected() {
    let (v, _, _, pass) = sample();
    // Drop the recovery slot (index 0), then unlock with the passphrase.
    let edited = edit_header(&v.to_bytes().unwrap(), |m| match field(m, "keyslots") {
        Value::Array(slots) => {
            slots.remove(0);
        }
        _ => panic!("keyslots is an array"),
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    assert!(matches!(
        locked.unlock_argon2(pass, PASSPHRASE),
        Err(Error::HeaderTampered)
    ));
}

/// Spec §9 "header rollback rejected": an older, validly MAC'd header
/// spliced onto a newer body must not open. Otherwise an attacker with
/// write access to a synced or backed-up vault could bring back a removed
/// keyslot (e.g. a leaked old passphrase) while keeping current data.
#[test]
fn old_header_spliced_onto_new_body_is_rejected() {
    let (mut v, _, _, pass) = sample();
    let old = v.to_bytes().unwrap();
    v.remove_keyslot(pass).unwrap();
    v.body_mut().collections[0].label = "NEW BODY".into();
    let new = v.to_bytes().unwrap();

    let old_outer: Value = ciborium::from_reader(&old[6..]).unwrap();
    let old_outer = old_outer.as_array().unwrap().clone();
    let spliced = edit_outer(&new, |a| {
        a[1] = old_outer[1].clone(); // header_bytes (still lists `pass`)
        a[2] = old_outer[2].clone(); // header_mac
    });
    let locked = LockedVault::from_bytes(&spliced).unwrap();
    assert!(matches!(
        locked.unlock_argon2(pass, PASSPHRASE),
        Err(Error::BodyTampered)
    ));
}

#[test]
fn wrapped_key_moved_to_another_slot_does_not_unwrap() {
    let (v, rk, rec, _) = sample();
    // Copy the recovery slot's wrapped key and nonce into slot 1 and give
    // slot 1 the recovery slot's salt/params, so the KEK is identical and
    // only the AAD (slot id + type) differs.
    let edited = edit_header(&v.to_bytes().unwrap(), |m| match field(m, "keyslots") {
        Value::Array(slots) => {
            let src = slots[0].clone();
            let dst = match &mut slots[1] {
                Value::Map(d) => d,
                _ => panic!(),
            };
            let src = match src {
                Value::Map(s) => s,
                _ => panic!(),
            };
            for name in ["nonce", "wrapped_mk", "kind"] {
                let val = src
                    .iter()
                    .find(|(k, _)| k.as_text() == Some(name))
                    .unwrap()
                    .1
                    .clone();
                *field(dst, name) = val;
            }
        }
        _ => panic!(),
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    let moved = locked.keyslots()[1].id;
    assert_ne!(moved, rec);
    assert!(matches!(
        locked.unlock_argon2(moved, rk.as_bytes()),
        Err(Error::UnwrapFailed)
    ));
}

#[test]
fn remove_keyslot_refuses_the_last_one() {
    let (mut v, _, rec, pass) = sample();
    v.remove_keyslot(pass).unwrap();
    assert!(matches!(v.remove_keyslot(rec), Err(Error::LastKeyslot)));
    assert!(matches!(
        v.remove_keyslot(Uuid::new_v4()),
        Err(Error::NoSuchKeyslot(_))
    ));
}

#[test]
fn vault_without_keyslots_cannot_be_serialized() {
    assert!(matches!(
        UnlockedVault::create().unwrap().to_bytes(),
        Err(Error::LastKeyslot)
    ));
}

#[test]
fn rotate_master_rewraps_all_slots_and_requires_every_kek() {
    let (mut v, rk, rec, pass) = sample();
    let slot_kek = |v: &UnlockedVault, id: Uuid, secret: &[u8]| {
        let a = v
            .keyslots()
            .iter()
            .find(|s| s.id == id)
            .unwrap()
            .kind
            .as_argon2()
            .unwrap()
            .clone();
        aleph_core::derive_kek(secret, &a.salt, &a.params).unwrap()
    };
    let rec_kek = slot_kek(&v, rec, rk.as_bytes());
    let pass_kek = slot_kek(&v, pass, PASSPHRASE);

    assert!(
        matches!(v.rotate_master(&[(rec, &rec_kek)]), Err(Error::MissingKek(id)) if id == pass)
    );

    let before: Vec<Vec<u8>> = v.keyslots().iter().map(|s| s.wrapped_mk.clone()).collect();
    v.rotate_master(&[(rec, &rec_kek), (pass, &pass_kek)])
        .unwrap();
    let after: Vec<Vec<u8>> = v.keyslots().iter().map(|s| s.wrapped_mk.clone()).collect();
    assert!(before.iter().zip(&after).all(|(b, a)| b != a));

    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert_eq!(
        first_secret(&locked.unlock_argon2(rec, rk.as_bytes()).unwrap()),
        b"ghp_secret"
    );
    assert_eq!(
        first_secret(&locked.unlock_argon2(pass, PASSPHRASE).unwrap()),
        b"ghp_secret"
    );
}

/// A wrong KEK (mistyped passphrase, wrong TPM auth) must be refused
/// before anything changes; otherwise that slot is silently rewrapped
/// under garbage and the unlock method is lost for good.
#[test]
fn rotate_master_rejects_a_wrong_kek_and_changes_nothing() {
    let (mut v, rk, rec, pass) = sample();
    let a = v.keyslots()[0].kind.as_argon2().unwrap().clone();
    let rec_kek = aleph_core::derive_kek(rk.as_bytes(), &a.salt, &a.params).unwrap();
    let wrong = aleph_core::Kek::generate().unwrap();
    let before: Vec<Vec<u8>> = v.keyslots().iter().map(|s| s.wrapped_mk.clone()).collect();

    assert!(matches!(
        v.rotate_master(&[(rec, &rec_kek), (pass, &wrong)]),
        Err(Error::WrongKek(id)) if id == pass
    ));

    let after: Vec<Vec<u8>> = v.keyslots().iter().map(|s| s.wrapped_mk.clone()).collect();
    assert_eq!(before, after);
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    locked.unlock_argon2(pass, PASSPHRASE).unwrap();
    locked.unlock_argon2(rec, rk.as_bytes()).unwrap();
}

/// Flipping any single bit of the file must never yield a successfully
/// unlocked vault. Exhaustive over every bit, not sampled.
#[test]
fn every_single_bit_flip_is_detected() {
    let (v, _, _, pass) = sample();
    let bytes = v.to_bytes().unwrap();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut b = bytes.clone();
            b[i] ^= 1 << bit;
            let unlocked =
                LockedVault::from_bytes(&b).and_then(|l| l.unlock_argon2(pass, PASSPHRASE));
            assert!(
                unlocked.is_err(),
                "bit {bit} of byte {i} flipped undetected"
            );
        }
    }
}

proptest! {

    /// Arbitrary input must be rejected with an error, never a panic.
    #[test]
    fn arbitrary_bytes_never_panic(tail in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut bytes = b"ALEPH\0".to_vec();
        bytes.extend(tail);
        let _ = LockedVault::from_bytes(&bytes);
    }

    #[test]
    fn body_round_trips(secret in prop::collection::vec(any::<u8>(), 0..256), label in ".{0,40}") {
        let (mut v, rk, rec, _) = sample();
        let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
        v.body_mut().collection_mut(login).unwrap().upsert(
            Item::new(label.clone(), BTreeMap::new(), SecretBytes::new(secret.clone()), "application/octet-stream"),
            false,
        );
        let back = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap().unlock_argon2(rec, rk.as_bytes()).unwrap();
        prop_assert_eq!(back.body(), v.body());
    }
}
