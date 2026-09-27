mod common;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{
    Error, Fido2Slot, HighWater, Item, Kek, LockedVault, RecoveryKey, SecretBytes, SlotKind,
    Standing, TpmSlot, UnlockedVault, highwater, vault,
};
use ciborium::Value;
use common::*;
use proptest::prelude::*;
use uuid::Uuid;

fn fido2_kind() -> SlotKind {
    SlotKind::Fido2(Fido2Slot {
        credential_id: vec![1; 16],
        salt: [2; 32],
        uv_required: true,
        pin_required: true,
    })
}

fn tpm_kind() -> SlotKind {
    SlotKind::Tpm(TpmSlot {
        public: vec![1],
        private: vec![2],
        auth_salt: [3; 16],
        srk_name: vec![4],
    })
}

#[test]
fn round_trip_through_bytes_with_recovery_key_or_password() {
    let (v, rk, rec, pw) = sample();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert_eq!(locked.keyslots().count(), 2);
    assert_eq!(
        first_secret(&locked.unlock_recovery(rec, &rk).unwrap()),
        b"ghp_secret"
    );
    assert_eq!(
        first_secret(&locked.unlock_login_password(pw, PASSWORD).unwrap()),
        b"ghp_secret"
    );
}

#[test]
fn wrong_secrets_and_wrong_slot_types_are_rejected() {
    let (v, _, rec, pw) = sample();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        locked.unlock_login_password(pw, b"wrong"),
        Err(Error::UnwrapFailed)
    ));
    let other = RecoveryKey::generate().unwrap();
    assert!(matches!(
        locked.unlock_recovery(rec, &other),
        Err(Error::UnwrapFailed)
    ));
    assert!(matches!(
        locked.unlock_recovery(pw, &other),
        Err(Error::WrongSlotType(_))
    ));
    assert!(matches!(
        locked.unlock_login_password(rec, PASSWORD),
        Err(Error::WrongSlotType(_))
    ));
    assert!(matches!(
        locked.unlock_login_password(Uuid::new_v4(), PASSWORD),
        Err(Error::NoSuchKeyslot(_))
    ));
}

#[test]
fn a_vault_without_a_recovery_slot_cannot_be_written() {
    let mut v = UnlockedVault::create().unwrap();
    v.add_login_password_slot("login", PASSWORD, FAST).unwrap();
    assert!(matches!(v.to_bytes(), Err(Error::RecoveryRequired)));
}

#[test]
fn only_hardware_slots_take_a_raw_kek_and_weak_params_are_refused() {
    let (mut v, ..) = sample();
    let kek = Kek::generate().unwrap();
    v.add_keyslot("fido", fido2_kind(), &kek).unwrap();
    v.add_keyslot("tpm", tpm_kind(), &kek).unwrap();
    let rec_kind = v
        .keyslots()
        .find(|s| matches!(s.kind, SlotKind::Recovery(_)))
        .unwrap()
        .kind
        .clone();
    assert!(matches!(
        v.add_keyslot("r", rec_kind, &kek),
        Err(Error::NotAHardwareSlot)
    ));
    let weak = aleph_core::Argon2Params {
        m_kib: 1024,
        t: 1,
        p: 1,
    };
    assert!(matches!(
        v.add_login_password_slot("w", PASSWORD, weak),
        Err(Error::WeakParams)
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
    let (v, _, _, pw) = sample();
    let edited = edit_slots(&v.to_bytes().unwrap(), |slots| {
        slots.remove(0); // the recovery slot
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    assert!(matches!(
        locked.unlock_login_password(pw, PASSWORD),
        Err(Error::HeaderTampered)
    ));
}

#[test]
fn lowering_the_generation_in_the_file_is_detected() {
    let (v, _, _, pw) = sample();
    let edited = edit_header(&v.to_bytes().unwrap(), |h| {
        *field(h, "generation") = Value::Integer(0.into());
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    assert!(matches!(
        locked.unlock_login_password(pw, PASSWORD),
        Err(Error::HeaderTampered)
    ));
}

/// Spec §9 "header rollback rejected": an older, validly MAC'd header
/// spliced onto a newer body must not open.
#[test]
fn old_header_spliced_onto_new_body_is_rejected() {
    let (mut v, _, _, pw) = sample();
    let old = v.to_bytes().unwrap();
    v.body_mut().collections[0].label = "NEW BODY".into();
    let new = v.to_bytes().unwrap();
    let old_outer: Value = ciborium::from_reader(&old[6..]).unwrap();
    let old_outer = old_outer.as_array().unwrap().clone();
    let spliced = edit_outer(&new, |a| {
        a[1] = old_outer[1].clone();
        a[2] = old_outer[2].clone();
    });
    let locked = LockedVault::from_bytes(&spliced).unwrap();
    assert!(matches!(
        locked.unlock_login_password(pw, PASSWORD),
        Err(Error::BodyTampered)
    ));
}

#[test]
fn wrapped_key_moved_to_another_slot_does_not_unwrap() {
    let (mut v, ..) = sample();
    let kek = Kek::generate().unwrap();
    let a = v.add_keyslot("a", fido2_kind(), &kek).unwrap();
    let b = v.add_keyslot("b", fido2_kind(), &kek).unwrap();
    // Same KEK, same type: only the slot id in the AAD differs.
    let edited = edit_slots(&v.to_bytes().unwrap(), |slots| {
        let src = slots[2].clone();
        let (Value::Map(src), Value::Map(dst)) = (&src, &mut slots[3]) else {
            panic!()
        };
        for name in ["nonce", "wrapped_mk"] {
            let val = src
                .iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .unwrap()
                .1
                .clone();
            *field(dst, name) = val;
        }
    });
    let locked = LockedVault::from_bytes(&edited).unwrap();
    // Slot `a` is untouched, but any header edit fails the MAC for every
    // slot; only the moved wrap fails earlier, at unwrap.
    assert!(matches!(locked.unlock(a, &kek), Err(Error::HeaderTampered)));
    assert!(matches!(locked.unlock(b, &kek), Err(Error::UnwrapFailed)));
}

#[test]
fn every_write_is_a_new_generation_and_marks_track_it() {
    let (v, rk, rec, _) = sample();
    let first = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    let second = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert_eq!(first.mark().generation + 1, second.mark().generation);
    assert_eq!(first.mark().mk_id, second.mark().mk_id);
    assert_eq!(v.mark(), second.mark());
    let reopened = second.unlock_recovery(rec, &rk).unwrap();
    assert_eq!(reopened.mark(), second.mark());
    let third = LockedVault::from_bytes(&reopened.to_bytes().unwrap()).unwrap();
    assert_eq!(third.mark().generation, second.mark().generation + 1);
}

/// The public `mk_id` in the header must match the key that unwrapped it.
/// Otherwise someone holding an old MK could stamp the current `mk_id` on a
/// forged file and pass the high-water check as `Current` or `Newer`.
#[test]
fn a_header_claiming_another_mk_id_is_rejected() {
    let (v, _, _, pw) = sample();
    let (other, ..) = sample();
    let forged = vault::testing::to_bytes_with_mk_id(&v, other.mark().mk_id).unwrap();
    let locked = LockedVault::from_bytes(&forged).unwrap();
    assert_eq!(locked.mark().mk_id, other.mark().mk_id);
    assert!(matches!(
        locked.unlock_login_password(pw, PASSWORD),
        Err(Error::HeaderTampered)
    ));
}

/// End to end through real files: a restored older copy is `RolledBack`.
#[test]
fn restoring_an_older_file_is_detected_as_rolled_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let hw = HighWater::new(dir.path().join("state"));
    let (v, ..) = sample();
    hw.record(&v.write(&path).unwrap()).unwrap();
    let old = std::fs::read(&path).unwrap();
    hw.record(&v.write(&path).unwrap()).unwrap();
    std::fs::write(&path, old).unwrap();
    let found = LockedVault::read(&path).unwrap().mark();
    assert!(matches!(
        hw.check(&found).unwrap(),
        Standing::RolledBack { .. }
    ));
}

/// Review finding: someone holding the old MK (an old file plus a removed
/// credential) re-serializes the old vault with a higher generation. It
/// must be flagged `Rekeyed`, not accepted as `Newer`.
#[test]
fn a_replayed_old_mk_with_a_forged_higher_generation_is_rekeyed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let hw = HighWater::new(dir.path().join("state"));
    let (mut v, _, _, pw) = sample();
    let rogue_kek = Kek::generate().unwrap();
    let rogue = v.add_keyslot("rogue", fido2_kind(), &rogue_kek).unwrap();
    hw.record(&v.write(&path).unwrap()).unwrap();
    let old = std::fs::read(&path).unwrap();

    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    v.remove_keyslot(rogue, &[(pw, &pw_kek)]).unwrap();
    hw.record(&v.write(&path).unwrap()).unwrap();

    // The attacker opens the old file with the revoked credential and
    // writes it back several generations ahead.
    let replay = LockedVault::from_bytes(&old)
        .unwrap()
        .unlock(rogue, &rogue_kek)
        .unwrap();
    for _ in 0..3 {
        replay.to_bytes().unwrap();
    }
    let forged = replay.to_bytes().unwrap();
    let found = LockedVault::from_bytes(&forged).unwrap();
    assert!(found.mark().generation > v.mark().generation);
    assert_eq!(hw.check(&found.mark()).unwrap(), Standing::Rekeyed);
    // Even an authenticated replay (it unlocks with the old credential)
    // cannot raise the mark to the old MK.
    let replayed = found.unlock(rogue, &rogue_kek).unwrap();
    assert_eq!(hw.raise(&replayed).unwrap(), Standing::Rekeyed);
    assert_eq!(hw.check(&v.mark()).unwrap(), Standing::Current);
}

/// `raise` only takes an unlocked (authenticated) vault: an unauthenticated
/// file claiming the real vault id, the public mk_id, and a huge generation
/// must not be able to move the mark. (`check` on it is fine.)
#[test]
fn only_an_unlocked_vault_can_raise_the_high_water_mark() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let hw = HighWater::new(dir.path().join("state"));
    let (v, _, _, pw) = sample();
    hw.record(&v.write(&path).unwrap()).unwrap();
    let edited = edit_header(&std::fs::read(&path).unwrap(), |h| {
        *field(h, "generation") = Value::Integer(u64::MAX.into());
    });
    let forged = LockedVault::from_bytes(&edited).unwrap();
    assert_eq!(hw.check(&forged.mark()).unwrap(), Standing::Newer);
    assert!(forged.unlock_login_password(pw, PASSWORD).is_err());
    // The only way to raise is with a vault that actually unlocked.
    let real = LockedVault::read(&path)
        .unwrap()
        .unlock_login_password(pw, PASSWORD)
        .unwrap();
    assert_eq!(hw.raise(&real).unwrap(), Standing::Current);
    assert_eq!(hw.check(&v.mark()).unwrap(), Standing::Current);
}

/// `write_recorded` records the mark it wrote, including after a rotation,
/// so the daemon's own rotation never looks like `Rekeyed`.
#[test]
fn write_recorded_keeps_own_rotations_current() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let hw = HighWater::new(dir.path().join("state"));
    let (mut v, _, _, pw) = sample();
    let kek = Kek::generate().unwrap();
    let fido = v.add_keyslot("yubikey", fido2_kind(), &kek).unwrap();
    v.write_recorded(&path, &hw).unwrap();
    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    v.remove_keyslot(fido, &[(pw, &pw_kek)]).unwrap();
    let m = v.write_recorded(&path, &hw).unwrap();
    let on_disk = LockedVault::read(&path).unwrap().mark();
    assert_eq!(on_disk, m);
    assert_eq!(hw.check(&on_disk).unwrap(), Standing::Current);
}

#[test]
fn highwater_detects_a_rolled_back_or_replaced_file() {
    let (v, ..) = sample();
    let old = LockedVault::from_bytes(&v.to_bytes().unwrap())
        .unwrap()
        .mark();
    let new = LockedVault::from_bytes(&v.to_bytes().unwrap())
        .unwrap()
        .mark();
    assert_eq!(
        highwater::compare(Some(&new), &old),
        Standing::RolledBack {
            recorded: new.generation
        }
    );
    let (other, ..) = sample();
    let mut replaced = LockedVault::from_bytes(&other.to_bytes().unwrap())
        .unwrap()
        .mark();
    replaced.vault_id = new.vault_id;
    replaced.generation = new.generation;
    assert_eq!(
        highwater::compare(Some(&new), &replaced),
        Standing::Replaced
    );
}

#[test]
fn removing_a_slot_rotates_so_it_cannot_open_later_files() {
    let (mut v, rk, rec, pw) = sample();
    let fido_kek = Kek::generate().unwrap();
    let fido = v.add_keyslot("yubikey", fido2_kind(), &fido_kek).unwrap();
    let before = v.to_bytes().unwrap();
    let mk_before = v.mark().mk_id;

    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    let rotation = v.remove_keyslot(fido, &[(pw, &pw_kek)]).unwrap();
    assert_eq!(rotation.dropped, vec![fido]);
    let after = v.to_bytes().unwrap();
    assert_ne!(v.mark().mk_id, mk_before);

    // The removed credential still opens the old copy (unavoidable)...
    assert!(
        LockedVault::from_bytes(&before)
            .unwrap()
            .unlock(fido, &fido_kek)
            .is_ok()
    );
    // ...but not the new file: its slot is gone, and splicing the old slot
    // in (same id, old wrap of the old MK) fails authentication.
    let locked_after = LockedVault::from_bytes(&after).unwrap();
    assert!(matches!(
        locked_after.unlock(fido, &fido_kek),
        Err(Error::NoSuchKeyslot(_))
    ));
    let old_slot: Value = {
        let outer: Value = ciborium::from_reader(&before[6..]).unwrap();
        let h: Value =
            ciborium::from_reader(outer.as_array().unwrap()[1].as_bytes().unwrap().as_slice())
                .unwrap();
        let slots = h
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("keyslots"))
            .unwrap()
            .1
            .clone();
        ciborium::from_reader(slots.as_array().unwrap()[2].as_bytes().unwrap().as_slice()).unwrap()
    };
    let spliced = edit_slots(&after, |slots| slots.push(old_slot));
    let err = LockedVault::from_bytes(&spliced)
        .unwrap()
        .unlock(fido, &fido_kek);
    assert!(matches!(
        err,
        Err(Error::HeaderTampered) | Err(Error::UnwrapFailed)
    ));

    // Remaining slots still work, and recovery was re-wrapped without its key.
    assert!(locked_after.unlock_recovery(rec, &rk).is_ok());
    assert!(locked_after.unlock_login_password(pw, PASSWORD).is_ok());
}

#[test]
fn rotation_needs_correct_keks_for_every_non_recovery_slot_and_changes_nothing_on_error() {
    let (mut v, _, rec, pw) = sample();
    let fido_kek = Kek::generate().unwrap();
    let fido = v.add_keyslot("yubikey", fido2_kind(), &fido_kek).unwrap();
    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    let wrong = Kek::generate().unwrap();
    let before: Vec<Vec<u8>> = v.keyslots().map(|s| s.wrapped_mk.clone()).collect();

    assert!(
        matches!(v.rotate_master(&[(pw, &pw_kek)], &[]), Err(Error::MissingKek(id)) if id == fido)
    );
    assert!(
        matches!(v.rotate_master(&[(pw, &pw_kek), (fido, &wrong)], &[]), Err(Error::WrongKek(id)) if id == fido)
    );
    assert!(matches!(
        v.rotate_master(&[], &[Uuid::new_v4()]),
        Err(Error::NoSuchKeyslot(_))
    ));
    assert!(matches!(
        v.rotate_master(&[(pw, &pw_kek), (fido, &fido_kek)], &[rec]),
        Err(Error::RecoveryRequired)
    ));
    let after: Vec<Vec<u8>> = v.keyslots().map(|s| s.wrapped_mk.clone()).collect();
    assert_eq!(before, after);

    v.rotate_master(&[(pw, &pw_kek), (fido, &fido_kek)], &[])
        .unwrap();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert!(locked.unlock(fido, &fido_kek).is_ok());
}

#[test]
fn reissuing_the_recovery_key_retires_the_old_one() {
    let (mut v, old_rk, old_rec, pw) = sample();
    let new_rk = RecoveryKey::generate().unwrap();
    let new_rec = v
        .add_recovery_slot("recovery 2", &new_rk.recipient().public_key())
        .unwrap();
    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    v.remove_keyslot(old_rec, &[(pw, &pw_kek)]).unwrap();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        locked.unlock_recovery(old_rec, &old_rk),
        Err(Error::NoSuchKeyslot(_))
    ));
    assert!(locked.unlock_recovery(new_rec, &new_rk).is_ok());
}

#[test]
fn unknown_slot_types_survive_writes_and_are_dropped_by_rotation() {
    let (v, rk, rec, pw) = sample();
    let future_id = Uuid::new_v4();
    let future = Value::Map(vec![
        (
            Value::Text("id".into()),
            Value::Bytes(future_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("label".into()),
            Value::Text("from aleph 9".into()),
        ),
        (
            Value::Text("kind".into()),
            Value::Map(vec![(
                Value::Text("slot_type".into()),
                Value::Text("quantum-dot".into()),
            )]),
        ),
    ]);
    let future_raw = encode(&future);
    // Simulate a newer aleph having written it: add the slot and re-MAC by
    // round-tripping through a vault that is then re-opened. The MAC check
    // uses the exact bytes, so inject before unlocking and expect
    // HeaderTampered; then check preservation through SlotEntry directly.
    let edited = edit_slots(&v.to_bytes().unwrap(), |slots| slots.push(future.clone()));
    let locked = LockedVault::from_bytes(&edited).unwrap();
    let unknown: Vec<_> = locked.unknown_keyslots().collect();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].slot_type, "quantum-dot");
    assert_eq!(unknown[0].id, Some(future_id));
    assert_eq!(unknown[0].raw, future_raw);
    assert!(matches!(
        locked.unlock_recovery(rec, &rk),
        Err(Error::HeaderTampered)
    ));

    // A legitimately written file with an unknown slot (produced by the
    // real serializer) keeps it byte-for-byte across writes.
    let mut unlocked = LockedVault::from_bytes(&v.to_bytes().unwrap())
        .unwrap()
        .unlock_recovery(rec, &rk)
        .unwrap();
    aleph_core::vault::testing::push_unknown(&mut unlocked, future_raw.clone());
    let rewritten = LockedVault::from_bytes(&unlocked.to_bytes().unwrap()).unwrap();
    let reopened = rewritten.unlock_recovery(rec, &rk).unwrap();
    assert_eq!(reopened.unknown_keyslots().next().unwrap().raw, future_raw);

    let pw_kek = unlocked.login_password_kek(pw, PASSWORD).unwrap();
    let rotation = unlocked.rotate_master(&[(pw, &pw_kek)], &[]).unwrap();
    assert_eq!(rotation.dropped_unknown.len(), 1);
    assert_eq!(unlocked.unknown_keyslots().count(), 0);
}

#[test]
fn rotation_reports_each_drop_once_and_unknown_slots_separately() {
    let (mut v, _, _, pw) = sample();
    let kek = Kek::generate().unwrap();
    let fido = v.add_keyslot("yubikey", fido2_kind(), &kek).unwrap();
    let future_id = Uuid::new_v4();
    let future = encode(&Value::Map(vec![
        (
            Value::Text("id".into()),
            Value::Bytes(future_id.as_bytes().to_vec()),
        ),
        (
            Value::Text("kind".into()),
            Value::Map(vec![(
                Value::Text("slot_type".into()),
                Value::Text("quantum-dot".into()),
            )]),
        ),
    ]));
    vault::testing::push_unknown(&mut v, future);
    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    let rotation = v
        .rotate_master(&[(pw, &pw_kek)], &[fido, fido, future_id])
        .unwrap();
    assert_eq!(rotation.dropped, vec![fido]);
    assert_eq!(rotation.dropped_unknown.len(), 1);
    assert_eq!(rotation.dropped_unknown[0].id, Some(future_id));
}

#[test]
fn generation_overflow_is_an_error_not_a_panic() {
    let (v, ..) = sample();
    vault::testing::set_generation(&v, u64::MAX);
    assert!(matches!(v.to_bytes(), Err(Error::GenerationOverflow)));
}

#[test]
fn backup_copy_contains_only_the_recovery_slot() {
    let (v, rk, rec, pw) = sample();
    let backup = LockedVault::from_bytes(&v.to_backup_bytes().unwrap()).unwrap();
    // Generations start at 1, even for a backup of a never-written vault.
    assert_eq!(backup.mark().generation, 1);
    let kinds: Vec<&str> = backup.keyslots().map(|s| s.kind.type_name()).collect();
    assert_eq!(kinds, vec!["recovery"]);
    assert!(matches!(
        backup.unlock_login_password(pw, PASSWORD),
        Err(Error::NoSuchKeyslot(_))
    ));
    assert_eq!(
        first_secret(&backup.unlock_recovery(rec, &rk).unwrap()),
        b"ghp_secret"
    );
}

/// Flipping any single bit of the file must never yield a successfully
/// unlocked vault. Exhaustive over every bit, not sampled. Unlocks through
/// a raw-KEK slot so ~25k attempts need no Argon2; every other slot's bytes
/// are still covered by the header MAC.
#[test]
fn every_single_bit_flip_is_detected() {
    let (mut v, ..) = sample();
    let kek = Kek::generate().unwrap();
    let fido = v.add_keyslot("yubikey", fido2_kind(), &kek).unwrap();
    let bytes = v.to_bytes().unwrap();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut b = bytes.clone();
            b[i] ^= 1 << bit;
            let unlocked = LockedVault::from_bytes(&b).and_then(|l| l.unlock(fido, &kek));
            assert!(
                unlocked.is_err(),
                "bit {bit} of byte {i} flipped undetected"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary input must be rejected with an error, never a panic.
    #[test]
    fn arbitrary_bytes_never_panic(tail in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut bytes = b"ALEPH\0".to_vec();
        bytes.extend(tail);
        let _ = LockedVault::from_bytes(&bytes);
    }

    // Each case builds a vault with an X-Wing recipient, hence 64 cases.
    #[test]
    fn body_round_trips(
        secret in prop::collection::vec(any::<u8>(), 0..256),
        label in ".{0,40}",
        collection_label in ".{0,40}",
        attributes in prop::collection::btree_map(".{0,20}", ".{0,40}", 0..6),
    ) {
        let (mut v, rk, rec, _) = sample();
        let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
        let c = v.body_mut().collection_mut(login).unwrap();
        c.label = collection_label;
        c.upsert(
            Item::new(label.clone(), attributes, SecretBytes::new(secret.clone()), "application/octet-stream"),
            false,
        );
        let back = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap().unlock_recovery(rec, &rk).unwrap();
        prop_assert_eq!(back.body(), v.body());
    }
}
