use aleph_core::{LockedVault, RecoveryKey, SlotKind, UnlockedVault};
use aleph_unlock::Error;
use aleph_unlock::fido2::mock::{MockAuthenticator, MockKeys};
use aleph_unlock::fido2::{self, Authenticator, CRED_PROTECT, CredProtect, Keys, Verification};

fn same_kek(a: &aleph_core::Kek, b: &aleph_core::Kek) -> bool {
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(a, b"t").unwrap();
    aleph_core::KeyHandle::unwraps_to(b, &w, b"t", &mk.id())
}

const PIN: &str = "123456";

#[test]
fn a_pin_key_enrolls_with_the_pin_and_unlocks_with_it() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    assert!(slot.pin_required && !slot.uv_required);
    assert_eq!(
        keys.devices[0].touches, 3,
        "enrollment is three touches (the third checks UV separation)"
    );
    let back = fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap();
    assert_eq!(keys.devices[0].touches, 4, "unlock is one touch");
    assert!(same_kek(&kek, &back));
}

#[test]
fn by_default_the_pin_is_required_at_enroll_and_unlock() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    assert!(matches!(
        fido2::enroll(&mut keys, None, Verification::PinOrUv),
        Err(Error::Fido2PinRequired)
    ));
    let (_, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    assert!(matches!(
        fido2::unlock(&mut keys, &slot, None),
        Err(Error::Fido2PinRequired)
    ));
    assert!(matches!(
        fido2::unlock(&mut keys, &slot, Some("000000")),
        Err(Error::Fido2PinInvalid)
    ));
}

#[test]
fn a_key_with_built_in_uv_uses_it_instead_of_a_pin() {
    let mut keys = MockKeys::one(MockAuthenticator::with_uv());
    let (kek, slot) = fido2::enroll(&mut keys, None, Verification::PinOrUv).unwrap();
    assert!(slot.uv_required && !slot.pin_required);
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, None).unwrap()
    ));
}

/// A key with neither PIN nor UV would let anyone holding it unlock, so by
/// default it is refused; touch-only is an explicit opt-in.
#[test]
fn a_bare_key_is_refused_unless_touch_only_is_chosen() {
    let mut keys = MockKeys::one(MockAuthenticator::new());
    assert!(matches!(
        fido2::enroll(&mut keys, None, Verification::PinOrUv),
        Err(Error::Fido2PinNotSet)
    ));
    let (kek, slot) = fido2::enroll(&mut keys, None, Verification::TouchOnly).unwrap();
    assert!(!slot.uv_required && !slot.pin_required);
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, None).unwrap()
    ));
}

#[test]
fn a_key_without_hmac_secret_is_refused() {
    let mut key = MockAuthenticator::with_pin(PIN);
    key.hmac_secret_supported = false;
    let mut keys = MockKeys::one(key);
    assert!(matches!(
        fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv),
        Err(Error::Fido2Unsupported)
    ));
}

#[test]
fn enrollment_needs_exactly_one_key() {
    let mut none = MockKeys::default();
    assert!(matches!(
        fido2::enroll(&mut none, Some(PIN), Verification::PinOrUv),
        Err(Error::Fido2NoDevice)
    ));
    let mut two = MockKeys {
        devices: vec![
            MockAuthenticator::with_pin(PIN),
            MockAuthenticator::with_pin(PIN),
        ],
        ..Default::default()
    };
    assert!(matches!(
        fido2::enroll(&mut two, Some(PIN), Verification::PinOrUv),
        Err(Error::Fido2MultipleDevices)
    ));
}

/// With several keys plugged in, unlock finds the one holding the
/// credential without touching the others (spec §5: preflight).
#[test]
fn unlock_picks_the_right_key_among_several_and_touches_only_it() {
    let mut enrolled = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (kek, slot) = fido2::enroll(&mut enrolled, Some(PIN), Verification::PinOrUv).unwrap();
    let right = enrolled.devices.pop().unwrap();
    let mut keys = MockKeys {
        devices: vec![
            MockAuthenticator::with_pin(PIN),
            right,
            MockAuthenticator::with_pin(PIN),
        ],
        ..Default::default()
    };
    let back = fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap();
    assert!(same_kek(&kek, &back));
    assert_eq!(keys.devices[0].touches, 0);
    assert_eq!(keys.devices[2].touches, 0);
}

#[test]
fn no_key_or_the_wrong_key_is_a_specific_error() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (_, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    assert!(matches!(
        fido2::unlock(&mut MockKeys::default(), &slot, Some(PIN)),
        Err(Error::Fido2NoDevice)
    ));
    let mut other = MockKeys::one(MockAuthenticator::with_pin(PIN));
    assert!(matches!(
        fido2::unlock(&mut other, &slot, Some(PIN)),
        Err(Error::Fido2NoCredential)
    ));
}

#[test]
fn repeated_wrong_pins_block_the_key() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (_, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    let mut last = None;
    for _ in 0..8 {
        last = Some(fido2::unlock(&mut keys, &slot, Some("000000")));
    }
    assert!(matches!(last, Some(Err(Error::Fido2PinBlocked))));
    assert!(matches!(
        fido2::unlock(&mut keys, &slot, Some(PIN)),
        Err(Error::Fido2PinBlocked)
    ));
}

#[test]
fn a_pin_offered_to_a_touch_only_slot_is_ignored() {
    // The prompter may send a PIN it collected for another slot; using it
    // would switch the key to its UV secret and yield the wrong KEK.
    let mut keys = MockKeys::one(MockAuthenticator::new());
    let (kek, slot) = fido2::enroll(&mut keys, None, Verification::TouchOnly).unwrap();
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap()
    ));
}

/// Without verification the key returns its other secret: a thief who can
/// touch a PIN key but not unlock it gets the wrong KEK.
#[test]
fn a_touch_without_verification_cannot_open_a_verified_slot() {
    let mut keys = MockKeys::one(MockAuthenticator::with_uv());
    let (kek, mut slot) = fido2::enroll(&mut keys, None, Verification::PinOrUv).unwrap();
    slot.uv_required = false;
    assert!(!same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, None).unwrap()
    ));
}

/// A key whose preflight errors is "not this key": the right key among
/// several still unlocks, and only if none matches is the error reported.
#[test]
fn a_failing_preflight_does_not_stop_the_search() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    let mut broken = MockAuthenticator::new();
    broken.fail_preflight = true;
    keys.devices.insert(0, broken);
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap()
    ));
    keys.devices[1] = MockAuthenticator::new();
    assert!(matches!(
        fido2::unlock(&mut keys, &slot, Some(PIN)),
        Err(Error::Fido2(m)) if m == "preflight failed"
    ));
}

/// A lone key is preflighted too: with a primary and a backup key
/// enrolled and only the primary plugged in, the backup's slot must not
/// send the backup's PIN to the primary (a wasted retry) or ask for a
/// touch.
#[test]
fn another_keys_slot_does_not_spend_this_keys_pin() {
    let mut backup = MockKeys::one(MockAuthenticator::with_pin("654321"));
    let (_, backup_slot) =
        fido2::enroll(&mut backup, Some("654321"), Verification::PinOrUv).unwrap();
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    let (touches, retries) = (keys.devices[0].touches, keys.devices[0].pin_retries());
    assert!(matches!(
        fido2::unlock(&mut keys, &backup_slot, Some("654321")),
        Err(Error::Fido2NoCredential)
    ));
    assert_eq!(keys.devices[0].touches, touches);
    assert_eq!(keys.devices[0].pin_retries(), retries);
}

/// With one key there is nothing to choose between: if its preflight
/// errors, it is asked directly rather than given up on.
#[test]
fn a_lone_key_whose_preflight_errors_is_asked_directly() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    keys.devices[0].fail_preflight = true;
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap()
    ));
}

/// Enrollment uses credProtect level 2, which the multi-key preflight
/// depends on: a level-3 credential is invisible to it.
#[test]
fn enrollment_uses_cred_protect_level_2() {
    assert_eq!(CRED_PROTECT, CredProtect::UvOptionalWithId);
    let mut hidden = MockAuthenticator::with_pin(PIN);
    let id = hidden
        .make_credential(fido2::RP_ID, CredProtect::UvRequired, Some(PIN), false)
        .unwrap();
    assert!(!hidden.has_credential(fido2::RP_ID, &id).unwrap());
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (_, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    assert!(
        keys.devices[0]
            .has_credential(fido2::RP_ID, &slot.credential_id)
            .unwrap()
    );
}

/// A CTAP 2.0 key returns the same `hmac-secret` with and without PIN/UV,
/// so its PIN would protect nothing: a thief with the key could open the
/// slot with a touch. PIN/UV enrollment checks and refuses such a key;
/// touch-only enrollment (which claims no more) still works.
#[test]
fn a_key_without_separate_uv_secrets_is_refused_for_pin_slots() {
    let mut old = MockAuthenticator::with_pin(PIN);
    old.single_cred_random = true;
    let mut keys = MockKeys::one(old);
    assert!(matches!(
        fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv),
        Err(Error::Fido2NoUvSeparation)
    ));
    let mut old = MockAuthenticator::new();
    old.single_cred_random = true;
    let mut keys = MockKeys::one(old);
    fido2::enroll(&mut keys, None, Verification::TouchOnly).unwrap();
}

/// A key that claims every credential is asked first but cannot produce
/// the secret; the search goes on to the key that really holds it.
#[test]
fn a_key_claiming_every_credential_does_not_hide_the_right_one() {
    let mut keys = MockKeys::one(MockAuthenticator::new());
    let (kek, slot) = fido2::enroll(&mut keys, None, Verification::TouchOnly).unwrap();
    let mut liar = MockAuthenticator::new();
    liar.lie_preflight = true;
    keys.devices.insert(0, liar);
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, None).unwrap()
    ));
}

/// A second key that is plugged in but cannot be opened (a browser holds
/// it) still makes enrollment ambiguous; unlock is unaffected.
#[test]
fn an_unopenable_second_key_still_makes_enrollment_ambiguous() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    keys.unopenable = 1;
    assert!(matches!(
        fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv),
        Err(Error::Fido2MultipleDevices)
    ));
    keys.unopenable = 0;
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    keys.unopenable = 1;
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, Some(PIN)).unwrap()
    ));
}

/// Touch-only on a key that has a PIN: keys that insist on the PIN to
/// create a credential get it for that step only; the slot itself needs
/// no PIN.
#[test]
fn touch_only_enrollment_on_a_pin_key_uses_the_pin_only_to_create() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::TouchOnly).unwrap();
    assert!(!slot.pin_required && !slot.uv_required);
    assert!(same_kek(
        &kek,
        &fido2::unlock(&mut keys, &slot, None).unwrap()
    ));
}

#[test]
fn any_present_reflects_connected_keys() {
    assert!(!MockKeys::default().any_present());
    assert!(MockKeys::one(MockAuthenticator::new()).any_present());
}

#[test]
fn a_fido2_slot_unlocks_a_vault_end_to_end() {
    let mut keys = MockKeys::one(MockAuthenticator::with_pin(PIN));
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::generate().unwrap();
    v.add_recovery_slot("recovery", &rk.recipient().public_key())
        .unwrap();
    let (kek, slot) = fido2::enroll(&mut keys, Some(PIN), Verification::PinOrUv).unwrap();
    let id = v
        .add_keyslot("yubikey", SlotKind::Fido2(slot), &kek)
        .unwrap();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    let stored = locked
        .keyslots()
        .find_map(|s| match &s.kind {
            SlotKind::Fido2(f) if s.id == id => Some(f.clone()),
            _ => None,
        })
        .unwrap();
    let kek = fido2::unlock(&mut keys, &stored, Some(PIN)).unwrap();
    assert_eq!(locked.unlock(id, &kek).unwrap().vault_id(), v.vault_id());
}
