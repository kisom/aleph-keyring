//! Opt-in test against a real FIDO2 security key (not run in CI).
//!
//! With one key plugged in (PIN set, or built-in UV):
//! `ALEPH_FIDO2_PIN=<pin, if set> cargo test -p aleph-unlock --test fido2_hardware -- --ignored`
//! Touch the key three times to enroll, once to unlock, then twice more.

use aleph_unlock::fido2::libfido2::Libfido2Keys;
use aleph_unlock::fido2::{self, Keys, Verification};

#[test]
#[ignore]
fn hardware_key_enroll_and_unlock() {
    let pin = std::env::var("ALEPH_FIDO2_PIN").ok();
    let mut keys = Libfido2Keys::new();
    assert!(keys.any_present(), "plug in a FIDO2 key");
    eprintln!("touch the key three times to enroll, once to unlock, then twice more");
    let (kek, slot) = fido2::enroll(&mut keys, pin.as_deref(), Verification::PinOrUv).unwrap();
    let back = fido2::unlock(&mut keys, &slot, pin.as_deref()).unwrap();
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(&kek, b"t").unwrap();
    assert!(aleph_core::KeyHandle::unwraps_to(&back, &w, b"t", &mk.id()));

    // What credProtect level 2 rests on: this key's hmac-secret output
    // without verification differs from the verified one, so a touch
    // alone cannot recompute the KEK.
    let mut devices = keys.devices().unwrap();
    let key = &mut devices[0];
    let id = &slot.credential_id;
    let verified = key
        .hmac_secret(
            fido2::RP_ID,
            id,
            &slot.salt,
            pin.as_deref(),
            slot.uv_required,
        )
        .unwrap();
    let touch_only = key
        .hmac_secret(fido2::RP_ID, id, &slot.salt, None, false)
        .unwrap();
    assert_ne!(*verified, *touch_only);
}
