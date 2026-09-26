//! Golden vault files. Every released format version gets a file here,
//! and every later release must still open it. Never regenerate an
//! existing version's file; add a new one for a new version.

use std::collections::BTreeMap;
use std::path::PathBuf;

use aleph_core::model::DEFAULT_ALIAS;
use aleph_core::{
    Argon2Kind, Argon2Params, Item, LockedVault, RecoveryKey, SecretBytes, UnlockedVault,
};

const RECOVERY_KEY: &str = "000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG-CC6W";
const PASSPHRASE: &[u8] = b"aleph golden v1";

fn golden_path(version: u32) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/v{version}.aleph"))
}

#[test]
fn golden_v1_opens_with_recovery_key_and_passphrase() {
    let locked = LockedVault::read(&golden_path(1)).expect("golden v1 file present");
    let slots = locked.keyslots();
    assert_eq!(slots.len(), 2);

    let rk = RecoveryKey::parse(RECOVERY_KEY).unwrap();
    for (slot, secret) in [
        (slots[0].id, rk.as_bytes().as_slice()),
        (slots[1].id, PASSPHRASE),
    ] {
        let v = locked.unlock_argon2(slot, secret).unwrap();
        let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap();
        assert_eq!(login.label, "Login");
        assert_eq!(login.items.len(), 1);
        let item = &login.items[0];
        assert_eq!(item.label, "golden item");
        assert_eq!(
            item.attributes.get("service").map(String::as_str),
            Some("example")
        );
        assert_eq!(item.secret.expose(), b"golden secret");
    }
}

/// Run once, by hand, when introducing a new format version:
/// `cargo test -p aleph-core --test golden -- --ignored regenerate`
#[test]
#[ignore]
fn regenerate_golden_v1() {
    let path = golden_path(1);
    assert!(
        !path.exists(),
        "refusing to overwrite an existing golden file"
    );
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::parse(RECOVERY_KEY).unwrap();
    v.add_argon2_keyslot(
        "recovery",
        Argon2Kind::RecoveryKey,
        rk.as_bytes(),
        Argon2Params::INSECURE_TEST,
    )
    .unwrap();
    v.add_argon2_keyslot(
        "passphrase",
        Argon2Kind::Passphrase,
        PASSPHRASE,
        Argon2Params::INSECURE_TEST,
    )
    .unwrap();
    let login = v.body().resolve_alias(DEFAULT_ALIAS).unwrap().id;
    let attrs = BTreeMap::from([("service".to_string(), "example".to_string())]);
    v.body_mut().collection_mut(login).unwrap().upsert(
        Item::new(
            "golden item",
            attrs,
            SecretBytes::new(b"golden secret".to_vec()),
            "text/plain",
        ),
        false,
    );
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, v.to_bytes().unwrap()).unwrap();
}
