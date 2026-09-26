mod common;

use std::os::unix::fs::PermissionsExt;

use aleph_core::LockedVault;
use common::*;

#[test]
fn write_is_atomic_private_and_keeps_a_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aleph").join("vault.aleph");
    let (mut v, rk, rec, _) = sample();

    v.write(&path).unwrap();
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!path.with_file_name("vault.aleph.bak").exists());

    let first = std::fs::read(&path).unwrap();
    v.body_mut().collections[0].label = "Renamed".into();
    v.write(&path).unwrap();

    let bak = path.with_file_name("vault.aleph.bak");
    assert_eq!(std::fs::read(&bak).unwrap(), first);
    assert_eq!(
        std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!path.with_file_name("vault.aleph.tmp").exists());

    let reopened = LockedVault::read(&path)
        .unwrap()
        .unlock_argon2(rec, rk.as_bytes())
        .unwrap();
    assert_eq!(reopened.body().collections[0].label, "Renamed");
}

#[test]
fn stale_temp_file_from_a_crashed_write_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    std::fs::write(dir.path().join("vault.aleph.tmp"), b"half-written garbage").unwrap();
    let (v, _, _, pass) = sample();
    v.write(&path).unwrap();
    assert!(!dir.path().join("vault.aleph.tmp").exists());
    LockedVault::read(&path)
        .unwrap()
        .unlock_argon2(pass, PASSPHRASE)
        .unwrap();
}
