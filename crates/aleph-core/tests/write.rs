mod common;

use std::os::unix::fs::PermissionsExt;

use aleph_core::LockedVault;
use common::*;

fn mode(path: &std::path::Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A pre-existing temp file created by some other tool with loose
/// permissions must not hand those permissions to the vault or backup.
#[test]
fn world_readable_leftover_temp_files_do_not_loosen_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let (v, ..) = sample();
    v.write(&path).unwrap();
    for name in ["vault.aleph.tmp", "vault.aleph.bak.tmp"] {
        let p = dir.path().join(name);
        std::fs::write(&p, b"stale").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    v.write(&path).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&dir.path().join("vault.aleph.bak")), 0o600);
}

#[test]
fn path_without_a_file_name_is_an_error_not_a_panic() {
    let (v, ..) = sample();
    for p in ["..", "/"] {
        assert!(
            matches!(
                v.write(std::path::Path::new(p)),
                Err(aleph_core::Error::Io(_))
            ),
            "{p}"
        );
    }
}

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
