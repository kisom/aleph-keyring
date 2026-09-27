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
        .unlock_recovery(rec, &rk)
        .unwrap();
    assert_eq!(reopened.body().collections[0].label, "Renamed");
}

#[test]
fn stale_temp_file_from_a_crashed_write_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    std::fs::write(dir.path().join("vault.aleph.tmp"), b"half-written garbage").unwrap();
    let (v, _, _, pw) = sample();
    v.write(&path).unwrap();
    assert!(!dir.path().join("vault.aleph.tmp").exists());
    LockedVault::read(&path)
        .unwrap()
        .unlock_login_password(pw, PASSWORD)
        .unwrap();
}

/// Two writers (say, the daemon and a CLI run against the same file) must
/// not interleave: one could unlink the other's temp file and rename a
/// half-written one over the vault. Every write must succeed and leave an
/// intact vault and backup.
#[test]
fn concurrent_writers_never_corrupt_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let (mut v, _, _, pw) = sample();
    // A larger file widens the window between create and rename.
    v.body_mut().collections[0].label = "x".repeat(256 << 10);
    v.write(&path).unwrap();
    let v = std::sync::Arc::new(v);
    let writers: Vec<_> = (0..8)
        .map(|_| {
            let (v, path) = (v.clone(), path.clone());
            std::thread::spawn(move || (0..5).map(|_| v.write(&path).unwrap()).collect::<Vec<_>>())
        })
        .collect();
    let mut marks: Vec<_> = writers
        .into_iter()
        .flat_map(|w| w.join().unwrap())
        .collect();
    // Every write got its own generation, and the file on disk (and the
    // vault's own mark) is exactly the last one written.
    marks.sort_by_key(|m| m.generation);
    marks.dedup_by_key(|m| m.generation);
    assert_eq!(marks.len(), 40);
    let on_disk = LockedVault::read(&path).unwrap().mark();
    assert_eq!(on_disk, *marks.last().unwrap());
    assert_eq!(v.mark(), on_disk);
    for p in [path.clone(), dir.path().join("vault.aleph.bak")] {
        LockedVault::read(&p)
            .unwrap()
            .unlock_login_password(pw, PASSWORD)
            .unwrap();
    }
}

/// `rename` would replace a symlink (say, into a sync folder) with a
/// regular file, silently breaking the link. Refuse instead.
#[test]
fn a_symlinked_vault_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("synced.aleph");
    let (v, ..) = sample();
    v.write(&target).unwrap();
    let link = dir.path().join("vault.aleph");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(matches!(v.write(&link), Err(aleph_core::Error::Io(_))));
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn a_group_or_world_accessible_vault_directory_is_tightened() {
    let dir = tempfile::tempdir().unwrap();
    let vault_dir = dir.path().join("aleph");
    std::fs::create_dir(&vault_dir).unwrap();
    std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (v, ..) = sample();
    v.write(&vault_dir.join("vault.aleph")).unwrap();
    assert_eq!(mode(&vault_dir), 0o700);
}

/// A failed write must not advance the vault's generation: otherwise the
/// daemon would record a generation that never reached the disk.
#[test]
fn a_failed_write_does_not_advance_the_generation() {
    let dir = tempfile::tempdir().unwrap();
    // A directory where the vault should be: serialization succeeds, then
    // the write itself fails.
    let path = dir.path().join("vault.aleph");
    std::fs::create_dir(&path).unwrap();
    let (v, ..) = sample();
    let before = v.mark();
    assert!(v.write(&path).is_err());
    assert_eq!(v.mark(), before);
}

/// After a rotation, the first write must not leave the pre-rotation file
/// (which still holds the removed slot and the old MK) in `.bak`.
#[test]
fn the_backup_after_a_rotation_does_not_keep_the_removed_slot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.aleph");
    let (mut v, _, _, pw) = sample();
    let kek = aleph_core::Kek::generate().unwrap();
    let fido = v
        .add_keyslot(
            "yubikey",
            aleph_core::SlotKind::Fido2(aleph_core::Fido2Slot {
                credential_id: vec![1; 16],
                salt: [2; 32],
                uv_required: true,
                pin_required: true,
            }),
            &kek,
        )
        .unwrap();
    v.write(&path).unwrap();
    let pw_kek = v.login_password_kek(pw, PASSWORD).unwrap();
    v.remove_keyslot(fido, &[(pw, &pw_kek)]).unwrap();
    v.write(&path).unwrap();
    let bak = LockedVault::read(&path.with_file_name("vault.aleph.bak")).unwrap();
    assert!(bak.keyslots().all(|s| s.id != fido));
    // Ordinary writes still keep the previous version as the backup.
    let before = std::fs::read(&path).unwrap();
    v.write(&path).unwrap();
    assert_eq!(
        std::fs::read(path.with_file_name("vault.aleph.bak")).unwrap(),
        before
    );
}
