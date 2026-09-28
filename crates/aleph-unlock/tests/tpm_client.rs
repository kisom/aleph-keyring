use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::Duration;

use aleph_core::{LockedVault, RecoveryKey, SlotKind, UnlockedVault};
use aleph_tpmd::server::Policy;
use aleph_tpmd::testing::SwTpm;
use aleph_unlock::{Error, TpmClient};

const PW: &[u8] = b"login password";

/// A real aleph-tpmd helper (on a private swtpm) serving a socket in a
/// temp directory; returns a client for it.
struct Helper {
    _sw: SwTpm,
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    client: TpmClient,
}

fn helper() -> Helper {
    helper_with(SwTpm::start(), Policy::allow_all())
}

fn helper_with(sw: SwTpm, policy: Policy) -> Helper {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let helper = Arc::new(sw.helper_with(policy));
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, helper));
    Helper {
        _sw: sw,
        _dir: dir,
        client: TpmClient::new(path.clone()),
        path,
    }
}

fn same_kek(a: &aleph_core::Kek, b: &aleph_core::Kek) -> bool {
    let mk = aleph_core::KeyHandle::generate().unwrap();
    let w = mk.wrap(a, b"t").unwrap();
    aleph_core::KeyHandle::unwraps_to(b, &w, b"t", &mk.id())
}

#[test]
fn seal_then_unseal_through_the_helper() {
    let h = helper();
    let (kek, slot) = h.client.seal(PW).unwrap();
    assert_eq!(slot.auth_salt.len(), 16);
    assert!(same_kek(&kek, &h.client.unseal(&slot, PW).unwrap()));
}

#[test]
fn helper_failures_map_to_specific_errors() {
    let h = helper();
    let (_, slot) = h.client.seal(PW).unwrap();
    assert!(matches!(
        h.client.unseal(&slot, b"wrong"),
        Err(Error::TpmAuthFailed)
    ));
    let mut foreign = slot.clone();
    foreign.srk_name[3] ^= 1;
    assert!(matches!(
        h.client.unseal(&foreign, PW),
        Err(Error::TpmParentMismatch)
    ));
    let mut corrupt = slot.clone();
    corrupt.public = vec![0xff; 5];
    assert!(matches!(
        h.client.unseal(&corrupt, PW),
        Err(Error::TpmSlotMalformed(_))
    ));
}

#[test]
fn helper_refusals_map_to_specific_errors() {
    // A TPM allowing one failure has no budget to spare: enrollment is
    // refused.
    let sw = SwTpm::start();
    sw.set_da_parameters(1, 600, 86400);
    let h = helper_with(sw, Policy::allow_all());
    assert!(matches!(
        h.client.seal(PW),
        Err(Error::TpmExhausted { retry_after: None })
    ));

    // With the reserve reached (2 failures of 3, spent directly on the
    // TPM), unseals are refused before they reach it.
    let sw = SwTpm::start();
    sw.set_da_parameters(3, 600, 86400);
    let (object, _) = sw.tpm().seal(0, b"other").unwrap();
    for _ in 0..2 {
        assert!(sw.tpm().unseal(0, &object, b"wrong").is_err());
    }
    let h = helper_with(sw, Policy::allow_all());
    let (_, slot) = h.client.seal(PW).unwrap();
    assert!(matches!(
        h.client.unseal(&slot, PW),
        Err(Error::TpmExhausted { retry_after: Some(d) }) if d == Duration::from_secs(600)
    ));

    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let others = Policy {
        uid_min: me.wrapping_add(1),
        uid_max: me.wrapping_add(1),
    };
    let h = helper_with(SwTpm::start(), others);
    assert!(matches!(h.client.seal(PW), Err(Error::TpmNotPermitted)));
}

/// `Busy` is transient (here: another connection of ours holds our uid's
/// slot until the helper's request deadline cuts it off), so the client
/// retries through it.
#[test]
fn the_client_retries_while_the_helper_is_busy() {
    use std::io::Write;
    let h = helper();
    let mut hog = std::os::unix::net::UnixStream::connect(&h.path).unwrap();
    hog.write_all(&100u32.to_be_bytes()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(h.client.status().is_ok());
}

/// `status_now` asks once: while the helper is busy it says so at once
/// instead of waiting the helper out (for `alephctl status`).
#[test]
fn status_now_does_not_wait_out_a_busy_helper() {
    use std::io::Write;
    let h = helper();
    assert!(h.client.status_now().is_ok());
    let mut hog = std::os::unix::net::UnixStream::connect(&h.path).unwrap();
    hog.write_all(&100u32.to_be_bytes()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let t = std::time::Instant::now();
    assert!(matches!(h.client.status_now(), Err(Error::TpmBusy)));
    assert!(t.elapsed() < std::time::Duration::from_millis(500));
}

#[test]
fn an_empty_password_is_refused_locally() {
    let h = helper();
    assert!(matches!(h.client.seal(b""), Err(Error::SecretRequired)));
    let (_, slot) = h.client.seal(PW).unwrap();
    assert!(matches!(
        h.client.unseal(&slot, b""),
        Err(Error::SecretRequired)
    ));
}

#[test]
fn a_missing_helper_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let client = TpmClient::new(dir.path().join("nobody-home.sock"));
    assert!(matches!(client.seal(PW), Err(Error::TpmUnavailable(_))));
    assert!(matches!(client.status(), Err(Error::TpmUnavailable(_))));
}

#[test]
fn status_comes_through() {
    let h = helper();
    let s = h.client.status().unwrap();
    assert_eq!(s.parent, aleph_tpm_proto::Parent::AlephPrimary);
}

#[test]
fn a_tpm_slot_unlocks_a_vault_end_to_end() {
    let h = helper();
    let mut v = UnlockedVault::create().unwrap();
    let rk = RecoveryKey::generate().unwrap();
    v.add_recovery_slot("recovery", &rk.recipient().public_key())
        .unwrap();
    let (kek, slot) = h.client.seal(PW).unwrap();
    let id = v.add_keyslot("tpm", SlotKind::Tpm(slot), &kek).unwrap();
    let locked = LockedVault::from_bytes(&v.to_bytes().unwrap()).unwrap();
    let stored = locked
        .keyslots()
        .find_map(|s| match &s.kind {
            SlotKind::Tpm(t) if s.id == id => Some(t.clone()),
            _ => None,
        })
        .unwrap();
    let kek = h.client.unseal(&stored, PW).unwrap();
    assert_eq!(locked.unlock(id, &kek).unwrap().vault_id(), v.vault_id());
}
