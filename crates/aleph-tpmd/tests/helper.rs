use std::time::Instant;

use aleph_tpm_proto::{Failure, Parent, Request, Response, SealedObject, Secret};
use aleph_tpmd::limiter::{FAILURES_PER_UID, reserve_threshold, window};
use aleph_tpmd::server::Policy;
use aleph_tpmd::testing::SwTpm;

const UID: u32 = 1000;
const PW: &[u8] = b"login password";

fn seal(h: &aleph_tpmd::Helper, uid: u32, pw: &[u8]) -> (SealedObject, Vec<u8>) {
    match h.handle(
        uid,
        Request::Seal {
            secret: Secret(pw.to_vec()),
        },
    ) {
        Response::Sealed { object, kek } => (object, kek.0.clone()),
        other => panic!("seal: {other:?}"),
    }
}

fn unseal(h: &aleph_tpmd::Helper, uid: u32, object: &SealedObject, pw: &[u8]) -> Response {
    h.handle(
        uid,
        Request::Unseal {
            object: object.clone(),
            secret: Secret(pw.to_vec()),
        },
    )
}

fn unsealed_kek(r: Response) -> Vec<u8> {
    match r {
        Response::Unsealed { kek } => kek.0.clone(),
        other => panic!("unseal: {other:?}"),
    }
}

#[test]
fn seal_then_unseal_returns_the_same_kek() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, kek) = seal(&h, UID, PW);
    assert_eq!(kek.len(), 32);
    assert_eq!(object.auth_salt.len(), 16);
    assert!(!object.srk_name.is_empty());
    assert_eq!(unsealed_kek(unseal(&h, UID, &object, PW)), kek);
}

#[test]
fn a_slot_survives_a_new_helper_process() {
    // aleph's primary is re-derived, not persisted: a fresh helper (as after
    // a reboot) finds the same parent Name and unseals.
    let sw = SwTpm::start();
    let (object, kek) = seal(&sw.helper(), UID, PW);
    assert_eq!(unsealed_kek(unseal(&sw.helper(), UID, &object, PW)), kek);
}

#[test]
fn each_seal_gets_its_own_salt_and_kek() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (a, ka) = seal(&h, UID, PW);
    let (b, kb) = seal(&h, UID, PW);
    assert_ne!(a.auth_salt, b.auth_salt);
    assert_ne!(ka, kb);
}

#[test]
fn a_wrong_password_is_auth_failed() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    assert_eq!(
        unseal(&h, UID, &object, b"wrong"),
        Response::Failed(Failure::AuthFailed)
    );
}

/// Another local user who copies your blobs gets nothing, even with your
/// password: the uid is part of the auth value and of the sealed payload.
#[test]
fn another_user_cannot_unseal_even_with_the_password() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    let r = unseal(&h, UID + 1, &object, PW);
    assert!(
        matches!(
            r,
            Response::Failed(Failure::AuthFailed | Failure::WrongUser)
        ),
        "{r:?}"
    );
}

/// A tampered or foreign parent Name is refused before the parent salts a
/// session and before any password attempt reaches the TPM.
#[test]
fn a_parent_name_mismatch_is_refused_without_an_auth_attempt() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (mut object, _) = seal(&h, UID, PW);
    object.srk_name[5] ^= 1;
    for _ in 0..(FAILURES_PER_UID + 2) {
        assert_eq!(
            unseal(&h, UID, &object, PW),
            Response::Failed(Failure::ParentMismatch)
        );
    }
    // No failures were counted against the user or the TPM.
    object.srk_name[5] ^= 1;
    unsealed_kek(unseal(&h, UID, &object, PW));
}

#[test]
fn a_slot_from_another_tpm_is_a_parent_mismatch() {
    // Each TPM's seed differs, so aleph's primary has a different Name.
    let (a, b) = (SwTpm::start(), SwTpm::start());
    let (object, _) = seal(&a.helper(), UID, PW);
    assert_eq!(
        unseal(&b.helper(), UID, &object, PW),
        Response::Failed(Failure::ParentMismatch)
    );
}

#[test]
fn corrupt_objects_are_errors_not_panics() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);

    let mut bad = object.clone();
    bad.public = vec![0xff; 7];
    assert!(matches!(
        unseal(&h, UID, &bad, PW),
        Response::Failed(Failure::Malformed(_))
    ));

    let mut bad = object.clone();
    bad.auth_salt = vec![0; 3];
    assert!(matches!(
        unseal(&h, UID, &bad, PW),
        Response::Failed(Failure::Malformed(_))
    ));

    let mut bad = object.clone();
    let n = bad.private.len();
    bad.private[n - 1] ^= 1; // the TPM's integrity check rejects it
    assert!(matches!(unseal(&h, UID, &bad, PW), Response::Failed(_)));
}

#[test]
fn failed_unseals_are_rate_limited_per_user() {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    let t0 = Instant::now();
    let attempt = |pw: &[u8], uid: u32, at| {
        h.handle_at(
            uid,
            Request::Unseal {
                object: object.clone(),
                secret: Secret(pw.to_vec()),
            },
            at,
        )
    };
    for _ in 0..FAILURES_PER_UID {
        assert_eq!(
            attempt(b"wrong", UID, t0),
            Response::Failed(Failure::AuthFailed)
        );
    }
    // Blocked now, even with the right password: the TPM is not asked.
    assert_eq!(
        attempt(PW, UID, t0),
        Response::Failed(Failure::RateLimited {
            retry_after: window(600).as_secs() as u32
        })
    );
    // Another user is unaffected.
    let (other, _) = seal(&h, UID + 1, PW);
    assert!(matches!(
        h.handle_at(
            UID + 1,
            Request::Unseal {
                object: other,
                secret: Secret(PW.to_vec())
            },
            t0
        ),
        Response::Unsealed { .. }
    ));
    // After the window, the user may try again.
    assert!(matches!(
        attempt(PW, UID, t0 + window(600)),
        Response::Unsealed { .. }
    ));
}

/// Transient handles and sessions must be flushed on every path: a TPM has
/// only a few slots, and a leak would fail within a handful of operations.
#[test]
fn many_operations_do_not_exhaust_tpm_handles() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    let mut mismatched = object.clone();
    mismatched.srk_name[0] ^= 1;
    for _ in 0..40 {
        unsealed_kek(unseal(&h, UID, &object, PW));
        seal(&h, UID, PW);
        assert_eq!(
            unseal(&h, UID, &mismatched, PW),
            Response::Failed(Failure::ParentMismatch)
        );
        assert!(matches!(
            h.handle(UID, Request::Status {}),
            Response::Status(_)
        ));
    }
}

#[test]
fn repeated_wrong_passwords_reach_tpm_lockout() {
    // Bypass the helper's limits to reach the TPM's own lockout.
    let sw = SwTpm::start();
    sw.set_da_parameters(3, 600, 86400);
    let mut tpm = sw.tpm();
    let (object, _) = tpm.seal(UID, PW).unwrap();
    let mut saw_lockout = false;
    for _ in 0..64 {
        match tpm.unseal(UID, &object, b"0000") {
            Err(aleph_tpmd::TpmError::AuthFailed) => {}
            Err(aleph_tpmd::TpmError::Lockout) => {
                saw_lockout = true;
                break;
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert!(saw_lockout, "TPM never entered lockout");
    let status = tpm.status().unwrap();
    assert!(status.in_lockout);
    assert_eq!(status.failed_tries, status.max_tries);
}

#[test]
fn status_reports_a_fresh_tpm() {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let Response::Status(s) = sw.helper().handle(UID, Request::Status {}) else {
        panic!()
    };
    assert_eq!(s.parent, Parent::AlephPrimary);
    assert!(!s.owner_auth_set);
    assert!(!s.lockout_auth_set);
    assert!(!s.in_lockout);
    assert_eq!(
        (s.max_tries, s.recovery_time, s.lockout_recovery),
        (32, 600, 86400)
    );
    assert_eq!(s.failed_tries, 0);
}

/// With `ownerAuth` set, aleph's primary cannot be created; the persistent
/// SRK is used instead, and its Name is what the slot records.
#[test]
fn with_owner_auth_set_the_persistent_srk_is_used() {
    let sw = SwTpm::start();
    // One long-lived helper throughout: it must notice ownerAuth change.
    let h = sw.helper();
    // A slot sealed under aleph's primary before ownerAuth was set...
    let (old, _) = seal(&h, UID, PW);
    sw.provision_persistent_srk();
    sw.set_owner_auth();
    let Response::Status(s) = h.handle(UID, Request::Status {}) else {
        panic!()
    };
    assert_eq!(s.parent, Parent::PersistentSrk);
    assert!(s.owner_auth_set);
    let (object, kek) = seal(&h, UID, PW);
    assert_ne!(object.srk_name, old.srk_name);
    assert_eq!(unsealed_kek(unseal(&h, UID, &object, PW)), kek);
    // ...no longer finds its parent: re-enrollment is needed (setup explains).
    assert_eq!(
        unseal(&h, UID, &old, PW),
        Response::Failed(Failure::ParentMismatch)
    );
}

#[test]
fn with_owner_auth_set_and_no_srk_enrollment_is_refused() {
    let sw = SwTpm::start();
    sw.set_owner_auth();
    let h = sw.helper();
    let Response::Status(s) = h.handle(UID, Request::Status {}) else {
        panic!()
    };
    assert_eq!(s.parent, Parent::Unavailable);
    assert_eq!(
        h.handle(
            UID,
            Request::Seal {
                secret: Secret(PW.to_vec())
            }
        ),
        Response::Failed(Failure::NoParent)
    );
}

/// The attack the budgets exist for: many uids (a compromised account can
/// have several, and every login uid has its own budget) guessing across
/// many recovery windows. The TPM must never reach lockout, which would
/// also block disk unlock and survive reboot; refusing with `Exhausted` is the
/// accepted cost.
#[test]
fn guessing_from_many_uids_over_many_windows_never_locks_the_tpm() {
    for max_tries in [3, 32] {
        let sw = SwTpm::start();
        sw.set_da_parameters(max_tries, 600, 86400);
        let h = sw.helper();
        let t0 = Instant::now();
        let uids: Vec<u32> = (0..20).map(|i| UID + i).collect();
        let objects: Vec<_> = uids.iter().map(|&u| seal(&h, u, PW).0).collect();
        let mut exhausted = 0;
        for w in 0..5 {
            let at = t0 + window(600) * w;
            for (&uid, object) in uids.iter().zip(&objects) {
                for _ in 0..(FAILURES_PER_UID + 1) {
                    let reply = h.handle_at(
                        uid,
                        Request::Unseal {
                            object: object.clone(),
                            secret: Secret(b"guess".to_vec()),
                        },
                        at,
                    );
                    match reply {
                        Response::Failed(Failure::AuthFailed | Failure::RateLimited { .. }) => {}
                        // At the threshold, one recovery time frees a try.
                        Response::Failed(Failure::Exhausted {
                            retry_after: Some(600),
                        }) => exhausted += 1,
                        other => panic!("max_tries {max_tries}: {other:?}"),
                    }
                }
            }
        }
        assert!(exhausted > 0, "the reserve never engaged");
        let Response::Status(s) = h.handle(UID, Request::Status {}) else {
            panic!()
        };
        assert!(!s.in_lockout, "max_tries {max_tries}: TPM locked out");
        assert_eq!(s.failed_tries, reserve_threshold(max_tries));
        // Disk unlock (or anything else) still has the reserve.
        assert!(s.max_tries - s.failed_tries >= 1);
    }
}

/// An object whose auth value is right but whose payload names another
/// uid is `WrongUser`, and counts against the caller.
#[test]
fn a_payload_for_another_uid_is_wrong_user() {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let (object, _) = sw.tpm().seal_with_payload_uid(UID, UID + 1, PW).unwrap();
    let h = sw.helper();
    let t0 = Instant::now();
    let attempt = || {
        h.handle_at(
            UID,
            Request::Unseal {
                object: object.clone(),
                secret: Secret(PW.to_vec()),
            },
            t0,
        )
    };
    for _ in 0..FAILURES_PER_UID {
        assert_eq!(attempt(), Response::Failed(Failure::WrongUser));
    }
    assert!(matches!(
        attempt(),
        Response::Failed(Failure::RateLimited { .. })
    ));
}

#[test]
fn only_login_uids_are_served() {
    let sw = SwTpm::start();
    let h = sw.helper_with(Policy {
        uid_min: 1000,
        uid_max: 60000,
    });
    for uid in [0, 999, 60514, u32::MAX] {
        for request in [
            Request::Seal {
                secret: Secret(PW.to_vec()),
            },
            Request::Status {},
        ] {
            assert_eq!(
                h.handle(uid, request),
                Response::Failed(Failure::NotPermitted),
                "uid {uid}"
            );
        }
    }
    let (object, kek) = seal(&h, 1000, PW);
    assert_eq!(unsealed_kek(unseal(&h, 1000, &object, PW)), kek);
    seal(&h, 60000, PW);
    // systemd-homed users are regular users too.
    seal(&h, 60001, PW);
    seal(&h, 60513, PW);
}

#[test]
fn the_policy_reads_login_defs() {
    let text = "# comment\nUID_MIN\t\t 2000\nUID_MAX 3000\nGID_MIN 5\nUID_MAX_ bogus\n";
    let c_style = "UID_MIN 0x3E8\nUID_MAX 0165140\n";
    assert_eq!(
        Policy::from_login_defs(c_style),
        Policy {
            uid_min: 1000,
            uid_max: 60000
        }
    );
    assert_eq!(
        Policy::from_login_defs(text),
        Policy {
            uid_min: 2000,
            uid_max: 3000
        }
    );
    assert_eq!(
        Policy::from_login_defs(""),
        Policy {
            uid_min: 1000,
            uid_max: 60000
        }
    );
}

/// A TPM whose whole failure budget is the reserve (one try) cannot hold
/// an aleph password slot: sealing is refused up front. With a recovery
/// time of zero the TPM counts no failures, so there is nothing to
/// reserve and slots work.
#[test]
fn a_tpm_with_no_spare_budget_refuses_enrollment() {
    let sw = SwTpm::start();
    sw.set_da_parameters(1, 600, 86400);
    let h = sw.helper();
    assert_eq!(
        h.handle(
            UID,
            Request::Seal {
                secret: Secret(PW.to_vec())
            }
        ),
        Response::Failed(Failure::Exhausted { retry_after: None })
    );
    sw.set_da_parameters(1, 0, 0);
    let (object, kek) = seal(&h, UID, PW);
    assert_eq!(unsealed_kek(unseal(&h, UID, &object, PW)), kek);
    for _ in 0..FAILURES_PER_UID {
        assert_eq!(
            unseal(&h, UID, &object, b"wrong"),
            Response::Failed(Failure::AuthFailed)
        );
    }
    // With one try and counting on, those failures would have locked the
    // TPM; another uid shows it is not.
    let (other, other_kek) = seal(&h, UID + 1, PW);
    assert_eq!(unsealed_kek(unseal(&h, UID + 1, &other, PW)), other_kek);
}

/// With ownerAuth set and no persistent SRK there is no parent at all,
/// which is `NoParent`, not a mismatch.
#[test]
fn with_owner_auth_set_and_no_srk_unseal_is_no_parent() {
    let sw = SwTpm::start();
    let h = sw.helper();
    let (object, _) = seal(&h, UID, PW);
    sw.set_owner_auth();
    assert_eq!(
        unseal(&h, UID, &object, PW),
        Response::Failed(Failure::NoParent)
    );
}

/// A slot sealed under the persistent SRK keeps working after `ownerAuth`
/// is cleared, although new slots then go under aleph's primary.
#[test]
fn a_slot_unseals_under_whichever_parent_it_names() {
    let sw = SwTpm::start();
    sw.provision_persistent_srk();
    sw.set_owner_auth();
    let (object, kek) = seal(&sw.helper(), UID, PW);
    sw.clear_owner_auth();
    let h = sw.helper();
    let Response::Status(s) = h.handle(UID, Request::Status {}) else {
        panic!()
    };
    assert_eq!(s.parent, Parent::AlephPrimary);
    assert_eq!(unsealed_kek(unseal(&h, UID, &object, PW)), kek);
    let (fresh, _) = seal(&h, UID, PW);
    assert_ne!(fresh.srk_name, object.srk_name);
}
