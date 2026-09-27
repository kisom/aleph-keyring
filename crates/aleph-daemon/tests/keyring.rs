//! The keyring engine against a real TPM helper (swtpm), mock FIDO2 keys,
//! a fixed password check, and a scripted prompter.

use aleph_daemon::testing::*;

fn asks(sent: &[ToPrompter]) -> Vec<(Option<String>, Option<u64>)> {
    sent.iter()
        .filter_map(|m| match m {
            ToPrompter::Ask {
                error, retry_after, ..
            } => Some((error.clone(), *retry_after)),
            _ => None,
        })
        .collect()
}

#[test]
fn create_then_unlock_with_the_login_password() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let s = k.status().unwrap();
    assert!(s.vault && !s.locked);
    let kinds: Vec<&str> = s.keyslots.iter().map(|k| k.kind.as_str()).collect();
    assert_eq!(kinds, ["recovery", "tpm"]);
    k.modify(|b| {
        b.collections[0].upsert(
            aleph_core::Item::new(
                "x",
                Default::default(),
                aleph_core::SecretBytes::new(b"s3cret".to_vec()),
                "text/plain",
            ),
            false,
        );
        Ok(())
    })
    .unwrap();
    k.lock();
    assert!(matches!(k.read(|_| ()), Err(Error::Locked)));
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
    assert!(matches!(
        p.sent().last(),
        Some(ToPrompter::Done { ok: true, .. })
    ));
}

/// The point of the PAM check: a mistyped password is refused before the
/// TPM sees it, so it costs no dictionary-attack budget.
#[test]
fn typos_never_reach_the_tpm() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    let p = Interactive::new(vec![password("typo"), password("tpyo"), password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    let errors = asks(&p.sent());
    assert_eq!(errors.len(), 3);
    assert_eq!(errors[1].0.as_deref(), Some("wrong password"));
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
}

#[test]
fn too_many_typos_are_refused_with_a_wait() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    let mut replies: Vec<_> = (0..5).map(|_| password("typo")).collect();
    replies.push(password(PW));
    let p = Interactive::new(replies);
    // The sixth attempt (the right password) is refused too: blocked, and
    // the conversation ends rather than asking again at once.
    assert!(matches!(
        k.unlock(&mut p.channel(), None),
        Err(Error::TooManyAttempts { .. })
    ));
    let sent = p.sent();
    assert_eq!(asks(&sent).len(), 6);
    assert!(matches!(
        sent.last(),
        Some(ToPrompter::Done { ok: false, message: Some(m) }) if m.contains("too many")
    ));
}

/// A TPM slot that rejects a password PAM accepts (the password changed
/// elsewhere) is marked stale and no longer offered; retrying clears it.
#[test]
fn a_slot_that_rejects_the_current_password_goes_stale() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    // The login password "changed": PAM now accepts only the new one.
    drop(k);
    let backends = Backends {
        tpm: Box::new(TpmClient::new(env.socket.clone())),
        keys: Box::new(MockKeys::default()),
        password: Box::new(Fixed(|p| p == "new password")),
    };
    let k = Keyring::new(&env.paths, backends).unwrap();
    let p = Interactive::new(vec![password("new password")]);
    assert!(k.unlock(&mut p.channel(), None).is_err());
    let errors = asks(&p.sent());
    assert!(
        errors[1].0.as_deref().unwrap().contains("stale"),
        "{errors:?}"
    );
    let tpm = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .find(|s| s.kind == "tpm")
        .unwrap();
    assert!(tpm.stale);
    // With the only password slot stale, there is nothing to offer.
    let p = Interactive::new(vec![]);
    assert!(matches!(
        k.unlock(&mut p.channel(), None),
        Err(Error::NoMethodWorked(_))
    ));
    k.retry_slot(tpm.id).unwrap();
    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
}

/// Refusals that say nothing about the slot (here the TPM's reserve)
/// leave it alone, and the prompter is told when to retry.
#[test]
fn an_exhausted_tpm_does_not_make_the_slot_stale() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    env.sw.set_da_parameters(3, 600, 86400);
    let (object, _) = env.sw.tpm().seal(0, b"other").unwrap();
    for _ in 0..2 {
        assert!(env.sw.tpm().unseal(0, &object, b"wrong").is_err());
    }
    let p = Interactive::new(vec![password(PW)]);
    assert!(k.unlock(&mut p.channel(), None).is_err());
    let errors = asks(&p.sent());
    assert!(
        errors.iter().any(|(_, wait)| *wait == Some(600)),
        "{errors:?}"
    );
    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
}

#[test]
fn a_fido2_keyring_unlocks_with_the_pin_and_retries_a_wrong_one() {
    let env = env();
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    let p = Interactive::new(vec![pin(PIN)]);
    k.create(&mut p.channel(), Method::Fido2).unwrap();
    k.lock();
    let p = Interactive::new(vec![FromPrompter::Fido2 {}, pin("000000"), pin(PIN)]);
    k.unlock(&mut p.channel(), None).unwrap();
    let pins: Vec<Option<String>> = p
        .sent()
        .iter()
        .filter_map(|m| match m {
            ToPrompter::Fido2Pin { error, .. } => Some(error.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(pins, [None, Some("wrong PIN (2 more tries here)".into())]);
    assert!(
        p.sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::Touch { .. }))
    );
}

/// Removing a slot rotates MK: every other slot is re-proven (the password
/// from re-authentication, each key's touch), and one that cannot be
/// presented is dropped only after the user confirms.
#[test]
fn removing_a_slot_rotates_and_drops_absent_keys_only_on_confirmation() {
    let env = env();
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    create_with_password(&k);
    let p = Interactive::new(vec![password(PW), pin(PIN)]);
    k.enroll_fido2(&mut p.channel(), false).unwrap();
    drop(k);
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    let p = Interactive::new(vec![password(PW), pin(PIN)]);
    k.enroll_fido2(&mut p.channel(), false).unwrap();
    let before = k.status().unwrap().keyslots;
    let fido: Vec<_> = before
        .iter()
        .filter(|s| s.kind == "fido2")
        .map(|s| s.id)
        .collect();
    assert_eq!((before.len(), fido.len()), (4, 2));
    // Unplug both keys, then remove the first: the second cannot be
    // re-wrapped.
    drop(k);
    let k = keyring(&env, MockKeys::default());
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    // Re-auth, skip the absent key, decline: nothing changes.
    let decline = Interactive::new(vec![
        password(PW),
        FromPrompter::Cancel {},
        FromPrompter::Confirm { yes: false },
    ]);
    assert!(matches!(
        k.remove_keyslot(&mut decline.channel(), fido[0]),
        Err(Error::Cancelled)
    ));
    assert_eq!(k.status().unwrap().keyslots, before);
    assert!(
        decline
            .sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::Confirm { text } if text.contains("security key")))
    );
    // Accept: both FIDO2 slots are gone; the TPM slot still works.
    let accept = Interactive::new(vec![
        password(PW),
        FromPrompter::Cancel {},
        FromPrompter::Confirm { yes: true },
    ]);
    k.remove_keyslot(&mut accept.channel(), fido[0]).unwrap();
    let kinds: Vec<String> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(kinds, ["recovery", "tpm"]);
    k.lock();
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
}

/// Removing the only unlock method would leave only the recovery key.
#[test]
fn the_last_unlock_method_cannot_be_removed() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let tpm = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .find(|s| s.kind == "tpm")
        .unwrap();
    let p = Interactive::new(vec![password(PW)]);
    assert!(matches!(
        k.remove_keyslot(&mut p.channel(), tpm.id),
        Err(Error::LastMethod)
    ));
    assert_eq!(k.status().unwrap().keyslots.len(), 2);
}

#[test]
fn rotation_keeps_every_presented_slot_working() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let before = k.status().unwrap().keyslots;
    let p = Interactive::new(vec![password(PW)]);
    k.rotate_master(&mut p.channel()).unwrap();
    assert_eq!(k.status().unwrap().keyslots.len(), before.len());
    k.lock();
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
}

#[test]
fn the_last_recovery_slot_cannot_be_removed() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let recovery = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .find(|s| s.kind == "recovery")
        .unwrap();
    let p = Interactive::new(vec![password(PW)]);
    assert!(matches!(
        k.remove_keyslot(&mut p.channel(), recovery.id),
        Err(Error::RecoverySlotRequired)
    ));
    assert_eq!(k.status().unwrap().keyslots.len(), 2);
}

#[test]
fn reissuing_the_recovery_key_replaces_the_slot() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let old = k.status().unwrap().keyslots;
    let p = Interactive::new(vec![password(PW)]);
    k.reissue_recovery(&mut p.channel()).unwrap();
    let new = k.status().unwrap().keyslots;
    let rec = |s: &[aleph_daemon::keyring::SlotInfo]| {
        s.iter()
            .filter(|x| x.kind == "recovery")
            .map(|x| x.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(rec(&new).len(), 1);
    assert_ne!(rec(&new), rec(&old));
}

/// A failed write leaves memory matching the file.
#[test]
fn a_failed_write_restores_the_body() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let vault = env.paths.vault();
    std::fs::rename(&vault, vault.with_extension("moved")).unwrap();
    std::os::unix::fs::symlink(vault.with_extension("moved"), &vault).unwrap();
    let result = k.modify(|b| {
        b.collections[0].upsert(
            aleph_core::Item::new(
                "x",
                Default::default(),
                aleph_core::SecretBytes::new(b"s".to_vec()),
                "text/plain",
            ),
            false,
        );
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 0);
}

/// A rolled-back file opens but refuses writes.
#[test]
fn a_rolled_back_file_is_read_only() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let vault = env.paths.vault();
    let old = std::fs::read(&vault).unwrap();
    k.modify(|_| Ok(())).unwrap();
    k.lock();
    std::fs::write(&vault, old).unwrap();
    let p = Interactive::new(vec![password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
    assert!(matches!(k.modify(|_| Ok(())), Err(Error::Untrusted(_))));
    assert!(matches!(
        p.sent().last(),
        Some(ToPrompter::Done { ok: true, message: Some(m) }) if m.contains("rolled back")
    ));
}

/// Reads never wait for a prompt: while an unlock waits on the user,
/// `read` answers `Locked` at once.
#[test]
fn reads_do_not_wait_for_a_prompt() {
    let env = env();
    let k = Arc::new(keyring(&env, MockKeys::default()));
    create_with_password(&k);
    k.lock();
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut silent =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(3)).unwrap();
    let waiting = {
        let k = k.clone();
        std::thread::spawn(move || k.unlock(&mut silent, None))
    };
    std::thread::sleep(std::time::Duration::from_millis(200));
    let t = std::time::Instant::now();
    assert!(matches!(k.read(|_| ()), Err(Error::Locked)));
    assert!(k.status().unwrap().locked);
    assert!(t.elapsed() < std::time::Duration::from_millis(500));
    assert!(waiting.join().unwrap().is_err());
}

/// `status` never waits for the hardware: while a FIDO2 unlock waits for
/// the key to be plugged in (holding the hardware), it answers at once,
/// with the TPM's usability unknown.
#[test]
fn status_does_not_wait_while_a_key_is_awaited() {
    let env = env();
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    let p = Interactive::new(vec![pin(PIN)]);
    k.create(&mut p.channel(), Method::Fido2).unwrap();
    drop(k);
    let k = Arc::new(keyring(&env, MockKeys::default()));
    let waiting = {
        let k = k.clone();
        std::thread::spawn(move || {
            let p = Interactive::new(vec![FromPrompter::Fido2 {}]);
            k.unlock(&mut p.channel(), None)
        })
    };
    std::thread::sleep(std::time::Duration::from_millis(150));
    let t = std::time::Instant::now();
    let s = k.status().unwrap();
    assert!(
        t.elapsed() < std::time::Duration::from_millis(100),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(s.tpm, None);
    assert!(waiting.join().unwrap().is_err());
}

/// Review C1: a TPM refusal that says nothing about the slot (Busy) stops
/// the rotation; it must never offer to drop a working slot, and reissue
/// must never leave only the recovery key.
#[test]
fn a_busy_tpm_stops_a_rotation_instead_of_dropping_the_slot() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    drop(k);
    // Good for the unlock and the re-authentication; Busy after that.
    let flaky = FlakyTpm {
        inner: TpmClient::new(env.socket.clone()),
        ok: 2.into(),
        then: || aleph_unlock::Error::TpmBusy,
    };
    let k = keyring_with(
        &env,
        Box::new(flaky),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let before = k.status().unwrap().keyslots;
    let p = Interactive::new(vec![password(PW), FromPrompter::Confirm { yes: true }]);
    assert!(matches!(
        k.reissue_recovery(&mut p.channel()),
        Err(Error::Unlock(aleph_unlock::Error::TpmBusy))
    ));
    assert_eq!(k.status().unwrap().keyslots, before);
    let sent = p.sent();
    assert!(!sent.iter().any(|m| matches!(m, ToPrompter::Confirm { .. })));
    // Review I-B: the new recovery key is never shown for a reissue that
    // then fails.
    assert!(
        !sent
            .iter()
            .any(|m| matches!(m, ToPrompter::ShowRecoveryKey { .. }))
    );
}

/// Review C1: reissuing the recovery key never leaves only the recovery
/// slot, even when the user agrees to drop a slot that rejects the
/// password.
#[test]
fn reissue_never_leaves_only_the_recovery_key() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    drop(k);
    let flaky = FlakyTpm {
        inner: TpmClient::new(env.socket.clone()),
        ok: 2.into(),
        then: || aleph_unlock::Error::TpmAuthFailed,
    };
    let k = keyring_with(
        &env,
        Box::new(flaky),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let before: Vec<String> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect();
    let p = Interactive::new(vec![password(PW), FromPrompter::Confirm { yes: true }]);
    assert!(matches!(
        k.reissue_recovery(&mut p.channel()),
        Err(Error::LastMethod)
    ));
    let after: Vec<String> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(after, before);
}

/// Review I5: with a PAM-accepted password, once the newest TPM slot
/// rejects it the older ones are marked stale without being tried (one
/// dictionary-attack failure, not one per slot), and a rotation never
/// unseals a stale slot.
#[test]
fn stale_tpm_slots_cost_one_failure_and_rotation_skips_them() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::one(MockAuthenticator::with_pin(PIN)),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    k.enroll_tpm(&mut Interactive::new(vec![password(PW)]).channel())
        .unwrap();
    k.enroll_fido2(
        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
        false,
    )
    .unwrap();
    k.lock();
    // The login password changed elsewhere: PAM now accepts "new".
    login.set("new");
    assert!(
        k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
            .is_err()
    );
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
    let stale: Vec<_> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .filter(|s| s.stale)
        .collect();
    assert_eq!(stale.len(), 2);
    // Unlock with the key, rotate: the stale slots are offered for removal
    // without another TPM attempt.
    k.unlock(
        &mut Interactive::new(vec![FromPrompter::Fido2 {}, pin(PIN)]).channel(),
        None,
    )
    .unwrap();
    let p = Interactive::new(vec![
        FromPrompter::Fido2 {},
        pin(PIN),
        // (Both TPM slots are stale: no password is asked for.)
        FromPrompter::Confirm { yes: true },
    ]);
    k.rotate_master(&mut p.channel()).unwrap();
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
    let confirm = p
        .sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::Confirm { text } => Some(text),
            _ => None,
        })
        .unwrap();
    assert!(confirm.contains("stale"), "{confirm}");
}

/// Review I6: when PAM cannot check a password, TPM slots are skipped but
/// a login-password slot still opens the vault.
#[test]
fn without_pam_a_login_password_slot_still_unlocks() {
    let env = env();
    // A vault with a login-password slot and (added later) a TPM slot.
    let k = keyring_with(
        &env,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_with_password(&k);
    drop(k);
    let k = keyring(&env, MockKeys::default());
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    k.enroll_tpm(&mut Interactive::new(vec![password(PW)]).channel())
        .unwrap();
    let kinds: Vec<String> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(kinds, ["recovery", "login-password", "tpm"]);
    drop(k);
    // PAM cannot check: the TPM is not risked, the login-password slot opens.
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(Unavailable),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
}

/// A TPM slot is sealed only with the current login password, even when
/// re-authentication used an (outdated) login-password slot.
#[test]
fn a_tpm_slot_is_sealed_only_with_the_current_login_password() {
    let env = env();
    let k = keyring_with(
        &env,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_with_password(&k);
    drop(k);
    // The login password changed; the vault still opens with the old one.
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(Fixed(|p| p == "new")),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let p = Interactive::new(vec![password(PW)]);
    assert!(matches!(
        k.enroll_tpm(&mut p.channel()),
        Err(Error::Invalid(_))
    ));
    assert_eq!(k.status().unwrap().keyslots.len(), 2);
}

/// Review minors 3 and 4: TPM slots are tried newest first, and within
/// one second the later-added slot counts as newer: the current slot opens
/// the vault without spending an attempt on the outdated one.
#[test]
fn the_newest_tpm_slot_is_tried_first() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::one(MockAuthenticator::with_pin(PIN)),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    k.enroll_fido2(
        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
        false,
    )
    .unwrap();
    // The password changes; a new TPM slot is sealed with it (same second).
    login.set("new");
    let p = Interactive::new(vec![FromPrompter::Fido2 {}, pin(PIN), password("new")]);
    k.enroll_tpm(&mut p.channel()).unwrap();
    k.lock();
    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
        .unwrap();
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
}

/// Review minor 2: a rotation never offers the TPM a password PAM has not
/// accepted (here PAM cannot check at all, so it stops instead).
#[test]
fn a_rotation_offers_the_tpm_only_a_pam_accepted_password() {
    let env = env();
    let k = keyring_with(
        &env,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_with_password(&k);
    drop(k);
    let k = keyring(&env, MockKeys::default());
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    k.enroll_tpm(&mut Interactive::new(vec![password(PW)]).channel())
        .unwrap();
    drop(k);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(Unavailable),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let before = k.status().unwrap().keyslots;
    let p = Interactive::new(vec![password(PW)]);
    assert!(matches!(
        k.rotate_master(&mut p.channel()),
        Err(Error::PasswordCheckUnavailable)
    ));
    assert_eq!(k.status().unwrap().keyslots, before);
}

/// Review minor 10: wrong FIDO2 PINs have a small budget per conversation,
/// so typos cannot burn the key's lifetime PIN retries.
#[test]
fn wrong_pins_end_the_conversation_after_three() {
    let env = env();
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    k.create(
        &mut Interactive::new(vec![pin(PIN)]).channel(),
        Method::Fido2,
    )
    .unwrap();
    k.lock();
    // After three wrong PINs the conversation ends: choosing the key
    // again does not buy three more.
    let p = Interactive::new(vec![
        FromPrompter::Fido2 {},
        pin("000000"),
        pin("000000"),
        pin("000000"),
        FromPrompter::Fido2 {},
        pin("000000"),
        pin(PIN),
    ]);
    assert!(k.unlock(&mut p.channel(), None).is_err());
    let asked = p
        .sent()
        .iter()
        .filter(|m| matches!(m, ToPrompter::Fido2Pin { .. }))
        .count();
    assert_eq!(asked, 3);
}

/// Verification minor 1: a rotation tries TPM slots newest first too, and
/// after the first rejection marks the older ones without trying: with
/// three live slots (two sealed with outdated passwords) the current one
/// is kept and the rotation costs one dictionary-attack failure.
#[test]
fn a_rotation_keeps_the_current_tpm_slot() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::one(MockAuthenticator::with_pin(PIN)),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    k.enroll_fido2(
        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
        false,
    )
    .unwrap();
    let tpm_ids = |k: &Keyring| -> Vec<uuid::Uuid> {
        k.status()
            .unwrap()
            .keyslots
            .into_iter()
            .filter(|s| s.kind == "tpm")
            .map(|s| s.id)
            .collect()
    };
    // Two password changes, a new TPM slot after each.
    for pw in ["mid", "new"] {
        login.set(pw);
        let p = Interactive::new(vec![FromPrompter::Fido2 {}, pin(PIN), password(pw)]);
        k.enroll_tpm(&mut p.channel()).unwrap();
    }
    let all = tpm_ids(&k);
    assert_eq!(all.len(), 3);
    let current = *all.last().unwrap();
    let p = Interactive::new(vec![
        password("new"),
        pin(PIN),
        FromPrompter::Confirm { yes: true },
    ]);
    k.rotate_master(&mut p.channel()).unwrap();
    assert_eq!(tpm_ids(&k), [current]);
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
}

#[test]
fn creating_twice_is_refused() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let p = Scripted::new(vec![]);
    assert!(matches!(
        k.create(&mut p.launch().unwrap(), Method::Password),
        Err(Error::VaultExists)
    ));
}
