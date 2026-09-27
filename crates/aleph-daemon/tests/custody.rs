//! Custody: recovery with the recovery key, restoring a backup, the backup
//! copy, accepting a rollback, and writing backups (keyring on swtpm).

use aleph_daemon::testing::*;

/// Create the vault with the login password and return its recovery key
/// (the scripted prompter was shown it).
fn create_capturing_key(k: &Keyring) -> String {
    let p = Interactive::new(vec![password(PW)]);
    k.create(&mut p.channel(), Method::Password).unwrap();
    p.sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::ShowRecoveryKey { key, .. } => Some(key.expose().to_string()),
            _ => None,
        })
        .unwrap()
}

/// A vault someone else made (its only method a login password this
/// machine's PAM does not accept): the file, its recovery key, and a backup.
fn foreign_vault() -> (Vec<u8>, String, Vec<u8>) {
    let there = env();
    let k = keyring_with(
        &there,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == "attacker")),
    );
    let p = Interactive::new(vec![password("attacker")]);
    k.create(&mut p.channel(), Method::Password).unwrap();
    let key = p
        .sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::ShowRecoveryKey { key, .. } => Some(key.expose().to_string()),
            _ => None,
        })
        .unwrap();
    let mut backup = Vec::new();
    k.backup(
        &mut Interactive::new(vec![password("attacker")]).channel(),
        |b| {
            backup = b.to_vec();
            Ok(())
        },
    )
    .unwrap();
    (std::fs::read(there.paths.vault()).unwrap(), key, backup)
}

/// This machine's keyring (TPM and login password), locked, with the
/// attacker's own security key plugged in.
fn victim(env: &Env) -> Keyring {
    let k = keyring(env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    create_capturing_key(&k);
    k.lock();
    k
}

/// What an attacker holding a backup and its recovery key answers: the key,
/// then its own security key as the new method.
fn attacker_answers(key: &str) -> Vec<FromPrompter> {
    vec![recovery(key), FromPrompter::Fido2 {}, pin(PIN), no()]
}

fn recovery(key: &str) -> FromPrompter {
    FromPrompter::RecoveryKey {
        key: Secret::new(key),
    }
}

fn yes() -> FromPrompter {
    FromPrompter::Confirm { yes: true }
}

fn no() -> FromPrompter {
    FromPrompter::Confirm { yes: false }
}

fn kinds(k: &Keyring) -> Vec<String> {
    k.status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect()
}

/// Files in the data directory whose names start with `prefix`.
fn kept(env: &Env, prefix: &str) -> usize {
    std::fs::read_dir(&env.paths.data_dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(prefix)
        })
        .count()
}

/// A backup of `k` (unlocked), after re-authentication with the password.
fn backup_of(k: &Keyring) -> Vec<u8> {
    let mut bytes = Vec::new();
    k.backup(&mut Interactive::new(vec![password(PW)]).channel(), |b| {
        bytes = b.to_vec();
        Ok(())
    })
    .unwrap();
    bytes
}

fn write_item(k: &Keyring, label: &str) {
    k.modify(|b| {
        b.collections[0].upsert(
            aleph_core::Item::new(
                label,
                [("id".to_string(), label.to_string())].into(),
                aleph_core::SecretBytes::new(b"s".to_vec()),
                "text/plain",
            ),
            false,
        );
        Ok(())
    })
    .unwrap();
}

/// The login password forgotten (or the TPM slot unusable): the recovery
/// key opens the vault, every other slot is replaced by a fresh unlock
/// method, and the replaced file is kept.
#[test]
fn the_recovery_key_recovers_the_current_vault() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(login.clone()),
    );
    let key = create_capturing_key(&k);
    write_item(&k, "kept");
    let before = k.status().unwrap().keyslots;
    k.lock();
    login.set("new");
    let p = Interactive::new(vec![recovery(&key), yes(), password("new"), no()]);
    k.recover(&mut p.channel(), None).unwrap();
    // Enter keeps the old slots (the question is a warning) and takes the
    // new recovery key (E7).
    let defaults: Vec<bool> = p
        .sent()
        .into_iter()
        .filter_map(|m| match m {
            ToPrompter::Confirm { default, .. } => Some(default),
            _ => None,
        })
        .collect();
    assert_eq!(defaults, [false, true]);
    assert_eq!(kinds(&k), ["recovery", "tpm"]);
    // A fresh TPM slot (the recovery slot keeps its id).
    let tpm = |slots: &[aleph_daemon::keyring::SlotInfo]| {
        slots.iter().find(|s| s.kind == "tpm").unwrap().id
    };
    assert_ne!(tpm(&k.status().unwrap().keyslots), tpm(&before));
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
    assert_eq!(kept(&env, "vault.aleph.replaced-"), 1);
    // The .bak it had is kept too (the rotation's write replaces .bak).
    assert_eq!(kept(&env, "vault.aleph.bak-"), 1);
    k.lock();
    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
        .unwrap();
}

/// A backup holds only the recovery slot, and restores on a new machine
/// (another TPM) with the recovery key and a fresh unlock method.
#[test]
fn a_backup_restores_on_a_new_machine() {
    let old = env();
    let k = keyring(&old, MockKeys::default());
    let key = create_capturing_key(&k);
    write_item(&k, "carried over");
    let bytes = backup_of(&k);
    let backup = aleph_core::LockedVault::from_bytes(&bytes).unwrap();
    assert!(
        backup
            .keyslots()
            .all(|s| matches!(s.kind, aleph_core::SlotKind::Recovery(_)))
    );
    let new = env();
    let k = keyring(&new, MockKeys::default());
    let p = Interactive::new(vec![recovery(&key), password(PW), no()]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert_eq!(kinds(&k), ["recovery", "tpm"]);
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
    k.lock();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
}

/// A restore that finishes after the pre-sleep lock writes nothing and
/// leaves nothing unlocked; after the resume it works.
#[test]
fn nothing_is_restored_while_the_system_sleeps() {
    let old = env();
    let k = keyring(&old, MockKeys::default());
    let key = create_capturing_key(&k);
    let bytes = backup_of(&k);
    let new = env();
    let k = keyring(&new, MockKeys::default());
    k.set_sleeping(true);
    let p = Interactive::new(vec![recovery(&key), password(PW), no()]);
    assert!(matches!(
        k.recover(&mut p.channel(), Some(&bytes)),
        Err(aleph_daemon::Error::Sleeping)
    ));
    assert!(k.is_locked());
    assert!(!new.paths.vault().exists());
    k.set_sleeping(false);
    let p = Interactive::new(vec![recovery(&key), password(PW), no()]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert!(!k.is_locked());
}

/// Replacing a vault that still opens needs its current method first:
/// declined, nothing changes; proven, the old file is kept.
#[test]
fn replacing_a_vault_that_opens_needs_its_method() {
    let other = env();
    let k2 = keyring(&other, MockKeys::default());
    let key2 = create_capturing_key(&k2);
    let bytes = backup_of(&k2);
    let here = env();
    let k = keyring(&here, MockKeys::default());
    create_capturing_key(&k);
    k.lock();
    let file = std::fs::read(here.paths.vault()).unwrap();
    // Answering the later questions without the method changes nothing.
    let p = Interactive::new(vec![recovery(&key2), password(PW), no()]);
    assert!(k.recover(&mut p.channel(), Some(&bytes)).is_err());
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), file);
    let p = Interactive::new(vec![password(PW), recovery(&key2), password(PW), no()]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert_eq!(kept(&here, "vault.aleph.replaced-"), 1);
}

/// Wrong recovery keys (malformed, or another vault's) change nothing.
#[test]
fn a_wrong_recovery_key_changes_nothing() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    k.lock();
    let file = std::fs::read(env.paths.vault()).unwrap();
    let other = aleph_core::RecoveryKey::generate().unwrap().format();
    let p = Interactive::new(vec![
        recovery("not a key"),
        recovery(&other),
        recovery(&other),
    ]);
    assert!(k.recover(&mut p.channel(), None).is_err());
    assert_eq!(std::fs::read(env.paths.vault()).unwrap(), file);
    assert!(k.is_locked());
}

/// An unreadable vault file is replaced by its backup copy, opened with
/// the usual method; the unreadable file is kept.
#[test]
fn the_backup_copy_replaces_an_unreadable_vault() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    write_item(&k, "first");
    write_item(&k, "second");
    drop(k);
    std::fs::write(env.paths.vault(), b"not a vault").unwrap();
    let bak = std::fs::read(env.paths.bak()).unwrap();
    let k = keyring(&env, MockKeys::default());
    let p = Interactive::new(vec![yes(), password(PW)]);
    k.restore_from_bak(&mut p.channel()).unwrap();
    // The good copy is kept whatever the write does to .bak.
    let kept_bak = std::fs::read_dir(&env.paths.data_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("vault.aleph.bak-")
        })
        .unwrap();
    assert_eq!(std::fs::read(kept_bak).unwrap(), bak);
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
    assert_eq!(kept(&env, "vault.aleph.corrupt-"), 1);
    assert_eq!(k.status().unwrap().untrusted, None);
}

/// A rolled-back file is accepted only after re-authentication and a yes;
/// it is then written past everything recorded, so the newer copy that was
/// replaced now reads as rolled back itself (the mark never goes down).
#[test]
fn an_accepted_rollback_never_lowers_the_mark() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    let older = std::fs::read(env.paths.vault()).unwrap();
    write_item(&k, "later");
    let newer = std::fs::read(env.paths.vault()).unwrap();
    k.lock();
    std::fs::write(env.paths.vault(), &older).unwrap();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
    let decline = Interactive::new(vec![password(PW), no()]);
    assert!(matches!(
        k.accept_rollback(&mut decline.channel()),
        Err(Error::Cancelled)
    ));
    assert!(k.status().unwrap().untrusted.is_some());
    // Enter declines the acceptance (E7).
    assert!(
        decline
            .sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::Confirm { default: false, .. }))
    );
    let accept = Interactive::new(vec![password(PW), yes()]);
    k.accept_rollback(&mut accept.channel()).unwrap();
    assert_eq!(k.status().unwrap().untrusted, None);
    let newer_generation = aleph_core::LockedVault::from_bytes(&newer)
        .unwrap()
        .mark()
        .generation;
    assert!(
        aleph_core::LockedVault::read(&env.paths.vault())
            .unwrap()
            .mark()
            .generation
            > newer_generation
    );
    write_item(&k, "after acceptance");
    k.lock();
    std::fs::write(env.paths.vault(), &newer).unwrap();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
}

/// A vault from before the vault-id file existed gets one at its first
/// unlock (setup never writes it), so a vault swapped in later is caught.
#[test]
fn a_vault_without_a_recorded_id_gets_one_at_unlock() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    k.lock();
    std::fs::remove_file(env.paths.expected_vault()).unwrap();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert!(env.paths.expected_vault().exists());
    assert_eq!(k.status().unwrap().untrusted, None);
}

/// A different vault put at the path is not trusted (its history is not
/// this machine's) until accepted.
#[test]
fn a_different_vault_at_the_path_is_not_trusted() {
    let here = env();
    let k = keyring_with(
        &here,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_capturing_key(&k);
    drop(k);
    let there = env();
    let k2 = keyring_with(
        &there,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_capturing_key(&k2);
    drop(k2);
    std::fs::copy(there.paths.vault(), here.paths.vault()).unwrap();
    let k = keyring_with(
        &here,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    let why = k.status().unwrap().untrusted.unwrap();
    assert!(why.contains("different vault"), "{why}");
    // Its own method, then the login password (PAM), then yes.
    k.accept_rollback(&mut Interactive::new(vec![password(PW), password(PW), yes()]).channel())
        .unwrap();
    assert_eq!(k.status().unwrap().untrusted, None);
}

/// E7 against a same-user process that holds a backup and its recovery
/// key: moving the vault away does not skip the proof.
#[test]
fn a_missing_vault_does_not_skip_the_proof() {
    let (_, key, backup) = foreign_vault();
    let here = env();
    let k = victim(&here);
    std::fs::remove_file(here.paths.vault()).unwrap();
    assert!(
        k.recover(
            &mut Interactive::new(attacker_answers(&key)).channel(),
            Some(&backup)
        )
        .is_err()
    );
    assert!(!here.paths.vault().exists());
    // The user, with the login password, can.
    let mut answers = vec![password(PW)];
    answers.extend(attacker_answers(&key));
    k.recover(&mut Interactive::new(answers).channel(), Some(&backup))
        .unwrap();
}

/// A planted vault proves nothing with its own methods.
#[test]
fn a_planted_vault_does_not_prove_the_right_to_replace_it() {
    let (planted, key, backup) = foreign_vault();
    let here = env();
    let k = victim(&here);
    std::fs::write(here.paths.vault(), &planted).unwrap();
    let mut answers = vec![password("attacker")];
    answers.extend(attacker_answers(&key));
    assert!(
        k.recover(&mut Interactive::new(answers).channel(), Some(&backup))
            .is_err()
    );
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), planted);
    // Nor through its own recovery key, with no backup given (yes to
    // dropping its slot).
    let mut answers = vec![recovery(&key), yes()];
    answers.extend(attacker_answers(&key).into_iter().skip(1));
    assert!(
        k.recover(&mut Interactive::new(answers).channel(), None)
            .is_err()
    );
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), planted);
}

/// While the keyring is unlocked, a missing file does not skip the proof.
#[test]
fn an_unlocked_keyring_is_replaced_only_after_reauthentication() {
    let (_, key, backup) = foreign_vault();
    let here = env();
    let k = victim(&here);
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    std::fs::remove_file(here.paths.vault()).unwrap();
    assert!(
        k.recover(
            &mut Interactive::new(attacker_answers(&key)).channel(),
            Some(&backup)
        )
        .is_err()
    );
    assert!(!here.paths.vault().exists());
}

/// A planted backup copy is not restored with its own methods.
#[test]
fn a_planted_backup_copy_needs_the_login_password() {
    let (planted, _, _) = foreign_vault();
    let here = env();
    let k = victim(&here);
    let file = std::fs::read(here.paths.vault()).unwrap();
    std::fs::write(here.paths.bak(), &planted).unwrap();
    let p = Interactive::new(vec![yes(), password("attacker")]);
    assert!(k.restore_from_bak(&mut p.channel()).is_err());
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), file);
}

/// A planted vault, unlocked with its own password, is not accepted with
/// it: accepting a different vault needs this machine's login password.
#[test]
fn a_planted_vault_is_not_accepted_with_its_own_password() {
    let (planted, _, _) = foreign_vault();
    let here = env();
    let k = keyring_with(
        &here,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_capturing_key(&k);
    k.lock();
    std::fs::write(here.paths.vault(), &planted).unwrap();
    k.unlock(
        &mut Interactive::new(vec![password("attacker")]).channel(),
        None,
    )
    .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
    let p = Interactive::new(vec![password("attacker"), yes()]);
    assert!(k.accept_rollback(&mut p.channel()).is_err());
    assert!(k.status().unwrap().untrusted.is_some());
    // A backup of it says it is not trusted.
    let p = Interactive::new(vec![password("attacker")]);
    k.backup(&mut p.channel(), |_| Ok(())).unwrap();
    let done = p
        .sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::Done { message, .. } => message,
            _ => None,
        })
        .unwrap();
    assert!(done.contains("not trusted"), "{done}");
}

/// A planted vault unlocked with its own method (the attacker's security
/// key) proves nothing for a restore: re-authenticating against it is not
/// proof.
#[test]
fn an_unlocked_planted_vault_proves_nothing() {
    let here = env();
    let k = keyring(&here, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    // The attacker's vault, on the attacker's key, made before this
    // machine's own.
    let p = Interactive::new(vec![pin(PIN)]);
    k.create(&mut p.channel(), Method::Fido2).unwrap();
    let key = p
        .sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::ShowRecoveryKey { key, .. } => Some(key.expose().to_string()),
            _ => None,
        })
        .unwrap();
    k.lock();
    let planted = std::fs::read(here.paths.vault()).unwrap();
    std::fs::remove_file(here.paths.vault()).unwrap();
    std::fs::remove_file(here.paths.expected_vault()).unwrap();
    create_capturing_key(&k);
    k.lock();
    std::fs::write(here.paths.vault(), &planted).unwrap();
    k.unlock(
        &mut Interactive::new(vec![FromPrompter::Fido2 {}, pin(PIN)]).channel(),
        None,
    )
    .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
    // Its recovery key, its own key for the proof, yes to dropping its
    // slot, and its key again as the new method.
    let answers = vec![
        recovery(&key),
        FromPrompter::Fido2 {},
        pin(PIN),
        yes(),
        FromPrompter::Fido2 {},
        pin(PIN),
        no(),
    ];
    assert!(
        k.recover(&mut Interactive::new(answers).channel(), None)
            .is_err()
    );
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), planted);
}

/// A file that is not a backup (garbage, a truncated backup) changes nothing.
#[test]
fn a_file_that_is_not_a_backup_changes_nothing() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    let key = create_capturing_key(&k);
    let bytes = backup_of(&k);
    k.lock();
    let file = std::fs::read(env.paths.vault()).unwrap();
    for junk in [b"not a vault".to_vec(), bytes[..bytes.len() / 2].to_vec()] {
        let p = Interactive::new(vec![password(PW), recovery(&key), password(PW), no()]);
        assert!(k.recover(&mut p.channel(), Some(&junk)).is_err());
        assert_eq!(std::fs::read(env.paths.vault()).unwrap(), file);
    }
}

/// Restoring an older backup of this vault says what is lost and asks
/// first (Enter says no); restored, it is written past the newer file,
/// which then reads as rolled back.
#[test]
fn an_older_backup_of_this_vault_asks_first_and_the_newer_file_stays_detectable() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    let key = create_capturing_key(&k);
    let bytes = backup_of(&k);
    write_item(&k, "written after the backup");
    let newer = std::fs::read(env.paths.vault()).unwrap();
    k.lock();
    let p = Interactive::new(vec![password(PW), no()]);
    assert!(matches!(
        k.recover(&mut p.channel(), Some(&bytes)),
        Err(Error::Cancelled)
    ));
    assert!(p.sent().iter().any(|m| matches!(
        m,
        ToPrompter::Confirm { text, default: false } if text.contains("not in it")
    )));
    assert_eq!(std::fs::read(env.paths.vault()).unwrap(), newer);
    let p = Interactive::new(vec![
        password(PW),
        yes(),
        recovery(&key),
        password(PW),
        no(),
    ]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 0);
    let newer_generation = aleph_core::LockedVault::from_bytes(&newer)
        .unwrap()
        .mark()
        .generation;
    assert!(
        aleph_core::LockedVault::read(&env.paths.vault())
            .unwrap()
            .mark()
            .generation
            > newer_generation
    );
    k.lock();
    std::fs::write(env.paths.vault(), &newer).unwrap();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert!(k.status().unwrap().untrusted.is_some());
}

/// A vault whose slot opens but whose contents fail authentication
/// (corrupt) proves nothing by opening (a forged file fails the same way):
/// the login password is asked too. It is replaced and kept.
#[test]
fn a_corrupt_vault_is_replaced_after_its_method_opens_its_slot() {
    let other = env();
    let k2 = keyring(&other, MockKeys::default());
    let key2 = create_capturing_key(&k2);
    let bytes = backup_of(&k2);
    let here = env();
    let k = keyring(&here, MockKeys::default());
    create_capturing_key(&k);
    k.lock();
    let mut file = std::fs::read(here.paths.vault()).unwrap();
    let last = file.len() - 1;
    file[last] ^= 1;
    std::fs::write(here.paths.vault(), &file).unwrap();
    let p = Interactive::new(vec![
        password(PW),
        password(PW),
        recovery(&key2),
        password(PW),
        no(),
    ]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert_eq!(kept(&here, "vault.aleph.replaced-"), 1);
}

/// E7 against an older copy of this very vault (same id) and its old
/// recovery key: put back at the path, it is not "the vault this machine
/// expects" (it is behind the recorded mark), so recovering it needs proof.
#[test]
fn an_older_copy_of_this_vault_needs_proof() {
    let here = env();
    let k = keyring(&here, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    let key = create_capturing_key(&k);
    let old = std::fs::read(here.paths.vault()).unwrap();
    write_item(&k, "newer");
    k.lock();
    let current = std::fs::read(here.paths.vault()).unwrap();
    std::fs::write(here.paths.vault(), &old).unwrap();
    // The recovery key, yes to dropping the old slot, its own security key.
    let p = Interactive::new(vec![
        recovery(&key),
        yes(),
        FromPrompter::Fido2 {},
        pin(PIN),
        no(),
    ]);
    assert!(k.recover(&mut p.channel(), None).is_err());
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), old);
    assert!(k.is_locked());
    drop(current);
}

/// A plain `restore` with the vault gone falls back to `.bak` (without
/// hanging the daemon); `.bak` is behind the mark, so the login password
/// is asked; an attacker's answers do not get through.
#[test]
fn recovering_from_the_backup_copy_needs_the_login_password() {
    let here = env();
    let k = keyring(&here, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    let key = create_capturing_key(&k);
    write_item(&k, "first");
    write_item(&k, "second");
    k.lock();
    std::fs::remove_file(here.paths.vault()).unwrap();
    let (done, wait) = std::sync::mpsc::channel();
    let k = std::sync::Arc::new(k);
    {
        let k = k.clone();
        let key = key.clone();
        std::thread::spawn(move || {
            let p = Interactive::new(vec![
                recovery(&key),
                yes(),
                FromPrompter::Fido2 {},
                pin(PIN),
                no(),
            ]);
            done.send(k.recover(&mut p.channel(), None).is_err())
                .unwrap();
        });
    }
    assert!(
        wait.recv_timeout(std::time::Duration::from_secs(60))
            .expect("recover hung")
    );
    assert!(!here.paths.vault().exists());
    // The user: the recovery key, the login password, yes, a new method.
    let p = Interactive::new(vec![
        recovery(&key),
        password(PW),
        yes(),
        password(PW),
        no(),
    ]);
    k.recover(&mut p.channel(), None).unwrap();
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
}

/// A vault forged with this machine's vault id (an old backup recovered
/// elsewhere onto the attacker's own key: same id, another master key)
/// proves nothing by opening with the attacker's key.
#[test]
fn a_forged_vault_with_this_id_proves_nothing() {
    let here = env();
    let k = keyring(&here, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    let key = create_capturing_key(&k);
    let backup = backup_of(&k);
    write_item(&k, "newer");
    k.lock();
    let real = std::fs::read(here.paths.vault()).unwrap();
    let state: Vec<(std::path::PathBuf, Vec<u8>)> = std::fs::read_dir(&here.paths.state_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .map(|p| {
            let bytes = std::fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect();
    // Forge: restore the old backup onto the attacker's key (as if on the
    // attacker's machine), then put this machine back as it was.
    let p = Interactive::new(vec![
        password(PW),
        yes(),
        recovery(&key),
        FromPrompter::Fido2 {},
        pin(PIN),
        no(),
    ]);
    k.recover(&mut p.channel(), Some(&backup)).unwrap();
    k.lock();
    let forged = std::fs::read(here.paths.vault()).unwrap();
    std::fs::write(here.paths.vault(), &real).unwrap();
    for (p, bytes) in &state {
        std::fs::write(p, bytes).unwrap();
    }
    // Attack: plant the forgery, prove with the attacker's key, restore.
    std::fs::write(here.paths.vault(), &forged).unwrap();
    let p = Interactive::new(vec![
        FromPrompter::Fido2 {},
        pin(PIN),
        yes(),
        recovery(&key),
        FromPrompter::Fido2 {},
        pin(PIN),
        no(),
    ]);
    assert!(k.recover(&mut p.channel(), Some(&backup)).is_err());
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), forged);
    // The same forgery as the backup copy, opened with the attacker's key.
    std::fs::write(here.paths.vault(), &real).unwrap();
    std::fs::write(here.paths.bak(), &forged).unwrap();
    let p = Interactive::new(vec![yes(), FromPrompter::Fido2 {}, pin(PIN)]);
    assert!(k.restore_from_bak(&mut p.channel()).is_err());
    assert_eq!(std::fs::read(here.paths.vault()).unwrap(), real);
}

/// A cancel at the new-recovery-key offer, after the vault is replaced,
/// still reports the restore (and the old key still works).
#[test]
fn a_restore_is_reported_even_if_the_new_recovery_key_is_declined_midway() {
    let old = env();
    let k = keyring(&old, MockKeys::default());
    let key = create_capturing_key(&k);
    let bytes = backup_of(&k);
    let new = env();
    let k = keyring(&new, MockKeys::default());
    let p = Interactive::new(vec![recovery(&key), password(PW), FromPrompter::Cancel {}]);
    k.recover(&mut p.channel(), Some(&bytes)).unwrap();
    assert!(!k.is_locked());
    let done = p
        .sent()
        .into_iter()
        .find_map(|m| match m {
            ToPrompter::Done { message, .. } => message,
            _ => None,
        })
        .unwrap();
    assert!(done.contains("not installed"), "{done}");
}

/// With the vault file gone, an older backup is still recognized as older
/// (against the recorded mark) and asks first.
#[test]
fn an_older_backup_asks_first_even_with_the_vault_gone() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    let bytes = backup_of(&k);
    write_item(&k, "written after the backup");
    k.lock();
    std::fs::remove_file(env.paths.vault()).unwrap();
    let p = Interactive::new(vec![password(PW), no()]);
    assert!(matches!(
        k.recover(&mut p.channel(), Some(&bytes)),
        Err(Error::Cancelled)
    ));
}

/// `--from-bak` names the generation this machine last recorded.
#[test]
fn restoring_from_bak_names_the_recorded_generation() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    write_item(&k, "first");
    write_item(&k, "second");
    k.lock();
    let p = Interactive::new(vec![no()]);
    assert!(k.restore_from_bak(&mut p.channel()).is_err());
    assert!(p.sent().iter().any(|m| matches!(
        m,
        ToPrompter::Confirm { text, .. } if text.contains("last recorded generation")
    )));
}

/// A backup needs re-authentication; declined, nothing is written.
#[test]
fn a_backup_needs_reauthentication() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_capturing_key(&k);
    let mut written = false;
    let result = k.backup(
        &mut Interactive::new(vec![FromPrompter::Cancel {}]).channel(),
        |_| {
            written = true;
            Ok(())
        },
    );
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(!written);
}
