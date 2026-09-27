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
/// elsewhere) is marked stale, and the previous password is asked for
/// (declined here); retrying clears the mark.
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
    let p = Interactive::new(vec![password("new password"), FromPrompter::Cancel {}]);
    assert!(matches!(
        k.unlock(&mut p.channel(), None),
        Err(Error::Cancelled)
    ));
    assert!(
        p.sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::OldPassword { error: None }))
    );
    let tpm = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .find(|s| s.kind == "tpm")
        .unwrap();
    assert!(tpm.stale);
    k.retry_slot(tpm.id).unwrap();
    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
}

/// The TPM slots' ids and the master key's id on disk.
fn slots_and_mk(k: &Keyring, env: &Env, kind: &str) -> (Vec<uuid::Uuid>, [u8; 16]) {
    let ids = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .filter(|s| s.kind == kind)
        .map(|s| s.id)
        .collect();
    let mk = aleph_core::LockedVault::read(&env.paths.vault())
        .unwrap()
        .mark()
        .mk_id;
    (ids, mk)
}

/// `passwd` (through `pam_aleph`) replaces the TPM slot with one sealed
/// under the new password and rotates MK: the old slot is gone and the
/// new password unlocks, with no failed TPM attempt.
#[test]
fn a_password_change_reseals_the_tpm_slot_and_rotates() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    let (before, mk_before) = slots_and_mk(&k, &env, "tpm");
    login.set("new");
    let done = k.change_login_password(PW, "new").unwrap();
    assert!(done.contains("rotated"), "{done}");
    let (after, mk_after) = slots_and_mk(&k, &env, "tpm");
    assert_eq!(after.len(), 1);
    assert_ne!(after, before);
    assert_ne!(mk_after, mk_before);
    k.lock();
    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
        .unwrap();
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
    assert!(!k.status().unwrap().rotation_pending);
}

/// With a FIDO2 slot (which needs a touch) MK cannot rotate during
/// `passwd`: the TPM slot is replaced keeping MK, and a rotation is marked
/// pending until the user runs one.
#[test]
fn with_a_security_key_a_password_change_marks_a_rotation_pending() {
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
    let (before, mk_before) = slots_and_mk(&k, &env, "tpm");
    login.set("new");
    let done = k.change_login_password(PW, "new").unwrap();
    assert!(done.contains("rotate-master"), "{done}");
    let (after, mk_after) = slots_and_mk(&k, &env, "tpm");
    assert_eq!(after.len(), 1);
    assert_ne!(after, before);
    assert_eq!(mk_after, mk_before);
    assert_eq!(slots_and_mk(&k, &env, "fido2").0.len(), 1);
    assert!(k.status().unwrap().rotation_pending);
    // Every unlock repeats it until done.
    k.lock();
    let p = Interactive::new(vec![password("new")]);
    k.unlock(&mut p.channel(), None).unwrap();
    assert!(
        matches!(
            p.sent().last(),
            Some(ToPrompter::Done { ok: true, message: Some(m) }) if m.contains("rotate-master")
        ),
        "{:?}",
        p.sent().last()
    );
    let p = Interactive::new(vec![password("new"), pin(PIN)]);
    k.rotate_master(&mut p.channel()).unwrap();
    assert!(!k.status().unwrap().rotation_pending);
    assert_ne!(slots_and_mk(&k, &env, "tpm").1, mk_before);
}

/// A password change while locked opens the vault with the old password
/// for the change, then locks it again.
#[test]
fn a_password_change_while_locked_leaves_it_locked() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    k.lock();
    login.set("new");
    k.change_login_password(PW, "new").unwrap();
    assert!(k.is_locked());
    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
        .unwrap();
}

/// A login-password slot (no TPM) is replaced by one for the new password.
#[test]
fn a_password_change_replaces_a_login_password_slot() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    login.set("new");
    k.change_login_password(PW, "new").unwrap();
    k.lock();
    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
        .unwrap();
    assert_eq!(slots_and_mk(&k, &env, "login-password").0.len(), 1);
}

/// `pam_aleph` runs even when `passwd` failed to change the password: a new
/// password PAM does not accept changes nothing.
#[test]
fn a_failed_passwd_changes_nothing() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let before = slots_and_mk(&k, &env, "tpm");
    assert!(k.change_login_password(PW, "new").is_err());
    assert_eq!(slots_and_mk(&k, &env, "tpm"), before);
}

/// A password from the login stack is still checked with PAM when PAM can:
/// a wrong one never reaches the TPM or marks a slot stale.
#[test]
fn a_wrong_login_stack_password_never_reaches_the_tpm() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    assert!(matches!(
        k.unlock_with_login_password("wrong"),
        Err(Error::WrongPassword)
    ));
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
    k.unlock_with_login_password(PW).unwrap();
    assert!(!k.is_locked());
}

/// A login password does not wait behind an open conversation (a prompter
/// nobody is answering, say while the screen is locked): it unlocks at
/// once, and the conversation's own late result does not replace it.
#[test]
fn a_login_password_does_not_wait_for_a_conversation() {
    let env = env();
    let k = Arc::new(keyring(&env, MockKeys::default()));
    create_with_password(&k);
    k.lock();
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut silent =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(60)).unwrap();
    let waiting = {
        let k = k.clone();
        std::thread::spawn(move || k.unlock(&mut silent, None))
    };
    std::thread::sleep(std::time::Duration::from_millis(200));
    // While the prompter stays silent (its timeout is a minute), the login
    // password gets in.
    let (done, wait_done) = std::sync::mpsc::channel();
    {
        let k = k.clone();
        std::thread::spawn(move || done.send(k.unlock_with_login_password(PW)).unwrap());
    }
    let unlocked = wait_done.recv_timeout(std::time::Duration::from_secs(30));
    drop(theirs); // the prompter goes away: the conversation ends
    unlocked.expect("the login password did not wait").unwrap();
    assert!(!k.is_locked());
    // (The conversation ends successfully: the vault was unlocked.)
    assert!(waiting.join().unwrap().is_ok());
    assert!(!k.is_locked());
}

/// When a login password unlocks the vault while a prompter waits at its
/// question, the conversation ends at once, successfully: the prompter is
/// told `Done` (no stale dialog), and the caller's unlock succeeds.
#[test]
fn a_waiting_prompter_is_released_when_the_vault_unlocks_elsewhere() {
    use std::io::{BufRead, BufReader};
    let env = env();
    let k = Arc::new(keyring(&env, MockKeys::default()));
    create_with_password(&k);
    k.lock();
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut chan =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(60)).unwrap();
    let (asked, wait_asked) = std::sync::mpsc::channel();
    let prompter = std::thread::spawn(move || {
        let mut reader = BufReader::new(theirs);
        let mut line = String::new();
        let mut seen = Vec::new();
        while reader.read_line(&mut line).unwrap() > 0 {
            let msg: ToPrompter = serde_json::from_str(&line).unwrap();
            line.clear();
            if matches!(msg, ToPrompter::Ask { .. }) {
                asked.send(()).unwrap();
            }
            let done = matches!(msg, ToPrompter::Done { .. });
            seen.push(msg);
            if done {
                break;
            }
        }
        seen
    });
    let conversation = {
        let k = k.clone();
        std::thread::spawn(move || k.unlock(&mut chan, None))
    };
    wait_asked.recv().unwrap();
    k.unlock_with_login_password(PW).unwrap();
    let (done, wait_done) = std::sync::mpsc::channel();
    std::thread::spawn(move || done.send(conversation.join().unwrap()).unwrap());
    let result = wait_done
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("the conversation ended without waiting for the prompter");
    result.unwrap();
    let seen = prompter.join().unwrap();
    assert!(
        matches!(seen.last(), Some(ToPrompter::Done { ok: true, .. })),
        "{:?}",
        seen.last()
    );
}

/// The system going to sleep: nothing is unlocked until it has resumed
/// (an open finishing just after the pre-sleep lock must not leave the
/// vault unlocked through the sleep).
#[test]
fn nothing_unlocks_while_the_system_sleeps() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    k.lock();
    k.set_sleeping(true);
    assert!(k.unlock_with_login_password(PW).is_err());
    assert!(k.is_locked());
    k.set_sleeping(false);
    k.unlock_with_login_password(PW).unwrap();
    assert!(!k.is_locked());
}

/// A keyring whose setup finishes after the pre-sleep lock is written, but
/// not left unlocked through the sleep.
#[test]
fn a_keyring_created_during_sleep_stays_locked() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    k.set_sleeping(true);
    create_with_password(&k);
    assert!(k.is_locked());
    k.set_sleeping(false);
    k.unlock_with_login_password(PW).unwrap();
    assert!(!k.is_locked());
}

/// Whichever opens the vault first stays: a conversation that finishes
/// after a login password unlocked it (and a secret was stored meanwhile,
/// and the vault locked again) does not put back the older copy it opened:
/// it opens the current file, which is neither lost nor read as a rollback.
#[test]
fn a_late_unlock_does_not_replace_the_open_vault() {
    use std::io::{BufRead, BufReader, Write};
    let env = env();
    let k = Arc::new(keyring(&env, MockKeys::default()));
    create_with_password(&k);
    k.lock();
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut chan =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(10)).unwrap();
    let (asked, wait_asked) = std::sync::mpsc::channel();
    let (answer, wait_answer) = std::sync::mpsc::channel::<()>();
    // A prompter that answers the password question only when told.
    let prompter = std::thread::spawn(move || {
        let mut reader = BufReader::new(theirs.try_clone().unwrap());
        let mut writer = theirs;
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap() > 0 {
            let msg: ToPrompter = serde_json::from_str(&line).unwrap();
            line.clear();
            match msg {
                ToPrompter::Ask { .. } => {
                    asked.send(()).unwrap();
                    wait_answer.recv().unwrap();
                    let mut out = serde_json::to_vec(&password(PW)).unwrap();
                    out.push(b'\n');
                    writer.write_all(&out).unwrap();
                }
                ToPrompter::Done { .. } => return,
                _ => {}
            }
        }
    });
    let conversation = {
        let k = k.clone();
        std::thread::spawn(move || k.unlock(&mut chan, None))
    };
    wait_asked.recv().unwrap();
    k.unlock_with_login_password(PW).unwrap();
    k.modify(|b| {
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
    })
    .unwrap();
    k.lock();
    answer.send(()).unwrap();
    conversation.join().unwrap().unwrap();
    prompter.join().unwrap();
    assert_eq!(k.read(|b| b.collections[0].items.len()).unwrap(), 1);
    assert_eq!(k.status().unwrap().untrusted, None);
}

/// A prompter that answers "security key", then holds the PIN question
/// until told, then cancels. Returns (the channel, a receiver that fires
/// when the PIN is asked, a sender that lets it cancel, its thread).
fn holding_pin_prompter() -> (
    aleph_daemon::prompt::Channel,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{BufRead, BufReader, Write};
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let chan =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(60)).unwrap();
    let (asked, wait_asked) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        let mut reader = BufReader::new(theirs.try_clone().unwrap());
        let mut writer = theirs;
        let mut line = String::new();
        let mut reply = |r: &FromPrompter| {
            let mut out = serde_json::to_vec(r).unwrap();
            out.push(b'\n');
            // (The conversation may already be over: the vault unlocked.)
            let _ = writer.write_all(&out);
        };
        while reader.read_line(&mut line).unwrap() > 0 {
            let msg: ToPrompter = serde_json::from_str(&line).unwrap();
            line.clear();
            match msg {
                ToPrompter::Ask { .. } => reply(&FromPrompter::Fido2 {}),
                ToPrompter::Fido2Pin { .. } => {
                    asked.send(()).unwrap();
                    wait_release.recv().unwrap();
                    reply(&FromPrompter::Cancel {});
                }
                ToPrompter::Done { .. } => return,
                _ => {}
            }
        }
    });
    (chan, wait_asked, release, thread)
}

/// A login password does not wait behind a security-key conversation
/// either, even while its PIN question is open (the hardware is not held
/// while the prompter is asked).
#[test]
fn a_login_password_does_not_wait_behind_a_pin_prompt() {
    let env = env();
    let k = Arc::new(keyring(
        &env,
        MockKeys::one(MockAuthenticator::with_pin(PIN)),
    ));
    create_with_password(&k);
    k.enroll_fido2(
        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
        false,
    )
    .unwrap();
    k.lock();
    let (mut chan, pin_asked, release, prompter) = holding_pin_prompter();
    let conversation = {
        let k = k.clone();
        std::thread::spawn(move || k.unlock(&mut chan, None))
    };
    pin_asked.recv().unwrap();
    // While the PIN question stays open (the prompter's timeout is a
    // minute), the login password gets in.
    let (done, wait_done) = std::sync::mpsc::channel();
    {
        let k = k.clone();
        std::thread::spawn(move || done.send(k.unlock_with_login_password(PW)).unwrap());
    }
    let unlocked = wait_done.recv_timeout(std::time::Duration::from_secs(30));
    release.send(()).unwrap();
    unlocked
        .expect("the login password did not wait for the PIN")
        .unwrap();
    assert!(conversation.join().unwrap().is_ok());
    prompter.join().unwrap();
    assert!(!k.is_locked());
}

/// `passwd` still changes the slots after a login with the new password got
/// there first (and marked the old TPM slot stale): the change opens the
/// file with the previous password whatever the stale mark.
#[test]
fn passwd_after_a_login_with_the_new_password_still_changes() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    k.lock();
    login.set("new");
    assert!(matches!(
        k.unlock_with_login_password("new"),
        Err(Error::PasswordChanged)
    ));
    k.change_login_password(PW, "new").unwrap();
    let p = Interactive::new(vec![password("new")]);
    k.unlock(&mut p.channel(), None).unwrap();
    assert!(
        !p.sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::OldPassword { .. }))
    );
}

/// When PAM cannot vouch for the new password, the old one must open the
/// vault file first: no same-user process can re-seal the vault under a
/// password of its choosing.
#[test]
fn without_pam_a_change_must_prove_the_old_password() {
    #[derive(Clone, Default)]
    struct Vanishing(Arc<std::sync::atomic::AtomicBool>);
    impl aleph_daemon::password::PasswordCheck for Vanishing {
        fn check(&self, pw: &str) -> aleph_daemon::Result<bool> {
            if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::PasswordCheckUnavailable);
            }
            Ok(pw == PW)
        }
    }
    let env = env();
    let pam = Vanishing::default();
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(pam.clone()),
    );
    create_with_password(&k);
    pam.0.store(true, std::sync::atomic::Ordering::SeqCst);
    let before = slots_and_mk(&k, &env, "tpm");
    assert!(matches!(
        k.change_login_password("junk", "chosen"),
        Err(Error::WrongPassword)
    ));
    assert_eq!(slots_and_mk(&k, &env, "tpm"), before);
    k.change_login_password(PW, "chosen").unwrap();
    assert_ne!(slots_and_mk(&k, &env, "tpm").0, before.0);
}

/// The previous password is asked at most twice per conversation, even
/// when the current one is typed again in between.
#[test]
fn the_previous_password_is_asked_at_most_twice_per_conversation() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    k.lock();
    login.set("new");
    let p = Interactive::new(vec![
        password("new"),
        password("wrong 1"),
        password("wrong 2"),
        password("new"),
        password("wrong 3"),
    ]);
    assert!(k.unlock(&mut p.channel(), None).is_err());
    let asked = p
        .sent()
        .iter()
        .filter(|m| matches!(m, ToPrompter::OldPassword { .. }))
        .count();
    assert_eq!(asked, 2);
}

/// Declining the previous-password question returns to the choice of
/// method; a security key then opens the vault, and the TPM slot is still
/// re-sealed under the current password.
#[test]
fn declining_the_previous_password_leaves_the_security_key() {
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
    let (before, _) = slots_and_mk(&k, &env, "tpm");
    k.lock();
    login.set("new");
    let p = Interactive::new(vec![
        password("new"),
        FromPrompter::Cancel {},
        FromPrompter::Fido2 {},
        pin(PIN),
    ]);
    k.unlock(&mut p.channel(), None).unwrap();
    let (after, _) = slots_and_mk(&k, &env, "tpm");
    assert_eq!(after.len(), 1);
    assert_ne!(after, before);
    k.lock();
    k.unlock(&mut Interactive::new(vec![password("new")]).channel(), None)
        .unwrap();
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
}

/// After an outside password change (PAM accepts the new password, the TPM
/// slot was sealed under the old one), the previous password opens the
/// vault and the slot is re-sealed under the new one: one failed TPM
/// attempt in all, and the next unlock needs only the new password.
#[test]
fn a_password_changed_elsewhere_is_resealed_with_the_previous_one() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    let (before, _) = slots_and_mk(&k, &env, "tpm");
    k.lock();
    login.set("new");
    let p = Interactive::new(vec![password("new"), password(PW)]);
    k.unlock(&mut p.channel(), None).unwrap();
    assert!(
        p.sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::OldPassword { .. }))
    );
    let (after, _) = slots_and_mk(&k, &env, "tpm");
    assert_ne!(after, before);
    assert!(!k.status().unwrap().keyslots.iter().any(|s| s.stale));
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
    k.lock();
    let p = Interactive::new(vec![password("new")]);
    k.unlock(&mut p.channel(), None).unwrap();
    assert!(
        !p.sent()
            .iter()
            .any(|m| matches!(m, ToPrompter::OldPassword { .. }))
    );
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 1);
}

/// Wrong previous passwords go straight to the TPM, so they are few: at
/// most two per conversation, and the TPM helper's own limit holds.
#[test]
fn wrong_previous_passwords_are_few() {
    let env = env();
    let login = Accepting::new(PW);
    let k = keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(login.clone()),
    );
    create_with_password(&k);
    k.lock();
    login.set("new");
    let p = Interactive::new(vec![
        password("new"),
        password("wrong"),
        password("wrong"),
        password("wrong"),
    ]);
    assert!(k.unlock(&mut p.channel(), None).is_err());
    let old_asked = p
        .sent()
        .iter()
        .filter(|m| matches!(m, ToPrompter::OldPassword { .. }))
        .count();
    assert!(old_asked <= 2, "{old_asked}");
    assert!(env.sw.tpm().status().unwrap().failed_tries <= 2);
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

/// `status` never waits for a conversation: while a FIDO2 unlock waits for
/// the key to be plugged in, it answers at once.
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
    k.status().unwrap();
    // (One round trip to the TPM helper at most; the key wait takes 600 ms.)
    assert!(
        t.elapsed() < std::time::Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
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

/// Final-review minor 1: a key that is simply not plugged in during a
/// rotation (the wait times out; nobody pressed "skip") counts as "not
/// presented", like a skip: the user is asked to confirm dropping it,
/// instead of the whole rotation failing.
#[test]
fn an_absent_key_that_times_out_is_offered_for_removal() {
    let env = env();
    let k = keyring(&env, MockKeys::one(MockAuthenticator::with_pin(PIN)));
    create_with_password(&k);
    k.enroll_fido2(
        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
        false,
    )
    .unwrap();
    drop(k);
    let k = keyring(&env, MockKeys::default());
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    // No reply to "insert your key": the wait runs out.
    let p = Interactive::new(vec![password(PW), FromPrompter::Confirm { yes: true }]);
    k.rotate_master(&mut p.channel()).unwrap();
    let confirm = p
        .sent()
        .iter()
        .find_map(|m| match m {
            ToPrompter::Confirm { text } => Some(text.clone()),
            _ => None,
        })
        .unwrap();
    assert!(confirm.contains("not presented"), "{confirm}");
    let kinds: Vec<String> = k
        .status()
        .unwrap()
        .keyslots
        .into_iter()
        .map(|s| s.kind)
        .collect();
    assert_eq!(kinds, ["recovery", "tpm"]);
}

/// A vault with a login-password slot and a TPM slot, the login password
/// (as PAM sees it) then changed to "new".
fn login_password_and_tpm_after_a_password_change(env: &Env) -> Keyring {
    let k = keyring_with(
        env,
        Box::new(NoTpm),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    create_with_password(&k);
    drop(k);
    let k = keyring(env, MockKeys::default());
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    k.enroll_tpm(&mut Interactive::new(vec![password(PW)]).channel())
        .unwrap();
    drop(k);
    keyring_with(
        env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        Box::new(Fixed(|p| p == "new")),
    )
}

/// Final-review minor 3: a password PAM rejects is kept from the TPM, but
/// a login-password slot still checks it itself (it may hold the password
/// from before an outside change).
#[test]
fn a_pam_rejected_password_still_opens_a_login_password_slot() {
    let env = env();
    let k = login_password_and_tpm_after_a_password_change(&env);
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
    assert_eq!(env.sw.tpm().status().unwrap().failed_tries, 0);
}

/// Each typed attempt counts once against the typing limit, however many
/// slots it was tried on: four typos, then the right password, still opens.
#[test]
fn a_typo_counts_once_however_many_slots_it_fails() {
    let env = env();
    let k = login_password_and_tpm_after_a_password_change(&env);
    let mut replies: Vec<_> = (0..4).map(|_| password("typo")).collect();
    replies.push(password(PW));
    k.unlock(&mut Interactive::new(replies).channel(), None)
        .unwrap();
}

/// Final-review minor 4: a rotation re-wraps a login-password slot with
/// that slot's own password, checked by the slot, not by PAM (which may be
/// missing, or know only a newer password).
#[test]
fn a_rotation_checks_a_login_password_slot_itself() {
    /// PAM that works until `gone` is set (the service file removed).
    #[derive(Clone, Default)]
    struct Vanishing(Arc<std::sync::atomic::AtomicBool>);
    impl aleph_daemon::password::PasswordCheck for Vanishing {
        fn check(&self, pw: &str) -> aleph_daemon::Result<bool> {
            if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::PasswordCheckUnavailable);
            }
            Ok(pw == PW)
        }
    }
    let env = env();
    let pam = Vanishing::default();
    let k = keyring_with(
        &env,
        Box::new(NoTpm),
        MockKeys::one(MockAuthenticator::with_pin(PIN)),
        Box::new(pam.clone()),
    );
    create_with_password(&k);
    k.enroll_fido2(
        &mut Interactive::new(vec![password(PW), pin(PIN)]).channel(),
        false,
    )
    .unwrap();
    pam.0.store(true, std::sync::atomic::Ordering::SeqCst);
    let before = k.status().unwrap().keyslots.len();
    // Proved by the key; then a wrong password for the slot, then the right one.
    let p = Interactive::new(vec![
        FromPrompter::Fido2 {},
        pin(PIN),
        password("wrong"),
        password(PW),
    ]);
    k.rotate_master(&mut p.channel()).unwrap();
    assert_eq!(k.status().unwrap().keyslots.len(), before);
    k.lock();
    k.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
        .unwrap();
}

/// Final-review minor 5: if installing the new recovery key fails after it
/// was shown, the user is told the key they wrote down was not installed.
#[test]
fn a_failed_reissue_says_the_shown_key_was_not_installed() {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let vault = env.paths.vault();
    std::fs::rename(&vault, vault.with_extension("moved")).unwrap();
    std::os::unix::fs::symlink(vault.with_extension("moved"), &vault).unwrap();
    let p = Interactive::new(vec![password(PW)]);
    assert!(k.reissue_recovery(&mut p.channel()).is_err());
    let sent = p.sent();
    assert!(
        sent.iter()
            .any(|m| matches!(m, ToPrompter::ShowRecoveryKey { .. }))
    );
    assert!(
        matches!(
            sent.last(),
            Some(ToPrompter::Done { ok: false, message: Some(m) })
                if m.contains("not installed") && m.contains("previous recovery key")
        ),
        "{:?}",
        sent.last()
    );
}

/// Final-review minor 2: while one conversation runs, another is refused
/// at once (and told why) instead of queueing silently behind it.
#[test]
fn a_second_conversation_is_refused_while_one_runs() {
    let env = env();
    let k = Arc::new(keyring(&env, MockKeys::default()));
    create_with_password(&k);
    k.lock();
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut silent =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(3)).unwrap();
    let running = {
        let k = k.clone();
        std::thread::spawn(move || k.unlock(&mut silent, None))
    };
    std::thread::sleep(std::time::Duration::from_millis(200));
    let t = std::time::Instant::now();
    let p = Interactive::new(vec![password(PW)]);
    assert!(matches!(k.unlock(&mut p.channel(), None), Err(Error::Busy)));
    assert!(t.elapsed() < std::time::Duration::from_millis(500));
    assert!(matches!(
        p.sent().last(),
        Some(ToPrompter::Done { ok: false, message: Some(m) }) if m.contains("in progress")
    ));
    assert!(running.join().unwrap().is_err());
}

/// Final-review minor 9: `status` never waits out a busy TPM helper (the
/// full usability check retries for seconds); it asks once.
#[test]
fn status_does_not_wait_out_a_busy_tpm() {
    /// A TPM whose patient check is slow (a busy helper, retried).
    struct Slow;
    impl aleph_daemon::keyring::Tpm for Slow {
        fn seal(&self, _: &[u8]) -> aleph_unlock::Result<(aleph_core::Kek, aleph_core::TpmSlot)> {
            Err(aleph_unlock::Error::TpmBusy)
        }
        fn unseal(
            &self,
            _: &aleph_core::TpmSlot,
            _: &[u8],
        ) -> aleph_unlock::Result<aleph_core::Kek> {
            Err(aleph_unlock::Error::TpmBusy)
        }
        fn usable(&self) -> bool {
            std::thread::sleep(std::time::Duration::from_secs(3));
            false
        }
        fn usable_now(&self) -> Option<bool> {
            None
        }
    }
    let env = env();
    let k = keyring_with(
        &env,
        Box::new(Slow),
        MockKeys::default(),
        Box::new(Fixed(|p| p == PW)),
    );
    let t = std::time::Instant::now();
    let s = k.status().unwrap();
    assert!(t.elapsed() < std::time::Duration::from_millis(500));
    assert_eq!(s.tpm, None);
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
