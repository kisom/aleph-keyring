//! `pam.sock` with the real daemon (keyring on swtpm, Secret Service on a
//! private bus), the test playing `pam_aleph`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use aleph_daemon::testing::*;
use aleph_pam_proto::{Password, Reply, Request};
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

/// A daemon with `pam.sock` served at a temporary path.
async fn served() -> (Daemon, PathBuf) {
    served_with(Box::new(Fixed(|p| p == PW))).await
}

/// `served`, with the given password check (PAM).
async fn served_with(check: Box<dyn aleph_daemon::password::PasswordCheck>) -> (Daemon, PathBuf) {
    let d = daemon_with(true, vec![], check).await;
    let path = d.env.paths.pam_socket();
    let listener = aleph_daemon::pamsock::listener(&path).unwrap();
    let (keyring, secrets) = (d.keyring.clone(), d.secrets.clone());
    tokio::spawn(aleph_daemon::pamsock::serve(listener, keyring, secrets));
    (d, path)
}

/// Send `request` as `pam_aleph` would; `None` if the daemon hung up
/// without a reply.
async fn send_raw(path: &std::path::Path, frame: Vec<u8>) -> Option<Reply> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut s = UnixStream::connect(&path).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        s.write_all(&frame).unwrap();
        let mut header = [0u8; 4];
        s.read_exact(&mut header).ok()?;
        let mut payload = vec![0u8; aleph_pam_proto::payload_len(header).unwrap()];
        s.read_exact(&mut payload).unwrap();
        Some(Reply::decode(&payload).unwrap())
    })
    .await
    .unwrap()
}

async fn send(path: &std::path::Path, request: Request) -> Reply {
    send_raw(path, request.encode().unwrap().to_vec())
        .await
        .expect("a reply")
}

fn unlock(pw: &str) -> Request {
    Request::Unlock {
        password: Password::new(pw.as_bytes()),
    }
}

/// The login password unlocks the vault, and a Secret Service prompt that
/// was waiting (no prompter at login) completes with it: the client that
/// asked before the unlock gets its answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_login_password_unlocks_and_completes_waiting_prompts() {
    use futures_util::StreamExt;
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    let c = zbus::connection::Builder::address(d.bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let svc = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = svc
        .call(
            "Unlock",
            &(vec![
                ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
            ],),
        )
        .await
        .unwrap();
    let p = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    let mut completed = p.receive_signal("Completed").await.unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(d.secrets.waiting_count(), 1);

    let reply = send(&path, unlock(PW)).await;
    assert!(reply.ok, "{reply:?}");
    assert!(!d.keyring.is_locked());
    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), completed.next())
        .await
        .expect("the waiting prompt completes")
        .unwrap();
    let (dismissed, _): (bool, zbus::zvariant::OwnedValue) = msg.body().deserialize().unwrap();
    assert!(!dismissed);
}

/// Failed requests are limited: after five, even the right password is
/// refused for a while, so a same-user process cannot guess through the
/// socket (and the TPM helper's own limit keeps its failures low).
#[tokio::test(flavor = "multi_thread")]
async fn failed_requests_are_limited() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    for _ in 0..aleph_daemon::password::TYPED_FAILURES {
        assert!(!send(&path, unlock("wrong")).await.ok);
    }
    let reply = send(&path, unlock(PW)).await;
    assert!(!reply.ok && reply.message.contains("too many"), "{reply:?}");
    assert!(d.keyring.is_locked());
    // (PAM rejected every wrong one: none reached the TPM.)
    assert_eq!(d.env.sw.tpm().status().unwrap().failed_tries, 0);
}

/// `passwd`'s change arrives through the socket; the new password then
/// unlocks.
#[tokio::test(flavor = "multi_thread")]
async fn a_password_change_arrives_through_the_socket() {
    let login = Accepting::new(PW);
    let (d, path) = served_with(Box::new(login.clone())).await;
    // passwd has changed the password when pam_aleph runs.
    login.set("new password");
    let reply = send(
        &path,
        Request::ChangePassword {
            old: Password::new(PW.as_bytes()),
            new: Password::new(b"new password"),
        },
    )
    .await;
    assert!(reply.ok, "{reply:?}");
    d.secrets.lock().await.unwrap();
    assert!(send(&path, unlock("new password")).await.ok);
    assert!(!d.keyring.is_locked());
}

/// The module's own delivery code (fork, connect, answer) against the
/// daemon's socket: the two ends agree.
#[tokio::test(flavor = "multi_thread")]
async fn pam_aleph_delivers_to_the_daemon() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    let outcome = tokio::task::spawn_blocking(move || {
        // SAFETY: getuid/getgid cannot fail.
        let me = unsafe {
            pam_aleph::deliver::Target {
                uid: libc::getuid(),
                gid: libc::getgid(),
            }
        };
        let frame = unlock(PW).encode().unwrap();
        pam_aleph::deliver::deliver(me, &path, &frame, pam_aleph::TIMEOUT)
    })
    .await
    .unwrap();
    assert_eq!(outcome, pam_aleph::deliver::Outcome::Accepted);
    assert!(!d.keyring.is_locked());
}

/// A conversation nobody answers holds the daemon's operation lock; returns
/// the prompter's end (drop it to end the conversation) and its thread.
fn hold_a_conversation(
    d: &Daemon,
) -> (
    UnixStream,
    std::thread::JoinHandle<aleph_daemon::Result<()>>,
) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let mut silent =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(60)).unwrap();
    let keyring = d.keyring.clone();
    let thread = std::thread::spawn(move || keyring.unlock(&mut silent, None));
    std::thread::sleep(std::time::Duration::from_millis(200));
    (theirs, thread)
}

fn change(old: &str, new: &str) -> Request {
    Request::ChangePassword {
        old: Password::new(old.as_bytes()),
        new: Password::new(new.as_bytes()),
    }
}

/// A new password PAM rejects is refused at once, even while a
/// conversation holds the daemon (nothing queues behind it).
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_new_password_is_refused_without_waiting() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    let (prompter, conversation) = hold_a_conversation(&d);
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        send(&path, change(PW, "not the login password")),
    )
    .await
    .expect("refused without waiting");
    assert!(
        !reply.ok && reply.message.contains("not the login password"),
        "{reply:?}"
    );
    drop(prompter);
    assert!(conversation.join().unwrap().is_err());
}

/// Requests being answered count against the limit, so parallel
/// connections cannot get past it: with a conversation holding the daemon,
/// five changes wait their turn and the rest are refused at once.
#[tokio::test(flavor = "multi_thread")]
async fn requests_in_flight_are_bounded() {
    let login = Accepting::new(PW);
    let (d, path) = served_with(Box::new(login.clone())).await;
    d.secrets.lock().await.unwrap();
    login.set("new");
    let (prompter, conversation) = hold_a_conversation(&d);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for _ in 0..7 {
        let (path, tx) = (path.clone(), tx.clone());
        tokio::spawn(async move { tx.send(send(&path, change(PW, "new")).await).unwrap() });
    }
    for _ in 0..2 {
        let reply = tokio::time::timeout(std::time::Duration::from_secs(20), rx.recv())
            .await
            .expect("refused at once")
            .unwrap();
        assert!(!reply.ok && reply.message.contains("at once"), "{reply:?}");
    }
    drop(prompter);
    assert!(conversation.join().unwrap().is_err());
    for _ in 0..5 {
        tokio::time::timeout(std::time::Duration::from_secs(60), rx.recv())
            .await
            .expect("answered once the conversation ended")
            .unwrap();
    }
}

/// A malformed request gets no reply, and the socket keeps serving.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_request_is_dropped() {
    let (d, path) = served().await;
    d.secrets.lock().await.unwrap();
    assert_eq!(send_raw(&path, vec![0, 0, 0, 1, 99]).await, None);
    assert!(send(&path, unlock(PW)).await.ok);
}

/// A leftover socket file (a crashed daemon) is replaced; anything else
/// at the path is left alone.
#[test]
fn the_listener_replaces_only_a_leftover_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run/aleph/pam.sock");
    drop(aleph_daemon::pamsock::listener(&path).unwrap());
    let l = aleph_daemon::pamsock::listener(&path).unwrap();
    drop(l);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"not a socket").unwrap();
    assert!(aleph_daemon::pamsock::listener(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
}

/// A socket something still serves (`alephd.socket`, when alephd is run by
/// hand) is left alone.
#[test]
fn the_listener_leaves_a_served_socket_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("run/aleph/pam.sock");
    let serving = aleph_daemon::pamsock::listener(&path).unwrap();
    assert!(aleph_daemon::pamsock::listener(&path).is_err());
    drop(serving);
    // (Nobody serves it now: a leftover, replaced.)
    drop(aleph_daemon::pamsock::listener(&path).unwrap());
}
