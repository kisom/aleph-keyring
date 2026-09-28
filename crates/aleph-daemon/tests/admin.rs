//! `io.aleph.Admin1` over a private bus, with the test as the prompter on
//! its end of a socketpair (as the `aleph` CLI is).

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use aleph_daemon::config::Config;
use aleph_daemon::testing::*;
use serde_json::Value as Json;

struct Daemon {
    _bus: Bus,
    _env: Env,
    _conn: zbus::Connection,
    client: zbus::Connection,
    paths: Paths,
}

async fn daemon() -> Daemon {
    let env = env();
    let bus = bus();
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.secrets")
        .unwrap()
        .name("io.aleph.Keyring")
        .unwrap()
        .build()
        .await
        .unwrap();
    let keyring = Arc::new(keyring(&env, MockKeys::default()));
    let launcher = Arc::new(InteractiveLauncher::new(vec![]));
    aleph_daemon::daemon::serve(
        &conn,
        keyring,
        launcher,
        Arc::new(std::sync::Mutex::new(Config::default())),
        env.paths.clone(),
    )
    .await
    .unwrap();
    let client = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    Daemon {
        paths: env.paths.clone(),
        _bus: bus,
        _env: env,
        _conn: conn,
        client,
    }
}

async fn admin(d: &Daemon) -> zbus::Proxy<'static> {
    zbus::Proxy::new(
        &d.client,
        "io.aleph.Keyring",
        "/io/aleph/Admin",
        "io.aleph.Admin1",
    )
    .await
    .unwrap()
}

/// Call a conversational method with a prompter answering `replies`;
/// returns what the prompter was sent, once the conversation is done.
async fn converse(
    d: &Daemon,
    method: &str,
    extra: &[&str],
    replies: Vec<FromPrompter>,
) -> Vec<ToPrompter> {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let prompter = Interactive::new(replies);
    prompter.respond(ours);
    let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
    let proxy = admin(d).await;
    match extra {
        [] => proxy.call_method(method, &(fd,)).await,
        [a] => proxy.call_method(method, &(fd, *a)).await,
        [a, b] => proxy.call_method(method, &(fd, *a, *b)).await,
        _ => unreachable!(),
    }
    .unwrap();
    tokio::task::spawn_blocking(move || prompter.sent())
        .await
        .unwrap()
}

async fn status(d: &Daemon) -> Json {
    let s: String = admin(d).await.call("Status", &()).await.unwrap();
    serde_json::from_str(&s).unwrap()
}

fn done(sent: &[ToPrompter]) -> (bool, Option<String>) {
    match sent.last() {
        Some(ToPrompter::Done { ok, message }) => (*ok, message.clone()),
        other => panic!("conversation did not finish: {other:?}"),
    }
}

async fn collections(d: &Daemon) -> Vec<String> {
    let p = zbus::Proxy::new(
        &d.client,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    let v: Vec<zbus::zvariant::OwnedObjectPath> = p.get_property("Collections").await.unwrap();
    v.into_iter().map(|p| p.to_string()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn create_lock_and_unlock_through_the_admin_interface() {
    let d = daemon().await;
    assert_eq!(status(&d).await["vault"], false);
    let sent = converse(&d, "Create", &["password"], vec![password(PW)]).await;
    assert!(done(&sent).0, "{sent:?}");
    let s = status(&d).await;
    assert_eq!(
        (s["vault"].clone(), s["locked"].clone()),
        (true.into(), false.into())
    );
    // Unlocked: the real collections are served.
    assert!(collections(&d).await[0].contains("/collection/"));

    admin(&d).await.call_method("Lock", &()).await.unwrap();
    assert_eq!(status(&d).await["locked"], true);
    assert_eq!(
        collections(&d).await,
        ["/org/freedesktop/secrets/aliases/default"]
    );

    let sent = converse(&d, "Unlock", &[], vec![password("typo"), password(PW)]).await;
    assert!(done(&sent).0);
    assert_eq!(status(&d).await["locked"], false);
    assert!(collections(&d).await[0].contains("/collection/"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_unlock_reports_failure_and_stays_locked() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    admin(&d).await.call_method("Lock", &()).await.unwrap();
    let sent = converse(&d, "Unlock", &[], vec![FromPrompter::Cancel {}]).await;
    assert_eq!(done(&sent), (false, Some("cancelled".into())));
    assert_eq!(status(&d).await["locked"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn setting_config_reauthenticates_and_saves() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    // A bad key is refused at once, before any prompt.
    let (_, theirs) = UnixStream::pair().unwrap();
    let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
    assert!(
        admin(&d)
            .await
            .call_method("SetConfig", &(fd, "lock.idel", "1"))
            .await
            .is_err()
    );
    let sent = converse(
        &d,
        "SetConfig",
        &["lock.idle_timeout", "900"],
        vec![password(PW)],
    )
    .await;
    assert!(done(&sent).0, "{sent:?}");
    assert!(sent.iter().any(|m| matches!(
        m,
        ToPrompter::Begin {
            purpose: aleph_daemon::prompt::Purpose::Reauth,
            ..
        }
    )));
    let v: String = admin(&d)
        .await
        .call("GetConfig", &("lock.idle_timeout",))
        .await
        .unwrap();
    assert_eq!(v, "900");
    assert_eq!(
        Config::load(&d.paths.config_file)
            .unwrap()
            .lock
            .idle_timeout,
        900
    );
}

/// `Reauth` proves an enrolled method again and does nothing else: the
/// manager's guard before it shows or copies a secret (the manager spec).
#[tokio::test(flavor = "multi_thread")]
async fn reauth_confirms_and_changes_nothing() {
    let d = daemon().await;
    converse(&d, "Create", &["password"], vec![password(PW)]).await;
    let before = status(&d).await;
    let sent = converse(&d, "Reauth", &[], vec![password(PW)]).await;
    assert!(
        matches!(
            sent.first(),
            Some(ToPrompter::Begin {
                purpose: aleph_daemon::prompt::Purpose::Reauth,
                ..
            })
        ),
        "{sent:?}"
    );
    assert_eq!(done(&sent), (true, None));
    assert_eq!(status(&d).await, before);
    // A wrong password is refused (and a typo never reaches the TPM).
    let sent = converse(
        &d,
        "Reauth",
        &[],
        vec![password("typo"), FromPrompter::Cancel {}],
    )
    .await;
    assert!(!done(&sent).0, "{sent:?}");
}
