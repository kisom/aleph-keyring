//! The lock policy against a stand-in logind (sleep, screen lock) and the
//! idle timer, with the real daemon.

use std::sync::Mutex;
use std::time::Duration;

use aleph_daemon::config::Config;
use aleph_daemon::testing::*;

/// Wait up to `secs` for `cond`.
async fn eventually(secs: u64, cond: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cond()
}

/// An unlocked daemon following the stand-in logind with `config`, and the
/// unique name of its connection to the (stand-in) system bus.
async fn following(config: Config) -> (Daemon, Logind, Arc<Mutex<Config>>, String) {
    let d = daemon(true, vec![]).await;
    let logind = Logind::start(&d.bus.address).await;
    let config = Arc::new(Mutex::new(config));
    let system = zbus::connection::Builder::address(d.bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let name = system.unique_name().unwrap().to_string();
    tokio::spawn(aleph_daemon::lockpolicy::watch_logind(
        system,
        d.secrets.clone(),
        config.clone(),
    ));
    assert!(eventually(5, || logind.inhibitors() == 1).await);
    assert!(!d.keyring.is_locked());
    (d, logind, config, name)
}

/// Before sleep the vault locks, and only then is the inhibitor released;
/// on resume a new one is taken.
#[tokio::test(flavor = "multi_thread")]
async fn sleep_locks_first_then_lets_the_sleep_go() {
    let (d, logind, _, _) = following(Config::default()).await;
    assert!(!logind.released(0));
    logind.sleep(true).await;
    assert!(eventually(5, || logind.released(0)).await);
    assert!(d.keyring.is_locked());
    logind.sleep(false).await;
    assert!(eventually(5, || logind.inhibitors() == 2).await);
    assert!(!logind.released(1));
}

/// With `on_suspend` off the vault stays unlocked, and the sleep is still
/// let go.
#[tokio::test(flavor = "multi_thread")]
async fn with_on_suspend_off_sleep_does_not_lock() {
    let mut config = Config::default();
    config.lock.on_suspend = false;
    let (d, logind, _, _) = following(config).await;
    logind.sleep(true).await;
    assert!(eventually(5, || logind.released(0)).await);
    assert!(!d.keyring.is_locked());
}

/// Locking this user's session locks the vault; another user's does not,
/// and neither does anything with `on_screen_lock` off.
#[tokio::test(flavor = "multi_thread")]
async fn a_screen_lock_of_this_user_locks() {
    let (d, logind, config, _) = following(Config::default()).await;
    logind.lock_session("other").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!d.keyring.is_locked());
    config.lock().unwrap().lock.on_screen_lock = false;
    logind.lock_session("mine").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!d.keyring.is_locked());
    config.lock().unwrap().lock.on_screen_lock = true;
    logind.lock_session("mine").await;
    assert!(eventually(5, || d.keyring.is_locked()).await);
}

/// A `Session.Lock` from anyone but logind (any peer can send a directed
/// signal) is ignored.
#[tokio::test(flavor = "multi_thread")]
async fn a_spoofed_screen_lock_is_ignored() {
    let (d, logind, _, watcher) = following(Config::default()).await;
    let spoofer = zbus::connection::Builder::address(d.bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    spoofer
        .emit_signal(
            Some(watcher.as_str()),
            "/org/freedesktop/login1/session/mine",
            "org.freedesktop.login1.Session",
            "Lock",
            &(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!d.keyring.is_locked());
    logind.lock_session("mine").await;
    assert!(eventually(5, || d.keyring.is_locked()).await);
}

/// With an idle timeout, the vault locks once nothing has read or written
/// a secret for that long, and not while it is in use.
#[tokio::test(flavor = "multi_thread")]
async fn an_idle_vault_locks() {
    let d = daemon(true, vec![]).await;
    let mut config = Config::default();
    config.lock.idle_timeout = 1;
    tokio::spawn(aleph_daemon::lockpolicy::lock_when_idle(
        d.keyring.clone(),
        d.secrets.clone(),
        Arc::new(Mutex::new(config)),
    ));
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        d.keyring.read(|_| ()).unwrap();
        assert!(!d.keyring.is_locked());
    }
    assert!(eventually(4, || d.keyring.is_locked()).await);
}
