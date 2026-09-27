//! Lock policy (spec §6 "Lock policy"), from `[lock]` in `config.toml`,
//! read at each event so changes apply at once.
//!
//! - **Sleep** (`on_suspend`): while running, `alephd` holds a logind
//!   `delay` inhibitor for `sleep`. On `PrepareForSleep(true)` it locks,
//!   then releases the inhibitor so the sleep can go ahead; on resume it
//!   takes a new one. logind does not say which sleep is coming, and
//!   suspend-then-hibernate moves on to hibernating without telling
//!   anyone, so `on_suspend` covers hibernation too.
//! - **Screen lock** (`on_screen_lock`): logind's `Session.Lock` signal
//!   (`loginctl lock-session`, which hypridle sends) for a session of this
//!   user. Only a signal whose sender is logind itself counts: any peer can
//!   send a directed signal, and a match rule cannot check a well-known
//!   sender on the receiving side.
//! - **Idle** (`idle_timeout`): no secret read or written for that many
//!   seconds.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use zbus::Connection;
use zbus::zvariant::OwnedObjectPath;

use crate::config::Config;
use crate::keyring::Keyring;
use crate::secret::service::SecretService;

const LOGIN1: &str = "org.freedesktop.login1";

/// Follow logind on `system` (the system bus) until it goes away.
pub async fn watch_logind(
    system: Connection,
    secrets: Arc<SecretService>,
    config: Arc<Mutex<Config>>,
) -> zbus::Result<()> {
    let manager = zbus::Proxy::new(
        &system,
        LOGIN1,
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await?;
    let mut sleeps = manager.receive_signal("PrepareForSleep").await?;
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(LOGIN1)?
        .interface("org.freedesktop.login1.Session")?
        .member("Lock")?
        .path_namespace("/org/freedesktop/login1/session")?
        .build();
    let mut locks = zbus::MessageStream::for_match_rule(rule, &system, None).await?;
    let dbus = zbus::fdo::DBusProxy::new(&system).await?;
    let mut inhibitor = Some(inhibit(&manager).await?);
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    loop {
        tokio::select! {
            Some(msg) = sleeps.next() => {
                let (starting,): (bool,) = msg.body().deserialize()?;
                if starting {
                    if config.lock().unwrap().lock.on_suspend {
                        if let Err(e) = secrets.lock().await {
                            tracing::error!("could not lock before sleep: {e}");
                        }
                        tracing::info!("locked before sleep");
                    }
                    // Done: let the sleep go ahead.
                    inhibitor = None;
                } else if inhibitor.is_none() {
                    inhibitor = inhibit(&manager).await.ok();
                }
            }
            Some(Ok(msg)) = locks.next() => {
                if !config.lock().unwrap().lock.on_screen_lock {
                    continue;
                }
                let Some(path) = msg.header().path().map(|p| OwnedObjectPath::from(p.to_owned())) else {
                    continue;
                };
                if !from_logind(&dbus, &msg).await {
                    tracing::warn!("ignored a Session.Lock that did not come from logind");
                    continue;
                }
                if session_uid(&system, path).await == Some(uid) {
                    if let Err(e) = secrets.lock().await {
                        tracing::error!("could not lock with the screen: {e}");
                    }
                    tracing::info!("locked with the screen");
                }
            }
            else => return Ok(()),
        }
    }
}

/// Whether `msg` was sent by the current owner of logind's name.
async fn from_logind(dbus: &zbus::fdo::DBusProxy<'_>, msg: &zbus::Message) -> bool {
    let Ok(name) = zbus::names::BusName::try_from(LOGIN1) else {
        return false;
    };
    match (dbus.get_name_owner(name).await, msg.header().sender()) {
        (Ok(owner), Some(sender)) => owner.as_str() == sender.as_str(),
        _ => false,
    }
}

/// A `delay` inhibitor for sleep: sleep waits until it is closed.
async fn inhibit(manager: &zbus::Proxy<'_>) -> zbus::Result<zbus::zvariant::OwnedFd> {
    manager
        .call(
            "Inhibit",
            &("sleep", "aleph", "Lock the keyring before sleep", "delay"),
        )
        .await
}

/// The uid owning the logind session at `path`.
async fn session_uid(system: &Connection, path: OwnedObjectPath) -> Option<u32> {
    let session = zbus::Proxy::new(system, LOGIN1, path, "org.freedesktop.login1.Session")
        .await
        .ok()?;
    let (uid, _): (u32, OwnedObjectPath) = session.get_property("User").await.ok()?;
    Some(uid)
}

/// Lock after `lock.idle_timeout` seconds without secret access.
pub async fn lock_when_idle(
    keyring: Arc<Keyring>,
    secrets: Arc<SecretService>,
    config: Arc<Mutex<Config>>,
) {
    loop {
        let timeout = config.lock().unwrap().lock.idle_timeout;
        // Check often enough for the timeout, and at least twice a minute
        // (a changed setting applies by then).
        let every = if timeout == 0 {
            30
        } else {
            timeout.clamp(1, 30)
        };
        tokio::time::sleep(Duration::from_secs(every)).await;
        if timeout > 0 && !keyring.is_locked() && keyring.idle_for() >= Duration::from_secs(timeout)
        {
            if let Err(e) = secrets.lock().await {
                tracing::error!("could not lock when idle: {e}");
            }
            tracing::info!("locked after {timeout} s without use");
        }
    }
}
