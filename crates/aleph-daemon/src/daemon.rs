//! Putting the daemon together: the keyring, the Secret Service, and the
//! admin interface on one bus connection. `main` uses this; so do the
//! integration tests, with a private bus and scripted prompters.

use std::sync::{Arc, Mutex};

use zbus::Connection;

use crate::admin::{ADMIN_PATH, Admin};
use crate::config::Config;
use crate::keyring::Keyring;
use crate::paths::Paths;
use crate::prompt::Launcher;
use crate::secret::service::SecretService;

/// Queue for `org.freedesktop.secrets`: never replacing its owner (while
/// gnome-keyring still runs, say) and never replaceable, so the bus hands
/// the name over the moment its owner releases it and it is never unowned
/// (DECISIONS.md E1). Returns whether this connection owns it now.
pub async fn request_secrets_name(conn: &Connection) -> zbus::Result<bool> {
    use enumflags2::BitFlag;
    let reply = conn
        .request_name_with_flags(
            crate::import::SECRETS_NAME,
            zbus::fdo::RequestNameFlags::empty(),
        )
        .await?;
    Ok(matches!(
        reply,
        zbus::fdo::RequestNameReply::PrimaryOwner | zbus::fdo::RequestNameReply::AlreadyOwner
    ))
}

/// Whether alephd claims the Secret Service at start: only while setup's
/// activation file (`activation`) is in place. Before setup (which claims it
/// through the admin interface) and after a revert, it is gnome-keyring's.
pub fn claims_at_start(activation: Option<&std::path::Path>) -> bool {
    activation.is_some_and(|a| a.exists())
}

/// Who owns `org.freedesktop.secrets` on `conn`'s bus, for `Status`:
/// `alephd`, `another program`, or `nobody`.
pub async fn secret_service_owner(conn: &Connection) -> String {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(conn).await else {
        return "unknown".into();
    };
    let Ok(name) = zbus::names::BusName::try_from(crate::import::SECRETS_NAME) else {
        return "unknown".into();
    };
    match dbus.get_name_owner(name).await {
        Ok(owner) if conn.unique_name().is_some_and(|me| *me == owner) => "alephd".into(),
        Ok(_) => "another program".into(),
        Err(_) => "nobody".into(),
    }
}

/// Serve the Secret Service and `io.aleph.Admin1` on `conn`, which should
/// own `io.aleph.Keyring` (and then queue for `org.freedesktop.secrets`,
/// [`request_secrets_name`]).
pub async fn serve(
    conn: &Connection,
    keyring: Arc<Keyring>,
    launcher: Arc<dyn Launcher>,
    config: Arc<Mutex<Config>>,
    paths: Paths,
) -> zbus::Result<Arc<SecretService>> {
    let secrets = SecretService::new(keyring.clone(), launcher);
    secrets.serve(conn).await?;
    conn.object_server()
        .at(
            ADMIN_PATH,
            Admin {
                keyring,
                secrets: secrets.clone(),
                config,
                paths,
            },
        )
        .await?;
    Ok(secrets)
}

#[cfg(test)]
mod claim_tests {
    /// alephd claims the Secret Service at start only while setup's
    /// activation file is in place.
    #[test]
    fn the_name_is_claimed_only_with_the_activation_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("org.freedesktop.secrets.service");
        assert!(!super::claims_at_start(Some(&file)));
        assert!(!super::claims_at_start(None));
        std::fs::write(&file, "x").unwrap();
        assert!(super::claims_at_start(Some(&file)));
    }
}
