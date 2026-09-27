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

/// Serve the Secret Service and `io.aleph.Admin1` on `conn`, which should
/// own `org.freedesktop.secrets` and `io.aleph.Keyring`.
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
