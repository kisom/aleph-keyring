//! `io.aleph.Admin1` on the session bus (spec §6 "Admin interface").
//!
//! Methods that need the user take a prompter: one end of a socketpair,
//! passed as a Unix fd, speaking the protocol of [`crate::prompt`]. The
//! `aleph` CLI answers it in the terminal; `aleph-gui` in its own windows.
//! Such a method returns as soon as the request is accepted, and the
//! outcome arrives on the prompter as `Done`, so no D-Bus call ever waits
//! for the user (and none runs into a bus reply timeout).
//!
//! Every method that changes keyslots or configuration re-authenticates
//! first (the keyring engine does this).

use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use uuid::Uuid;
use zbus::interface;

use crate::config::Config;
use crate::keyring::Keyring;
use crate::paths::Paths;
use crate::prompt::{Channel, Method};
use crate::secret::service::SecretService;

pub const ADMIN_PATH: &str = "/io/aleph/Admin";
pub const BUS_NAME: &str = "io.aleph.Keyring";

pub struct Admin {
    pub keyring: Arc<Keyring>,
    pub secrets: Arc<SecretService>,
    pub config: Arc<Mutex<Config>>,
    pub paths: Paths,
}

fn failed(msg: impl std::fmt::Display) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(msg.to_string())
}

fn slot_id(id: &str) -> zbus::fdo::Result<Uuid> {
    Uuid::try_parse(id)
        .map_err(|_| zbus::fdo::Error::InvalidArgs(format!("not a keyslot id: {id:?}")))
}

/// How long an import waits for gnome-keyring's own unlock prompt.
const IMPORT_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// The largest backup file read (a vault this size holds a great deal).
const MAX_BACKUP: u64 = 64 * 1024 * 1024;

/// A restore file's bytes: a regular file only (a pipe, terminal, or socket
/// could hold the reading thread indefinitely), at most `MAX_BACKUP`.
fn read_backup(file: std::fs::File) -> zbus::fdo::Result<Vec<u8>> {
    use std::io::Read;
    if !file.metadata().map_err(failed)?.is_file() {
        return Err(zbus::fdo::Error::InvalidArgs(
            "a backup is read only from a regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BACKUP + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if bytes.len() as u64 > MAX_BACKUP {
        return Err(zbus::fdo::Error::InvalidArgs(
            "that file is too large to be a backup".into(),
        ));
    }
    Ok(bytes)
}

/// Refuse a backup target that is not a new (empty) regular file, or lies
/// inside aleph's data or state directory. (A hard link to the vault
/// elsewhere is not empty.)
fn check_backup_target(paths: &Paths, file: &std::fs::File) -> zbus::fdo::Result<()> {
    use std::os::fd::AsRawFd;
    let meta = file.metadata().map_err(failed)?;
    if !meta.is_file() {
        return Err(zbus::fdo::Error::InvalidArgs(
            "the backup target is not a regular file".into(),
        ));
    }
    if meta.len() != 0 {
        return Err(zbus::fdo::Error::InvalidArgs(
            "the backup target is not empty (a backup goes only into a new file)".into(),
        ));
    }
    let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(failed)?;
    for dir in [&paths.data_dir, &paths.state_dir] {
        let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
        if path.starts_with(&dir) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "a backup cannot go inside {}",
                dir.display()
            )));
        }
    }
    Ok(())
}

impl Admin {
    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.lock().unwrap().prompt.timeout)
    }

    /// Run a conversation on the caller's prompter in the background, then
    /// bring the Secret Service objects up to date.
    fn converse(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        work: impl FnOnce(&Keyring, &mut Channel) -> crate::Result<()> + Send + 'static,
    ) -> zbus::fdo::Result<()> {
        let mut chan = Channel::from_fd(OwnedFd::from(prompter), self.timeout()).map_err(failed)?;
        let (keyring, secrets) = (self.keyring.clone(), self.secrets.clone());
        tokio::spawn(async move {
            let k = keyring.clone();
            let result = tokio::task::spawn_blocking(move || work(&k, &mut chan)).await;
            if let Ok(Err(e)) = &result {
                tracing::info!("admin operation ended: {e}");
            }
            if keyring.is_locked() {
                let _ = secrets.sync().await;
            } else {
                let _ = secrets.unlocked().await;
            }
        });
        Ok(())
    }
}

#[interface(name = "io.aleph.Admin1")]
impl Admin {
    /// The keyring's state as JSON (`keyring::Status`).
    async fn status(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        // Reads the vault header and asks the TPM helper: off the runtime.
        let keyring = self.keyring.clone();
        let mut status = tokio::task::spawn_blocking(move || keyring.status())
            .await
            .map_err(failed)?
            .map_err(failed)?;
        status.secret_service = Some(crate::daemon::secret_service_owner(conn).await);
        serde_json::to_string(&status).map_err(failed)
    }

    /// Import every gnome-keyring item (DECISIONS.md E1, E2) while
    /// gnome-keyring still owns `org.freedesktop.secrets`, then keep
    /// following it until the name changes hands. Returns the summary.
    async fn import_gnome_keyring(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        if self.keyring.is_locked() {
            return Err(zbus::fdo::Error::Failed(
                "the keyring is locked: unlock it first (`aleph unlock`)".into(),
            ));
        }
        let Some(importer) = crate::import::Importer::connect(conn, IMPORT_PROMPT_TIMEOUT)
            .await
            .map_err(failed)?
        else {
            return Ok("gnome-keyring is not running: nothing to import.".into());
        };
        let mut summary = crate::import::Summary::default();
        let fetched = importer
            .fetch_all(&mut summary.skipped)
            .await
            .map_err(failed)?;
        let keyring = self.keyring.clone();
        let summary = tokio::task::spawn_blocking(move || {
            keyring.modify(|body| {
                crate::import::merge(body, fetched, &mut summary);
                Ok(summary)
            })
        })
        .await
        .map_err(failed)?
        .map_err(failed)?;
        let _ = self.secrets.unlocked().await;
        tokio::spawn(importer.follow(self.keyring.clone(), self.secrets.clone()));
        Ok(summary.to_string())
    }

    async fn lock(&self) -> zbus::fdo::Result<()> {
        self.secrets.lock().await.map_err(failed)
    }

    async fn unlock(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.unlock(chan, None))
    }

    /// Create the vault; `method` is `password` or `fido2`.
    async fn create(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        method: String,
    ) -> zbus::fdo::Result<()> {
        let method = match method.as_str() {
            "password" => Method::Password,
            "fido2" => Method::Fido2,
            other => {
                return Err(zbus::fdo::Error::InvalidArgs(format!(
                    "unknown method {other:?}"
                )));
            }
        };
        self.converse(prompter, move |k, chan| k.create(chan, method))
    }

    async fn enroll_tpm(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.enroll_tpm(chan))
    }

    async fn enroll_fido2(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        touch_only: bool,
    ) -> zbus::fdo::Result<()> {
        self.converse(prompter, move |k, chan| k.enroll_fido2(chan, touch_only))
    }

    async fn remove_keyslot(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        id: String,
    ) -> zbus::fdo::Result<()> {
        let id = slot_id(&id)?;
        self.converse(prompter, move |k, chan| k.remove_keyslot(chan, id))
    }

    async fn rotate_master(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.rotate_master(chan))
    }

    async fn reissue_recovery_key(
        &self,
        prompter: zbus::zvariant::OwnedFd,
    ) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.reissue_recovery(chan))
    }

    /// Recover the current vault with the recovery key (`aleph restore`).
    async fn recover(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.recover(chan, None))
    }

    /// Restore the backup file `file` (opened by the caller) with its
    /// recovery key (`aleph restore <file>`).
    async fn restore_backup(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        file: zbus::zvariant::OwnedFd,
    ) -> zbus::fdo::Result<()> {
        let file = std::fs::File::from(OwnedFd::from(file));
        let bytes = tokio::task::spawn_blocking(move || read_backup(file))
            .await
            .map_err(failed)??;
        self.converse(prompter, move |k, chan| k.recover(chan, Some(&bytes)))
    }

    /// Replace an unreadable vault file with its backup copy
    /// (`aleph restore --from-bak`).
    async fn restore_from_bak(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.restore_from_bak(chan))
    }

    /// Accept a rolled-back, replaced, or different vault file
    /// (`aleph restore --accept-rollback`).
    async fn accept_rollback(&self, prompter: zbus::zvariant::OwnedFd) -> zbus::fdo::Result<()> {
        self.converse(prompter, |k, chan| k.accept_rollback(chan))
    }

    /// Write a backup into `file`, which the caller opened: a regular file
    /// outside aleph's own directories (a backup over the live vault would
    /// leave only the recovery slot).
    async fn backup(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        file: zbus::zvariant::OwnedFd,
    ) -> zbus::fdo::Result<()> {
        let file = std::fs::File::from(OwnedFd::from(file));
        check_backup_target(&self.paths, &file)?;
        self.converse(prompter, move |k, chan| {
            k.backup(chan, |bytes| {
                use std::io::Write;
                (&file).write_all(bytes)?;
                file.sync_all()?;
                Ok(())
            })
        })
    }

    /// Clear a keyslot's stale mark so it is tried again.
    async fn retry_keyslot(&self, id: String) -> zbus::fdo::Result<()> {
        self.keyring.retry_slot(slot_id(&id)?).map_err(failed)
    }

    async fn get_config(&self, key: String) -> zbus::fdo::Result<String> {
        self.config.lock().unwrap().get(&key).map_err(failed)
    }

    /// Change a setting (after re-authentication) and save the file.
    async fn set_config(
        &self,
        prompter: zbus::zvariant::OwnedFd,
        key: String,
        value: String,
    ) -> zbus::fdo::Result<()> {
        // Reject a bad key or value now, before asking the user anything.
        let mut preview = self.config.lock().unwrap().clone();
        preview.set(&key, &value).map_err(failed)?;
        let (config, file) = (self.config.clone(), self.paths.config_file.clone());
        self.converse(prompter, move |k, chan| {
            k.with_reauth(chan, &format!("Set {key} = {value}"), || {
                let mut current = config.lock().unwrap();
                let mut next = current.clone();
                next.set(&key, &value)?;
                next.save(&file)?;
                *current = next;
                Ok(Some(format!("{key} = {value}")))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pipe (or a terminal, a socket) is never read as a backup: it
    /// could hold a daemon thread until the other end closes.
    #[test]
    fn only_a_regular_file_is_read_as_a_backup() {
        let (r, w) = std::io::pipe().unwrap();
        drop(w);
        let f = std::fs::File::from(OwnedFd::from(r));
        assert!(read_backup(f).is_err());
    }

    /// A backup goes only into a new, empty regular file outside aleph's
    /// directories (a hard link to the vault elsewhere is not empty).
    #[test]
    fn a_backup_target_must_be_empty_and_outside_aleph() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(&dir.path().join("aleph"));
        std::fs::create_dir_all(&paths.data_dir).unwrap();
        let outside = dir.path().join("backup");
        std::fs::write(&outside, b"").unwrap();
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&outside)
            .unwrap();
        assert!(check_backup_target(&paths, &f).is_ok());
        std::fs::write(&outside, b"a vault").unwrap();
        assert!(check_backup_target(&paths, &f).is_err());
        let inside = paths.data_dir.join("copy");
        std::fs::write(&inside, b"").unwrap();
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&inside)
            .unwrap();
        assert!(check_backup_target(&paths, &f).is_err());
    }
}
