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
    async fn status(&self) -> zbus::fdo::Result<String> {
        // Reads the vault header and asks the TPM helper: off the runtime.
        let keyring = self.keyring.clone();
        let status = tokio::task::spawn_blocking(move || keyring.status())
            .await
            .map_err(failed)?
            .map_err(failed)?;
        serde_json::to_string(&status).map_err(failed)
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
