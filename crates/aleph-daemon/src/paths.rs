//! Where aleph keeps its files (spec §4 "File", §6 "Lock policy").
//!
//! | What | Where |
//! |---|---|
//! | vault | `$XDG_DATA_HOME/aleph/vault.aleph` |
//! | high-water marks, slot state | `$XDG_STATE_HOME/aleph/` |
//! | configuration | `$XDG_CONFIG_HOME/aleph/config.toml` |
//! | sockets | `$XDG_RUNTIME_DIR/aleph/` |

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub state_dir: PathBuf,
    pub config_file: PathBuf,
    pub runtime_dir: PathBuf,
}

impl Paths {
    /// From the XDG environment variables, with the XDG defaults under
    /// `$HOME`. Relative XDG values are ignored, as the XDG spec requires.
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let home = var("HOME").ok_or(Error::Environment("HOME is not set"))?;
        let runtime = var("XDG_RUNTIME_DIR").ok_or(Error::Environment(
            "XDG_RUNTIME_DIR is not set (not in a login session?)",
        ))?;
        Ok(Self {
            data_dir: var("XDG_DATA_HOME")
                .unwrap_or_else(|| home.join(".local/share"))
                .join("aleph"),
            state_dir: var("XDG_STATE_HOME")
                .unwrap_or_else(|| home.join(".local/state"))
                .join("aleph"),
            config_file: var("XDG_CONFIG_HOME")
                .unwrap_or_else(|| home.join(".config"))
                .join("aleph/config.toml"),
            runtime_dir: runtime.join("aleph"),
        })
    }

    /// Everything under one directory (tests).
    pub fn under(root: &Path) -> Self {
        Self {
            data_dir: root.join("data/aleph"),
            state_dir: root.join("state/aleph"),
            config_file: root.join("config/aleph/config.toml"),
            runtime_dir: root.join("run/aleph"),
        }
    }

    pub fn vault(&self) -> PathBuf {
        self.data_dir.join("vault.aleph")
    }

    /// Held by the running daemon for its whole lifetime.
    pub fn daemon_lock(&self) -> PathBuf {
        self.data_dir.join("vault.aleph.daemon")
    }

    /// Which slots are stale (§5), kept outside the vault because it
    /// changes while the vault is locked.
    pub fn slot_state(&self) -> PathBuf {
        self.state_dir.join("slots.json")
    }

    /// The previous version of the vault, kept by every write (§4).
    pub fn bak(&self) -> PathBuf {
        self.data_dir.join("vault.aleph.bak")
    }

    /// The id of the vault this machine expects at the path (recorded at
    /// create and restore; a different vault there is not trusted).
    pub fn expected_vault(&self) -> PathBuf {
        self.state_dir.join("vault-id")
    }

    /// The items `aleph setup` imported from gnome-keyring (for revert).
    pub fn imported(&self) -> PathBuf {
        self.state_dir.join("imported.json")
    }

    /// Where `pam_aleph` hands over the login password (§6).
    pub fn pam_socket(&self) -> PathBuf {
        self.runtime_dir.join("pam.sock")
    }
}
