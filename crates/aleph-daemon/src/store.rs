//! The vault file as the daemon owns it (spec §4 "File", "Generation and
//! high-water mark").
//!
//! - The daemon holds `vault.aleph.daemon` for its lifetime, so a second
//!   daemon (or anything else that honours the lock) refuses to run.
//! - The data directory is created `0700`; an existing one that is group-
//!   or world-accessible is tightened, with a warning.
//! - Writes go through `UnlockedVault::write_recorded`, so the high-water
//!   mark follows the daemon's own writes.

use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use aleph_core::{HighWater, LockedVault, Mark, Standing, UnlockedVault};

use crate::error::{Error, Result};
use crate::paths::Paths;

pub struct Store {
    paths: Paths,
    highwater: HighWater,
    _daemon_lock: File,
}

impl Store {
    /// Take ownership of the vault location.
    pub fn open(paths: &Paths) -> Result<Self> {
        ensure_private_dir(&paths.data_dir)?;
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(paths.daemon_lock())?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(Error::AlreadyRunning),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        Ok(Self {
            paths: paths.clone(),
            highwater: HighWater::new(&paths.state_dir),
            _daemon_lock: lock,
        })
    }

    pub fn exists(&self) -> bool {
        self.paths.vault().symlink_metadata().is_ok()
    }

    pub fn read(&self) -> Result<LockedVault> {
        match LockedVault::read(&self.paths.vault()) {
            Err(aleph_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::NoVault)
            }
            other => Ok(other?),
        }
    }

    /// How a file read from disk compares with the recorded mark. The
    /// header is not yet authenticated: this may only warn, never raise.
    pub fn check(&self, vault: &LockedVault) -> Result<Standing> {
        Ok(self.highwater.check(&vault.mark())?)
    }

    /// Raise the mark for an unlocked (authenticated) vault.
    pub fn raise(&self, vault: &UnlockedVault) -> Result<Standing> {
        Ok(self.highwater.raise(vault)?)
    }

    /// Record a mark (a `Pending` own write, or an accepted rollback).
    pub fn record(&self, mark: &Mark) -> Result<()> {
        Ok(self.highwater.record(mark)?)
    }

    pub fn write(&self, vault: &UnlockedVault) -> Result<Mark> {
        Ok(vault.write_recorded(&self.paths.vault(), &self.highwater)?)
    }
}

/// Create `dir` as `0700`, or tighten an existing group- or
/// world-accessible one (warning, since someone loosened it).
fn ensure_private_dir(dir: &Path) -> Result<()> {
    match std::fs::metadata(dir) {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    dir = %dir.display(),
                    mode = format!("{mode:o}"),
                    "vault directory was group- or world-accessible; tightened to 0700"
                );
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_daemon_may_own_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let first = Store::open(&paths).unwrap();
        assert!(matches!(Store::open(&paths), Err(Error::AlreadyRunning)));
        drop(first);
        // Retry briefly: a process forked meanwhile by another test (PAM
        // runs unix_chkpwd) holds a copy of the lock's descriptor until
        // its exec closes it.
        let mut again = Store::open(&paths);
        for _ in 0..100 {
            if again.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            again = Store::open(&paths);
        }
        again.unwrap();
    }

    #[test]
    fn the_data_directory_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        drop(Store::open(&paths).unwrap());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&paths.data_dir), 0o700);
        std::fs::set_permissions(&paths.data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        drop(Store::open(&paths).unwrap());
        assert_eq!(mode(&paths.data_dir), 0o700);
    }

    #[test]
    fn a_missing_vault_is_no_vault() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&Paths::under(dir.path())).unwrap();
        assert!(!store.exists());
        assert!(matches!(store.read(), Err(Error::NoVault)));
    }
}
