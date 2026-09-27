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
use std::path::{Path, PathBuf};

use aleph_core::{HighWater, LockedVault, Mark, Standing, UnlockedVault};
use uuid::Uuid;

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

    /// What this machine last recorded for `vault_id`.
    pub fn recorded(&self, vault_id: Uuid) -> Result<Option<Mark>> {
        Ok(self.highwater.load(vault_id)?)
    }

    /// The backup copy every write keeps (`vault.aleph.bak`).
    pub fn read_bak(&self) -> Result<LockedVault> {
        match LockedVault::read(&self.paths.bak()) {
            Err(aleph_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Err(
                Error::Invalid("there is no backup copy (vault.aleph.bak)".into()),
            ),
            other => Ok(other?),
        }
    }

    /// Keep the vault file also as `vault.aleph.<what>-<unix time>`, before
    /// a write replaces it: a hard link (a copy where links fail), so the
    /// vault stays in place until the replacement's rename, and a crash in
    /// between leaves it. Returns the kept name.
    pub fn keep_aside(&self, what: &str) -> Result<PathBuf> {
        self.keep(&self.paths.vault(), what)
    }

    /// Keep `vault.aleph.bak` as well (`vault.aleph.bak-<unix time>`), if
    /// there is one: a custody write replaces it, and it may be the only
    /// good copy.
    pub fn keep_bak_aside(&self) -> Result<Option<PathBuf>> {
        let bak = self.paths.bak();
        if std::fs::symlink_metadata(&bak).is_err() {
            return Ok(None);
        }
        Ok(Some(self.keep(&bak, "bak")?))
    }

    /// Keep `from` as `vault.aleph.<what>-<unix time>[-<n>]`, never over an
    /// existing name: a hard link, or a synced copy where links fail.
    fn keep(&self, from: &Path, what: &str) -> Result<PathBuf> {
        use std::io::Write;
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for n in 0..1000 {
            let name = match n {
                0 => format!("vault.aleph.{what}-{secs}"),
                n => format!("vault.aleph.{what}-{secs}-{n}"),
            };
            let to = self.paths.data_dir.join(name);
            match std::fs::hard_link(from, &to) {
                Ok(()) => return Ok(to),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => {}
            }
            let bytes = std::fs::read(from)?;
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&to)
            {
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                other => other?,
            };
            file.write_all(&bytes)?;
            file.sync_all()?;
            return Ok(to);
        }
        Err(Error::Invalid("too many kept copies of the vault".into()))
    }

    /// The vault this machine expects at the path, if one was recorded.
    pub fn expected_vault_id(&self) -> Option<Uuid> {
        std::fs::read_to_string(self.paths.expected_vault())
            .ok()
            .and_then(|s| Uuid::try_parse(s.trim()).ok())
    }

    /// Record the vault this machine expects at the path.
    pub fn expect_vault_id(&self, id: Uuid) -> Result<()> {
        let path = self.paths.expected_vault();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, id.to_string())?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
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

    /// A vault about to be replaced is kept under another name first, and
    /// stays in place until the replacement's rename (a crash before it
    /// leaves the old vault); the expected vault id is remembered.
    #[test]
    fn a_vault_kept_aside_survives_its_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let store = Store::open(&paths).unwrap();
        std::fs::write(paths.vault(), b"old vault").unwrap();
        let kept = store.keep_aside("replaced").unwrap();
        assert!(store.exists());
        let tmp = paths.data_dir.join("new");
        std::fs::write(&tmp, b"new vault").unwrap();
        std::fs::rename(&tmp, paths.vault()).unwrap();
        assert_eq!(std::fs::read(&kept).unwrap(), b"old vault");
        assert!(
            kept.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("vault.aleph.replaced-")
        );
        assert_eq!(store.expected_vault_id(), None);
        let id = Uuid::new_v4();
        store.expect_vault_id(id).unwrap();
        assert_eq!(store.expected_vault_id(), Some(id));
        assert!(matches!(store.read_bak(), Err(Error::Invalid(_))));
    }

    /// Two copies kept in the same second get different names: the second
    /// never writes into the first (which is the old vault's own file).
    #[test]
    fn copies_kept_in_the_same_second_never_overwrite_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let store = Store::open(&paths).unwrap();
        std::fs::write(paths.vault(), b"first").unwrap();
        let a = store.keep_aside("replaced").unwrap();
        let tmp = paths.data_dir.join("new");
        std::fs::write(&tmp, b"second").unwrap();
        std::fs::rename(&tmp, paths.vault()).unwrap();
        let b = store.keep_aside("replaced").unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read(&a).unwrap(), b"first");
        assert_eq!(std::fs::read(&b).unwrap(), b"second");
        assert!(store.keep_bak_aside().unwrap().is_none());
        std::fs::write(paths.bak(), b"bak").unwrap();
        let c = store.keep_bak_aside().unwrap().unwrap();
        assert_eq!(std::fs::read(&c).unwrap(), b"bak");
        assert!(
            c.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("vault.aleph.bak-")
        );
    }

    #[test]
    fn a_missing_vault_is_no_vault() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&Paths::under(dir.path())).unwrap();
        assert!(!store.exists());
        assert!(matches!(store.read(), Err(Error::NoVault)));
    }
}
