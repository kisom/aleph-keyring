//! The high-water mark: the newest `(generation, mk_id)` seen for each
//! vault, kept outside the vault's directory (`$XDG_STATE_HOME/aleph/`) so
//! backups and sync do not carry it (spec §4).
//!
//! Comparing a file's mark against the recorded one reveals a vault that
//! was rolled back (lower generation), replaced (same generation, different
//! MK), or re-keyed elsewhere (higher generation, different MK). The last
//! case matters because anyone holding an old MK (an old file plus a since-
//! removed credential) can re-serialize the old vault with any generation.
//! Only the daemon's own writes may move the mark to a new MK, via
//! `record`. It is not tamper-proof against an attacker who can also write
//! the state directory.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::vault::UnlockedVault;

/// One generation of one vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mark {
    pub vault_id: Uuid,
    pub generation: u64,
    #[serde(with = "serde_bytes")]
    pub mk_id: [u8; 16],
}

/// How a file's mark stands against the recorded high-water mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Nothing recorded for this vault yet.
    Unrecorded,
    /// Exactly the recorded generation.
    Current,
    /// Newer than recorded, under the same master key.
    Newer,
    /// Older than recorded: the file was rolled back.
    RolledBack { recorded: u64 },
    /// Same generation as recorded but a different master key: the file
    /// was replaced.
    Replaced,
    /// Higher generation than recorded but a different master key: MK was
    /// changed somewhere other than this daemon, or an old MK is being
    /// replayed under a forged generation.
    Rekeyed,
    /// Exactly the mark of an own write that was renamed into place but
    /// not yet recorded (a crash or error between the two). The caller
    /// should `record` it.
    Pending,
}

impl Standing {
    /// Whether the daemon may proceed without asking the user.
    pub fn is_ok(self) -> bool {
        matches!(
            self,
            Standing::Unrecorded | Standing::Current | Standing::Newer | Standing::Pending
        )
    }
}

/// Compare a vault file's mark with what was recorded for that vault.
pub fn compare(recorded: Option<&Mark>, found: &Mark) -> Standing {
    match recorded {
        None => Standing::Unrecorded,
        Some(r) if found.generation < r.generation => Standing::RolledBack {
            recorded: r.generation,
        },
        Some(r) => match (found.generation == r.generation, found.mk_id == r.mk_id) {
            (true, true) => Standing::Current,
            (true, false) => Standing::Replaced,
            (false, true) => Standing::Newer,
            (false, false) => Standing::Rekeyed,
        },
    }
}

/// High-water marks stored as one small file per vault in a directory.
pub struct HighWater {
    dir: PathBuf,
}

impl HighWater {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, vault_id: Uuid) -> PathBuf {
        self.dir.join(format!("highwater-{vault_id}"))
    }

    fn pending_path(&self, vault_id: Uuid) -> PathBuf {
        self.dir.join(format!("highwater-{vault_id}.pending"))
    }

    /// Hold the per-vault lock while `f` runs, so concurrent recorders and
    /// raisers neither tear the record nor interleave check-then-store.
    fn locked<T>(&self, vault_id: Uuid, f: impl FnOnce() -> Result<T>) -> Result<T> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir)?;
            fs::set_permissions(
                &self.dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )?;
        }
        let lock: File = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.dir.join(format!("highwater-{vault_id}.lock")))?;
        lock.lock()?;
        f()
    }

    pub fn load(&self, vault_id: Uuid) -> Result<Option<Mark>> {
        read_mark(&self.path(vault_id), vault_id)
    }

    fn load_pending(&self, vault_id: Uuid) -> Result<Option<Mark>> {
        read_mark(&self.pending_path(vault_id), vault_id)
    }
}

fn read_mark(path: &std::path::Path, vault_id: Uuid) -> Result<Option<Mark>> {
    match fs::read(path) {
        Ok(bytes) => {
            let malformed = |m: String| Error::Malformed(format!("high-water mark: {m}"));
            let mut cursor = std::io::Cursor::new(bytes.as_slice());
            let mark: Mark =
                ciborium::from_reader(&mut cursor).map_err(|e| malformed(e.to_string()))?;
            if cursor.position() != bytes.len() as u64 {
                return Err(malformed("trailing data".into()));
            }
            if mark.vault_id != vault_id {
                return Err(Error::Malformed("high-water mark for another vault".into()));
            }
            Ok(Some(mark))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

impl HighWater {
    /// How `found` (which may come from an unauthenticated header) stands
    /// against this store's record for its vault.
    pub fn check(&self, found: &Mark) -> Result<Standing> {
        self.locked(found.vault_id, || self.check_unlocked(found))
    }

    fn check_unlocked(&self, found: &Mark) -> Result<Standing> {
        if self.load_pending(found.vault_id)?.as_ref() == Some(found) {
            return Ok(Standing::Pending);
        }
        Ok(compare(self.load(found.vault_id)?.as_ref(), found))
    }

    /// Record the mark of a vault the daemon *read and unlocked*, if it
    /// stands acceptably (`Standing::is_ok`), and report how it stood.
    /// Taking an `UnlockedVault` means the mark is authenticated: an
    /// unauthenticated header can be `check`ed but never raise the mark.
    /// Never lowers the mark or moves it to another MK.
    pub fn raise(&self, vault: &UnlockedVault) -> Result<Standing> {
        self.raise_mark(&vault.mark())
    }

    /// `raise` for a mark the caller has already authenticated.
    pub(crate) fn raise_mark(&self, mark: &Mark) -> Result<Standing> {
        let mark = *mark;
        self.locked(mark.vault_id, || {
            let standing = self.check_unlocked(&mark)?;
            if standing.is_ok() && standing != Standing::Current {
                self.store(&mark)?;
            }
            Ok(standing)
        })
    }

    /// Record `mark` unconditionally and clear any pending intent. Use only
    /// for marks the daemon itself wrote (`UnlockedVault::write_recorded`
    /// does this) and for a rollback or replacement the user explicitly
    /// accepted.
    pub fn record(&self, mark: &Mark) -> Result<()> {
        self.locked(mark.vault_id, || {
            self.store(mark)?;
            match fs::remove_file(self.pending_path(mark.vault_id)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            }
        })
    }

    /// Note that an own write of `mark` is about to be renamed into place,
    /// so that if the process stops before `record`, the file is recognised
    /// as `Pending` rather than `Rekeyed`.
    pub fn intend(&self, mark: &Mark) -> Result<()> {
        self.locked(mark.vault_id, || {
            let mut bytes = Vec::new();
            ciborium::into_writer(mark, &mut bytes).map_err(|e| Error::Malformed(e.to_string()))?;
            crate::vault::write_small_file(&self.pending_path(mark.vault_id), &bytes)
        })
    }

    fn store(&self, mark: &Mark) -> Result<()> {
        let mut bytes = Vec::new();
        ciborium::into_writer(mark, &mut bytes).map_err(|e| Error::Malformed(e.to_string()))?;
        crate::vault::write_small_file(&self.path(mark.vault_id), &bytes)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn mark(generation: u64, mk: u8) -> Mark {
        Mark {
            vault_id: Uuid::from_bytes([9; 16]),
            generation,
            mk_id: [mk; 16],
        }
    }

    #[test]
    fn compare_classifies_every_case() {
        assert_eq!(compare(None, &mark(5, 1)), Standing::Unrecorded);
        assert_eq!(compare(Some(&mark(5, 1)), &mark(5, 1)), Standing::Current);
        assert_eq!(compare(Some(&mark(5, 1)), &mark(6, 1)), Standing::Newer);
        assert_eq!(
            compare(Some(&mark(5, 1)), &mark(4, 1)),
            Standing::RolledBack { recorded: 5 }
        );
        assert_eq!(compare(Some(&mark(5, 1)), &mark(5, 2)), Standing::Replaced);
        assert_eq!(compare(Some(&mark(5, 1)), &mark(6, 2)), Standing::Rekeyed);
        assert!(Standing::Newer.is_ok());
        for s in [
            Standing::Replaced,
            Standing::Rekeyed,
            Standing::RolledBack { recorded: 1 },
        ] {
            assert!(!s.is_ok(), "{s:?}");
        }
    }

    /// Someone holding the old MK can re-serialize an old file with any
    /// generation. A higher generation under a different MK than recorded
    /// is therefore not "newer": it must not be accepted or recorded.
    #[test]
    fn a_higher_generation_under_a_different_mk_is_rekeyed_not_newer() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path());
        hw.record(&mark(5, 1)).unwrap();
        assert_eq!(
            hw.raise_mark(&mark(u64::MAX, 2)).unwrap(),
            Standing::Rekeyed
        );
        assert_eq!(hw.load(mark(1, 1).vault_id).unwrap(), Some(mark(5, 1)));
    }

    #[test]
    fn raise_stores_only_acceptable_marks_and_reports_the_standing() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path().join("state"));
        assert_eq!(hw.load(mark(1, 1).vault_id).unwrap(), None);
        assert_eq!(hw.raise_mark(&mark(5, 1)).unwrap(), Standing::Unrecorded);
        assert_eq!(
            hw.raise_mark(&mark(3, 1)).unwrap(),
            Standing::RolledBack { recorded: 5 }
        );
        assert_eq!(hw.raise_mark(&mark(5, 2)).unwrap(), Standing::Replaced);
        assert_eq!(hw.raise_mark(&mark(6, 1)).unwrap(), Standing::Newer);
        assert_eq!(hw.load(mark(1, 1).vault_id).unwrap(), Some(mark(6, 1)));
    }

    /// `record` is for marks the daemon itself wrote (including its own
    /// rotations) and for rollbacks the user accepted: stored unconditionally.
    #[test]
    fn record_stores_unconditionally() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path());
        hw.record(&mark(5, 1)).unwrap();
        hw.record(&mark(6, 2)).unwrap(); // own rotation
        assert_eq!(hw.check(&mark(6, 2)).unwrap(), Standing::Current);
        hw.record(&mark(3, 2)).unwrap(); // accepted rollback
        assert_eq!(hw.check(&mark(3, 2)).unwrap(), Standing::Current);
    }

    #[test]
    fn corrupt_foreign_or_padded_record_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path());
        let m = mark(1, 1);
        std::fs::write(hw.path(m.vault_id), b"garbage").unwrap();
        assert!(matches!(hw.load(m.vault_id), Err(Error::Malformed(_))));

        hw.record(&m).unwrap();
        let mut padded = std::fs::read(hw.path(m.vault_id)).unwrap();
        padded.push(0);
        std::fs::write(hw.path(m.vault_id), padded).unwrap();
        assert!(matches!(hw.load(m.vault_id), Err(Error::Malformed(_))));

        let other = Mark {
            vault_id: Uuid::from_bytes([1; 16]),
            ..m
        };
        hw.record(&other).unwrap();
        std::fs::rename(hw.path(other.vault_id), hw.path(m.vault_id)).unwrap();
        assert!(matches!(hw.load(m.vault_id), Err(Error::Malformed(_))));
    }

    /// An interrupted own write: the intended mark was recorded before the
    /// rename, the rename happened, but `record` did not (crash, or an error
    /// after the commit). The file is our own, not an attack.
    #[test]
    fn a_file_matching_the_pending_intent_is_pending_not_rekeyed() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path());
        hw.record(&mark(5, 1)).unwrap();
        hw.intend(&mark(6, 2)).unwrap();
        assert_eq!(hw.check(&mark(6, 2)).unwrap(), Standing::Pending);
        assert!(Standing::Pending.is_ok());
        // Anything else still stands against the recorded mark.
        assert_eq!(hw.check(&mark(7, 3)).unwrap(), Standing::Rekeyed);
        // Recording the write clears the intent.
        hw.record(&mark(6, 2)).unwrap();
        assert_eq!(hw.check(&mark(6, 2)).unwrap(), Standing::Current);
        hw.intend(&mark(7, 2)).unwrap();
        hw.record(&mark(7, 2)).unwrap();
        assert_eq!(hw.check(&mark(9, 9)).unwrap(), Standing::Rekeyed);
    }

    /// Concurrent recorders must never leave a torn record behind.
    #[test]
    fn concurrent_records_never_corrupt_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let hw = std::sync::Arc::new(HighWater::new(dir.path()));
        let threads: Vec<_> = (0..8u8)
            .map(|t| {
                let hw = hw.clone();
                std::thread::spawn(move || {
                    for g in 0..50u64 {
                        hw.record(&mark(g, t)).unwrap();
                        hw.load(mark(0, 0).vault_id).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert!(hw.load(mark(0, 0).vault_id).unwrap().is_some());
    }
}
