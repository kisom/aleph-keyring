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

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

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
}

impl Standing {
    /// Whether the daemon may proceed without asking the user.
    pub fn is_ok(self) -> bool {
        matches!(
            self,
            Standing::Unrecorded | Standing::Current | Standing::Newer
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

    pub fn load(&self, vault_id: Uuid) -> Result<Option<Mark>> {
        match fs::read(self.path(vault_id)) {
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

    /// How `found` stands against this store's record for its vault.
    pub fn check(&self, found: &Mark) -> Result<Standing> {
        Ok(compare(self.load(found.vault_id)?.as_ref(), found))
    }

    /// Record `mark` if it stands acceptably (`Standing::is_ok`) against
    /// the current record, and report how it stood. Use for marks of files
    /// the daemon *read*. Never lowers the mark or moves it to another MK.
    pub fn raise(&self, mark: &Mark) -> Result<Standing> {
        let standing = self.check(mark)?;
        if standing.is_ok() && standing != Standing::Current {
            self.store(mark)?;
        }
        Ok(standing)
    }

    /// Record `mark` unconditionally. Use only for marks the daemon itself
    /// wrote (the `Mark` returned by `UnlockedVault::write`, including after
    /// its own rotations) and for a rollback or replacement the user
    /// explicitly accepted.
    pub fn record(&self, mark: &Mark) -> Result<()> {
        self.store(mark)
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
        assert_eq!(hw.raise(&mark(u64::MAX, 2)).unwrap(), Standing::Rekeyed);
        assert_eq!(hw.load(mark(1, 1).vault_id).unwrap(), Some(mark(5, 1)));
    }

    #[test]
    fn raise_stores_only_acceptable_marks_and_reports_the_standing() {
        let dir = tempfile::tempdir().unwrap();
        let hw = HighWater::new(dir.path().join("state"));
        assert_eq!(hw.load(mark(1, 1).vault_id).unwrap(), None);
        assert_eq!(hw.raise(&mark(5, 1)).unwrap(), Standing::Unrecorded);
        assert_eq!(
            hw.raise(&mark(3, 1)).unwrap(),
            Standing::RolledBack { recorded: 5 }
        );
        assert_eq!(hw.raise(&mark(5, 2)).unwrap(), Standing::Replaced);
        assert_eq!(hw.raise(&mark(6, 1)).unwrap(), Standing::Newer);
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
}
