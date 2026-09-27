//! Which keyslots are stale (spec §5, "Rate limiting").
//!
//! A TPM slot that answered `AuthFailed` or `WrongUser` is marked stale and
//! is not tried automatically again until it is re-enrolled or the user
//! retries it explicitly, so an outdated password cannot keep spending the
//! TPM's dictionary-attack budget. The mark changes while the vault is
//! locked, so it lives in its own file, not in the (MACed) vault header.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    stale: BTreeSet<Uuid>,
}

#[derive(Debug)]
pub struct SlotState {
    path: PathBuf,
    stale: BTreeSet<Uuid>,
}

impl SlotState {
    /// Load the state; a missing or unreadable file means "nothing stale"
    /// (the worst case is one extra attempt per slot).
    pub fn load(path: &Path) -> Self {
        let stale = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<File>(&b).ok())
            .map(|f| f.stale)
            .unwrap_or_default();
        Self {
            path: path.to_path_buf(),
            stale,
        }
    }

    pub fn is_stale(&self, slot: Uuid) -> bool {
        self.stale.contains(&slot)
    }

    pub fn stale(&self) -> impl Iterator<Item = &Uuid> {
        self.stale.iter()
    }

    pub fn mark_stale(&mut self, slot: Uuid) -> Result<()> {
        if self.stale.insert(slot) {
            self.save()?;
        }
        Ok(())
    }

    pub fn clear(&mut self, slot: Uuid) -> Result<()> {
        if self.stale.remove(&slot) {
            self.save()?;
        }
        Ok(())
    }

    /// Forget slots that no longer exist.
    pub fn retain(&mut self, exists: impl Fn(Uuid) -> bool) -> Result<()> {
        let before = self.stale.len();
        self.stale.retain(|s| exists(*s));
        if self.stale.len() != before {
            self.save()?;
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec(&File {
                stale: self.stale.clone(),
            })
            .expect("serializable"),
        )?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_marks_persist_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/slots.json");
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut s = SlotState::load(&path);
        assert!(!s.is_stale(a));
        s.mark_stale(a).unwrap();
        s.mark_stale(b).unwrap();
        let mut s = SlotState::load(&path);
        assert!(s.is_stale(a) && s.is_stale(b));
        s.clear(a).unwrap();
        s.retain(|id| id != b).unwrap();
        let s = SlotState::load(&path);
        assert!(!s.is_stale(a) && !s.is_stale(b));
    }

    #[test]
    fn a_corrupt_file_means_nothing_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slots.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(SlotState::load(&path).stale().count(), 0);
    }
}
