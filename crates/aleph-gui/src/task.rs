//! What the manager's confirmation is for (the admin spec,
//! "Architecture"): a reveal, a settings save, and (Plan 5d) an admin
//! operation share one path: the unlock-first step for a sealed vault, the
//! embedded confirmation, the wording after an interruption, and what
//! happens on finish. The words each kind uses are here, so
//! `manager.rs` never branches on the kind to say something.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use crate::store::Request;

/// What a fetched secret is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    Show,
    Copy,
    Edit,
}

/// Work that needs alephd's confirmation, and an open vault for it.
#[derive(Debug)]
pub enum Job {
    /// The VAULT settings' SAVE (the changes are read from the form when it
    /// starts).
    Settings,
    /// An ADMIN operation.
    Admin(AdminOp),
}

/// One admin operation (the admin spec, "The screen").
#[derive(Debug)]
pub enum AdminOp {
    AddTpm,
    AddFido2 { touch_only: bool },
    Remove { id: String, label: String },
    RotateMaster,
    NewRecoveryKey,
    Backup(BackupTarget),
}

/// A backup's new file, opened by the manager (alephd writes into it
/// through the descriptor it is handed). Only a file the manager made is
/// ever removed, and only while the path still names that file:
/// - dropped while still empty (nothing was sent to alephd, or it was cut
///   short before any answer went to it), it is removed, unless it was
///   [kept](Self::keep);
/// - [kept](Self::keep) (cut short after an answer went to alephd, which
///   may be writing it), it stays whatever its size;
/// - [discarded](Self::discard) (alephd said it failed), it is removed
///   whatever its size.
#[derive(Debug)]
pub struct BackupTarget {
    pub path: PathBuf,
    file: std::fs::File,
    created: bool,
    kept: bool,
    /// (A seam for the tests: `file` fails, as a failed clone would.)
    #[cfg(test)]
    unclonable: bool,
}

impl BackupTarget {
    /// Create `path` (create-new, mode 0600). A file already there is used
    /// only if it is empty (and is then left in place when it is dropped);
    /// one with content is refused, never overwritten.
    pub fn open(path: &Path) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).mode(0o600);
        let (file, created) = match options.clone().create_new(true).open(path) {
            Ok(f) => (f, true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // (Not through a symbolic link, and never waiting: a FIFO
                // opened for writing would hold the window until a reader
                // came. On a regular file O_NONBLOCK changes nothing.)
                let f = options
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(path)
                    .map_err(|e| {
                        // (A FIFO with no reader, or a symbolic link, fails
                        // to open: say what it is.)
                        if std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_file()) {
                            not_regular(path)
                        } else {
                            format!("cannot open {}: {e}", path.display())
                        }
                    })?;
                let meta = f
                    .metadata()
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                if !meta.is_file() {
                    return Err(not_regular(path));
                }
                if meta.len() > 0 {
                    return Err(format!(
                        "{} already exists and is not empty: choose a new name",
                        path.display()
                    ));
                }
                (f, false)
            }
            Err(e) => return Err(format!("cannot create {}: {e}", path.display())),
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
            created,
            kept: false,
            #[cfg(test)]
            unclonable: false,
        })
    }

    /// A handle on the same file, for the request.
    pub fn file(&self) -> std::io::Result<std::fs::File> {
        #[cfg(test)]
        if self.unclonable {
            return Err(std::io::Error::other("no more descriptors"));
        }
        self.file.try_clone()
    }

    /// Leave the file in place whatever its size (alephd may be writing
    /// it).
    pub fn keep(&mut self) {
        self.kept = true;
    }

    /// alephd said the backup failed: a file the manager made goes, even
    /// one it wrote part of.
    pub fn discard(mut self) {
        self.remove();
        self.kept = true;
    }

    /// Remove the file if the manager made it and the path still names it
    /// (something put in its place is not touched).
    fn remove(&self) {
        use std::os::unix::fs::MetadataExt;
        if !self.created {
            return;
        }
        let (Ok(ours), Ok(there)) = (self.file.metadata(), std::fs::symlink_metadata(&self.path))
        else {
            return;
        };
        if (ours.dev(), ours.ino()) == (there.dev(), there.ino()) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[cfg(test)]
    pub(crate) fn unclonable(mut self) -> Self {
        self.unclonable = true;
        self
    }
}

fn not_regular(path: &Path) -> String {
    format!(
        "{} is not a regular file: choose a new name",
        path.display()
    )
}

impl Drop for BackupTarget {
    fn drop(&mut self) {
        if !self.kept && self.file.metadata().is_ok_and(|m| m.len() == 0) {
            self.remove();
        }
    }
}

impl AdminOp {
    /// The store request's name (`Request::name`).
    pub fn request_name(&self) -> &'static str {
        match self {
            Self::AddTpm => "add the TPM slot",
            Self::AddFido2 { .. } => "add the security key",
            Self::Remove { .. } => "remove the keyslot",
            Self::RotateMaster => "rotate the master key",
            Self::NewRecoveryKey => "issue a new recovery key",
            Self::Backup(_) => "back up",
        }
    }

    /// What the status line says when it went through.
    pub fn done_text(&self) -> String {
        match self {
            Self::Backup(t) => format!(
                "BACKED UP :: {} (it opens only with your recovery key)",
                t.path.display()
            ),
            Self::AddTpm | Self::AddFido2 { .. } => "KEYSLOT ADDED".into(),
            Self::Remove { .. } => "KEYSLOT REMOVED".into(),
            Self::RotateMaster => "MASTER KEY ROTATED".into(),
            Self::NewRecoveryKey => "NEW RECOVERY KEY ISSUED".into(),
        }
    }

    /// The store request, conversing on `prompter` (a backup's file handle
    /// is made here: if it cannot be, why).
    pub fn request(&self, prompter: OwnedFd) -> Result<Request, String> {
        Ok(match self {
            Self::AddTpm => Request::AddTpm(prompter),
            Self::AddFido2 { touch_only } => Request::AddFido2(prompter, *touch_only),
            Self::Remove { id, .. } => Request::RemoveKeyslot(prompter, id.clone()),
            Self::RotateMaster => Request::RotateMaster(prompter),
            Self::NewRecoveryKey => Request::ReissueRecovery(prompter),
            Self::Backup(t) => Request::Backup(
                prompter,
                t.file()
                    .map_err(|e| format!("cannot use the backup file: {e}"))?
                    .into(),
            ),
        })
    }
}

impl Job {
    /// The store request's name (`Request::name`), as `Done` reports it.
    pub fn request_name(&self) -> &'static str {
        match self {
            Self::Settings => "save the settings",
            Self::Admin(op) => op.request_name(),
        }
    }

    /// After a lock or a lost link ended it: alephd may have gone ahead.
    pub fn may_not_have_gone_through(&self) -> &'static str {
        match self {
            Self::Settings => "the save may not have gone through",
            Self::Admin(_) => "the operation may not have gone through",
        }
    }

    /// After the window or the confirmation ended early.
    pub fn may_not_have_been_done(&self) -> &'static str {
        match self {
            Self::Settings => "the settings may not have been saved",
            Self::Admin(_) => "the operation may not have gone through",
        }
    }

    /// What is true when the person cancelled, or the unlock did not come.
    pub fn nothing(&self) -> &'static str {
        match self {
            Self::Settings => "nothing was saved",
            Self::Admin(_) => "nothing was changed",
        }
    }

    /// The vault opened, but there was nothing left to do.
    pub fn unlock_missed(&self) -> &'static str {
        match self {
            Self::Settings => "the settings were not saved",
            Self::Admin(_) => "the operation was not run",
        }
    }

    pub fn cancelled(&self) -> String {
        format!("cancelled: {}", self.nothing())
    }

    /// Its confirmation was cut short (`answered`: after an answer went to
    /// alephd). A backup that had its answer may be being written: its file
    /// is kept, and what this returns (added to the status) says where.
    pub fn interrupted(&mut self, answered: bool) -> String {
        match self {
            Self::Admin(AdminOp::Backup(t)) if answered => {
                t.keep();
                format!(
                    "; check {} (an empty file means it did not)",
                    t.path.display()
                )
            }
            _ => String::new(),
        }
    }

    /// alephd said it failed: a backup's file goes, even written.
    pub fn failed(self) {
        if let Self::Admin(AdminOp::Backup(t)) = self {
            t.discard();
        }
    }

    /// alephd ended the conversation without success, with its message.
    pub fn refused(&self, message: &str) -> String {
        match self {
            Self::Settings => format!("not saved: {message}"),
            Self::Admin(_) => format!("not done: {message}"),
        }
    }
}

/// What the confirmation on screen is for.
#[derive(Debug)]
pub enum Running {
    /// Show, copy or edit a secret: fetched once the guard confirms.
    Reveal {
        path: String,
        want: Want,
    },
    Job(Job),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_backup_file_is_new_private_and_removed_while_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.aleph");
        let t = BackupTarget::open(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(t);
        // Still empty when it is dropped: the manager made it, so it goes.
        assert!(!path.exists());
    }

    #[test]
    fn a_written_backup_stays() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.aleph");
        let t = BackupTarget::open(&path).unwrap();
        (&t.file().unwrap()).write_all(b"x").unwrap();
        drop(t);
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }

    /// (Review Focus 1.) Somebody else's file is neither overwritten nor
    /// removed; an empty one they made is used and left in place.
    #[test]
    fn an_existing_file_is_not_overwritten_or_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mine.aleph");
        std::fs::write(&path, b"precious").unwrap();
        let e = BackupTarget::open(&path).err().unwrap();
        assert!(
            e.contains("already exists") && e.contains("choose a new name"),
            "{e}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"precious");

        let empty = dir.path().join("empty.aleph");
        std::fs::write(&empty, b"").unwrap();
        let t = BackupTarget::open(&empty).unwrap();
        drop(t);
        assert!(empty.exists(), "not made by the manager: not removed");
    }

    /// A FIFO at the path is refused at once (opening it for writing would
    /// wait for a reader), and a symbolic link is not followed to an empty
    /// file elsewhere.
    #[test]
    fn a_fifo_or_a_symlink_is_refused_without_waiting() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo.aleph");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let e = BackupTarget::open(&fifo).err().unwrap();
        assert!(e.contains("is not a regular file"), "{e}");
        assert!(fifo.exists());

        let target = dir.path().join("elsewhere");
        std::fs::write(&target, b"").unwrap();
        let link = dir.path().join("link.aleph");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let e = BackupTarget::open(&link).err().unwrap();
        assert!(e.contains("is not a regular file"), "{e}");
        assert!(target.exists() && link.exists());
    }

    /// Removal is of the file the manager opened: another file put at the
    /// path meanwhile stays.
    #[test]
    fn a_file_that_replaced_the_backup_is_not_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.aleph");
        let t = BackupTarget::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"other").unwrap();
        drop(t);
        assert_eq!(std::fs::read(&path).unwrap(), b"other");

        let t = BackupTarget::open(&dir.path().join("c.aleph")).unwrap();
        std::fs::rename(dir.path().join("b.aleph"), dir.path().join("c.aleph")).unwrap();
        t.discard();
        assert_eq!(std::fs::read(dir.path().join("c.aleph")).unwrap(), b"other");
    }

    /// A kept backup stays, even empty (alephd may still be writing it).
    #[test]
    fn a_kept_backup_stays_even_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.aleph");
        let mut t = BackupTarget::open(&path).unwrap();
        t.keep();
        drop(t);
        assert!(path.exists());
    }

    /// alephd said it failed: a file the manager made goes, written or not;
    /// one that was already there stays.
    #[test]
    fn a_discarded_backup_goes_even_written() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.aleph");
        let t = BackupTarget::open(&path).unwrap();
        (&t.file().unwrap()).write_all(b"half").unwrap();
        t.discard();
        assert!(!path.exists());

        let theirs = dir.path().join("theirs.aleph");
        std::fs::write(&theirs, b"").unwrap();
        let t = BackupTarget::open(&theirs).unwrap();
        (&t.file().unwrap()).write_all(b"half").unwrap();
        t.discard();
        assert!(theirs.exists(), "not made by the manager: not removed");
    }

    #[test]
    fn a_backup_says_where_it_went() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.aleph");
        let t = BackupTarget::open(&path).unwrap();
        let op = AdminOp::Backup(t);
        assert_eq!(op.request_name(), "back up");
        assert_eq!(
            op.done_text(),
            format!(
                "BACKED UP :: {} (it opens only with your recovery key)",
                path.display()
            )
        );
    }

    #[test]
    fn an_admin_job_has_its_own_words() {
        let j = Job::Admin(AdminOp::RotateMaster);
        assert_eq!(j.request_name(), "rotate the master key");
        assert_eq!(j.nothing(), "nothing was changed");
        assert_eq!(j.cancelled(), "cancelled: nothing was changed");
        assert_eq!(j.refused("no"), "not done: no");
        assert_eq!(
            j.may_not_have_gone_through(),
            "the operation may not have gone through"
        );
        assert_eq!(
            j.may_not_have_been_done(),
            "the operation may not have gone through"
        );
        assert_eq!(j.unlock_missed(), "the operation was not run");
        assert_eq!(AdminOp::RotateMaster.done_text(), "MASTER KEY ROTATED");
        assert_eq!(
            AdminOp::AddFido2 { touch_only: true }.done_text(),
            "KEYSLOT ADDED"
        );
        assert_eq!(AdminOp::AddTpm.done_text(), "KEYSLOT ADDED");
        assert_eq!(
            AdminOp::Remove {
                id: "1".into(),
                label: "x".into()
            }
            .done_text(),
            "KEYSLOT REMOVED"
        );
        assert_eq!(
            AdminOp::NewRecoveryKey.done_text(),
            "NEW RECOVERY KEY ISSUED"
        );
    }

    /// The words the Plan 5c tests pin for a settings save.
    #[test]
    fn a_settings_save_keeps_its_words() {
        let j = Job::Settings;
        assert_eq!(j.request_name(), "save the settings");
        assert_eq!(
            j.may_not_have_gone_through(),
            "the save may not have gone through"
        );
        assert_eq!(
            j.may_not_have_been_done(),
            "the settings may not have been saved"
        );
        assert_eq!(j.nothing(), "nothing was saved");
        assert_eq!(j.unlock_missed(), "the settings were not saved");
        assert_eq!(j.cancelled(), "cancelled: nothing was saved");
        assert_eq!(j.refused("boom"), "not saved: boom");
    }
}
