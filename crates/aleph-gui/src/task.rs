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
/// through the descriptor it is handed). If the manager made the file and it
/// is still empty when this is dropped (the backup was cancelled, refused,
/// or cut short), it is removed: a half-made backup never sits at the path.
#[derive(Debug)]
pub struct BackupTarget {
    pub path: PathBuf,
    file: std::fs::File,
    created: bool,
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
                    .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
                let meta = f
                    .metadata()
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                if !meta.is_file() || meta.len() > 0 {
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
        })
    }

    /// A handle on the same file, for the request.
    pub fn file(&self) -> std::io::Result<std::fs::File> {
        self.file.try_clone()
    }
}

impl Drop for BackupTarget {
    fn drop(&mut self) {
        if self.created && self.file.metadata().is_ok_and(|m| m.len() == 0) {
            let _ = std::fs::remove_file(&self.path);
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
            Self::Backup(t) => {
                return format!(
                    "BACKED UP :: {} (it opens only with your recovery key)",
                    t.path.display()
                );
            }
            Self::AddTpm | Self::AddFido2 { .. } => "KEYSLOT ADDED",
            Self::Remove { .. } => "KEYSLOT REMOVED",
            Self::RotateMaster => "MASTER KEY ROTATED",
            Self::NewRecoveryKey => "NEW RECOVERY KEY ISSUED",
        }
        .into()
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
        assert!(BackupTarget::open(&fifo).is_err());
        assert!(fifo.exists());

        let target = dir.path().join("elsewhere");
        std::fs::write(&target, b"").unwrap();
        let link = dir.path().join("link.aleph");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(BackupTarget::open(&link).is_err());
        assert!(target.exists() && link.exists());
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

    /// The words the Plan 5c tests pin for a settings save.
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
