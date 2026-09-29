//! What the manager's confirmation is for (the admin spec,
//! "Architecture"): a reveal, a settings save, and (Plan 5d) an admin
//! operation share one path: the unlock-first step for a sealed vault, the
//! embedded confirmation, the wording after an interruption, and what
//! happens on finish. The words each kind uses are here, so
//! `manager.rs` never branches on the kind to say something.

use std::os::fd::OwnedFd;

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
        }
    }

    /// What the status line says when it went through.
    pub fn done_text(&self) -> String {
        match self {
            Self::AddTpm | Self::AddFido2 { .. } => "KEYSLOT ADDED",
            Self::Remove { .. } => "KEYSLOT REMOVED",
            Self::RotateMaster => "MASTER KEY ROTATED",
            Self::NewRecoveryKey => "NEW RECOVERY KEY ISSUED",
        }
        .into()
    }

    /// The store request, conversing on `prompter`.
    pub fn request(&self, prompter: OwnedFd) -> Request {
        match self {
            Self::AddTpm => Request::AddTpm(prompter),
            Self::AddFido2 { touch_only } => Request::AddFido2(prompter, *touch_only),
            Self::Remove { id, .. } => Request::RemoveKeyslot(prompter, id.clone()),
            Self::RotateMaster => Request::RotateMaster(prompter),
            Self::NewRecoveryKey => Request::ReissueRecovery(prompter),
        }
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
