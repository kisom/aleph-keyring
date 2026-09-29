//! What the manager's confirmation is for (the admin spec,
//! "Architecture"): a reveal, a settings save, and (Plan 5d) an admin
//! operation share one path: the unlock-first step for a sealed vault, the
//! embedded confirmation, the wording after an interruption, and what
//! happens on finish. The words each kind uses are here, so
//! `manager.rs` never branches on the kind to say something.

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
}

impl Job {
    /// The store request's name (`Request::name`), as `Done` reports it.
    pub fn request_name(&self) -> &'static str {
        match self {
            Self::Settings => "save the settings",
        }
    }

    /// After a lock or a lost link ended it: alephd may have gone ahead.
    pub fn may_not_have_gone_through(&self) -> &'static str {
        match self {
            Self::Settings => "the save may not have gone through",
        }
    }

    /// After the window or the confirmation ended early.
    pub fn may_not_have_been_done(&self) -> &'static str {
        match self {
            Self::Settings => "the settings may not have been saved",
        }
    }

    /// What is true when the person cancelled, or the unlock did not come.
    pub fn nothing(&self) -> &'static str {
        match self {
            Self::Settings => "nothing was saved",
        }
    }

    /// The vault opened, but there was nothing left to do.
    pub fn unlock_missed(&self) -> &'static str {
        match self {
            Self::Settings => "the settings were not saved",
        }
    }

    pub fn cancelled(&self) -> String {
        format!("cancelled: {}", self.nothing())
    }

    /// alephd ended the conversation without success, with its message.
    pub fn refused(&self, message: &str) -> String {
        match self {
            Self::Settings => format!("not saved: {message}"),
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
