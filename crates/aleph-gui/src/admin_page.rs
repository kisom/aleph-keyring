//! The ADMIN page (the admin spec, "The screen"): what STATUS says, which
//! buttons a slot gets, the Yes/No steps, and the drawing. It never touches
//! the store or the window: `manager.rs` wires the effects.

use egui::{RichText, TextEdit};

use crate::store::{AdminStatus, SlotInfo};
use crate::theme::Palette;

pub const SEALED_NOTE: &str = "VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST";
pub const NEW_KEY_ASK: &str =
    "The current recovery key stops working as soon as the new one is issued.";
pub const TOUCH_WARNING: &str = "anyone holding the key can unlock";

/// The page's status, as far as it has come.
#[derive(Debug)]
pub enum AdminState {
    /// Not asked for yet (or nothing worth keeping when the link went).
    Unknown,
    Loading,
    Failed(String),
    Ready(AdminStatus),
}

impl AdminState {
    /// What a link's return, or a lock or unlock, reads again.
    pub fn is_stale(&self) -> bool {
        matches!(self, Self::Failed(_) | Self::Ready(_))
    }
}

/// How alephd can be reached now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    Up,
    Connecting,
    Down(String),
}

/// The Yes/No steps before the two irreversible operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ask {
    Remove { id: String, label: String },
    NewRecoveryKey,
}

impl Ask {
    pub fn text(&self) -> String {
        match self {
            Self::Remove { label, .. } => format!(
                "Remove keyslot '{label}'? This rotates the master key. The key can no longer unlock the vault."
            ),
            Self::NewRecoveryKey => NEW_KEY_ASK.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub text: String,
    /// Offers ROTATE NOW beside it.
    pub rotate_now: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusText {
    pub facts: [String; 2],
    pub warnings: Vec<Warning>,
    /// Another program owns the Secret Service: shown in the warning colour.
    pub owner_foreign: bool,
}

/// What STATUS says (`alephctl status`, in two lines and the warnings that
/// are true).
pub fn status_text(s: &AdminStatus) -> StatusText {
    let vault = match (s.vault, s.locked) {
        (false, _) => "none",
        (true, true) => "locked",
        (true, false) => "unlocked",
    };
    let owner = s.secret_service.as_deref().unwrap_or("unknown");
    let tpm = match s.tpm {
        Some(true) => "usable",
        Some(false) => "unavailable",
        None => "busy",
    };
    let memory = match s.memory_locked {
        Some(true) => "locked in RAM",
        Some(false) => "not locked in RAM",
        None => "—",
    };
    let mut warnings = Vec::new();
    if let Some(why) = &s.untrusted {
        warnings.push(Warning {
            text: format!("writes refused: {why}; see alephctl restore --accept-rollback"),
            rotate_now: false,
        });
    }
    if s.rotation_pending {
        warnings.push(Warning {
            text: "a password change is pending: rotate the master key".into(),
            rotate_now: true,
        });
    }
    StatusText {
        facts: [
            format!("vault  {vault} · secret service  {owner}"),
            format!("TPM  {tpm} · master key  {memory}"),
        ],
        warnings,
        owner_foreign: owner == "another program",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowButtons {
    pub remove: bool,
    pub retry: bool,
}

/// A slot's buttons: REMOVE on all but the recovery slot (NEW RECOVERY KEY
/// replaces that one), RETRY on a stale one.
pub fn row_buttons(slot: &SlotInfo) -> RowButtons {
    RowButtons {
        remove: slot.kind != "recovery",
        retry: slot.stale,
    }
}

pub fn suggested_backup_name(date: &str) -> String {
    format!("aleph-backup-{date}.aleph")
}

/// What the page is allowed to do now.
pub struct AdminView {
    pub link: Link,
    /// The vault is locked: every action unlocks it first (and says so).
    pub sealed: bool,
    /// An action is waiting for the unlock: the buttons wait too.
    pub waiting: bool,
}

/// What the person asked of the page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminAction {
    /// Read the status again (after a failed read).
    Reload,
    /// ROTATE NOW, beside the pending-rotation warning.
    RotateNow,
    AddTpm,
    AddFido2 {
        touch_only: bool,
    },
    Remove {
        id: String,
        label: String,
    },
    Retry(String),
    RotateMaster,
    NewRecoveryKey,
    BackUp,
    /// "type a path instead": the backup's typed-path field.
    TypePath,
}

fn header(ui: &mut egui::Ui, p: &Palette, text: &str) {
    ui.label(RichText::new(text).strong().color(p.accent));
    ui.add_space(6.0);
}

/// A button whose accessible name is `name` (for the rows, where the same
/// word repeats).
fn named_button(ui: &mut egui::Ui, text: &str, name: String, enabled: bool) -> bool {
    let r = ui.add_enabled(enabled, egui::Button::new(text));
    ui.ctx()
        .accesskit_node_builder(r.id, move |n| n.set_label(name));
    r.clicked()
}

/// The page: STATUS, KEYSLOTS, KEEPING IT SAFE.
pub fn admin_section(
    ui: &mut egui::Ui,
    p: &Palette,
    state: &AdminState,
    view: &AdminView,
    touch_alone: &mut bool,
) -> Option<AdminAction> {
    let mut action = None;
    header(ui, p, "STATUS  // alephd");
    let up = view.link == Link::Up;
    let s = match state {
        AdminState::Failed(why) => {
            ui.label(RichText::new(crate::conversation::shown(why, 200)).color(p.error));
            if ui.button("RETRY").clicked() {
                action = Some(AdminAction::Reload);
            }
            return action;
        }
        AdminState::Unknown | AdminState::Loading => {
            match &view.link {
                Link::Up => ui.label("LOADING…"),
                Link::Connecting => ui.label("CONNECTING…"),
                Link::Down(why) => {
                    ui.label(RichText::new("LINK DOWN").strong().color(p.error));
                    ui.label(crate::conversation::shown(why, 200))
                }
            };
            return None;
        }
        AdminState::Ready(s) => s,
    };
    if !up {
        ui.label(RichText::new("LINK DOWN: alephd cannot be reached").color(p.error));
    }
    let text = status_text(s);
    for (i, line) in text.facts.iter().enumerate() {
        let colour = if i == 0 && text.owner_foreign {
            p.warning
        } else {
            p.foreground
        };
        ui.label(RichText::new(line).color(colour));
    }
    let enabled = up && s.vault && !view.waiting;
    for w in &text.warnings {
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("! {}", w.text)).color(p.warning));
            if w.rotate_now
                && ui
                    .add_enabled(enabled, egui::Button::new("ROTATE NOW"))
                    .clicked()
            {
                action = Some(AdminAction::RotateNow);
            }
        });
    }
    if !s.vault {
        ui.add_space(8.0);
        ui.label("no vault: run `alephctl setup`");
        return action;
    }
    ui.add_space(12.0);
    header(ui, p, "KEYSLOTS");
    if view.sealed {
        ui.label(RichText::new(SEALED_NOTE).strong().color(p.warning));
    }
    for slot in &s.keyslots {
        ui.horizontal(|ui| {
            ui.label(&slot.label);
            ui.label(RichText::new(&slot.kind).color(p.muted));
            ui.label(RichText::new(crate::manager::date(slot.created)).color(p.muted));
            let b = row_buttons(slot);
            if slot.stale {
                ui.label(RichText::new("STALE").color(p.warning));
            }
            // Deliberately ignores `view.waiting`: RETRY needs no unlock.
            if b.retry && named_button(ui, "RETRY", format!("Retry keyslot {}", slot.label), up) {
                action = Some(AdminAction::Retry(slot.id.clone()));
            }
            if b.remove
                && named_button(
                    ui,
                    "REMOVE",
                    format!("Remove keyslot {}", slot.label),
                    enabled,
                )
            {
                action = Some(AdminAction::Remove {
                    id: slot.id.clone(),
                    label: slot.label.clone(),
                });
            }
        });
    }
    ui.horizontal(|ui| {
        if ui
            .add_enabled(enabled, egui::Button::new("+ TPM"))
            .clicked()
        {
            action = Some(AdminAction::AddTpm);
        }
        if ui
            .add_enabled(enabled, egui::Button::new("+ SECURITY KEY"))
            .clicked()
        {
            action = Some(AdminAction::AddFido2 {
                touch_only: *touch_alone,
            });
        }
        ui.checkbox(touch_alone, "touch alone");
    });
    if *touch_alone {
        ui.label(RichText::new(TOUCH_WARNING).small().color(p.warning));
    }
    ui.add_space(12.0);
    header(ui, p, "KEEPING IT SAFE");
    ui.horizontal(|ui| {
        if ui
            .add_enabled(enabled, egui::Button::new("ROTATE MASTER KEY"))
            .clicked()
        {
            action = Some(AdminAction::RotateMaster);
        }
        if ui
            .add_enabled(enabled, egui::Button::new("NEW RECOVERY KEY"))
            .clicked()
        {
            action = Some(AdminAction::NewRecoveryKey);
        }
        if ui
            .add_enabled(enabled, egui::Button::new("BACK UP…"))
            .clicked()
        {
            action = Some(AdminAction::BackUp);
        }
        if ui
            .add_enabled(enabled, egui::Button::new("type a path instead").small())
            .clicked()
        {
            action = Some(AdminAction::TypePath);
        }
    });
    if view.waiting {
        ui.label("waiting for the unlock…");
    }
    action
}

/// A Yes/No step: No first, and focused (the default). `Some(true)` is Yes.
pub fn ask_section(ui: &mut egui::Ui, p: &Palette, ask: &Ask) -> Option<bool> {
    ui.label(RichText::new(ask.text()).color(p.warning));
    ui.add_space(8.0);
    let mut answer = None;
    ui.horizontal(|ui| {
        let no = ui.button("No");
        // Only while nothing has focus: a request every frame would pull
        // focus back from Yes when Tab moves it there.
        if ui.memory(|m| m.focused().is_none()) {
            no.request_focus();
        }
        if no.clicked() {
            answer = Some(false);
        }
        if ui.button("Yes").clicked() {
            answer = Some(true);
        }
    });
    answer
}

/// What the person did in the typed-path field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupField {
    Go,
    Cancel,
}

/// The fallback for the save dialog: a path to type (`error` says why the
/// last one was refused).
pub fn backup_field(
    ui: &mut egui::Ui,
    p: &Palette,
    path: &mut String,
    error: Option<&str>,
) -> Option<BackupField> {
    header(ui, p, "BACK UP  // a new file");
    let r = ui.add(
        TextEdit::singleline(path)
            .hint_text("path_")
            .desired_width(f32::INFINITY),
    );
    ui.ctx()
        .accesskit_node_builder(r.id, |n| n.set_label("Backup path"));
    if let Some(e) = error {
        ui.label(
            RichText::new(crate::conversation::shown(e, 200))
                .small()
                .color(p.warning),
        );
    }
    let mut out = None;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(!path.trim().is_empty(), egui::Button::new("BACK UP"))
            .clicked()
        {
            out = Some(BackupField::Go);
        }
        if ui.button("CANCEL").clicked() {
            out = Some(BackupField::Cancel);
        }
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{AdminStatus, SlotInfo};

    fn slot(id: &str, label: &str, kind: &str, stale: bool) -> SlotInfo {
        SlotInfo {
            id: id.into(),
            label: label.into(),
            kind: kind.into(),
            created: 1_790_553_600,
            stale,
        }
    }

    fn status() -> AdminStatus {
        AdminStatus {
            vault: true,
            locked: false,
            untrusted: None,
            memory_locked: Some(true),
            tpm: Some(true),
            keyslots: vec![
                slot("1", "tpm", "tpm", false),
                slot("2", "yubikey", "fido2", false),
                slot("3", "recovery", "recovery", false),
                slot("4", "login password", "login-password", true),
            ],
            rotation_pending: false,
            secret_service: Some("alephd".into()),
        }
    }

    #[test]
    fn status_says_the_facts_and_only_the_warnings_that_are_true() {
        let t = status_text(&status());
        assert_eq!(t.facts[0], "vault  unlocked · secret service  alephd");
        assert_eq!(t.facts[1], "TPM  usable · master key  locked in RAM");
        assert!(t.warnings.is_empty());
        assert!(!t.owner_foreign);

        let mut s = status();
        s.locked = true;
        s.memory_locked = None;
        s.tpm = None;
        s.untrusted = Some("rolled back to an older version".into());
        s.rotation_pending = true;
        s.secret_service = Some("another program".into());
        let t = status_text(&s);
        assert_eq!(
            t.facts[0],
            "vault  locked · secret service  another program"
        );
        assert_eq!(t.facts[1], "TPM  busy · master key  —");
        assert!(t.owner_foreign);
        assert_eq!(
            t.warnings,
            vec![
                Warning {
                    text: "writes refused: rolled back to an older version; see alephctl restore --accept-rollback".into(),
                    rotate_now: false
                },
                Warning {
                    text: "a password change is pending: rotate the master key".into(),
                    rotate_now: true
                },
            ]
        );
        let mut s = status();
        s.vault = false;
        s.tpm = Some(false);
        s.secret_service = None;
        let t = status_text(&s);
        assert_eq!(t.facts[0], "vault  none · secret service  unknown");
        assert!(t.facts[1].starts_with("TPM  unavailable"));
    }

    #[test]
    fn slots_get_the_buttons_that_fit() {
        let s = status();
        let b = |i: usize| row_buttons(&s.keyslots[i]);
        assert_eq!((b(0).remove, b(0).retry), (true, false));
        assert_eq!((b(1).remove, b(1).retry), (true, false));
        // The recovery slot is replaced, not removed.
        assert_eq!((b(2).remove, b(2).retry), (false, false));
        assert_eq!((b(3).remove, b(3).retry), (true, true));
        // A slot of a kind this version does not know can still be removed.
        assert!(row_buttons(&slot("9", "odd", "quantum", false)).remove);
    }

    #[test]
    fn the_yes_no_steps_use_the_agreed_words() {
        assert_eq!(
            Ask::Remove {
                id: "2".into(),
                label: "yubikey".into()
            }
            .text(),
            "Remove keyslot 'yubikey'? This rotates the master key. The key can no longer unlock the vault."
        );
        assert_eq!(
            Ask::NewRecoveryKey.text(),
            "The current recovery key stops working as soon as the new one is issued."
        );
    }

    #[test]
    fn the_backup_suggestion_names_the_day() {
        assert_eq!(
            suggested_backup_name("2026-09-28"),
            "aleph-backup-2026-09-28.aleph"
        );
    }

    #[test]
    fn a_failed_or_known_state_is_stale_and_a_loading_one_is_not() {
        assert!(AdminState::Failed("x".into()).is_stale());
        assert!(AdminState::Ready(status()).is_stale());
        assert!(!AdminState::Loading.is_stale());
        assert!(!AdminState::Unknown.is_stale());
    }
}
