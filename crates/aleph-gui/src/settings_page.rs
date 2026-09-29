//! The SETTINGS screen (the settings spec, "The screen"): what the VAULT
//! controls hold, the presets, the checking of typed minutes, and the
//! drawing of both sections. It never touches the store or the window:
//! `manager.rs` wires the effects.

use std::collections::BTreeMap;

use egui::{RichText, TextEdit};

use crate::settings::{Settings, ThemeChoice};
use crate::theme::Palette;

pub const SUSPEND: &str = "lock.on_suspend";
pub const SCREEN_LOCK: &str = "lock.on_screen_lock";
pub const IDLE: &str = "lock.idle_timeout";
pub const PROMPT: &str = "prompt.timeout";

pub const IDLE_PRESETS: &[u64] = &[0, 300, 900, 1800, 3600, 14_400];
pub const PROMPT_PRESETS: &[u64] = &[60, 300, 900, 1800];
pub const REVEAL_PRESETS: &[u64] = &[0, 60, 300, 900, 1800, 3600];
/// alephd's cap on the prompt timeout (86 400 s), in minutes.
pub const PROMPT_MAX_MINUTES: u64 = 1440;

pub const SUSPEND_WARNING: &str =
    "the master key can reach a hibernation image unless swap is encrypted";
pub const SAVE_NOTE: &str =
    "Saving asks you to confirm it is you, once (a FIDO2 touch or your login password).";
pub const LOCKED_NOTE: &str = "VAULT SEALED :: SAVE WILL UNLOCK FIRST";
pub const FOCUS_NOTE: &str = "unlocked: click this window to finish saving";

/// Which duration a control sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// alephd's idle lock; 0 is off.
    Idle,
    /// How long alephd's questions wait.
    Prompt,
    /// How long a confirmation lets secrets be shown (gui.toml); 0 is every time.
    Reveal,
}

impl Kind {
    /// The list's fixed choices, in seconds.
    pub fn presets(self) -> &'static [u64] {
        match self {
            Self::Idle => IDLE_PRESETS,
            Self::Prompt => PROMPT_PRESETS,
            Self::Reveal => REVEAL_PRESETS,
        }
    }

    /// Whether the list has a "Custom…" entry (the reveal hold has none).
    pub fn custom_minutes(self) -> bool {
        self != Self::Reveal
    }

    /// The whole minutes a typed entry may be, and the words for a bad one.
    fn bounds(self) -> (u64, u64, &'static str) {
        match self {
            // (Up to what `× 60` holds: alephd takes any number of seconds.)
            Self::Idle => (0, u64::MAX / 60, "whole minutes, 0 or more"),
            Self::Prompt => (1, PROMPT_MAX_MINUTES, "whole minutes, 1 to 1440"),
            Self::Reveal => (0, 60, "whole minutes, 0 to 60"),
        }
    }
}

/// A value in words: a preset's name, else `Custom (N min)` or, if it is
/// not whole minutes, `Custom (N s)`.
pub fn describe(kind: Kind, secs: u64) -> String {
    match (kind, secs) {
        (Kind::Idle, 0) => "Off".into(),
        (Kind::Reveal, 0) => "Every time".into(),
        (Kind::Idle, 14_400) => "4 h".into(),
        _ if kind.presets().contains(&secs) => format!("{} min", secs / 60),
        _ if secs.is_multiple_of(60) => format!("Custom ({} min)", secs / 60),
        _ => format!("Custom ({secs} s)"),
    }
}

/// What a duration control is set to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    Preset(u64),
    /// The value read, when it is not a preset: kept unless changed.
    Kept,
    /// Whole minutes, typed.
    Custom,
}

/// One duration control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timeout {
    pub kind: Kind,
    pub choice: Choice,
    /// The minutes typed, while `choice` is `Custom`.
    pub typed: String,
    read: u64,
}

impl Timeout {
    pub fn new(kind: Kind, read: u64) -> Self {
        let choice = if kind.presets().contains(&read) {
            Choice::Preset(read)
        } else {
            Choice::Kept
        };
        Self {
            kind,
            choice,
            typed: String::new(),
            read,
        }
    }

    /// The seconds alephd holds.
    pub fn read(&self) -> u64 {
        self.read
    }

    /// The list's entry for the value read, if it is not a preset.
    pub fn kept_text(&self) -> Option<String> {
        (!self.kind.presets().contains(&self.read)).then(|| describe(self.kind, self.read))
    }

    /// Pick "Custom…": an empty field to type the minutes into.
    pub fn choose_custom(&mut self) {
        if self.choice != Choice::Custom {
            self.choice = Choice::Custom;
            self.typed.clear();
        }
    }

    /// The seconds the control stands for, or the words for a bad entry.
    pub fn value(&self) -> Result<u64, String> {
        match &self.choice {
            Choice::Preset(s) => Ok(*s),
            Choice::Kept => Ok(self.read),
            Choice::Custom => {
                let (low, high, words) = self.kind.bounds();
                let t = self.typed.trim();
                let whole = !t.is_empty() && t.chars().all(|c| c.is_ascii_digit());
                match t.parse::<u64>() {
                    Ok(n) if whole && (low..=high).contains(&n) => Ok(n * 60),
                    _ => Err(words.into()),
                }
            }
        }
    }

    /// What to say under the field: only for something typed, and bad.
    pub fn error(&self) -> Option<String> {
        if self.choice == Choice::Custom && !self.typed.trim().is_empty() {
            self.value().err()
        } else {
            None
        }
    }

    /// Whether it differs from what was read (a bad entry is an edit).
    pub fn edited(&self) -> bool {
        !self.value().is_ok_and(|v| v == self.read)
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.kind, self.read);
    }

    /// `read` is what is in force now: unedited, the control follows it
    /// (a `Kept` or a preset equal to the old value becomes the new
    /// value's entry); edited, it keeps the choice and what was typed.
    fn rebase(&mut self, read: u64) {
        if self.edited() {
            self.read = read;
        } else {
            *self = Self::new(self.kind, read);
        }
    }
}

/// The VAULT section's controls, and what was read (so that only what
/// changed is sent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    pub on_suspend: bool,
    pub on_screen_lock: bool,
    pub idle: Timeout,
    pub prompt: Timeout,
    read_suspend: bool,
    read_screen_lock: bool,
}

impl Form {
    /// From alephd's four values; an error names the one that is wrong.
    pub fn from_values(values: &BTreeMap<String, String>) -> Result<Self, String> {
        let get = |key: &str| {
            values
                .get(key)
                .ok_or_else(|| format!("alephd did not send {key}"))
        };
        let flag = |key: &str| match get(key)?.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(format!("{key}: expected true or false, not {other:?}")),
        };
        let secs = |key: &str| {
            get(key)?
                .parse::<u64>()
                .map_err(|_| format!("{key}: expected a number of seconds"))
        };
        let (suspend, screen_lock) = (flag(SUSPEND)?, flag(SCREEN_LOCK)?);
        Ok(Self {
            on_suspend: suspend,
            on_screen_lock: screen_lock,
            idle: Timeout::new(Kind::Idle, secs(IDLE)?),
            prompt: Timeout::new(Kind::Prompt, secs(PROMPT)?),
            read_suspend: suspend,
            read_screen_lock: screen_lock,
        })
    }

    /// Whether every duration is a usable value (Save waits for it).
    pub fn valid(&self) -> bool {
        self.idle.value().is_ok() && self.prompt.value().is_ok()
    }

    /// Whether anything differs from what was read.
    pub fn edited(&self) -> bool {
        self.on_suspend != self.read_suspend
            || self.on_screen_lock != self.read_screen_lock
            || self.idle.edited()
            || self.prompt.edited()
    }

    /// The keys that changed, as alephd takes them (only valid ones).
    pub fn changes(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        if self.on_suspend != self.read_suspend {
            out.insert(SUSPEND.to_string(), self.on_suspend.to_string());
        }
        if self.on_screen_lock != self.read_screen_lock {
            out.insert(SCREEN_LOCK.to_string(), self.on_screen_lock.to_string());
        }
        for (key, t) in [(IDLE, &self.idle), (PROMPT, &self.prompt)] {
            if let Ok(v) = t.value()
                && v != t.read()
            {
                out.insert(key.to_string(), v.to_string());
            }
        }
        out
    }

    /// alephd's values read again (after a save that may or may not have
    /// gone through): they become what the edits are compared with. A
    /// control left as it was follows its new value; an edited one keeps
    /// the edit (and is no edit any more if it now matches). A reply that
    /// cannot be read changes nothing.
    pub fn rebase(&mut self, values: &BTreeMap<String, String>) -> Result<(), String> {
        let fresh = Self::from_values(values)?;
        if self.on_suspend == self.read_suspend {
            self.on_suspend = fresh.read_suspend;
        }
        if self.on_screen_lock == self.read_screen_lock {
            self.on_screen_lock = fresh.read_screen_lock;
        }
        self.read_suspend = fresh.read_suspend;
        self.read_screen_lock = fresh.read_screen_lock;
        self.idle.rebase(fresh.idle.read());
        self.prompt.rebase(fresh.prompt.read());
        Ok(())
    }

    /// Put back what was read.
    pub fn cancel(&mut self) {
        self.on_suspend = self.read_suspend;
        self.on_screen_lock = self.read_screen_lock;
        self.idle.reset();
        self.prompt.reset();
    }
}

/// The VAULT section's data, as far as it has come.
#[derive(Debug)]
pub enum Values {
    /// Not asked for yet (or nothing worth keeping when the link went).
    Unknown,
    Loading,
    Failed(String),
    Ready(Form),
}

impl Values {
    /// Worth reading again (the screen reopened, the link back): a failed
    /// read, or a form with no edits to keep.
    pub(crate) fn is_stale(&self) -> bool {
        match self {
            Self::Failed(_) => true,
            Self::Ready(f) => !f.edited(),
            Self::Unknown | Self::Loading => false,
        }
    }
}

/// A section's header line.
pub fn header(ui: &mut egui::Ui, p: &Palette, text: &str) {
    ui.label(RichText::new(text).strong().color(p.accent));
    ui.add_space(6.0);
}

/// What the VAULT section is allowed to do now.
pub struct VaultView {
    /// The controls work (alephd can be reached).
    pub enabled: bool,
    /// The vault is locked: Save will unlock it first (and says so).
    pub sealed: bool,
    /// An unlock asked for by Save is under way: Save waits for it.
    pub unlocking: bool,
    /// That unlock is done, but the window lacks the keyboard: the save
    /// waits for it instead (and says so).
    pub unlocked_waiting_focus: bool,
}

/// What the person asked of the VAULT section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultAction {
    Save,
    Cancel,
}

/// A drop-down list whose accessible name is `name: selected` (so a
/// screen reader, and the tests, hear what is chosen).
fn named_combo(ui: &mut egui::Ui, name: &str, selected: &str, body: impl FnOnce(&mut egui::Ui)) {
    let r = egui::ComboBox::from_id_salt(name)
        .selected_text(selected)
        .show_ui(ui, body);
    let label = format!("{name}: {selected}");
    ui.ctx()
        .accesskit_node_builder(r.response.id, move |n| n.set_label(label));
}

/// One duration row: the list, and the minutes field beside it while
/// "Custom…" is chosen, with its message under.
fn timeout_row(ui: &mut egui::Ui, p: &Palette, name: &str, t: &mut Timeout) {
    ui.horizontal(|ui| {
        ui.label(name);
        let selected = match &t.choice {
            Choice::Preset(s) => describe(t.kind, *s),
            Choice::Kept => describe(t.kind, t.read()),
            Choice::Custom => "Custom…".to_string(),
        };
        let kind = t.kind;
        let kept = t.kept_text();
        named_combo(ui, name, &selected, |ui| {
            for &s in kind.presets() {
                ui.selectable_value(&mut t.choice, Choice::Preset(s), describe(kind, s));
            }
            if let Some(text) = kept {
                ui.selectable_value(&mut t.choice, Choice::Kept, text);
            }
            if kind.custom_minutes()
                && ui
                    .selectable_label(t.choice == Choice::Custom, "Custom…")
                    .clicked()
            {
                t.choose_custom();
            }
        });
        if t.choice == Choice::Custom {
            let r = ui.add(
                TextEdit::singleline(&mut t.typed)
                    .hint_text("minutes")
                    .desired_width(70.0),
            );
            let field = format!("{name} minutes");
            ui.ctx()
                .accesskit_node_builder(r.id, move |n| n.set_label(field));
            ui.label("min");
        }
    });
    if let Some(e) = t.error() {
        ui.label(RichText::new(e).small().color(p.warning));
    }
}

/// The VAULT section's form. `Save` and `Cancel` are returned, never done
/// here.
pub fn vault_section(
    ui: &mut egui::Ui,
    p: &Palette,
    form: &mut Form,
    view: &VaultView,
) -> Option<VaultAction> {
    ui.add_enabled_ui(view.enabled, |ui| {
        ui.horizontal(|ui| {
            ui.checkbox(&mut form.on_suspend, "Lock on suspend");
            ui.label(
                RichText::new("(also covers hibernate)")
                    .small()
                    .color(p.muted),
            );
        });
        ui.checkbox(&mut form.on_screen_lock, "Lock on screen lock");
        timeout_row(ui, p, "Idle lock", &mut form.idle);
        timeout_row(ui, p, "Prompt timeout", &mut form.prompt);
    });
    if !form.on_suspend {
        ui.label(RichText::new(SUSPEND_WARNING).color(p.warning));
    }
    ui.add_space(8.0);
    ui.label(RichText::new(SAVE_NOTE).small().color(p.muted));
    if view.sealed {
        // (Beside the buttons, and not small: what Save will do first.)
        ui.label(RichText::new(LOCKED_NOTE).strong().color(p.warning));
    }
    let mut action = None;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(view.enabled && form.edited(), egui::Button::new("CANCEL"))
            .clicked()
        {
            action = Some(VaultAction::Cancel);
        }
        let ready = view.enabled && !view.unlocking && form.edited() && form.valid();
        if ui.add_enabled(ready, egui::Button::new("SAVE")).clicked() {
            action = Some(VaultAction::Save);
        }
        if view.unlocked_waiting_focus {
            ui.label(FOCUS_NOTE);
        } else if view.unlocking {
            ui.label("waiting for the unlock…");
        }
    });
    action
}

/// What the DISPLAY section is allowed to do now.
pub struct DisplayView {
    /// gui.toml did not read as settings: its error (the controls wait).
    pub broken: Option<String>,
    /// Reduced motion is asked for, so scanlines are off whatever is set.
    pub still: bool,
}

/// What the person changed in the DISPLAY section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayAction {
    Theme(ThemeChoice),
    Scanlines(bool),
    Reveal(u64),
    Reset,
}

pub fn display_section(
    ui: &mut egui::Ui,
    p: &Palette,
    s: &Settings,
    view: &DisplayView,
) -> Option<DisplayAction> {
    let mut action = None;
    header(ui, p, "DISPLAY  // gui · changes apply now");
    if let Some(why) = &view.broken {
        ui.label(RichText::new(crate::conversation::shown(why, 300)).color(p.error));
        if ui.button("RESET TO DEFAULTS").clicked() {
            action = Some(DisplayAction::Reset);
        }
    }
    ui.add_enabled_ui(view.broken.is_none(), |ui| {
        ui.horizontal(|ui| {
            ui.label("Theme");
            for (choice, name) in [(ThemeChoice::Auto, "Auto"), (ThemeChoice::Neon, "Neon")] {
                if ui.radio(s.theme == choice, name).clicked() && s.theme != choice {
                    action = Some(DisplayAction::Theme(choice));
                }
            }
        });
        ui.horizontal(|ui| {
            let mut on = s.scanlines;
            if ui.checkbox(&mut on, "Scanlines").changed() {
                action = Some(DisplayAction::Scanlines(on));
            }
            if view.still {
                ui.label(
                    RichText::new("(off: reduced motion is asked for)")
                        .small()
                        .color(p.muted),
                );
            }
        });
        ui.horizontal(|ui| {
            ui.label("Reveal confirmation lasts");
            let mut hold = s.reveal_hold;
            let selected = describe(Kind::Reveal, hold);
            named_combo(ui, "Reveal confirmation lasts", &selected, |ui| {
                for &secs in REVEAL_PRESETS {
                    ui.selectable_value(&mut hold, secs, describe(Kind::Reveal, secs));
                }
                if !REVEAL_PRESETS.contains(&s.reveal_hold) {
                    ui.selectable_value(
                        &mut hold,
                        s.reveal_hold,
                        describe(Kind::Reveal, s.reveal_hold),
                    );
                }
            });
            if hold != s.reveal_hold {
                action = Some(DisplayAction::Reveal(hold));
            }
        });
    });
    action
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(idle: &str, prompt: &str, suspend: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("lock.on_suspend".to_string(), suspend.to_string()),
            ("lock.on_screen_lock".to_string(), "true".to_string()),
            ("lock.idle_timeout".to_string(), idle.to_string()),
            ("prompt.timeout".to_string(), prompt.to_string()),
        ])
    }

    fn form(idle: &str, prompt: &str) -> Form {
        Form::from_values(&values(idle, prompt, "true")).unwrap()
    }

    fn typed(kind: Kind, text: &str) -> Result<u64, String> {
        let mut t = Timeout::new(kind, 300);
        t.choose_custom();
        t.typed = text.to_string();
        t.value()
    }

    #[test]
    fn words_for_presets_and_other_values() {
        assert_eq!(describe(Kind::Idle, 0), "Off");
        assert_eq!(describe(Kind::Idle, 900), "15 min");
        assert_eq!(describe(Kind::Idle, 3600), "60 min");
        assert_eq!(describe(Kind::Idle, 14_400), "4 h");
        assert_eq!(describe(Kind::Idle, 7200), "Custom (120 min)");
        assert_eq!(describe(Kind::Idle, 90), "Custom (90 s)");
        assert_eq!(describe(Kind::Prompt, 60), "1 min");
        assert_eq!(describe(Kind::Reveal, 0), "Every time");
        assert_eq!(describe(Kind::Reveal, 300), "5 min");
        assert_eq!(describe(Kind::Reveal, 45), "Custom (45 s)");
    }

    #[test]
    fn a_read_value_is_a_preset_or_kept() {
        let f = form("900", "300");
        assert_eq!(f.idle.choice, Choice::Preset(900));
        assert_eq!(f.prompt.choice, Choice::Preset(300));
        let f = form("7200", "90");
        assert_eq!(f.idle.choice, Choice::Kept);
        assert_eq!(f.idle.kept_text().as_deref(), Some("Custom (120 min)"));
        assert_eq!(f.prompt.kept_text().as_deref(), Some("Custom (90 s)"));
        // Kept is not an edit, and is never sent.
        assert!(!f.edited());
        assert!(f.changes().is_empty());
        assert_eq!(f.idle.value(), Ok(7200));
    }

    #[test]
    fn only_what_changed_is_sent() {
        let mut f = form("0", "300");
        assert!(!f.edited());
        f.idle.choice = Choice::Preset(900);
        f.on_suspend = false;
        assert!(f.edited() && f.valid());
        assert_eq!(
            f.changes(),
            BTreeMap::from([
                ("lock.idle_timeout".to_string(), "900".to_string()),
                ("lock.on_suspend".to_string(), "false".to_string()),
            ])
        );
        // Put back by hand: not an edit any more.
        f.idle.choice = Choice::Preset(0);
        f.on_suspend = true;
        assert!(!f.edited());
        assert!(f.changes().is_empty());
    }

    #[test]
    fn cancel_puts_the_read_values_back() {
        let mut f = form("900", "300");
        f.idle.choose_custom();
        f.idle.typed = "20".into();
        f.on_screen_lock = false;
        assert!(f.edited());
        f.cancel();
        assert!(!f.edited());
        assert_eq!(f.idle.choice, Choice::Preset(900));
        assert!(f.on_screen_lock);
    }

    #[test]
    fn typed_minutes_are_whole_and_in_range() {
        assert_eq!(typed(Kind::Idle, "0"), Ok(0));
        assert_eq!(typed(Kind::Idle, "20"), Ok(1200));
        assert_eq!(typed(Kind::Idle, " 15 "), Ok(900));
        assert_eq!(typed(Kind::Prompt, "1"), Ok(60));
        assert_eq!(typed(Kind::Prompt, "1440"), Ok(86_400));
        let prompt_bad = "whole minutes, 1 to 1440";
        for bad in [
            "0", "1441", "-1", "+5", "1e3", "1.5", "1 5", "x", "１５", "",
        ] {
            assert_eq!(
                typed(Kind::Prompt, bad),
                Err(prompt_bad.to_string()),
                "{bad:?}"
            );
        }
        // (Review Focus 3.) Too large to multiply, or to parse: refused, no panic.
        let huge = (u64::MAX / 60 + 1).to_string();
        assert!(typed(Kind::Idle, &huge).is_err());
        assert!(typed(Kind::Idle, "99999999999999999999999").is_err());
        assert_eq!(
            typed(Kind::Idle, "x"),
            Err("whole minutes, 0 or more".to_string())
        );
    }

    #[test]
    fn a_bad_entry_disables_saving_and_an_empty_one_only_waits() {
        let mut f = form("0", "300");
        f.prompt.choose_custom();
        // Just chosen: empty. Nothing to complain about yet, but not valid.
        assert_eq!(f.prompt.error(), None);
        assert!(!f.valid());
        assert!(f.edited());
        f.prompt.typed = "1441".into();
        assert_eq!(
            f.prompt.error().as_deref(),
            Some("whole minutes, 1 to 1440")
        );
        assert!(!f.valid());
        f.prompt.typed = "20".into();
        assert_eq!(f.prompt.error(), None);
        assert!(f.valid());
        assert_eq!(f.changes()["prompt.timeout"], "1200");
    }

    /// The reveal hold's list has no "Custom…", but its bounds are an hour
    /// in whole minutes, should one be typed.
    #[test]
    fn typed_reveal_minutes_are_at_most_an_hour() {
        assert_eq!(typed(Kind::Reveal, "0"), Ok(0));
        assert_eq!(typed(Kind::Reveal, "60"), Ok(3600));
        assert_eq!(
            typed(Kind::Reveal, "61"),
            Err("whole minutes, 0 to 60".to_string())
        );
    }

    /// After an interrupted save the values are read again: what is in
    /// force becomes the baseline, an unedited control follows it, and an
    /// edited one keeps the edit.
    #[test]
    fn a_rebase_keeps_the_edits_and_follows_the_rest() {
        let mut f = form("0", "300");
        f.idle.choice = Choice::Preset(900);
        f.on_screen_lock = false;
        // alephd now holds: idle 0 (as read), prompt 900 (changed
        // elsewhere), suspend off (changed elsewhere), screen lock on.
        f.rebase(&values("0", "900", "false")).unwrap();
        assert_eq!(f.idle.choice, Choice::Preset(900), "an edit stays");
        assert!(!f.on_screen_lock, "an edit stays");
        assert_eq!(f.prompt.choice, Choice::Preset(900), "follows");
        assert!(!f.on_suspend, "follows");
        assert_eq!(
            f.changes(),
            BTreeMap::from([
                ("lock.idle_timeout".to_string(), "900".to_string()),
                ("lock.on_screen_lock".to_string(), "false".to_string()),
            ])
        );
        // The save had gone through: nothing is an edit any more.
        let mut saved = values("900", "900", "false");
        saved.insert("lock.on_screen_lock".into(), "false".into());
        f.rebase(&saved).unwrap();
        assert!(!f.edited(), "{f:?}");
        // A kept value (not a preset) follows too; a typed one stays.
        let mut f = form("7200", "90");
        f.prompt.choose_custom();
        f.prompt.typed = "20".into();
        f.rebase(&values("5400", "600", "true")).unwrap();
        assert_eq!(f.idle.choice, Choice::Kept);
        assert_eq!(f.idle.value(), Ok(5400));
        assert_eq!(f.prompt.choice, Choice::Custom);
        assert_eq!(f.prompt.typed, "20");
        assert_eq!(f.prompt.read(), 600);
        // A reply that cannot be read changes nothing.
        let before = f.clone();
        assert!(f.rebase(&values("soon", "600", "true")).is_err());
        assert_eq!(f, before);
    }

    #[test]
    fn stale_values_are_read_again_and_edits_are_not() {
        assert!(Values::Failed("x".into()).is_stale());
        let mut f = form("0", "300");
        assert!(Values::Ready(f.clone()).is_stale());
        f.on_suspend = false;
        assert!(!Values::Ready(f).is_stale());
        assert!(!Values::Unknown.is_stale());
        assert!(!Values::Loading.is_stale());
    }

    #[test]
    fn a_reply_that_cannot_be_read_is_an_error_naming_the_key() {
        let mut v = values("0", "300", "true");
        v.insert("lock.idle_timeout".into(), "soon".into());
        let e = Form::from_values(&v).unwrap_err();
        assert!(e.contains("lock.idle_timeout"), "{e}");
        let mut v = values("0", "300", "maybe");
        assert!(
            Form::from_values(&v)
                .unwrap_err()
                .contains("lock.on_suspend")
        );
        v.remove("prompt.timeout");
        assert!(Form::from_values(&v).is_err());
    }
}
