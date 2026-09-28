//! Drawing the prompter's screens (spec §7 "Prompter"), and turning
//! clicks and keys into [`Action`]s. No I/O here: the window (`app.rs`)
//! sends what `show` returns.

use std::time::{Duration, Instant};

use aleph_prompt_proto::{Method, Purpose, Secret};
use egui::{Align, Button, Key, Layout, RichText, TextEdit};
use zeroize::Zeroizing;

use crate::conversation::{Action, Conversation, Screen};
use crate::theme::Palette;

/// The window's size for unlocking and confirming (the prompts alephd
/// opens), and the taller one the recovery key's screens ask for.
pub const SIZE: [f32; 2] = [460.0, 210.0];
pub const TALL: [f32; 2] = [460.0, 300.0];

/// The size a screen needs.
pub fn size_for(screen: &Screen) -> [f32; 2] {
    match screen {
        Screen::RecoveryKey { .. } | Screen::ShowRecoveryKey { .. } => TALL,
        // (Its explanation takes three rows in monospace.)
        Screen::OldPassword { .. } => [SIZE[0], 250.0],
        _ => SIZE,
    }
}

/// The unlock flow's words for a denial and for backing out (the
/// confirmations and the recovery screens keep plain words).
const DENIED: &str = "ACCESS DENIED";
const ABORT: &str = "ABORT";

/// Room kept for the row of buttons along the bottom.
const BUTTON_ROW: f32 = 36.0;

/// The most rows an error takes.
const ERROR_ROWS: usize = 3;

/// The prompter's state between frames: the conversation and what is
/// being typed.
pub struct PromptUi {
    pub conversation: Conversation,
    pub palette: Palette,
    /// No spinners (reduced motion).
    pub still: bool,
    /// What is typed. Zeroized on drop; moved (never copied) into the
    /// answer. (egui keeps its own copies while editing: spec §4 "Memory
    /// hygiene", not guaranteed.)
    pub secret: Zeroizing<String>,
    pub groups: [Zeroizing<String>; 2],
    pub show_recovery_key: bool,
    /// Which screen the fields were last focused for (focus moves to the
    /// field once per screen).
    focused_for: u64,
    screen_number: u64,
}

impl PromptUi {
    pub fn new(palette: Palette, still: bool) -> Self {
        Self {
            conversation: Conversation::new(),
            palette,
            still,
            secret: Zeroizing::default(),
            groups: Default::default(),
            show_recovery_key: false,
            focused_for: u64::MAX,
            screen_number: 0,
        }
    }

    /// A new message arrived (the screen changed): clear what was typed
    /// and move focus again.
    pub fn screen_changed(&mut self) {
        self.screen_number += 1;
        self.secret = Zeroizing::default();
        self.groups = Default::default();
        self.show_recovery_key = false;
    }

    fn take_secret(&mut self) -> Secret {
        Secret::new(std::mem::take(&mut *self.secret))
    }

    /// Draw the current screen; returns what the person did, if anything.
    pub fn show(&mut self, ui: &mut egui::Ui, now: Instant) -> Option<Action> {
        let escape = ui.input(|i| i.key_pressed(Key::Escape));
        let enter = ui.input(|i| i.key_pressed(Key::Enter));
        let focus = self.focused_for != self.screen_number;
        self.focused_for = self.screen_number;
        let p = self.palette.clone();
        let body = egui::Frame::central_panel(ui.style())
            .inner_margin(18.0)
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                self.header(ui, &p);
                ui.add_space(10.0);
                self.body(ui, &p, now, focus, enter)
            })
            .inner;
        if escape && !self.conversation.finished() {
            return Some(Action::Cancel);
        }
        if escape {
            return Some(Action::Close);
        }
        body
    }

    fn header(&self, ui: &mut egui::Ui, p: &Palette) {
        let c = &self.conversation;
        let tagline = match c.purpose {
            Some(Purpose::Unlock) | None => "ALEPH // UNLOCK VAULT",
            Some(Purpose::Reauth) => "ALEPH // IDENTITY CHECK",
            Some(Purpose::Create) => "ALEPH // NEW CONSTRUCT",
            Some(Purpose::Recover) => "ALEPH // RECOVERY PROTOCOL",
        };
        ui.label(RichText::new(tagline).small().strong().color(p.accent));
        let title = if c.operation.is_empty() {
            "aleph keyring"
        } else {
            c.operation.as_str()
        };
        ui.add(egui::Label::new(RichText::new(title).heading().strong()).truncate());
        if let Some(caller) = &c.caller {
            let who = match (&caller.name, caller.pid) {
                (Some(n), Some(pid)) => format!("REQUEST FROM {n} :: PID {pid}"),
                (Some(n), None) => format!("REQUEST FROM {n}"),
                (None, Some(pid)) => format!("REQUEST FROM PID {pid}"),
                (None, None) => String::new(),
            };
            if !who.is_empty() {
                ui.label(
                    RichText::new(who)
                        .small()
                        .color(p.foreground.gamma_multiply(0.7)),
                );
            }
        }
    }

    /// An error after `prefix` ("ACCESS DENIED"), cut to three rows: the
    /// field and the buttons below it must stay on the window.
    fn error(ui: &mut egui::Ui, p: &Palette, prefix: &str, error: &Option<String>) {
        if let Some(e) = error {
            ui.label(fitted(ui, &format!("{prefix} :: {e}"), ERROR_ROWS, p.error));
        }
    }

    /// The screen's main button: filled with the accent while it can be
    /// used, plain (and faded) while it cannot.
    fn primary(p: &Palette, text: &str, enabled: bool, ui: &mut egui::Ui) -> bool {
        let button = if enabled {
            Button::new(RichText::new(text).color(p.background).strong()).fill(p.accent)
        } else {
            Button::new(text)
        };
        ui.add_enabled(enabled, button).clicked()
    }

    /// A single-line secret field, `masked` or not, with no visible label:
    /// `hint` shows in it while it is empty, and `name` is what screen
    /// readers (and the tests) call it. True when Enter was pressed in it.
    fn secret_field(
        ui: &mut egui::Ui,
        text: &mut String,
        name: &str,
        hint: &str,
        masked: bool,
        focus: bool,
    ) -> bool {
        let r = ui.add(
            TextEdit::singleline(text)
                .password(masked)
                .hint_text(hint)
                .desired_width(f32::INFINITY),
        );
        let name = name.to_string();
        ui.ctx()
            .accesskit_node_builder(r.id, move |node| node.set_label(name));
        if focus {
            r.request_focus();
        }
        r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
    }

    /// Buttons along the bottom, right to left: `cancel` last.
    fn buttons(
        ui: &mut egui::Ui,
        cancel: &str,
        add: impl FnOnce(&mut egui::Ui) -> Option<Action>,
    ) -> Option<Action> {
        let mut out = None;
        ui.with_layout(Layout::bottom_up(Align::Max), |ui| {
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    out = add(ui);
                    if ui.button(cancel).clicked() {
                        out = Some(Action::Cancel);
                    }
                });
            });
        });
        out
    }

    fn spinner(&self, ui: &mut egui::Ui, text: &str) {
        ui.horizontal(|ui| {
            if !self.still {
                ui.spinner();
            }
            ui.label(text);
        });
    }

    fn body(
        &mut self,
        ui: &mut egui::Ui,
        p: &Palette,
        now: Instant,
        focus: bool,
        enter: bool,
    ) -> Option<Action> {
        let unlocking = self.conversation.purpose == Some(Purpose::Unlock);
        // (Split borrows: the screen is read while the fields are edited.)
        let screen = std::mem::replace(&mut self.conversation.screen, Screen::Working);
        let action = match &screen {
            Screen::Working => {
                self.spinner(
                    ui,
                    if unlocking {
                        "DECRYPTING…"
                    } else {
                        "VERIFYING…"
                    },
                );
                Self::buttons(ui, ABORT, |_| None)
            }
            Screen::Ask {
                methods,
                error,
                retry_at,
            } => {
                Self::error(ui, p, DENIED, error);
                let password = methods.contains(&Method::Password);
                let key = methods.contains(&Method::Fido2);
                let wait = retry_at
                    .map(|at| at.saturating_duration_since(now))
                    .filter(|d| !d.is_zero());
                let mut submit = false;
                if password {
                    submit = Self::secret_field(
                        ui,
                        &mut self.secret,
                        "Login password",
                        "enter passphrase_",
                        true,
                        focus,
                    );
                    if let Some(d) = wait {
                        ui.label(
                            RichText::new(format!(
                                "COUNTERMEASURES ACTIVE :: retry in {} s",
                                d.as_secs() + 1
                            ))
                            .color(p.warning),
                        );
                        ui.ctx().request_repaint_after(Duration::from_millis(250));
                    }
                } else {
                    ui.label("HARDWARE TOKEN REQUIRED");
                }
                let ready = password && wait.is_none() && !self.secret.is_empty();
                if submit && !ready {
                    // (Enter left the field: give it the keyboard back.)
                    self.focused_for = u64::MAX;
                }
                let label = if unlocking { "UNLOCK" } else { "PROCEED" };
                let mut clicked = None;
                let bar = Self::buttons(ui, ABORT, |ui| {
                    if password && Self::primary(p, label, ready, ui) {
                        clicked = Some(true);
                    }
                    if key {
                        let b = if password {
                            ui.button("USE KEY")
                        } else {
                            ui.add(
                                Button::new(RichText::new("USE KEY").color(p.background).strong())
                                    .fill(p.accent),
                            )
                        };
                        if b.clicked() {
                            clicked = Some(false);
                        }
                    }
                    None
                });
                bar.or(match clicked {
                    Some(true) => Some(Action::Password(self.take_secret())),
                    Some(false) => Some(Action::Fido2),
                    None if submit && ready => Some(Action::Password(self.take_secret())),
                    None if !password && key && enter => Some(Action::Fido2),
                    None => None,
                })
            }
            Screen::OldPassword { error } => {
                ui.label(
                    RichText::new("CREDENTIALS OUT OF SYNC")
                        .strong()
                        .color(p.warning),
                );
                ui.label(
                    "Your login password was changed outside aleph. Enter the previous one to \
                     update the TPM keyslot (a wrong one costs a TPM attempt).",
                );
                Self::error(ui, p, DENIED, error);
                let submit = Self::secret_field(
                    ui,
                    &mut self.secret,
                    "Previous login password",
                    "previous passphrase_",
                    true,
                    focus,
                );
                self.secret_answer(ui, p, submit, Action::Password, ("PROCEED", ABORT))
            }
            Screen::Pin { key, error } => {
                Self::error(ui, p, DENIED, error);
                let submit = Self::secret_field(
                    ui,
                    &mut self.secret,
                    &format!("PIN for {key}"),
                    &format!("PIN for {key}_"),
                    true,
                    focus,
                );
                self.secret_answer(ui, p, submit, Action::Pin, ("PROCEED", ABORT))
            }
            Screen::InsertKey { key } => {
                self.spinner(ui, &format!("AWAITING HARDWARE TOKEN :: insert {key}"));
                Self::buttons(ui, ABORT, |_| None)
            }
            Screen::Touch { key } => {
                self.spinner(ui, &format!("TOUCH {key} TO AUTHORIZE"));
                Self::buttons(ui, ABORT, |_| None)
            }
            Screen::Confirm { text, default } => {
                // (Cut to the rows that fit above the buttons: the text may
                // carry another program's collection label.)
                ui.label(fitted(
                    ui,
                    text,
                    rows_above_buttons(ui),
                    ui.visuals().text_color(),
                ));
                let mut answer = None;
                let bar = Self::buttons(ui, "Cancel", |ui| {
                    // (Right to left: "Yes" rightmost.)
                    let yes = ui.button("Yes");
                    let no = ui.button("No");
                    if focus {
                        if *default {
                            yes.request_focus()
                        } else {
                            no.request_focus()
                        }
                    }
                    if yes.clicked() {
                        answer = Some(true);
                    } else if no.clicked() {
                        answer = Some(false);
                    }
                    None
                });
                // (Cancel means no, too; Enter gives the default.)
                bar.or(answer.or(enter.then_some(*default)).map(Action::Confirm))
            }
            Screen::RecoveryKey { error } => {
                Self::error(ui, p, DENIED, error);
                let submit = Self::secret_field(
                    ui,
                    &mut self.secret,
                    "Recovery key (14 groups of 4)",
                    "recovery key (14 groups of 4)",
                    !self.show_recovery_key,
                    focus,
                );
                ui.checkbox(&mut self.show_recovery_key, "Show what I type");
                self.secret_answer(ui, p, submit, Action::RecoveryKey, ("Continue", "Cancel"))
            }
            Screen::ShowRecoveryKey {
                key,
                error,
                checking: false,
                ..
            } => {
                Self::error(ui, p, "CHECK FAILED", error);
                ui.label(
                    "Your new recovery key. Write it down and keep it somewhere safe: it is shown \
                     only this once, and it is the only way back in if every other method is lost.",
                );
                ui.add_space(6.0);
                key_grid(ui, p, key.expose());
                let mut done = false;
                let bar = Self::buttons(ui, "Cancel", |ui| {
                    done = Self::primary(p, "I have written it down", true, ui);
                    None
                });
                if done {
                    // (The check's first field takes the keyboard.)
                    self.focused_for = u64::MAX;
                }
                bar.or(done.then_some(Action::RecoveryKeyWritten))
            }
            Screen::ShowRecoveryKey {
                check,
                error,
                checking: true,
                ..
            } => {
                Self::error(ui, p, "CHECK FAILED", error);
                let [a, b] = &mut self.groups;
                let first = Self::secret_field(
                    ui,
                    a,
                    &format!("Group {} of your recovery key", check[0]),
                    &format!("group {}", check[0]),
                    false,
                    focus,
                );
                let second = Self::secret_field(
                    ui,
                    b,
                    &format!("Group {} of your recovery key", check[1]),
                    &format!("group {}", check[1]),
                    false,
                    false,
                );
                let ready = !a.is_empty() && !b.is_empty();
                let mut clicked = false;
                let bar = Self::buttons(ui, "Cancel", |ui| {
                    clicked = Self::primary(p, "Continue", ready, ui);
                    None
                });
                bar.or(((clicked || first || second) && ready).then(|| {
                    let [a, b] = &mut self.groups;
                    Action::RecoveryCheck([
                        Secret::new(std::mem::take(&mut **a)),
                        Secret::new(std::mem::take(&mut **b)),
                    ])
                }))
            }
            Screen::Finished { ok, message } => {
                let text = message
                    .as_deref()
                    .unwrap_or(if *ok { "Done." } else { "Stopped." });
                let color = if *ok { p.foreground } else { p.error };
                ui.label(fitted(ui, text, rows_above_buttons(ui), color));
                let mut close = false;
                ui.with_layout(Layout::bottom_up(Align::Max), |ui| {
                    close = Self::primary(p, "Close", true, ui);
                });
                (close || enter).then_some(Action::Close)
            }
        };
        self.conversation.screen = screen;
        action
    }

    /// The primary button (and Enter in the field) for a one-secret screen.
    fn secret_answer(
        &mut self,
        ui: &mut egui::Ui,
        p: &Palette,
        submit: bool,
        make: fn(Secret) -> Action,
        (proceed, cancel): (&str, &str),
    ) -> Option<Action> {
        let ready = !self.secret.is_empty();
        if submit && !ready {
            // (Enter left the empty field: give it the keyboard back.)
            self.focused_for = u64::MAX;
        }
        let mut clicked = false;
        let bar = Self::buttons(ui, cancel, |ui| {
            clicked = Self::primary(p, proceed, ready, ui);
            None
        });
        bar.or(((clicked || submit) && ready).then(|| make(self.take_secret())))
    }
}

/// The rows of body text that fit between here and the row of buttons.
fn rows_above_buttons(ui: &egui::Ui) -> usize {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let row = ui.fonts_mut(|f| f.row_height(&font));
    ((ui.available_height() - BUTTON_ROW) / row)
        .floor()
        .max(1.0) as usize
}

/// `text` wrapped to the width, cut (with "…") to `rows`.
fn fitted(ui: &egui::Ui, text: &str, rows: usize, color: egui::Color32) -> egui::text::LayoutJob {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let mut job = egui::text::LayoutJob::single_section(
        text.to_string(),
        egui::TextFormat::simple(font, color),
    );
    job.wrap = egui::text::TextWrapping {
        max_width: ui.available_width(),
        max_rows: rows,
        break_anywhere: false,
        overflow_character: Some('…'),
    };
    job
}

/// The recovery key as a grid of numbered groups, 7 to a row.
fn key_grid(ui: &mut egui::Ui, p: &Palette, key: &str) {
    let groups: Vec<&str> = key.split('-').collect();
    egui::Grid::new("recovery-key")
        .spacing([10.0, 2.0])
        .show(ui, |ui| {
            for (r, chunk) in groups.chunks(7).enumerate() {
                for (i, _) in chunk.iter().enumerate() {
                    ui.label(
                        RichText::new(format!("{}", r * 7 + i + 1))
                            .small()
                            .color(p.muted),
                    );
                }
                ui.end_row();
                for g in chunk {
                    ui.label(RichText::new(*g).monospace().size(16.0).color(p.foreground));
                }
                ui.end_row();
            }
        });
}
