//! The manager window (the manager spec, "The window"): folders and items
//! from the [`Store`], a detail pane, and the actions on them. Secrets are
//! fetched only to show, copy, or edit one, after the reveal guard.

use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use egui::{Button, RichText, TextEdit};
use zeroize::Zeroizing;

use crate::app::PromptApp;
use crate::clipboard::{Backend, Clipboard};
use crate::conversation::{Screen, shown};
use crate::reauth::Reauth;
use crate::settings::Settings;
use crate::settings_page::{
    self, DisplayAction, DisplayView, Form, Values, VaultAction, VaultView,
};
use crate::store::{Collection, Item, Request, Store, StoreEvent, Vault};
use crate::theme::{self, Palette};

/// The window's first size.
pub const SIZE: [f32; 2] = [900.0, 560.0];

/// The longest label or value shown in a list (the full text is in the
/// detail pane, wrapped).
const NAME: usize = 60;

/// The requests a form's SAVE sends ([`Request::name`]).
const SAVES: &[&str] = &[
    "rename",
    "change the secret",
    "create the item",
    "create the folder",
];

/// What is selected in the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    Item(String),
    Collection(String),
}

/// What a fetched secret is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    Show,
    Copy,
    Edit,
}

/// Which screen the window shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Secrets,
    Settings,
}

/// A secret on screen.
pub enum Shown {
    Text(Zeroizing<String>),
    /// Not UTF-8 text: its length.
    Binary(usize),
}

/// The list panel, and the least width it and the detail get.
const LIST: &str = "aleph-list";
const LIST_MIN: f32 = 140.0;
const DETAIL_MIN: f32 = 140.0;

/// The most of a shown secret's height the pane gives it (it scrolls).
const SECRET_HEIGHT: f32 = 220.0;

/// What the detail pane is doing.
pub enum Mode {
    Browse,
    Edit {
        path: String,
        label: String,
        /// The secret being edited: fetched (after the reveal guard), or
        /// typed.
        secret: Option<Zeroizing<String>>,
        /// The secret as fetched: a save sends the secret only if it
        /// differs (`None` once a lock forgot it: then what was typed is
        /// sent).
        original: Option<Zeroizing<String>>,
    },
    New {
        collection: String,
        label: String,
        secret: Zeroizing<String>,
        attributes: Vec<(String, String)>,
    },
    DeleteItem {
        path: String,
        label: String,
    },
    NewFolder {
        label: String,
    },
}

pub struct Manager<S: Store, B: Backend> {
    pub store: S,
    pub clipboard: Clipboard<B>,
    pub reauth: Reauth,
    pub vault: Vault,
    pub search: String,
    pub selected: Option<Selection>,
    pub shown: Option<(String, Shown)>,
    pub mode: Mode,
    /// The one-line status at the top (errors, "copied").
    pub status: Option<String>,
    /// A secret asked for, and what for.
    awaiting: Option<(String, Want)>,
    /// The list's share of the width the navigation leaves (the rest is
    /// the detail's), and that width when last drawn.
    list_share: f32,
    list_room: f32,
    /// What runs once the reveal guard confirms.
    pending: Option<(String, Want)>,
    /// The reveal guard's conversation, drawn in the detail pane.
    confirm: Option<PromptApp>,
    /// Keys ignored as the confirmation appears (the tests set it to 0).
    pub confirm_guard: Duration,
    /// Save requests not answered yet: the form stays until they succeed
    /// (and stays, with the error, if one fails).
    pub saving: usize,
    settings: Settings,
    settings_file: Option<PathBuf>,
    display_broken: Option<String>,
    home: Option<PathBuf>,
    still: bool,
    pub palette: Palette,
    watch: Option<theme::Watch>,
    page: Page,
    /// The VAULT section's values: kept across screens, so edits stay.
    values: Values,
    /// The confirmation on screen is for a settings save, not a reveal.
    saving_settings: bool,
    /// SAVE was pressed while the vault was locked: it asked alephd to
    /// unlock, and saves (with the edits as they are then) once it is open.
    save_after_unlock: bool,
}

impl<S: Store, B: Backend> Manager<S, B> {
    pub fn new(
        store: S,
        backend: B,
        settings: Settings,
        home: Option<PathBuf>,
        still: bool,
    ) -> Self {
        let palette = theme::resolve(&settings, home.as_deref());
        Self {
            store,
            clipboard: Clipboard::new(backend),
            reauth: Reauth::default(),
            vault: Vault::Connecting,
            search: String::new(),
            selected: None,
            shown: None,
            mode: Mode::Browse,
            status: None,
            awaiting: None,
            list_share: 0.5,
            list_room: 0.0,
            pending: None,
            confirm: None,
            confirm_guard: crate::app::INPUT_GUARD,
            saving: 0,
            settings,
            settings_file: None,
            display_broken: None,
            home,
            still,
            palette,
            watch: None,
            page: Page::Secrets,
            values: Values::Unknown,
            saving_settings: false,
            save_after_unlock: false,
        }
    }

    /// Where gui.toml is, and why it could not be read (if it could not):
    /// DISPLAY writes there, and waits for a reset when it is broken.
    pub fn with_settings_file(mut self, file: Option<PathBuf>, broken: Option<String>) -> Self {
        self.settings_file = file;
        self.display_broken = broken;
        self
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// A DISPLAY change: in effect now, and written to gui.toml. A write
    /// that fails is said so; the change holds for this run.
    fn apply_display(&mut self, ctx: &egui::Context, action: DisplayAction) {
        match action {
            DisplayAction::Theme(t) => self.settings.theme = t,
            DisplayAction::Scanlines(on) => self.settings.scanlines = on,
            DisplayAction::Reveal(secs) => self.settings.reveal_hold = secs,
            DisplayAction::Reset => {
                self.settings = Settings::default();
                let done = match &self.settings_file {
                    Some(file) => Settings::reset(file),
                    None => Ok(()),
                };
                match done {
                    Ok(()) => self.display_broken = None,
                    Err(e) => self.status = Some(format!("not reset: {e}")),
                }
                self.palette = theme::resolve(&self.settings, self.home.as_deref());
                theme::apply(ctx, &self.palette);
                return;
            }
        }
        self.palette = theme::resolve(&self.settings, self.home.as_deref());
        theme::apply(ctx, &self.palette);
        let written = match &self.settings_file {
            Some(file) => self.settings.save(file),
            None => Err("no configuration directory".to_string()),
        };
        if let Err(e) = written {
            self.status = Some(format!(
                "not saved: {e} (the change holds until the window closes)"
            ));
        }
    }

    pub fn page(&self) -> Page {
        self.page
    }

    /// The VAULT form, once read.
    pub fn form(&self) -> Option<&Form> {
        match &self.values {
            Values::Ready(f) => Some(f),
            _ => None,
        }
    }

    /// Re-theme live when the Omarchy theme changes (spec §7).
    pub fn watch_theme(&mut self, ctx: &egui::Context) {
        self.watch = self
            .home
            .as_deref()
            .and_then(|home| theme::Watch::start(home, ctx));
    }

    fn collections(&self) -> &[Collection] {
        match &self.vault {
            Vault::Unlocked(c) => c,
            _ => &[],
        }
    }

    fn item(&self, path: &str) -> Option<&Item> {
        self.collections()
            .iter()
            .flat_map(|c| &c.items)
            .find(|i| i.path == path)
    }

    /// Show, copy, or edit `path`'s secret: after the reveal guard, then
    /// fetched.
    fn want(&mut self, ctx: &egui::Context, path: String, want: Want, now: Instant) {
        if self
            .reauth
            .needed(now, Duration::from_secs(self.settings.reveal_hold))
        {
            self.start_confirm(ctx, path, want);
        } else {
            self.fetch(path, want);
        }
    }

    fn fetch(&mut self, path: String, want: Want) {
        self.store.request(Request::Secret(path.clone()));
        self.awaiting = Some((path, want));
    }

    /// Open the confirmation in this window: the prompter's end of a new
    /// socketpair (for alephd), or `None` (with the reason in the status).
    fn open_confirm(&mut self, ctx: &egui::Context) -> Option<UnixStream> {
        let Ok((ours, theirs)) = UnixStream::pair() else {
            self.status = Some("cannot start the confirmation".into());
            return None;
        };
        let Ok(reader) = ours.try_clone() else {
            self.status = Some("cannot start the confirmation".into());
            return None;
        };
        // (Each message from alephd wakes the window: with animations off
        // nothing else draws the next frame.)
        let wake = ctx.clone();
        let Ok(events) = crate::link::spawn_reader(reader, move || wake.request_repaint()) else {
            self.status = Some("cannot start the confirmation".into());
            return None;
        };
        let mut app = PromptApp::new(
            ours,
            events,
            self.settings.clone(),
            self.home.clone(),
            self.still,
        );
        app.embedded = true;
        app.input_guard = self.confirm_guard;
        self.confirm = Some(app);
        Some(theirs)
    }

    fn start_confirm(&mut self, ctx: &egui::Context, path: String, want: Want) {
        let Some(theirs) = self.open_confirm(ctx) else {
            return;
        };
        self.pending = Some((path, want));
        self.store.request(Request::Reauth(theirs.into()));
    }

    /// Save the changed VAULT settings: one confirmation for all of them.
    fn start_save(&mut self, ctx: &egui::Context, changes: BTreeMap<String, String>) {
        let Some(theirs) = self.open_confirm(ctx) else {
            return;
        };
        self.saving_settings = true;
        self.store
            .request(Request::SetConfigs(theirs.into(), changes));
    }

    /// End the confirmation, if one runs (alephd holds its conversation
    /// lock until it ends).
    fn end_confirm(&mut self) {
        if let Some(app) = self.confirm.take() {
            app.shutdown();
        }
    }

    /// Hide and forget what the keyring's lock makes unreadable.
    fn sealed(&mut self) {
        self.reauth.forget();
        self.shown = None;
        self.awaiting = None;
        self.pending = None;
        self.end_confirm();
        if std::mem::take(&mut self.saving_settings) {
            self.status = Some("the vault locked: nothing was saved".into());
        }
        if let Mode::Edit {
            secret, original, ..
        } = &mut self.mode
        {
            // (The form stays. A fetched secret left as it was must be
            // fetched again; one typed or edited stays, and is saved as is.)
            if *secret == *original {
                *secret = None;
            }
            *original = None;
        }
    }

    fn take_events(&mut self) {
        for e in self.store.events() {
            match e {
                StoreEvent::Vault(v) => {
                    if !matches!(v, Vault::Unlocked(_)) && matches!(self.vault, Vault::Unlocked(_))
                    {
                        self.sealed();
                    }
                    let was_up = matches!(self.vault, Vault::Locked | Vault::Unlocked(_));
                    self.vault = v;
                    let up = matches!(self.vault, Vault::Locked | Vault::Unlocked(_));
                    if !up && matches!(self.values, Values::Loading) {
                        self.values = Values::Unknown;
                    }
                    if up && !was_up {
                        // (The link is back: read again, unless there are
                        // edits, which stay.)
                        let again = match &self.values {
                            Values::Failed(_) => true,
                            Values::Ready(f) => !f.edited(),
                            _ => false,
                        };
                        if again {
                            self.values = Values::Unknown;
                        }
                    }
                    // (The selection goes if its item or folder went.)
                    let gone = match &self.selected {
                        Some(Selection::Item(p)) => self.item(p).is_none(),
                        Some(Selection::Collection(p)) => {
                            !self.collections().iter().any(|c| &c.path == p)
                        }
                        None => false,
                    };
                    if gone && matches!(self.vault, Vault::Unlocked(_)) {
                        self.selected = None;
                        self.shown = None;
                    }
                    // (A form on an item deleted elsewhere closes, saying
                    // so: its save would go nowhere.)
                    let form_gone = match &self.mode {
                        Mode::Edit { path, label, .. } | Mode::DeleteItem { path, label }
                            if matches!(self.vault, Vault::Unlocked(_))
                                && self.item(path).is_none() =>
                        {
                            Some(label.clone())
                        }
                        _ => None,
                    };
                    if let Some(label) = form_gone {
                        self.mode = Mode::Browse;
                        self.saving = 0;
                        self.status =
                            Some(format!("'{}' was deleted elsewhere", shown(&label, NAME)));
                    }
                }
                StoreEvent::Config(result) => {
                    // (Only the answer being waited for.)
                    if matches!(self.values, Values::Loading) {
                        self.values = match result.and_then(|v| Form::from_values(&v)) {
                            Ok(form) => Values::Ready(form),
                            Err(e) => Values::Failed(e),
                        };
                    }
                }
                StoreEvent::SecretFailed { path, .. } => {
                    // (Only if it is the one asked for last; the error is
                    // in the `Done` that follows.)
                    if self.awaiting.as_ref().is_some_and(|(p, _)| *p == path) {
                        self.awaiting = None;
                    }
                }
                StoreEvent::Secret { path, secret, .. } => {
                    // (Only the secret asked for last: an earlier one is
                    // dropped, and wiped.)
                    let Some(want) = self
                        .awaiting
                        .as_ref()
                        .filter(|(p, _)| *p == path)
                        .map(|(_, w)| *w)
                    else {
                        continue;
                    };
                    self.awaiting = None;
                    match want {
                        Want::Show => {
                            let shown = match std::str::from_utf8(&secret) {
                                // (JSON indented, for reading; COPY and EDIT
                                // fetch the secret as stored.)
                                Ok(t) => Shown::Text(
                                    crate::pretty::json(t)
                                        .unwrap_or_else(|| Zeroizing::new(t.to_string())),
                                ),
                                Err(_) => Shown::Binary(secret.len()),
                            };
                            self.shown = Some((path, shown));
                        }
                        Want::Copy => {
                            self.status = Some(match self.clipboard.copy(secret) {
                                Ok(()) => "COPIED :: the clipboard clears in 30 s".into(),
                                Err(e) => format!("cannot copy: {e}"),
                            });
                        }
                        Want::Edit => {
                            let Ok(text) = std::str::from_utf8(&secret) else {
                                self.status = Some(
                                    "binary secret: not editable here (it can be copied)".into(),
                                );
                                continue;
                            };
                            if let Mode::Edit {
                                path: p,
                                secret: s,
                                original,
                                ..
                            } = &mut self.mode
                                && *p == path
                            {
                                *s = Some(Zeroizing::new(text.to_string()));
                                *original = Some(Zeroizing::new(text.to_string()));
                            }
                        }
                    }
                }
                StoreEvent::Done {
                    request,
                    error,
                    dismissed,
                } => {
                    if request == "unlock"
                        && self.save_after_unlock
                        && (error.is_some() || dismissed)
                    {
                        // (A save waiting for the unlock is dropped; the edits stay.
                        // A successful unlock keeps it: `resume_save` runs when the
                        // vault event shows it open.)
                        self.save_after_unlock = false;
                        self.status = Some(match &error {
                            Some(e) => format!("cannot unlock: {e}; nothing was saved"),
                            None => "the unlock was dismissed: nothing was saved".into(),
                        });
                        continue;
                    }
                    if request == "read the settings" {
                        // (The VAULT section shows why, with RETRY.)
                        continue;
                    }
                    if request == "save the settings" {
                        if let Some(e) = error {
                            self.end_confirm();
                            self.saving_settings = false;
                            self.status = Some(format!("cannot save the settings: {e}"));
                        }
                        continue;
                    }
                    let save = SAVES.contains(&request) && self.saving > 0;
                    match error {
                        Some(e) => {
                            self.status = Some(format!("cannot {request}: {e}"));
                            // (The form stays, with what was typed.)
                            if save {
                                self.saving = 0;
                            }
                        }
                        None if save => {
                            self.saving -= 1;
                            if self.saving == 0 {
                                self.mode = Mode::Browse;
                            }
                        }
                        None => {}
                    }
                }
            }
        }
    }

    /// One frame.
    pub fn frame(&mut self, ui: &mut egui::Ui) {
        let now = Instant::now();
        if self.watch.as_ref().is_some_and(theme::Watch::changed) {
            self.palette = theme::resolve(&self.settings, self.home.as_deref());
            theme::apply(ui.ctx(), &self.palette);
        }
        // Leaving the window hides a shown secret and ends a confirmation
        // (which holds alephd's conversation lock until it ends).
        if ui.input(|i| {
            i.events
                .iter()
                .any(|e| matches!(e, egui::Event::WindowFocused(false)))
        }) {
            self.shown = None;
            self.end_confirm();
            self.pending = None;
            if std::mem::take(&mut self.saving_settings) {
                self.status = Some("the window lost focus: nothing was saved".into());
            }
            if matches!(self.awaiting, Some((_, Want::Show))) {
                self.awaiting = None;
            }
        }
        self.take_events();
        self.resume_save(&ui.ctx().clone());
        self.ask_config();
        let p = self.palette.clone();
        let mut go = None;
        egui::Panel::left("aleph-nav")
            .exact_size(130.0)
            .resizable(false)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("ALEPH").strong().color(p.accent));
                ui.label(RichText::new("// VAULT").small().color(p.accent));
                ui.add_space(16.0);
                // (Not while a confirmation runs: it is drawn in the page.)
                ui.add_enabled_ui(self.confirm.is_none(), |ui| {
                    for (page, name) in [(Page::Secrets, "SECRETS"), (Page::Settings, "SETTINGS")] {
                        let picked = self.page == page;
                        if ui
                            .add(Button::selectable(picked, RichText::new(name).strong()))
                            .clicked()
                        {
                            go = Some(page);
                        }
                    }
                });
            });
        if let Some(page) = go {
            self.page = page;
        }
        match self.page {
            Page::Secrets => self.secrets(ui, &p, now),
            Page::Settings => self.settings_screen(ui, &p, now),
        }
        if self.settings.scanlines && !self.still {
            theme::paint_scanlines(ui.ctx(), &p);
        }
    }

    /// The secrets screen: the vault's state, or its folders and items.
    fn secrets(&mut self, ui: &mut egui::Ui, p: &Palette, now: Instant) {
        match self.vault.clone() {
            Vault::Unlocked(collections) => self.unlocked(ui, p, &collections, now),
            other => {
                egui::CentralPanel::default().show(ui, |ui| {
                    self.status_line(ui, p);
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| match other {
                        Vault::Connecting => {
                            ui.label("CONNECTING…");
                        }
                        Vault::Unreachable(why) => {
                            ui.label(RichText::new("LINK DOWN").strong().color(p.error));
                            ui.label(shown(&why, 200));
                            ui.label("alephd cannot be reached; retrying.");
                        }
                        Vault::Locked => {
                            ui.label(RichText::new("VAULT SEALED").strong().color(p.warning));
                            ui.add_space(8.0);
                            if ui
                                .add(
                                    Button::new(
                                        RichText::new("UNLOCK").strong().color(p.background),
                                    )
                                    .fill(p.accent),
                                )
                                .clicked()
                            {
                                self.store.request(Request::Unlock);
                            }
                        }
                        Vault::Unlocked(_) => {}
                    });
                });
            }
        }
    }

    /// A save that waited for the unlock (SAVE pressed while sealed): now
    /// that the vault is open, confirm and save what is in the form. Not
    /// if the form went (another screen, nothing left to save).
    fn resume_save(&mut self, ctx: &egui::Context) {
        if !self.save_after_unlock || !matches!(self.vault, Vault::Unlocked(_)) {
            return;
        }
        self.save_after_unlock = false;
        let changes = match &self.values {
            Values::Ready(f) if self.page == Page::Settings && f.edited() && f.valid() => {
                f.changes()
            }
            _ => {
                // (Not silently: the edits stay, for another SAVE.)
                self.status = Some("the vault unlocked: the settings were not saved".into());
                return;
            }
        };
        self.start_save(ctx, changes);
    }

    /// Ask alephd for the VAULT values when the screen needs them.
    fn ask_config(&mut self) {
        let up = matches!(self.vault, Vault::Locked | Vault::Unlocked(_));
        if self.page == Page::Settings && up && matches!(self.values, Values::Unknown) {
            self.values = Values::Loading;
            self.store.request(Request::Config);
        }
    }

    fn settings_screen(&mut self, ui: &mut egui::Ui, p: &Palette, now: Instant) {
        egui::CentralPanel::default().show(ui, |ui| {
            self.status_line(ui, p);
            if self.confirm.is_some() {
                self.confirming(ui, now);
                return;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.vault_settings(ui, p);
                ui.add_space(16.0);
                ui.separator();
                let view = DisplayView {
                    broken: self.display_broken.clone(),
                    still: self.still,
                };
                if let Some(a) = settings_page::display_section(ui, p, &self.settings, &view) {
                    self.apply_display(&ui.ctx().clone(), a);
                }
            });
        });
    }

    fn vault_settings(&mut self, ui: &mut egui::Ui, p: &Palette) {
        settings_page::header(ui, p, "VAULT  // alephd");
        let up = matches!(self.vault, Vault::Locked | Vault::Unlocked(_));
        let sealed = matches!(self.vault, Vault::Locked);
        let mut action = None;
        match &mut self.values {
            Values::Ready(form) => {
                if !up {
                    ui.label(RichText::new("LINK DOWN: alephd cannot be reached").color(p.error));
                }
                let view = VaultView {
                    enabled: up,
                    sealed,
                    unlocking: self.save_after_unlock,
                };
                action = settings_page::vault_section(ui, p, form, &view);
            }
            Values::Failed(why) => {
                ui.label(RichText::new(shown(why, 200)).color(p.error));
                if ui.button("RETRY").clicked() {
                    self.values = Values::Unknown;
                }
            }
            Values::Unknown | Values::Loading => {
                if up {
                    ui.label("LOADING…");
                } else if let Vault::Unreachable(why) = &self.vault {
                    ui.label(RichText::new("LINK DOWN").strong().color(p.error));
                    ui.label(shown(why, 200));
                } else {
                    ui.label("CONNECTING…");
                }
            }
        }
        match action {
            Some(VaultAction::Cancel) => {
                if let Values::Ready(form) = &mut self.values {
                    form.cancel();
                }
                self.save_after_unlock = false;
            }
            Some(VaultAction::Save) => {
                if sealed {
                    // (Confirming needs the vault open: unlock first, and
                    // save when it is; `resume_save`.)
                    self.save_after_unlock = true;
                    self.store.request(Request::Unlock);
                } else if let Values::Ready(form) = &self.values {
                    let changes = form.changes();
                    self.start_save(&ui.ctx().clone(), changes);
                }
            }
            None => {}
        }
    }

    fn status_line(&mut self, ui: &mut egui::Ui, p: &Palette) {
        if let Some(s) = &self.status {
            let mut clear = false;
            ui.horizontal(|ui| {
                ui.label(RichText::new(shown(s, 200)).color(p.warning));
                clear = ui.small_button("×").clicked();
            });
            if clear {
                self.status = None;
            }
        }
    }

    fn matches(&self, item: &Item) -> bool {
        let q = self.search.trim().to_lowercase();
        q.is_empty()
            || item.label.to_lowercase().contains(&q)
            || item
                .attributes
                .values()
                .any(|v| v.to_lowercase().contains(&q))
    }

    fn unlocked(
        &mut self,
        ui: &mut egui::Ui,
        p: &Palette,
        collections: &[Collection],
        now: Instant,
    ) {
        // The list and the detail share the width, evenly at first; the
        // divider drags, and the share it leaves holds when the window is
        // retiled (half a screen, side by side, leaves little).
        let room = ui.available_width();
        let range = if room >= LIST_MIN + DETAIL_MIN {
            LIST_MIN..=room - DETAIL_MIN
        } else {
            room / 2.0..=room / 2.0
        };
        if room != self.list_room {
            // (The panel keeps its last width: forget it, so the share
            // applies to the new room.)
            ui.ctx()
                .data_mut(|d| d.remove::<egui::containers::panel::PanelState>(egui::Id::new(LIST)));
            self.list_room = room;
        }
        let list = egui::Panel::left(LIST)
            .default_size((self.list_share * room).clamp(*range.start(), *range.end()))
            .size_range(range)
            .resizable(true)
            .show(ui, |ui| {
                ui.add_space(6.0);
                let search = ui.add(
                    TextEdit::singleline(&mut self.search)
                        .hint_text("search_")
                        .desired_width(f32::INFINITY),
                );
                let name = "Search".to_string();
                ui.ctx()
                    .accesskit_node_builder(search.id, move |n| n.set_label(name));
                ui.add_space(6.0);
                egui::Panel::bottom("aleph-list-buttons").show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("+ ITEM").clicked() {
                            let collection = match &self.selected {
                                Some(Selection::Collection(c)) => c.clone(),
                                Some(Selection::Item(i)) => collections
                                    .iter()
                                    .find(|c| c.items.iter().any(|it| &it.path == i))
                                    .map(|c| c.path.clone())
                                    .unwrap_or_default(),
                                None => collections
                                    .first()
                                    .map(|c| c.path.clone())
                                    .unwrap_or_default(),
                            };
                            // (A new form: an answer still owed to another no longer closes it.)
                            self.saving = 0;
                            self.shown = None;
                            self.mode = Mode::New {
                                collection,
                                label: String::new(),
                                secret: Zeroizing::default(),
                                attributes: Vec::new(),
                            };
                        }
                        if ui.button("+ FOLDER").clicked() {
                            // (A new form: an answer still owed to another no longer closes it.)
                            self.saving = 0;
                            self.shown = None;
                            self.mode = Mode::NewFolder {
                                label: String::new(),
                            };
                        }
                    });
                });
                let mut clicked = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for c in collections {
                        let title = if c.is_default {
                            format!("{} (default)", shown(&c.label, NAME))
                        } else {
                            shown(&c.label, NAME)
                        };
                        let picked = self.selected == Some(Selection::Collection(c.path.clone()));
                        // (Rows are cut to the list's width: a panel grows to
                        // fit what is wider, and the divider could not move.)
                        if ui
                            .add(
                                Button::selectable(picked, RichText::new(title).strong())
                                    .truncate(),
                            )
                            .clicked()
                        {
                            clicked = Some(Selection::Collection(c.path.clone()));
                        }
                        for it in c.items.iter().filter(|i| self.matches(i)) {
                            let picked = self.selected == Some(Selection::Item(it.path.clone()));
                            ui.horizontal(|ui| {
                                ui.add_space(14.0);
                                if ui
                                    .add(
                                        Button::selectable(picked, shown(&it.label, NAME))
                                            .truncate(),
                                    )
                                    .clicked()
                                {
                                    clicked = Some(Selection::Item(it.path.clone()));
                                }
                            });
                        }
                    }
                });
                if let Some(s) = clicked {
                    self.select(s);
                }
            });
        if room > 0.0 {
            self.list_share = list.response.rect.width() / room;
        }
        egui::CentralPanel::default().show(ui, |ui| {
            self.status_line(ui, p);
            if self.confirm.is_some() {
                self.confirming(ui, now);
                return;
            }
            self.detail(ui, p, collections, now);
        });
    }

    fn select(&mut self, s: Selection) {
        if self.selected.as_ref() != Some(&s) {
            self.shown = None;
            // (A secret still coming for the old one is not kept unseen.)
            self.awaiting = None;
            self.mode = Mode::Browse;
            // (The form was left: its answer, still to come, closes nothing.)
            self.saving = 0;
        }
        self.selected = Some(s);
    }

    /// The reveal guard, drawn with the prompter's screens.
    fn confirming(&mut self, ui: &mut egui::Ui, now: Instant) {
        let Some(app) = self.confirm.as_mut() else {
            return;
        };
        if self.pending.is_some() {
            // (What the guard is worth: spec §6.)
            ui.label(
                RichText::new(
                    "Any program running as you can read secrets; this only guards against a glance.",
                )
                .small()
                .color(self.palette.foreground.gamma_multiply(0.7)),
            );
        }
        app.frame(ui);
        if app.closed {
            let (ok, message) = match &app.ui.conversation.screen {
                Screen::Finished { ok, message } => (*ok, message.clone()),
                _ => (false, None),
            };
            self.end_confirm();
            if std::mem::take(&mut self.saving_settings) {
                if ok {
                    // (The same proof as a reveal's; and read again.)
                    self.reauth.confirmed(now);
                    self.status = Some("SETTINGS SAVED".into());
                    self.values = Values::Unknown;
                } else {
                    self.status = Some(match message {
                        Some(m) => format!("not saved: {m}"),
                        None => "cancelled: nothing was saved".into(),
                    });
                }
            } else if let Some((path, want)) = self.pending.take()
                && ok
            {
                self.reauth.confirmed(now);
                self.fetch(path, want);
            }
        }
    }

    fn detail(&mut self, ui: &mut egui::Ui, p: &Palette, collections: &[Collection], now: Instant) {
        match std::mem::replace(&mut self.mode, Mode::Browse) {
            Mode::Browse => {
                self.mode = Mode::Browse;
                self.browse(ui, p, collections, now);
            }
            Mode::Edit {
                path,
                mut label,
                secret,
                original,
            } => {
                ui.label(RichText::new("EDIT").strong().color(p.accent));
                ui.add_space(6.0);
                field(ui, &mut label, "Label", "label_", false);
                let mut secret = secret;
                match &mut secret {
                    Some(s) => {
                        field(ui, s, "Secret", "secret_", true);
                    }
                    None => {
                        ui.label(RichText::new("the secret is not loaded").color(p.muted));
                        if ui.button("LOAD SECRET").clicked() {
                            self.want(&ui.ctx().clone(), path.clone(), Want::Edit, now);
                        }
                    }
                }
                ui.add_space(8.0);
                let (save, cancel) = self.save_buttons(ui, !label.trim().is_empty());
                if cancel {
                    // (An answer still to come no longer closes a form.)
                    self.saving = 0;
                }
                if save {
                    let mut sent = 0;
                    if self.item(&path).is_some_and(|i| i.label != label) {
                        self.store.request(Request::SetLabel {
                            path: path.clone(),
                            label: label.clone(),
                        });
                        sent += 1;
                    }
                    // (Only a secret that changed: an unchanged one is not
                    // rewritten.)
                    if let Some(s) = &secret
                        && secret != original
                    {
                        self.store.request(Request::SetSecret {
                            path: path.clone(),
                            secret: Zeroizing::new(s.as_bytes().to_vec()),
                        });
                        sent += 1;
                    }
                    self.shown = None;
                    self.saving = sent;
                }
                if !cancel && !(save && self.saving == 0) {
                    self.mode = Mode::Edit {
                        path,
                        label,
                        secret,
                        original,
                    };
                }
            }
            Mode::New {
                collection,
                mut label,
                mut secret,
                mut attributes,
            } => {
                let folder = collections
                    .iter()
                    .find(|c| c.path == collection)
                    .map(|c| shown(&c.label, NAME))
                    .unwrap_or_default();
                ui.label(
                    RichText::new(format!("NEW ITEM :: {folder}"))
                        .strong()
                        .color(p.accent),
                );
                ui.add_space(6.0);
                if collection.is_empty() {
                    ui.label(
                        RichText::new("No folder to put it in: create a folder first (+ FOLDER).")
                            .color(p.warning),
                    );
                }
                field(ui, &mut label, "Label", "label_", false);
                field(ui, &mut secret, "Secret", "secret_", true);
                ui.add_space(4.0);
                ui.label(RichText::new("ATTRIBUTES").small().color(p.muted));
                let mut remove = None;
                for (i, (k, v)) in attributes.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        let key = ui.add(
                            TextEdit::singleline(k)
                                .hint_text("key")
                                .desired_width(120.0),
                        );
                        let name = format!("Attribute {} key", i + 1);
                        ui.ctx()
                            .accesskit_node_builder(key.id, move |n| n.set_label(name));
                        let value = ui.add(
                            TextEdit::singleline(v)
                                .hint_text("value")
                                .desired_width(200.0),
                        );
                        let name = format!("Attribute {} value", i + 1);
                        ui.ctx()
                            .accesskit_node_builder(value.id, move |n| n.set_label(name));
                        if ui.small_button("×").clicked() {
                            remove = Some(i);
                        }
                    });
                }
                if let Some(i) = remove {
                    attributes.remove(i);
                }
                if ui.small_button("+ ATTRIBUTE").clicked() {
                    attributes.push((String::new(), String::new()));
                }
                ui.add_space(8.0);
                let ready =
                    !label.trim().is_empty() && !secret.is_empty() && !collection.is_empty();
                let (save, cancel) = self.save_buttons(ui, ready);
                if cancel {
                    // (An answer still to come no longer closes a form.)
                    self.saving = 0;
                }
                if save {
                    let wanted: BTreeMap<String, String> = attributes
                        .iter()
                        .filter(|(k, _)| !k.trim().is_empty())
                        .map(|(k, v)| (k.trim().to_string(), v.clone()))
                        .collect();
                    self.store.request(Request::CreateItem {
                        collection: collection.clone(),
                        label: label.clone(),
                        attributes: wanted,
                        secret: Zeroizing::new(secret.as_bytes().to_vec()),
                    });
                    self.saving = 1;
                }
                if !cancel {
                    self.mode = Mode::New {
                        collection,
                        label,
                        secret,
                        attributes,
                    };
                }
            }
            Mode::DeleteItem { path, label } => {
                ui.label(format!("Delete '{}'?", shown(&label, NAME)));
                ui.add_space(8.0);
                let (mut yes, mut no) = (false, false);
                ui.horizontal(|ui| {
                    // (No first, and focused: the default.)
                    let n = ui.button("No");
                    n.request_focus();
                    no = n.clicked();
                    yes = ui.button("Yes").clicked();
                });
                if yes {
                    self.store.request(Request::DeleteItem(path));
                    self.selected = None;
                    self.shown = None;
                } else if !no {
                    self.mode = Mode::DeleteItem { path, label };
                }
            }
            Mode::NewFolder { mut label } => {
                ui.label(RichText::new("NEW FOLDER").strong().color(p.accent));
                ui.add_space(6.0);
                field(ui, &mut label, "Folder name", "name_", false);
                let (create, cancel) = self.save_buttons(ui, !label.trim().is_empty());
                if cancel {
                    // (An answer still to come no longer closes a form.)
                    self.saving = 0;
                }
                if create {
                    // (alephd confirms it in its own prompt window.)
                    self.store
                        .request(Request::CreateCollection(label.trim().to_string()));
                    self.saving = 1;
                }
                if !cancel {
                    self.mode = Mode::NewFolder { label };
                }
            }
        }
    }

    /// SAVE (enabled when `ready` and nothing is being saved) and CANCEL;
    /// "SAVING…" while a save is answered.
    fn save_buttons(&self, ui: &mut egui::Ui, ready: bool) -> (bool, bool) {
        let (mut save, mut cancel) = (false, false);
        ui.horizontal(|ui| {
            save = ui
                .add_enabled(ready && self.saving == 0, Button::new("SAVE"))
                .clicked();
            cancel = ui.button("CANCEL").clicked();
            if self.saving > 0 {
                ui.label("SAVING…");
            }
        });
        (save, cancel)
    }

    fn browse(&mut self, ui: &mut egui::Ui, p: &Palette, collections: &[Collection], now: Instant) {
        match self.selected.clone() {
            None => {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("SELECT AN ENTRY").color(p.muted));
                });
            }
            Some(Selection::Collection(path)) => {
                let Some(c) = collections.iter().find(|c| c.path == path) else {
                    return;
                };
                ui.heading(shown(&c.label, 200));
                ui.label(format!(
                    "{} item(s){}",
                    c.items.len(),
                    if c.is_default { " · default" } else { "" }
                ));
                ui.add_space(8.0);
                if ui.button("DELETE FOLDER").clicked() {
                    // (alephd asks, in its own prompt window.)
                    self.store.request(Request::DeleteCollection(path));
                }
            }
            Some(Selection::Item(path)) => {
                let Some(it) = self.item(&path).cloned() else {
                    return;
                };
                ui.heading(shown(&it.label, 200));
                ui.add_space(6.0);
                egui::Grid::new("attributes")
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        for (k, v) in &it.attributes {
                            ui.label(
                                RichText::new(shown(k, NAME))
                                    .color(p.foreground.gamma_multiply(0.7)),
                            );
                            ui.label(shown(v, 200));
                            ui.end_row();
                        }
                        ui.label(RichText::new("created").color(p.foreground.gamma_multiply(0.7)));
                        ui.label(date(it.created));
                        ui.end_row();
                        ui.label(RichText::new("modified").color(p.foreground.gamma_multiply(0.7)));
                        ui.label(date(it.modified));
                        ui.end_row();
                    });
                ui.add_space(8.0);
                let showing = self.shown.as_ref().filter(|(p, _)| *p == path);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("secret").color(p.foreground.gamma_multiply(0.7)));
                    match showing.map(|(_, s)| s) {
                        // (Below, where it has the pane's width.)
                        Some(Shown::Text(_)) => {}
                        Some(Shown::Binary(n)) => {
                            ui.label(format!("binary secret, {n} bytes"));
                        }
                        None => {
                            ui.label("•••••••");
                        }
                    }
                });
                if let Some(Shown::Text(t)) = showing.map(|(_, s)| s) {
                    // Unwrapped, and scrolled both ways when it does not fit
                    // (a long token, a JSON document).
                    egui::ScrollArea::both()
                        .id_salt("secret")
                        .max_height(SECRET_HEIGHT)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(RichText::new(t.as_str()).monospace()).extend(),
                            );
                        });
                }
                ui.add_space(6.0);
                let (mut show, mut hide, mut copy, mut edit, mut delete) =
                    (false, false, false, false, false);
                ui.horizontal(|ui| {
                    if showing.is_some() {
                        hide = ui.button("HIDE").clicked();
                    } else {
                        show = ui.button("SHOW").clicked();
                    }
                    copy = ui.button("COPY").clicked();
                    edit = ui.button("EDIT").clicked();
                    delete = ui.button("DELETE").clicked();
                });
                if show {
                    self.want(&ui.ctx().clone(), path.clone(), Want::Show, now);
                }
                if hide {
                    self.shown = None;
                    // (A secret still coming is not shown after HIDE.)
                    self.awaiting = None;
                }
                if copy {
                    self.want(&ui.ctx().clone(), path.clone(), Want::Copy, now);
                }
                if edit {
                    // (A new form: an answer still owed to another no longer closes it.)
                    self.saving = 0;
                    self.shown = None;
                    self.mode = Mode::Edit {
                        path: path.clone(),
                        label: it.label.clone(),
                        secret: None,
                        original: None,
                    };
                }
                if delete {
                    self.shown = None;
                    self.mode = Mode::DeleteItem {
                        path,
                        label: it.label,
                    };
                }
            }
        }
    }
}

/// A single-line field with no visible label: `hint` inside it while
/// empty, `name` for screen readers (and the tests).
fn field(ui: &mut egui::Ui, text: &mut String, name: &str, hint: &str, masked: bool) {
    let r = ui.add(
        TextEdit::singleline(text)
            .password(masked)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
    let name = name.to_string();
    ui.ctx()
        .accesskit_node_builder(r.id, move |n| n.set_label(name));
}

/// Seconds since the epoch as a UTC date (0: unknown).
pub fn date(secs: u64) -> String {
    if secs == 0 {
        return "unknown".into();
    }
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

impl<S: Store, B: Backend> eframe::App for Manager<S, B> {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
    }
}

#[cfg(test)]
mod tests {
    use super::date;

    #[test]
    fn dates_are_utc_calendar_days() {
        assert_eq!(date(0), "unknown");
        assert_eq!(date(1), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_790_553_600), "2026-09-28");
    }
}
