//! The prompt window: alephd's messages in, the person's answers out.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use aleph_prompt_proto::FromPrompter;

use crate::conversation::Action;
use crate::link::{self, Event};
use crate::screens::PromptUi;
use crate::settings::Settings;
use crate::theme;

pub struct PromptApp {
    pub ui: PromptUi,
    stream: UnixStream,
    events: Receiver<Event>,
    settings: Settings,
    home: Option<PathBuf>,
    /// Scanlines drawn (the setting, unless reduced motion is asked for).
    scanlines: bool,
    /// Set by the theme watcher.
    watch: Option<theme::Watch>,
    /// The window was told to close.
    pub closed: bool,
    /// How long keys are ignored after a screen appears, so the end of
    /// something typed into another window (and its Enter) never becomes
    /// an answer here.
    pub input_guard: Duration,
    /// How long a closing message stays up (the window holds the keyboard
    /// while it is open): a failure's, and a note after success.
    pub message_for: Duration,
    pub note_for: Duration,
    /// When the current screen appeared.
    shown_at: Instant,
    /// When a closing message closes itself.
    close_at: Option<Instant>,
    /// The window size last asked for.
    size: [f32; 2],
    /// Drawn inside another window (the manager's confirmation): closing
    /// ends the conversation, never the window, which it never resizes.
    pub embedded: bool,
}

/// Keys ignored after a screen appears.
pub const INPUT_GUARD: Duration = Duration::from_millis(400);
/// A closing message's time on screen: a failure's, and a note after
/// success (a pending rotation: it would come with every unlock).
pub const MESSAGE_FOR: Duration = Duration::from_secs(20);
pub const NOTE_FOR: Duration = Duration::from_secs(6);

impl PromptApp {
    pub fn new(
        stream: UnixStream,
        events: Receiver<Event>,
        settings: Settings,
        home: Option<PathBuf>,
        still: bool,
    ) -> Self {
        let palette = theme::resolve(&settings, home.as_deref());
        Self {
            ui: PromptUi::new(palette, still),
            stream,
            events,
            scanlines: settings.scanlines && !still,
            settings,
            home,
            watch: None,
            closed: false,
            input_guard: INPUT_GUARD,
            message_for: MESSAGE_FOR,
            note_for: NOTE_FOR,
            shown_at: Instant::now(),
            close_at: None,
            size: crate::screens::SIZE,
            embedded: false,
        }
    }

    /// Re-theme live when the Omarchy theme changes (spec §7).
    pub fn watch_theme(&mut self, ctx: &egui::Context) {
        self.watch = self
            .home
            .as_deref()
            .and_then(|home| theme::Watch::start(home, ctx));
    }

    fn close(&mut self, ctx: &egui::Context) {
        if !self.closed {
            self.closed = true;
            if !self.embedded {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn reply(&mut self, ctx: &egui::Context, reply: FromPrompter) {
        let cancel = reply == FromPrompter::Cancel {};
        // alephd gone: nothing to answer any more.
        if link::send(&self.stream, &reply).is_err() || cancel {
            self.close(ctx);
        }
    }

    /// One frame: take alephd's messages, draw, send what the person did.
    pub fn frame(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let now = Instant::now();
        if self.watch.as_ref().is_some_and(theme::Watch::changed) {
            self.ui.palette = theme::resolve(&self.settings, self.home.as_deref());
            theme::apply(&ctx, &self.ui.palette);
        }
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Message(msg) => {
                    if let Some(refusal) = self.ui.conversation.receive(msg, now) {
                        self.reply(&ctx, refusal);
                    }
                    self.ui.screen_changed();
                    self.shown_at = now;
                    // (The recovery key's screens need a taller window.)
                    let size = crate::screens::size_for(&self.ui.conversation.screen);
                    if size != self.size && !self.embedded {
                        self.size = size;
                        let size = egui::Vec2::from(size);
                        ctx.send_viewport_cmd(egui::ViewportCommand::MinInnerSize(size));
                        ctx.send_viewport_cmd(egui::ViewportCommand::MaxInnerSize(size));
                        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
                    }
                }
                // alephd is done with us: nothing more to answer. A
                // closing message stays up until it is read.
                Event::Closed => {
                    if !matches!(
                        self.ui.conversation.screen,
                        crate::conversation::Screen::Finished {
                            message: Some(_),
                            ..
                        }
                    ) {
                        self.close(&ctx);
                    }
                }
                // Prompter trouble, not the person's no: close without
                // answering, so the prompt waits (a Cancel would dismiss it).
                Event::Broken(why) => {
                    eprintln!("aleph-gui: {why}");
                    self.close(&ctx);
                }
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.closed && !self.embedded {
            // Closed by the window manager.
            if !self.ui.conversation.finished() {
                let _ = link::send(&self.stream, &FromPrompter::Cancel {});
            }
            self.closed = true;
        }
        match self.ui.conversation.screen {
            crate::conversation::Screen::Finished { message: None, .. } => self.close(&ctx),
            // A closing message closes itself after a while.
            crate::conversation::Screen::Finished {
                ok,
                message: Some(_),
                ..
            } => {
                let stay = if ok { self.note_for } else { self.message_for };
                let at = *self.close_at.get_or_insert(now + stay);
                if now >= at {
                    self.close(&ctx);
                } else {
                    ctx.request_repaint_after(at - now);
                }
            }
            _ => {}
        }
        if self.closed {
            return;
        }
        // (The guard starts again when the window gets the keyboard: it may
        // have opened unfocused, behind the lock screen, say.)
        if ctx.input(|i| {
            i.events
                .iter()
                .any(|e| matches!(e, egui::Event::WindowFocused(true)))
        }) {
            self.shown_at = now;
        }
        if now < self.shown_at + self.input_guard {
            ctx.input_mut(|i| {
                i.events.retain(|e| {
                    !matches!(
                        e,
                        egui::Event::Key { .. }
                            | egui::Event::Text(_)
                            | egui::Event::Paste(_)
                            | egui::Event::Ime(_)
                    )
                })
            });
            ctx.request_repaint_after(self.shown_at + self.input_guard - now);
        }
        let action = self.ui.show(ui, now);
        // (Embedded, the window around it paints them.)
        if self.scanlines && !self.embedded {
            theme::paint_scanlines(&ctx, &self.ui.palette);
        }
        match action {
            Some(Action::Close) => self.close(&ctx),
            Some(action) => {
                if let Some(reply) = self.ui.conversation.act(action, now) {
                    self.reply(&ctx, reply);
                }
            }
            None => {}
        }
    }
}

impl eframe::App for PromptApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
    }
}
