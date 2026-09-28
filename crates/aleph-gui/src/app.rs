//! The prompt window: alephd's messages in, the person's answers out.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    theme_changed: Arc<AtomicBool>,
    _watcher: Option<notify::RecommendedWatcher>,
    /// The window was told to close.
    pub closed: bool,
    /// How long keys are ignored after a screen appears, so the end of
    /// something typed into another window (and its Enter) never becomes
    /// an answer here.
    pub input_guard: Duration,
    /// How long a closing message stays up (the window holds the keyboard
    /// while it is open).
    pub message_for: Duration,
    /// When the current screen appeared.
    shown_at: Instant,
    /// When a closing message closes itself.
    close_at: Option<Instant>,
}

/// Keys ignored after a screen appears.
pub const INPUT_GUARD: Duration = Duration::from_millis(400);
/// A closing message's time on screen.
pub const MESSAGE_FOR: Duration = Duration::from_secs(20);

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
            theme_changed: Arc::default(),
            _watcher: None,
            closed: false,
            input_guard: INPUT_GUARD,
            message_for: MESSAGE_FOR,
            shown_at: Instant::now(),
            close_at: None,
        }
    }

    /// Re-theme live when the Omarchy theme changes (spec §7).
    pub fn watch_theme(&mut self, ctx: &egui::Context) {
        use notify::Watcher;
        let Some(home) = &self.home else { return };
        let flag = self.theme_changed.clone();
        let ctx = ctx.clone();
        let watcher = notify::recommended_watcher(move |_: notify::Result<notify::Event>| {
            flag.store(true, Ordering::SeqCst);
            ctx.request_repaint();
        });
        if let Ok(mut w) = watcher
            && w.watch(
                &theme::omarchy_current(home),
                notify::RecursiveMode::Recursive,
            )
            .is_ok()
        {
            self._watcher = Some(w);
        }
    }

    fn close(&mut self, ctx: &egui::Context) {
        if !self.closed {
            self.closed = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
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
        if self.theme_changed.swap(false, Ordering::SeqCst) {
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
                Event::Broken(why) => {
                    eprintln!("aleph-gui: {why}");
                    self.reply(&ctx, FromPrompter::Cancel {});
                }
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.closed {
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
                message: Some(_), ..
            } => {
                let at = *self.close_at.get_or_insert(now + self.message_for);
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
        if now < self.shown_at + self.input_guard {
            ctx.input_mut(|i| {
                i.events.retain(|e| {
                    !matches!(
                        e,
                        egui::Event::Key { .. } | egui::Event::Text(_) | egui::Event::Paste(_)
                    )
                })
            });
            ctx.request_repaint_after(self.shown_at + self.input_guard - now);
        }
        let action = self.ui.show(ui, now);
        if self.scanlines {
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
