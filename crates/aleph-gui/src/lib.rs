//! `aleph-gui`: the aleph keyring's manager window (`aleph-gui`, the
//! manager spec) and the prompter alephd starts (`aleph-gui prompt`, spec
//! §7).

pub mod app;
pub mod clipboard;
pub mod conversation;
pub mod link;
pub mod manager;
pub mod pretty;
pub mod reauth;
pub mod screens;
pub mod settings;
pub mod store;
pub mod theme;

/// How both windows open. Without vsync: Mesa's Wayland swap waits for the
/// compositor's frame callback, which a window on a hidden workspace never
/// gets, so the first repaint there (a store event, a timer) would block
/// the window's thread, and Hyprland would call it not responding. Neither
/// window animates, so nothing spins without it.
pub fn native_options(viewport: egui::ViewportBuilder) -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport,
        glow_options: eframe::egui_glow::GlowConfiguration {
            vsync: false,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_windows_never_wait_for_a_frame_callback() {
        assert!(
            !super::native_options(egui::ViewportBuilder::default())
                .glow_options
                .vsync
        );
    }
}
