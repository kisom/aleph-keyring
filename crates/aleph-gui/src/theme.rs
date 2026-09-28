//! Colors and fonts (spec §7 "Theme"): the current Omarchy theme where
//! there is one (`~/.local/state/omarchy/current/theme/colors.toml`,
//! followed live), else Aleph neon; and the optional scanline overlay.

use std::path::{Path, PathBuf};

use egui::{Color32, Stroke, Visuals};
use serde::Deserialize;

use crate::settings::{Settings, ThemeChoice};

#[derive(Clone, Debug, PartialEq)]
pub struct Palette {
    pub dark: bool,
    pub background: Color32,
    /// Input fields.
    pub field: Color32,
    pub foreground: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub selection: Color32,
    pub error: Color32,
    pub warning: Color32,
    /// Everything in monospace (Aleph neon).
    pub monospace: bool,
}

/// Aleph neon: near-black, neon cyan and magenta, monospace.
pub fn neon() -> Palette {
    Palette {
        dark: true,
        background: Color32::from_rgb(0x0a, 0x0a, 0x12),
        field: Color32::from_rgb(0x04, 0x04, 0x08),
        foreground: Color32::from_rgb(0xd6, 0xf8, 0xff),
        muted: Color32::from_rgb(0x5a, 0x6a, 0x80),
        accent: Color32::from_rgb(0x00, 0xf0, 0xff),
        selection: Color32::from_rgb(0xff, 0x2b, 0xd6),
        error: Color32::from_rgb(0xff, 0x38, 0x60),
        warning: Color32::from_rgb(0xff, 0xd2, 0x3f),
        monospace: true,
    }
}

/// Omarchy's theme file under `home`.
pub fn omarchy_colors(home: &Path) -> PathBuf {
    home.join(".local/state/omarchy/current/theme/colors.toml")
}

/// The directory to watch for theme switches (Omarchy rewrites the
/// theme's files in place).
pub fn omarchy_current(home: &Path) -> PathBuf {
    home.join(".local/state/omarchy/current")
}

#[derive(Deserialize)]
struct ColorsToml {
    mode: Option<String>,
    background: String,
    foreground: String,
    accent: String,
    dark_background: Option<String>,
    selection: Option<String>,
    muted: Option<String>,
    red: Option<String>,
    yellow: Option<String>,
}

fn hex(s: &str) -> Result<Color32, String> {
    let h = s.trim().strip_prefix('#').unwrap_or(s.trim());
    if h.len() != 6 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("not a #rrggbb color: {s:?}"));
    }
    let v = u32::from_str_radix(h, 16).map_err(|e| e.to_string())?;
    Ok(Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8))
}

/// An Omarchy `colors.toml`: `background`, `foreground`, and `accent` are
/// required; the rest fall back to blends of those. Other keys (the ANSI
/// colors Omarchy also lists) are ignored.
pub fn parse_colors(text: &str) -> Result<Palette, String> {
    let c: ColorsToml = toml::from_str(text).map_err(|e| e.to_string())?;
    let background = hex(&c.background)?;
    let foreground = hex(&c.foreground)?;
    let accent = hex(&c.accent)?;
    let or = |v: &Option<String>, fallback: Color32| -> Result<Color32, String> {
        v.as_deref().map(hex).unwrap_or(Ok(fallback))
    };
    let dark = c.mode.as_deref() != Some("light");
    let field = or(&c.dark_background, blend(background, Color32::BLACK, 0.25))?;
    Ok(Palette {
        dark,
        background,
        field,
        foreground,
        muted: or(&c.muted, blend(foreground, background, 0.5))?,
        accent,
        selection: or(&c.selection, blend(accent, background, 0.5))?,
        error: or(&c.red, Color32::from_rgb(0xe0, 0x6c, 0x75))?,
        warning: or(&c.yellow, Color32::from_rgb(0xe5, 0xc0, 0x7b))?,
        monospace: false,
    })
}

fn blend(a: Color32, b: Color32, t: f32) -> Color32 {
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

/// The palette the settings ask for: with `auto`, Omarchy's when its file
/// reads, Aleph neon otherwise.
pub fn resolve(settings: &Settings, home: Option<&Path>) -> Palette {
    match (settings.theme, home) {
        (ThemeChoice::Auto, Some(home)) => std::fs::read_to_string(omarchy_colors(home))
            .ok()
            .and_then(|t| parse_colors(&t).ok())
            .unwrap_or_else(neon),
        _ => neon(),
    }
}

/// egui's visuals for a palette.
pub fn visuals(p: &Palette) -> Visuals {
    let mut v = if p.dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    v.override_text_color = Some(p.foreground);
    v.panel_fill = p.background;
    v.window_fill = p.background;
    v.extreme_bg_color = p.field;
    v.text_edit_bg_color = Some(p.field);
    v.faint_bg_color = p.field;
    v.hyperlink_color = p.accent;
    v.error_fg_color = p.error;
    v.warn_fg_color = p.warning;
    v.selection.bg_fill = p.selection;
    v.selection.stroke = Stroke::new(1.0, p.foreground);
    let w = &mut v.widgets;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.muted);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.foreground);
    for state in [&mut w.inactive, &mut w.hovered, &mut w.active, &mut w.open] {
        state.fg_stroke = Stroke::new(1.0, p.foreground);
    }
    w.inactive.bg_fill = p.field;
    w.inactive.weak_bg_fill = p.field;
    w.inactive.bg_stroke = Stroke::new(1.0, p.muted);
    w.hovered.bg_fill = p.field;
    w.hovered.weak_bg_fill = p.field;
    w.hovered.bg_stroke = Stroke::new(1.0, p.accent);
    w.active.bg_fill = p.selection;
    w.active.weak_bg_fill = p.selection;
    w.active.bg_stroke = Stroke::new(1.5, p.accent);
    v
}

/// Apply a palette: visuals, and monospace everywhere for Aleph neon.
pub fn apply(ctx: &egui::Context, p: &Palette) {
    ctx.set_visuals(visuals(p));
    let mut fonts = egui::FontDefinitions::default();
    if p.monospace {
        let mono = fonts.families[&egui::FontFamily::Monospace].clone();
        fonts.families.insert(egui::FontFamily::Proportional, mono);
    }
    ctx.set_fonts(fonts);
}

/// Faint horizontal lines over everything, every third pixel. Static:
/// nothing moves.
pub fn paint_scanlines(ctx: &egui::Context, p: &Palette) {
    let painter = ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::new("aleph-scanlines"),
    ));
    let rect = ctx.content_rect();
    let shade = if p.dark {
        Color32::from_black_alpha(60)
    } else {
        Color32::from_black_alpha(18)
    };
    let mut y = rect.top();
    while y < rect.bottom() {
        painter.hline(rect.x_range(), y, Stroke::new(1.0, shade));
        y += 3.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NORD: &str = include_str!("../tests/fixtures/colors.toml");

    #[test]
    fn an_omarchy_theme_file_maps_to_a_palette() {
        let p = parse_colors(NORD).unwrap();
        assert!(p.dark);
        assert_eq!(p.background, Color32::from_rgb(0x2e, 0x34, 0x40));
        assert_eq!(p.accent, Color32::from_rgb(0x81, 0xa1, 0xc1));
        assert_eq!(p.field, Color32::from_rgb(0x22, 0x27, 0x30));
        assert_eq!(p.error, Color32::from_rgb(0xbf, 0x61, 0x6a));
        assert!(!p.monospace);
    }

    #[test]
    fn only_the_three_base_colors_are_required() {
        let p = parse_colors(
            "mode = \"light\"\nbackground = \"#ffffff\"\nforeground = \"#000000\"\naccent = \"#0000ff\"\n",
        )
        .unwrap();
        assert!(!p.dark);
        assert_eq!(p.muted, Color32::from_rgb(0x80, 0x80, 0x80));
        assert!(
            parse_colors("background = \"#fff\"\nforeground = \"#000000\"\naccent = \"#0000ff\"\n")
                .is_err()
        );
        assert!(parse_colors("foreground = \"#000000\"\n").is_err());
    }

    #[test]
    fn auto_follows_omarchy_and_falls_back_to_neon() {
        let home = tempfile::tempdir().unwrap();
        let auto = Settings::default();
        assert_eq!(resolve(&auto, Some(home.path())), neon());
        let file = omarchy_colors(home.path());
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, NORD).unwrap();
        assert_eq!(
            resolve(&auto, Some(home.path())),
            parse_colors(NORD).unwrap()
        );
        let neon_setting = Settings {
            theme: ThemeChoice::Neon,
            ..Settings::default()
        };
        assert_eq!(resolve(&neon_setting, Some(home.path())), neon());
        // A broken file is not fatal.
        std::fs::write(&file, "background = 3").unwrap();
        assert_eq!(resolve(&auto, Some(home.path())), neon());
    }
}
