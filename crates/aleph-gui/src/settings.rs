//! The GUI's own settings, `~/.config/aleph/gui.toml` (spec §7 "Theme").
//!
//! A file of their own: alephd's `config.toml` refuses unknown keys, and
//! alephd has no use for these.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    /// The current Omarchy theme where there is one, else Aleph neon.
    #[default]
    Auto,
    /// Aleph neon everywhere.
    Neon,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub theme: ThemeChoice,
    /// The scanline overlay (off anyway when reduced motion is asked for).
    pub scanlines: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::Auto,
            scanlines: true,
        }
    }
}

impl Settings {
    /// The file's settings; the defaults if it is missing, and (with a
    /// warning) if it is unreadable: a prompt must still open.
    pub fn load(path: &Path) -> (Self, Option<String>) {
        match std::fs::read_to_string(path) {
            Ok(text) => match toml::from_str(&text) {
                Ok(s) => (s, None),
                Err(e) => (
                    Self::default(),
                    Some(format!("{}: {e} (using the defaults)", path.display())),
                ),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Self::default(), None),
            Err(e) => (
                Self::default(),
                Some(format!("{}: {e} (using the defaults)", path.display())),
            ),
        }
    }
}

/// Where the settings live: `$XDG_CONFIG_HOME/aleph/gui.toml`.
pub fn path(config_home: &Path) -> PathBuf {
    config_home.join("aleph/gui.toml")
}

/// `$XDG_CONFIG_HOME`, or `~/.config`.
pub fn config_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home().map(|h| h.join(".config")))
}

pub fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Whether the desktop asks for reduced motion: GNOME's
/// `enable-animations` setting, which GTK and the portal share, read
/// through `gsettings` (absent: not asked). It gets at most a second: a
/// stuck settings service must not keep the prompt from opening.
pub fn reduced_motion() -> bool {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let Ok(mut child) = std::process::Command::new("gsettings")
        .args(["get", "org.gnome.desktop.interface", "enable-animations"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    let _ = stdout.read_to_string(&mut out);
                }
                return status.success() && animations_off(&out);
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn animations_off(gsettings_output: &str) -> bool {
    gsettings_output.trim() == "false"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            Settings::load(&dir.path().join("gui.toml")),
            (Settings::default(), None)
        );
    }

    #[test]
    fn settings_are_read_and_typos_warned_about() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gui.toml");
        std::fs::write(&file, "theme = \"neon\"\nscanlines = false\n").unwrap();
        assert_eq!(
            Settings::load(&file).0,
            Settings {
                theme: ThemeChoice::Neon,
                scanlines: false
            }
        );
        std::fs::write(&file, "scanline = false\n").unwrap();
        let (s, warning) = Settings::load(&file);
        assert_eq!(s, Settings::default());
        assert!(warning.unwrap().contains("scanline"));
    }

    #[test]
    fn only_false_turns_animations_off() {
        assert!(animations_off("false\n"));
        assert!(!animations_off("true\n"));
        assert!(!animations_off(""));
    }
}
