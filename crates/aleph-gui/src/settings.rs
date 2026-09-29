//! The GUI's own settings, `~/.config/aleph/gui.toml` (spec §7 "Theme";
//! the settings spec for the reveal hold and for writing the file).
//!
//! A file of their own: alephd's `config.toml` refuses unknown keys, and
//! alephd has no use for these.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    /// The current Omarchy theme where there is one, else Aleph neon.
    #[default]
    Auto,
    /// Aleph neon everywhere.
    Neon,
}

/// The longest a confirmation may hold, in seconds (an hour).
pub const MAX_REVEAL_HOLD: u64 = 3600;
/// How long one holds unless the file says otherwise (5 minutes).
pub const DEFAULT_REVEAL_HOLD: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    pub theme: ThemeChoice,
    /// The scanline overlay (off anyway when reduced motion is asked for).
    pub scanlines: bool,
    /// Seconds a confirmation lets secrets be shown without another; 0 is
    /// every time. A larger value in the file is read as
    /// [`MAX_REVEAL_HOLD`].
    #[serde(deserialize_with = "capped_hold")]
    pub reveal_hold: u64,
}

fn capped_hold<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    Ok(u64::deserialize(d)?.min(MAX_REVEAL_HOLD))
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::Auto,
            scanlines: true,
            reveal_hold: DEFAULT_REVEAL_HOLD,
        }
    }
}

impl Settings {
    /// The file's settings; the defaults if it is missing, and (with a
    /// warning) if it is unreadable: a prompt must still open.
    pub fn load(path: &Path) -> (Self, Option<String>) {
        match Self::read_strict(path) {
            Ok(s) => (s, None),
            Err(e) => (Self::default(), Some(format!("{e} (using the defaults)"))),
        }
    }

    /// The file's settings, the defaults if it does not exist, and an
    /// error naming the file if it cannot be read as settings (no
    /// defaults then: a DISPLAY change starts from what is in the file).
    pub fn read_strict(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Write the settings. A file that does not read as settings is never
    /// overwritten (the owner fixes it, or resets it). Comments in the
    /// file are lost: the whole file is rewritten.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        Self::read_strict(path)?;
        self.write(path)
    }

    /// The defaults, over whatever is there (the broken-file button).
    pub fn reset(path: &Path) -> Result<(), String> {
        Self::default().write(path)
    }

    /// Atomically: a temp file (this process's own, on disk before the
    /// rename), then a rename; the directory is created. A temp file left
    /// by a failure is removed.
    fn write(&self, path: &Path) -> Result<(), String> {
        use std::io::Write;
        let at = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
        let dir = path.parent().ok_or_else(|| at(&"no directory"))?;
        std::fs::create_dir_all(dir).map_err(|e| at(&e))?;
        let text = toml::to_string(self).map_err(|e| at(&e))?;
        let tmp = path.with_extension(format!("toml.{}.tmp", std::process::id()));
        let written = std::fs::File::create(&tmp).and_then(|mut f| {
            f.write_all(text.as_bytes())?;
            f.sync_all()
        });
        let done = written.and_then(|()| std::fs::rename(&tmp, path));
        if done.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        done.map_err(|e| at(&e))
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
                scanlines: false,
                ..Settings::default()
            }
        );
        std::fs::write(&file, "scanline = false\n").unwrap();
        let (s, warning) = Settings::load(&file);
        assert_eq!(s, Settings::default());
        assert!(warning.unwrap().contains("scanline"));
    }

    #[test]
    fn the_reveal_hold_defaults_to_five_minutes_and_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gui.toml");
        assert_eq!(Settings::load(&file).0.reveal_hold, 300);
        for (text, want) in [
            ("reveal_hold = 900\n", 900),
            ("reveal_hold = 0\n", 0),
            ("reveal_hold = 3600\n", 3600),
            // (A larger value, hand-edited, is read as the largest.)
            ("reveal_hold = 99999\n", 3600),
            ("scanlines = false\n", 300),
        ] {
            std::fs::write(&file, text).unwrap();
            assert_eq!(Settings::load(&file).0.reveal_hold, want, "{text}");
        }
        std::fs::write(&file, "reveal_hold = -1\n").unwrap();
        assert!(Settings::load(&file).1.is_some());
    }

    #[test]
    fn saved_settings_read_back_and_the_directory_is_made() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("aleph/gui.toml");
        let s = Settings {
            theme: ThemeChoice::Neon,
            scanlines: false,
            reveal_hold: 900,
        };
        s.save(&file).unwrap();
        assert_eq!(Settings::load(&file), (s.clone(), None));
        // Saving again over a good file is fine.
        Settings {
            reveal_hold: 0,
            ..s
        }
        .save(&file)
        .unwrap();
        assert_eq!(Settings::load(&file).0.reveal_hold, 0);
    }

    /// (Review Focus 4.) A file that does not read as settings is the
    /// owner's to fix: saving never overwrites it.
    #[test]
    fn a_broken_file_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gui.toml");
        std::fs::write(&file, "scanline = false\n# my note\n").unwrap();
        let e = Settings::default().save(&file).unwrap_err();
        assert!(e.contains("gui.toml") && e.contains("scanline"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "scanline = false\n# my note\n"
        );
        // Reset is the way out: it writes the defaults.
        Settings::reset(&file).unwrap();
        assert_eq!(Settings::load(&file), (Settings::default(), None));
    }

    /// A write whose rename fails (the file's place is taken by a
    /// directory) says so and leaves no temp file behind.
    #[test]
    fn a_failed_rename_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gui.toml");
        std::fs::create_dir(&file).unwrap();
        std::fs::write(file.join("inside"), b"x").unwrap();
        assert!(Settings::reset(&file).is_err());
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn only_false_turns_animations_off() {
        assert!(animations_off("false\n"));
        assert!(!animations_off("true\n"));
        assert!(!animations_off(""));
    }
}
