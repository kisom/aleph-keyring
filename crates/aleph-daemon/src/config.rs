//! `~/.config/aleph/config.toml` (spec §6 "Lock policy").
//!
//! Unknown keys are errors, so a typo is reported rather than silently
//! ignored. `alephctl config get|set` addresses values as `section.key`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub lock: LockConfig,
    pub prompt: PromptConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LockConfig {
    /// Lock before sleep: suspend and hibernate alike (logind does not say
    /// which is coming). Off, the master key can reach a hibernation image.
    pub on_suspend: bool,
    /// Lock when the session is locked (logind `Session.Lock`).
    pub on_screen_lock: bool,
    /// Seconds without secret access before locking; 0 disables.
    pub idle_timeout: u64,
}

impl Default for LockConfig {
    fn default() -> Self {
        Self {
            on_suspend: true,
            on_screen_lock: true,
            idle_timeout: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PromptConfig {
    /// The prompter program, run as `<program> prompt`.
    pub program: String,
    /// Seconds a question may stay unanswered. (Not the Secret Service
    /// unlock window's choice of method: that one waits for the person.)
    pub timeout: u64,
}

impl Default for PromptConfig {
    fn default() -> Self {
        Self {
            program: "aleph-gui".into(),
            timeout: 300,
        }
    }
}

/// The longest prompt timeout accepted (a day): larger values would
/// overflow deadline arithmetic.
pub const MAX_PROMPT_TIMEOUT: u64 = 86_400;

/// The keys `get`/`set` accept.
pub const KEYS: &[&str] = &[
    "lock.on_suspend",
    "lock.on_screen_lock",
    "lock.idle_timeout",
    "prompt.program",
    "prompt.timeout",
];

impl Config {
    /// The file's configuration, or the defaults if it does not exist.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let c: Self = toml::from_str(&text).map_err(|e| Error::Config(e.to_string()))?;
                if c.prompt.timeout == 0 || c.prompt.timeout > MAX_PROMPT_TIMEOUT {
                    return Err(Error::Config(format!(
                        "prompt.timeout must be 1 to {MAX_PROMPT_TIMEOUT} seconds"
                    )));
                }
                Ok(c)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// For startup: the file's configuration, or the defaults and a
    /// warning if it cannot be used. A bad setting must not keep the
    /// keyring from starting.
    pub fn load_or_default(path: &Path) -> (Self, Option<String>) {
        match Self::load(path) {
            Ok(c) => (c, None),
            Err(e) => (
                Self::default(),
                Some(format!(
                    "ignoring {}: {e}; using the defaults",
                    path.display()
                )),
            ),
        }
    }

    /// Write atomically (temp file, then rename), creating the directory.
    pub fn save(&self, path: &Path) -> Result<()> {
        let dir = path
            .parent()
            .ok_or(Error::Config("configuration path has no directory".into()))?;
        std::fs::create_dir_all(dir)?;
        let text = toml::to_string(self).map_err(|e| Error::Config(e.to_string()))?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<String> {
        Ok(match key {
            "lock.on_suspend" => self.lock.on_suspend.to_string(),
            "lock.on_screen_lock" => self.lock.on_screen_lock.to_string(),
            "lock.idle_timeout" => self.lock.idle_timeout.to_string(),
            "prompt.program" => self.prompt.program.clone(),
            "prompt.timeout" => self.prompt.timeout.to_string(),
            _ => return Err(unknown(key)),
        })
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let bad = |what: &str| Error::Config(format!("{key} must be {what}, not {value:?}"));
        match key {
            "lock.on_suspend" => {
                self.lock.on_suspend = value.parse().map_err(|_| bad("true or false"))?
            }
            "lock.on_screen_lock" => {
                self.lock.on_screen_lock = value.parse().map_err(|_| bad("true or false"))?;
            }
            "lock.idle_timeout" => {
                self.lock.idle_timeout = value.parse().map_err(|_| bad("a number of seconds"))?;
            }
            "prompt.program" if value.trim().is_empty() => return Err(bad("a program name")),
            "prompt.program" => self.prompt.program = value.to_string(),
            "prompt.timeout" => match value.parse() {
                Ok(n @ 1..=MAX_PROMPT_TIMEOUT) => self.prompt.timeout = n,
                _ => return Err(bad("1 to 86400 seconds")),
            },
            _ => return Err(unknown(key)),
        }
        Ok(())
    }

    /// Every pair, or none: on an error `self` is unchanged. An empty map
    /// is an error (there is nothing to confirm).
    pub fn set_many(&mut self, values: &BTreeMap<String, String>) -> Result<()> {
        if values.is_empty() {
            return Err(Error::Config("no settings to change".into()));
        }
        let mut next = self.clone();
        for (key, value) in values {
            next.set(key, value)?;
        }
        *self = next;
        Ok(())
    }
}

fn unknown(key: &str) -> Error {
    Error::Config(format!(
        "unknown key {key:?}; known keys: {}",
        KEYS.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_many_applies_all_or_none() {
        use std::collections::BTreeMap;
        let pairs = |p: &[(&str, &str)]| -> BTreeMap<String, String> {
            p.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let mut c = Config::default();
        let before = c.clone();
        // One bad value: nothing changes, not even the good pair.
        assert!(
            c.set_many(&pairs(&[
                ("lock.idle_timeout", "900"),
                ("prompt.timeout", "0")
            ]))
            .is_err()
        );
        assert_eq!(c, before);
        // An unknown key too, and an empty map.
        assert!(c.set_many(&pairs(&[("lock.idel", "1")])).is_err());
        assert!(c.set_many(&BTreeMap::new()).is_err());
        assert_eq!(c, before);
        c.set_many(&pairs(&[
            ("lock.idle_timeout", "900"),
            ("prompt.timeout", "600"),
            ("lock.on_suspend", "false"),
        ]))
        .unwrap();
        assert_eq!(
            (c.lock.idle_timeout, c.prompt.timeout, c.lock.on_suspend),
            (900, 600, false)
        );
    }

    #[test]
    fn a_missing_file_gives_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::load(&dir.path().join("none.toml")).unwrap();
        assert_eq!(c, Config::default());
        assert!(c.lock.on_suspend && c.lock.on_screen_lock);
        assert_eq!(c.lock.idle_timeout, 0);
    }

    #[test]
    fn set_get_and_save_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aleph/config.toml");
        let mut c = Config::default();
        c.set("lock.idle_timeout", "900").unwrap();
        c.set("lock.on_suspend", "false").unwrap();
        c.save(&path).unwrap();
        let back = Config::load(&path).unwrap();
        assert_eq!(back.get("lock.idle_timeout").unwrap(), "900");
        assert_eq!(back.get("lock.on_suspend").unwrap(), "false");
        for key in KEYS {
            back.get(key).unwrap();
        }
    }

    #[test]
    fn bad_keys_values_and_files_are_errors() {
        let mut c = Config::default();
        assert!(c.set("lock.idle", "1").is_err());
        assert!(c.set("lock.on_suspend", "yes").is_err());
        assert!(c.set("prompt.timeout", "0").is_err());
        assert!(c.set("prompt.timeout", "86401").is_err());
        assert!(c.set("prompt.timeout", &u64::MAX.to_string()).is_err());
        assert!(c.get("nope").is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "[lock]\non_suspnd = false\n").unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::write(&path, "[prompt]\ntimeout = 18446744073709551615\n").unwrap();
        assert!(Config::load(&path).is_err());
    }

    /// Final-review minor 8: at startup a broken file means the defaults
    /// and a warning naming the file, never a daemon that will not start
    /// (every Secret Service client would lose its keyring).
    #[test]
    fn at_startup_a_broken_file_falls_back_to_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "[lock]\non_suspnd = false\n").unwrap();
        let (c, warning) = Config::load_or_default(&path);
        assert_eq!(c, Config::default());
        let warning = warning.unwrap();
        assert!(warning.contains("c.toml"), "{warning}");
        std::fs::write(&path, "[lock]\nidle_timeout = 60\n").unwrap();
        let (c, warning) = Config::load_or_default(&path);
        assert_eq!((c.lock.idle_timeout, warning), (60, None));
    }
}
