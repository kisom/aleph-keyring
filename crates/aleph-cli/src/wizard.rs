//! The parts of the setup wizard around the switchover (spec §7 `aleph
//! setup`; DECISIONS.md E5, D9, G1): autologin detection, Omarchy's lock
//! hook, the TPM's lockoutAuth, and running the root side through sudo.

use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, String>;

/// SDDM's configuration, in the order it applies it (later wins).
pub struct SddmConfig {
    /// Directories whose files are read in name order: SDDM's own, then
    /// the administrator's.
    pub dirs: Vec<PathBuf>,
    /// The main file, read last.
    pub main: PathBuf,
}

impl SddmConfig {
    pub fn system() -> Self {
        Self {
            dirs: vec![
                "/usr/lib/sddm/sddm.conf.d".into(),
                "/etc/sddm.conf.d".into(),
            ],
            main: "/etc/sddm.conf".into(),
        }
    }
}

/// The user SDDM logs in automatically, if any (E5: advisory; it only
/// picks the default unlock method and the summary). Every file in the
/// directories counts, not only `*.conf`: SDDM may read them all, so a
/// renamed `autologin.conf.disabled` is not trusted to be off.
pub fn autologin_user(config: &SddmConfig) -> Option<String> {
    let mut files = Vec::new();
    for dir in &config.dirs {
        let mut in_dir: Vec<PathBuf> = std::fs::read_dir(dir)
            .map(|d| {
                d.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_file())
                    .collect()
            })
            .unwrap_or_default();
        in_dir.sort();
        files.extend(in_dir);
    }
    files.push(config.main.clone());
    let mut user = None;
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let mut section = String::new();
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].to_string();
            } else if section == "Autologin"
                && let Some((key, value)) = line.split_once('=')
                && key.trim() == "User"
            {
                user = Some(value.trim().to_string());
            }
        }
    }
    user.filter(|u| !u.is_empty())
}

/// The hook Omarchy's lock runs once it calls `omarchy-hook lock` (G1).
pub const OMARCHY_HOOK: &str =
    "# Installed by aleph setup: lock the keyring with the screen.\naleph lock\n";

fn omarchy_hook(config_home: &Path) -> PathBuf {
    config_home.join("omarchy/hooks/lock.d/aleph")
}

/// Install the lock hook if this is an Omarchy user (`omarchy/` in the
/// configuration directory); returns its path if it was just installed.
pub fn install_omarchy_hook(config_home: &Path) -> Result<Option<PathBuf>> {
    if !config_home.join("omarchy").is_dir() {
        return Ok(None);
    }
    let path = omarchy_hook(config_home);
    if std::fs::read(&path).ok().as_deref() == Some(OMARCHY_HOOK.as_bytes()) {
        return Ok(None);
    }
    let dir = path.parent().expect("has a parent");
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(&path, OMARCHY_HOOK).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(path))
}

/// Remove the hook if it is still ours (revert); returns its path if so.
pub fn remove_omarchy_hook(config_home: &Path) -> Result<Option<PathBuf>> {
    let path = omarchy_hook(config_home);
    if std::fs::read(&path).ok().as_deref() != Some(OMARCHY_HOOK.as_bytes()) {
        return Ok(None);
    }
    std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(path))
}

/// The program that runs the root side (`sudo`; `ALEPH_SUDO` names another,
/// for tests, which must never run the real one).
fn sudo() -> std::ffi::OsString {
    std::env::var_os("ALEPH_SUDO").unwrap_or_else(|| "/usr/bin/sudo".into())
}

/// Run `args` as root through sudo, on the terminal (sudo asks for the
/// password there).
pub fn run_as_root(args: &[&str]) -> Result<()> {
    // Before sudo: running a user-writable binary as root trusts its writer.
    if let Some(w) = crate::system::writable_binary_warning() {
        eprintln!("aleph: {w}");
    }
    let status = std::process::Command::new(sudo())
        .args(args)
        .status()
        .map_err(|e| format!("sudo: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`sudo {}` failed", args.join(" ")))
    }
}

/// A lockoutAuth value: 32 characters of base32 (160 random bits), in
/// groups of four.
pub fn lockout_value() -> Result<String> {
    use std::io::Read;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("randomness: {e}"))?;
    let chars: Vec<char> = bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % 32] as char)
        .collect();
    Ok(chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-"))
}

/// Whether `typed` is the lockout value, however it was grouped or cased.
pub fn lockout_matches(value: &str, typed: &str) -> bool {
    let norm = |s: &str| {
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect::<String>()
    };
    !typed.trim().is_empty() && norm(value) == norm(typed)
}

/// The command that sets lockoutAuth, reading the value on standard input
/// so it never appears in `argv` or shell history (D9).
pub const LOCKOUT_COMMAND: [&str; 4] = ["tpm2_changeauth", "-c", "lockout", "file:-"];

/// Set the TPM's lockoutAuth to `value` through sudo.
pub fn set_lockout_auth(value: &str) -> Result<()> {
    use std::io::Write;
    let mut child = std::process::Command::new(sudo())
        .args(LOCKOUT_COMMAND)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("sudo: {e}"))?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(value.as_bytes())
        .map_err(|e| e.to_string())?;
    let status = child.wait().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("tpm2_changeauth failed (lockoutAuth may already be set)".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path) -> SddmConfig {
        SddmConfig {
            dirs: vec![dir.join("lib"), dir.join("etc")],
            main: dir.join("sddm.conf"),
        }
    }

    /// Later files win; every file in a directory counts (a `.disabled`
    /// one too); an empty user means none.
    #[test]
    fn autologin_follows_sddm_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let c = config(dir.path());
        std::fs::create_dir_all(dir.path().join("lib")).unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        assert_eq!(autologin_user(&c), None);
        std::fs::write(
            dir.path().join("etc/autologin.conf.disabled"),
            "[Autologin]\nUser=kyle\nSession=hyprland\n",
        )
        .unwrap();
        assert_eq!(autologin_user(&c).as_deref(), Some("kyle"));
        std::fs::write(dir.path().join("etc/zz.conf"), "[Autologin]\nUser=\n").unwrap();
        assert_eq!(autologin_user(&c), None);
        std::fs::write(dir.path().join("sddm.conf"), "[Autologin]\nUser = alice\n").unwrap();
        assert_eq!(autologin_user(&c).as_deref(), Some("alice"));
        // Another section's User is not autologin.
        std::fs::write(dir.path().join("sddm.conf"), "[Users]\nUser=bob\n").unwrap();
        assert_eq!(autologin_user(&c), None);
    }

    /// The hook goes in only for Omarchy users, once, and revert removes
    /// it only while it is still ours.
    #[test]
    fn the_omarchy_hook_is_installed_once_and_removed_only_if_ours() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(install_omarchy_hook(dir.path()).unwrap(), None);
        std::fs::create_dir_all(dir.path().join("omarchy")).unwrap();
        let path = install_omarchy_hook(dir.path()).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), OMARCHY_HOOK);
        assert_eq!(install_omarchy_hook(dir.path()).unwrap(), None);
        std::fs::write(&path, "edited\n").unwrap();
        assert_eq!(remove_omarchy_hook(dir.path()).unwrap(), None);
        assert!(path.exists());
        std::fs::write(&path, OMARCHY_HOOK).unwrap();
        assert_eq!(remove_omarchy_hook(dir.path()).unwrap(), Some(path.clone()));
        assert!(!path.exists());
    }

    #[test]
    fn a_lockout_value_matches_however_it_is_typed() {
        let v = "ABCD-EFGH-2345";
        assert!(lockout_matches(v, "abcd efgh 2345"));
        assert!(lockout_matches(v, "ABCDEFGH2345"));
        assert!(!lockout_matches(v, "ABCDEFGH2346"));
    }

    #[test]
    fn a_lockout_value_is_32_base32_characters_in_groups() {
        let v = lockout_value().unwrap();
        assert_eq!(v.len(), 39);
        assert!(v.split('-').all(|g| g.len() == 4));
        assert_ne!(v, lockout_value().unwrap());
    }
}
