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
    "# Installed by alephctl setup: lock the keyring with the screen.\nalephctl lock\n";

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

/// The window rule the package installs for the prompter (spec §7
/// "Prompter": float, center, pin).
pub const HYPRLAND_RULE_FILE: &str = "/usr/share/aleph/hyprland/aleph-prompt.lua";

/// What setup adds to `hyprland.lua`. Through `pcall`, so a missing file
/// (aleph uninstalled) never breaks Hyprland's configuration.
pub const HYPRLAND_INCLUDE: &str = "\n-- Added by alephctl setup: float aleph's unlock prompt.\n\
     pcall(dofile, \"/usr/share/aleph/hyprland/aleph-prompt.lua\")\n";

/// The include's working line: present, the rule is included (whatever
/// became of the comment above it).
const HYPRLAND_INCLUDE_LINE: &str = "pcall(dofile, \"/usr/share/aleph/hyprland/aleph-prompt.lua\")";

/// The user's Hyprland configuration, if it is the Lua kind (Omarchy's).
pub fn hyprland_config(config_home: &Path) -> Option<PathBuf> {
    let path = config_home.join("hypr/hyprland.lua");
    path.is_file().then_some(path)
}

pub fn hyprland_rule_included(config: &Path) -> bool {
    std::fs::read_to_string(config).is_ok_and(|t| t.contains(HYPRLAND_INCLUDE_LINE))
}

/// Append the include (once), ending the file's last line first if it is
/// unfinished. Appended in place: a symlinked dotfile stays a symlink.
pub fn include_hyprland_rule(config: &Path) -> Result<bool> {
    use std::io::Write;
    let text = std::fs::read_to_string(config).map_err(|e| format!("{}: {e}", config.display()))?;
    if text.contains(HYPRLAND_INCLUDE_LINE) {
        return Ok(false);
    }
    let sep = if text.is_empty() || text.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    std::fs::OpenOptions::new()
        .append(true)
        .open(config)
        .and_then(|mut f| f.write_all(format!("{sep}{HYPRLAND_INCLUDE}").as_bytes()))
        .map_err(|e| format!("{}: {e}", config.display()))?;
    Ok(true)
}

/// Take the include out again (revert), leaving the rest of the file as
/// setup found it (with its last line ended); returns the file's path if
/// the include was there.
pub fn remove_hyprland_rule(config_home: &Path) -> Result<Option<PathBuf>> {
    let Some(config) = hyprland_config(config_home) else {
        return Ok(None);
    };
    let text =
        std::fs::read_to_string(&config).map_err(|e| format!("{}: {e}", config.display()))?;
    let Some(at) = text.find(HYPRLAND_INCLUDE) else {
        return Ok(None);
    };
    let rest = format!("{}{}", &text[..at], &text[at + HYPRLAND_INCLUDE.len()..]);
    // (Written through a symlink, like the append.)
    std::fs::write(&config, rest).map_err(|e| format!("{}: {e}", config.display()))?;
    Ok(Some(config))
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
        eprintln!("alephctl: {w}");
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
    fn the_omarchy_hook_runs_alephctl() {
        // (`aleph` on PATH is TeX's, from texlive-bin.)
        assert!(
            OMARCHY_HOOK.lines().any(|l| l == "alephctl lock"),
            "{OMARCHY_HOOK}"
        );
    }

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

    /// The include goes in once, after what is there, and revert takes out
    /// exactly what setup added.
    #[test]
    fn the_hyprland_include_is_added_once_and_removed_exactly() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(hyprland_config(dir.path()), None);
        assert_eq!(remove_hyprland_rule(dir.path()).unwrap(), None);
        let config = dir.path().join("hypr/hyprland.lua");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        let original = "require(\"hypr.bindings\")\n-- mine\n";
        std::fs::write(&config, original).unwrap();
        assert_eq!(hyprland_config(dir.path()), Some(config.clone()));
        assert!(include_hyprland_rule(&config).unwrap());
        assert!(!include_hyprland_rule(&config).unwrap());
        let text = std::fs::read_to_string(&config).unwrap();
        assert!(text.starts_with(original), "{text}");
        assert_eq!(text.matches(HYPRLAND_INCLUDE).count(), 1);
        assert!(hyprland_rule_included(&config));
        assert_eq!(
            remove_hyprland_rule(dir.path()).unwrap(),
            Some(config.clone())
        );
        assert_eq!(std::fs::read_to_string(&config).unwrap(), original);
        // An unfinished last line is ended, and stays ended.
        std::fs::write(&config, "-- mine").unwrap();
        include_hyprland_rule(&config).unwrap();
        remove_hyprland_rule(dir.path()).unwrap();
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "-- mine\n");
    }

    /// The include is recognized by its `pcall` line: a user who rewords
    /// the comment above it does not get it added again.
    #[test]
    fn an_edited_comment_does_not_add_the_include_again() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("hyprland.lua");
        std::fs::write(
            &config,
            "-- aleph's prompt (my words)\npcall(dofile, \"/usr/share/aleph/hyprland/aleph-prompt.lua\")\n",
        )
        .unwrap();
        assert!(hyprland_rule_included(&config));
        assert!(!include_hyprland_rule(&config).unwrap());
    }

    /// A symlinked configuration (a dotfiles repository) stays a symlink.
    #[test]
    fn a_symlinked_hyprland_config_stays_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("dotfiles.lua");
        std::fs::write(&real, "-- mine\n").unwrap();
        let config = dir.path().join("hypr/hyprland.lua");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, &config).unwrap();
        include_hyprland_rule(&config).unwrap();
        assert!(config.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(
            std::fs::read_to_string(&real)
                .unwrap()
                .contains(HYPRLAND_INCLUDE)
        );
        remove_hyprland_rule(dir.path()).unwrap();
        assert!(config.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "-- mine\n");
    }

    /// The include names the file the package installs, and both are valid
    /// Lua (`luac -p`; Hyprland would refuse the whole configuration).
    #[test]
    fn the_hyprland_files_are_lua() {
        assert!(HYPRLAND_INCLUDE.contains(HYPRLAND_RULE_FILE));
        let dir = tempfile::tempdir().unwrap();
        let include = dir.path().join("include.lua");
        std::fs::write(&include, HYPRLAND_INCLUDE).unwrap();
        let rule = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packaging/hyprland/aleph-prompt.lua"
        );
        for file in [include.as_path(), Path::new(rule)] {
            let out = std::process::Command::new("luac")
                .arg("-p")
                .arg(file)
                .output()
                .expect("luac (Arch: pacman -S lua)");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let text = std::fs::read_to_string(rule).unwrap();
        assert!(text.contains("\"^aleph-prompt$\""), "{text}");
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
