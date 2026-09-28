//! The root side of setup: `sudo aleph system apply | verify | revert`
//! (spec §6 "PAM integration"; DECISIONS.md E4–E6).
//!
//! Small on purpose: it reads no user configuration, no D-Bus, and no
//! user-writable paths. Each edit is a pure text transformation of one PAM
//! service, written atomically; `apply` then runs the edited stacks
//! through real Linux-PAM and restores the originals at once if one fails.
//! Everything is recorded in a root-owned manifest, so `revert` undoes
//! exactly that: byte for byte from the `.aleph-orig` backup if the file
//! is still what `apply` wrote, else by the inverse transformation if it
//! applies cleanly, else not at all (with what to remove by hand).

use std::collections::BTreeMap;
use std::ffi::{CString, c_char, c_int, c_void};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, String>;

/// aleph's lines, each with a `-` prefix: a missing module is skipped
/// silently (a missing `include`d file could fail the whole service).
pub const AUTH: &str = "-auth      optional  pam_aleph.so";
pub const SESSION: &str = "-session   optional  pam_aleph.so";
pub const PASSWORD: &str = "-password  optional  pam_aleph.so";

/// The PAM services setup edits (spec §6's table). `system-login`,
/// `system-auth`, `login`, and the rest are never edited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// The graphical login.
    Sddm,
    /// Autologin: only gnome-keyring's lines go (it has no password).
    SddmAutologin,
    /// Omarchy's lock screen.
    LockPassword,
    Passwd,
}

impl Service {
    pub const ALL: [Service; 4] = [
        Service::Sddm,
        Service::SddmAutologin,
        Service::LockPassword,
        Service::Passwd,
    ];

    pub fn file(self) -> &'static str {
        match self {
            Self::Sddm => "sddm",
            Self::SddmAutologin => "sddm-autologin",
            Self::LockPassword => "omarchy-lock-password",
            Self::Passwd => "passwd",
        }
    }

    fn from_file(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.file() == name)
    }
}

/// A line a transformation removed, and the line it followed (for the
/// inverse).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    pub after: Option<String>,
    pub line: String,
}

/// A transformed service file.
#[derive(Debug, PartialEq, Eq)]
pub struct Edit {
    pub text: String,
    pub removed: Vec<Removed>,
}

fn words(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

fn module_is(line: &str, module: &str) -> bool {
    !line.trim_start().starts_with('#')
        && words(line)
            .iter()
            .any(|w| *w == module || w.ends_with(&format!("/{module}")))
}

fn starts(line: &str, prefix: &[&str]) -> bool {
    words(line).starts_with(prefix)
}

/// Insert `ours` after the first line matching `anchor`, unless an
/// equivalent line is already there.
fn insert_after(
    lines: &mut Vec<String>,
    anchor: impl Fn(&str) -> bool,
    ours: &str,
    service: Service,
) -> Result<()> {
    if lines.iter().any(|l| words(l) == words(ours)) {
        return Ok(());
    }
    let at = lines.iter().position(|l| anchor(l)).ok_or_else(|| {
        format!(
            "{}: the expected line is missing; add `{ours}` by hand",
            service.file()
        )
    })?;
    lines.insert(at + 1, ours.to_string());
    Ok(())
}

/// Transform `text` for `service`: idempotent (an applied file comes back
/// unchanged, with nothing removed).
pub fn transform(service: Service, text: &str) -> Result<Edit> {
    let mut lines: Vec<String> = Vec::new();
    let mut removed = Vec::new();
    let drop_gnome = matches!(service, Service::Sddm | Service::SddmAutologin);
    for line in text.lines() {
        if drop_gnome && module_is(line, "pam_gnome_keyring.so") {
            removed.push(Removed {
                after: lines.last().cloned(),
                line: line.to_string(),
            });
        } else {
            lines.push(line.to_string());
        }
    }
    match service {
        Service::Sddm => {
            insert_after(
                &mut lines,
                |l| starts(l, &["auth", "include", "system-login"]),
                AUTH,
                service,
            )?;
            insert_after(
                &mut lines,
                |l| starts(l, &["session", "include", "system-login"]),
                SESSION,
                service,
            )?;
        }
        Service::SddmAutologin => {}
        Service::LockPassword => {
            // After the last auth line (`pam_faillock authsucc`): only a
            // password pam_unix accepted ever reaches aleph.
            if !lines.iter().any(|l| words(l) == words(AUTH)) {
                let last = lines
                    .iter()
                    .rposition(|l| starts(l, &["auth"]) || starts(l, &["-auth"]))
                    .ok_or_else(|| {
                        format!("{}: no auth lines; add `{AUTH}` by hand", service.file())
                    })?;
                lines.insert(last + 1, AUTH.to_string());
            }
        }
        Service::Passwd => insert_after(
            &mut lines,
            |l| starts(l, &["password", "include", "system-auth"]),
            PASSWORD,
            service,
        )?,
    }
    let mut out = lines.join("\n");
    if text.ends_with('\n') || !text.is_empty() {
        out.push('\n');
    }
    Ok(Edit { text: out, removed })
}

/// Undo `transform` on `text`: aleph's lines removed and the removed lines
/// put back after the lines they followed. `None` if that does not apply
/// cleanly (a line to put back no longer has its anchor).
pub fn inverse(text: &str, removed: &[Removed]) -> Option<String> {
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| {
            let w = words(l);
            w != words(AUTH) && w != words(SESSION) && w != words(PASSWORD)
        })
        .map(str::to_string)
        .collect();
    for r in removed {
        if lines.contains(&r.line) {
            continue;
        }
        let at = match &r.after {
            None => 0,
            Some(after) => lines.iter().rposition(|l| l == after)? + 1,
        };
        lines.insert(at, r.line.clone());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    Some(out)
}

/// Where the root side works (tests use a temporary tree and their own
/// uid as the required owner).
pub struct Root {
    /// `/etc/pam.d`.
    pub pam_dir: PathBuf,
    /// `/var/lib/aleph`, holding the manifest.
    pub state_dir: PathBuf,
    /// The owner every edited file must have (root).
    pub owner: u32,
}

impl Root {
    pub fn system() -> Self {
        Self {
            pam_dir: "/etc/pam.d".into(),
            state_dir: "/var/lib/aleph".into(),
            owner: 0,
        }
    }

    fn manifest_path(&self) -> PathBuf {
        self.state_dir.join("manifest.json")
    }

    fn backup(&self, service: Service) -> PathBuf {
        self.pam_dir.join(format!("{}.aleph-orig", service.file()))
    }
}

/// What `apply` did to one file (the manifest's entry).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    /// The file as `apply` wrote it.
    pub applied: String,
    pub removed: Vec<Removed>,
    /// Whether an `.aleph-orig` backup holds the file from before.
    pub backup: bool,
}

/// Everything setup did as root (`/var/lib/aleph/manifest.json`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub files: BTreeMap<String, Applied>,
}

impl Manifest {
    pub fn load(root: &Root) -> Result<Self> {
        match std::fs::read(root.manifest_path()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("the manifest: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", root.manifest_path().display())),
        }
    }

    fn save(&self, root: &Root) -> Result<()> {
        if self.files.is_empty() {
            return match std::fs::remove_file(root.manifest_path()) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            };
        }
        std::fs::create_dir_all(&root.state_dir).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&root.manifest_path(), &bytes, 0o644, None)
    }
}

/// Why a file is left for the user to edit (E6): not a regular file owned
/// by `owner` (a symlink, a NixOS-managed file, ...).
fn not_ordinary(path: &Path, owner: u32) -> Option<String> {
    match std::fs::symlink_metadata(path) {
        Err(e) => Some(format!("{}: {e}", path.display())),
        Ok(m) if m.file_type().is_symlink() => Some(format!("{} is a symlink", path.display())),
        Ok(m) if !m.is_file() => Some(format!("{} is not a regular file", path.display())),
        Ok(m) if m.uid() != owner => {
            Some(format!("{} is not owned by uid {owner}", path.display()))
        }
        Ok(_) => None,
    }
}

/// Write `path` atomically: a temporary file in the same directory, fsync,
/// the given mode and owner, rename, then fsync the directory.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32, owner: Option<(u32, u32)>) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().ok_or("no directory")?;
    let name = path.file_name().ok_or("no file name")?.to_string_lossy();
    let tmp = dir.join(format!(".{name}.aleph-tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| e.to_string())?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(|e| e.to_string())?;
    }
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| e.to_string())
}

/// What `apply` changed, and what it left for the user.
#[derive(Debug, Default)]
pub struct Report {
    pub changed: Vec<Service>,
    /// Files not ordinary, with what to add by hand.
    pub manual: Vec<String>,
}

/// Apply every transformation (E4). Files that are not ordinary put that
/// service in manual mode (E6); missing ones are skipped.
pub fn apply(root: &Root) -> Result<Report> {
    let mut manifest = Manifest::load(root)?;
    let mut report = Report::default();
    // Every transformation first: a service that cannot be transformed (its
    // anchor gone) is left for the user, and nothing half-done is written.
    let mut plans = Vec::new();
    for service in Service::ALL {
        let path = root.pam_dir.join(service.file());
        if !path.exists() && std::fs::symlink_metadata(&path).is_err() {
            continue;
        }
        if let Some(why) = not_ordinary(&path, root.owner) {
            report
                .manual
                .push(format!("{why}: {}", manual_lines(service)));
            continue;
        }
        let current =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        match transform(service, &current) {
            Ok(edit) => plans.push((service, path, current, edit)),
            Err(e) => report.manual.push(e),
        }
    }
    for (service, path, current, edit) in plans {
        let name = service.file().to_string();
        let backup = root.backup(service);
        let known = manifest.files.get(&name).cloned();
        if edit.text == current {
            // Already applied: by an earlier run, by a run cut short before
            // its manifest (then the backup holds the original), or by hand.
            if known.is_none() {
                let (has_backup, removed) = match std::fs::read_to_string(&backup) {
                    Ok(original) => (
                        true,
                        transform(service, &original)
                            .map(|e| e.removed)
                            .unwrap_or_default(),
                    ),
                    Err(_) => (false, Vec::new()),
                };
                manifest.files.insert(
                    name,
                    Applied {
                        applied: current,
                        removed,
                        backup: has_backup,
                    },
                );
                manifest.save(root)?;
            }
            continue;
        }
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let mode = meta.mode() & 0o7777;
        let owner = Some((meta.uid(), meta.gid()));
        // With no record of this file, a backup lying there is stale: the
        // backup is the file as it is now.
        if known.is_none() || !backup.exists() {
            write_atomic(&backup, current.as_bytes(), mode, owner)?;
        }
        let removed = match known {
            // (A re-run keeps what the first run removed.)
            Some(prev) if edit.removed.is_empty() => prev.removed,
            _ => edit.removed,
        };
        // Recorded before the file is replaced: a crash in between leaves a
        // record revert can work from.
        manifest.files.insert(
            name,
            Applied {
                applied: edit.text.clone(),
                removed,
                backup: true,
            },
        );
        manifest.save(root)?;
        write_atomic(&path, edit.text.as_bytes(), mode, owner)?;
        report.changed.push(service);
    }
    Ok(report)
}

/// Apply, then check the login and lock screen with `check` (real
/// Linux-PAM: [`verify`]) whenever anything is recorded, a re-run after an
/// interrupted check included; a failure puts every recorded file back from
/// its backup.
pub fn apply_checked(
    root: &Root,
    user: &str,
    password: &str,
    check: impl Fn(&Root, &str, &str) -> Result<()>,
) -> Result<Report> {
    let report = apply(root)?;
    let manifest = Manifest::load(root)?;
    if manifest.files.is_empty() {
        return Ok(report);
    }
    if let Err(e) = check(root, user, password) {
        let recorded: Vec<Service> = manifest
            .files
            .iter()
            .filter(|(_, a)| a.backup)
            .filter_map(|(name, _)| Service::from_file(name))
            .collect();
        roll_back(root, &recorded)?;
        return Err(format!(
            "the check failed ({e}); the PAM changes were undone"
        ));
    }
    Ok(report)
}

fn manual_lines(service: Service) -> String {
    match service {
        Service::Sddm => format!(
            "add `{AUTH}` after `auth include system-login` and `{SESSION}` after `session include system-login`, and remove the pam_gnome_keyring lines"
        ),
        Service::SddmAutologin => "remove the pam_gnome_keyring lines".into(),
        Service::LockPassword => format!("add `{AUTH}` after the last auth line"),
        Service::Passwd => format!("add `{PASSWORD}` after `password include system-auth`"),
    }
}

/// Put back the files `apply` changed (a failed verification): each from
/// its backup, byte for byte; their manifest entries go.
pub fn roll_back(root: &Root, services: &[Service]) -> Result<()> {
    let mut manifest = Manifest::load(root)?;
    for service in services {
        let backup = root.backup(*service);
        let path = root.pam_dir.join(service.file());
        let bytes = std::fs::read(&backup).map_err(|e| format!("{}: {e}", backup.display()))?;
        let meta = std::fs::metadata(&backup).map_err(|e| e.to_string())?;
        write_atomic(
            &path,
            &bytes,
            meta.mode() & 0o7777,
            Some((meta.uid(), meta.gid())),
        )?;
        let _ = std::fs::remove_file(&backup);
        manifest.files.remove(service.file());
    }
    manifest.save(root)
}

/// Undo what the manifest records (E4's conditional revert). Returns one
/// line per file.
pub fn revert(root: &Root) -> Result<Vec<String>> {
    let mut manifest = Manifest::load(root)?;
    let mut done = Vec::new();
    let names: Vec<String> = manifest.files.keys().cloned().collect();
    for name in names {
        let entry = manifest.files[&name].clone();
        let Some(service) = Service::from_file(&name) else {
            continue;
        };
        let path = root.pam_dir.join(&name);
        if let Some(why) = not_ordinary(&path, root.owner) {
            done.push(format!("{why}: left alone; {}", undo_lines(service)));
            manifest.files.remove(&name);
            continue;
        }
        let current =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let (mode, owner) = (meta.mode() & 0o7777, Some((meta.uid(), meta.gid())));
        let backup = root.backup(service);
        if current == entry.applied && entry.backup && backup.exists() {
            let bytes = std::fs::read(&backup).map_err(|e| e.to_string())?;
            write_atomic(&path, &bytes, mode, owner)?;
            let _ = std::fs::remove_file(&backup);
            done.push(format!("{}: restored from its backup", path.display()));
        } else if let Some(text) = inverse(&current, &entry.removed) {
            if text != current {
                write_atomic(&path, text.as_bytes(), mode, owner)?;
            }
            let _ = std::fs::remove_file(&backup);
            done.push(format!(
                "{}: aleph's lines taken out (the file changed since setup; the rest is kept)",
                path.display()
            ));
        } else {
            // (Its backup is stale now: a later apply must not bring it
            // back.)
            let _ = std::fs::remove_file(&backup);
            done.push(format!(
                "{}: changed since setup and left alone; {}",
                path.display(),
                undo_lines(service)
            ));
        }
        manifest.files.remove(&name);
    }
    manifest.save(root)?;
    Ok(done)
}

fn undo_lines(service: Service) -> String {
    match service {
        Service::SddmAutologin => "put back the pam_gnome_keyring lines if you want them".into(),
        Service::Sddm => {
            "remove the pam_aleph lines and put back the pam_gnome_keyring lines".into()
        }
        _ => "remove the pam_aleph line".into(),
    }
}

// ---- verification through real Linux-PAM

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

#[repr(C)]
struct Message {
    style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct Response {
    resp: *mut c_char,
    retcode: c_int,
}

#[repr(C)]
struct Conv {
    conv: extern "C" fn(c_int, *mut *const Message, *mut *mut Response, *mut c_void) -> c_int,
    appdata: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conv: *const Conv,
        confdir: *const c_char,
        handle: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    fn pam_strerror(handle: *mut c_void, errnum: c_int) -> *const c_char;
}

/// Answers every hidden prompt with the password in `appdata`.
extern "C" fn answer(
    n: c_int,
    msgs: *mut *const Message,
    out: *mut *mut Response,
    appdata: *mut c_void,
) -> c_int {
    // SAFETY: PAM passes `n` messages and our appdata (a live CString);
    // responses are calloc'd and answers strdup'd, as PAM frees them.
    unsafe {
        let password = appdata.cast::<c_char>();
        let responses =
            libc::calloc(n as usize, std::mem::size_of::<Response>()).cast::<Response>();
        if responses.is_null() {
            return 5; // PAM_BUF_ERR
        }
        for i in 0..n as usize {
            if (**msgs.add(i)).style == PAM_PROMPT_ECHO_OFF {
                (*responses.add(i)).resp = libc::strdup(password);
            }
        }
        *out = responses;
    }
    PAM_SUCCESS
}

/// Authenticate `user` with `password` through `service` in `confdir`,
/// as the display manager or the lock screen would.
pub fn authenticate(confdir: &Path, service: &str, user: &str, password: &str) -> Result<()> {
    let service_c = CString::new(service).map_err(|e| e.to_string())?;
    let user_c = CString::new(user).map_err(|e| e.to_string())?;
    let dir = CString::new(confdir.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
    let password = zeroize::Zeroizing::new(CString::new(password).map_err(|e| e.to_string())?);
    let conv = Conv {
        conv: answer,
        appdata: password.as_ptr() as *mut c_void,
    };
    let mut h = std::ptr::null_mut();
    // SAFETY: valid strings and conversation for the handle's lifetime;
    // the handle is ended before they drop.
    unsafe {
        let r = pam_start_confdir(
            service_c.as_ptr(),
            user_c.as_ptr(),
            &conv,
            dir.as_ptr(),
            &mut h,
        );
        if r != PAM_SUCCESS {
            return Err(format!("{service}: pam_start failed ({r})"));
        }
        let r = pam_authenticate(h, 0);
        let why = std::ffi::CStr::from_ptr(pam_strerror(h, r))
            .to_string_lossy()
            .into_owned();
        pam_end(h, r);
        if r != PAM_SUCCESS {
            return Err(format!("{service}: {why}"));
        }
    }
    Ok(())
}

/// The services `verify` runs: the lock screen, then the login (never
/// `passwd`, which would change the password).
pub const VERIFIED: [Service; 2] = [Service::LockPassword, Service::Sddm];

/// Check the edited stacks with a real login (E4): each verified service
/// present authenticates `user` with `password`.
pub fn verify(root: &Root, user: &str, password: &str) -> Result<()> {
    for service in VERIFIED {
        if root.pam_dir.join(service.file()).exists() {
            authenticate(&root.pam_dir, service.file(), user, password)?;
        }
    }
    Ok(())
}

/// A warning if this binary could be replaced by a user (the root side
/// runs as `sudo <this binary>`).
pub fn writable_binary_warning() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let meta = std::fs::metadata(&exe).ok()?;
    (meta.uid() != 0 || meta.mode() & 0o022 != 0).then(|| {
        format!(
            "warning: {} is not a root-owned, root-only-writable file; running it as root trusts whoever can write it",
            exe.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(dir: &str, name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/pam")
                .join(dir)
                .join(name),
        )
        .unwrap()
    }

    /// The stock Omarchy files become the applied ones; applying again
    /// changes nothing; the inverse gives back the stock files exactly.
    #[test]
    fn transforms_match_the_fixtures_are_idempotent_and_invert() {
        for service in Service::ALL {
            let stock = fixture("omarchy", service.file());
            let edit = transform(service, &stock).unwrap();
            assert_eq!(
                edit.text,
                fixture("omarchy-applied", service.file()),
                "{service:?}"
            );
            let again = transform(service, &edit.text).unwrap();
            assert_eq!(again.text, edit.text, "{service:?}");
            assert!(again.removed.is_empty());
            assert_eq!(
                inverse(&edit.text, &edit.removed).unwrap(),
                stock,
                "{service:?}"
            );
        }
    }

    /// Only the expected lines move: gnome-keyring's go from sddm and
    /// sddm-autologin, and stay in passwd.
    #[test]
    fn gnome_keyring_lines_go_only_from_the_login_services() {
        let e = transform(Service::Passwd, &fixture("omarchy", "passwd")).unwrap();
        assert!(e.text.contains("pam_gnome_keyring.so"));
        assert!(e.removed.is_empty());
        let e = transform(
            Service::SddmAutologin,
            &fixture("omarchy", "sddm-autologin"),
        )
        .unwrap();
        assert!(!e.text.contains("pam_gnome_keyring.so"));
        assert!(!e.text.contains("pam_aleph.so"));
        assert_eq!(e.removed.len(), 2);
    }

    fn tree() -> (tempfile::TempDir, Root) {
        let dir = tempfile::tempdir().unwrap();
        let pam_dir = dir.path().join("pam.d");
        std::fs::create_dir_all(&pam_dir).unwrap();
        for service in Service::ALL {
            std::fs::write(
                pam_dir.join(service.file()),
                fixture("omarchy", service.file()),
            )
            .unwrap();
        }
        let root = Root {
            pam_dir,
            state_dir: dir.path().join("state"),
            owner: unsafe { libc::getuid() },
        };
        (dir, root)
    }

    /// Apply edits everything and records it; revert restores every file
    /// byte for byte and leaves no backups or manifest behind.
    #[test]
    fn apply_then_revert_restores_every_file_exactly() {
        let (_dir, root) = tree();
        let report = apply(&root).unwrap();
        assert_eq!(report.changed.len(), 4);
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy-applied", service.file())
            );
        }
        assert!(apply(&root).unwrap().changed.is_empty());
        let done = revert(&root).unwrap();
        assert_eq!(done.len(), 4, "{done:?}");
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
            assert!(!root.backup(service).exists());
        }
        assert!(!root.manifest_path().exists());
    }

    /// A file changed since apply keeps the change: aleph's lines come out
    /// by the inverse; one whose anchors are gone is left alone.
    #[test]
    fn revert_after_an_edit_keeps_the_edit_or_leaves_the_file() {
        let (_dir, root) = tree();
        apply(&root).unwrap();
        let passwd = root.pam_dir.join("passwd");
        let mut text = std::fs::read_to_string(&passwd).unwrap();
        text.push_str("# a local change\n");
        std::fs::write(&passwd, &text).unwrap();
        let sddm = root.pam_dir.join("sddm");
        std::fs::write(
            &sddm,
            "#%PAM-1.0\nauth required pam_deny.so\n-auth      optional  pam_aleph.so\n",
        )
        .unwrap();
        let done = revert(&root).unwrap();
        let passwd_now = std::fs::read_to_string(&passwd).unwrap();
        assert!(passwd_now.contains("# a local change"));
        assert!(!passwd_now.contains("pam_aleph"));
        assert!(
            std::fs::read_to_string(&sddm)
                .unwrap()
                .contains("pam_aleph")
        );
        assert!(done.iter().any(|d| d.contains("left alone")), "{done:?}");
    }

    /// Files not owned by the required owner (root) are left for the user,
    /// unchanged.
    #[test]
    fn files_not_owned_by_root_are_manual() {
        let (_dir, mut root) = tree();
        root.owner = root.owner.wrapping_add(1);
        let report = apply(&root).unwrap();
        assert!(report.changed.is_empty());
        assert_eq!(report.manual.len(), 4);
        assert!(
            report.manual[0].contains("is not owned by uid"),
            "{:?}",
            report.manual
        );
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
        }
    }

    /// A failed check puts every changed file back exactly, and forgets it.
    #[test]
    fn roll_back_restores_the_changed_files() {
        let (_dir, root) = tree();
        let report = apply(&root).unwrap();
        roll_back(&root, &report.changed).unwrap();
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
            assert!(!root.backup(service).exists());
        }
        assert!(!root.manifest_path().exists());
    }

    /// One service that cannot be transformed (its anchor is gone) is left
    /// for the user; the others are still applied and recorded, so revert
    /// undoes them.
    #[test]
    fn a_service_without_its_anchor_is_manual_and_the_rest_recorded() {
        let (_dir, root) = tree();
        std::fs::write(
            root.pam_dir.join("passwd"),
            "#%PAM-1.0\npassword required pam_unix.so\n",
        )
        .unwrap();
        let report = apply(&root).unwrap();
        assert_eq!(report.changed.len(), 3);
        assert!(
            report.manual.iter().any(|m| m.contains("passwd")),
            "{:?}",
            report.manual
        );
        revert(&root).unwrap();
        for service in [Service::Sddm, Service::SddmAutologin, Service::LockPassword] {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
        }
    }

    /// A crash after the files were written but before the manifest: a
    /// re-run trusts the backup (the original), and revert restores it.
    #[test]
    fn a_crash_before_the_manifest_keeps_the_original() {
        let (_dir, root) = tree();
        apply(&root).unwrap();
        std::fs::remove_file(root.manifest_path()).unwrap();
        apply(&root).unwrap();
        revert(&root).unwrap();
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file()),
                "{service:?}"
            );
        }
    }

    /// A backup left from long ago (no manifest entry) is not trusted: the
    /// backup is the file as it is now.
    #[test]
    fn a_stale_backup_is_replaced_by_the_current_file() {
        let (_dir, root) = tree();
        let passwd = root.pam_dir.join("passwd");
        std::fs::write(root.backup(Service::Passwd), "#%PAM-1.0\nold\n").unwrap();
        let mut current = fixture("omarchy", "passwd");
        current.push_str("auth required pam_u2f.so\n");
        std::fs::write(&passwd, &current).unwrap();
        apply(&root).unwrap();
        revert(&root).unwrap();
        assert_eq!(std::fs::read_to_string(&passwd).unwrap(), current);
    }

    /// A file revert leaves alone loses its backup too (it is stale now).
    #[test]
    fn a_file_left_alone_by_revert_loses_its_backup() {
        let (_dir, root) = tree();
        apply(&root).unwrap();
        let sddm = root.pam_dir.join("sddm");
        std::fs::write(
            &sddm,
            "#%PAM-1.0\nauth required pam_deny.so\n-auth      optional  pam_aleph.so\n",
        )
        .unwrap();
        revert(&root).unwrap();
        assert!(!root.backup(Service::Sddm).exists());
    }

    /// The check runs whenever something is recorded (a re-run after an
    /// interrupted check too), and a failure puts every recorded file back.
    #[test]
    fn a_checked_apply_rolls_back_on_failure_even_on_a_rerun() {
        let (_dir, root) = tree();
        let fail = |_: &Root, _: &str, _: &str| -> Result<()> { Err("no".into()) };
        let pass = |_: &Root, _: &str, _: &str| -> Result<()> { Ok(()) };
        // First run: applied, then the check is interrupted (not run).
        apply(&root).unwrap();
        let err = apply_checked(&root, "u", "pw", fail).unwrap_err();
        assert!(err.contains("undone"), "{err}");
        for service in Service::ALL {
            assert_eq!(
                std::fs::read_to_string(root.pam_dir.join(service.file())).unwrap(),
                fixture("omarchy", service.file())
            );
        }
        apply_checked(&root, "u", "pw", pass).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.pam_dir.join("passwd")).unwrap(),
            fixture("omarchy-applied", "passwd")
        );
    }

    /// A symlinked service is left for the user, with the lines to add.
    #[test]
    fn a_symlinked_service_is_manual() {
        let (dir, root) = tree();
        let real = dir.path().join("real-passwd");
        std::fs::rename(root.pam_dir.join("passwd"), &real).unwrap();
        std::os::unix::fs::symlink(&real, root.pam_dir.join("passwd")).unwrap();
        let report = apply(&root).unwrap();
        assert!(
            report
                .manual
                .iter()
                .any(|m| m.contains("symlink") && m.contains(PASSWORD))
        );
        assert_eq!(
            std::fs::read_to_string(&real).unwrap(),
            fixture("omarchy", "passwd")
        );
    }

    /// The transformed lock-screen and login stacks, through real
    /// Linux-PAM: the right password passes and a wrong one fails, with
    /// aleph's line in place (jumps intact). pam_unix is replaced by a
    /// password check, pam_faillock (root-only) by pam_permit, and
    /// pam_aleph points at a socket that does not exist, so nothing can
    /// reach a real daemon.
    #[test]
    fn the_transformed_stacks_run_through_real_pam() {
        let dir = tempfile::tempdir().unwrap();
        let check = dir.path().join("check");
        std::fs::write(&check, "#!/bin/sh\nread -r p\n[ \"$p\" = hunter2 ]\n").unwrap();
        std::fs::set_permissions(&check, std::fs::Permissions::from_mode(0o755)).unwrap();
        let unix = format!("pam_exec.so expose_authtok quiet {}", check.display());
        let aleph = format!(
            "pam_aleph.so socket={}",
            dir.path().join("none.sock").display()
        );
        let stub = |text: String| {
            text.lines()
                .map(|l| {
                    if l.contains("pam_unix.so") {
                        l.replace("pam_unix.so try_first_pass nullok", &unix)
                    } else if l.contains("pam_faillock.so") {
                        let w = words(l);
                        format!("{} {} pam_permit.so", w[0], w[1])
                    } else {
                        l.replace("pam_aleph.so", &aleph)
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        };
        for service in VERIFIED {
            std::fs::write(
                dir.path().join(service.file()),
                stub(fixture("omarchy-applied", service.file())),
            )
            .unwrap();
        }
        std::fs::write(
            dir.path().join("system-login"),
            format!("auth required {unix}\naccount required pam_permit.so\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("system-local-login"),
            "account required pam_permit.so\n",
        )
        .unwrap();
        let user = std::env::var("USER").unwrap();
        for service in VERIFIED {
            authenticate(dir.path(), service.file(), &user, "hunter2").unwrap();
            assert!(authenticate(dir.path(), service.file(), &user, "wrong").is_err());
        }
    }

    /// Real Linux-PAM: a stack that accepts the password passes, one that
    /// does not fails (stub stacks: never pam_aleph here, which could reach
    /// a real daemon).
    #[test]
    fn authenticate_runs_real_pam() {
        let dir = tempfile::tempdir().unwrap();
        let check = dir.path().join("check");
        std::fs::write(&check, "#!/bin/sh\nread -r p\n[ \"$p\" = hunter2 ]\n").unwrap();
        std::fs::set_permissions(&check, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            dir.path().join("ok"),
            format!(
                "auth required pam_exec.so expose_authtok quiet {}\n",
                check.display()
            ),
        )
        .unwrap();
        let user = std::env::var("USER").unwrap();
        authenticate(dir.path(), "ok", &user, "hunter2").unwrap();
        let err = authenticate(dir.path(), "ok", &user, "wrong").unwrap_err();
        assert!(err.starts_with("ok:"), "{err}");
    }
}
