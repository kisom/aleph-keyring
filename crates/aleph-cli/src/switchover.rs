//! Switching the session's Secret Service from gnome-keyring to alephd
//! (spec §6 "Startup and switchover"; DECISIONS.md E9, E10). User-level
//! only: D-Bus activation files, the bus's configuration, and systemd user
//! units. Every step checks the real state first, so a re-run does only
//! what is still undone.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, String>;

pub const SECRETS_NAME: &str = "org.freedesktop.secrets";
pub const ALEPH_NAME: &str = "io.aleph.Keyring";
/// gnome-keyring's user units (masked, then stopped).
pub const GNOME_UNITS: [&str; 2] = [
    "gnome-keyring-daemon.service",
    "gnome-keyring-daemon.socket",
];

/// User-level D-Bus activation files, which take precedence over the
/// system ones: the Secret Service name starts alephd, and gnome-keyring's
/// own names (which would start it directly, bypassing systemd) start
/// nothing.
pub const ACTIVATION: [(&str, &str); 3] = [
    (
        "org.freedesktop.secrets.service",
        "[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/usr/lib/aleph/alephd\nSystemdService=alephd.service\n",
    ),
    (
        "org.gnome.keyring.service",
        "# Disabled by aleph setup (aleph serves the Secret Service).\n[D-BUS Service]\nName=org.gnome.keyring\nExec=/bin/false\n",
    ),
    (
        "org.freedesktop.impl.portal.Secret.service",
        "# Disabled by aleph setup (aleph serves the Secret Service).\n[D-BUS Service]\nName=org.freedesktop.impl.portal.Secret\nExec=/bin/false\n",
    ),
];

/// A unit's state before setup changed it (for revert).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitState {
    /// `systemctl is-enabled` (enabled, disabled, static, masked, ...).
    pub enabled: String,
    pub active: bool,
}

/// systemd user units, as setup uses them.
pub trait Units {
    fn state(&self, unit: &str) -> Result<UnitState>;
    fn mask(&self, units: &[&str]) -> Result<()>;
    fn stop(&self, units: &[&str]) -> Result<()>;
    fn unmask(&self, units: &[&str]) -> Result<()>;
    fn enable(&self, units: &[&str]) -> Result<()>;
    fn start(&self, units: &[&str]) -> Result<()>;
}

/// The real thing: `systemctl --user` (`ALEPH_SYSTEMCTL` names another
/// program, for tests, which must never touch the real user manager).
pub struct Systemctl;

impl Systemctl {
    fn program() -> std::ffi::OsString {
        std::env::var_os("ALEPH_SYSTEMCTL").unwrap_or_else(|| "systemctl".into())
    }

    /// A query's answer. (`is-enabled` and `is-active` exit non-zero for
    /// "disabled" or "inactive": their output is what counts; no output is
    /// a failure, never a state to record.)
    fn run(args: &[&str]) -> Result<String> {
        let out = std::process::Command::new(Self::program())
            .arg("--user")
            .args(args)
            .output()
            .map_err(|e| format!("systemctl: {e}"))?;
        let answer = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if answer.is_empty() {
            return Err(format!(
                "systemctl --user {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(answer)
    }

    fn checked(args: &[&str]) -> Result<()> {
        let out = std::process::Command::new(Self::program())
            .arg("--user")
            .args(args)
            .output()
            .map_err(|e| format!("systemctl: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "systemctl --user {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

impl Units for Systemctl {
    fn state(&self, unit: &str) -> Result<UnitState> {
        Ok(UnitState {
            enabled: Self::run(&["is-enabled", unit])?,
            active: Self::run(&["is-active", unit])? == "active",
        })
    }

    fn mask(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["mask"], units].concat())
    }

    fn stop(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["stop"], units].concat())
    }

    fn unmask(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["unmask"], units].concat())
    }

    fn enable(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["enable"], units].concat())
    }

    fn start(&self, units: &[&str]) -> Result<()> {
        Self::checked(&[&["start"], units].concat())
    }
}

/// Where setup's user-level files go.
pub struct Dirs {
    /// `$XDG_DATA_HOME` (activation files under `dbus-1/services`).
    pub data_home: PathBuf,
    /// `$XDG_STATE_HOME` (setup's record under `aleph`).
    pub state_home: PathBuf,
    /// `$XDG_CONFIG_HOME` (Omarchy's hooks).
    pub config_home: PathBuf,
}

impl Dirs {
    pub fn from_env() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")?;
        let xdg = |var: &str, default: &str| {
            std::env::var_os(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(default))
        };
        Ok(Self {
            data_home: xdg("XDG_DATA_HOME", ".local/share"),
            state_home: xdg("XDG_STATE_HOME", ".local/state"),
            config_home: xdg("XDG_CONFIG_HOME", ".config"),
        })
    }

    pub fn services(&self) -> PathBuf {
        self.data_home.join("dbus-1/services")
    }

    fn record(&self) -> PathBuf {
        self.state_home.join("aleph/setup.json")
    }
}

/// What setup records: only choices and what it must restore (E10: the
/// real state is checked on every run, never trusted from here).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Record {
    /// gnome-keyring's units as they were before setup first changed them.
    #[serde(default)]
    pub units: BTreeMap<String, UnitState>,
    /// How far an unfinished revert got ([`SWITCHED_BACK`]: only the
    /// release is left).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_phase: Option<String>,
}

/// A revert's phase once gnome-keyring's routes are restored.
pub const SWITCHED_BACK: &str = "switched-back";

impl Record {
    pub fn load(dirs: &Dirs) -> Result<Self> {
        match std::fs::read(dirs.record()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("{}: {e}", dirs.record().display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", dirs.record().display())),
        }
    }

    pub fn save(&self, dirs: &Dirs) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&dirs.record(), &bytes)
    }
}

/// Write `path` through a temporary file and a rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or("no parent directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = path.with_extension("aleph-tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

async fn owner(bus: &zbus::Connection, name: &str) -> Option<String> {
    let dbus = zbus::fdo::DBusProxy::new(bus).await.ok()?;
    let name = zbus::names::BusName::try_from(name).ok()?;
    dbus.get_name_owner(name).await.ok().map(|o| o.to_string())
}

/// Hand the session's Secret Service to alephd (E9's order): activation
/// files and a bus reload; the prior unit states recorded (once); units
/// masked, then stopped; then the name's owner checked. Returns what was
/// done, one line per step.
pub async fn switch_over(
    bus: &zbus::Connection,
    units: &dyn Units,
    dirs: &Dirs,
    record: &mut Record,
) -> Result<Vec<String>> {
    let mut done = Vec::new();
    let services = dirs.services();
    let mut wrote = false;
    for (name, contents) in ACTIVATION {
        let path = services.join(name);
        if std::fs::read(&path).ok().as_deref() != Some(contents.as_bytes()) {
            write_atomic(&path, contents.as_bytes())?;
            wrote = true;
        }
    }
    if wrote {
        // dbus-broker does not notice new activation files by itself.
        bus.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "ReloadConfig",
            &(),
        )
        .await
        .map_err(|e| format!("reloading the bus configuration: {e}"))?;
        done.push(format!(
            "installed D-Bus activation files in {}",
            services.display()
        ));
    }
    // The running alephd queues for the name now (it claims it at start
    // only while this activation file exists).
    bus.call_method(
        Some(ALEPH_NAME),
        "/io/aleph/Admin",
        Some("io.aleph.Admin1"),
        "ClaimSecretService",
        &(),
    )
    .await
    .map_err(|e| format!("asking alephd to queue for the Secret Service: {e}"))?;
    let mut states = Vec::new();
    for unit in GNOME_UNITS {
        states.push((unit, units.state(unit)?));
    }
    if record.units.is_empty() {
        record.units = states
            .iter()
            .map(|(u, s)| (u.to_string(), s.clone()))
            .collect();
        record.save(dirs)?;
    }
    let to_mask: Vec<&str> = states
        .iter()
        .filter(|(_, s)| s.enabled != "masked" && s.enabled != "not-found")
        .map(|(u, _)| *u)
        .collect();
    if !to_mask.is_empty() {
        units.mask(&to_mask)?;
        done.push(format!("masked {}", to_mask.join(", ")));
    }
    let to_stop: Vec<&str> = states
        .iter()
        .filter(|(_, s)| s.active)
        .map(|(u, _)| *u)
        .collect();
    if !to_stop.is_empty() {
        // One last import, just before gnome-keyring stops: what it stored
        // or changed since (a signal can run ahead of its data) is not lost.
        let _: String = bus
            .call_method(
                Some(ALEPH_NAME),
                "/io/aleph/Admin",
                Some("io.aleph.Admin1"),
                "ImportGnomeKeyring",
                &(),
            )
            .await
            .and_then(|m| m.body().deserialize())
            .map_err(|e| format!("the last import before the switchover: {e}"))?;
        units.stop(&to_stop)?;
        done.push("stopped gnome-keyring (its pkcs11 component goes away with it)".into());
    }
    // The bus hands the name to the queued alephd at once.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let aleph = owner(bus, ALEPH_NAME).await;
        let secrets = owner(bus, SECRETS_NAME).await;
        if aleph.is_some() && aleph == secrets {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err(
                "another program still owns org.freedesktop.secrets (gnome-keyring started outside systemd? end it with `pkill -x gnome-keyring-d`, then run setup again)"
                    .into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    done.push("alephd serves the Secret Service".into());
    Ok(done)
}

/// Give the Secret Service back to gnome-keyring, after a verified export
/// (E3's order): alephd's activation files removed (only if still ours)
/// and the bus reloaded; gnome-keyring's units unmasked and restored as
/// recorded. The caller then has alephd let go of the name, which the bus
/// hands to gnome-keyring, queued behind it.
pub async fn switch_back(
    bus: &zbus::Connection,
    units: &dyn Units,
    dirs: &Dirs,
    record: &mut Record,
) -> Result<Vec<String>> {
    let mut done = Vec::new();
    let services = dirs.services();
    let mut removed = false;
    for (name, contents) in ACTIVATION {
        let path = services.join(name);
        match std::fs::read(&path) {
            Ok(bytes) if bytes == contents.as_bytes() => {
                std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                removed = true;
            }
            Ok(_) => done.push(format!("left {} (changed since setup)", path.display())),
            Err(_) => {}
        }
    }
    if removed {
        bus.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "ReloadConfig",
            &(),
        )
        .await
        .map_err(|e| format!("reloading the bus configuration: {e}"))?;
        done.push(format!(
            "removed aleph's D-Bus activation files from {}",
            services.display()
        ));
    }
    let recorded: Vec<(String, UnitState)> = record
        .units
        .iter()
        .map(|(u, s)| (u.clone(), s.clone()))
        .collect();
    let mut unmask = Vec::new();
    let mut enable = Vec::new();
    let mut start = Vec::new();
    for (unit, before) in &recorded {
        let now = units.state(unit)?;
        if now.enabled == "masked" && before.enabled != "masked" {
            unmask.push(unit.as_str());
        }
        if before.enabled == "enabled" {
            enable.push(unit.as_str());
        }
        if before.active {
            start.push(unit.as_str());
        }
    }
    if !unmask.is_empty() {
        units.unmask(&unmask)?;
        done.push(format!("unmasked {}", unmask.join(", ")));
    }
    if !enable.is_empty() {
        units.enable(&enable)?;
    }
    if !start.is_empty() {
        units.start(&start)?;
        done.push("started gnome-keyring".into());
    }
    record.units.clear();
    // (In the same save: a stop right after never loses the phase.)
    record.revert_phase = Some(SWITCHED_BACK.into());
    record.save(dirs)?;
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aleph_daemon::testing::{GnomeKeyring, bus, daemon_on};
    use std::sync::Mutex;

    /// systemd, as far as setup can tell: stopping gnome-keyring's service
    /// stops the real gnome-keyring on the test bus.
    struct FakeUnits {
        gk: Mutex<Option<GnomeKeyring>>,
        states: Mutex<BTreeMap<String, UnitState>>,
        calls: Mutex<Vec<String>>,
    }

    impl FakeUnits {
        fn new(gk: GnomeKeyring) -> Self {
            let s = |enabled: &str, active| UnitState {
                enabled: enabled.into(),
                active,
            };
            Self {
                gk: Mutex::new(Some(gk)),
                states: Mutex::new(BTreeMap::from([
                    (GNOME_UNITS[0].to_string(), s("static", true)),
                    (GNOME_UNITS[1].to_string(), s("enabled", true)),
                ])),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Units for FakeUnits {
        fn state(&self, unit: &str) -> Result<UnitState> {
            Ok(self.states.lock().unwrap()[unit].clone())
        }

        fn mask(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("mask {}", units.join(" ")));
            for u in units {
                self.states.lock().unwrap().get_mut(*u).unwrap().enabled = "masked".into();
            }
            Ok(())
        }

        fn stop(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("stop {}", units.join(" ")));
            for u in units {
                self.states.lock().unwrap().get_mut(*u).unwrap().active = false;
            }
            if let Some(gk) = self.gk.lock().unwrap().take() {
                gk.stop();
            }
            Ok(())
        }

        fn unmask(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("unmask {}", units.join(" ")));
            Ok(())
        }

        fn enable(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("enable {}", units.join(" ")));
            Ok(())
        }

        fn start(&self, units: &[&str]) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("start {}", units.join(" ")));
            Ok(())
        }
    }

    /// Switching back removes only aleph's activation files and restores
    /// the units as they were before setup.
    #[tokio::test(flavor = "multi_thread")]
    async fn switching_back_restores_what_setup_changed() {
        let bus = bus();
        let address = bus.address.clone();
        let gk = GnomeKeyring::start(&bus, "login password");
        let _d = daemon_on(bus, true).await;
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs {
            data_home: home.path().join("data"),
            state_home: home.path().join("state"),
            config_home: home.path().join("config"),
        };
        let units = FakeUnits::new(gk);
        let mut record = Record::load(&dirs).unwrap();
        switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        // Someone edited one activation file: it stays.
        let changed = dirs.services().join(ACTIVATION[1].0);
        std::fs::write(&changed, "edited").unwrap();
        units.calls.lock().unwrap().clear();
        let mut record = Record::load(&dirs).unwrap();
        let done = switch_back(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        assert!(!dirs.services().join(ACTIVATION[0].0).exists());
        assert!(changed.exists());
        assert!(
            done.iter().any(|d| d.contains("changed since setup")),
            "{done:?}"
        );
        assert_eq!(
            *units.calls.lock().unwrap(),
            [
                format!("unmask {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
                format!("enable {}", GNOME_UNITS[1]),
                format!("start {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
            ]
        );
        let saved = Record::load(&dirs).unwrap();
        assert!(saved.units.is_empty());
        // (In the same save: a stop right after never loses the phase.)
        assert_eq!(saved.revert_phase.as_deref(), Some(SWITCHED_BACK));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gnome_keyring_hands_over_and_a_rerun_changes_nothing() {
        let bus = bus();
        let address = bus.address.clone();
        let gk = GnomeKeyring::start(&bus, "login password");
        let d = daemon_on(bus, true).await;
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs {
            data_home: home.path().join("data"),
            state_home: home.path().join("state"),
            config_home: home.path().join("config"),
        };
        let units = FakeUnits::new(gk);
        let mut record = Record::load(&dirs).unwrap();
        let done = switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        assert_eq!(done.len(), 4, "{done:?}");
        assert_eq!(
            aleph_daemon::daemon::secret_service_owner(&d.conn).await,
            "alephd"
        );
        for (name, contents) in ACTIVATION {
            assert_eq!(
                std::fs::read_to_string(dirs.services().join(name)).unwrap(),
                contents
            );
        }
        // The states before setup are what revert restores.
        let saved = Record::load(&dirs).unwrap();
        assert_eq!(saved.units[GNOME_UNITS[1]].enabled, "enabled");
        assert!(saved.units[GNOME_UNITS[0]].active);
        assert_eq!(
            *units.calls.lock().unwrap(),
            [
                format!("mask {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
                format!("stop {} {}", GNOME_UNITS[0], GNOME_UNITS[1]),
            ]
        );
        // Again: only the check.
        let mut record = Record::load(&dirs).unwrap();
        let done = switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap();
        assert_eq!(done, ["alephd serves the Secret Service"]);
        assert_eq!(units.calls.lock().unwrap().len(), 2);
        assert_eq!(
            Record::load(&dirs).unwrap().units[GNOME_UNITS[1]].enabled,
            "enabled"
        );
    }

    /// Something still holding the name (gnome-keyring started outside
    /// systemd) is reported, not waited on forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_gnome_keyring_outside_systemd_is_reported() {
        let bus = bus();
        let address = bus.address.clone();
        let gk = GnomeKeyring::start(&bus, "login password");
        let _d = daemon_on(bus, true).await;
        let conn = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs {
            data_home: home.path().join("data"),
            state_home: home.path().join("state"),
            config_home: home.path().join("config"),
        };
        let units = FakeUnits::new(gk);
        // (systemd stops nothing: the fixture outlives the "stop".)
        let kept = units.gk.lock().unwrap().take();
        let mut record = Record::default();
        let err = switch_over(&conn, &units, &dirs, &mut record)
            .await
            .unwrap_err();
        assert!(err.contains("pkill"), "{err}");
        drop(kept);
    }
}
