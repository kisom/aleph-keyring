//! Copying the keyring back to gnome-keyring, for `aleph setup --revert`
//! (spec §6; DECISIONS.md E3).
//!
//! alephd runs its own gnome-keyring on a private bus over the keyring
//! files, after checking that none serves this session, and unlocks the
//! login keyring with the login password (which `pam_gnome_keyring` kept
//! in step in `passwd`). What to write is decided by comparison, not by
//! timestamp: every item missing there or different is written, then read
//! back on a fresh connection. The session never changes hands before that
//! verification passes.
//!
//! Collections gnome-keyring does not have go into its default collection
//! (creating one would need its own password prompt).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

use aleph_core::Body;
use zbus::Connection;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::error::{Error, Result};
use crate::import::{ImportedItem, SECRETS_NAME};
use crate::secret::session::{ClientDh, DH, Session};

const SECRETS_PATH: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";

fn gk(e: impl std::fmt::Display) -> Error {
    Error::Invalid(format!("gnome-keyring: {e}"))
}

/// Whether a gnome-keyring already serves this session: `org.gnome.keyring`
/// is owned, or the Secret Service name is held by someone other than this
/// connection. Revert then refuses, rather than run a second instance over
/// the same keyring files.
pub async fn gnome_keyring_active(session: &Connection) -> bool {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(session).await else {
        return false;
    };
    let owner = |name: &'static str| {
        let dbus = dbus.clone();
        async move {
            let name = zbus::names::BusName::try_from(name).ok()?;
            dbus.get_name_owner(name).await.ok().map(|o| o.to_string())
        }
    };
    let me = session.unique_name().map(|u| u.to_string());
    owner("org.gnome.keyring").await.is_some()
        || owner(SECRETS_NAME).await.is_some_and(|o| Some(o) != me)
}

/// A private session bus's configuration: no service directories, so
/// nothing (a prompter, a second gnome-keyring) is ever started on it.
pub const PRIVATE_BUS_CONFIG: &str = r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#;

/// Let a child inherit nothing above stderr: alephd's own descriptors (its
/// TPM connection, `pam.sock`) must not live on in a long-running child.
fn no_inherited_fds(cmd: &mut std::process::Command) -> &mut std::process::Command {
    use std::os::unix::process::CommandExt;
    // SAFETY: close_range is async-signal-safe and touches no memory.
    // CLOSE_RANGE_CLOEXEC, not closing: std's exec-error pipe must stay
    // open until the exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
            Ok(())
        })
    }
}

/// A gnome-keyring (secrets component) alephd runs itself on a private
/// bus, over the keyring files in `data_home`; killed on drop.
pub struct Private {
    bus: std::process::Child,
    daemon: std::process::Child,
    pub address: String,
    _dirs: tempfile::TempDir,
}

impl Private {
    /// Start it and unlock the login keyring with `password`. Its home and
    /// runtime directory are throwaway; only `data_home` (holding
    /// `keyrings/`) is real.
    pub async fn start(data_home: &Path, password: &str) -> Result<Self> {
        use std::io::{BufRead, Write};
        let dirs = tempfile::tempdir().map_err(gk)?;
        let run = dirs.path().join("run");
        std::fs::create_dir_all(&run).map_err(gk)?;
        std::fs::set_permissions(&run, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(gk)?;
        let config = dirs.path().join("bus.conf");
        std::fs::write(&config, PRIVATE_BUS_CONFIG).map_err(gk)?;
        let mut bus = no_inherited_fds(&mut std::process::Command::new("dbus-daemon"))
            .arg(format!("--config-file={}", config.display()))
            .args(["--nofork", "--nopidfile", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| gk(format!("dbus-daemon: {e}")))?;
        let mut address = String::new();
        std::io::BufReader::new(bus.stdout.take().expect("piped"))
            .read_line(&mut address)
            .map_err(gk)?;
        let address = address.trim().to_string();
        let daemon = no_inherited_fds(&mut std::process::Command::new("gnome-keyring-daemon"))
            .args(["--foreground", "--components=secrets", "--unlock"])
            .env("HOME", dirs.path())
            .env("XDG_RUNTIME_DIR", &run)
            .env("XDG_DATA_HOME", data_home)
            .env("XDG_CONFIG_HOME", dirs.path().join("config"))
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .env_remove("GNOME_KEYRING_CONTROL")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let mut daemon = match daemon {
            Ok(d) => d,
            Err(e) => {
                let _ = bus.kill();
                let _ = bus.wait();
                return Err(gk(format!("gnome-keyring-daemon: {e}")));
            }
        };
        let mut stdin = daemon.stdin.take().expect("piped");
        let _ = stdin.write_all(password.as_bytes());
        drop(stdin);
        let private = Self {
            bus,
            daemon,
            address,
            _dirs: dirs,
        };
        let conn = private.connect().await?;
        let dbus = zbus::fdo::DBusProxy::new(&conn).await.map_err(gk)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let name = zbus::names::BusName::try_from(SECRETS_NAME).map_err(gk)?;
            if dbus.get_name_owner(name).await.is_ok() {
                return Ok(private);
            }
            if std::time::Instant::now() > deadline {
                return Err(gk("it did not start"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A new connection to its bus.
    pub async fn connect(&self) -> Result<Connection> {
        zbus::connection::Builder::address(self.address.as_str())
            .map_err(gk)?
            .build()
            .await
            .map_err(gk)
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        for child in [&mut self.daemon, &mut self.bus] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// What an export did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub exported: usize,
    pub unchanged: usize,
    pub deleted: usize,
    /// Items of collections gnome-keyring lacks, put in its default one.
    pub into_default: usize,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Copied {} item(s) to gnome-keyring and read each back ({} already there)",
            self.exported, self.unchanged
        )?;
        if self.into_default > 0 {
            write!(
                f,
                "; {} from collections gnome-keyring lacks went into its default collection",
                self.into_default
            )?;
        }
        if self.deleted > 0 {
            write!(
                f,
                "; deleted {} item(s) deleted in aleph since the import",
                self.deleted
            )?;
        }
        write!(f, ".")
    }
}

/// One gnome-keyring conversation: its service, an encrypted session.
struct Remote {
    conn: Connection,
    owner: String,
    session: Session,
    session_path: OwnedObjectPath,
}

impl Remote {
    async fn open(conn: &Connection) -> Result<Self> {
        let dbus = zbus::fdo::DBusProxy::new(conn).await.map_err(gk)?;
        let name = zbus::names::BusName::try_from(SECRETS_NAME).map_err(gk)?;
        let owner = dbus.get_name_owner(name).await.map_err(gk)?.to_string();
        let service = proxy(conn, &owner, SECRETS_PATH, SERVICE).await?;
        let dh = ClientDh::new().map_err(gk)?;
        let (output, session_path): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &(DH, Value::from(dh.public.clone())))
            .await
            .map_err(gk)?;
        let server_public: Vec<u8> = output.try_into().map_err(gk)?;
        Ok(Self {
            conn: conn.clone(),
            session: dh.finish(&server_public).map_err(gk)?,
            owner,
            session_path,
        })
    }

    async fn proxy(&self, path: &str, interface: &'static str) -> Result<zbus::Proxy<'static>> {
        proxy(&self.conn, &self.owner, path, interface).await
    }

    /// The items in `collection` with these attributes and label, with
    /// their secrets.
    async fn find(
        &self,
        collection: &OwnedObjectPath,
        attributes: &BTreeMap<String, String>,
        label: &str,
    ) -> Result<Vec<(OwnedObjectPath, Vec<u8>)>> {
        let c = self.proxy(collection.as_str(), COLLECTION).await?;
        let attrs: HashMap<&str, &str> = attributes
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let paths: Vec<OwnedObjectPath> = c.call("SearchItems", &(attrs,)).await.map_err(gk)?;
        let mut out = Vec::new();
        for path in paths {
            let item = self.proxy(path.as_str(), ITEM).await?;
            let l: String = item.get_property("Label").await.map_err(gk)?;
            // (SearchItems matches items with at least these attributes;
            // an item with more is another item.)
            let a: HashMap<String, String> = item.get_property("Attributes").await.map_err(gk)?;
            if l != label || !crate::import::same_attributes(&a.into_iter().collect(), attributes) {
                continue;
            }
            let (_, parameters, value, _): (OwnedObjectPath, Vec<u8>, Vec<u8>, String) = item
                .call("GetSecret", &(self.session_path.clone(),))
                .await
                .map_err(gk)?;
            let secret = self.session.decrypt(&parameters, &value).map_err(gk)?;
            out.push((path, secret.to_vec()));
        }
        Ok(out)
    }
}

async fn proxy(
    conn: &Connection,
    owner: &str,
    path: &str,
    interface: &'static str,
) -> Result<zbus::Proxy<'static>> {
    zbus::proxy::Builder::new(conn)
        .destination(owner.to_string())
        .and_then(|b| b.path(path.to_string()))
        .and_then(|b| b.interface(interface))
        .map(|b| b.cache_properties(CacheProperties::No))
        .map_err(gk)?
        .build()
        .await
        .map_err(gk)
}

/// Write `body` into the gnome-keyring on `conn` (every item missing
/// there or different), delete the `delete` items there, then read every
/// written item back on a fresh connection to `address`.
pub async fn export(
    conn: &Connection,
    address: &str,
    body: &Body,
    delete: &[ImportedItem],
    imported: &std::collections::HashSet<uuid::Uuid>,
) -> Result<Report> {
    let remote = Remote::open(conn).await?;
    let service = remote.proxy(SECRETS_PATH, SERVICE).await?;
    let default: OwnedObjectPath = service.call("ReadAlias", &("default",)).await.map_err(gk)?;
    if default.as_str() == "/" {
        return Err(gk("it has no default collection"));
    }
    let locked: bool = remote
        .proxy(default.as_str(), COLLECTION)
        .await?
        .get_property("Locked")
        .await
        .map_err(gk)?;
    if locked {
        return Err(Error::Invalid(
            "gnome-keyring's login keyring did not unlock with your login password (its password may differ); nothing was changed".into(),
        ));
    }
    let mut by_label = HashMap::new();
    let paths: Vec<OwnedObjectPath> = service.get_property("Collections").await.map_err(gk)?;
    for path in paths {
        let c = remote.proxy(path.as_str(), COLLECTION).await?;
        // A collection only its own password opens (the private instance
        // unlocks the login keyring alone) is left out: items for it go to
        // the default collection.
        if c.get_property::<bool>("Locked").await.map_err(gk)? {
            continue;
        }
        let label: String = c.get_property("Label").await.map_err(gk)?;
        by_label.entry(label).or_insert(path);
    }
    let aleph_default = body
        .resolve_alias(aleph_core::model::DEFAULT_ALIAS)
        .map(|c| c.id);
    let target_of = |id, label: &str, report: &mut Report| {
        if Some(id) == aleph_default {
            default.clone()
        } else if let Some(p) = by_label.get(label) {
            p.clone()
        } else {
            report.into_default += 1;
            default.clone()
        }
    };
    let mut report = Report::default();
    // Deletions first, and never of an item aleph still holds (one deleted
    // and stored again with the same label and attributes).
    let held = |label: &str, attributes: &BTreeMap<String, String>| {
        body.collections.iter().any(|c| {
            c.items.iter().any(|i| {
                i.label == label && crate::import::same_attributes(&i.attributes, attributes)
            })
        })
    };
    for d in delete {
        if held(&d.label, &d.attributes) {
            continue;
        }
        let target = if d.is_default {
            default.clone()
        } else {
            by_label
                .get(&d.collection)
                .cloned()
                .unwrap_or(default.clone())
        };
        for (path, _) in remote.find(&target, &d.attributes, &d.label).await? {
            let _: OwnedObjectPath = remote
                .proxy(path.as_str(), ITEM)
                .await?
                .call("Delete", &())
                .await
                .map_err(gk)?;
            report.deleted += 1;
        }
    }
    // An aleph item standing where a deleted imported item was (the same
    // label and attributes: deleted and stored again) is its successor, and
    // updates it in place like an imported item.
    let successors: std::collections::HashSet<uuid::Uuid> = body
        .collections
        .iter()
        .flat_map(|c| c.items.iter())
        .filter(|i| {
            delete.iter().any(|d| {
                d.label == i.label && crate::import::same_attributes(&d.attributes, &i.attributes)
            })
        })
        .map(|i| i.id)
        .collect();
    let mut written = Vec::new();
    // Each gnome-keyring item stands for one aleph item at most.
    let mut used: std::collections::HashSet<OwnedObjectPath> = Default::default();
    for collection in &body.collections {
        for item in &collection.items {
            let target = target_of(collection.id, &collection.label, &mut report);
            let found: Vec<_> = remote
                .find(&target, &item.attributes, &item.label)
                .await?
                .into_iter()
                .filter(|(p, _)| !used.contains(p))
                .collect();
            if let Some((path, _)) = found.iter().find(|(_, s)| s == item.secret.expose()) {
                used.insert(path.clone());
                report.unchanged += 1;
                written.push((target, item));
                continue;
            }
            // An item the import brought, changed in aleph since: updated
            // in place (no duplicate). Anything else is added beside
            // whatever gnome-keyring has, never over it.
            if (imported.contains(&item.id) || successors.contains(&item.id))
                && let Some((path, _)) = found.first()
            {
                used.insert(path.clone());
                let (parameters, value) =
                    remote.session.encrypt(item.secret.expose()).map_err(gk)?;
                let secret = (
                    remote.session_path.clone(),
                    parameters,
                    value,
                    item.content_type.clone(),
                );
                remote
                    .proxy(path.as_str(), ITEM)
                    .await?
                    .call_method("SetSecret", &(secret,))
                    .await
                    .map_err(gk)?;
                report.exported += 1;
                written.push((target, item));
                continue;
            }
            let (parameters, value) = remote.session.encrypt(item.secret.expose()).map_err(gk)?;
            let properties: HashMap<&str, Value> = HashMap::from([
                (
                    "org.freedesktop.Secret.Item.Label",
                    Value::from(item.label.clone()),
                ),
                (
                    "org.freedesktop.Secret.Item.Attributes",
                    Value::from(
                        item.attributes
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect::<HashMap<String, String>>(),
                    ),
                ),
            ]);
            let secret = (
                remote.session_path.clone(),
                parameters,
                value,
                item.content_type.clone(),
            );
            let (created, prompt): (OwnedObjectPath, OwnedObjectPath) = remote
                .proxy(target.as_str(), COLLECTION)
                .await?
                .call("CreateItem", &(properties, secret, false))
                .await
                .map_err(gk)?;
            if prompt.as_str() != "/" {
                return Err(gk("it asked for a prompt to store an item"));
            }
            used.insert(created);
            report.exported += 1;
            written.push((target, item));
        }
    }
    // Read every item back (the unchanged ones too), on a fresh
    // connection and session.
    let fresh = zbus::connection::Builder::address(address)
        .map_err(gk)?
        .build()
        .await
        .map_err(gk)?;
    let check = Remote::open(&fresh).await?;
    for (target, item) in written {
        let found = check.find(&target, &item.attributes, &item.label).await?;
        if !found.iter().any(|(_, s)| s == item.secret.expose()) {
            return Err(Error::Invalid(format!(
                "copying to gnome-keyring could not be verified ({}); the session was not handed over",
                item.label
            )));
        }
    }
    Ok(report)
}
