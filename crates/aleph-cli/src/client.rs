//! Talking to `alephd` on the session bus: `io.aleph.Admin1` for the
//! keyring itself, and the freedesktop Secret Service for items (spec §7).

use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use serde::Deserialize;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::prompter::{self, Outcome, Terminal};

pub type Result<T> = std::result::Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct SlotInfo {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub created: u64,
    pub stale: bool,
}

#[derive(Debug, Deserialize, serde::Serialize)]
pub struct Status {
    pub vault: bool,
    pub locked: bool,
    pub untrusted: Option<String>,
    pub memory_locked: Option<bool>,
    pub tpm: Option<bool>,
    pub keyslots: Vec<SlotInfo>,
    #[serde(default)]
    pub rotation_pending: bool,
}

/// One item, as the CLI shows it.
#[derive(Debug, serde::Serialize)]
pub struct ItemInfo {
    #[serde(skip)]
    pub path: OwnedObjectPath,
    pub label: String,
    pub attributes: HashMap<String, String>,
}

/// `(session, parameters, value, content_type)`, as the Secret Service
/// sends a secret.
type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// Extra arguments of a conversational admin method (after the fd).
pub enum Args<'a> {
    None,
    Str(&'a str),
    Bool(bool),
    Str2(&'a str, &'a str),
    /// A file the daemon reads or writes (passed as a descriptor).
    File(std::fs::File),
}

pub struct Client {
    conn: zbus::Connection,
}

impl Client {
    pub async fn connect() -> Result<Self> {
        let conn = zbus::Connection::session()
            .await
            .map_err(|e| format!("cannot reach the session bus: {e}"))?;
        Ok(Self { conn })
    }

    async fn admin(&self) -> Result<zbus::Proxy<'static>> {
        zbus::Proxy::new(
            &self.conn,
            "io.aleph.Keyring",
            "/io/aleph/Admin",
            "io.aleph.Admin1",
        )
        .await
        .map_err(err)
    }

    async fn service(&self) -> Result<zbus::Proxy<'static>> {
        zbus::Proxy::new(
            &self.conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service",
        )
        .await
        .map_err(err)
    }

    async fn proxy(
        &self,
        path: &OwnedObjectPath,
        iface: &'static str,
    ) -> Result<zbus::Proxy<'static>> {
        zbus::Proxy::new(&self.conn, "org.freedesktop.secrets", path.clone(), iface)
            .await
            .map_err(err)
    }

    pub async fn status(&self) -> Result<Status> {
        let json: String = self
            .admin()
            .await?
            .call("Status", &())
            .await
            .map_err(|e| format!("cannot reach alephd: {e}"))?;
        serde_json::from_str(&json).map_err(err)
    }

    pub async fn lock(&self) -> Result<()> {
        self.admin()
            .await?
            .call_method("Lock", &())
            .await
            .map_err(err)?;
        Ok(())
    }

    pub async fn get_config(&self, key: &str) -> Result<String> {
        self.admin()
            .await?
            .call("GetConfig", &(key,))
            .await
            .map_err(err)
    }

    pub async fn retry_keyslot(&self, id: &str) -> Result<()> {
        self.admin()
            .await?
            .call_method("RetryKeyslot", &(id,))
            .await
            .map_err(err)?;
        Ok(())
    }

    /// Call an admin method that needs the user, answering its prompts in
    /// the terminal. The call returns at once; the outcome comes as `Done`.
    pub async fn converse(&self, method: &str, args: Args<'_>) -> Result<Outcome> {
        let (ours, theirs) = UnixStream::pair().map_err(err)?;
        let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
        let admin = self.admin().await?;
        match args {
            Args::None => admin.call_method(method, &(fd,)).await,
            Args::Str(a) => admin.call_method(method, &(fd, a)).await,
            Args::Bool(b) => admin.call_method(method, &(fd, b)).await,
            Args::Str2(a, b) => admin.call_method(method, &(fd, a, b)).await,
            Args::File(f) => {
                let f = zbus::zvariant::OwnedFd::from(OwnedFd::from(f));
                admin.call_method(method, &(fd, f)).await
            }
        }
        .map_err(|e| format!("cannot reach alephd: {e}"))?;
        tokio::task::spawn_blocking(move || prompter::converse(ours, &mut Terminal::new()))
            .await
            .map_err(err)?
            .map_err(err)
    }

    /// Unlock first (in the terminal) if the keyring is locked.
    pub async fn ensure_unlocked(&self) -> Result<()> {
        let status = self.status().await?;
        if !status.vault {
            return Err("no keyring yet; run `aleph setup`".into());
        }
        if status.locked {
            let outcome = self.converse("Unlock", Args::None).await?;
            if !outcome.ok {
                return Err(outcome.message.unwrap_or_else(|| "unlock failed".into()));
            }
        }
        Ok(())
    }

    async fn session(&self) -> Result<OwnedObjectPath> {
        let (_, session): (OwnedValue, OwnedObjectPath) = self
            .service()
            .await?
            .call("OpenSession", &("plain", Value::from("")))
            .await
            .map_err(err)?;
        Ok(session)
    }

    pub async fn search(&self, attributes: &HashMap<String, String>) -> Result<Vec<ItemInfo>> {
        let mut unlocked = Vec::new();
        let mut still_locked = false;
        // Twice at most: if the keyring was locked again between the
        // unlock and the search, the search answers with a placeholder in
        // `locked`, which must not read as "nothing found".
        for _ in 0..2 {
            self.ensure_unlocked().await?;
            let (found, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = self
                .service()
                .await?
                .call("SearchItems", &(attributes,))
                .await
                .map_err(err)?;
            unlocked = found;
            still_locked = !locked.is_empty();
            if !still_locked {
                break;
            }
        }
        if still_locked {
            return Err("the keyring was locked again during the search; try again".into());
        }
        let mut items = Vec::new();
        for path in unlocked {
            let item = self.proxy(&path, "org.freedesktop.Secret.Item").await?;
            items.push(ItemInfo {
                label: item.get_property("Label").await.map_err(err)?,
                attributes: item.get_property("Attributes").await.map_err(err)?,
                path,
            });
        }
        Ok(items)
    }

    pub async fn secret(&self, item: &OwnedObjectPath) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let session = self.session().await?;
        let result: Result<(SecretStruct,)> = self
            .proxy(item, "org.freedesktop.Secret.Item")
            .await?
            .call("GetSecret", &(session.clone(),))
            .await
            .map_err(err);
        self.close(&session).await;
        Ok(zeroize::Zeroizing::new(result?.0.2))
    }

    /// Close a session we opened (the daemon also frees it when we exit).
    async fn close(&self, session: &OwnedObjectPath) {
        if let Ok(s) = self.proxy(session, "org.freedesktop.Secret.Session").await {
            let _ = s.call_method("Close", &()).await;
        }
    }

    /// Store in the default collection, replacing an item with the same
    /// attributes (as `secret-tool store` does).
    pub async fn store(
        &self,
        label: &str,
        attributes: &HashMap<String, String>,
        secret: &[u8],
    ) -> Result<()> {
        self.ensure_unlocked().await?;
        let session = self.session().await?;
        let mut props: HashMap<&str, Value<'_>> = HashMap::new();
        props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        props.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(attributes.clone()),
        );
        let secret = (
            session.clone(),
            Vec::<u8>::new(),
            secret.to_vec(),
            "text/plain",
        );
        let default: OwnedObjectPath = self
            .service()
            .await?
            .call("ReadAlias", &("default",))
            .await
            .map_err(err)?;
        let result: Result<(OwnedObjectPath, OwnedObjectPath)> = self
            .proxy(&default, "org.freedesktop.Secret.Collection")
            .await?
            .call("CreateItem", &(props, secret, true))
            .await
            .map_err(err);
        self.close(&session).await;
        result.map(|_| ())
    }

    pub async fn delete(&self, item: &OwnedObjectPath) -> Result<()> {
        let _: OwnedObjectPath = self
            .proxy(item, "org.freedesktop.Secret.Item")
            .await?
            .call("Delete", &())
            .await
            .map_err(err)?;
        Ok(())
    }

    /// `(label, items)` for every collection.
    pub async fn collections(&self) -> Result<Vec<(String, Vec<ItemInfo>)>> {
        self.ensure_unlocked().await?;
        let paths: Vec<OwnedObjectPath> = self
            .service()
            .await?
            .get_property("Collections")
            .await
            .map_err(err)?;
        let mut out = Vec::new();
        for path in paths {
            let c = self
                .proxy(&path, "org.freedesktop.Secret.Collection")
                .await?;
            let label: String = c.get_property("Label").await.map_err(err)?;
            let item_paths: Vec<OwnedObjectPath> = c.get_property("Items").await.map_err(err)?;
            let mut items = Vec::new();
            for p in item_paths {
                let item = self.proxy(&p, "org.freedesktop.Secret.Item").await?;
                items.push(ItemInfo {
                    label: item.get_property("Label").await.map_err(err)?,
                    attributes: item.get_property("Attributes").await.map_err(err)?,
                    path: p,
                });
            }
            out.push((label, items));
        }
        Ok(out)
    }
}
