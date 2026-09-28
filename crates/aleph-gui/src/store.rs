//! The manager's view of the keyring (the manager spec, "Architecture"): a
//! Secret Service client, like Seahorse. Secrets reach it only through
//! `org.freedesktop.secrets`, over an encrypted session, and only when one
//! is asked for.
//!
//! The client runs on a thread of its own; the window sends [`Request`]s
//! and takes [`StoreEvent`]s, through the [`Store`] trait (the window's
//! tests use a stand-in).

use std::collections::{BTreeMap, HashMap};
use std::os::fd::OwnedFd;
use std::sync::mpsc;
use std::time::Duration;

use aleph_secret_session::{ClientDh, DH, Session};
use futures_util::{FutureExt, StreamExt};
use zbus::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

const SECRETS: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const DEFAULT_ALIAS: &str = "/org/freedesktop/secrets/aliases/default";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const SESSION: &str = "org.freedesktop.Secret.Session";
const PROMPT: &str = "org.freedesktop.Secret.Prompt";
const SESSION_COLLECTION: &str = "/org/freedesktop/secrets/collection/session";
const ADMIN_NAME: &str = "io.aleph.Keyring";
const ADMIN_PATH: &str = "/io/aleph/Admin";
const ADMIN: &str = "io.aleph.Admin1";

/// How often the lock state is checked, besides the signals alephd sends
/// (one missed, or alephd restarting, is caught within this).
pub const POLL: Duration = Duration::from_secs(2);

/// How long a burst of signals may run before the lists are fetched once.
const SETTLE: Duration = Duration::from_millis(50);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub path: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    /// Seconds since the epoch.
    pub created: u64,
    pub modified: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Collection {
    pub path: String,
    pub label: String,
    pub is_default: bool,
    pub items: Vec<Item>,
}

/// What the keyring looks like now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Vault {
    /// Not known yet.
    Connecting,
    /// alephd cannot be reached (the reason).
    Unreachable(String),
    Locked,
    Unlocked(Vec<Collection>),
}

/// What the window asks for.
#[derive(Debug)]
pub enum Request {
    /// Ask alephd to unlock (its prompt window opens).
    Unlock,
    /// One item's secret.
    Secret(String),
    SetLabel {
        path: String,
        label: String,
    },
    SetSecret {
        path: String,
        secret: Zeroizing<Vec<u8>>,
    },
    CreateItem {
        collection: String,
        label: String,
        attributes: BTreeMap<String, String>,
        secret: Zeroizing<Vec<u8>>,
    },
    DeleteItem(String),
    CreateCollection(String),
    DeleteCollection(String),
    /// Re-authenticate (the reveal guard): alephd converses on this end
    /// of a socketpair; the window answers on the other.
    Reauth(OwnedFd),
}

impl Request {
    /// What it was, for `Done` and the log (never a secret or a label).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unlock => "unlock",
            Self::Secret(_) => "fetch the secret",
            Self::SetLabel { .. } => "rename",
            Self::SetSecret { .. } => "change the secret",
            Self::CreateItem { .. } => "create the item",
            Self::DeleteItem(_) => "delete the item",
            Self::CreateCollection(_) => "create the folder",
            Self::DeleteCollection(_) => "delete the folder",
            Self::Reauth(_) => "confirm",
        }
    }
}

/// What the store tells the window.
#[derive(Debug)]
pub enum StoreEvent {
    Vault(Vault),
    Secret {
        path: String,
        secret: Zeroizing<Vec<u8>>,
        content_type: String,
    },
    /// A request finished; `error` if it failed (a dismissed prompt is
    /// not an error: `dismissed`).
    Done {
        request: &'static str,
        error: Option<String>,
        dismissed: bool,
    },
}

pub trait Store {
    fn request(&self, request: Request);
    /// Events since the last call.
    fn events(&self) -> Vec<StoreEvent>;
}

/// The real store: a Secret Service client on its own thread.
pub struct DbusStore {
    requests: tokio::sync::mpsc::UnboundedSender<Request>,
    events: mpsc::Receiver<StoreEvent>,
}

impl DbusStore {
    /// Connect to `address` (the session bus if `None`); `wake` is called
    /// after every event (the window repaints).
    pub fn start(address: Option<String>, wake: impl Fn() + Send + Sync + 'static) -> Self {
        let (req_tx, req_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("aleph-store".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime");
                let emit = Emit {
                    tx: ev_tx,
                    wake: std::sync::Arc::new(wake),
                };
                rt.block_on(run(address, req_rx, emit));
            })
            .expect("a thread");
        Self {
            requests: req_tx,
            events: ev_rx,
        }
    }
}

impl Store for DbusStore {
    fn request(&self, request: Request) {
        let _ = self.requests.send(request);
    }

    fn events(&self) -> Vec<StoreEvent> {
        self.events.try_iter().collect()
    }
}

#[derive(Clone)]
struct Emit {
    tx: mpsc::Sender<StoreEvent>,
    wake: std::sync::Arc<dyn Fn() + Send + Sync>,
}

impl Emit {
    fn send(&self, e: StoreEvent) {
        let _ = self.tx.send(e);
        (self.wake)();
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

async fn proxy<'a>(
    conn: &Connection,
    path: &'a str,
    iface: &'a str,
) -> Result<zbus::Proxy<'a>, String> {
    zbus::proxy::Builder::new(conn)
        .destination(SECRETS)
        .map_err(err)?
        .path(path)
        .map_err(err)?
        .interface(iface)
        .map_err(err)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(err)
}

async fn connect(address: &Option<String>) -> Result<Connection, String> {
    match address {
        Some(a) => zbus::connection::Builder::address(a.as_str())
            .map_err(err)?
            .build()
            .await
            .map_err(err),
        None => Connection::session().await.map_err(err),
    }
}

/// The session: its keys, its path, and the unique name of the alephd
/// that opened it.
type Opened = (Session, OwnedObjectPath, String);

/// The client on its thread (cheap to clone: each request runs on its
/// own, and an unlock prompt may wait for the person indefinitely).
#[derive(Clone)]
struct Client {
    conn: Connection,
    /// Opened on first use, and again for another alephd (sessions do not
    /// survive a restart).
    session: std::sync::Arc<tokio::sync::Mutex<Option<Opened>>>,
}

impl Client {
    /// Who serves the Secret Service now (its unique name).
    async fn owner(&self) -> Result<String, String> {
        let dbus = zbus::fdo::DBusProxy::new(&self.conn).await.map_err(err)?;
        let name = zbus::names::BusName::try_from(SECRETS).map_err(err)?;
        Ok(dbus.get_name_owner(name).await.map_err(err)?.to_string())
    }

    /// Run `f` with the session, opened if need be, and again if another
    /// alephd serves now.
    async fn with_session<T>(
        &self,
        f: impl FnOnce(&Session, &OwnedObjectPath) -> Result<T, String>,
    ) -> Result<T, String> {
        let owner = self.owner().await?;
        let mut guard = self.session.lock().await;
        if guard.as_ref().is_some_and(|(_, _, o)| *o != owner) {
            *guard = None;
        }
        if guard.is_none() {
            let service = proxy(&self.conn, SERVICE_PATH, SERVICE).await?;
            let dh = ClientDh::new().map_err(err)?;
            let (output, path): (OwnedValue, OwnedObjectPath) = service
                .call("OpenSession", &(DH, Value::from(dh.public.clone())))
                .await
                .map_err(err)?;
            let server: Vec<u8> = output.try_into().map_err(err)?;
            *guard = Some((dh.finish(&server).map_err(err)?, path, owner));
        }
        let (session, path, _) = guard.as_ref().expect("just opened");
        f(session, path)
    }

    /// Drop the session (it failed: alephd forgot it, or it is not ours),
    /// closing it if the same alephd still serves.
    async fn reset_session(&self) {
        let old = self.session.lock().await.take();
        if let Some((_, path, owner)) = old
            && self.owner().await.is_ok_and(|o| o == owner)
            && let Ok(p) = proxy(&self.conn, path.as_str(), SESSION).await
        {
            let _ = p.call_method("Close", &()).await;
        }
    }

    /// Whether the keyring is locked. While locked alephd serves only the
    /// default alias (locked); while unlocked the alias may be gone (its
    /// folder deleted), and then the service answering is enough.
    async fn locked(&self) -> Result<bool, String> {
        let alias = proxy(&self.conn, DEFAULT_ALIAS, COLLECTION)
            .await?
            .get_property::<bool>("Locked")
            .await;
        match alias {
            Ok(locked) => Ok(locked),
            Err(_) => {
                let _: Vec<OwnedObjectPath> = proxy(&self.conn, SERVICE_PATH, SERVICE)
                    .await?
                    .get_property("Collections")
                    .await
                    .map_err(err)?;
                Ok(false)
            }
        }
    }

    async fn vault(&self) -> Vault {
        match self.snapshot().await {
            Ok(v) => v,
            Err(e) => Vault::Unreachable(e),
        }
    }

    async fn snapshot(&self) -> Result<Vault, String> {
        if self.locked().await? {
            return Ok(Vault::Locked);
        }
        let service = proxy(&self.conn, SERVICE_PATH, SERVICE).await?;
        let paths: Vec<OwnedObjectPath> = service.get_property("Collections").await.map_err(err)?;
        let default: Option<OwnedObjectPath> = service.call("ReadAlias", &("default",)).await.ok();
        let mut out = Vec::new();
        for path in paths {
            if path.as_str() == SESSION_COLLECTION || path.as_str().contains("/aliases/") {
                continue;
            }
            // (A folder or item deleted while it is listed is skipped, not
            // an error.)
            if let Some(c) = self.collection(&path, default.as_ref()).await {
                out.push(c);
            }
        }
        // The default folder first, then by label.
        out.sort_by(|a, b| {
            b.is_default
                .cmp(&a.is_default)
                .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
        });
        Ok(Vault::Unlocked(out))
    }

    async fn collection(
        &self,
        path: &OwnedObjectPath,
        default: Option<&OwnedObjectPath>,
    ) -> Option<Collection> {
        let c = proxy(&self.conn, path.as_str(), COLLECTION).await.ok()?;
        let item_paths: Vec<OwnedObjectPath> = c.get_property("Items").await.ok()?;
        let label: String = c.get_property("Label").await.ok()?;
        let mut items = Vec::new();
        for ip in item_paths {
            if let Some(i) = self.item(ip).await {
                items.push(i);
            }
        }
        items.sort_by_key(|i| i.label.to_lowercase());
        Some(Collection {
            is_default: default == Some(path),
            label,
            path: path.to_string(),
            items,
        })
    }

    /// One item's label, attributes, and times (`None` if it went).
    async fn item(&self, path: OwnedObjectPath) -> Option<Item> {
        let i = proxy(&self.conn, path.as_str(), ITEM).await.ok()?;
        let attributes: HashMap<String, String> = i.get_property("Attributes").await.ok()?;
        Some(Item {
            label: i.get_property("Label").await.ok()?,
            attributes: attributes.into_iter().collect(),
            created: i.get_property("Created").await.unwrap_or(0),
            modified: i.get_property("Modified").await.unwrap_or(0),
            path: path.to_string(),
        })
    }

    /// The secret as the session wraps it for alephd.
    async fn wrap(
        &self,
        secret: &[u8],
    ) -> Result<(OwnedObjectPath, Vec<u8>, Vec<u8>, String), String> {
        self.with_session(|session, path| {
            let (params, value) = session.encrypt(secret).map_err(err)?;
            Ok((path.clone(), params, value, "text/plain".into()))
        })
        .await
    }

    async fn fetch(&self, path: &str) -> Result<StoreEvent, String> {
        let session_path = self.with_session(|_, p| Ok(p.clone())).await?;
        type Wrapped = ((OwnedObjectPath, Vec<u8>, Vec<u8>, String),);
        let ((_, params, value, content_type),): Wrapped = proxy(&self.conn, path, ITEM)
            .await?
            .call("GetSecret", &(session_path,))
            .await
            .map_err(err)?;
        let secret = self
            .with_session(|session, _| {
                Ok(Zeroizing::new(
                    session.decrypt(&params, &value).map_err(err)?.to_vec(),
                ))
            })
            .await?;
        Ok(StoreEvent::Secret {
            path: path.to_string(),
            secret,
            content_type,
        })
    }

    async fn set_secret(&self, path: &str, secret: &[u8]) -> Result<(), String> {
        let wrapped = self.wrap(secret).await?;
        proxy(&self.conn, path, ITEM)
            .await?
            .call::<_, _, ()>("SetSecret", &(wrapped,))
            .await
            .map_err(err)
    }

    async fn create(
        &self,
        collection: &str,
        props: &HashMap<&str, Value<'_>>,
        secret: &[u8],
    ) -> Result<OwnedObjectPath, String> {
        let wrapped = self.wrap(secret).await?;
        let (_, prompt): (OwnedObjectPath, OwnedObjectPath) =
            proxy(&self.conn, collection, COLLECTION)
                .await?
                .call("CreateItem", &(props, wrapped, false))
                .await
                .map_err(err)?;
        Ok(prompt)
    }

    /// Run a prompt alephd returned ("/" for none); `true` if dismissed.
    async fn prompt(&self, prompt: &OwnedObjectPath) -> Result<bool, String> {
        if prompt.as_str() == "/" {
            return Ok(false);
        }
        let p = proxy(&self.conn, prompt.as_str(), PROMPT).await?;
        let mut completed = p.receive_signal("Completed").await.map_err(err)?;
        p.call_method("Prompt", &("",)).await.map_err(err)?;
        // (No timeout: alephd's unlock window waits for the person.)
        match completed.next().await {
            Some(msg) => {
                let (dismissed, _): (bool, OwnedValue) = msg.body().deserialize().map_err(err)?;
                Ok(dismissed)
            }
            None => Err("alephd went away during the prompt".into()),
        }
    }

    /// Carry out one request: `(dismissed, secret event)`. A request that
    /// uses the session is tried once more on a new one if it fails
    /// (alephd may have restarted and forgotten ours).
    async fn handle(&self, request: Request) -> Result<(bool, Option<StoreEvent>), String> {
        match request {
            Request::Unlock => {
                let service = proxy(&self.conn, SERVICE_PATH, SERVICE).await?;
                let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
                    .call(
                        "Unlock",
                        &(vec![ObjectPath::try_from(DEFAULT_ALIAS).map_err(err)?],),
                    )
                    .await
                    .map_err(err)?;
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::Secret(path) => {
                let secret = match self.fetch(&path).await {
                    Ok(s) => s,
                    Err(_) => {
                        self.reset_session().await;
                        self.fetch(&path).await?
                    }
                };
                Ok((false, Some(secret)))
            }
            Request::SetLabel { path, label } => {
                proxy(&self.conn, &path, ITEM)
                    .await?
                    .set_property("Label", label)
                    .await
                    .map_err(err)?;
                Ok((false, None))
            }
            Request::SetSecret { path, secret } => {
                if self.set_secret(&path, &secret).await.is_err() {
                    self.reset_session().await;
                    self.set_secret(&path, &secret).await?;
                }
                Ok((false, None))
            }
            Request::CreateItem {
                collection,
                label,
                attributes,
                secret,
            } => {
                let mut attributes: HashMap<String, String> = attributes.into_iter().collect();
                attributes
                    .entry("xdg:schema".into())
                    .or_insert_with(|| "org.freedesktop.Secret.Generic".into());
                let mut props: HashMap<&str, Value> = HashMap::new();
                props.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
                props.insert(
                    "org.freedesktop.Secret.Item.Attributes",
                    Value::from(attributes),
                );
                let prompt = match self.create(&collection, &props, &secret).await {
                    Ok(p) => p,
                    Err(_) => {
                        self.reset_session().await;
                        self.create(&collection, &props, &secret).await?
                    }
                };
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::DeleteItem(path) => {
                let prompt: OwnedObjectPath = proxy(&self.conn, &path, ITEM)
                    .await?
                    .call("Delete", &())
                    .await
                    .map_err(err)?;
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::CreateCollection(label) => {
                let mut props: HashMap<&str, Value> = HashMap::new();
                props.insert(
                    "org.freedesktop.Secret.Collection.Label",
                    Value::from(label),
                );
                let (_, prompt): (OwnedObjectPath, OwnedObjectPath) =
                    proxy(&self.conn, SERVICE_PATH, SERVICE)
                        .await?
                        .call("CreateCollection", &(props, ""))
                        .await
                        .map_err(err)?;
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::DeleteCollection(path) => {
                let prompt: OwnedObjectPath = proxy(&self.conn, &path, COLLECTION)
                    .await?
                    .call("Delete", &())
                    .await
                    .map_err(err)?;
                Ok((self.prompt(&prompt).await?, None))
            }
            Request::Reauth(fd) => {
                let admin = zbus::proxy::Builder::<zbus::Proxy>::new(&self.conn)
                    .destination(ADMIN_NAME)
                    .map_err(err)?
                    .path(ADMIN_PATH)
                    .map_err(err)?
                    .interface(ADMIN)
                    .map_err(err)?
                    .build()
                    .await
                    .map_err(err)?;
                admin
                    .call::<_, _, ()>("Reauth", &(zbus::zvariant::OwnedFd::from(fd),))
                    .await
                    .map_err(err)?;
                Ok((false, None))
            }
        }
    }
}

async fn run(
    address: Option<String>,
    mut requests: tokio::sync::mpsc::UnboundedReceiver<Request>,
    emit: Emit,
) {
    emit.send(StoreEvent::Vault(Vault::Connecting));
    let conn = loop {
        match connect(&address).await {
            Ok(c) => break c,
            Err(e) => {
                emit.send(StoreEvent::Vault(Vault::Unreachable(e)));
                tokio::time::sleep(POLL).await;
            }
        }
    };
    // Signals from whoever serves the Secret Service (alephd): any of them
    // means the lists may have changed.
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(SECRETS)
        .expect("a valid name")
        .path_namespace(SERVICE_PATH)
        .expect("a valid path")
        .build();
    let mut signals = zbus::MessageStream::for_match_rule(rule, &conn, Some(256))
        .await
        .ok();
    let client = Client {
        conn: conn.clone(),
        session: Default::default(),
    };
    // Requests ask for a fresh listing when they end; only this loop lists,
    // so what it last sent is always what the window shows.
    let (refresh_tx, mut refresh) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut last = client.vault().await;
    emit.send(StoreEvent::Vault(last.clone()));
    let mut poll = tokio::time::interval(POLL);
    loop {
        let changed = tokio::select! {
            r = requests.recv() => {
                let Some(r) = r else { return };
                let (client, emit, refresh_tx) = (client.clone(), emit.clone(), refresh_tx.clone());
                tokio::spawn(async move {
                    let name = r.name();
                    match client.handle(r).await {
                        Ok((dismissed, secret)) => {
                            if let Some(s) = secret {
                                emit.send(s);
                            }
                            emit.send(StoreEvent::Done { request: name, error: None, dismissed });
                        }
                        Err(e) => {
                            // (Operations and reasons only: never a secret
                            // or a label.)
                            eprintln!("aleph-gui: cannot {name}: {e}");
                            emit.send(StoreEvent::Done { request: name, error: Some(e), dismissed: false });
                        }
                    }
                    let _ = refresh_tx.send(());
                });
                false
            }
            Some(()) = refresh.recv() => true,
            m = async {
                match &mut signals {
                    Some(s) => s.next().await,
                    None => std::future::pending().await,
                }
            } => {
                // (A burst of signals means one listing.)
                tokio::time::sleep(SETTLE).await;
                if let Some(s) = &mut signals {
                    while let Some(Some(_)) = s.next().now_or_never() {}
                }
                m.is_some()
            }
            // (Only the lock state is polled: listing every item each time
            // would cost a few calls per item.)
            _ = poll.tick() => {
                let locked = client.locked().await.ok();
                let known = match &last {
                    Vault::Locked => Some(true),
                    Vault::Unlocked(_) => Some(false),
                    _ => None,
                };
                locked.is_none() || locked != known
            }
        };
        if changed {
            let v = client.vault().await;
            if v != last {
                last = v.clone();
                emit.send(StoreEvent::Vault(v));
            }
        }
    }
}
