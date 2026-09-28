//! The freedesktop Secret Service on D-Bus (spec §6 "Secret Service", §4
//! "Locked search").
//!
//! Object layout:
//!
//! | Path | Interface |
//! |---|---|
//! | `/org/freedesktop/secrets` | `Service` |
//! | `…/collection/<id>` and `…/aliases/<name>` | `Collection` |
//! | `…/collection/<id>/<item>` | `Item` |
//! | `…/session/<n>` | `Session` |
//! | `…/prompt/<n>` | `Prompt` |
//!
//! The vault encrypts collection names and item attributes, so while it is
//! locked only the `default` alias exists, as a locked collection, and a
//! search cannot be answered. Instead of a false "not found" (§4 "Locked
//! search"), a locked `SearchItems` returns a placeholder item
//! (`…/search/<n>`) in its `locked` list. libsecret then calls `Unlock` on
//! it, and the prompt's result lists the real matching items. Reads of the
//! body (`GetSecrets`, `GetSecret`, …) answer `IsLocked`.
//!
//! No method waits for the user. An unlock prompt with no prompter to run
//! (no graphical session) is not dismissed: it waits until the vault is
//! unlocked some other way (`alephctl unlock`, PAM), then completes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aleph_core::{Body, Collection, Item, SecretBytes};
use uuid::Uuid;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, interface};

use crate::error::Error;
use crate::keyring::Keyring;
use crate::prompt::{Caller, Launcher};
use crate::secret::session::Session;

pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLLECTION_PREFIX: &str = "/org/freedesktop/secrets/collection/";
const ALIAS_PREFIX: &str = "/org/freedesktop/secrets/aliases/";
const SEARCH_PREFIX: &str = "/org/freedesktop/secrets/search/";
/// Placeholder searches kept at once; the oldest go first.
const MAX_SEARCHES: usize = 256;
const LABEL: &str = "org.freedesktop.Secret.Collection.Label";
const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";

/// `(session, parameters, value, content_type)`.
pub type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretError {
    #[zbus(error)]
    ZBus(zbus::Error),
    IsLocked(String),
    NoSession(String),
    NoSuchObject(String),
}

type Result<T> = std::result::Result<T, SecretError>;

impl From<Error> for SecretError {
    fn from(e: Error) -> Self {
        match e {
            Error::Locked => Self::IsLocked("the keyring is locked".into()),
            Error::NotFound => Self::NoSuchObject("no such object".into()),
            other => Self::ZBus(zbus::Error::Failure(other.to_string())),
        }
    }
}

fn path(s: String) -> OwnedObjectPath {
    OwnedObjectPath::try_from(s).expect("valid object path")
}

pub fn collection_path(id: Uuid) -> OwnedObjectPath {
    path(format!("{COLLECTION_PREFIX}{}", id.simple()))
}

pub fn item_path(collection: Uuid, item: Uuid) -> OwnedObjectPath {
    path(format!(
        "{COLLECTION_PREFIX}{}/{}",
        collection.simple(),
        item.simple()
    ))
}

pub fn alias_path(name: &str) -> OwnedObjectPath {
    path(format!("{ALIAS_PREFIX}{name}"))
}

fn root() -> OwnedObjectPath {
    path("/".into())
}

/// Aliases name a collection; only letters, digits, and `_` fit in a path.
fn valid_alias(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// What a prompt does when the user answers it.
#[derive(Clone, Debug)]
enum Action {
    Unlock(Vec<Target>),
    CreateCollection { label: String, alias: String },
    DeleteCollection(Uuid),
}

struct Waiting {
    prompt: OwnedObjectPath,
    client: Option<String>,
    targets: Vec<Target>,
    /// The unlock conversation this prompt joined, if it joined one (it
    /// ends with that conversation if the conversation is dismissed).
    joined: Option<u64>,
}

/// The unlock conversation (one runs at a time).
#[derive(Default)]
struct UnlockConversation {
    running: bool,
    /// The number of the latest conversation.
    current: u64,
    /// Recent conversations that ended dismissed.
    dismissed: std::collections::VecDeque<u64>,
}

/// Dismissed conversations remembered (for prompts joining as one ends).
const DISMISSED_KEPT: usize = 16;

/// Prompt objects one client may hold at once (started or not).
const MAX_PROMPTS_PER_CLIENT: usize = 16;

/// Sessions one client may hold open at once.
const MAX_SESSIONS_PER_CLIENT: usize = 32;

/// Waiting unlock prompts allowed per client, and in all.
const MAX_WAITING_PER_CLIENT: usize = 8;
const MAX_WAITING: usize = 128;

/// The daemon state the D-Bus objects share.
pub struct SecretService {
    pub keyring: Arc<Keyring>,
    pub launcher: Arc<dyn Launcher>,
    /// Open sessions and the client (unique bus name) that opened each.
    sessions: Mutex<HashMap<OwnedObjectPath, (Session, Option<String>)>>,
    next: AtomicU64,
    /// Collection, alias, and item paths currently served.
    served: tokio::sync::Mutex<HashSet<OwnedObjectPath>>,
    /// Placeholder items for searches made while locked, oldest first.
    searches: Mutex<Vec<(OwnedObjectPath, HashMap<String, String>)>>,
    /// Unlock prompts waiting for an unlock from elsewhere, with the
    /// client that started each.
    waiting: Mutex<Vec<Waiting>>,
    /// Every live prompt object and the client that asked for it.
    prompts: Mutex<HashMap<OwnedObjectPath, Option<String>>>,
    /// The unlock conversation, if one is running, and how recent ones ended.
    unlock: Mutex<UnlockConversation>,
    conn: std::sync::OnceLock<Connection>,
}

impl SecretService {
    pub fn new(keyring: Arc<Keyring>, launcher: Arc<dyn Launcher>) -> Arc<Self> {
        Arc::new(Self {
            keyring,
            launcher,
            sessions: Mutex::default(),
            next: AtomicU64::new(1),
            served: tokio::sync::Mutex::default(),
            searches: Mutex::default(),
            waiting: Mutex::default(),
            prompts: Mutex::default(),
            unlock: Mutex::default(),
            conn: std::sync::OnceLock::new(),
        })
    }

    /// Serve on `conn` (which should own `org.freedesktop.secrets`).
    pub async fn serve(self: &Arc<Self>, conn: &Connection) -> zbus::Result<()> {
        let _ = self.conn.set(conn.clone());
        self.watch_clients().await?;
        conn.object_server()
            .at(SERVICE_PATH, ServiceObj { svc: self.clone() })
            .await?;
        self.sync().await
    }

    fn conn(&self) -> &Connection {
        self.conn.get().expect("serving")
    }

    fn next_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// Register exactly the collection, alias, and item objects the
    /// current state has, and drop the rest.
    pub async fn sync(self: &Arc<Self>) -> zbus::Result<()> {
        let mut want: HashMap<OwnedObjectPath, Obj> = HashMap::new();
        match self.keyring.read(|b| {
            let mut out = Vec::new();
            for c in &b.collections {
                out.push((collection_path(c.id), Obj::Collection(Target::Id(c.id))));
                for i in &c.items {
                    out.push((item_path(c.id, i.id), Obj::Item(c.id, i.id)));
                }
            }
            for name in b.aliases.keys().filter(|n| valid_alias(n)) {
                out.push((
                    alias_path(name),
                    Obj::Collection(Target::Alias(name.clone())),
                ));
            }
            out
        }) {
            Ok(objs) => want.extend(objs),
            // Locked: only the default alias, as a locked collection.
            Err(_) => {
                want.insert(
                    alias_path("default"),
                    Obj::Collection(Target::Alias("default".into())),
                );
            }
        }
        let server = self.conn().object_server();
        let mut served = self.served.lock().await;
        for p in served.iter().filter(|p| !want.contains_key(*p)) {
            let _ = server.remove::<ItemObj, _>(p.as_ref()).await;
            let _ = server.remove::<CollectionObj, _>(p.as_ref()).await;
        }
        served.retain(|p| want.contains_key(p));
        for (p, obj) in want {
            if served.contains(&p) {
                continue;
            }
            match obj {
                Obj::Collection(target) => {
                    server
                        .at(
                            p.as_ref(),
                            CollectionObj {
                                svc: self.clone(),
                                target,
                            },
                        )
                        .await?;
                }
                Obj::Item(c, i) => {
                    server
                        .at(
                            p.as_ref(),
                            ItemObj {
                                svc: self.clone(),
                                collection: c,
                                item: i,
                            },
                        )
                        .await?;
                }
            }
            served.insert(p);
        }
        Ok(())
    }

    /// Free what a client leaves behind when it disconnects: its sessions
    /// (and their keys) and its waiting prompts. libsecret never closes
    /// its session, so without this they would pile up until lock.
    async fn watch_clients(self: &Arc<Self>) -> zbus::Result<()> {
        use futures_util::StreamExt;
        let dbus = zbus::fdo::DBusProxy::new(self.conn()).await?;
        let mut changes = dbus.receive_name_owner_changed().await?;
        let svc = Arc::downgrade(self);
        tokio::spawn(async move {
            while let Some(change) = changes.next().await {
                let Ok(args) = change.args() else { continue };
                let name = args.name().to_string();
                if !name.starts_with(':') || args.new_owner().is_some() {
                    continue;
                }
                let Some(svc) = svc.upgrade() else { break };
                svc.forget_client(&name).await;
            }
        });
        Ok(())
    }

    pub async fn forget_client(self: &Arc<Self>, client: &str) {
        let sessions: Vec<OwnedObjectPath> = {
            let mut map = self.sessions.lock().unwrap();
            let gone: Vec<_> = map
                .iter()
                .filter(|(_, (_, owner))| owner.as_deref() == Some(client))
                .map(|(p, _)| p.clone())
                .collect();
            for p in &gone {
                map.remove(p);
            }
            gone
        };
        for p in sessions {
            let _ = self
                .conn()
                .object_server()
                .remove::<SessionObj, _>(p.as_ref())
                .await;
        }
        self.waiting
            .lock()
            .unwrap()
            .retain(|w| w.client.as_deref() != Some(client));
        let prompts: Vec<OwnedObjectPath> = {
            let mut all = self.prompts.lock().unwrap();
            let gone: Vec<_> = all
                .iter()
                .filter(|(_, owner)| owner.as_deref() == Some(client))
                .map(|(p, _)| p.clone())
                .collect();
            for p in &gone {
                all.remove(p);
            }
            gone
        };
        for p in prompts {
            let _ = self
                .conn()
                .object_server()
                .remove::<PromptObj, _>(p.as_ref())
                .await;
        }
    }

    /// Live prompt objects now (tests).
    pub fn prompt_count(&self) -> usize {
        self.prompts.lock().unwrap().len()
    }

    /// Unlock prompts waiting now (tests).
    pub fn waiting_count(&self) -> usize {
        self.waiting.lock().unwrap().len()
    }

    /// Sessions open now (tests).
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// `Keyring::modify` on a blocking thread: it encrypts, writes, and
    /// fsyncs, which must not stall the async runtime.
    pub async fn modify<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Body) -> std::result::Result<T, Error> + Send + 'static,
    ) -> std::result::Result<T, Error> {
        let keyring = self.keyring.clone();
        tokio::task::spawn_blocking(move || keyring.modify(f))
            .await
            .unwrap_or_else(|e| Err(Error::Invalid(e.to_string())))
    }

    /// Lock: drop MK and the decrypted body (§4).
    pub async fn lock(self: &Arc<Self>) -> zbus::Result<()> {
        // Already locked: nothing to do. In particular a second `Lock` must
        // not close the sessions of clients waiting for an unlock, or drop
        // the placeholders their searches returned.
        if self.keyring.is_locked() {
            return Ok(());
        }
        // Sessions stay open: they hold only transport keys, nothing is
        // readable through them while locked, and libsecret clients keep
        // theirs for the life of the process (closing them would break
        // every long-lived client at each screen lock). They are freed on
        // `Close`, when their client disconnects, and at exit.
        self.keyring.lock();
        let searches: Vec<_> = self
            .searches
            .lock()
            .unwrap()
            .drain(..)
            .map(|(p, _)| p)
            .collect();
        for p in searches {
            let _ = self
                .conn()
                .object_server()
                .remove::<PlaceholderObj, _>(p.as_ref())
                .await;
        }
        self.sync().await?;
        self.announce_all().await
    }

    /// The vault was unlocked (by a prompt, `alephctl unlock`, or PAM): serve
    /// its objects and complete every waiting unlock prompt.
    pub async fn unlocked(self: &Arc<Self>) -> zbus::Result<()> {
        self.sync().await?;
        self.announce_all().await?;
        let waiting: Vec<_> = self.waiting.lock().unwrap().drain(..).collect();
        for w in waiting {
            match self.unlocked_value(&w.targets) {
                Some(value) => finish(self, &w.prompt, Some(value), empty_paths()).await,
                // Locked again meanwhile: keep waiting, never answer empty.
                None => self.waiting.lock().unwrap().push(w),
            }
        }
        Ok(())
    }

    /// End (dismissed) the waiting prompts that joined an unlock
    /// conversation which was dismissed: nothing else is asking the user.
    async fn end_dismissed_joiners(self: &Arc<Self>) {
        let dismissed = self.unlock.lock().unwrap().dismissed.clone();
        let ended: Vec<Waiting> = {
            let mut waiting = self.waiting.lock().unwrap();
            let (ended, kept) = waiting
                .drain(..)
                .partition(|w| w.joined.is_some_and(|id| dismissed.contains(&id)));
            *waiting = kept;
            ended
        };
        for w in ended {
            finish(self, &w.prompt, None, empty_paths()).await;
        }
    }

    /// A placeholder item standing for `query` while the vault is locked.
    async fn placeholder(
        self: &Arc<Self>,
        query: HashMap<String, String>,
    ) -> Result<OwnedObjectPath> {
        let p = path(format!("{SEARCH_PREFIX}q{}", self.next_id()));
        self.conn()
            .object_server()
            .at(
                p.as_ref(),
                PlaceholderObj {
                    query: query.clone(),
                },
            )
            .await?;
        let evicted = {
            let mut searches = self.searches.lock().unwrap();
            searches.push((p.clone(), query));
            if searches.len() > MAX_SEARCHES {
                Some(searches.remove(0).0)
            } else {
                None
            }
        };
        if let Some(old) = evicted {
            let _ = self
                .conn()
                .object_server()
                .remove::<PlaceholderObj, _>(old.as_ref())
                .await;
        }
        Ok(p)
    }

    /// What an unlock of `objects` yields once the vault is open: each
    /// placeholder becomes the items its search now finds.
    /// What `Unlock(objects)` is about, captured when it is called: each
    /// placeholder's query is copied now, so it survives the placeholder
    /// being evicted or cleared before the prompt completes.
    fn targets(&self, objects: Vec<OwnedObjectPath>) -> Vec<Target> {
        let searches = self.searches.lock().unwrap();
        objects
            .into_iter()
            .map(|o| match searches.iter().find(|(p, _)| *p == o) {
                Some((_, query)) => Target::Search(query.clone()),
                None => Target::Path(o),
            })
            .collect()
    }

    /// The unlocked objects `targets` stand for, once the vault is open.
    /// A search path that is no longer known is dropped, never echoed back
    /// (a client would take it for an item).
    /// `None` if the vault is locked (it cannot be answered yet).
    fn resolve_unlocked(&self, targets: &[Target]) -> Option<Vec<OwnedObjectPath>> {
        if self.keyring.is_locked() {
            return None;
        }
        let mut out: Vec<OwnedObjectPath> = Vec::new();
        for t in targets {
            match t {
                Target::Search(query) => {
                    out.extend(self.keyring.read(|b| matching(b, query)).ok()?)
                }
                Target::Path(p) if p.as_str().starts_with(SEARCH_PREFIX) => {}
                Target::Path(p) => out.push(p.clone()),
                Target::Id(_) | Target::Alias(_) => {}
            }
        }
        let mut seen = HashSet::new();
        out.retain(|p| seen.insert(p.clone()));
        Some(out)
    }

    fn unlocked_value(&self, targets: &[Target]) -> Option<OwnedValue> {
        OwnedValue::try_from(Value::from(self.resolve_unlocked(targets)?)).ok()
    }

    /// Tell clients every collection changed (after lock or unlock).
    async fn announce_all(self: &Arc<Self>) -> zbus::Result<()> {
        let paths: Vec<OwnedObjectPath> = self
            .served
            .lock()
            .await
            .iter()
            .filter(|p| !is_item(p))
            .cloned()
            .collect();
        let emitter = SignalEmitter::new(self.conn(), SERVICE_PATH)?;
        for p in paths {
            ServiceObj::collection_changed(&emitter, p.as_ref()).await?;
        }
        Ok(())
    }

    fn resolve(&self, target: &Target) -> std::result::Result<Uuid, Error> {
        self.keyring.read(|b| match target {
            Target::Id(id) => b.collection(*id).map(|c| c.id).ok_or(Error::NotFound),
            Target::Alias(name) => b.resolve_alias(name).map(|c| c.id).ok_or(Error::NotFound),
            Target::Path(_) | Target::Search(_) => Err(Error::NotFound),
        })?
    }

    fn session(&self, p: &ObjectPath<'_>) -> Result<SessionGuard<'_>> {
        let sessions = self.sessions.lock().unwrap();
        if !sessions.contains_key(&OwnedObjectPath::from(p.to_owned())) {
            return Err(SecretError::NoSession(format!("no session {p}")));
        }
        Ok(SessionGuard {
            sessions,
            path: OwnedObjectPath::from(p.to_owned()),
        })
    }

    fn secret_for(&self, session: &ObjectPath<'_>, item: &Item) -> Result<SecretStruct> {
        let guard = self.session(session)?;
        let (params, value) = guard
            .get()
            .encrypt(item.secret.expose())
            .map_err(|e| SecretError::ZBus(zbus::Error::Failure(e.to_string())))?;
        Ok((
            OwnedObjectPath::from(session.to_owned()),
            params,
            value,
            item.content_type.clone(),
        ))
    }

    fn decrypt(&self, secret: &SecretStruct) -> Result<SecretBytes> {
        let guard = self.session(&secret.0.as_ref())?;
        let plain = guard
            .get()
            .decrypt(&secret.1, &secret.2)
            .map_err(|e| SecretError::ZBus(zbus::Error::Failure(e.to_string())))?;
        Ok(SecretBytes::new(plain.to_vec()))
    }

    /// Create a prompt object for `action` and return its path.
    async fn prompt(
        self: &Arc<Self>,
        action: Action,
        owner: Option<String>,
    ) -> Result<OwnedObjectPath> {
        let p = path(format!("{SERVICE_PATH}/prompt/p{}", self.next_id()));
        {
            let mut prompts = self.prompts.lock().unwrap();
            let mine = prompts.values().filter(|o| **o == owner).count();
            if owner.is_some() && mine >= MAX_PROMPTS_PER_CLIENT {
                return Err(SecretError::ZBus(zbus::Error::Failure(
                    "too many open prompts for this client".into(),
                )));
            }
            prompts.insert(p.clone(), owner.clone());
        }
        self.conn()
            .object_server()
            .at(
                p.as_ref(),
                PromptObj {
                    svc: self.clone(),
                    path: p.clone(),
                    action,
                    started: Default::default(),
                },
            )
            .await?;
        self.gone_already(owner.as_deref()).await;
        Ok(p)
    }

    /// If `client` disconnected while we were creating something for it
    /// (its `NameOwnerChanged` already handled), free what it left.
    async fn gone_already(self: &Arc<Self>, client: Option<&str>) {
        let Some(client) = client else { return };
        let Ok(dbus) = zbus::fdo::DBusProxy::new(self.conn()).await else {
            return;
        };
        let Ok(name) = zbus::names::BusName::try_from(client.to_string()) else {
            return;
        };
        if !dbus.name_has_owner(name).await.unwrap_or(true) {
            self.forget_client(client).await;
        }
    }

    /// Run `action` through the prompter (blocking; call from a blocking
    /// task).
    fn run(self: &Arc<Self>, action: &Action, caller: Option<Caller>) -> Outcome {
        if let Action::Unlock(targets) = action {
            // Unlocked meanwhile: answer without a prompter.
            if let Some(v) = self.unlocked_value(targets) {
                return Outcome::Done(v);
            }
            // One unlock conversation at a time: the others wait for it
            // (and complete when it unlocks), rather than each opening a
            // prompter window.
            let id = {
                let mut u = self.unlock.lock().unwrap();
                if u.running {
                    return Outcome::Joined(u.current);
                }
                u.running = true;
                u.current += 1;
                u.current
            };
            // Cleared on every exit, a panic included: a flag stuck at
            // true would leave every later unlock prompt waiting forever.
            // A conversation that did not end well (a panic too) is
            // recorded as dismissed, so the prompts that joined it end.
            struct Running<'a> {
                unlock: &'a Mutex<UnlockConversation>,
                id: u64,
                dismissed: bool,
            }
            impl Drop for Running<'_> {
                fn drop(&mut self) {
                    let mut u = self.unlock.lock().unwrap_or_else(|e| e.into_inner());
                    u.running = false;
                    if self.dismissed {
                        u.dismissed.push_back(self.id);
                        if u.dismissed.len() > DISMISSED_KEPT {
                            u.dismissed.pop_front();
                        }
                    }
                }
            }
            let mut running = Running {
                unlock: &self.unlock,
                id,
                dismissed: true,
            };
            let outcome = self.run_unlock(targets, caller);
            running.dismissed = matches!(outcome, Outcome::Dismissed);
            return outcome;
        }
        let mut chan = match self.launcher.launch() {
            Ok(chan) => chan,
            Err(e) => {
                // (Unlocks never get here: see `run_unlock`, which waits.)
                tracing::info!("no prompter: {e}");
                return Outcome::Dismissed;
            }
        };
        let value = match action {
            Action::Unlock(_) => unreachable!("handled above"),
            Action::CreateCollection { label, alias } => {
                let confirmed = confirm(
                    &mut chan,
                    &format!("Create the collection '{label}'?"),
                    caller,
                );
                if !confirmed {
                    return Outcome::Dismissed;
                }
                let (label, alias) = (label.clone(), alias.clone());
                self.keyring
                    .modify(move |b| {
                        let c = Collection::new(label);
                        let id = c.id;
                        b.collections.push(c);
                        if valid_alias(&alias) {
                            b.aliases.insert(alias, id);
                        }
                        Ok(id)
                    })
                    .ok()
                    .map(|id| path_value(collection_path(id)))
            }
            Action::DeleteCollection(id) => {
                let Some(label) = self
                    .keyring
                    .read(|b| b.collection(*id).map(|c| c.label.clone()))
                    .ok()
                    .flatten()
                else {
                    return Outcome::Dismissed;
                };
                if !confirm(
                    &mut chan,
                    &format!("Delete the collection '{label}' and all its items?"),
                    caller,
                ) {
                    return Outcome::Dismissed;
                }
                let id = *id;
                self.keyring
                    .modify(move |b| {
                        b.remove_collection(id).ok_or(Error::NotFound)?;
                        b.aliases.retain(|_, c| *c != id);
                        Ok(())
                    })
                    .ok()
                    .map(|()| path_value(root()))
            }
        };
        match value {
            Some(v) => Outcome::Done(v),
            None => Outcome::Dismissed,
        }
    }
}

impl SecretService {
    fn run_unlock(self: &Arc<Self>, targets: &[Target], caller: Option<Caller>) -> Outcome {
        // The prompter starts only once any admin conversation is over.
        match self
            .keyring
            .unlock_prompting(|| self.launcher.launch(), caller)
        {
            Ok(true) => match self.unlocked_value(targets) {
                Some(v) => Outcome::Done(v),
                None => Outcome::Wait,
            },
            // No prompter: wait for an unlock from elsewhere.
            Ok(false) => Outcome::Wait,
            Err(_) => Outcome::Dismissed,
        }
    }
}

/// How a prompt ended.
enum Outcome {
    Done(OwnedValue),
    Dismissed,
    /// No prompter could start: wait for an unlock from elsewhere.
    Wait,
    /// Another unlock conversation (this number) is running: wait for it,
    /// and end with it if it is dismissed.
    Joined(u64),
}

fn path_value(p: OwnedObjectPath) -> OwnedValue {
    OwnedValue::try_from(Value::from(p)).expect("an object path is a value")
}

fn is_item(p: &OwnedObjectPath) -> bool {
    p.as_str()
        .strip_prefix(COLLECTION_PREFIX)
        .is_some_and(|rest| rest.contains('/'))
}

/// Ask a yes/no question through the prompter and end the conversation.
fn confirm(chan: &mut crate::prompt::Channel, text: &str, caller: Option<Caller>) -> bool {
    use crate::prompt::{FromPrompter, Purpose, ToPrompter};
    let yes = chan
        .send(&ToPrompter::Begin {
            purpose: Purpose::Reauth,
            operation: text.into(),
            caller,
        })
        .and_then(|()| {
            chan.ask(&ToPrompter::Confirm {
                text: text.into(),
                default: false,
            })
        })
        .is_ok_and(|r| r == FromPrompter::Confirm { yes: true });
    chan.done(yes, None);
    yes
}

struct SessionGuard<'a> {
    sessions: std::sync::MutexGuard<'a, HashMap<OwnedObjectPath, (Session, Option<String>)>>,
    path: OwnedObjectPath,
}

impl SessionGuard<'_> {
    fn get(&self) -> &Session {
        &self.sessions[&self.path].0
    }
}

#[derive(Clone, Debug)]
enum Target {
    Id(Uuid),
    Alias(String),
    /// An object to report back as unlocked.
    Path(OwnedObjectPath),
    /// A locked search's placeholder: the items its query finds.
    Search(HashMap<String, String>),
}

enum Obj {
    Collection(Target),
    Item(Uuid, Uuid),
}

/// The caller's pid and name, for the prompt (display only).
async fn caller(conn: &Connection, hdr: &zbus::message::Header<'_>) -> Option<Caller> {
    let sender = hdr.sender()?.to_owned();
    let dbus = zbus::fdo::DBusProxy::new(conn).await.ok()?;
    let pid = dbus
        .get_connection_unix_process_id(zbus::names::BusName::Unique(sender))
        .await
        .ok()?;
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string());
    Some(Caller {
        name,
        pid: Some(pid),
    })
}

fn matching(b: &Body, attributes: &HashMap<String, String>) -> Vec<OwnedObjectPath> {
    let query: BTreeMap<String, String> = attributes.clone().into_iter().collect();
    b.collections
        .iter()
        .flat_map(|c| {
            c.items
                .iter()
                .filter(|i| i.matches(&query))
                .map(|i| item_path(c.id, i.id))
        })
        .collect()
}

/// Parse `…/collection/<c>/<i>` into ids.
fn parse_item(p: &ObjectPath<'_>) -> Option<(Uuid, Uuid)> {
    let rest = p.as_str().strip_prefix(COLLECTION_PREFIX)?;
    let (c, i) = rest.split_once('/')?;
    Some((Uuid::try_parse(c).ok()?, Uuid::try_parse(i).ok()?))
}

struct ServiceObj {
    svc: Arc<SecretService>,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl ServiceObj {
    async fn open_session(
        &self,
        algorithm: String,
        input: OwnedValue,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(OwnedValue, OwnedObjectPath)> {
        let bytes: Vec<u8> =
            Vec::<u8>::try_from(input.try_clone().map_err(zbus::Error::from)?).unwrap_or_default();
        let (session, output) = Session::open(&algorithm, &bytes).map_err(|e| {
            SecretError::ZBus(zbus::Error::FDO(Box::new(zbus::fdo::Error::NotSupported(
                e.to_string(),
            ))))
        })?;
        let p = path(format!("{SERVICE_PATH}/session/s{}", self.svc.next_id()));
        let client = hdr.sender().map(|s| s.to_string());
        {
            let mut sessions = self.svc.sessions.lock().unwrap();
            let mine = sessions
                .values()
                .filter(|(_, owner)| *owner == client)
                .count();
            if mine >= MAX_SESSIONS_PER_CLIENT {
                return Err(SecretError::ZBus(zbus::Error::Failure(
                    "too many open sessions for this client".into(),
                )));
            }
            sessions.insert(p.clone(), (session, client.clone()));
        }
        self.svc
            .conn()
            .object_server()
            .at(
                p.as_ref(),
                SessionObj {
                    svc: self.svc.clone(),
                    path: p.clone(),
                },
            )
            .await?;
        self.svc.gone_already(client.as_deref()).await;
        let output = if algorithm == crate::secret::session::PLAIN {
            OwnedValue::from(zbus::zvariant::Str::from(""))
        } else {
            OwnedValue::try_from(Value::from(output)).map_err(zbus::Error::from)?
        };
        Ok((output, p))
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let existing = self
            .svc
            .keyring
            .read(|b| b.resolve_alias(&alias).map(|c| c.id))
            .map_err(SecretError::from)?;
        if let (Some(id), false) = (existing, alias.is_empty()) {
            return Ok((collection_path(id), root()));
        }
        let label = properties
            .get(LABEL)
            .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let owner = hdr.sender().map(|s| s.to_string());
        let prompt = self
            .svc
            .prompt(Action::CreateCollection { label, alias }, owner)
            .await?;
        Ok((root(), prompt))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        match self.svc.keyring.read(|b| matching(b, &attributes)) {
            Ok(found) => Ok((found, Vec::new())),
            Err(Error::Locked) => Ok((Vec::new(), vec![self.svc.placeholder(attributes).await?])),
            Err(e) => Err(e.into()),
        }
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let targets = self.svc.targets(objects);
        if let Some(unlocked) = self.svc.resolve_unlocked(&targets) {
            return Ok((unlocked, root()));
        }
        let owner = hdr.sender().map(|s| s.to_string());
        Ok((
            Vec::new(),
            self.svc.prompt(Action::Unlock(targets), owner).await?,
        ))
    }

    async fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        self.svc.lock().await?;
        Ok((objects, root()))
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> Result<HashMap<OwnedObjectPath, SecretStruct>> {
        let found: Vec<(OwnedObjectPath, Item)> = self.svc.keyring.read(|b| {
            items
                .iter()
                .filter_map(|p| {
                    let (c, i) = parse_item(&p.as_ref())?;
                    let item = b.collection(c)?.items.iter().find(|x| x.id == i)?;
                    Some((p.clone(), item.clone()))
                })
                .collect()
        })?;
        let mut out = HashMap::new();
        for (p, item) in found {
            out.insert(p, self.svc.secret_for(&session.as_ref(), &item)?);
        }
        Ok(out)
    }

    async fn read_alias(&self, name: String) -> Result<OwnedObjectPath> {
        match self
            .svc
            .keyring
            .read(|b| b.resolve_alias(&name).map(|c| c.id))
        {
            Ok(Some(id)) => Ok(collection_path(id)),
            Ok(None) => Ok(root()),
            // Locked: the default alias stands for its collection.
            Err(_) if name == "default" => Ok(alias_path("default")),
            Err(_) => Ok(root()),
        }
    }

    async fn set_alias(&self, name: String, collection: OwnedObjectPath) -> Result<()> {
        if !valid_alias(&name) {
            return Err(SecretError::ZBus(zbus::Error::Failure(format!(
                "invalid alias {name:?}"
            ))));
        }
        let target = collection
            .as_str()
            .strip_prefix(COLLECTION_PREFIX)
            .and_then(|s| Uuid::try_parse(s).ok());
        self.svc
            .modify(move |b| {
                match target {
                    Some(id) if b.collection(id).is_some() => {
                        b.aliases.insert(name, id);
                    }
                    None if collection.as_str() == "/" => {
                        b.aliases.remove(&name);
                    }
                    _ => return Err(Error::NotFound),
                }
                Ok(())
            })
            .await?;
        self.svc.sync().await?;
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        self.svc
            .keyring
            .read(|b| {
                b.collections
                    .iter()
                    .map(|c| collection_path(c.id))
                    .collect()
            })
            .unwrap_or_else(|_| vec![alias_path("default")])
    }

    #[zbus(signal)]
    async fn collection_created(
        emitter: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_deleted(
        emitter: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn collection_changed(
        emitter: &SignalEmitter<'_>,
        collection: ObjectPath<'_>,
    ) -> zbus::Result<()>;
}

struct CollectionObj {
    svc: Arc<SecretService>,
    target: Target,
}

impl CollectionObj {
    fn id(&self) -> Result<Uuid> {
        Ok(self.svc.resolve(&self.target)?)
    }

    fn with<T>(&self, f: impl FnOnce(&Collection) -> T) -> Result<T> {
        let id = self.id()?;
        Ok(self
            .svc
            .keyring
            .read(|b| b.collection(id).map(f))?
            .ok_or(Error::NotFound)?)
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionObj {
    async fn delete(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> Result<OwnedObjectPath> {
        let id = self.id()?;
        let owner = hdr.sender().map(|s| s.to_string());
        self.svc.prompt(Action::DeleteCollection(id), owner).await
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>> {
        if self.svc.keyring.is_locked() {
            return Ok(vec![self.svc.placeholder(attributes).await?]);
        }
        let query: BTreeMap<String, String> = attributes.into_iter().collect();
        self.with(|c| {
            c.items
                .iter()
                .filter(|i| i.matches(&query))
                .map(|i| item_path(c.id, i.id))
                .collect()
        })
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let id = self.id()?;
        let label = properties
            .get(ITEM_LABEL)
            .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let attributes: BTreeMap<String, String> = properties
            .get(ITEM_ATTRIBUTES)
            .and_then(|v| HashMap::<String, String>::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let value = self.svc.decrypt(&secret)?;
        let item = Item::new(label, attributes, value, secret.3.clone());
        let before: HashSet<Uuid> = self
            .svc
            .keyring
            .read(|b| {
                b.collection(id)
                    .map(|c| c.items.iter().map(|i| i.id).collect())
            })?
            .unwrap_or_default();
        let item_id = self
            .svc
            .modify(move |b| {
                let c = b.collection_mut(id).ok_or(Error::NotFound)?;
                Ok(c.upsert(item, replace))
            })
            .await?;
        self.svc.sync().await?;
        let p = item_path(id, item_id);
        // From the collection's own path, even if called through an alias.
        let emitter = SignalEmitter::new(self.svc.conn(), collection_path(id))?;
        if before.contains(&item_id) {
            Self::item_changed(&emitter, p.as_ref()).await?;
        } else {
            Self::item_created(&emitter, p.as_ref()).await?;
        }
        Ok((p, root()))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        self.with(|c| c.items.iter().map(|i| item_path(c.id, i.id)).collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        self.with(|c| c.label.clone()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> zbus::fdo::Result<()> {
        let id = self
            .id()
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:?}")))?;
        self.svc
            .modify(move |b| {
                b.collection_mut(id).ok_or(Error::NotFound)?.label = label;
                Ok(())
            })
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.svc.keyring.is_locked()
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        self.with(|c| c.created).unwrap_or_default()
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        self.with(|c| c.modified).unwrap_or_default()
    }

    #[zbus(signal)]
    async fn item_created(emitter: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_deleted(emitter: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn item_changed(emitter: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;
}

struct ItemObj {
    svc: Arc<SecretService>,
    collection: Uuid,
    item: Uuid,
}

impl ItemObj {
    fn with<T>(&self, f: impl FnOnce(&Item) -> T) -> Result<T> {
        let (c, i) = (self.collection, self.item);
        Ok(self
            .svc
            .keyring
            .read(|b| {
                b.collection(c)
                    .and_then(|c| c.items.iter().find(|x| x.id == i))
                    .map(f)
            })?
            .ok_or(Error::NotFound)?)
    }

    async fn edit(
        &self,
        f: impl FnOnce(&mut Item) + Send + 'static,
    ) -> std::result::Result<(), Error> {
        let (c, i) = (self.collection, self.item);
        self.svc
            .modify(move |b| {
                let item = b
                    .collection_mut(c)
                    .and_then(|c| c.items.iter_mut().find(|x| x.id == i))
                    .ok_or(Error::NotFound)?;
                f(item);
                item.modified = aleph_core::model::now();
                Ok(())
            })
            .await
    }

    async fn changed(&self) -> zbus::Result<()> {
        let emitter = SignalEmitter::new(self.svc.conn(), collection_path(self.collection))?;
        CollectionObj::item_changed(&emitter, item_path(self.collection, self.item).as_ref()).await
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemObj {
    async fn delete(&self) -> Result<OwnedObjectPath> {
        let (c, i) = (self.collection, self.item);
        self.svc
            .modify(move |b| {
                b.collection_mut(c)
                    .and_then(|c| c.remove(i))
                    .ok_or(Error::NotFound)?;
                Ok(())
            })
            .await?;
        self.svc.sync().await?;
        let emitter = SignalEmitter::new(self.svc.conn(), collection_path(c))?;
        CollectionObj::item_deleted(&emitter, item_path(c, i).as_ref()).await?;
        Ok(root())
    }

    /// One struct out-argument, `((oayays))`: a bare tuple would be sent as
    /// four arguments, which libsecret rejects.
    #[zbus(out_args("secret"))]
    async fn get_secret(&self, session: OwnedObjectPath) -> Result<(SecretStruct,)> {
        let item = self.with(Item::clone)?;
        Ok((self.svc.secret_for(&session.as_ref(), &item)?,))
    }

    async fn set_secret(&self, secret: SecretStruct) -> Result<()> {
        let value = self.svc.decrypt(&secret)?;
        let content_type = secret.3.clone();
        self.edit(move |i| {
            i.secret = value;
            i.content_type = content_type;
        })
        .await?;
        self.changed().await?;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.svc.keyring.is_locked()
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        self.with(|i| i.attributes.clone().into_iter().collect())
            .unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_attributes(
        &mut self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<()> {
        self.edit(move |i| i.attributes = attributes.into_iter().collect())
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        let _ = self.changed().await;
        Ok(())
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        self.with(|i| i.label.clone()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> zbus::fdo::Result<()> {
        self.edit(move |i| i.label = label)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        let _ = self.changed().await;
        Ok(())
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        self.with(|i| i.created).unwrap_or_default()
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        self.with(|i| i.modified).unwrap_or_default()
    }
}

/// A locked search's stand-in: an item that is always locked. `Unlock` on
/// it resolves to the items the search finds once the vault is open.
struct PlaceholderObj {
    query: HashMap<String, String>,
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl PlaceholderObj {
    async fn delete(&self) -> Result<OwnedObjectPath> {
        Err(SecretError::IsLocked("the keyring is locked".into()))
    }

    async fn get_secret(&self, _session: OwnedObjectPath) -> Result<(SecretStruct,)> {
        Err(SecretError::IsLocked("the keyring is locked".into()))
    }

    async fn set_secret(&self, _secret: SecretStruct) -> Result<()> {
        Err(SecretError::IsLocked("the keyring is locked".into()))
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        true
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        self.query.clone()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        "Locked keyring".into()
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        0
    }
}

struct SessionObj {
    svc: Arc<SecretService>,
    path: OwnedObjectPath,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionObj {
    async fn close(&self, #[zbus(object_server)] server: &zbus::ObjectServer) -> Result<()> {
        self.svc.sessions.lock().unwrap().remove(&self.path);
        server.remove::<SessionObj, _>(self.path.as_ref()).await?;
        Ok(())
    }
}

struct PromptObj {
    svc: Arc<SecretService>,
    path: OwnedObjectPath,
    action: Action,
    /// `Prompt` runs once; a repeated call is ignored.
    started: std::sync::atomic::AtomicBool,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptObj {
    /// Start the prompt; the answer arrives as `Completed`.
    async fn prompt(
        &self,
        _window_id: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<()> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let client = hdr.sender().map(|s| s.to_string());
        let who = caller(conn, &hdr).await;
        let (svc, action, p) = (self.svc.clone(), self.action.clone(), self.path.clone());
        let unlocking = matches!(action, Action::Unlock(_));
        let empty = action.empty_result();
        tokio::spawn(async move {
            let run = svc.clone();
            let targets = match &action {
                Action::Unlock(targets) => targets.clone(),
                _ => Vec::new(),
            };
            let collection_signal = match &action {
                Action::DeleteCollection(id) => Some((false, collection_path(*id))),
                _ => None,
            };
            let creating = matches!(action, Action::CreateCollection { .. });
            let outcome = tokio::task::spawn_blocking(move || run.run(&action, who))
                .await
                .unwrap_or(Outcome::Dismissed);
            match outcome {
                Outcome::Done(value) if unlocking => {
                    // Serve the objects, then complete this prompt and any
                    // others that were waiting.
                    let _ = svc.unlocked().await;
                    finish(&svc, &p, Some(value), empty).await;
                }
                Outcome::Done(value) => {
                    let _ = svc.sync().await;
                    let signal = if creating {
                        value
                            .try_clone()
                            .ok()
                            .and_then(|v| OwnedObjectPath::try_from(v).ok())
                            .map(|c| (true, c))
                    } else {
                        collection_signal
                    };
                    if let (Some((created, c)), Ok(emitter)) =
                        (signal, SignalEmitter::new(svc.conn(), SERVICE_PATH))
                    {
                        let _ = if created {
                            ServiceObj::collection_created(&emitter, c.as_ref()).await
                        } else {
                            ServiceObj::collection_deleted(&emitter, c.as_ref()).await
                        };
                    }
                    finish(&svc, &p, Some(value), empty).await;
                }
                Outcome::Dismissed => {
                    finish(&svc, &p, None, empty).await;
                    if unlocking {
                        svc.end_dismissed_joiners().await;
                    }
                }
                Outcome::Wait | Outcome::Joined(_) => {
                    let joined = match outcome {
                        Outcome::Joined(id) => Some(id),
                        _ => None,
                    };
                    let admitted = {
                        let mut waiting = svc.waiting.lock().unwrap();
                        let mine = waiting.iter().filter(|w| w.client == client).count();
                        let ok = mine < MAX_WAITING_PER_CLIENT && waiting.len() < MAX_WAITING;
                        if ok {
                            waiting.push(Waiting {
                                prompt: p.clone(),
                                client: client.clone(),
                                targets,
                                joined,
                            });
                        }
                        ok
                    };
                    if !admitted {
                        finish(&svc, &p, None, empty).await;
                        return;
                    }
                    // The conversation may have been dismissed while this
                    // prompt was joining it.
                    if joined.is_some() {
                        svc.end_dismissed_joiners().await;
                    }
                    svc.gone_already(client.as_deref()).await;
                    // Unlocked meanwhile? Then complete now.
                    if !svc.keyring.is_locked() {
                        let _ = svc.unlocked().await;
                    }
                }
            }
        });
        Ok(())
    }

    async fn dismiss(&self) -> Result<()> {
        self.svc
            .waiting
            .lock()
            .unwrap()
            .retain(|w| w.prompt != self.path);
        finish(&self.svc, &self.path, None, self.action.empty_result()).await;
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

impl Action {
    /// The result a dismissed prompt carries: an empty value of the type a
    /// completed one would. libsecret checks the type even when dismissed,
    /// and a mismatch (e.g. `s` for an unlock's `ao`) hangs it.
    fn empty_result(&self) -> OwnedValue {
        match self {
            Action::Unlock(_) => empty_paths(),
            Action::CreateCollection { .. } | Action::DeleteCollection(_) => path_value(root()),
        }
    }
}

fn empty_paths() -> OwnedValue {
    OwnedValue::try_from(Value::from(Vec::<OwnedObjectPath>::new())).expect("ao is a value")
}

/// Emit `Completed` (with `result`, or dismissed with `empty`) and retire
/// the prompt object.
async fn finish(
    svc: &Arc<SecretService>,
    p: &OwnedObjectPath,
    result: Option<OwnedValue>,
    empty: OwnedValue,
) {
    // Exactly once: a prompt dismissed while it runs is already finished.
    if svc.prompts.lock().unwrap().remove(p).is_none() {
        return;
    }
    if let Ok(emitter) = SignalEmitter::new(svc.conn(), p.as_ref()) {
        let (dismissed, value) = match result {
            Some(v) => (false, Value::from(v)),
            None => (true, Value::from(empty)),
        };
        let _ = PromptObj::completed(&emitter, dismissed, value).await;
    }
    let _ = svc
        .conn()
        .object_server()
        .remove::<PromptObj, _>(p.as_ref())
        .await;
}
