//! Importing from gnome-keyring (spec §7 "Import"; DECISIONS.md E1, E2).
//!
//! alephd, queued behind gnome-keyring for `org.freedesktop.secrets`, reads
//! every collection and item through gnome-keyring's own Secret Service API
//! over an encrypted session (secrets never pass through the CLI), and
//! merges them into the vault:
//! - idempotent and never overwriting: an item already here (same
//!   collection, label, and attributes) with the same secret is left as it
//!   is; with a different secret it is a conflict, skipped and listed. Only
//!   items that existed before a merge count, so duplicates within
//!   gnome-keyring itself all arrive;
//! - content types, attributes (`xdg:schema` included), and timestamps are
//!   kept; the transient `session` collection is skipped;
//! - a locked collection is unlocked through gnome-keyring's own prompt; a
//!   dismissed (or unanswered) prompt skips that collection, and a re-run
//!   picks it up.
//!
//! After the first pass it keeps following gnome-keyring's item signals
//! (subscribed before listing) until the name changes hands, so nothing
//! stored in between is lost.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aleph_core::{Body, Item, SecretBytes};
use futures_util::StreamExt;
use zbus::Connection;
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use crate::error::{Error, Result};
use crate::keyring::Keyring;
use crate::secret::service::SecretService;
use crate::secret::session::{ClientDh, DH, Session};

pub const SECRETS_NAME: &str = "org.freedesktop.secrets";
const SECRETS_PATH: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const PROMPT: &str = "org.freedesktop.Secret.Prompt";
/// The transient collection gnome-keyring keeps in memory only.
const SESSION_COLLECTION: &str = "/org/freedesktop/secrets/collection/session";

/// One item as read from gnome-keyring.
pub struct Fetched {
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: SecretBytes,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

/// One collection as read from gnome-keyring.
pub struct FetchedCollection {
    pub label: String,
    /// gnome-keyring's default collection (its items go to aleph's).
    pub is_default: bool,
    pub items: Vec<Fetched>,
}

/// An item an import added, as it was (for revert: items imported and
/// deleted in aleph since are listed, E3).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportedItem {
    pub id: uuid::Uuid,
    pub collection: String,
    pub is_default: bool,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
}

/// The items imported so far (`imported.json`).
pub fn load_imported(path: &Path) -> Vec<ImportedItem> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Add `items` to the record.
pub fn record_imported(path: &Path, items: &[ImportedItem]) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let mut all = load_imported(path);
    all.extend_from_slice(items);
    let bytes = serde_json::to_vec_pretty(&all).map_err(gk)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Imported items no longer in `body` (deleted in aleph since).
pub fn removed_since(imported: &[ImportedItem], body: &Body) -> Vec<ImportedItem> {
    imported
        .iter()
        .filter(|i| {
            !body
                .collections
                .iter()
                .any(|c| c.items.iter().any(|x| x.id == i.id))
        })
        .cloned()
        .collect()
}

/// What an import did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub imported: usize,
    pub unchanged: usize,
    /// Imported items gnome-keyring changed since (followed).
    pub updated: usize,
    /// Items skipped because a different secret is already here.
    pub conflicts: Vec<String>,
    /// Collections skipped, with the reason.
    pub skipped: Vec<String>,
    /// The items added (recorded for revert).
    pub added: Vec<ImportedItem>,
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Imported {} item(s) from gnome-keyring ({} already here",
            self.imported, self.unchanged
        )?;
        if self.updated > 0 {
            write!(f, ", {} updated", self.updated)?;
        }
        write!(f, ").")?;
        if !self.conflicts.is_empty() {
            write!(
                f,
                " Skipped, a different secret is already here: {}.",
                self.conflicts.join(", ")
            )?;
        }
        if !self.skipped.is_empty() {
            write!(f, " Not imported: {}.", self.skipped.join("; "))?;
        }
        Ok(())
    }
}

/// The schema gnome-keyring adds to an item stored without one.
const GENERIC_SCHEMA: &str = "org.freedesktop.Secret.Generic";

/// Whether `a` and `b` are the same item's attributes: equal, except that
/// one may carry the generic schema gnome-keyring adds (at times after the
/// item is first read) where the other has none.
pub fn same_attributes(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> bool {
    fn schema(m: &BTreeMap<String, String>) -> Option<&str> {
        m.get("xdg:schema").map(String::as_str)
    }
    fn rest(m: &BTreeMap<String, String>) -> impl Iterator<Item = (&String, &String)> {
        m.iter().filter(|(k, _)| *k != "xdg:schema")
    }
    match (schema(a), schema(b)) {
        (x, y) if x == y => a == b,
        (None, Some(GENERIC_SCHEMA)) | (Some(GENERIC_SCHEMA), None) => rest(a).eq(rest(b)),
        _ => false,
    }
}

/// An item already in the target collection: id, label, attributes, secret.
type Before = (uuid::Uuid, String, BTreeMap<String, String>, Vec<u8>);

/// Merge `fetched` into `body` (see the module comment for the rules).
pub fn merge(body: &mut Body, fetched: Vec<FetchedCollection>, summary: &mut Summary) {
    merge_following(body, fetched, summary, &std::collections::HashSet::new());
}

/// `merge`, where a different secret for an item in `updatable` (one the
/// import brought, followed until the switchover) updates it instead of
/// being a conflict: gnome-keyring still owns it then.
pub fn merge_following(
    body: &mut Body,
    fetched: Vec<FetchedCollection>,
    summary: &mut Summary,
    updatable: &std::collections::HashSet<uuid::Uuid>,
) {
    for collection in fetched {
        let target = if collection.is_default {
            body.resolve_alias(aleph_core::model::DEFAULT_ALIAS)
                .map(|c| c.id)
        } else {
            body.collections
                .iter()
                .find(|c| c.label == collection.label)
                .map(|c| c.id)
        };
        let id = match target {
            Some(id) => id,
            None => {
                let c = aleph_core::Collection::new(collection.label.clone());
                let id = c.id;
                body.collections.push(c);
                id
            }
        };
        let target = body.collection_mut(id).expect("just found or created");
        // Only what was here before this merge counts.
        let before: Vec<Before> = target
            .items
            .iter()
            .map(|i| {
                (
                    i.id,
                    i.label.clone(),
                    i.attributes.clone(),
                    i.secret.expose().to_vec(),
                )
            })
            .collect();
        for f in collection.items {
            let same: Vec<_> = before
                .iter()
                .filter(|(_, l, a, _)| *l == f.label && same_attributes(a, &f.attributes))
                .collect();
            if same.iter().any(|(_, _, _, s)| s == f.secret.expose()) {
                summary.unchanged += 1;
                continue;
            }
            if let Some((id, ..)) = same.iter().find(|(id, ..)| updatable.contains(id))
                && let Some(item) = target.items.iter_mut().find(|i| i.id == *id)
            {
                item.secret = f.secret;
                item.attributes = f.attributes;
                item.content_type = f.content_type;
                item.modified = f.modified.max(aleph_core::model::now());
                summary.updated += 1;
                continue;
            }
            if !same.is_empty() {
                summary
                    .conflicts
                    .push(format!("{} ({})", f.label, collection.label));
                continue;
            }
            summary.added.push(ImportedItem {
                id: uuid::Uuid::nil(),
                collection: collection.label.clone(),
                is_default: collection.is_default,
                label: f.label.clone(),
                attributes: f.attributes.clone(),
            });
            let mut item = Item::new(f.label, f.attributes, f.secret, f.content_type);
            item.created = f.created;
            item.modified = f.modified;
            let id = target.upsert(item, false);
            summary.added.last_mut().expect("just pushed").id = id;
            summary.imported += 1;
        }
    }
}

fn gk(e: impl std::fmt::Display) -> Error {
    Error::Invalid(format!("reading gnome-keyring: {e}"))
}

/// A connection to gnome-keyring's Secret Service, with an open encrypted
/// session and its item signals already subscribed.
pub struct Importer {
    conn: Connection,
    owner: String,
    session: Session,
    session_path: OwnedObjectPath,
    events: zbus::MessageStream,
    prompt_timeout: Duration,
}

impl Importer {
    /// `None` if nothing else owns `org.freedesktop.secrets` (gnome-keyring
    /// is not running, or this daemon already owns the name).
    pub async fn connect(conn: &Connection, prompt_timeout: Duration) -> Result<Option<Self>> {
        let dbus = zbus::fdo::DBusProxy::new(conn).await.map_err(gk)?;
        let name = zbus::names::BusName::try_from(SECRETS_NAME).map_err(gk)?;
        let owner = match dbus.get_name_owner(name).await {
            Ok(owner) => owner.to_string(),
            Err(_) => return Ok(None),
        };
        if conn.unique_name().is_some_and(|me| me.as_str() == owner) {
            return Ok(None);
        }
        // Subscribe before listing: nothing stored meanwhile is missed.
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(owner.as_str())
            .map_err(gk)?
            .interface(COLLECTION)
            .map_err(gk)?
            .build();
        let events = zbus::MessageStream::for_match_rule(rule, conn, Some(256))
            .await
            .map_err(gk)?;
        let service = proxy(conn, &owner, SECRETS_PATH, SERVICE).await?;
        let dh = ClientDh::new().map_err(gk)?;
        let (output, session_path): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &(DH, Value::from(dh.public.clone())))
            .await
            .map_err(gk)?;
        let server_public: Vec<u8> = output.try_into().map_err(gk)?;
        let session = dh.finish(&server_public).map_err(gk)?;
        Ok(Some(Self {
            conn: conn.clone(),
            owner,
            session,
            session_path,
            events,
            prompt_timeout,
        }))
    }

    /// Every collection (but `session`) and item. Collections that stay
    /// locked are listed in `skipped` with the reason.
    pub async fn fetch_all(&self, skipped: &mut Vec<String>) -> Result<Vec<FetchedCollection>> {
        let service = proxy(&self.conn, &self.owner, SECRETS_PATH, SERVICE).await?;
        let paths: Vec<OwnedObjectPath> = service.get_property("Collections").await.map_err(gk)?;
        let default: OwnedObjectPath =
            service.call("ReadAlias", &("default",)).await.map_err(gk)?;
        let mut out = Vec::new();
        for path in paths {
            if path.as_str() == SESSION_COLLECTION {
                continue;
            }
            let c = proxy(&self.conn, &self.owner, path.as_str(), COLLECTION).await?;
            let label: String = c.get_property("Label").await.map_err(gk)?;
            let locked: bool = c.get_property("Locked").await.map_err(gk)?;
            if locked && !self.unlock(&service, &path).await? {
                skipped.push(format!(
                    "{label} (locked; its unlock was dismissed; run the import again to retry)"
                ));
                continue;
            }
            let items: Vec<OwnedObjectPath> = c.get_property("Items").await.map_err(gk)?;
            out.push(FetchedCollection {
                label,
                is_default: path == default,
                items: self.fetch_items(&items).await?,
            });
        }
        Ok(out)
    }

    /// Unlock one collection through gnome-keyring's prompt; `false` if the
    /// prompt was dismissed or not answered in time.
    async fn unlock(&self, service: &zbus::Proxy<'_>, path: &OwnedObjectPath) -> Result<bool> {
        let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
            .call("Unlock", &(vec![path.clone()],))
            .await
            .map_err(gk)?;
        if unlocked.contains(path) {
            return Ok(true);
        }
        if prompt.as_str() == "/" {
            return Ok(false);
        }
        let p = proxy(&self.conn, &self.owner, prompt.as_str(), PROMPT).await?;
        let mut completed = p.receive_signal("Completed").await.map_err(gk)?;
        if p.call_method("Prompt", &("",)).await.is_err() {
            return Ok(false);
        }
        match tokio::time::timeout(self.prompt_timeout, completed.next()).await {
            Ok(Some(msg)) => {
                let (dismissed, _): (bool, OwnedValue) = msg.body().deserialize().map_err(gk)?;
                Ok(!dismissed)
            }
            _ => Ok(false),
        }
    }

    async fn fetch_items(&self, items: &[OwnedObjectPath]) -> Result<Vec<Fetched>> {
        if items.is_empty() {
            return Ok(Vec::new());
        }
        let service = proxy(&self.conn, &self.owner, SECRETS_PATH, SERVICE).await?;
        type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
        let secrets: HashMap<OwnedObjectPath, Secret> = service
            .call("GetSecrets", &(items.to_vec(), self.session_path.clone()))
            .await
            .map_err(gk)?;
        let mut out = Vec::new();
        for path in items {
            // (An item deleted meanwhile has no secret: skipped.)
            let Some((_, parameters, value, content_type)) = secrets.get(path) else {
                continue;
            };
            let i = proxy(&self.conn, &self.owner, path.as_str(), ITEM).await?;
            let attributes: HashMap<String, String> =
                i.get_property("Attributes").await.map_err(gk)?;
            let secret = self.session.decrypt(parameters, value).map_err(gk)?;
            out.push(Fetched {
                label: i.get_property("Label").await.map_err(gk)?,
                attributes: attributes.into_iter().collect(),
                secret: SecretBytes::new(secret.to_vec()),
                content_type: content_type.clone(),
                created: i.get_property("Created").await.unwrap_or(0),
                modified: i.get_property("Modified").await.unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Keep importing items gnome-keyring creates or changes until
    /// `org.freedesktop.secrets` changes hands (E1).
    pub async fn follow(
        mut self,
        keyring: Arc<Keyring>,
        secrets: Arc<SecretService>,
        record: PathBuf,
    ) {
        let Ok(dbus) = zbus::fdo::DBusProxy::new(&self.conn).await else {
            return;
        };
        let Ok(mut owner_changes) = dbus
            .receive_name_owner_changed_with_args(&[(0, SECRETS_NAME)])
            .await
        else {
            return;
        };
        let mut labels: HashMap<String, (String, bool)> = HashMap::new();
        loop {
            // (Item signals first: one sent just before gnome-keyring let
            // go is still taken.)
            let msg = tokio::select! {
                biased;
                msg = self.events.next() => match msg {
                    Some(Ok(msg)) => msg,
                    Some(Err(_)) => continue,
                    None => return,
                },
                _ = owner_changes.next() => return,
            };
            let header = msg.header();
            let member = header.member().map(|m| m.as_str().to_string());
            if !matches!(member.as_deref(), Some("ItemCreated" | "ItemChanged")) {
                continue;
            }
            let Some(collection) = header.path().map(|p| p.as_str().to_string()) else {
                continue;
            };
            let Ok(item) = msg.body().deserialize::<OwnedObjectPath>() else {
                continue;
            };
            if collection == SESSION_COLLECTION {
                continue;
            }
            if let Err(e) = self
                .import_one(&keyring, &mut labels, &collection, item, &record)
                .await
            {
                tracing::warn!("following gnome-keyring: {e}");
                continue;
            }
            let _ = secrets.unlocked().await;
        }
    }

    async fn import_one(
        &self,
        keyring: &Arc<Keyring>,
        labels: &mut HashMap<String, (String, bool)>,
        collection: &str,
        item: OwnedObjectPath,
        record: &Path,
    ) -> Result<()> {
        if !labels.contains_key(collection) {
            let c = proxy(&self.conn, &self.owner, collection, COLLECTION).await?;
            let service = proxy(&self.conn, &self.owner, SECRETS_PATH, SERVICE).await?;
            let default: OwnedObjectPath =
                service.call("ReadAlias", &("default",)).await.map_err(gk)?;
            let label: String = c.get_property("Label").await.map_err(gk)?;
            labels.insert(
                collection.to_string(),
                (label, default.as_str() == collection),
            );
        }
        let (label, is_default) = labels[collection].clone();
        let items = self.fetch_items(&[item]).await?;
        let keyring = keyring.clone();
        let updatable: std::collections::HashSet<uuid::Uuid> =
            load_imported(record).into_iter().map(|i| i.id).collect();
        let summary = tokio::task::spawn_blocking(move || {
            keyring.modify(|body| {
                let mut summary = Summary::default();
                merge_following(
                    body,
                    vec![FetchedCollection {
                        label,
                        is_default,
                        items,
                    }],
                    &mut summary,
                    &updatable,
                );
                Ok(summary)
            })
        })
        .await
        .map_err(gk)??;
        record_imported(record, &summary.added)?;
        if !summary.conflicts.is_empty() {
            tracing::info!(
                "gnome-keyring changed an item after it was imported; kept aleph's: {}",
                summary.conflicts.join(", ")
            );
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fetched(label: &str, attrs: &[(&str, &str)], secret: &[u8]) -> Fetched {
        Fetched {
            label: label.into(),
            attributes: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            secret: SecretBytes::new(secret.to_vec()),
            content_type: "application/octet-stream".into(),
            created: 111,
            modified: 222,
        }
    }

    fn body() -> Body {
        Body::default()
    }

    /// Attributes match exactly: an item with more (or fewer) is another
    /// item (`SearchItems` alone matches at least the attributes given).
    #[test]
    fn attributes_match_exactly() {
        let m = |p: &[(&str, &str)]| -> BTreeMap<String, String> {
            p.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert!(same_attributes(&m(&[("k", "t")]), &m(&[("k", "t")])));
        assert!(!same_attributes(
            &m(&[("k", "t")]),
            &m(&[("k", "t"), ("extra", "1")])
        ));
        assert!(!same_attributes(
            &m(&[("k", "t"), ("extra", "1")]),
            &m(&[("k", "t")])
        ));
        assert!(!same_attributes(&m(&[("k", "t")]), &m(&[("k", "u")])));
    }

    /// gnome-keyring adds the generic schema to an item stored without one,
    /// sometimes after the item is first read: the same item either way.
    #[test]
    fn the_generic_schema_gnome_keyring_adds_is_the_same_item() {
        let one = |attrs: &[(&str, &str)], secret: &[u8]| {
            vec![FetchedCollection {
                label: "Login".into(),
                is_default: true,
                items: vec![fetched("token", attrs, secret)],
            }]
        };
        let mut b = body();
        let mut s = Summary::default();
        merge(&mut b, one(&[("k", "t")], b"v1"), &mut s);
        let ids = s.added.iter().map(|i| i.id).collect();
        let generic = [("k", "t"), ("xdg:schema", "org.freedesktop.Secret.Generic")];
        let mut s = Summary::default();
        merge_following(&mut b, one(&generic, b"v2"), &mut s, &ids);
        assert_eq!((s.imported, s.updated), (0, 1));
        let items = &b.collections[0].items;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].secret.expose(), b"v2");
        // (Another schema is another item.)
        let mut s = Summary::default();
        merge(
            &mut b,
            one(&[("k", "t"), ("xdg:schema", "org.x")], b"v2"),
            &mut s,
        );
        assert_eq!(s.imported, 1);
    }

    /// Default collection to aleph's default; others by label (created);
    /// attributes, content type, and timestamps kept.
    #[test]
    fn items_arrive_with_everything_kept() {
        let mut b = body();
        let mut s = Summary::default();
        merge(
            &mut b,
            vec![
                FetchedCollection {
                    label: "Login".into(),
                    is_default: true,
                    items: vec![fetched(
                        "mail",
                        &[("xdg:schema", "org.x"), ("u", "a")],
                        b"pw",
                    )],
                },
                FetchedCollection {
                    label: "Work".into(),
                    is_default: false,
                    items: vec![fetched("vpn", &[("h", "v")], b"k")],
                },
            ],
            &mut s,
        );
        assert_eq!(s.imported, 2);
        let default = b.resolve_alias(aleph_core::model::DEFAULT_ALIAS).unwrap();
        let mail = &default.items[0];
        assert_eq!(mail.attributes["xdg:schema"], "org.x");
        assert_eq!(mail.content_type, "application/octet-stream");
        assert_eq!((mail.created, mail.modified), (111, 222));
        assert!(
            b.collections
                .iter()
                .any(|c| c.label == "Work" && c.items.len() == 1)
        );
    }

    /// A second import changes nothing; a different secret already here is
    /// a conflict, skipped and listed; duplicates within gnome-keyring all
    /// arrive.
    #[test]
    fn import_is_idempotent_and_never_overwrites() {
        let mut b = body();
        let one = || FetchedCollection {
            label: "Login".into(),
            is_default: true,
            items: vec![fetched("mail", &[("u", "a")], b"pw")],
        };
        merge(&mut b, vec![one()], &mut Summary::default());
        let mut s = Summary::default();
        merge(&mut b, vec![one()], &mut s);
        assert_eq!((s.imported, s.unchanged), (0, 1));
        let mut s = Summary::default();
        merge(
            &mut b,
            vec![FetchedCollection {
                label: "Login".into(),
                is_default: true,
                items: vec![
                    fetched("mail", &[("u", "a")], b"other"),
                    fetched("dup", &[("d", "1")], b"x"),
                    fetched("dup", &[("d", "1")], b"x"),
                ],
            }],
            &mut s,
        );
        assert_eq!(s.conflicts, ["mail (Login)"]);
        assert_eq!(s.imported, 2);
        let default = b.resolve_alias(aleph_core::model::DEFAULT_ALIAS).unwrap();
        assert_eq!(default.items[0].secret.expose(), b"pw");
        assert!(s.to_string().contains("mail (Login)"));
    }
}
