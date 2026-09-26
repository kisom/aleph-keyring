//! The decrypted vault body: collections of items, as the Secret Service
//! models them.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_ALIAS: &str = "default";
pub const LOGIN_COLLECTION_LABEL: &str = "Login";

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Secret bytes: zeroized on drop, redacted in `Debug`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretBytes(#[serde(with = "serde_bytes")] Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub secret: SecretBytes,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

impl Item {
    pub fn new(
        label: impl Into<String>,
        attributes: BTreeMap<String, String>,
        secret: SecretBytes,
        content_type: impl Into<String>,
    ) -> Self {
        let t = now();
        Self {
            id: Uuid::new_v4(),
            label: label.into(),
            attributes,
            secret,
            content_type: content_type.into(),
            created: t,
            modified: t,
        }
    }

    /// True if every `(key, value)` in `query` is present on this item.
    /// An empty query matches everything, as in the Secret Service spec.
    pub fn matches(&self, query: &BTreeMap<String, String>) -> bool {
        query.iter().all(|(k, v)| self.attributes.get(k) == Some(v))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collection {
    pub id: Uuid,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    pub items: Vec<Item>,
}

impl Collection {
    pub fn new(label: impl Into<String>) -> Self {
        let t = now();
        Self {
            id: Uuid::new_v4(),
            label: label.into(),
            created: t,
            modified: t,
            items: Vec::new(),
        }
    }

    pub fn search<'a>(
        &'a self,
        query: &'a BTreeMap<String, String>,
    ) -> impl Iterator<Item = &'a Item> + 'a {
        self.items.iter().filter(move |i| i.matches(query))
    }

    /// Add `item`. With `replace`, an existing item whose attributes are
    /// exactly equal is updated in place (keeping its id and `created`),
    /// matching `CreateItem(replace=true)`. Returns the stored item's id.
    pub fn upsert(&mut self, mut item: Item, replace: bool) -> Uuid {
        self.modified = now();
        if replace
            && let Some(existing) = self
                .items
                .iter_mut()
                .find(|i| i.attributes == item.attributes)
        {
            item.id = existing.id;
            item.created = existing.created;
            item.modified = self.modified;
            *existing = item;
            return existing.id;
        }
        let id = item.id;
        self.items.push(item);
        id
    }

    pub fn remove(&mut self, id: Uuid) -> Option<Item> {
        let pos = self.items.iter().position(|i| i.id == id)?;
        self.modified = now();
        Some(self.items.remove(pos))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    pub collections: Vec<Collection>,
    /// Alias name → collection id (e.g. `default` → the login collection).
    pub aliases: BTreeMap<String, Uuid>,
}

impl Default for Body {
    /// A new vault: one `Login` collection, aliased as `default`.
    fn default() -> Self {
        let login = Collection::new(LOGIN_COLLECTION_LABEL);
        let aliases = BTreeMap::from([(DEFAULT_ALIAS.to_string(), login.id)]);
        Self {
            collections: vec![login],
            aliases,
        }
    }
}

impl Body {
    pub fn collection(&self, id: Uuid) -> Option<&Collection> {
        self.collections.iter().find(|c| c.id == id)
    }

    pub fn collection_mut(&mut self, id: Uuid) -> Option<&mut Collection> {
        self.collections.iter_mut().find(|c| c.id == id)
    }

    pub fn resolve_alias(&self, alias: &str) -> Option<&Collection> {
        self.aliases.get(alias).and_then(|id| self.collection(*id))
    }

    /// Remove a collection and any aliases pointing at it.
    pub fn remove_collection(&mut self, id: Uuid) -> Option<Collection> {
        let pos = self.collections.iter().position(|c| c.id == id)?;
        self.aliases.retain(|_, target| *target != id);
        Some(self.collections.remove(pos))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn item(pairs: &[(&str, &str)], secret: &[u8]) -> Item {
        Item::new(
            "label",
            attrs(pairs),
            SecretBytes::new(secret.to_vec()),
            "text/plain",
        )
    }

    #[test]
    fn default_body_has_login_collection_aliased_default() {
        let body = Body::default();
        assert_eq!(body.collections.len(), 1);
        assert_eq!(
            body.resolve_alias(DEFAULT_ALIAS).unwrap().label,
            LOGIN_COLLECTION_LABEL
        );
    }

    #[test]
    fn search_requires_all_query_attributes() {
        let mut c = Collection::new("c");
        c.upsert(
            item(&[("service", "github"), ("user", "kyle")], b"1"),
            false,
        );
        c.upsert(item(&[("service", "github"), ("user", "bot")], b"2"), false);
        assert_eq!(c.search(&attrs(&[("service", "github")])).count(), 2);
        assert_eq!(
            c.search(&attrs(&[("service", "github"), ("user", "kyle")]))
                .count(),
            1
        );
        assert_eq!(c.search(&attrs(&[("service", "gitlab")])).count(), 0);
        assert_eq!(c.search(&BTreeMap::new()).count(), 2);
    }

    #[test]
    fn upsert_replace_updates_in_place_keeping_id_and_created() {
        let mut c = Collection::new("c");
        let first = c.upsert(item(&[("k", "v")], b"old"), true);
        let created = c.items[0].created;
        let second = c.upsert(item(&[("k", "v")], b"new"), true);
        assert_eq!(first, second);
        assert_eq!(c.items.len(), 1);
        assert_eq!(c.items[0].secret.expose(), b"new");
        assert_eq!(c.items[0].created, created);
    }

    #[test]
    fn upsert_without_replace_adds_duplicate() {
        let mut c = Collection::new("c");
        c.upsert(item(&[("k", "v")], b"a"), false);
        c.upsert(item(&[("k", "v")], b"b"), false);
        assert_eq!(c.items.len(), 2);
    }

    #[test]
    fn removing_collection_drops_its_aliases() {
        let mut body = Body::default();
        let id = body.resolve_alias(DEFAULT_ALIAS).unwrap().id;
        body.remove_collection(id).unwrap();
        assert!(body.resolve_alias(DEFAULT_ALIAS).is_none());
        assert!(body.aliases.is_empty());
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", SecretBytes::new(b"hunter2".to_vec())),
            "SecretBytes([REDACTED])"
        );
    }
}
