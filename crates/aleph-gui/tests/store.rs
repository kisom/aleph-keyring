//! The manager's store against a real alephd on a private bus (the
//! daemon's test harness: a swtpm TPM helper, scripted prompters). Never
//! the session bus.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use aleph_daemon::testing::{FromPrompter, Interactive, PW, daemon, password};
use aleph_gui::store::{Collection, DbusStore, Request, Store, StoreEvent, Vault};
use zeroize::Zeroizing;

/// A store and the events it sent that no wait has taken yet.
struct Probe {
    store: DbusStore,
    pending: std::collections::VecDeque<StoreEvent>,
}

impl Probe {
    fn new(address: &str) -> Self {
        Self {
            store: DbusStore::start(Some(address.to_string()), || {}),
            pending: Default::default(),
        }
    }

    /// The first event (sent or pending) for which `f` returns something,
    /// dropping the ones before it (or failing after 20 s).
    async fn until<T>(&mut self, mut f: impl FnMut(&StoreEvent) -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            self.pending.extend(self.store.events());
            while let Some(e) = self.pending.pop_front() {
                if let Some(t) = f(&e) {
                    return t;
                }
            }
            assert!(Instant::now() < deadline, "timed out waiting for the store");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn unlocked(&mut self, want: impl Fn(&[Collection]) -> bool) -> Vec<Collection> {
        self.until(|e| match e {
            StoreEvent::Vault(Vault::Unlocked(c)) if want(c) => Some(c.clone()),
            _ => None,
        })
        .await
    }

    async fn done(&mut self, name: &str) -> (Option<String>, bool) {
        self.until(|e| match e {
            StoreEvent::Done {
                request,
                error,
                dismissed,
            } if *request == name => Some((error.clone(), *dismissed)),
            _ => None,
        })
        .await
    }

    fn request(&self, r: Request) {
        self.store.request(r);
    }
}

fn item<'a>(c: &'a [Collection], label: &str) -> Option<&'a aleph_gui::store::Item> {
    c.iter().flat_map(|c| &c.items).find(|i| i.label == label)
}

/// Items are listed, created, shown, renamed, changed, and deleted, all
/// through the Secret Service.
#[tokio::test(flavor = "multi_thread")]
async fn items_are_listed_created_shown_changed_and_deleted() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    let cols = store.unlocked(|c| !c.is_empty()).await;
    assert!(cols[0].is_default, "{cols:?}");
    let default = cols[0].path.clone();

    store.request(Request::CreateItem {
        collection: default,
        label: "GitHub token".into(),
        attributes: BTreeMap::from([("service".into(), "github.com".into())]),
        secret: Zeroizing::new(b"s3cret".to_vec()),
    });
    assert_eq!(store.done("create the item").await, (None, false));
    let cols = store.unlocked(|c| item(c, "GitHub token").is_some()).await;
    let it = item(&cols, "GitHub token").unwrap().clone();
    assert_eq!(it.attributes["service"], "github.com");
    assert_eq!(
        it.attributes["xdg:schema"],
        "org.freedesktop.Secret.Generic"
    );

    store.request(Request::Secret(it.path.clone()));
    let secret = store
        .until(|e| match e {
            StoreEvent::Secret { path, secret, .. } if *path == it.path => Some(secret.clone()),
            _ => None,
        })
        .await;
    assert_eq!(&secret[..], b"s3cret");

    store.request(Request::SetLabel {
        path: it.path.clone(),
        label: "GitHub".into(),
    });
    assert_eq!(store.done("rename").await.0, None);
    store.unlocked(|c| item(c, "GitHub").is_some()).await;

    store.request(Request::SetSecret {
        path: it.path.clone(),
        secret: Zeroizing::new(b"n3w".to_vec()),
    });
    assert_eq!(store.done("change the secret").await.0, None);
    store.request(Request::Secret(it.path.clone()));
    let secret = store
        .until(|e| match e {
            StoreEvent::Secret { secret, .. } => Some(secret.clone()),
            _ => None,
        })
        .await;
    assert_eq!(&secret[..], b"n3w");

    store.request(Request::DeleteItem(it.path.clone()));
    assert_eq!(store.done("delete the item").await, (None, false));
    store.unlocked(|c| item(c, "GitHub").is_none()).await;
}

/// A lock shows as locked (alephd signals it, and the store also polls);
/// an unlock through alephd's prompt shows the items again.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_shows_and_an_unlock_through_the_prompt_restores() {
    let d = daemon(true, vec![vec![password(PW)]]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    d.secrets.lock().await.unwrap();
    store
        .until(|e| matches!(e, StoreEvent::Vault(Vault::Locked)).then_some(()))
        .await;
    store.request(Request::Unlock);
    assert_eq!(store.done("unlock").await, (None, false));
    store.unlocked(|c| !c.is_empty()).await;
}

/// Folders are created and deleted; alephd confirms each through its own
/// prompt (answered yes here).
#[tokio::test(flavor = "multi_thread")]
async fn folders_are_created_and_deleted_after_alephds_confirmation() {
    let yes = || vec![FromPrompter::Confirm { yes: true }];
    let d = daemon(true, vec![yes(), yes()]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    store.request(Request::CreateCollection("work".into()));
    assert_eq!(store.done("create the folder").await, (None, false));
    let cols = store
        .unlocked(|c| c.iter().any(|c| c.label == "work"))
        .await;
    let work = cols
        .iter()
        .find(|c| c.label == "work")
        .unwrap()
        .path
        .clone();
    store.request(Request::DeleteCollection(work));
    assert_eq!(store.done("delete the folder").await, (None, false));
    store
        .unlocked(|c| !c.iter().any(|c| c.label == "work"))
        .await;
}

/// `Reauth` runs on the window's end of a socketpair and changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn reauth_converses_on_the_windows_socket() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let prompter = Interactive::new(vec![password(PW)]);
    prompter.respond(ours);
    store.request(Request::Reauth(theirs.into()));
    assert_eq!(store.done("confirm").await.0, None);
    let sent = tokio::task::spawn_blocking(move || prompter.sent())
        .await
        .unwrap();
    assert!(
        matches!(
            sent.last(),
            Some(aleph_daemon::testing::ToPrompter::Done { ok: true, .. })
        ),
        "{sent:?}"
    );
}

/// After alephd forgets every session (as a restart does), a secret is
/// still shown and an item still created: the store opens a new session.
#[tokio::test(flavor = "multi_thread")]
async fn a_forgotten_session_is_replaced() {
    let d = daemon(true, vec![]).await;
    let mut store = Probe::new(&d.bus.address);
    let cols = store.unlocked(|c| !c.is_empty()).await;
    let default = cols[0].path.clone();
    let create = |label: &str| Request::CreateItem {
        collection: default.clone(),
        label: label.into(),
        attributes: BTreeMap::new(),
        secret: Zeroizing::new(b"one".to_vec()),
    };
    store.request(create("A"));
    assert_eq!(store.done("create the item").await, (None, false));
    let cols = store.unlocked(|c| item(c, "A").is_some()).await;
    let a = item(&cols, "A").unwrap().path.clone();
    store.request(Request::Secret(a.clone()));
    assert_eq!(store.done("fetch the secret").await.0, None);
    d.secrets.forget_sessions();
    store.request(Request::Secret(a));
    assert_eq!(store.done("fetch the secret").await.0, None);
    d.secrets.forget_sessions();
    store.request(create("B"));
    assert_eq!(store.done("create the item").await, (None, false));
    store.unlocked(|c| item(c, "B").is_some()).await;
}

/// Deleting the default folder (its alias goes with it) leaves the
/// keyring unlocked, not unreachable.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_the_default_folder_keeps_the_keyring_reachable() {
    let yes = || vec![FromPrompter::Confirm { yes: true }];
    let d = daemon(true, vec![yes(), yes()]).await;
    let mut store = Probe::new(&d.bus.address);
    store.unlocked(|c| !c.is_empty()).await;
    store.request(Request::CreateCollection("work".into()));
    assert_eq!(store.done("create the folder").await, (None, false));
    let cols = store
        .unlocked(|c| c.iter().any(|c| c.label == "work"))
        .await;
    let default = cols.iter().find(|c| c.is_default).unwrap().path.clone();
    store.request(Request::DeleteCollection(default));
    assert_eq!(store.done("delete the folder").await, (None, false));
    let cols = store
        .unlocked(|c| c.iter().all(|c| !c.is_default) && c.iter().any(|c| c.label == "work"))
        .await;
    assert_eq!(cols.len(), 1);
    // And it stays so across polls.
    tokio::time::sleep(aleph_gui::store::POLL * 2).await;
    store.pending.extend(store.store.events());
    assert!(
        !store
            .pending
            .iter()
            .any(|e| matches!(e, StoreEvent::Vault(Vault::Unreachable(_)))),
        "{:?}",
        store.pending
    );
}

/// A burst of writes by other programs (signals arriving faster than a
/// long listing drains them) does not stall the store: it still answers,
/// and lists everything.
#[tokio::test(flavor = "multi_thread")]
async fn a_burst_of_signals_does_not_hang_the_store() {
    use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
    let d = daemon(true, vec![]).await;
    // (A queue of 2: a full queue must never stall the store, whatever
    // its size; with the real one it takes hundreds of signals during one
    // listing.)
    let mut store = Probe {
        store: DbusStore::with_signal_queue(Some(d.bus.address.clone()), || {}, 2),
        pending: Default::default(),
    };
    let cols = store.unlocked(|c| !c.is_empty()).await;
    let default = cols[0].path.clone();
    let writer = |first: usize, n: usize| {
        let (address, default) = (d.bus.address.clone(), default.clone());
        tokio::spawn(async move {
            let c = zbus::connection::Builder::address(address.as_str())
                .unwrap()
                .build()
                .await
                .unwrap();
            let svc = zbus::Proxy::new(
                &c,
                "org.freedesktop.secrets",
                "/org/freedesktop/secrets",
                "org.freedesktop.Secret.Service",
            )
            .await
            .unwrap();
            let (_, session): (OwnedValue, OwnedObjectPath) = svc
                .call("OpenSession", &("plain", Value::from("")))
                .await
                .unwrap();
            let col = zbus::Proxy::new(
                &c,
                "org.freedesktop.secrets",
                default,
                "org.freedesktop.Secret.Collection",
            )
            .await
            .unwrap();
            for i in first..first + n {
                let mut props: std::collections::HashMap<&str, Value> = Default::default();
                props.insert(
                    "org.freedesktop.Secret.Item.Label",
                    Value::from(format!("ext {i}")),
                );
                props.insert(
                    "org.freedesktop.Secret.Item.Attributes",
                    Value::from(std::collections::HashMap::from([(
                        "n".to_string(),
                        i.to_string(),
                    )])),
                );
                let secret = (
                    session.clone(),
                    Vec::<u8>::new(),
                    b"x".to_vec(),
                    "text/plain".to_string(),
                );
                let _: (OwnedObjectPath, OwnedObjectPath) = col
                    .call("CreateItem", &(props, secret, false))
                    .await
                    .unwrap();
            }
        })
    };
    writer(0, 100).await.unwrap();
    store.unlocked(|c| c[0].items.len() >= 100).await;
    let writers: Vec<_> = (0..4).map(|k| writer(1000 + k * 100, 50)).collect();
    for w in writers {
        w.await.unwrap();
    }
    store.request(Request::Secret(format!("{default}/none")));
    let started = Instant::now();
    let (mut answered, mut most) = (false, 0);
    while started.elapsed() < Duration::from_secs(60) && !(answered && most >= 300) {
        for e in store.store.events() {
            match e {
                StoreEvent::Done {
                    request: "fetch the secret",
                    ..
                } => answered = true,
                StoreEvent::Vault(Vault::Unlocked(c)) => most = most.max(c[0].items.len()),
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(answered, "the store stopped answering");
    assert!(most >= 300, "listed at most {most} items");
}

/// With the default folder deleted, the store's polling does not count as
/// using the keyring (alephd's idle lock still comes).
#[tokio::test(flavor = "multi_thread")]
async fn polling_without_the_default_folder_is_not_use() {
    let yes = || vec![FromPrompter::Confirm { yes: true }];
    let d = daemon(true, vec![yes()]).await;
    let mut store = Probe::new(&d.bus.address);
    let cols = store.unlocked(|c| !c.is_empty()).await;
    store.request(Request::DeleteCollection(cols[0].path.clone()));
    assert_eq!(store.done("delete the folder").await, (None, false));
    store.unlocked(|c| c.is_empty()).await;
    tokio::time::sleep(aleph_gui::store::POLL * 3).await;
    let idle = d.keyring.idle_for();
    assert!(idle >= aleph_gui::store::POLL * 2, "idle for only {idle:?}");
}

/// Only requests that change something are followed by a listing.
#[test]
fn only_changes_are_followed_by_a_listing() {
    assert!(!Request::Secret("/i".into()).changes());
    assert!(!Request::Reauth(std::os::unix::net::UnixStream::pair().unwrap().0.into()).changes());
    assert!(Request::Unlock.changes());
    assert!(Request::DeleteItem("/i".into()).changes());
    assert!(
        Request::SetLabel {
            path: "/i".into(),
            label: "x".into()
        }
        .changes()
    );
}

/// With no alephd, the store says so (and keeps trying).
#[tokio::test(flavor = "multi_thread")]
async fn without_alephd_the_store_is_unreachable() {
    let bus = aleph_daemon::testing::bus();
    let mut store = Probe::new(&bus.address);
    store
        .until(|e| matches!(e, StoreEvent::Vault(Vault::Unreachable(_))).then_some(()))
        .await;
}
