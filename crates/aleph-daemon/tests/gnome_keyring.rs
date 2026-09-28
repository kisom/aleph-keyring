//! Importing from a real gnome-keyring on a private bus (DECISIONS.md E1,
//! E2, E11): alephd queues behind it for `org.freedesktop.secrets`, reads
//! its items over an encrypted session, keeps following it, and takes the
//! name the moment gnome-keyring lets go.

use aleph_daemon::testing::*;

async fn client(address: &str) -> zbus::Connection {
    zbus::connection::Builder::address(address)
        .unwrap()
        .build()
        .await
        .unwrap()
}

async fn admin(c: &zbus::Connection, method: &str) -> zbus::Result<String> {
    c.call_method(
        Some(aleph_daemon::admin::BUS_NAME),
        aleph_daemon::admin::ADMIN_PATH,
        Some("io.aleph.Admin1"),
        method,
        &(),
    )
    .await?
    .body()
    .deserialize()
}

fn items_labelled(
    d: &Daemon,
    label: &str,
) -> Vec<(String, std::collections::BTreeMap<String, String>, Vec<u8>)> {
    d.keyring
        .read(|b| {
            b.collections
                .iter()
                .flat_map(|c| c.items.iter())
                .filter(|i| i.label == label)
                .map(|i| {
                    (
                        i.content_type.clone(),
                        i.attributes.clone(),
                        i.secret.expose().to_vec(),
                    )
                })
                .collect()
        })
        .unwrap()
}

async fn eventually(what: &str, mut ok: impl AsyncFnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !ok().await {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting: {what}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn items_move_over_and_the_name_changes_hands() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store(
        "Mail",
        &[
            ("xdg:schema", "org.example.Mail"),
            ("service", "mail"),
            ("user", "alice"),
        ],
        "s3cret",
    );
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    let status: serde_json::Value =
        serde_json::from_str(&admin(&c, "Status").await.unwrap()).unwrap();
    assert_eq!(status["secret_service"], "another program");

    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    assert!(summary.contains("Imported 1 item"), "{summary}");
    let mail = items_labelled(&d, "Mail");
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].1["user"], "alice");
    assert_eq!(mail[0].1["xdg:schema"], "org.example.Mail");
    assert_eq!(mail[0].2, b"s3cret");
    // Again: nothing new.
    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    assert!(
        summary.contains("Imported 0 item(s) from gnome-keyring (1 already here)"),
        "{summary}"
    );

    // Stored in gnome-keyring after the import: followed.
    gk.store("Later", &[("service", "later")], "stored later");
    eventually("the later item", async || {
        items_labelled(&d, "Later").len() == 1
    })
    .await;

    // gnome-keyring lets go: the name is alephd's at once.
    gk.stop();
    eventually("the name handoff", async || {
        aleph_daemon::daemon::secret_service_owner(&d.conn).await == "alephd"
    })
    .await;
    // And alephd serves the imported item to Secret Service clients.
    let found: Vec<zbus::zvariant::OwnedObjectPath> = c
        .call_method(
            Some("org.freedesktop.secrets"),
            "/org/freedesktop/secrets",
            Some("org.freedesktop.Secret.Service"),
            "SearchItems",
            &(std::collections::HashMap::from([("service", "mail")]),),
        )
        .await
        .unwrap()
        .body()
        .deserialize::<(
            Vec<zbus::zvariant::OwnedObjectPath>,
            Vec<zbus::zvariant::OwnedObjectPath>,
        )>()
        .unwrap()
        .0;
    assert_eq!(found.len(), 1);
}

/// A locked gnome-keyring collection whose unlock prompt cannot be shown
/// (or is dismissed) is skipped with a message, not waited on forever.
#[tokio::test(flavor = "multi_thread")]
async fn a_collection_that_stays_locked_is_skipped_with_a_message() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Mail", &[("service", "mail")], "s3cret");
    let c = client(&address).await;
    c.call_method(
        Some("org.freedesktop.secrets"),
        "/org/freedesktop/secrets",
        Some("org.freedesktop.Secret.Service"),
        "Lock",
        &(vec![
            zbus::zvariant::ObjectPath::try_from("/org/freedesktop/secrets/collection/login")
                .unwrap(),
        ],),
    )
    .await
    .unwrap();
    let d = daemon_on(bus, true).await;
    let started = std::time::Instant::now();
    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    eprintln!("took {:?}: {summary}", started.elapsed());
    assert!(summary.contains("Imported 0"), "{summary}");
    assert!(summary.contains("locked"), "{summary}");
    assert!(items_labelled(&d, "Mail").is_empty());
}

/// Without gnome-keyring there is nothing to import, and nothing fails.
#[tokio::test(flavor = "multi_thread")]
async fn without_gnome_keyring_there_is_nothing_to_import() {
    let d = daemon(true, vec![]).await;
    let c = client(&d.bus.address).await;
    let summary = admin(&c, "ImportGnomeKeyring").await.unwrap();
    assert!(summary.contains("not running"), "{summary}");
}

/// `ExportToGnomeKeyring` with a prompter answering `replies`: (ok, message).
async fn export(d: &Daemon, delete: bool, replies: Vec<FromPrompter>) -> (bool, Option<String>) {
    use std::os::fd::OwnedFd;
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let prompter = Interactive::new(replies);
    prompter.respond(ours);
    let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
    let c = client(&d.bus.address).await;
    c.call_method(
        Some(aleph_daemon::admin::BUS_NAME),
        aleph_daemon::admin::ADMIN_PATH,
        Some("io.aleph.Admin1"),
        "ExportToGnomeKeyring",
        &(fd, delete),
    )
    .await
    .unwrap();
    let sent = tokio::task::spawn_blocking(move || prompter.sent())
        .await
        .unwrap();
    match sent.last() {
        Some(ToPrompter::Done { ok, message }) => (*ok, message.clone()),
        other => panic!("the export did not finish: {other:?}"),
    }
}

fn add(d: &Daemon, collection: Option<&str>, label: &str, attrs: &[(&str, &str)], secret: &str) {
    d.keyring
        .modify(|b| {
            let id = match collection {
                None => {
                    b.resolve_alias(aleph_core::model::DEFAULT_ALIAS)
                        .unwrap()
                        .id
                }
                Some(name) => match b.collections.iter().find(|c| c.label == name) {
                    Some(c) => c.id,
                    None => {
                        let c = aleph_core::Collection::new(name);
                        let id = c.id;
                        b.collections.push(c);
                        id
                    }
                },
            };
            b.collection_mut(id).unwrap().upsert(
                aleph_core::Item::new(
                    label,
                    attrs
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                    aleph_core::SecretBytes::new(secret.as_bytes().to_vec()),
                    "text/plain",
                ),
                false,
            );
            Ok(())
        })
        .unwrap();
}

/// The number of items gnome-keyring on `conn`'s bus finds for `attrs`.
async fn found(conn: &zbus::Connection, attrs: &[(&str, &str)]) -> usize {
    let attrs: std::collections::HashMap<&str, &str> = attrs.iter().copied().collect();
    let (unlocked, locked): (
        Vec<zbus::zvariant::OwnedObjectPath>,
        Vec<zbus::zvariant::OwnedObjectPath>,
    ) = conn
        .call_method(
            Some("org.freedesktop.secrets"),
            "/org/freedesktop/secrets",
            Some("org.freedesktop.Secret.Service"),
            "SearchItems",
            &(attrs,),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    unlocked.len() + locked.len()
}

/// Everything goes back to gnome-keyring (a collection it lacks into its
/// default one) and is read back; writes pause until the revert ends or
/// they are resumed; a second export finds everything there.
#[tokio::test(flavor = "multi_thread")]
async fn items_are_copied_back_and_writes_pause() {
    let d = daemon(true, vec![]).await;
    add(&d, None, "Mail", &[("service", "mail")], "s3cret");
    add(&d, Some("Work"), "VPN", &[("service", "vpn")], "k3y");
    let (ok, message) = export(&d, false, vec![password(PW)]).await;
    let message = message.unwrap_or_default();
    assert!(ok, "{message}");
    assert!(message.contains("Copied 2 item(s)"), "{message}");
    assert!(message.contains("default collection"), "{message}");
    assert!(matches!(
        d.keyring.modify(|_| Ok(())),
        Err(aleph_daemon::Error::Frozen)
    ));
    admin(&client(&d.bus.address).await, "ThawWrites")
        .await
        .ok();
    d.keyring.modify(|_| Ok(())).unwrap();
    // Read back by a gnome-keyring of our own over the same files.
    let data_home = d.env.paths.data_dir.parent().unwrap().to_path_buf();
    {
        let gk = aleph_daemon::export::Private::start(&data_home, PW)
            .await
            .unwrap();
        let c = gk.connect().await.unwrap();
        assert_eq!(found(&c, &[("service", "mail")]).await, 1);
        assert_eq!(found(&c, &[("service", "vpn")]).await, 1);
    }
    let (ok, message) = export(&d, false, vec![password(PW)]).await;
    assert!(ok);
    assert!(message.unwrap().contains("2 already there"));
}

/// A login keyring that does not open with the login password (their
/// passwords differ) changes nothing, and writes are not paused.
#[tokio::test(flavor = "multi_thread")]
async fn a_login_keyring_that_does_not_unlock_changes_nothing() {
    let d = daemon(true, vec![]).await;
    add(&d, None, "Mail", &[("service", "mail")], "s3cret");
    let data_home = d.env.paths.data_dir.parent().unwrap().to_path_buf();
    drop(
        aleph_daemon::export::Private::start(&data_home, "another password")
            .await
            .unwrap(),
    );
    let (ok, message) = export(&d, false, vec![password(PW)]).await;
    assert!(!ok);
    assert!(message.unwrap().contains("did not unlock"));
    d.keyring.modify(|_| Ok(())).unwrap();
}

/// Revert does not run a second gnome-keyring over the same files.
#[tokio::test(flavor = "multi_thread")]
async fn revert_refuses_while_gnome_keyring_runs() {
    let bus = bus();
    let _gk = GnomeKeyring::start(&bus, "login password");
    let d = daemon_on(bus, true).await;
    use std::os::fd::OwnedFd;
    let (_ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = zbus::zvariant::OwnedFd::from(OwnedFd::from(theirs));
    let err = client(&d.bus.address)
        .await
        .call_method(
            Some(aleph_daemon::admin::BUS_NAME),
            aleph_daemon::admin::ADMIN_PATH,
            Some("io.aleph.Admin1"),
            "ExportToGnomeKeyring",
            &(fd, false),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("gnome-keyring is running"),
        "{err}"
    );
}

/// Items imported and deleted in aleph since are listed, and deleted in
/// gnome-keyring too when asked; the rest stays.
#[tokio::test(flavor = "multi_thread")]
async fn items_deleted_since_the_import_are_deleted_there_too() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Gone", &[("k", "gone")], "x");
    gk.store("Kept", &[("k", "kept")], "y");
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    admin(&c, "ImportGnomeKeyring").await.unwrap();
    d.keyring
        .modify(|b| {
            for col in &mut b.collections {
                col.items.retain(|i| i.label != "Gone");
            }
            Ok(())
        })
        .unwrap();
    let removed: Vec<String> = c
        .call_method(
            Some(aleph_daemon::admin::BUS_NAME),
            aleph_daemon::admin::ADMIN_PATH,
            Some("io.aleph.Admin1"),
            "RemovedSinceImport",
            &(),
        )
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    assert_eq!(removed, ["Gone (Login)"]);
    // (Straight to the export, against the running gnome-keyring.)
    let body = d.keyring.read(|b| b.clone()).unwrap();
    let delete = aleph_daemon::import::removed_since(
        &aleph_daemon::import::load_imported(&d.env.paths.imported()),
        &body,
    );
    let report = aleph_daemon::export::export(&c, &address, &body, &delete, &Default::default())
        .await
        .unwrap();
    assert_eq!(
        (report.exported, report.unchanged, report.deleted),
        (0, 1, 1)
    );
    assert_eq!(found(&c, &[("k", "gone")]).await, 0);
    assert_eq!(found(&c, &[("k", "kept")]).await, 1);
}

/// Nobody can take the Secret Service name from alephd: it never allows
/// replacement, so even `ReplaceExisting` just queues.
#[tokio::test(flavor = "multi_thread")]
async fn the_name_cannot_be_taken_from_alephd() {
    let d = daemon(true, vec![]).await;
    let other = client(&d.bus.address).await;
    let reply = other
        .request_name_with_flags(
            "org.freedesktop.secrets",
            zbus::fdo::RequestNameFlags::ReplaceExisting.into(),
        )
        .await
        .unwrap();
    assert_eq!(reply, zbus::fdo::RequestNameReply::InQueue);
    assert_eq!(
        aleph_daemon::daemon::secret_service_owner(&d.conn).await,
        "alephd"
    );
}

/// An item imported, deleted in aleph, and stored again (same label and
/// attributes) is not deleted from gnome-keyring by revert; its new secret
/// is what gnome-keyring ends up with.
#[tokio::test(flavor = "multi_thread")]
async fn revert_never_deletes_what_aleph_still_holds() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Mail", &[("k", "mail")], "old");
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    admin(&c, "ImportGnomeKeyring").await.unwrap();
    d.keyring
        .modify(|b| {
            for col in &mut b.collections {
                col.items.retain(|i| i.label != "Mail");
            }
            Ok(())
        })
        .unwrap();
    add(&d, None, "Mail", &[("k", "mail")], "new");
    let body = d.keyring.read(|b| b.clone()).unwrap();
    let delete = aleph_daemon::import::removed_since(
        &aleph_daemon::import::load_imported(&d.env.paths.imported()),
        &body,
    );
    assert_eq!(delete.len(), 1);
    let report = aleph_daemon::export::export(&c, &address, &body, &delete, &Default::default())
        .await
        .unwrap();
    assert_eq!(report.deleted, 0);
    assert_eq!(found(&c, &[("k", "mail")]).await, 1);
    // (The secret there is the new one: export verified it.)
    assert_eq!(report.exported, 1);
}

/// An item in gnome-keyring with the same attributes but another label is
/// a different item: export adds aleph's beside it, never over it.
#[tokio::test(flavor = "multi_thread")]
async fn export_does_not_replace_an_item_with_another_label() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Theirs", &[("k", "same")], "theirs");
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    add(&d, None, "Ours", &[("k", "same")], "ours");
    let body = d.keyring.read(|b| b.clone()).unwrap();
    aleph_daemon::export::export(&c, &address, &body, &[], &Default::default())
        .await
        .unwrap();
    assert_eq!(found(&c, &[("k", "same")]).await, 2);
}

/// A secret gnome-keyring changes after the import (a token refresh)
/// reaches aleph by the next import (setup runs one right before stopping
/// gnome-keyring), for the items the import brought.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_in_gnome_keyring_reaches_aleph_by_the_next_import() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Token", &[("k", "token")], "v1");
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    admin(&c, "ImportGnomeKeyring").await.unwrap();
    gk.store("Token", &[("k", "token")], "v2");
    // (gnome-keyring may take a moment to serve the replaced secret, and
    // alephd's following may bring it first.)
    eventually("the update by the next import", async || {
        admin(&c, "ImportGnomeKeyring").await.unwrap();
        items_labelled(&d, "Token")
            .iter()
            .any(|(_, _, s)| s == b"v2")
    })
    .await;
    let token = items_labelled(&d, "Token");
    assert_eq!(token.len(), 1, "{token:?}");
}

/// `ClaimSecretService` queues for the name (setup calls it once its
/// activation file is in place).
#[tokio::test(flavor = "multi_thread")]
async fn claiming_the_name_queues_behind_gnome_keyring() {
    let bus = bus();
    let address = bus.address.clone();
    let _gk = GnomeKeyring::start(&bus, "login password");
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    c.call_method(
        Some(aleph_daemon::admin::BUS_NAME),
        aleph_daemon::admin::ADMIN_PATH,
        Some("io.aleph.Admin1"),
        "ClaimSecretService",
        &(),
    )
    .await
    .unwrap();
    assert_eq!(
        aleph_daemon::daemon::secret_service_owner(&d.conn).await,
        "another program"
    );
}

/// Exact attributes only: an item in gnome-keyring with extra attributes
/// is another item, never overwritten.
#[tokio::test(flavor = "multi_thread")]
async fn export_matches_exact_attributes_only() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Same", &[("k", "same"), ("extra", "1")], "theirs");
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    add(&d, None, "Same", &[("k", "same")], "ours");
    let body = d.keyring.read(|b| b.clone()).unwrap();
    let report = aleph_daemon::export::export(&c, &address, &body, &[], &Default::default())
        .await
        .unwrap();
    assert_eq!(report.exported, 1);
    assert_eq!(found(&c, &[("k", "same")]).await, 2);
    assert_eq!(found(&c, &[("extra", "1")]).await, 1);
}

/// Two aleph items with the same label and attributes (an imported one and
/// a later one) both end up in gnome-keyring; neither overwrites the other,
/// and the check covers the unchanged one too.
#[tokio::test(flavor = "multi_thread")]
async fn export_keeps_both_of_two_same_items() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Mail", &[("k", "mail")], "gk-secret");
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    admin(&c, "ImportGnomeKeyring").await.unwrap();
    add(&d, None, "Mail", &[("k", "mail")], "aleph-secret");
    let body = d.keyring.read(|b| b.clone()).unwrap();
    let imported: std::collections::HashSet<uuid::Uuid> =
        aleph_daemon::import::load_imported(&d.env.paths.imported())
            .into_iter()
            .map(|i| i.id)
            .collect();
    let report = aleph_daemon::export::export(&c, &address, &body, &[], &imported)
        .await
        .unwrap();
    assert_eq!((report.unchanged, report.exported), (1, 1));
    assert_eq!(found(&c, &[("k", "mail")]).await, 2);
}

/// An imported item changed in aleph since is updated in gnome-keyring in
/// place (no duplicate); an item aleph had before the import (a conflict
/// then) is added beside gnome-keyring's, never over it.
#[tokio::test(flavor = "multi_thread")]
async fn export_updates_only_imported_items_in_place() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Token", &[("k", "token")], "v1");
    gk.store("Mine", &[("k", "mine")], "theirs");
    let d = daemon_on(bus, true).await;
    add(&d, None, "Mine", &[("k", "mine")], "ours");
    let c = client(&address).await;
    admin(&c, "ImportGnomeKeyring").await.unwrap();
    d.keyring
        .modify(|b| {
            for col in &mut b.collections {
                for i in &mut col.items {
                    if i.label == "Token" {
                        i.secret = aleph_core::SecretBytes::new(b"v2".to_vec());
                    }
                }
            }
            Ok(())
        })
        .unwrap();
    let body = d.keyring.read(|b| b.clone()).unwrap();
    let imported: std::collections::HashSet<uuid::Uuid> =
        aleph_daemon::import::load_imported(&d.env.paths.imported())
            .into_iter()
            .map(|i| i.id)
            .collect();
    aleph_daemon::export::export(&c, &address, &body, &[], &imported)
        .await
        .unwrap();
    assert_eq!(found(&c, &[("k", "token")]).await, 1);
    assert_eq!(found(&c, &[("k", "mine")]).await, 2);
}

/// Two aleph items alike in label, attributes, and secret are two items in
/// gnome-keyring too: one gnome-keyring item never stands for both.
#[tokio::test(flavor = "multi_thread")]
async fn export_keeps_both_of_two_identical_items() {
    let bus = bus();
    let address = bus.address.clone();
    let gk = GnomeKeyring::start(&bus, "login password");
    gk.store("Mail", &[("k", "mail")], "s");
    let d = daemon_on(bus, true).await;
    let c = client(&address).await;
    admin(&c, "ImportGnomeKeyring").await.unwrap();
    add(&d, None, "Mail", &[("k", "mail")], "s");
    let body = d.keyring.read(|b| b.clone()).unwrap();
    let report = aleph_daemon::export::export(&c, &address, &body, &[], &Default::default())
        .await
        .unwrap();
    assert_eq!((report.unchanged, report.exported), (1, 1));
    assert_eq!(found(&c, &[("k", "mail")]).await, 2);
}
