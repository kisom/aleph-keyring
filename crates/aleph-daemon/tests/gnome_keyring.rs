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
