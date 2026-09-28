//! alephd's start: its interfaces are in place before it owns its bus
//! name, so the call that D-Bus activation starts it for is never lost.

use std::sync::Arc;

use aleph_daemon::config::Config;
use aleph_daemon::testing::{InteractiveLauncher, MockKeys, bus, env, keyring};
use futures_util::StreamExt;

/// A client that calls the admin interface the moment `io.aleph.Keyring`
/// gets an owner (as a D-Bus-activated `alephctl` does) is answered.
#[tokio::test(flavor = "multi_thread")]
async fn the_name_is_owned_only_once_the_interfaces_answer() {
    let env = env();
    let bus = bus();
    let client = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let dbus = zbus::fdo::DBusProxy::new(&client).await.unwrap();
    let mut owners = dbus
        .receive_name_owner_changed_with_args(&[(0, aleph_daemon::admin::BUS_NAME)])
        .await
        .unwrap();
    let asked = {
        let client = client.clone();
        tokio::spawn(async move {
            let _owned = owners.next().await.unwrap();
            client
                .call_method(
                    Some(aleph_daemon::admin::BUS_NAME),
                    aleph_daemon::admin::ADMIN_PATH,
                    Some("io.aleph.Admin1"),
                    "Status",
                    &(),
                )
                .await
                .map(|reply| reply.body().deserialize::<String>().unwrap())
        })
    };
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    aleph_daemon::daemon::start(
        &conn,
        Arc::new(keyring(&env, MockKeys::default())),
        Arc::new(InteractiveLauncher::new(vec![])),
        Arc::new(std::sync::Mutex::new(Config::default())),
        env.paths.clone(),
    )
    .await
    .unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), asked)
        .await
        .expect("the name got an owner")
        .unwrap();
    assert!(status.is_ok(), "{status:?}");
}
