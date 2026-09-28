//! The prompter's display comes from the user manager's environment, read
//! at each launch (a stand-in `org.freedesktop.systemd1` on a private bus:
//! the real manager is never asked).

use std::sync::{Arc, Mutex};

use aleph_daemon::display::{Session, UserManager};

struct Manager(Arc<Mutex<Vec<String>>>);

#[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
impl Manager {
    #[zbus(property)]
    fn environment(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

async fn connect(bus: &aleph_daemon::testing::Bus) -> zbus::Connection {
    zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap()
}

/// The display the compositor exported after alephd started is the one
/// used, and a change is seen at the next launch.
#[tokio::test(flavor = "multi_thread")]
async fn the_display_is_read_from_the_user_manager_at_each_launch() {
    let bus = aleph_daemon::testing::bus();
    let env = Arc::new(Mutex::new(vec!["PATH=/usr/bin".to_string()]));
    let _manager = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.systemd1")
        .unwrap()
        .serve_at("/org/freedesktop/systemd1", Manager(env.clone()))
        .unwrap()
        .build()
        .await
        .unwrap();
    let session = Arc::new(UserManager {
        conn: connect(&bus).await,
        runtime: tokio::runtime::Handle::current(),
    });
    let ask = |s: Arc<UserManager>| tokio::task::spawn_blocking(move || s.wayland_display());
    assert_eq!(ask(session.clone()).await.unwrap(), None);
    env.lock().unwrap().push("WAYLAND_DISPLAY=wayland-7".into());
    assert_eq!(ask(session).await.unwrap(), Some("wayland-7".into()));
}
