//! Where a backup goes (the admin spec, "BACK UP…"): the XDG portal's
//! save dialog, through `rfd`, on a thread of its own so the window never
//! waits for it. `rfd` cannot tell "there is no portal" from "the person
//! cancelled", so whether the portal is there is decided first, by the
//! owner of `org.freedesktop.portal.Desktop` on the session bus.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver};

const PORTAL: &str = "org.freedesktop.portal.Desktop";

/// What the save dialog came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pick {
    /// No portal to ask (or the dialog could not start): the window shows a
    /// typed-path field instead.
    Unavailable,
    Cancelled,
    Chosen(PathBuf),
}

pub trait FilePicker {
    /// Ask where to save a file called `suggested`, starting in `dir`. The
    /// answer arrives on the receiver (the window polls it each frame).
    fn start(&self, suggested: String, dir: Option<PathBuf>) -> Receiver<Pick>;
}

/// A shared picker (the tests keep a handle on their fake).
impl<T: FilePicker + ?Sized> FilePicker for std::sync::Arc<T> {
    fn start(&self, suggested: String, dir: Option<PathBuf>) -> Receiver<Pick> {
        (**self).start(suggested, dir)
    }
}

/// Whether the portal has an owner on the bus at `address` (the session
/// bus if `None`). Any failure to ask is "no".
pub async fn portal_present(address: Option<&str>) -> bool {
    let conn = match address {
        Some(a) => match zbus::connection::Builder::address(a) {
            Ok(b) => b.build().await,
            Err(e) => Err(e),
        },
        None => zbus::Connection::session().await,
    };
    let Ok(conn) = conn else {
        return false;
    };
    let Ok(dbus) = zbus::fdo::DBusProxy::new(&conn).await else {
        return false;
    };
    let Ok(name) = zbus::names::BusName::try_from(PORTAL) else {
        return false;
    };
    dbus.name_has_owner(name).await.unwrap_or(false)
}

/// The real dialog.
pub struct Portal;

impl FilePicker for Portal {
    fn start(&self, suggested: String, dir: Option<PathBuf>) -> Receiver<Pick> {
        let (tx, rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("aleph-save-dialog".into())
            .spawn({
                let tx = tx.clone();
                move || {
                    let _ = tx.send(pick(&suggested, dir.as_deref()));
                }
            });
        if spawned.is_err() {
            let _ = tx.send(Pick::Unavailable);
        }
        rx
    }
}

fn pick(suggested: &str, dir: Option<&std::path::Path>) -> Pick {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Pick::Unavailable;
    };
    rt.block_on(async {
        if !portal_present(None).await {
            return Pick::Unavailable;
        }
        let mut dialog = rfd::AsyncFileDialog::new()
            .set_title("Save the aleph backup")
            .set_file_name(suggested);
        if let Some(dir) = dir {
            dialog = dialog.set_directory(dir);
        }
        match dialog.save_file().await {
            Some(handle) => Pick::Chosen(handle.path().to_path_buf()),
            None => Pick::Cancelled,
        }
    })
}

/// A picker for the tests: answers from a list, in order (a cancel once it
/// runs out), and remembers what it was asked.
pub struct Fake {
    picks: Mutex<Vec<Pick>>,
    pub asked: Mutex<Vec<(String, Option<PathBuf>)>>,
}

impl Fake {
    pub fn new(mut picks: Vec<Pick>) -> Self {
        picks.reverse();
        Self {
            picks: Mutex::new(picks),
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl FilePicker for Fake {
    fn start(&self, suggested: String, dir: Option<PathBuf>) -> Receiver<Pick> {
        self.asked.lock().unwrap().push((suggested, dir));
        let next = self.picks.lock().unwrap().pop().unwrap_or(Pick::Cancelled);
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(next);
        rx
    }
}
