//! A manager built with `Manager::new` and no file picker set never asks
//! the real XDG portal: BACK UP… shows the typed-path field. (A binary of
//! its own, with one test: it points the session bus at a socket it owns,
//! and would see the portal being asked as a connection to it.)

use std::cell::RefCell;
use std::os::unix::net::UnixListener;
use std::rc::Rc;
use std::time::{Duration, Instant};

use aleph_gui::clipboard::Backend;
use aleph_gui::manager::Manager;
use aleph_gui::settings::Settings;
use aleph_gui::store::{AdminStatus, Request, Store, StoreEvent, Vault};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use zeroize::Zeroizing;

#[derive(Clone, Default)]
struct Fake {
    requests: Rc<RefCell<Vec<Request>>>,
    events: Rc<RefCell<Vec<StoreEvent>>>,
}

impl Store for Fake {
    fn request(&self, r: Request) {
        self.requests.borrow_mut().push(r);
    }
    fn events(&self) -> Vec<StoreEvent> {
        self.events.borrow_mut().drain(..).collect()
    }
}

#[derive(Clone, Default)]
struct Clip;

impl Backend for Clip {
    fn offer(&mut self, _secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
        Ok(())
    }
    fn still_ours(&self) -> bool {
        false
    }
    fn clear(&mut self) {}
}

#[test]
fn with_no_picker_set_back_up_shows_the_typed_path_and_asks_no_portal() {
    let dir = tempfile::tempdir().unwrap();
    let bus = dir.path().join("bus");
    let listener = UnixListener::bind(&bus).unwrap();
    listener.set_nonblocking(true).unwrap();
    // SAFETY: this binary's only test, and nothing has read the
    // environment on another thread yet.
    unsafe {
        std::env::set_var(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", bus.display()),
        );
    }

    let store = Fake::default();
    let home = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/home");
    let mut m = Manager::new(store.clone(), Clip, Settings::default(), Some(home), true);
    m.confirm_guard = Duration::ZERO;
    store
        .events
        .borrow_mut()
        .push(StoreEvent::Vault(Vault::Locked));
    let mut h = Harness::builder()
        .with_size(egui::Vec2::from(aleph_gui::manager::SIZE))
        .build_ui_state(|ui, m: &mut Manager<Fake, Clip>| m.frame(ui), m);
    h.run_steps(4);
    h.get_by_label("ADMIN").click();
    h.run_steps(4);
    let asked: Vec<Request> = store.requests.borrow_mut().drain(..).collect();
    assert!(matches!(asked.as_slice(), [Request::Status]), "{asked:?}");
    store
        .events
        .borrow_mut()
        .push(StoreEvent::Status(Ok(AdminStatus {
            vault: true,
            locked: true,
            untrusted: None,
            memory_locked: Some(true),
            tpm: Some(true),
            keyslots: Vec::new(),
            rotation_pending: false,
            secret_service: Some("alephd".into()),
        })));
    h.run_steps(4);

    h.get_by_label("BACK UP…").click();
    // (A portal asked would connect to the bus here: watch for a second.)
    let until = Instant::now() + Duration::from_secs(1);
    let mut connected = false;
    while Instant::now() < until {
        h.step();
        match listener.accept() {
            Ok(_) => {
                connected = true;
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("{e}"),
        }
    }
    assert!(!connected, "the session bus was asked for the portal");
    h.get_by_label("Backup path");
    assert!(
        store.requests.borrow().is_empty(),
        "nothing asked of alephd"
    );
}
