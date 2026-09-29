//! The manager window, driven as a person would (egui_kittest), against a
//! stand-in store and clipboard; snapshots of its views in both themes.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use aleph_daemon::prompt::{Channel, FromPrompter, Method, Purpose, ToPrompter};
use aleph_gui::clipboard::Backend;
use aleph_gui::filepicker::{Fake as Picker, Pick};
use aleph_gui::manager::{Manager, Page, SIZE};
use aleph_gui::settings::{Settings, ThemeChoice};
use aleph_gui::store::{
    AdminStatus, Collection, Item, Request, SlotInfo, Store, StoreEvent, Vault,
};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use zeroize::Zeroizing;

/// The store's stand-in: requests are recorded, events are queued by the
/// test.
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

impl Fake {
    fn send(&self, e: StoreEvent) {
        self.events.borrow_mut().push(e);
    }
    fn take(&self) -> Vec<Request> {
        self.requests.borrow_mut().drain(..).collect()
    }
}

#[derive(Clone, Default)]
struct Clip(std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>);

impl Backend for Clip {
    fn offer(&mut self, secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(secret.to_vec());
        Ok(())
    }
    fn still_ours(&self) -> bool {
        self.0.lock().unwrap().is_some()
    }
    fn clear(&mut self) {
        *self.0.lock().unwrap() = None;
    }
}

type Window = Harness<'static, Manager<Fake, Clip>>;

fn item(path: &str, label: &str, attrs: &[(&str, &str)]) -> Item {
    Item {
        path: path.into(),
        label: label.into(),
        attributes: attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        created: 1_790_553_600,
        modified: 1_790_553_600,
    }
}

fn vault() -> Vault {
    Vault::Unlocked(vec![
        Collection {
            path: "/c/login".into(),
            label: "Login".into(),
            is_default: true,
            items: vec![
                item(
                    "/c/login/1",
                    "GitHub token",
                    &[("service", "github.com"), ("user", "kyle")],
                ),
                item(
                    "/c/login/2",
                    "Mail app password",
                    &[("service", "imap.example.org")],
                ),
            ],
        },
        Collection {
            path: "/c/work".into(),
            label: "work".into(),
            is_default: false,
            items: vec![item("/c/work/1", "VPN", &[("service", "vpn")])],
        },
    ])
}

fn window(theme: ThemeChoice, v: Vault) -> (Window, Fake, Clip) {
    window_sized(theme, v, SIZE)
}

fn window_sized(theme: ThemeChoice, v: Vault, size: [f32; 2]) -> (Window, Fake, Clip) {
    window_with(theme, v, size, |m| m)
}

/// A window whose manager `configure` may change before it first draws.
fn window_with(
    theme: ThemeChoice,
    v: Vault,
    size: [f32; 2],
    configure: impl FnOnce(Manager<Fake, Clip>) -> Manager<Fake, Clip>,
) -> (Window, Fake, Clip) {
    let settings = Settings {
        theme,
        scanlines: true,
        ..Settings::default()
    };
    window_full(settings, v, size, configure)
}

/// `window_with`, from whole settings (a reveal hold, say).
fn window_full(
    settings: Settings,
    v: Vault,
    size: [f32; 2],
    configure: impl FnOnce(Manager<Fake, Clip>) -> Manager<Fake, Clip>,
) -> (Window, Fake, Clip) {
    let store = Fake::default();
    let clip = Clip::default();
    let home = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/home");
    let mut m = configure(Manager::new(
        store.clone(),
        clip.clone(),
        settings,
        Some(home),
        true,
    ));
    m.confirm_guard = Duration::ZERO;
    let palette = m.palette.clone();
    store.send(StoreEvent::Vault(v));
    let mut h = Harness::builder()
        .with_size(egui::Vec2::from(size))
        .build_ui_state(|ui, m: &mut Manager<Fake, Clip>| m.frame(ui), m);
    aleph_gui::theme::apply(&h.ctx, &palette);
    frames(&mut h);
    (h, store, clip)
}

fn frames(h: &mut Window) {
    h.run_steps(4);
}

/// Let the reader thread deliver (the confirmation is asynchronous).
fn settle(h: &mut Window) {
    for _ in 0..40 {
        h.step();
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn type_into(h: &mut Window, label: &str, text: &str) {
    h.get_by_label(label).focus();
    frames(h);
    h.get_by_label(label).type_text(text);
    frames(h);
}

/// Play alephd on the confirmation's socket: ask for the password, and
/// answer whether it was `pw`.
fn alephd_confirms(fd: std::os::fd::OwnedFd, pw: &'static str) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
        chan.send(&ToPrompter::Begin {
            purpose: Purpose::Reauth,
            operation: "Confirm it is you".into(),
            caller: None,
        })
        .unwrap();
        let reply = chan
            .ask(&ToPrompter::Ask {
                methods: vec![Method::Password],
                error: None,
                retry_after: None,
            })
            .unwrap();
        let ok = matches!(reply, FromPrompter::Password { password } if password.expose() == pw);
        chan.done(ok, None);
        ok
    })
}

fn only(requests: Vec<Request>) -> Request {
    assert_eq!(requests.len(), 1, "{requests:?}");
    requests.into_iter().next().unwrap()
}

#[test]
fn folders_and_items_are_listed_and_searched() {
    let (mut h, _, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("Login (default)");
    h.get_by_label("GitHub token");
    h.get_by_label("VPN");
    type_into(&mut h, "Search", "imap");
    assert!(h.query_by_label("GitHub token").is_none());
    h.get_by_label("Mail app password");
}

/// Showing a secret confirms it is you first, then fetches it; within 5
/// minutes a second show does not ask again.
#[test]
fn a_secret_is_shown_after_the_confirmation() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    let Request::Reauth(fd) = only(store.take()) else {
        panic!("no confirmation");
    };
    let alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(alephd.join().unwrap());
    settle(&mut h);
    match only(store.take()) {
        Request::Secret(p) => assert_eq!(p, "/c/login/1"),
        other => panic!("{other:?}"),
    }
    store.send(StoreEvent::Secret {
        path: "/c/login/1".into(),
        secret: Zeroizing::new(b"ghp_s3cret".to_vec()),
        content_type: "text/plain".into(),
    });
    frames(&mut h);
    h.get_by_label("ghp_s3cret");
    h.get_by_label("HIDE").click();
    frames(&mut h);
    assert!(h.query_by_label("ghp_s3cret").is_none());
    // Within 5 minutes: fetched at once.
    h.get_by_label("SHOW").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Secret(_)));
}

/// alephd's messages to the confirmation wake the window: with animations
/// off nothing else would draw the next frame.
#[test]
fn the_confirmation_wakes_the_window() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    let Request::Reauth(fd) = only(store.take()) else {
        panic!("no confirmation");
    };
    // (Settle the frames the click asked for, then let alephd speak.)
    for _ in 0..10 {
        h.step();
    }
    let alephd = std::thread::spawn(move || {
        let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
        chan.send(&ToPrompter::Begin {
            purpose: Purpose::Reauth,
            operation: "Confirm it is you".into(),
            caller: None,
        })
        .unwrap();
        chan
    });
    let chan = alephd.join().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(h.ctx.has_requested_repaint(), "nothing woke the window");
    drop(chan);
}

/// A refused confirmation fetches nothing.
#[test]
fn a_refused_confirmation_fetches_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    let Request::Reauth(fd) = only(store.take()) else {
        panic!("no confirmation");
    };
    let alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "wrong");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(!alephd.join().unwrap());
    settle(&mut h);
    assert!(store.take().is_empty());
}

/// A copy goes to the clipboard (and nowhere on screen).
#[test]
fn a_copy_goes_to_the_clipboard() {
    let (mut h, store, clip) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("COPY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Secret(_)));
    store.send(StoreEvent::Secret {
        path: "/c/login/1".into(),
        secret: Zeroizing::new(b"ghp_s3cret".to_vec()),
        content_type: "text/plain".into(),
    });
    frames(&mut h);
    assert_eq!(clip.0.lock().unwrap().as_deref(), Some(&b"ghp_s3cret"[..]));
    assert!(h.query_by_label("ghp_s3cret").is_none());
    h.get_by_label_contains("COPIED");
}

/// Editing the label saves only the label (the secret was never loaded).
#[test]
fn an_edited_label_is_saved() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    type_into(&mut h, "Label", " (work)");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    match only(store.take()) {
        Request::SetLabel { path, label } => {
            assert_eq!(path, "/c/login/1");
            assert_eq!(label, "GitHub token (work)");
        }
        other => panic!("{other:?}"),
    }
}

/// A new item goes to the selected folder, with the attributes typed.
#[test]
fn a_new_item_is_created_in_the_folder() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("work").click();
    frames(&mut h);
    h.get_by_label("+ ITEM").click();
    frames(&mut h);
    type_into(&mut h, "Label", "Router");
    type_into(&mut h, "Secret", "admin123");
    h.get_by_label("+ ATTRIBUTE").click();
    frames(&mut h);
    type_into(&mut h, "Attribute 1 key", "host");
    type_into(&mut h, "Attribute 1 value", "192.168.1.1");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    match only(store.take()) {
        Request::CreateItem {
            collection,
            label,
            attributes,
            secret,
        } => {
            assert_eq!(collection, "/c/work");
            assert_eq!(label, "Router");
            assert_eq!(
                attributes,
                BTreeMap::from([("host".into(), "192.168.1.1".into())])
            );
            assert_eq!(&secret[..], b"admin123");
        }
        other => panic!("{other:?}"),
    }
}

/// Delete asks first; No deletes nothing.
#[test]
fn delete_asks_first() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("VPN").click();
    frames(&mut h);
    h.get_by_label("DELETE").click();
    frames(&mut h);
    h.get_by_label("Delete 'VPN'?");
    h.get_by_label("No").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    h.get_by_label("DELETE").click();
    frames(&mut h);
    h.get_by_label("Yes").click();
    frames(&mut h);
    match only(store.take()) {
        Request::DeleteItem(p) => assert_eq!(p, "/c/work/1"),
        other => panic!("{other:?}"),
    }
}

/// A lock hides what is shown and forgets the confirmation; Unlock asks
/// alephd.
#[test]
fn a_lock_seals_the_window() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    store.take();
    store.send(StoreEvent::Secret {
        path: "/c/login/1".into(),
        secret: Zeroizing::new(b"ghp_s3cret".to_vec()),
        content_type: "text/plain".into(),
    });
    frames(&mut h);
    h.get_by_label("ghp_s3cret");
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    assert!(h.query_by_label("ghp_s3cret").is_none());
    assert!(
        h.state()
            .reauth
            .needed(Instant::now(), Duration::from_secs(300))
    );
    h.get_by_label("VAULT SEALED");
    h.get_by_label("UNLOCK").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    // Unlocked again: the secret is not back until shown (and confirmed).
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    assert!(h.query_by_label("ghp_s3cret").is_none());
}

/// A secret that is not text is not shown (its length is), and can still
/// be copied.
#[test]
fn a_binary_secret_is_not_shown() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    store.take();
    store.send(StoreEvent::Secret {
        path: "/c/login/1".into(),
        secret: Zeroizing::new(vec![0xff, 0xfe, 0x00, 0x01]),
        content_type: "application/octet-stream".into(),
    });
    frames(&mut h);
    h.get_by_label("binary secret, 4 bytes");
}

const JSON: &[u8] = br#"{"user":"kyle","scopes":["repo","read:org"],"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"}"#;

/// A JSON secret is shown indented (what is copied or edited is the
/// secret as stored).
#[test]
fn a_json_secret_is_shown_indented() {
    let (mut h, store, clip) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    store.take();
    secret(&store, "/c/login/1", br#"{"user":"kyle","n":[1,2]}"#);
    frames(&mut h);
    h.get_by_label("{\n  \"user\": \"kyle\",\n  \"n\": [\n    1,\n    2\n  ]\n}");
    h.get_by_label("COPY").click();
    frames(&mut h);
    store.take();
    secret(&store, "/c/login/1", br#"{"user":"kyle","n":[1,2]}"#);
    frames(&mut h);
    assert_eq!(
        clip.0.lock().unwrap().as_deref(),
        Some(&br#"{"user":"kyle","n":[1,2]}"#[..])
    );
}

/// A label another program chose (long, with line breaks of its own) is
/// shown on one line, cut short, in the list.
#[test]
fn a_hostile_label_stays_on_one_line_in_the_list() {
    let label = format!("GitHub\n\nALEPH // UNLOCK VAULT\n{}", "w".repeat(500));
    let v = Vault::Unlocked(vec![Collection {
        path: "/c/login".into(),
        label: "Login".into(),
        is_default: true,
        items: vec![item("/c/login/1", &label, &[])],
    }]);
    let (h, _, _) = window(ThemeChoice::Neon, v);
    let row = h.get_by_label_contains("GitHub");
    let text = row.accesskit_node().label().unwrap_or_default().to_string();
    assert!(!text.contains('\n'), "{text:?}");
    assert!(text.chars().count() <= 61, "{}", text.chars().count());
}

fn secret(store: &Fake, path: &str, bytes: &[u8]) {
    store.send(StoreEvent::Secret {
        path: path.into(),
        secret: Zeroizing::new(bytes.to_vec()),
        content_type: "text/plain".into(),
    });
}

fn done(store: &Fake, request: &'static str, error: Option<&str>) {
    store.send(StoreEvent::Done {
        request,
        error: error.map(Into::into),
        dismissed: false,
    });
}

/// After LOAD SECRET, a save sends only what changed: an unchanged secret
/// is not rewritten.
#[test]
fn a_loaded_secret_is_saved_only_if_changed() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    h.get_by_label("LOAD SECRET").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Secret(_)));
    secret(&store, "/c/login/1", b"ghp_s3cret");
    frames(&mut h);
    type_into(&mut h, "Label", "!");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::SetLabel { .. }));
}

/// A secret that is not text is not loaded into the editor.
#[test]
fn a_binary_secret_is_not_editable() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    h.get_by_label("LOAD SECRET").click();
    frames(&mut h);
    store.take();
    secret(&store, "/c/login/1", &[0xff, 0xfe]);
    frames(&mut h);
    assert!(h.query_by_label("Secret").is_none());
    h.get_by_label_contains("not editable");
}

/// A save that fails keeps the form, with what was typed; one that
/// succeeds closes it.
#[test]
fn a_failed_save_keeps_the_form() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("+ ITEM").click();
    frames(&mut h);
    type_into(&mut h, "Label", "Router");
    type_into(&mut h, "Secret", "admin123");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::CreateItem { .. }));
    h.get_by_label("SAVING…");
    done(
        &store,
        "create the item",
        Some("org.freedesktop.Secret.Error.IsLocked"),
    );
    frames(&mut h);
    assert_eq!(h.get_by_label("Label").value().as_deref(), Some("Router"));
    h.get_by_label_contains("cannot create the item");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::CreateItem { .. }));
    done(&store, "create the item", None);
    frames(&mut h);
    assert!(h.query_by_label("Label").is_none());
}

/// A secret typed into the editor survives a lock, and is saved after the
/// unlock.
#[test]
fn a_typed_secret_survives_a_lock() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    h.get_by_label("LOAD SECRET").click();
    frames(&mut h);
    store.take();
    secret(&store, "/c/login/1", b"old");
    frames(&mut h);
    type_into(&mut h, "Secret", "new");
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    h.get_by_label("SAVE").click();
    frames(&mut h);
    match only(store.take()) {
        Request::SetSecret { secret, .. } => assert_eq!(&secret[..], b"oldnew"),
        other => panic!("{other:?}"),
    }
}

/// A save's answer belongs to its form: another form opened while alephd's
/// prompt waits (a new folder's confirmation) can still be saved, and is
/// not closed by the old answer.
#[test]
fn a_save_answer_belongs_to_its_form() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("+ FOLDER").click();
    frames(&mut h);
    type_into(&mut h, "Folder name", "tmp");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::CreateCollection(_)));
    h.get_by_label("VPN").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    type_into(&mut h, "Label", " typed");
    assert!(!h.get_by_label("SAVE").accesskit_node().is_disabled());
    done(&store, "create the folder", None);
    frames(&mut h);
    assert_eq!(
        h.get_by_label("Label").value().as_deref(),
        Some("VPN typed")
    );
}

/// A failed fetch of an earlier secret does not drop the one asked for
/// last.
#[test]
fn a_failed_fetch_does_not_drop_the_one_asked_for_last() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    h.get_by_label("VPN").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    store.take();
    store.send(StoreEvent::SecretFailed {
        path: "/c/login/1".into(),
        error: "gone".into(),
    });
    done(&store, "fetch the secret", Some("gone"));
    secret(&store, "/c/work/1", b"vpn-pw");
    frames(&mut h);
    h.get_by_label("vpn-pw");
}

/// Moving to another item cancels a secret still on its way: it is never
/// held unseen.
#[test]
fn moving_on_cancels_a_secret_still_coming() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    store.take();
    h.get_by_label("VPN").click();
    frames(&mut h);
    secret(&store, "/c/login/1", b"ghp_s3cret");
    frames(&mut h);
    assert!(h.state().shown.is_none());
}

/// Leaving the window hides a shown secret and ends a confirmation (which
/// would otherwise hold alephd's conversation lock).
#[test]
fn leaving_the_window_hides_the_secret_and_ends_the_confirmation() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    store.take();
    secret(&store, "/c/login/1", b"ghp_s3cret");
    frames(&mut h);
    h.get_by_label("ghp_s3cret");
    h.event(egui::Event::WindowFocused(false));
    frames(&mut h);
    assert!(h.query_by_label("ghp_s3cret").is_none());
    // A confirmation in progress ends: alephd sees its socket close.
    h.state_mut().reauth.forget();
    h.get_by_label("SHOW").click();
    frames(&mut h);
    let Request::Reauth(fd) = only(store.take()) else {
        panic!("no confirmation");
    };
    h.event(egui::Event::WindowFocused(false));
    frames(&mut h);
    let mut theirs = std::os::unix::net::UnixStream::from(fd);
    theirs
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(std::io::Read::read(&mut theirs, &mut buf).unwrap(), 0);
}

/// An item deleted elsewhere while its form is open closes the form, and
/// says why.
#[test]
fn an_item_deleted_elsewhere_closes_its_form() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("VPN").click();
    frames(&mut h);
    h.get_by_label("EDIT").click();
    frames(&mut h);
    let Vault::Unlocked(mut cols) = vault() else {
        unreachable!()
    };
    cols[1].items.clear();
    store.send(StoreEvent::Vault(Vault::Unlocked(cols)));
    frames(&mut h);
    assert!(h.query_by_label("Label").is_none());
    h.get_by_label_contains("deleted elsewhere");
}

/// With no folder at all, a new item says to create one first.
#[test]
fn a_new_item_without_a_folder_says_so() {
    let (mut h, _, _) = window(ThemeChoice::Neon, Vault::Unlocked(vec![]));
    h.get_by_label("+ ITEM").click();
    frames(&mut h);
    h.get_by_label_contains("create a folder first");
}

/// Enter on the delete question answers its default: No.
#[test]
fn enter_on_the_delete_question_says_no() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("VPN").click();
    frames(&mut h);
    h.get_by_label("DELETE").click();
    frames(&mut h);
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(store.take().is_empty());
    assert!(h.query_by_label("Delete 'VPN'?").is_none());
}

#[test]
fn without_alephd_the_link_is_down() {
    let (h, _, _) = window(ThemeChoice::Neon, Vault::Unreachable("no such name".into()));
    h.get_by_label("LINK DOWN");
}

/// The list's right edge (its search field spans it).
fn list_edge(h: &Window) -> f32 {
    h.get_by_label("Search").rect().right()
}

/// Half a screen (Hyprland's side-by-side tiling): the list and the
/// detail share what the navigation leaves, evenly.
#[test]
fn a_narrow_window_splits_list_and_detail_evenly() {
    let (mut h, _, _) = window_sized(ThemeChoice::Neon, vault(), [640.0, 560.0]);
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    let edge = list_edge(&h);
    let detail = 640.0 - edge;
    assert!(detail > 230.0, "the detail pane is {detail} wide");
    assert!(
        (edge - (130.0 + 255.0)).abs() < 20.0,
        "the list ends at {edge}"
    );
}

/// Drag the divider from where it is by `dx`.
fn drag_divider(h: &mut Window, dx: f32) {
    let x = list_edge(h) + 8.0;
    let y = 300.0;
    let press = |x: f32, pressed| egui::Event::PointerButton {
        pos: egui::pos2(x, y),
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    h.event(egui::Event::PointerMoved(egui::pos2(x, y)));
    frames(h);
    h.event(press(x, true));
    frames(h);
    for step in 1..=6 {
        h.event(egui::Event::PointerMoved(egui::pos2(
            x + dx * step as f32 / 6.0,
            y,
        )));
        h.step();
    }
    h.event(press(x + dx, false));
    frames(h);
}

/// A vault like a real one: many items, some with long labels (the list
/// scrolls, and its rows are wider than it).
fn crowded() -> Vault {
    let items = (0..40)
        .map(|i| {
            item(
                &format!("/c/login/{i}"),
                &format!("Password for 'proton-sso-account-{i}' on 'account.proton.me'"),
                &[("service", "proton")],
            )
        })
        .collect();
    Vault::Unlocked(vec![Collection {
        path: "/c/login".into(),
        label: "Login".into(),
        is_default: true,
        items,
    }])
}

/// With a real vault's list, the divider drags both ways.
#[test]
fn the_divider_drags_with_a_crowded_list() {
    let (mut h, _, _) = window_sized(ThemeChoice::Neon, crowded(), [620.0, 560.0]);
    frames(&mut h);
    let start = list_edge(&h);
    drag_divider(&mut h, 60.0);
    let wider = list_edge(&h);
    assert!(
        wider > start + 40.0,
        "right: the list ended at {start}, now {wider}"
    );
    drag_divider(&mut h, -120.0);
    let narrower = list_edge(&h);
    assert!(
        narrower < wider - 80.0,
        "left: the list ended at {wider}, now {narrower}"
    );
}

/// At half a screen the divider drags right too (a long label wants a
/// wider list): the detail's floor must not stop it at once.
#[test]
fn the_list_widens_at_half_a_screen() {
    let (mut h, _, _) = window_sized(ThemeChoice::Neon, vault(), [620.0, 560.0]);
    frames(&mut h);
    let before = list_edge(&h);
    drag_divider(&mut h, 60.0);
    let after = list_edge(&h);
    assert!(
        after > before + 40.0,
        "the list ended at {before}, now {after}"
    );
}

/// The divider between the list and the detail drags.
#[test]
fn the_list_divider_drags() {
    let (mut h, _, _) = window_sized(ThemeChoice::Neon, vault(), [640.0, 560.0]);
    frames(&mut h);
    let before = list_edge(&h);
    drag_divider(&mut h, -60.0);
    let after = list_edge(&h);
    assert!(
        after < before - 40.0,
        "the list ended at {before}, now {after}"
    );
    // Retiled to full width: the list keeps its share, not its width.
    let share = (after - 130.0) / (640.0 - 130.0);
    h.set_size(egui::vec2(1200.0, 560.0));
    frames(&mut h);
    let wide = list_edge(&h);
    let expected = 130.0 + share * (1200.0 - 130.0);
    assert!(
        (wide - expected).abs() < 20.0,
        "the list ends at {wide}, not {expected}"
    );
}

// --- SETTINGS ---

fn config(idle: &str, prompt: &str, suspend: &str) -> StoreEvent {
    StoreEvent::Config(Ok(BTreeMap::from([
        ("lock.on_suspend".to_string(), suspend.to_string()),
        ("lock.on_screen_lock".to_string(), "true".to_string()),
        ("lock.idle_timeout".to_string(), idle.to_string()),
        ("prompt.timeout".to_string(), prompt.to_string()),
    ])))
}

/// Open SETTINGS, answer the read with the given values.
fn open_settings(h: &mut Window, store: &Fake, idle: &str, prompt: &str, suspend: &str) {
    h.get_by_label("SETTINGS").click();
    frames(h);
    assert!(matches!(only(store.take()), Request::Config));
    store.send(config(idle, prompt, suspend));
    frames(h);
}

/// Pick `option` in the list called `control` (its label ends with the
/// selected value: `Idle lock: 15 min`).
fn pick(h: &mut Window, control: &str, option: &str) {
    h.get_by_label_contains(&format!("{control}:")).click();
    frames(h);
    h.get_by_label(option).click();
    frames(h);
}

fn press(h: &mut Window, label: &str, key: egui::Key, times: usize) {
    h.get_by_label(label).focus();
    frames(h);
    for _ in 0..times {
        h.key_press(key);
        frames(h);
    }
}

fn saved_map(fd_and_map: Request) -> (std::os::fd::OwnedFd, BTreeMap<String, String>) {
    match fd_and_map {
        Request::SetConfigs(fd, map) => (fd, map),
        other => panic!("{other:?}"),
    }
}

#[test]
fn settings_are_asked_for_once_and_shown() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Config));
    h.get_by_label("LOADING…");
    frames(&mut h);
    // (Not asked again while it is on its way.)
    assert!(store.take().is_empty());
    store.send(config("900", "300", "true"));
    frames(&mut h);
    h.get_by_label("Lock on suspend");
    h.get_by_label("Lock on screen lock");
    h.get_by_label("Idle lock: 15 min");
    h.get_by_label("Prompt timeout: 5 min");
    h.get_by_label_contains("Saving asks you to confirm it is you, once");
    // (Unlocked: nothing to say about a seal.)
    assert!(
        h.query_by_label("VAULT SEALED :: SAVE WILL UNLOCK FIRST")
            .is_none()
    );
    assert_eq!(h.state().page(), aleph_gui::manager::Page::Settings);
}

/// One SAVE, one confirmation, only the changed keys (Review Focus 5:
/// and one request: the page shows the confirmation, not the button).
#[test]
fn an_edit_is_saved_with_one_confirmation_and_only_the_changed_keys() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    pick(&mut h, "Prompt timeout", "30 min");
    h.get_by_label("Lock on screen lock").click();
    frames(&mut h);
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (fd, map) = saved_map(only(store.take()));
    assert_eq!(
        map,
        BTreeMap::from([
            ("lock.idle_timeout".to_string(), "900".to_string()),
            ("lock.on_screen_lock".to_string(), "false".to_string()),
            ("prompt.timeout".to_string(), "1800".to_string()),
        ])
    );
    // The confirmation is in the window; the form is not (no second Save).
    assert!(h.query_by_label("SAVE").is_none());
    let alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(alephd.join().unwrap());
    settle(&mut h);
    h.get_by_label_contains("SETTINGS SAVED");
    // Read again, and the reveal window opened: it is the same proof.
    assert!(matches!(only(store.take()), Request::Config));
    assert!(
        !h.state()
            .reauth
            .needed(Instant::now(), Duration::from_secs(300))
    );
    store.send(config("900", "1800", "true"));
    frames(&mut h);
    assert!(!h.state().form().unwrap().edited());
}

#[test]
fn cancel_puts_the_read_values_back() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    assert!(h.state().form().unwrap().edited());
    h.get_by_label("CANCEL").click();
    frames(&mut h);
    assert!(!h.state().form().unwrap().edited());
    h.get_by_label("Idle lock: Off");
    assert!(store.take().is_empty());
}

#[test]
fn a_bad_custom_value_shows_why_and_cannot_be_saved() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Prompt timeout", "Custom…");
    // Chosen, still empty: nothing said yet, and nothing to save.
    assert!(h.query_by_label("whole minutes, 1 to 1440").is_none());
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    type_into(&mut h, "Prompt timeout minutes", "1441");
    h.get_by_label("whole minutes, 1 to 1440");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    // Fixed as typed: the message goes and SAVE works.
    press(&mut h, "Prompt timeout minutes", egui::Key::Backspace, 4);
    type_into(&mut h, "Prompt timeout minutes", "20");
    assert!(h.query_by_label("whole minutes, 1 to 1440").is_none());
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (_fd, map) = saved_map(only(store.take()));
    assert_eq!(
        map,
        BTreeMap::from([("prompt.timeout".to_string(), "1200".to_string())])
    );
}

#[test]
fn a_value_that_is_not_a_preset_is_shown_and_kept() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "7200", "90", "true");
    h.get_by_label("Idle lock: Custom (120 min)");
    h.get_by_label("Prompt timeout: Custom (90 s)");
    // Nothing edited: Save has nothing to send.
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(store.take().is_empty());
}

#[test]
fn the_suspend_warning_shows_while_it_is_off() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    assert!(h.query_by_label_contains("hibernation image").is_none());
    h.get_by_label("Lock on suspend").click();
    frames(&mut h);
    h.get_by_label_contains(
        "the master key can reach a hibernation image unless swap is encrypted",
    );
    h.get_by_label("Lock on suspend").click();
    frames(&mut h);
    assert!(h.query_by_label_contains("hibernation image").is_none());
}

#[test]
fn unsaved_edits_are_kept_across_screens() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    h.get_by_label("GitHub token");
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    assert!(store.take().is_empty(), "read again");
    h.get_by_label("Idle lock: 15 min");
    assert!(h.state().form().unwrap().edited());
}

/// Reopening SETTINGS with nothing edited reads the values again.
#[test]
fn reopening_settings_reads_again_when_unedited() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Config));
    store.send(config("900", "300", "true"));
    frames(&mut h);
    h.get_by_label("Idle lock: 15 min");
}

/// alephd going away during the unlock a save waits for drops the save.
#[test]
fn alephd_going_away_drops_a_save_waiting_for_the_unlock() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(StoreEvent::Vault(Vault::Unreachable("gone".into())));
    frames(&mut h);
    h.get_by_label_contains("nothing was saved");
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    assert!(
        store.take().is_empty(),
        "no save, no re-read of an edited form"
    );
    h.get_by_label("Idle lock: 15 min");
}

/// A locked vault: the values show, Save says it will unlock first, asks
/// alephd to unlock, and confirms and saves once the vault is open.
#[test]
fn a_locked_vault_says_save_unlocks_first_and_then_saves() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("VAULT SEALED :: SAVE WILL UNLOCK FIRST");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    // Only the unlock, so far: no confirmation until the vault is open.
    assert!(matches!(only(store.take()), Request::Unlock));
    h.get_by_label("waiting for the unlock…");
    store.send(StoreEvent::Done {
        request: "unlock",
        error: None,
        dismissed: false,
    });
    frames(&mut h);
    assert!(store.take().is_empty(), "the vault is not open yet");
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    let (_fd, map) = saved_map(only(store.take()));
    assert_eq!(
        map,
        BTreeMap::from([("lock.idle_timeout".to_string(), "900".to_string())])
    );
}

/// A dismissed (or failed) unlock saves nothing and leaves the edits; a
/// vault unlocked later, by anything else, does not resume the save.
#[test]
fn a_dismissed_unlock_saves_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(StoreEvent::Done {
        request: "unlock",
        error: None,
        dismissed: true,
    });
    frames(&mut h);
    h.get_by_label_contains("nothing was saved");
    h.get_by_label("Idle lock: 15 min");
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    assert!(store.take().is_empty(), "nothing asked for the save");
    // (And the note is gone with the seal.)
    assert!(
        h.query_by_label("VAULT SEALED :: SAVE WILL UNLOCK FIRST")
            .is_none()
    );
}

/// SETTINGS left while the unlock runs: the save is not made, and the
/// window says so (nothing is dropped silently).
#[test]
fn a_save_waiting_for_the_unlock_says_so_when_it_is_not_made() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    assert!(store.take().is_empty(), "saved from another screen");
    h.get_by_label_contains("the settings were not saved");
    assert!(h.state().form().unwrap().edited());
}

#[test]
fn with_alephd_down_the_settings_wait_for_the_link() {
    let (mut h, store, _) = window(
        ThemeChoice::Neon,
        Vault::Unreachable("org.freedesktop.secrets has no owner".into()),
    );
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    assert!(store.take().is_empty(), "nothing to ask");
    h.get_by_label("LINK DOWN");
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Config));
}

#[test]
fn a_failed_read_says_why_and_can_be_retried() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    store.take();
    store.send(StoreEvent::Config(Err("no reply from alephd".into())));
    frames(&mut h);
    h.get_by_label_contains("no reply from alephd");
    h.get_by_label("RETRY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Config));
}

/// A save alephd refuses (before it asks) keeps the edits and says why.
#[test]
fn a_refused_save_keeps_the_edits_and_says_why() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (_fd, _) = saved_map(only(store.take()));
    store.send(StoreEvent::Done {
        request: "save the settings",
        error: Some("prompt.timeout must be 1 to 86400 seconds, not \"0\"".into()),
        dismissed: false,
    });
    frames(&mut h);
    h.get_by_label_contains("cannot save the settings");
    h.get_by_label("Idle lock: 15 min");
    assert!(h.state().form().unwrap().edited());
    assert!(store.take().is_empty(), "no re-read: nothing changed");
}

/// A save's refusal that comes after its confirmation ended (no save
/// running) is still said, not dropped.
#[test]
fn a_late_refused_save_still_says_why() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    store.send(StoreEvent::Done {
        request: "save the settings",
        error: Some("boom".into()),
        dismissed: false,
    });
    frames(&mut h);
    h.get_by_label_contains("cannot save the settings: boom");
}

/// (Review Focus 5.) A confirmation the person cancels saves nothing and
/// leaves the edits.
#[test]
fn a_cancelled_confirmation_saves_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (fd, _) = saved_map(only(store.take()));
    // (alephd asks; the answer is the person's Cancel.)
    let alephd = std::thread::spawn(move || {
        let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
        chan.send(&ToPrompter::Begin {
            purpose: Purpose::Reauth,
            operation: "Set lock.idle_timeout = 900".into(),
            caller: None,
        })
        .unwrap();
        chan.ask(&ToPrompter::Ask {
            methods: vec![Method::Password],
            error: None,
            retry_after: None,
        })
        .is_err()
    });
    settle(&mut h);
    h.get_by_label("Login password");
    h.key_press(egui::Key::Escape);
    frames(&mut h);
    assert!(alephd.join().unwrap(), "not cancelled");
    settle(&mut h);
    h.get_by_label_contains("cancelled: nothing was saved");
    assert!(store.take().is_empty(), "no re-read: nothing changed");
    h.get_by_label("Idle lock: 15 min");
}

/// Answer the re-read an interrupted save asked for: the idle lock as
/// read, the prompt timeout changed meanwhile (15 min).
fn reread_after_interruption(h: &mut Window, store: &Fake) {
    assert!(matches!(only(store.take()), Request::Config), "no re-read");
    store.send(config("0", "900", "true"));
    frames(h);
    // The unedited control follows what is in force; the edit stays.
    h.get_by_label("Prompt timeout: 15 min");
    h.get_by_label("Idle lock: 15 min");
    let form = h.state().form().unwrap();
    assert_eq!(
        form.changes(),
        BTreeMap::from([("lock.idle_timeout".to_string(), "900".to_string())])
    );
}

/// Open SETTINGS, edit the idle lock, and SAVE: the confirmation's fd.
fn save_an_edit(h: &mut Window, store: &Fake) -> std::os::fd::OwnedFd {
    open_settings(h, store, "0", "300", "true");
    pick(h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(h);
    saved_map(only(store.take())).0
}

/// A confirmation that ends with no answer from alephd may have saved or
/// not: the window says so, and reads the values again, keeping the edits.
#[test]
fn a_confirmation_closed_without_an_answer_may_not_have_saved() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    let fd = save_an_edit(&mut h, &store);
    drop(fd);
    settle(&mut h);
    h.get_by_label_contains("may not have been saved");
    reread_after_interruption(&mut h, &store);
}

/// (Review Focus 5.) The vault locking under a confirmation ends it; the
/// save may have gone through, so the values are read again (the edits
/// stay).
#[test]
fn a_lock_during_the_confirmation_may_not_have_saved_and_reads_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    let _fd = save_an_edit(&mut h, &store);
    store.send(StoreEvent::Vault(Vault::Locked));
    settle(&mut h);
    h.get_by_label_contains("the vault locked: the save may not have gone through");
    reread_after_interruption(&mut h, &store);
    assert!(h.state().form().unwrap().edited());
}

/// alephd going away under a confirmation says so (not "the vault
/// locked"), and the values are read again once it is back.
#[test]
fn alephd_going_away_during_the_confirmation_reads_again_when_back() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    let _fd = save_an_edit(&mut h, &store);
    store.send(StoreEvent::Vault(Vault::Unreachable("gone".into())));
    settle(&mut h);
    h.get_by_label_contains("alephd went away: the save may not have gone through");
    assert!(store.take().is_empty(), "nothing to ask while it is away");
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    reread_after_interruption(&mut h, &store);
}

/// Leaving the window under a settings confirmation ends it; the save
/// may have gone through, so the values are read again (the edits stay).
#[test]
fn leaving_the_window_during_a_settings_confirmation_reads_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    let fd = save_an_edit(&mut h, &store);
    h.event(egui::Event::WindowFocused(false));
    frames(&mut h);
    h.get_by_label_contains("may not have been saved");
    reread_after_interruption(&mut h, &store);
    drop(fd);
}

/// An unlock that fails while a save waits for it saves nothing, says
/// why, and a vault unlocked later does not resume the save.
#[test]
fn a_failed_unlock_drops_the_waiting_save() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(StoreEvent::Done {
        request: "unlock",
        error: Some("the TPM is busy".into()),
        dismissed: false,
    });
    frames(&mut h);
    h.get_by_label_contains("the TPM is busy");
    h.get_by_label_contains("nothing was saved");
    assert!(h.query_by_label("waiting for the unlock…").is_none());
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    assert!(store.take().is_empty(), "saved after all");
    h.get_by_label("Idle lock: 15 min");
}

/// A save resumed after the unlock waits for the window to have the
/// keyboard: its confirmation would otherwise hold alephd's conversation
/// lock, unseen.
#[test]
fn a_resumed_save_waits_for_the_window_to_be_focused() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    // (alephd's unlock prompt has the keyboard.)
    h.input_mut().focused = false;
    h.event(egui::Event::WindowFocused(false));
    frames(&mut h);
    h.get_by_label("waiting for the unlock…");
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    assert!(store.take().is_empty(), "confirmation opened unseen");
    // (Unlocked now: what it waits for is this window.)
    assert!(h.query_by_label("waiting for the unlock…").is_none());
    h.get_by_label("unlocked: click this window to finish saving");
    h.input_mut().focused = true;
    h.event(egui::Event::WindowFocused(true));
    frames(&mut h);
    assert!(
        h.query_by_label("unlocked: click this window to finish saving")
            .is_none()
    );
    let (_fd, map) = saved_map(only(store.take()));
    assert_eq!(
        map,
        BTreeMap::from([("lock.idle_timeout".to_string(), "900".to_string())])
    );
}

/// A window whose gui.toml is `dir/aleph/gui.toml`.
fn display_window(
    theme: ThemeChoice,
    file: std::path::PathBuf,
    broken: Option<&str>,
) -> (Window, Fake) {
    let broken = broken.map(String::from);
    let (h, store, _) = window_with(theme, vault(), SIZE, move |m| {
        m.with_settings_file(Some(file), broken)
    });
    (h, store)
}

fn gui_toml(file: &std::path::Path) -> Settings {
    Settings::load(file).0
}

/// DISPLAY needs no confirmation and no Save: each change is written at
/// once and takes effect at once.
#[test]
fn display_changes_are_written_and_apply_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("aleph/gui.toml");
    let (mut h, store) = display_window(ThemeChoice::Auto, file.clone(), None);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    store.take();
    let before = h.state().palette.clone();
    h.get_by_label("Neon").click();
    frames(&mut h);
    assert_eq!(h.state().settings().theme, ThemeChoice::Neon);
    assert_ne!(h.state().palette.accent, before.accent, "re-themed at once");
    assert_eq!(gui_toml(&file).theme, ThemeChoice::Neon);
    h.get_by_label("Scanlines").click();
    frames(&mut h);
    assert!(!h.state().settings().scanlines);
    assert!(!gui_toml(&file).scanlines);
    h.get_by_label("Reveal confirmation lasts: 5 min");
    pick(&mut h, "Reveal confirmation lasts", "Every time");
    assert_eq!(gui_toml(&file).reveal_hold, 0);
    // "Every time": even a confirmation just given does not hold.
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    // (The only request is the confirmation SHOW now asks for: nothing
    // DISPLAY did asked alephd for anything.)
    assert!(matches!(only(store.take()), Request::Reauth(_)));
}

/// (Review Focus 4.) A hold in the file that is not a preset is shown as it
/// is and stays until another is picked.
#[test]
fn a_reveal_hold_that_is_not_a_preset_is_shown_and_kept() {
    let settings = Settings {
        theme: ThemeChoice::Neon,
        reveal_hold: 45,
        ..Settings::default()
    };
    let (mut h, _store, _) = window_full(settings, vault(), SIZE, |m| m);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label("Reveal confirmation lasts: Custom (45 s)");
    pick(&mut h, "Reveal confirmation lasts", "15 min");
    h.get_by_label("Reveal confirmation lasts: 15 min");
    assert_eq!(h.state().settings().reveal_hold, 900);
}

#[test]
fn a_broken_gui_toml_is_shown_and_never_overwritten_until_reset() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("gui.toml");
    std::fs::write(&file, "scanline = false\n# mine\n").unwrap();
    let broken = format!(
        "{}: unknown field `scanline` (using the defaults)",
        file.display()
    );
    let (mut h, _store) = display_window(ThemeChoice::Neon, file.clone(), Some(&broken));
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label_contains("unknown field `scanline`");
    // The controls are disabled: a click changes nothing.
    for control in ["Auto", "Neon", "Scanlines"] {
        assert!(
            h.get_by_label(control).accesskit_node().is_disabled(),
            "{control} is enabled"
        );
    }
    h.get_by_label("Auto").click();
    h.get_by_label("Scanlines").click();
    frames(&mut h);
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "scanline = false\n# mine\n"
    );
    h.get_by_label("RESET TO DEFAULTS").click();
    frames(&mut h);
    assert_eq!(Settings::load(&file), (Settings::default(), None));
    assert!(h.query_by_label_contains("unknown field").is_none());
    // Working now.
    h.get_by_label("Scanlines").click();
    frames(&mut h);
    assert!(!gui_toml(&file).scanlines);
}

/// A file that cannot be written says so, and the change holds for this run.
#[test]
fn a_failed_write_says_so_and_the_change_holds() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").unwrap();
    let (mut h, _store) = display_window(ThemeChoice::Auto, blocker.join("gui.toml"), None);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label("Neon").click();
    frames(&mut h);
    h.get_by_label_contains("not saved");
    assert_eq!(h.state().settings().theme, ThemeChoice::Neon);
}

/// A write that works again clears the "not saved" it follows.
#[test]
fn a_write_that_works_again_clears_the_not_saved_status() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").unwrap();
    let file = blocker.join("gui.toml");
    let (mut h, _store) = display_window(ThemeChoice::Auto, file.clone(), None);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label("Neon").click();
    frames(&mut h);
    h.get_by_label_contains("not saved");
    std::fs::remove_file(&blocker).unwrap();
    h.get_by_label("Auto").click();
    frames(&mut h);
    assert!(h.query_by_label_contains("not saved").is_none());
    assert_eq!(gui_toml(&file).theme, ThemeChoice::Auto);
}

/// A change whose write failed is written with the next one that works:
/// the "not saved" goes only once nothing is left unsaved.
#[test]
fn an_unsaved_change_is_written_with_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").unwrap();
    let file = blocker.join("gui.toml");
    let (mut h, _store) = display_window(ThemeChoice::Auto, file.clone(), None);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label("Scanlines").click();
    frames(&mut h);
    h.get_by_label_contains("not saved");
    std::fs::remove_file(&blocker).unwrap();
    h.get_by_label("Neon").click();
    frames(&mut h);
    let on_disk = gui_toml(&file);
    assert!(!on_disk.scanlines, "the unsaved change was dropped");
    assert_eq!(on_disk.theme, ThemeChoice::Neon);
    assert!(h.query_by_label_contains("not saved").is_none());
}

/// While writes keep failing, the "not saved" stays.
#[test]
fn a_second_failed_write_keeps_the_not_saved_status() {
    let dir = tempfile::tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").unwrap();
    let (mut h, _store) = display_window(ThemeChoice::Auto, blocker.join("gui.toml"), None);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label("Scanlines").click();
    frames(&mut h);
    h.get_by_label_contains("not saved");
    h.get_by_label("Neon").click();
    frames(&mut h);
    h.get_by_label_contains("not saved");
}

/// A DISPLAY change writes only its own field over what is in the file
/// now: a hand-edit made while the window runs is kept.
#[test]
fn a_display_change_keeps_a_hand_edit_made_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("gui.toml");
    std::fs::write(&file, "theme = \"neon\"\n").unwrap();
    let (mut h, _store) = display_window(ThemeChoice::Auto, file.clone(), None);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    std::fs::write(&file, "theme = \"neon\"\nreveal_hold = 900\n").unwrap();
    h.get_by_label("Scanlines").click();
    frames(&mut h);
    let on_disk = gui_toml(&file);
    assert_eq!(on_disk.reveal_hold, 900, "the hand-edit was reverted");
    assert_eq!(on_disk.theme, ThemeChoice::Neon);
    assert!(!on_disk.scanlines);
    assert!(!h.state().settings().scanlines);
}

/// A reset that cannot be written changes nothing: the settings in force
/// and the file's error stay, and the window says so.
#[test]
fn a_failed_reset_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("gui.toml");
    std::fs::create_dir(&file).unwrap();
    std::fs::write(file.join("inside"), b"x").unwrap();
    let broken = format!("{}: Is a directory (using the defaults)", file.display());
    let (mut h, _store) = display_window(ThemeChoice::Neon, file.clone(), Some(&broken));
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    let palette = h.state().palette.clone();
    h.get_by_label("RESET TO DEFAULTS").click();
    frames(&mut h);
    h.get_by_label_contains("not reset");
    assert_eq!(h.state().settings().theme, ThemeChoice::Neon);
    assert_eq!(h.state().palette.accent, palette.accent);
    h.get_by_label_contains("Is a directory (using the defaults)");
    h.get_by_label("RESET TO DEFAULTS");
}

/// Reduced motion: the Scanlines control says they are off anyway.
#[test]
fn the_scanlines_control_says_reduced_motion_turns_them_off() {
    let (mut h, _store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label_contains("reduced motion");
}

// --- ADMIN ---

fn slot(id: &str, label: &str, kind: &str, stale: bool) -> SlotInfo {
    SlotInfo {
        id: id.into(),
        label: label.into(),
        kind: kind.into(),
        created: 1_790_553_600,
        stale,
    }
}

fn admin_status() -> AdminStatus {
    AdminStatus {
        vault: true,
        locked: false,
        untrusted: None,
        memory_locked: Some(true),
        tpm: Some(true),
        keyslots: vec![
            slot("1", "tpm", "tpm", false),
            slot("2", "yubikey", "fido2", false),
            slot("3", "recovery", "recovery", false),
            slot("4", "login password", "login-password", true),
        ],
        rotation_pending: false,
        secret_service: Some("alephd".into()),
    }
}

/// Open ADMIN and answer the status read.
fn open_admin(h: &mut Window, store: &Fake, status: AdminStatus) {
    h.get_by_label("ADMIN").click();
    frames(h);
    assert!(matches!(only(store.take()), Request::Status));
    store.send(StoreEvent::Status(Ok(status)));
    frames(h);
}

/// A `Done` for `request` (`done` above sends one; this builds it).
fn done_event(request: &'static str, error: Option<&str>) -> StoreEvent {
    StoreEvent::Done {
        request,
        error: error.map(String::from),
        dismissed: false,
    }
}

#[test]
fn admin_reads_the_status_once_and_shows_it() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("ADMIN").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
    h.get_by_label("LOADING…");
    frames(&mut h);
    assert!(
        store.take().is_empty(),
        "not asked again while it is on its way"
    );
    store.send(StoreEvent::Status(Ok(admin_status())));
    frames(&mut h);
    h.get_by_label("vault  unlocked · secret service  alephd");
    h.get_by_label("TPM  usable · master key  locked in RAM");
    assert_eq!(h.state().page(), Page::Admin);
    // Leaving and returning reads it again (there are no edits to keep).
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    h.get_by_label("ADMIN").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}

#[test]
fn slots_get_their_buttons() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("Remove keyslot tpm");
    h.get_by_label("Remove keyslot yubikey");
    h.get_by_label("Remove keyslot login password");
    assert!(h.query_by_label("Remove keyslot recovery").is_none());
    h.get_by_label("Retry keyslot login password");
    assert!(h.query_by_label("Retry keyslot tpm").is_none());
    h.get_by_label("STALE");
}

#[test]
fn warnings_show_only_when_true_and_rotating_now_rotates() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    assert!(h.query_by_label_contains("writes refused").is_none());
    assert!(
        h.query_by_label_contains("a password change is pending")
            .is_none()
    );
    let mut s = admin_status();
    s.untrusted = Some("rolled back to an older version".into());
    s.rotation_pending = true;
    // (Read again: leave and return.)
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    open_admin(&mut h, &store, s);
    h.get_by_label_contains("writes refused: rolled back to an older version");
    h.get_by_label_contains("a password change is pending");
    h.get_by_label("ROTATE NOW").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::RotateMaster(_)));
}

/// Operations that go straight to alephd's confirmation, each with the
/// request that fits.
#[test]
fn the_plain_actions_send_their_requests() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("+ TPM").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::AddTpm(_)));
    end_confirmation(&mut h, &store);

    h.get_by_label("+ SECURITY KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::AddFido2(_, false)));
    end_confirmation(&mut h, &store);

    h.get_by_label("touch alone").click();
    frames(&mut h);
    h.get_by_label("anyone holding the key can unlock");
    h.get_by_label("+ SECURITY KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::AddFido2(_, true)));
    end_confirmation(&mut h, &store);

    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::RotateMaster(_)));
}

/// The request (and with it alephd's end of the confirmation) is gone:
/// the confirmation closes with no answer, the operation may have gone
/// through, so the status is read again; answer it, back on the page.
fn end_confirmation(h: &mut Window, store: &Fake) {
    settle(h);
    h.get_by_label_contains("the operation may not have gone through");
    assert!(matches!(only(store.take()), Request::Status));
    store.send(StoreEvent::Status(Ok(admin_status())));
    frames(h);
}

#[test]
fn remove_asks_first_with_no_the_default() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("Remove keyslot yubikey").click();
    frames(&mut h);
    assert!(store.take().is_empty(), "nothing before Yes");
    h.get_by_label(
        "Remove keyslot 'yubikey'? This rotates the master key. The key can no longer unlock the vault.",
    );
    // (No has the focus, though the click left it on REMOVE.)
    assert!(h.get_by_label("No").accesskit_node().is_focused());
    h.get_by_label("No").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    h.get_by_label("Remove keyslot yubikey").click();
    frames(&mut h);
    assert!(h.get_by_label("No").accesskit_node().is_focused());
    h.get_by_label("Yes").click();
    frames(&mut h);
    match only(store.take()) {
        Request::RemoveKeyslot(_, id) => assert_eq!(id, "2"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_new_recovery_key_asks_first() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("NEW RECOVERY KEY").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    h.get_by_label("The current recovery key stops working as soon as the new one is issued.");
    h.get_by_label("Yes").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::ReissueRecovery(_)));
}

#[test]
fn retrying_a_slot_is_immediate_and_reads_the_status_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("Retry keyslot login password").click();
    frames(&mut h);
    match only(store.take()) {
        Request::RetryKeyslot(id) => assert_eq!(id, "4"),
        other => panic!("{other:?}"),
    }
    store.send(done_event("retry the keyslot", None));
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}

/// A sealed vault: status shows, the note says every action unlocks first,
/// and an action asks for the unlock, then its confirmation.
#[test]
fn a_sealed_vault_unlocks_first() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST");
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    h.get_by_label("waiting for the unlock…");
    // Nothing else starts while it waits.
    h.get_by_label("+ TPM").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    store.send(done_event("unlock", None));
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    let requests = store.take();
    assert!(
        requests
            .iter()
            .any(|r| matches!(r, Request::RotateMaster(_))),
        "{requests:?}"
    );
    assert!(!requests.iter().any(|r| matches!(r, Request::AddTpm(_))));
}

/// (Review Focus 4.) A dismissed unlock runs nothing, and a later unlock by
/// something else does not resume it.
#[test]
fn a_dismissed_unlock_runs_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, Vault::Locked);
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(StoreEvent::Done {
        request: "unlock",
        error: None,
        dismissed: true,
    });
    frames(&mut h);
    h.get_by_label_contains("nothing was changed");
    store.send(StoreEvent::Vault(vault()));
    frames(&mut h);
    let requests = store.take();
    assert!(
        !requests
            .iter()
            .any(|r| matches!(r, Request::RotateMaster(_))),
        "{requests:?}"
    );
}

/// (Review Focus 5.) A refusal says why, changes nothing, and the status is
/// read again.
#[test]
fn a_refused_operation_says_why_and_reads_the_status_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    let Request::RotateMaster(_fd) = only(store.take()) else {
        panic!("no rotation");
    };
    store.send(done_event(
        "rotate the master key",
        Some("would leave only the recovery slot"),
    ));
    frames(&mut h);
    h.get_by_label_contains("cannot rotate the master key: would leave only the recovery slot");
    assert!(matches!(only(store.take()), Request::Status));
}

/// (Review Focus 5.) A lock during the confirmation may have let the
/// operation through: it says so, and the status is read again.
#[test]
fn a_lock_during_an_operation_may_have_let_it_through() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    let _request = only(store.take());
    store.send(StoreEvent::Vault(Vault::Locked));
    settle(&mut h);
    h.get_by_label_contains("the operation may not have gone through");
    let requests = store.take();
    assert!(
        requests.iter().any(|r| matches!(r, Request::Status)),
        "{requests:?}"
    );
}

#[test]
fn a_successful_operation_says_so_and_reads_the_status_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("ROTATE MASTER KEY").click();
    frames(&mut h);
    let Request::RotateMaster(fd) = only(store.take()) else {
        panic!("no rotation");
    };
    let alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(alephd.join().unwrap());
    settle(&mut h);
    h.get_by_label_contains("MASTER KEY ROTATED");
    assert!(matches!(only(store.take()), Request::Status));
}

#[test]
fn with_no_vault_the_page_says_so_and_offers_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    let mut s = admin_status();
    s.vault = false;
    s.keyslots.clear();
    open_admin(&mut h, &store, s);
    h.get_by_label_contains("no vault: run `alephctl setup`");
    assert!(h.query_by_label("+ TPM").is_none());
}

#[test]
fn with_alephd_down_the_page_waits_for_the_link() {
    let (mut h, store, _) = window(
        ThemeChoice::Neon,
        Vault::Unreachable("org.freedesktop.secrets has no owner".into()),
    );
    h.get_by_label("ADMIN").click();
    frames(&mut h);
    assert!(store.take().is_empty(), "nothing to ask");
    h.get_by_label("LINK DOWN");
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}

#[test]
fn a_failed_status_read_says_why_and_can_be_retried() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("ADMIN").click();
    frames(&mut h);
    store.take();
    store.send(StoreEvent::Status(Err("no reply from alephd".into())));
    frames(&mut h);
    h.get_by_label_contains("no reply from alephd");
    h.get_by_label("RETRY").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}

/// A lock or unlock changes what STATUS says (locked, memory-locked): it
/// is read again.
#[test]
fn a_lock_or_unlock_reads_the_status_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_admin(&mut h, &store, admin_status());
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Status));
}

/// Every view, in both themes.
#[test]
fn snapshots() {
    let mut failures = Vec::new();
    for (theme, suffix) in [(ThemeChoice::Neon, "neon"), (ThemeChoice::Auto, "omarchy")] {
        let mut shot = |h: &mut Window, name: &str| {
            if let Err(e) = h.try_snapshot(format!("manager_{name}_{suffix}")) {
                failures.push(e.to_string());
            }
        };
        // Half a screen, with a real vault's list: rows cut to the list.
        let (mut h, _, _) = window_sized(theme, crowded(), [620.0, 560.0]);
        h.get_by_label_contains("proton-sso-account-3'").click();
        frames(&mut h);
        shot(&mut h, "crowded");
        let (mut h, store, _) = window(theme, vault());
        shot(&mut h, "empty");
        h.get_by_label("GitHub token").click();
        frames(&mut h);
        shot(&mut h, "item");
        h.state_mut().reauth.confirmed(Instant::now());
        h.get_by_label("SHOW").click();
        frames(&mut h);
        store.take();
        store.send(StoreEvent::Secret {
            path: "/c/login/1".into(),
            secret: Zeroizing::new(b"ghp_s3cret".to_vec()),
            content_type: "text/plain".into(),
        });
        frames(&mut h);
        shot(&mut h, "shown");
        // Too wide and too long for the pane: it scrolls, both ways.
        h.get_by_label("HIDE").click();
        frames(&mut h);
        h.get_by_label("SHOW").click();
        frames(&mut h);
        store.take();
        let mut long = JSON.to_vec();
        long.truncate(long.len() - 1);
        long.extend((0..12).flat_map(|i| format!(",\"k{i}\":{i}").into_bytes()));
        long.push(b'}');
        secret(&store, "/c/login/1", &long);
        frames(&mut h);
        shot(&mut h, "shown_json");
        h.get_by_label("EDIT").click();
        frames(&mut h);
        shot(&mut h, "edit");
        h.get_by_label("CANCEL").click();
        frames(&mut h);
        h.get_by_label("+ ITEM").click();
        frames(&mut h);
        shot(&mut h, "new");
        // The confirmation, drawn inside the window (alephd has asked).
        let (mut h, store, _) = window(theme, vault());
        h.get_by_label("GitHub token").click();
        frames(&mut h);
        h.get_by_label("SHOW").click();
        frames(&mut h);
        let Request::Reauth(fd) = only(store.take()) else {
            panic!("no confirmation");
        };
        let alephd = std::thread::spawn(move || {
            let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
            chan.send(&ToPrompter::Begin {
                purpose: Purpose::Reauth,
                operation: "Confirm it is you".into(),
                caller: None,
            })
            .unwrap();
            chan.send(&ToPrompter::Ask {
                methods: vec![Method::Password],
                error: None,
                retry_after: None,
            })
            .unwrap();
            chan
        });
        let chan = alephd.join().unwrap();
        settle(&mut h);
        shot(&mut h, "confirm");
        drop(chan);
        let (mut h, _, _) = window(theme, Vault::Locked);
        shot(&mut h, "locked");
        let (mut h, _, _) = window(
            theme,
            Vault::Unreachable("org.freedesktop.secrets has no owner".into()),
        );
        shot(&mut h, "unreachable");
        // SETTINGS: the form, a bad entry, locked, the confirmation, a broken file.
        let dir = tempfile::tempdir().unwrap();
        let (mut h, store, _) = window_with(theme, vault(), SIZE, {
            let file = dir.path().join("gui.toml");
            move |m| m.with_settings_file(Some(file), None)
        });
        open_settings(&mut h, &store, "900", "300", "false");
        shot(&mut h, "settings");
        pick(&mut h, "Prompt timeout", "Custom…");
        type_into(&mut h, "Prompt timeout minutes", "1441");
        shot(&mut h, "settings_custom");
        // Back to a preset: the bad entry would keep Save off.
        pick(&mut h, "Prompt timeout", "5 min");
        pick(&mut h, "Idle lock", "30 min");
        h.get_by_label("SAVE").click();
        frames(&mut h);
        let (fd, _) = saved_map(only(store.take()));
        let alephd = std::thread::spawn(move || {
            let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
            chan.send(&ToPrompter::Begin {
                purpose: Purpose::Reauth,
                operation: "Set lock.idle_timeout = 1800".into(),
                caller: None,
            })
            .unwrap();
            chan.send(&ToPrompter::Ask {
                methods: vec![Method::Password],
                error: None,
                retry_after: None,
            })
            .unwrap();
            chan
        });
        let chan = alephd.join().unwrap();
        settle(&mut h);
        shot(&mut h, "settings_confirm");
        drop(chan);
        let (mut h, store, _) = window(theme, Vault::Locked);
        open_settings(&mut h, &store, "0", "300", "true");
        shot(&mut h, "settings_locked");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gui.toml");
        let (mut h, _) = display_window(
            theme,
            file,
            Some(
                "gui.toml: unknown field `scanline`, expected one of `theme`, `scanlines`, `reveal_hold` (using the defaults)",
            ),
        );
        h.get_by_label("SETTINGS").click();
        frames(&mut h);
        shot(&mut h, "settings_broken");
        // ADMIN: the page, a Yes/No step, sealed, with warnings, the typed path.
        let (mut h, store, _) = window(theme, vault());
        open_admin(&mut h, &store, admin_status());
        shot(&mut h, "admin");
        h.get_by_label("Remove keyslot yubikey").click();
        frames(&mut h);
        shot(&mut h, "admin_ask");
        let (mut h, store, _) = window(theme, Vault::Locked);
        let mut sealed = admin_status();
        sealed.locked = true;
        open_admin(&mut h, &store, sealed);
        shot(&mut h, "admin_sealed");
        let (mut h, store, _) = window(theme, vault());
        let mut s = admin_status();
        s.untrusted = Some("rolled back to an older version".into());
        s.rotation_pending = true;
        s.secret_service = Some("another program".into());
        open_admin(&mut h, &store, s);
        shot(&mut h, "admin_warnings");
        let (mut h, store, _) = window(theme, vault());
        open_admin(&mut h, &store, admin_status());
        h.get_by_label("type a path instead").click();
        frames(&mut h);
        // The field starts with today's date in the name: pin it.
        retype(&mut h, "Backup path", "/home/u/aleph-backup.aleph");
        shot(&mut h, "admin_path");
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The nav's LOCK: one `Request::Lock`, no confirmation, and the window
/// follows the vault event to VAULT SEALED (a shown secret goes) on the
/// same page.
#[test]
fn lock_asks_alephd_to_lock_and_the_window_follows() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.state_mut().reauth.confirmed(Instant::now());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    store.take();
    secret(&store, "/c/login/1", b"ghp_s3cret");
    frames(&mut h);
    h.get_by_label("ghp_s3cret");
    assert!(!h.get_by_label("LOCK").accesskit_node().is_disabled());
    h.get_by_label("LOCK").click();
    frames(&mut h);
    assert!(matches!(only(store.take()), Request::Lock));
    done(&store, "lock", None);
    store.send(StoreEvent::Vault(Vault::Locked));
    frames(&mut h);
    h.get_by_label("VAULT SEALED");
    assert!(h.query_by_label("ghp_s3cret").is_none());
    assert_eq!(h.state().page(), aleph_gui::manager::Page::Secrets);
    assert!(!h.state().exit_requested());
}

/// A refused lock says why in the status line.
#[test]
fn a_failed_lock_says_why() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("LOCK").click();
    frames(&mut h);
    store.take();
    done(&store, "lock", Some("alephd went away"));
    frames(&mut h);
    h.get_by_label_contains("cannot lock: alephd went away");
}

/// LOCK is only for an open vault: greyed while sealed, unreachable or
/// connecting, and a click sends nothing.
#[test]
fn lock_is_disabled_unless_the_vault_is_open() {
    for v in [
        Vault::Locked,
        Vault::Unreachable("no such name".into()),
        Vault::Connecting,
    ] {
        let (mut h, store, _) = window(ThemeChoice::Neon, v.clone());
        assert!(h.get_by_label("LOCK").accesskit_node().is_disabled());
        h.get_by_label("LOCK").click();
        frames(&mut h);
        assert!(store.take().is_empty(), "{v:?}");
    }
}

/// While a confirmation runs LOCK is greyed like the other nav buttons.
#[test]
fn lock_is_disabled_during_a_confirmation() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    let _fd = save_an_edit(&mut h, &store);
    settle(&mut h);
    assert!(h.get_by_label("LOCK").accesskit_node().is_disabled());
    h.get_by_label("LOCK").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    assert!(!h.state().exit_requested());
}

/// EXIT closes the window, and does not lock.
#[test]
fn exit_closes_the_window_without_locking() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    assert!(!h.state().exit_requested());
    h.get_by_label("EXIT").click();
    frames(&mut h);
    assert!(h.state().exit_requested());
    assert!(store.take().is_empty());
}

/// EXIT is there with the link down and with the vault sealed.
#[test]
fn exit_works_with_the_link_down_and_sealed() {
    for v in [Vault::Unreachable("no such name".into()), Vault::Locked] {
        let (mut h, _, _) = window(ThemeChoice::Neon, v);
        assert!(!h.get_by_label("EXIT").accesskit_node().is_disabled());
        h.get_by_label("EXIT").click();
        frames(&mut h);
        assert!(h.state().exit_requested());
    }
}

/// Settings edits are not lost by one click: the first says so, the second
/// closes.
#[test]
fn exit_with_unsaved_settings_asks_to_press_it_again() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("EXIT").click();
    frames(&mut h);
    assert!(!h.state().exit_requested());
    h.get_by_label_contains("Unsaved settings will be lost: press EXIT again to quit");
    h.get_by_label("EXIT").click();
    frames(&mut h);
    assert!(h.state().exit_requested());
}

/// Nothing edited, nothing to warn about: one click closes.
#[test]
fn exit_with_an_unedited_form_closes_at_once() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    h.get_by_label("EXIT").click();
    frames(&mut h);
    assert!(h.state().exit_requested());
    assert!(h.query_by_label_contains("Unsaved settings").is_none());
}

/// Cancelling the edits (or moving to another screen) puts the warning
/// away: the next click starts again.
#[test]
fn the_exit_warning_is_disarmed_by_cancel_and_by_changing_screens() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("EXIT").click();
    frames(&mut h);
    assert!(!h.state().exit_requested());
    // Another screen and back (the edits stay): armed again from scratch.
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label("EXIT").click();
    frames(&mut h);
    assert!(!h.state().exit_requested(), "closed on the second click");
    // Cancel, and one click closes.
    h.get_by_label("CANCEL").click();
    frames(&mut h);
    h.get_by_label("EXIT").click();
    frames(&mut h);
    assert!(h.state().exit_requested());
}

/// EXIT during a settings confirmation, with the edits unsaved, warns first
/// and leaves the confirmation running; the second press ends it and closes.
#[test]
fn exit_during_a_settings_confirmation_warns_then_ends_it_and_closes() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    let fd = save_an_edit(&mut h, &store);
    // (alephd's end; it fails when the window ends the conversation.)
    let _alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    h.get_by_label("Login password");
    assert!(h.state().form().unwrap().edited());
    assert!(!h.get_by_label("EXIT").accesskit_node().is_disabled());
    h.get_by_label("EXIT").click();
    settle(&mut h);
    assert!(!h.state().exit_requested());
    h.get_by_label_contains("Unsaved settings will be lost: press EXIT again to quit");
    h.get_by_label("Login password");
    h.get_by_label("EXIT").click();
    settle(&mut h);
    assert!(h.state().exit_requested());
    assert!(h.query_by_label("Login password").is_none());
}

/// A reveal confirmation with nothing edited: one EXIT closes.
#[test]
fn exit_during_a_reveal_confirmation_closes_at_once() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    h.get_by_label("GitHub token").click();
    frames(&mut h);
    h.get_by_label("SHOW").click();
    frames(&mut h);
    let Request::Reauth(fd) = only(store.take()) else {
        panic!("no confirmation");
    };
    let _alephd = alephd_confirms(fd, "hunter2");
    settle(&mut h);
    h.get_by_label("Login password");
    h.get_by_label("EXIT").click();
    settle(&mut h);
    assert!(h.state().exit_requested());
    assert!(h.query_by_label("Login password").is_none());
}

/// The warning goes away with the reason for it: a cancel or a change of
/// screen takes it off the status line (other messages stay).
#[test]
fn the_exit_warning_leaves_the_status_line_when_disarmed() {
    let warning = "Unsaved settings will be lost: press EXIT again to quit";
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("EXIT").click();
    frames(&mut h);
    h.get_by_label_contains(warning);
    h.get_by_label("CANCEL").click();
    frames(&mut h);
    assert!(h.query_by_label_contains(warning).is_none());
    // A page change does the same.
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("EXIT").click();
    frames(&mut h);
    h.get_by_label_contains(warning);
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    assert!(h.query_by_label_contains(warning).is_none());
    // Another message is not taken down.
    done(&store, "lock", Some("boom"));
    frames(&mut h);
    h.get_by_label_contains("cannot lock: boom");
    h.get_by_label("SETTINGS").click();
    frames(&mut h);
    h.get_by_label_contains("cannot lock: boom");
}

// ---- BACK UP… (Plan 5d, Task 6) ----

/// A window whose save dialog is `picks` (a fake), on the ADMIN page.
fn backup_window(picks: Vec<Pick>) -> (Window, Fake, std::sync::Arc<Picker>) {
    backup_window_in(vault(), picks)
}

/// `backup_window`, with the vault as `v` (sealed, say).
fn backup_window_in(v: Vault, picks: Vec<Pick>) -> (Window, Fake, std::sync::Arc<Picker>) {
    let picker = std::sync::Arc::new(Picker::new(picks));
    let handle = picker.clone();
    let (mut h, store, _) = window_with(ThemeChoice::Neon, v, SIZE, move |m| {
        m.with_file_picker(Box::new(handle))
    });
    open_admin(&mut h, &store, admin_status());
    (h, store, picker)
}

fn backup_request(store: &Fake) -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    match only(store.take()) {
        Request::Backup(fd, file) => (fd, file),
        other => panic!("{other:?}"),
    }
}

/// Play alephd for a backup: ask for the password and, if it is `pw`,
/// write the backup into `file` before saying so (alephd writes and syncs
/// the file before its `done`).
fn alephd_backs_up(
    fd: std::os::fd::OwnedFd,
    file: std::os::fd::OwnedFd,
    pw: &'static str,
) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
        chan.send(&ToPrompter::Begin {
            purpose: Purpose::Reauth,
            operation: "Back up the vault".into(),
            caller: None,
        })
        .unwrap();
        let reply = chan
            .ask(&ToPrompter::Ask {
                methods: vec![Method::Password],
                error: None,
                retry_after: None,
            })
            .unwrap();
        let ok = matches!(reply, FromPrompter::Password { password } if password.expose() == pw);
        if ok {
            use std::io::Write;
            (&std::fs::File::from(file)).write_all(b"backup").unwrap();
        }
        chan.done(ok, None);
        ok
    })
}

/// Clear the field called `label` and type `text` into it.
fn retype(h: &mut Window, label: &str, text: &str) {
    h.get_by_label(label).focus();
    frames(h);
    for _ in 0..200 {
        h.key_press(egui::Key::Backspace);
    }
    frames(h);
    type_into(h, label, text);
}

/// Choose `path` in the (fake) dialog and get the backup's request.
fn start_backup(
    path: &std::path::Path,
) -> (Window, Fake, std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
    let (mut h, store, _) = backup_window(vec![Pick::Chosen(path.to_path_buf())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    let (fd, file) = backup_request(&store);
    assert!(path.exists());
    (h, store, fd, file)
}

#[test]
fn a_chosen_path_gets_a_private_new_file_and_a_confirmation() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, picker) = backup_window(vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    // The dialog was asked for a dated suggestion.
    let asked = picker.asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert!(
        asked[0].0.starts_with("aleph-backup-") && asked[0].0.ends_with(".aleph"),
        "{asked:?}"
    );
    let (fd, file) = backup_request(&store);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // alephd writes into the file and confirms.
    let alephd = alephd_backs_up(fd, file, "hunter2");
    settle(&mut h);
    type_into(&mut h, "Login password", "hunter2");
    h.key_press(egui::Key::Enter);
    frames(&mut h);
    assert!(alephd.join().unwrap());
    settle(&mut h);
    h.get_by_label_contains(&format!(
        "BACKED UP :: {} (it opens only with your recovery key)",
        path.display()
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"backup");
    assert!(matches!(only(store.take()), Request::Status));
    // (And it stays once the window is gone.)
    drop(h);
    assert_eq!(std::fs::read(&path).unwrap(), b"backup");
}

/// (Review Focus 1.) A confirmation that ends with no answer leaves no
/// empty file behind.
#[test]
fn a_cancelled_backup_removes_the_empty_file_it_made() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, _) = backup_window(vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    let (fd, file) = backup_request(&store);
    assert!(path.exists());
    drop(fd);
    drop(file);
    settle(&mut h);
    h.get_by_label_contains("the operation may not have gone through");
    assert!(
        !path.exists(),
        "an empty file the manager made stays behind"
    );
}

/// (Review Focus 1.) The person's Cancel in the confirmation removes the
/// empty file too.
#[test]
fn a_backup_cancelled_by_the_person_removes_the_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, _store, fd, _file) = start_backup(&path);
    let alephd = std::thread::spawn(move || {
        let mut chan = Channel::from_fd(fd, Duration::from_secs(10)).unwrap();
        chan.send(&ToPrompter::Begin {
            purpose: Purpose::Reauth,
            operation: "Back up the vault".into(),
            caller: None,
        })
        .unwrap();
        chan.ask(&ToPrompter::Ask {
            methods: vec![Method::Password],
            error: None,
            retry_after: None,
        })
        .is_err()
    });
    settle(&mut h);
    h.get_by_label("Login password");
    h.key_press(egui::Key::Escape);
    frames(&mut h);
    assert!(alephd.join().unwrap(), "not cancelled");
    settle(&mut h);
    h.get_by_label_contains("cancelled: nothing was changed");
    assert!(!path.exists());
}

/// (Review Focus 1.) A file with content is refused and left alone.
#[test]
fn an_existing_file_is_refused_and_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.aleph");
    std::fs::write(&path, b"precious").unwrap();
    let (mut h, store, _) = backup_window(vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(store.take().is_empty(), "nothing asked of alephd");
    h.get_by_label_contains("choose a new name");
    assert_eq!(std::fs::read(&path).unwrap(), b"precious");
    drop(h);
    assert_eq!(std::fs::read(&path).unwrap(), b"precious");
}

/// (Review Focus 1.) An empty file that was already there is used, and
/// stays when the backup does not happen.
#[test]
fn an_empty_file_already_there_is_used_and_not_removed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.aleph");
    std::fs::write(&path, b"").unwrap();
    let (mut h, _store, fd, file) = start_backup(&path);
    drop(fd);
    drop(file);
    settle(&mut h);
    h.get_by_label_contains("the operation may not have gone through");
    assert!(path.exists(), "not the manager's to remove");
}

#[test]
fn a_closed_dialog_does_nothing() {
    let (mut h, store, _) = backup_window(vec![Pick::Cancelled]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(store.take().is_empty());
    assert!(h.query_by_label("Backup path").is_none());
}

/// (Review Focus 2.) No portal: the typed-path field, prefilled, and
/// working.
#[test]
fn without_a_portal_the_path_is_typed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("typed.aleph");
    let (mut h, store, _) = backup_window(vec![Pick::Unavailable]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(store.take().is_empty());
    // (Prefilled with the dated name in the home directory.)
    let home = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/home");
    let prefilled = h.get_by_label("Backup path").value().unwrap_or_default();
    assert!(
        prefilled.starts_with(&format!("{}/aleph-backup-", home.display()))
            && prefilled.ends_with(".aleph"),
        "{prefilled}"
    );
    retype(&mut h, "Backup path", path.to_str().unwrap());
    h.get_by_label("BACK UP").click();
    settle(&mut h);
    let (_fd, _file) = backup_request(&store);
    assert!(path.exists());
    assert!(h.query_by_label("Backup path").is_none());
}

/// (Review Focus 2.) The typed path refuses a file with content, says why,
/// and stays open for another name.
#[test]
fn the_typed_path_refuses_an_existing_file_and_stays_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.aleph");
    std::fs::write(&path, b"precious").unwrap();
    let (mut h, store, _) = backup_window(vec![]);
    h.get_by_label("type a path instead").click();
    frames(&mut h);
    retype(&mut h, "Backup path", path.to_str().unwrap());
    h.get_by_label("BACK UP").click();
    frames(&mut h);
    assert!(store.take().is_empty());
    h.get_by_label("Backup path");
    // (In the status line and under the field.)
    assert_eq!(
        h.query_all_by_label_contains("choose a new name").count(),
        2,
        "the reason shows"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"precious");
    // Another name works.
    let new = dir.path().join("new.aleph");
    retype(&mut h, "Backup path", new.to_str().unwrap());
    h.get_by_label("BACK UP").click();
    settle(&mut h);
    let (_fd, _file) = backup_request(&store);
    assert!(new.exists());
    assert_eq!(std::fs::read(&path).unwrap(), b"precious");
}

#[test]
fn type_a_path_instead_opens_the_field_and_cancel_closes_it() {
    let (mut h, store, picker) = backup_window(vec![]);
    h.get_by_label("type a path instead").click();
    frames(&mut h);
    h.get_by_label("Backup path");
    assert!(picker.asked.lock().unwrap().is_empty(), "no dialog");
    h.get_by_label("CANCEL").click();
    frames(&mut h);
    assert!(h.query_by_label("Backup path").is_none());
    assert!(store.take().is_empty());
}

/// Leaving the ADMIN page forgets the typed-path field.
#[test]
fn leaving_the_page_forgets_the_typed_path() {
    let (mut h, store, _) = backup_window(vec![]);
    h.get_by_label("type a path instead").click();
    frames(&mut h);
    h.get_by_label("Backup path");
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    open_admin(&mut h, &store, admin_status());
    assert!(h.query_by_label("Backup path").is_none());
    h.get_by_label("BACK UP…");
}

/// A path chosen after the ADMIN page was left is not used: no file, and
/// it says so.
#[test]
fn a_path_chosen_after_leaving_the_page_is_not_used() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (tx, rx) = std::sync::mpsc::channel();
    struct Slow(std::sync::Mutex<Option<std::sync::mpsc::Receiver<Pick>>>);
    impl aleph_gui::filepicker::FilePicker for Slow {
        fn start(
            &self,
            _: String,
            _: Option<std::path::PathBuf>,
        ) -> std::sync::mpsc::Receiver<Pick> {
            self.0.lock().unwrap().take().unwrap()
        }
    }
    let slow = Slow(std::sync::Mutex::new(Some(rx)));
    let (mut h, store, _) = window_with(ThemeChoice::Neon, vault(), SIZE, move |m| {
        m.with_file_picker(Box::new(slow))
    });
    open_admin(&mut h, &store, admin_status());
    h.get_by_label("BACK UP…").click();
    frames(&mut h);
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    tx.send(Pick::Chosen(path.clone())).unwrap();
    settle(&mut h);
    assert!(store.take().is_empty());
    assert!(!path.exists());
    h.get_by_label_contains("not backed up");
}

/// (Review Focus 2.) alephd refuses a path inside its own directory: the
/// reason shows, and the empty file goes.
#[test]
fn a_refused_backup_says_why_and_removes_the_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inside.aleph");
    let (mut h, store, _fd, file) = start_backup(&path);
    drop(file);
    store.send(done_event(
        "back up",
        Some("a backup cannot go inside /home/u/.local/share/aleph"),
    ));
    settle(&mut h);
    h.get_by_label_contains("cannot back up: a backup cannot go inside");
    assert!(!path.exists());
}

/// A lock during the confirmation: it may have gone through, but the file
/// is still empty, so it goes.
#[test]
fn a_lock_during_a_backup_removes_the_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, _fd, _file) = start_backup(&path);
    store.send(StoreEvent::Vault(Vault::Locked));
    settle(&mut h);
    h.get_by_label_contains("the vault locked: the operation may not have gone through");
    assert!(!path.exists());
}

/// alephd going away during the confirmation removes the empty file.
#[test]
fn alephd_going_away_during_a_backup_removes_the_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, _fd, _file) = start_backup(&path);
    store.send(StoreEvent::Vault(Vault::Unreachable("gone".into())));
    settle(&mut h);
    h.get_by_label_contains("alephd went away");
    assert!(!path.exists());
}

/// Leaving the window during the confirmation removes the empty file.
#[test]
fn leaving_the_window_during_a_backup_removes_the_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, _store, _fd, _file) = start_backup(&path);
    h.event(egui::Event::WindowFocused(false));
    settle(&mut h);
    h.get_by_label_contains("the window lost focus");
    assert!(!path.exists());
}

/// EXIT during the confirmation removes the empty file.
#[test]
fn exit_during_a_backup_removes_the_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, _store, _fd, _file) = start_backup(&path);
    h.get_by_label("EXIT").click();
    settle(&mut h);
    assert!(h.state().exit_requested());
    assert!(!path.exists());
}

/// A sealed vault: the path is chosen and the file made first, then alephd
/// unlocks, then the confirmation.
#[test]
fn a_sealed_vault_unlocks_first_for_a_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, _) = backup_window_in(Vault::Locked, vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    assert!(path.exists(), "the file is made before the unlock");
    store.send(done_event("unlock", None));
    store.send(StoreEvent::Vault(vault()));
    settle(&mut h);
    assert!(
        store
            .take()
            .iter()
            .any(|r| matches!(r, Request::Backup(..)))
    );
    assert!(path.exists());
}

/// A dismissed unlock removes the file it had made.
#[test]
fn a_dismissed_unlock_removes_the_backup_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, _) = backup_window_in(Vault::Locked, vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(StoreEvent::Done {
        request: "unlock",
        error: None,
        dismissed: true,
    });
    settle(&mut h);
    h.get_by_label_contains("the unlock was dismissed: nothing was changed");
    assert!(!path.exists());
}

/// A failed unlock removes the file it had made.
#[test]
fn a_failed_unlock_removes_the_backup_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, _) = backup_window_in(Vault::Locked, vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(done_event("unlock", Some("the TPM is busy")));
    settle(&mut h);
    h.get_by_label_contains("cannot unlock: the TPM is busy");
    assert!(!path.exists());
}

/// alephd going away while the backup waits for the unlock removes the
/// file.
#[test]
fn alephd_going_away_during_the_unlock_removes_the_backup_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, _) = backup_window_in(Vault::Locked, vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    store.send(StoreEvent::Vault(Vault::Unreachable("gone".into())));
    settle(&mut h);
    h.get_by_label_contains("alephd went away: nothing was changed");
    assert!(!path.exists());
}

/// The page left while the backup waits for the unlock: once open, it is
/// not run, says so, and its file goes.
#[test]
fn a_backup_unlocked_after_leaving_the_page_is_not_run_and_its_file_goes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mine.aleph");
    let (mut h, store, _) = backup_window_in(Vault::Locked, vec![Pick::Chosen(path.clone())]);
    h.get_by_label("BACK UP…").click();
    settle(&mut h);
    assert!(matches!(only(store.take()), Request::Unlock));
    h.get_by_label("SECRETS").click();
    frames(&mut h);
    store.send(done_event("unlock", None));
    store.send(StoreEvent::Vault(vault()));
    settle(&mut h);
    assert!(
        !store
            .take()
            .iter()
            .any(|r| matches!(r, Request::Backup(..)))
    );
    h.get_by_label_contains("the vault unlocked: the operation was not run");
    assert!(!path.exists());
}
