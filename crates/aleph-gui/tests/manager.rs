//! The manager window, driven as a person would (egui_kittest), against a
//! stand-in store and clipboard; snapshots of its views in both themes.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use aleph_daemon::prompt::{Channel, FromPrompter, Method, Purpose, ToPrompter};
use aleph_gui::clipboard::Backend;
use aleph_gui::manager::{Manager, SIZE};
use aleph_gui::settings::{Settings, ThemeChoice};
use aleph_gui::store::{Collection, Item, Request, Store, StoreEvent, Vault};
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
}

/// (Review Focus 5.) A confirmation that is cancelled saves nothing and
/// leaves the edits.
#[test]
fn a_cancelled_confirmation_saves_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (fd, _) = saved_map(only(store.take()));
    drop(fd);
    settle(&mut h);
    h.get_by_label_contains("nothing was saved");
    assert!(store.take().is_empty(), "no re-read: nothing changed");
    h.get_by_label("Idle lock: 15 min");
}

/// (Review Focus 5.) The vault locking under a confirmation ends it and
/// says nothing was saved.
#[test]
fn a_lock_during_the_confirmation_saves_nothing() {
    let (mut h, store, _) = window(ThemeChoice::Neon, vault());
    open_settings(&mut h, &store, "0", "300", "true");
    pick(&mut h, "Idle lock", "15 min");
    h.get_by_label("SAVE").click();
    frames(&mut h);
    let (_fd, _) = saved_map(only(store.take()));
    store.send(StoreEvent::Vault(Vault::Locked));
    settle(&mut h);
    h.get_by_label_contains("nothing was saved");
    h.get_by_label("Idle lock: 15 min");
    assert!(h.state().form().unwrap().edited());
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
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
