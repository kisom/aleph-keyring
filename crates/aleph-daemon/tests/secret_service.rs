//! The Secret Service against real clients: a private `dbus-daemon`, the
//! daemon served in-process, and libsecret's `secret-tool`.

use std::io::Write;
use std::process::{Command, Stdio};

use aleph_daemon::secret::service::SecretService;
use aleph_daemon::testing::*;

struct Served {
    _bus: Bus,
    address: String,
    svc: Arc<SecretService>,
    launcher: Arc<InteractiveLauncher>,
    _conn: zbus::Connection,
    _env: Env,
}

/// A daemon with a fresh, unlocked vault, serving on a private bus.
async fn served(prompts: Vec<Vec<FromPrompter>>) -> Served {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let bus = bus();
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.secrets")
        .unwrap()
        .build()
        .await
        .unwrap();
    let launcher = Arc::new(InteractiveLauncher::new(prompts));
    let svc = SecretService::new(Arc::new(k), launcher.clone());
    svc.serve(&conn).await.unwrap();
    Served {
        address: bus.address.clone(),
        _bus: bus,
        svc,
        launcher,
        _conn: conn,
        _env: env,
    }
}

/// Run secret-tool on the private bus: `(exit ok, stdout, stderr)`.
async fn secret_tool(s: &Served, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let (address, args, stdin) = (
        s.address.clone(),
        args.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        stdin.map(str::to_string),
    );
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new("secret-tool")
            .args(&args)
            .env("DBUS_SESSION_BUS_ADDRESS", address)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("secret-tool (Arch: pacman -S libsecret)");
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn secret_tool_stores_looks_up_searches_and_clears() {
    let s = served(vec![]).await;
    let (ok, _, err) = secret_tool(
        &s,
        &[
            "store",
            "--label=Test entry",
            "service",
            "aleph-test",
            "user",
            "alice",
        ],
        Some("hunter2"),
    )
    .await;
    assert!(ok, "store: {err}");
    let (ok, out, err) = secret_tool(
        &s,
        &["lookup", "service", "aleph-test", "user", "alice"],
        None,
    )
    .await;
    assert!(ok, "lookup: {err}");
    assert_eq!(out, "hunter2");
    // (secret-tool prints attributes, and any error, on stderr.)
    let (ok, out, err) = secret_tool(&s, &["search", "--all", "service", "aleph-test"], None).await;
    assert!(ok);
    assert!(out.contains("label = Test entry"), "{out}");
    assert!(out.contains("secret = hunter2"), "{out}{err}");
    assert!(err.contains("attribute.user = alice"), "{err}");
    let (ok, _, err) = secret_tool(
        &s,
        &["clear", "service", "aleph-test", "user", "alice"],
        None,
    )
    .await;
    assert!(ok, "clear: {err}");
    let (ok, out, _) = secret_tool(
        &s,
        &["lookup", "service", "aleph-test", "user", "alice"],
        None,
    )
    .await;
    assert!(!ok && out.is_empty());
}

fn launched(s: &Served) -> usize {
    s.launcher
        .launched
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// §4 "Locked search": a lookup while locked is not a false "not found".
/// libsecret unlocks the placeholder the search returns, the prompter runs
/// once, and the lookup gets the secret.
#[tokio::test(flavor = "multi_thread")]
async fn a_locked_lookup_prompts_once_and_finds_the_secret() {
    let s = served(vec![vec![password(PW)]]).await;
    let stored = secret_tool(
        &s,
        &["store", "--label=T", "service", "x", "user", "a"],
        Some("pw"),
    )
    .await;
    assert!(stored.0, "{stored:?}");
    s.svc.lock().await.unwrap();
    let (ok, out, err) = secret_tool(&s, &["lookup", "service", "x", "user", "a"], None).await;
    assert!(ok, "{err}");
    assert_eq!(out, "pw");
    assert_eq!(launched(&s), 1);
}

/// With no prompter (no graphical session), the lookup waits rather than
/// failing, and completes when the vault is unlocked some other way.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_prompter_a_locked_lookup_waits_for_an_unlock_elsewhere() {
    let s = served(vec![]).await;
    secret_tool(
        &s,
        &["store", "--label=T", "service", "x", "user", "a"],
        Some("pw"),
    )
    .await;
    s.svc.lock().await.unwrap();
    let lookup = {
        let (address, svc) = (s.address.clone(), s.svc.clone());
        let _ = svc;
        tokio::task::spawn_blocking(move || {
            Command::new("secret-tool")
                .args(["lookup", "service", "x", "user", "a"])
                .env("DBUS_SESSION_BUS_ADDRESS", address)
                .stdin(Stdio::null())
                .output()
                .unwrap()
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(!lookup.is_finished(), "the lookup should be waiting");
    // "alephctl unlock" in a terminal: unlock through another channel.
    let keyring = s.svc.keyring.clone();
    tokio::task::spawn_blocking(move || {
        keyring.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
    })
    .await
    .unwrap()
    .unwrap();
    s.svc.unlocked().await.unwrap();
    let out = tokio::time::timeout(std::time::Duration::from_secs(10), lookup)
        .await
        .expect("the lookup completes after the unlock")
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "pw");
}

/// Cancelling the prompter dismisses the prompt: the lookup ends without a
/// secret (as with gnome-keyring when the user cancels).
#[tokio::test(flavor = "multi_thread")]
async fn cancelling_the_prompt_ends_the_lookup_empty_handed() {
    let s = served(vec![vec![FromPrompter::Cancel {}]]).await;
    secret_tool(
        &s,
        &["store", "--label=T", "service", "x", "user", "a"],
        Some("pw"),
    )
    .await;
    s.svc.lock().await.unwrap();
    let (ok, out, _) = secret_tool(&s, &["lookup", "service", "x", "user", "a"], None).await;
    assert!(!ok && out.is_empty());
    assert!(s.svc.keyring.is_locked());
}

/// Storing while locked unlocks first (libsecret unlocks the default
/// collection), then stores.
#[tokio::test(flavor = "multi_thread")]
async fn storing_while_locked_unlocks_first() {
    let s = served(vec![vec![password(PW)]]).await;
    s.svc.lock().await.unwrap();
    let (ok, _, err) = secret_tool(&s, &["store", "--label=T", "service", "y"], Some("pw2")).await;
    assert!(ok, "{err}");
    assert!(!s.svc.keyring.is_locked());
    let (_, out, _) = secret_tool(&s, &["lookup", "service", "y"], None).await;
    assert_eq!(out, "pw2");
}

/// Review I1: a second `Lock` while a lookup waits must not strand it: the
/// lookup still gets the secret once the vault is unlocked.
#[tokio::test(flavor = "multi_thread")]
async fn a_redundant_lock_does_not_strand_a_waiting_lookup() {
    let s = served(vec![]).await;
    secret_tool(
        &s,
        &["store", "--label=T", "service", "x", "user", "a"],
        Some("pw"),
    )
    .await;
    s.svc.lock().await.unwrap();
    let address = s.address.clone();
    let lookup = tokio::task::spawn_blocking(move || {
        Command::new("secret-tool")
            .args(["lookup", "service", "x", "user", "a"])
            .env("DBUS_SESSION_BUS_ADDRESS", address)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    s.svc.lock().await.unwrap();
    let keyring = s.svc.keyring.clone();
    tokio::task::spawn_blocking(move || {
        keyring.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
    })
    .await
    .unwrap()
    .unwrap();
    s.svc.unlocked().await.unwrap();
    let out = tokio::time::timeout(std::time::Duration::from_secs(10), lookup)
        .await
        .expect("the lookup completes")
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "pw");
}

async fn wait_until(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if done() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    done()
}

/// Review I3: a client's sessions are freed when it disconnects (libsecret
/// never closes its own).
#[tokio::test(flavor = "multi_thread")]
async fn sessions_are_freed_when_their_client_leaves() {
    let s = served(vec![]).await;
    secret_tool(&s, &["store", "--label=T", "service", "x"], Some("pw")).await;
    secret_tool(&s, &["lookup", "service", "x"], None).await;
    assert!(
        wait_until(|| s.svc.session_count() == 0).await,
        "{}",
        s.svc.session_count()
    );
}

/// Review I4: with no prompter, one client's waiting unlock prompts are
/// capped, and they go when the client leaves.
#[tokio::test(flavor = "multi_thread")]
async fn waiting_prompts_are_capped_and_dropped_with_their_client() {
    let s = served(vec![]).await;
    s.svc.lock().await.unwrap();
    let client = zbus::connection::Builder::address(s.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let service = zbus::Proxy::new(
        &client,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap();
    for _ in 0..12 {
        let (_, prompt): (
            Vec<zbus::zvariant::OwnedObjectPath>,
            zbus::zvariant::OwnedObjectPath,
        ) = service
            .call(
                "Unlock",
                &(vec![
                    zbus::zvariant::ObjectPath::try_from(
                        "/org/freedesktop/secrets/aliases/default",
                    )
                    .unwrap(),
                ],),
            )
            .await
            .unwrap();
        let p = zbus::Proxy::new(
            &client,
            "org.freedesktop.secrets",
            prompt,
            "org.freedesktop.Secret.Prompt",
        )
        .await
        .unwrap();
        // A second Prompt() on the same object is ignored.
        p.call_method("Prompt", &("",)).await.unwrap();
        // (Past the cap the prompt is dismissed and gone at once.)
        let _ = p.call_method("Prompt", &("",)).await;
    }
    assert!(
        wait_until(|| s.svc.waiting_count() == 8).await,
        "{}",
        s.svc.waiting_count()
    );
    drop(service);
    drop(client);
    assert!(
        wait_until(|| s.svc.waiting_count() == 0).await,
        "{}",
        s.svc.waiting_count()
    );
}

use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue};

async fn client(s: &Served) -> zbus::Connection {
    zbus::connection::Builder::address(s.address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap()
}

async fn service(c: &zbus::Connection) -> zbus::Proxy<'static> {
    zbus::Proxy::new(
        c,
        "org.freedesktop.secrets",
        "/org/freedesktop/secrets",
        "org.freedesktop.Secret.Service",
    )
    .await
    .unwrap()
}

async fn unlock_elsewhere(s: &Served) {
    let keyring = s.svc.keyring.clone();
    tokio::task::spawn_blocking(move || {
        keyring.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
    })
    .await
    .unwrap()
    .unwrap();
    s.svc.unlocked().await.unwrap();
}

/// Review I-A: a lock keeps sessions, so a long-lived client (libsecret
/// keeps one session per process) still reads secrets after lock and
/// unlock.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_survives_lock_and_unlock() {
    let s = served(vec![]).await;
    secret_tool(&s, &["store", "--label=T", "service", "x"], Some("pw")).await;
    let c = client(&s).await;
    let svc = service(&c).await;
    let (_, session): (OwnedValue, OwnedObjectPath) = svc
        .call("OpenSession", &("plain", zbus::zvariant::Value::from("")))
        .await
        .unwrap();
    s.svc.lock().await.unwrap();
    unlock_elsewhere(&s).await;
    let attrs: std::collections::HashMap<&str, &str> = [("service", "x")].into();
    let (found, _): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        svc.call("SearchItems", &(attrs,)).await.unwrap();
    let item = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        found[0].clone(),
        "org.freedesktop.Secret.Item",
    )
    .await
    .unwrap();
    let (secret,): ((OwnedObjectPath, Vec<u8>, Vec<u8>, String),) =
        item.call("GetSecret", &(session,)).await.unwrap();
    assert_eq!(secret.2, b"pw");
}

/// Review minor 1: `unlocked()` while (again) locked answers nobody with
/// an empty result: waiting prompts keep waiting.
#[tokio::test(flavor = "multi_thread")]
async fn waiting_prompts_are_not_answered_while_locked() {
    let s = served(vec![]).await;
    s.svc.lock().await.unwrap();
    let c = client(&s).await;
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service(&c)
        .await
        .call(
            "Unlock",
            &(vec![
                ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
            ],),
        )
        .await
        .unwrap();
    let p = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    assert!(wait_until(|| s.svc.waiting_count() == 1).await);
    s.svc.unlocked().await.unwrap();
    assert_eq!(s.svc.waiting_count(), 1);
}

/// Review I1 (captured query): the answer to a locked search survives its
/// placeholder being evicted between `Unlock` and the prompt; an unknown
/// search path is never echoed back.
#[tokio::test(flavor = "multi_thread")]
async fn a_placeholder_query_is_captured_when_unlock_is_called() {
    use futures_util::StreamExt;
    let s = served(vec![vec![password(PW)]]).await;
    secret_tool(&s, &["store", "--label=T", "service", "x"], Some("pw")).await;
    s.svc.lock().await.unwrap();
    let c = client(&s).await;
    let svc = service(&c).await;
    let attrs: std::collections::HashMap<&str, &str> = [("service", "x")].into();
    let (_, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
        svc.call("SearchItems", &(attrs.clone(),)).await.unwrap();
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) =
        svc.call("Unlock", &(locked,)).await.unwrap();
    // Evict the placeholder (more than 256 newer searches).
    let other: std::collections::HashMap<&str, &str> = [("service", "y")].into();
    for _ in 0..260 {
        let _: (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
            svc.call("SearchItems", &(other.clone(),)).await.unwrap();
    }
    let p = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    let mut completed = p.receive_signal("Completed").await.unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    let msg = tokio::time::timeout(std::time::Duration::from_secs(10), completed.next())
        .await
        .unwrap()
        .unwrap();
    let (dismissed, result): (bool, OwnedValue) = msg.body().deserialize().unwrap();
    assert!(!dismissed);
    let items: Vec<OwnedObjectPath> = result.try_into().unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert!(items[0].as_str().contains("/collection/"));
    // Unlocked now: an unknown search path yields nothing, not itself.
    let (unlocked, _): (Vec<OwnedObjectPath>, OwnedObjectPath) = svc
        .call(
            "Unlock",
            &(vec![
                ObjectPath::try_from("/org/freedesktop/secrets/search/q999999").unwrap(),
            ],),
        )
        .await
        .unwrap();
    assert!(unlocked.is_empty());
}

/// A launcher whose prompters never answer: each conversation holds until
/// its 2-second timeout, long enough to act while it runs.
struct Holding {
    launched: std::sync::atomic::AtomicUsize,
    peers: std::sync::Mutex<Vec<std::os::unix::net::UnixStream>>,
}

impl Launcher for Holding {
    fn launch(&self) -> aleph_daemon::Result<aleph_daemon::prompt::Channel> {
        self.launched
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
        self.peers.lock().unwrap().push(theirs);
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(2))
    }
}

/// `served`, but with the holding launcher.
async fn served_holding() -> (Served, Arc<Holding>) {
    let env = env();
    let k = keyring(&env, MockKeys::default());
    create_with_password(&k);
    let bus = bus();
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.secrets")
        .unwrap()
        .build()
        .await
        .unwrap();
    let holding = Arc::new(Holding {
        launched: Default::default(),
        peers: Default::default(),
    });
    let svc = SecretService::new(Arc::new(k), holding.clone());
    svc.serve(&conn).await.unwrap();
    let s = Served {
        address: bus.address.clone(),
        _bus: bus,
        svc,
        launcher: Arc::new(InteractiveLauncher::new(vec![])),
        _conn: conn,
        _env: env,
    };
    (s, holding)
}

fn held(h: &Holding) -> usize {
    h.launched.load(std::sync::atomic::Ordering::SeqCst)
}

async fn create_collection_prompt(c: &zbus::Connection) -> zbus::Proxy<'static> {
    let props: std::collections::HashMap<&str, zbus::zvariant::Value<'_>> = [(
        "org.freedesktop.Secret.Collection.Label",
        zbus::zvariant::Value::from("Work"),
    )]
    .into();
    let (_, prompt): (OwnedObjectPath, OwnedObjectPath) = service(c)
        .await
        .call("CreateCollection", &(props, ""))
        .await
        .unwrap();
    zbus::Proxy::new(
        c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap()
}

/// Review I4: `Prompt()` runs once; a repeated call while it runs does not
/// start a second prompter.
#[tokio::test(flavor = "multi_thread")]
async fn a_prompt_runs_once() {
    let (s, holding) = served_holding().await;
    let c = client(&s).await;
    let p = create_collection_prompt(&c).await;
    p.call_method("Prompt", &("",)).await.unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(held(&holding), 1);
}

/// While one unlock conversation runs, other unlock prompts wait for it
/// instead of opening prompters of their own.
#[tokio::test(flavor = "multi_thread")]
async fn unlock_prompts_share_one_prompter() {
    let (s, holding) = served_holding().await;
    s.svc.lock().await.unwrap();
    let c = client(&s).await;
    for _ in 0..3 {
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service(&c)
            .await
            .call(
                "Unlock",
                &(vec![
                    ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
                ],),
            )
            .await
            .unwrap();
        let p = zbus::Proxy::new(
            &c,
            "org.freedesktop.secrets",
            prompt,
            "org.freedesktop.Secret.Prompt",
        )
        .await
        .unwrap();
        p.call_method("Prompt", &("",)).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(held(&holding), 1);
    assert_eq!(s.svc.waiting_count(), 2);
}

/// A prompter that times out (or crashes) is not the user's answer: the
/// unlock prompt that started it and those that joined it keep waiting
/// (as with no prompter, spec §4), and complete, undismissed, when the
/// vault is unlocked some other way. (Only Cancel dismisses.)
#[tokio::test(flavor = "multi_thread")]
async fn unlock_prompts_wait_when_the_prompter_times_out() {
    use futures_util::StreamExt;
    let (s, holding) = served_holding().await;
    s.svc.lock().await.unwrap();
    let c = client(&s).await;
    let mut prompts = Vec::new();
    for _ in 0..2 {
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service(&c)
            .await
            .call(
                "Unlock",
                &(vec![
                    ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
                ],),
            )
            .await
            .unwrap();
        let p = zbus::Proxy::new(
            &c,
            "org.freedesktop.secrets",
            prompt,
            "org.freedesktop.Secret.Prompt",
        )
        .await
        .unwrap();
        let completed = p.receive_signal("Completed").await.unwrap();
        p.call_method("Prompt", &("",)).await.unwrap();
        prompts.push((p, completed));
        // The first starts the conversation; the second joins it.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert_eq!(held(&holding), 1);
    // The held conversation times out after 2 s: both prompts wait on.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    for (_, completed) in &mut prompts {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), completed.next())
                .await
                .is_err(),
            "a prompt completed after the prompter timed out"
        );
    }
    assert_eq!(s.svc.waiting_count(), 2);
    // "alephctl unlock" in a terminal: both complete, undismissed.
    let keyring = s.svc.keyring.clone();
    tokio::task::spawn_blocking(move || {
        keyring.unlock(&mut Interactive::new(vec![password(PW)]).channel(), None)
    })
    .await
    .unwrap()
    .unwrap();
    s.svc.unlocked().await.unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    for (_, completed) in &mut prompts {
        let msg = tokio::time::timeout_at(deadline, completed.next())
            .await
            .expect("the prompt completes")
            .unwrap();
        let (dismissed, _): (bool, zbus::zvariant::OwnedValue) = msg.body().deserialize().unwrap();
        assert!(!dismissed);
    }
    assert_eq!(s.svc.waiting_count(), 0);
    assert_eq!(held(&holding), 1);
}

/// Final-review minor 11: while an admin conversation runs (here an
/// `alephctl unlock` whose user has not answered), a Secret Service unlock
/// does not open a prompter window onto the queue; it starts one once the
/// admin conversation is over.
#[tokio::test(flavor = "multi_thread")]
async fn no_prompter_opens_while_an_admin_conversation_runs() {
    let (s, holding) = served_holding().await;
    s.svc.lock().await.unwrap();
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut silent =
        aleph_daemon::prompt::Channel::new(ours, std::time::Duration::from_secs(2)).unwrap();
    let keyring = s.svc.keyring.clone();
    let admin = std::thread::spawn(move || keyring.unlock(&mut silent, None));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let c = client(&s).await;
    let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service(&c)
        .await
        .call(
            "Unlock",
            &(vec![
                ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
            ],),
        )
        .await
        .unwrap();
    let p = zbus::Proxy::new(
        &c,
        "org.freedesktop.secrets",
        prompt,
        "org.freedesktop.Secret.Prompt",
    )
    .await
    .unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(held(&holding), 0);
    // The admin conversation times out; then the prompter starts.
    assert!(admin.join().unwrap().is_err());
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(held(&holding), 1);
}

/// A prompt dismissed while its conversation runs completes once: the
/// conversation ending later sends nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn a_dismissed_prompt_completes_once() {
    use futures_util::StreamExt;
    let (s, _holding) = served_holding().await;
    let c = client(&s).await;
    let p = create_collection_prompt(&c).await;
    let mut completed = p.receive_signal("Completed").await.unwrap();
    p.call_method("Prompt", &("",)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    p.call_method("Dismiss", &()).await.unwrap();
    // The held conversation times out after 2 s and finishes too.
    let mut count = 0;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
    while let Ok(Some(_)) = tokio::time::timeout_at(deadline, completed.next()).await {
        count += 1;
    }
    assert_eq!(count, 1);
}

/// Prompts a client never starts are capped, and freed when it leaves.
#[tokio::test(flavor = "multi_thread")]
async fn unstarted_prompts_are_capped_and_freed_with_their_client() {
    let s = served(vec![]).await;
    s.svc.lock().await.unwrap();
    let c = client(&s).await;
    let svc = service(&c).await;
    let mut refused = 0;
    for _ in 0..20 {
        let r: zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> = svc
            .call(
                "Unlock",
                &(vec![
                    ObjectPath::try_from("/org/freedesktop/secrets/aliases/default").unwrap(),
                ],),
            )
            .await;
        if r.is_err() {
            refused += 1;
        }
    }
    assert_eq!((s.svc.prompt_count(), refused), (16, 4));
    drop(svc);
    drop(c);
    assert!(
        wait_until(|| s.svc.prompt_count() == 0).await,
        "{}",
        s.svc.prompt_count()
    );
}
