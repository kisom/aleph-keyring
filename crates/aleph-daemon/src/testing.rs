//! Test support (feature `testing`), shared by this crate's and the CLI's
//! integration tests: a TPM helper on swtpm, a keyring on it, a private
//! session bus, and scripted prompters. Nothing here is used in production.
#![allow(dead_code, unused_imports)]

use std::os::unix::net::UnixListener;
pub use std::sync::Arc;

pub use crate::Error;
pub use crate::keyring::{Backends, Keyring, Tpm};
pub use crate::password::Fixed;
pub use crate::paths::Paths;
pub use crate::prompt::scripted::Scripted;
pub use crate::prompt::{FromPrompter, Launcher, Method, Secret, ToPrompter};
pub use aleph_tpmd::server::Policy;
pub use aleph_tpmd::testing::SwTpm;
pub use aleph_unlock::TpmClient;
pub use aleph_unlock::fido2::mock::{MockAuthenticator, MockKeys};

pub const PW: &str = "correct horse";
pub const PIN: &str = "123456";

pub struct Env {
    pub sw: SwTpm,
    _dir: tempfile::TempDir,
    pub paths: Paths,
    pub socket: std::path::PathBuf,
}

pub fn env() -> Env {
    let sw = SwTpm::start();
    sw.set_da_parameters(32, 600, 86400);
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("tpm.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let helper = Arc::new(sw.helper_with(Policy::allow_all()));
    std::thread::spawn(move || aleph_tpmd::server::serve(&listener, helper));
    let paths = Paths::under(dir.path());
    Env {
        sw,
        _dir: dir,
        paths,
        socket,
    }
}

pub fn keyring(env: &Env, keys: MockKeys) -> Keyring {
    keyring_with(
        env,
        Box::new(TpmClient::new(env.socket.clone())),
        keys,
        Box::new(Fixed(|p| p == PW)),
    )
}

/// A keyring with the given TPM and password check (test parameters).
pub fn keyring_with(
    env: &Env,
    tpm: Box<dyn Tpm>,
    keys: MockKeys,
    password: Box<dyn crate::password::PasswordCheck>,
) -> Keyring {
    let backends = Backends {
        tpm,
        keys: Box::new(keys),
        password,
    };
    // Tests reopen the vault right after dropping a keyring. A process
    // another test forks meanwhile (swtpm, unix_chkpwd) briefly holds a copy
    // of the daemon lock's descriptor until its exec closes it: retry.
    let mut store = crate::store::Store::open(&env.paths);
    for _ in 0..200 {
        if !matches!(store, Err(crate::Error::AlreadyRunning)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        store = crate::store::Store::open(&env.paths);
    }
    let mut k = Keyring::from_store(store.unwrap(), &env.paths, backends);
    k.argon2 = aleph_core::Argon2Params::INSECURE_TEST;
    k.key_wait = std::time::Duration::from_millis(600);
    k
}

/// A machine without a usable TPM.
pub struct NoTpm;

impl Tpm for NoTpm {
    fn seal(&self, _: &[u8]) -> aleph_unlock::Result<(aleph_core::Kek, aleph_core::TpmSlot)> {
        Err(aleph_unlock::Error::TpmUnavailable("no TPM".into()))
    }

    fn unseal(&self, _: &aleph_core::TpmSlot, _: &[u8]) -> aleph_unlock::Result<aleph_core::Kek> {
        Err(aleph_unlock::Error::TpmUnavailable("no TPM".into()))
    }

    fn usable(&self) -> bool {
        false
    }

    fn usable_now(&self) -> Option<bool> {
        Some(false)
    }
}

/// A TPM whose unseals succeed `ok` times, then fail with `then()`
/// (`Busy`, or `AuthFailed` as if the password had changed).
pub struct FlakyTpm {
    pub inner: TpmClient,
    pub ok: std::sync::atomic::AtomicUsize,
    pub then: fn() -> aleph_unlock::Error,
}

impl Tpm for FlakyTpm {
    fn seal(&self, pw: &[u8]) -> aleph_unlock::Result<(aleph_core::Kek, aleph_core::TpmSlot)> {
        self.inner.seal(pw)
    }

    fn unseal(
        &self,
        slot: &aleph_core::TpmSlot,
        pw: &[u8],
    ) -> aleph_unlock::Result<aleph_core::Kek> {
        use std::sync::atomic::Ordering;
        if self.ok.load(Ordering::SeqCst) == 0 {
            return Err((self.then)());
        }
        self.ok.fetch_sub(1, Ordering::SeqCst);
        self.inner.unseal(slot, pw)
    }

    fn usable(&self) -> bool {
        true
    }

    fn usable_now(&self) -> Option<bool> {
        Some(true)
    }
}

/// A password check accepting whatever the shared value currently is (the
/// login password can "change" mid-test).
#[derive(Clone)]
pub struct Accepting(pub Arc<std::sync::Mutex<String>>);

impl Accepting {
    pub fn new(pw: &str) -> Self {
        Self(Arc::new(std::sync::Mutex::new(pw.to_string())))
    }

    pub fn set(&self, pw: &str) {
        *self.0.lock().unwrap() = pw.to_string();
    }
}

impl crate::password::PasswordCheck for Accepting {
    fn check(&self, pw: &str) -> crate::Result<bool> {
        Ok(*self.0.lock().unwrap() == pw)
    }
}

/// A password check that cannot run (no PAM service file).
pub struct Unavailable;

impl crate::password::PasswordCheck for Unavailable {
    fn check(&self, _: &str) -> crate::Result<bool> {
        Err(crate::Error::PasswordCheckUnavailable)
    }
}

pub fn password(p: &str) -> FromPrompter {
    FromPrompter::Password {
        password: Secret::new(p),
    }
}

pub fn pin(p: &str) -> FromPrompter {
    FromPrompter::Pin {
        pin: Secret::new(p),
    }
}

/// Answers a `ShowRecoveryKey` by reading the key it was shown: the
/// scripted prompter cannot know the key in advance, so these tests use a
/// prompter thread that fills the check in.
fn recovery_answer(sent: &[ToPrompter]) -> Option<FromPrompter> {
    sent.iter().rev().find_map(|m| match m {
        ToPrompter::ShowRecoveryKey { key, check, .. } => {
            let groups: Vec<&str> = key.expose().split('-').collect();
            Some(FromPrompter::RecoveryCheck {
                groups: [
                    Secret::new(groups[check[0] - 1].to_lowercase()),
                    Secret::new(groups[check[1] - 1]),
                ],
            })
        }
        _ => None,
    })
}

/// A prompter that answers `Ask`/`Fido2Pin`/`Confirm` from `replies` and
/// confirms any recovery key it is shown.
pub struct Interactive {
    replies: std::sync::Mutex<Vec<FromPrompter>>,
    sent: Arc<std::sync::Mutex<Vec<ToPrompter>>>,
}

impl Interactive {
    pub fn new(replies: Vec<FromPrompter>) -> Self {
        Self {
            replies: std::sync::Mutex::new(replies),
            sent: Arc::default(),
        }
    }

    /// Everything sent, once the conversation has ended (`Done`).
    pub fn sent(&self) -> Vec<ToPrompter> {
        for _ in 0..200 {
            let sent = self.sent.lock().unwrap().clone();
            if matches!(sent.last(), Some(ToPrompter::Done { .. })) {
                return sent;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        self.sent.lock().unwrap().clone()
    }

    pub fn channel(&self) -> crate::prompt::Channel {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        self.respond(theirs);
        crate::prompt::Channel::new(ours, std::time::Duration::from_secs(10)).unwrap()
    }

    /// Answer the conversation arriving on `theirs` (the prompter's end).
    pub fn respond(&self, theirs: std::os::unix::net::UnixStream) {
        use std::io::{BufRead, BufReader, Write};
        let replies: Vec<FromPrompter> = std::mem::take(&mut *self.replies.lock().unwrap());
        let sent = self.sent.clone();
        std::thread::spawn(move || {
            let mut replies = replies.into_iter().peekable();
            let mut reader = BufReader::new(theirs.try_clone().unwrap());
            let mut writer = theirs;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let msg: ToPrompter = serde_json::from_str(&line).unwrap();
                line.clear();
                sent.lock().unwrap().push(msg.clone());
                let reply = match &msg {
                    ToPrompter::ShowRecoveryKey { .. } => {
                        recovery_answer(std::slice::from_ref(&msg))
                    }
                    // A scripted Cancel may answer "insert your key" (skip).
                    ToPrompter::InsertKey { .. }
                        if replies.peek() == Some(&FromPrompter::Cancel {}) =>
                    {
                        replies.next()
                    }
                    m if m.needs_reply() => Some(replies.next().unwrap_or(FromPrompter::Cancel {})),
                    ToPrompter::Done { .. } => break,
                    _ => None,
                };
                if let Some(r) = reply {
                    let mut out = serde_json::to_vec(&r).unwrap();
                    out.push(b'\n');
                    if writer.write_all(&out).is_err() {
                        break;
                    }
                }
            }
        });
    }
}

pub fn create_with_password(k: &Keyring) {
    let p = Interactive::new(vec![password(PW)]);
    k.create(&mut p.channel(), Method::Password).unwrap();
}

/// A launcher handing out `Interactive` channels, each answering from its
/// own reply list (tests push one list per expected prompt).
pub struct InteractiveLauncher {
    pub scripts: std::sync::Mutex<Vec<Vec<FromPrompter>>>,
    pub launched: std::sync::atomic::AtomicUsize,
}

impl InteractiveLauncher {
    pub fn new(scripts: Vec<Vec<FromPrompter>>) -> Self {
        Self {
            scripts: std::sync::Mutex::new(scripts),
            launched: Default::default(),
        }
    }
}

impl Launcher for InteractiveLauncher {
    fn launch(&self) -> crate::Result<crate::prompt::Channel> {
        self.launched
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut scripts = self.scripts.lock().unwrap();
        if scripts.is_empty() {
            return Err(crate::Error::NoPrompter);
        }
        Ok(Interactive::new(scripts.remove(0)).channel())
    }
}

/// A private session bus, killed on drop.
pub struct Bus {
    child: std::process::Child,
    pub address: String,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn bus() -> Bus {
    let mut child = std::process::Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--nopidfile", "--print-address=1"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("dbus-daemon (Arch: pacman -S dbus)");
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(child.stdout.take().unwrap()),
        &mut line,
    )
    .unwrap();
    Bus {
        child,
        address: line.trim().to_string(),
    }
}

/// A daemon (Secret Service and admin interface) on a private bus, with a
/// keyring on a swtpm TPM helper. `create` makes the vault (unlocked);
/// `prompts` answer Secret Service prompts, one list per prompt.
pub struct Daemon {
    pub secrets: Arc<crate::secret::service::SecretService>,
    pub keyring: Arc<Keyring>,
    pub bus: Bus,
    pub conn: zbus::Connection,
    pub env: Env,
}

pub async fn daemon(create: bool, prompts: Vec<Vec<FromPrompter>>) -> Daemon {
    daemon_with(create, prompts, Box::new(Fixed(|p| p == PW))).await
}

/// `daemon`, with the given password check (PAM).
pub async fn daemon_with(
    create: bool,
    prompts: Vec<Vec<FromPrompter>>,
    check: Box<dyn crate::password::PasswordCheck>,
) -> Daemon {
    let env = env();
    let keyring = Arc::new(keyring_with(
        &env,
        Box::new(TpmClient::new(env.socket.clone())),
        MockKeys::default(),
        check,
    ));
    if create {
        create_with_password(&keyring);
    }
    let bus = bus();
    let conn = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.secrets")
        .unwrap()
        .name(crate::admin::BUS_NAME)
        .unwrap()
        .build()
        .await
        .unwrap();
    let launcher = Arc::new(InteractiveLauncher::new(prompts));
    let secrets = crate::daemon::serve(
        &conn,
        keyring.clone(),
        launcher,
        Arc::new(std::sync::Mutex::new(crate::config::Config::default())),
        env.paths.clone(),
    )
    .await
    .unwrap();
    Daemon {
        secrets,
        keyring,
        bus,
        conn,
        env,
    }
}
