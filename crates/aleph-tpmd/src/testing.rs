//! Test support (feature `testing`): a private software TPM per test: `swtpm` on a pair of loopback TCP
//! ports with state in a temp directory, killed when the fixture drops.
//! Tests run in parallel with no shared state and never touch the host TPM.
//!
//! TCP, not Unix sockets: tss-esapi 7.7's `swtpm:` TCTI parser only
//! understands `host=`/`port=` and silently ignores `path=`.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use tss_esapi::Context;

static START_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Let the child inherit nothing above stderr. tss2 opens its TPM sockets
/// without close-on-exec: a long-lived swtpm that inherits another test's
/// connection keeps it open after its owner closes it, and that test's
/// swtpm (one client at a time) never accepts the next one.
pub fn no_inherited_fds(cmd: &mut Command) -> &mut Command {
    use std::os::unix::process::CommandExt;
    // SAFETY: close_range is async-signal-safe and touches no memory.
    // CLOSE_RANGE_CLOEXEC, not closing: std's exec-error pipe must stay
    // open until the exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
            Ok(())
        })
    }
}

pub struct SwTpm {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl SwTpm {
    pub fn start() -> Self {
        // Choosing ports, spawning swtpm, and waiting for it are serialized
        // across this process's tests. Otherwise a parallel test can bind a
        // port we just checked, our swtpm dies, and our readiness probe
        // connects to the *other* test's swtpm, which serves one client at
        // a time: the probe then blocks forever. (Cargo runs one test binary
        // at a time, so a process-wide lock suffices.)
        let _serial = START_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..20 {
            if let Some(sw) = Self::try_start() {
                return sw;
            }
        }
        panic!("could not start swtpm (is it installed? Arch: pacman -S swtpm)");
    }

    fn try_start() -> Option<Self> {
        let port = free_port_pair()?;
        let dir = tempfile::tempdir().unwrap();
        let child = no_inherited_fds(&mut Command::new("swtpm"))
            .arg("socket")
            .arg("--tpm2")
            .arg("--tpmstate")
            .arg(format!("dir={}", dir.path().display()))
            .arg("--server")
            .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1))
            .arg("--flags")
            .arg("not-need-init,startup-clear")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("swtpm not found: install it (Arch: pacman -S swtpm)");
        let mut sw = Self {
            child,
            port,
            _dir: dir,
        };
        // Ready means a real TPM connection succeeds.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // Probe only while our own swtpm is alive, so a dead one (port
            // clash) is never mistaken for another test's.
            if sw.child.try_wait().ok().flatten().is_some() || Instant::now() > deadline {
                return None; // swtpm died (port clash) or never came up; Drop reaps it
            }
            if crate::Tpm::open(&sw.tcti()).is_ok() {
                return Some(sw);
            }
            if Instant::now() > deadline {
                return None; // swtpm died (port clash) or never came up; Drop reaps it
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn tcti(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    pub fn tpm(&self) -> crate::Tpm {
        crate::Tpm::open(&self.tcti()).unwrap()
    }

    /// A helper serving every uid (tests run as whoever runs them).
    pub fn helper(&self) -> crate::Helper {
        self.helper_with(crate::server::Policy::allow_all())
    }

    pub fn helper_with(&self, policy: crate::server::Policy) -> crate::Helper {
        crate::Helper::new(self.tpm(), policy)
    }

    fn raw(&self) -> Context {
        let conf = tss_esapi::tcti_ldr::TctiNameConf::from_str(&self.tcti()).unwrap();
        Context::new(conf).unwrap()
    }

    /// Provision the TCG storage root key (ECC P-256, AES-128-CFB) at the
    /// persistent handle `0x81000001`, as `systemd-cryptenroll` does.
    pub fn provision_persistent_srk(&self) {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::handles::PersistentTpmHandle;
        use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
        use tss_esapi::interface_types::dynamic_handles::Persistent;
        use tss_esapi::interface_types::ecc::EccCurve;
        use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
        use tss_esapi::structures::{
            EccPoint, PublicBuilder, PublicEccParametersBuilder, SymmetricDefinitionObject,
        };
        let mut ctx = self.raw();
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .unwrap();
        let template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new_restricted_decryption_key(
                    SymmetricDefinitionObject::AES_128_CFB,
                    EccCurve::NistP256,
                )
                .build()
                .unwrap(),
            )
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .unwrap();
        let key = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
            })
            .unwrap()
            .key_handle;
        let persistent =
            Persistent::Persistent(PersistentTpmHandle::new(crate::tpm::SRK_HANDLE).unwrap());
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(Provision::Owner, key.into(), persistent)
        })
        .unwrap();
        ctx.flush_context(key.into()).unwrap();
    }

    /// Set the owner hierarchy's authorization, which makes creating
    /// aleph's own primary impossible.
    pub fn set_owner_auth(&self) {
        use tss_esapi::handles::AuthHandle;
        use tss_esapi::structures::Auth;
        let mut ctx = self.raw();
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.hierarchy_change_auth(
                AuthHandle::Owner,
                Auth::try_from(b"owner".to_vec()).unwrap(),
            )
        })
        .unwrap();
    }

    /// Clear the owner authorization set by [`Self::set_owner_auth`].
    pub fn clear_owner_auth(&self) {
        use tss_esapi::handles::{AuthHandle, ObjectHandle};
        use tss_esapi::structures::Auth;
        let mut ctx = self.raw();
        ctx.tr_set_auth(
            ObjectHandle::Owner,
            Auth::try_from(b"owner".to_vec()).unwrap(),
        )
        .unwrap();
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.hierarchy_change_auth(AuthHandle::Owner, Auth::default())
        })
        .unwrap();
    }
}

impl SwTpm {
    /// The swtpm process's id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Set the TPM's dictionary-attack parameters, as a real TPM might ship
    /// (swtpm defaults to 3 tries). tss-esapi 7.7 lacks
    /// TPM2_DictionaryAttackParameters, so this uses tpm2-tools.
    pub fn set_da_parameters(&self, max_tries: u32, recovery_time: u32, lockout_recovery: u32) {
        let status = no_inherited_fds(&mut Command::new("tpm2_dictionarylockout"))
            .env("TPM2TOOLS_TCTI", self.tcti())
            .arg("--setup-parameters")
            .arg(format!("--max-tries={max_tries}"))
            .arg(format!("--recovery-time={recovery_time}"))
            .arg(format!("--lockout-recovery-time={lockout_recovery}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("tpm2_dictionarylockout not found: install tpm2-tools");
        assert!(status.success(), "tpm2_dictionarylockout failed");
    }
}

impl Drop for SwTpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A port P such that P and P+1 were both free a moment ago (swtpm's TCTI
/// uses P for commands and P+1 for control).
fn free_port_pair() -> Option<u16> {
    for _ in 0..50 {
        let a = TcpListener::bind("127.0.0.1:0").ok()?;
        let port = a.local_addr().ok()?.port();
        if port < u16::MAX && TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
            return Some(port);
        }
    }
    None
}
