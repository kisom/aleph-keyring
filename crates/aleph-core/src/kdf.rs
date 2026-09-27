//! Argon2id key derivation for the login-password keyslot (the only
//! slot type whose KEK comes from a secret the user types).

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::crypto::KEY_LEN;
use crate::error::{Error, Result};
use crate::key::Kek;

pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters, stored in each keyslot so they can change
/// per slot and over time without a format change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Argon2Params {
    /// Floor for the no-TPM login-password fallback; `tune` raises `t` to
    /// about 0.3 s. Enrollment refuses anything weaker.
    pub const LOGIN_PASSWORD_FLOOR: Self = Self {
        m_kib: 64 * 1024,
        t: 2,
        p: 4,
    };
    /// Only for tests: fast, and never valid in a real vault. Exists only
    /// under `cfg(test)` or the `insecure-test-params` feature.
    #[cfg(any(test, feature = "insecure-test-params"))]
    pub const INSECURE_TEST: Self = Self {
        m_kib: 32,
        t: 1,
        p: 1,
    };

    /// Upper bounds accepted from a vault file. A corrupt or hostile slot
    /// must produce an error, not a multi-terabyte allocation.
    pub const MAX: Self = Self {
        m_kib: 4 * 1024 * 1024,
        t: 64,
        p: 16,
    };

    /// True if every cost is at least `floor`'s.
    pub fn meets(&self, floor: &Self) -> bool {
        self.m_kib >= floor.m_kib && self.t >= floor.t && self.p >= floor.p
    }

    /// Whether enrollment may use these parameters: at least the floor, or
    /// the test parameters when the `insecure-test-params` feature is on.
    pub fn enrollable(&self) -> bool {
        #[cfg(any(test, feature = "insecure-test-params"))]
        if *self == Self::INSECURE_TEST {
            return true;
        }
        self.meets(&Self::LOGIN_PASSWORD_FLOOR)
    }

    fn argon2(&self) -> Result<argon2::Argon2<'static>> {
        if self.m_kib > Self::MAX.m_kib || self.t > Self::MAX.t || self.p > Self::MAX.p {
            return Err(Error::Kdf(format!("parameters exceed limits: {self:?}")));
        }
        check_memory(self.m_kib, memory_limit_kib())?;
        let params = argon2::Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map_err(|e| Error::Kdf(e.to_string()))?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// Refuse a derivation that needs more memory than this process can ever
/// get. Under Linux overcommit the allocation itself succeeds and the OOM
/// killer ends the process mid-derivation, so this check is the only way a
/// corrupt slot's `m_kib` becomes an error instead of a dead daemon.
/// `None` (limit unknown) falls back to the fixed `Argon2Params::MAX` cap.
fn check_memory(m_kib: u32, limit_kib: Option<u64>) -> Result<()> {
    match limit_kib {
        Some(limit_kib) if u64::from(m_kib) > limit_kib => Err(Error::InsufficientMemory {
            needed_kib: m_kib.into(),
            limit_kib,
        }),
        _ => Ok(()),
    }
}

/// The most memory a derivation in this process can use: RAM plus swap,
/// lowered by any cgroup v2 limit on the way to the root.
///
/// Deliberately capacity, not `MemAvailable`: that is a momentary figure
/// (it excludes swap and drops when a browser is open) and would turn a
/// busy desktop into a failed unlock indistinguishable from a bad slot.
fn memory_limit_kib() -> Option<u64> {
    let system = parse_system_limit(&std::fs::read_to_string("/proc/meminfo").ok()?);
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|s| {
            let path = parse_cgroup_path(&s)?.to_owned();
            cgroup_limit_kib(Path::new("/sys/fs/cgroup"), &path)
        });
    match (system, cgroup) {
        (Some(s), Some(c)) => Some(s.min(c)),
        (s, c) => s.or(c),
    }
}

fn meminfo_kib(meminfo: &str, field: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix(field)?.strip_prefix(':'))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
}

fn parse_system_limit(meminfo: &str) -> Option<u64> {
    let ram = meminfo_kib(meminfo, "MemTotal")?;
    Some(ram + meminfo_kib(meminfo, "SwapTotal").unwrap_or(0))
}

/// The unified (v2) hierarchy's path from `/proc/self/cgroup`.
fn parse_cgroup_path(proc_cgroup: &str) -> Option<&str> {
    proc_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::trim)
}

/// One cgroup's limit from its `memory.max` and `memory.swap.max`. `None`
/// when either is `max` (or swap is unaccounted): the cgroup then imposes
/// nothing beyond the system-wide limit.
fn parse_cgroup_limit(memory_max: &str, swap_max: Option<&str>) -> Option<u64> {
    let bytes = |s: &str| s.trim().parse::<u64>().ok();
    Some((bytes(memory_max)? + bytes(swap_max?)?) / 1024)
}

/// The tightest limit among the cgroup at `path` and its ancestors.
fn cgroup_limit_kib(root: &Path, path: &str) -> Option<u64> {
    let mut dir = root.join(path.trim_start_matches('/'));
    let mut tightest: Option<u64> = None;
    while dir.starts_with(root) && dir != root {
        if let Ok(max) = std::fs::read_to_string(dir.join("memory.max")) {
            let swap = std::fs::read_to_string(dir.join("memory.swap.max")).ok();
            if let Some(limit) = parse_cgroup_limit(&max, swap.as_deref()) {
                tightest = Some(tightest.map_or(limit, |t| t.min(limit)));
            }
        }
        if !dir.pop() {
            break;
        }
    }
    tightest
}

/// Held for every derivation. `check_memory` vets one derivation against
/// the limit; running them one at a time keeps two concurrent unlocks from
/// jointly exceeding it. Derivations take ~1 s, so async callers must
/// already be on a blocking thread.
static DERIVE_LOCK: Mutex<()> = Mutex::new(());

/// Derive a KEK from a password-like secret.
pub fn derive_kek(secret: &[u8], salt: &[u8; SALT_LEN], params: &Argon2Params) -> Result<Kek> {
    let argon2 = params.argon2()?;
    // A panic mid-derivation leaves no state behind to protect.
    let _serialized = DERIVE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    Kek::try_init(|out| {
        argon2
            .hash_password_into(secret, salt, out)
            .map_err(|e| Error::Kdf(e.to_string()))
    })
}

/// Raise the pass count from `floor` until one derivation takes at least
/// `target` on this machine. Memory and lanes stay at the floor.
pub fn tune(floor: Argon2Params, target: Duration) -> Result<Argon2Params> {
    let salt = [0u8; SALT_LEN];
    let mut params = floor;
    loop {
        let start = Instant::now();
        derive_kek(b"aleph tune", &salt, &params)?;
        let elapsed = start.elapsed();
        if elapsed >= target || params.t >= 64 {
            return Ok(params);
        }
        // Scale passes proportionally, always making progress.
        let scale = target.as_secs_f64() / elapsed.as_secs_f64().max(1e-6);
        params.t = ((params.t as f64 * scale).ceil() as u32).clamp(params.t + 1, 64);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_and_salted() {
        let p = Argon2Params::INSECURE_TEST;
        let a = derive_kek(b"pw", &[1; SALT_LEN], &p).unwrap();
        let b = derive_kek(b"pw", &[1; SALT_LEN], &p).unwrap();
        let c = derive_kek(b"pw", &[2; SALT_LEN], &p).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), c.expose());
    }

    /// Known answer for the login-password floor. If this changes,
    /// existing login-password slots can no longer be opened. Verified
    /// against the reference C implementation:
    /// `printf "aleph known answer" | argon2 BBBBBBBBBBBBBBBB -id -t 2 -m 16 -p 4 -l 32 -r`
    #[test]
    fn login_password_floor_known_answer() {
        let kek = derive_kek(
            b"aleph known answer",
            &[0x42; SALT_LEN],
            &Argon2Params::LOGIN_PASSWORD_FLOOR,
        )
        .unwrap();
        assert_eq!(
            hex(kek.expose()),
            "70f16ec941691d57b88ca192c0b7d38373c5cee7adbe788a52e3f5d4b1860cbb"
        );
    }

    #[test]
    fn enrollment_requires_the_floor() {
        let floor = Argon2Params::LOGIN_PASSWORD_FLOOR;
        assert!(floor.enrollable());
        assert!(Argon2Params { t: 5, ..floor }.enrollable());
        assert!(
            !Argon2Params {
                m_kib: 1024,
                ..floor
            }
            .enrollable()
        );
        assert!(!Argon2Params { t: 1, ..floor }.enrollable());
        assert!(!Argon2Params { p: 1, ..floor }.enrollable());
        // Test parameters are enrollable only because cfg(test) is on here.
        assert!(Argon2Params::INSECURE_TEST.enrollable());
    }

    #[test]
    fn tune_never_goes_below_floor() {
        let floor = Argon2Params {
            m_kib: 64,
            t: 1,
            p: 1,
        };
        let tuned = tune(floor, Duration::from_millis(5)).unwrap();
        assert!(tuned.t >= floor.t);
        assert_eq!(tuned.m_kib, floor.m_kib);
        assert_eq!(tuned.p, floor.p);
    }

    #[test]
    fn invalid_params_are_an_error_not_a_panic() {
        let bad = Argon2Params {
            m_kib: 1,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            derive_kek(b"pw", &[0; SALT_LEN], &bad),
            Err(Error::Kdf(_))
        ));
    }

    #[test]
    fn params_needing_more_memory_than_the_limit_are_rejected() {
        // A corrupt slot asking for 1 GiB on a 512 MiB machine must be a
        // distinct error, not an OOM kill and not a generic KDF failure.
        assert!(matches!(
            check_memory(1024 * 1024, Some(512 * 1024)),
            Err(Error::InsufficientMemory {
                needed_kib: 1_048_576,
                limit_kib: 524_288
            })
        ));
        assert!(check_memory(1024 * 1024, Some(2 * 1024 * 1024)).is_ok());
        // Unknown limit (no /proc) falls back to the fixed caps.
        assert!(check_memory(1024 * 1024, None).is_ok());
    }

    /// The limit is capacity (RAM + swap), not the momentary MemAvailable:
    /// a busy desktop with little free RAM must still unlock.
    #[test]
    fn system_limit_is_total_ram_plus_swap_not_available() {
        let meminfo = "MemTotal:        8000000 kB\nMemFree:  100 kB\n\
                       MemAvailable:     900000 kB\nSwapTotal:       4000000 kB\n";
        assert_eq!(parse_system_limit(meminfo), Some(12_000_000));
        let no_swap = "MemTotal:        8000000 kB\nMemAvailable: 1 kB\n";
        assert_eq!(parse_system_limit(no_swap), Some(8_000_000));
        assert_eq!(parse_system_limit("SwapTotal: 1 kB\n"), None);
        assert!(check_memory(1024 * 1024, parse_system_limit(meminfo)).is_ok());
    }

    #[test]
    fn cgroup_v2_path_is_parsed() {
        assert_eq!(
            parse_cgroup_path("0::/user.slice/user@1000.service/app.slice/alephd.service\n"),
            Some("/user.slice/user@1000.service/app.slice/alephd.service")
        );
        // cgroup v1 hierarchies only: no unified path.
        assert_eq!(parse_cgroup_path("4:memory:/user.slice\n"), None);
    }

    #[test]
    fn cgroup_limit_is_memory_plus_swap_and_max_is_unlimited() {
        // MemoryMax=512M, MemorySwapMax=256M.
        assert_eq!(
            parse_cgroup_limit("536870912\n", Some("268435456\n")),
            Some(768 * 1024)
        );
        assert_eq!(
            parse_cgroup_limit("536870912\n", Some("0\n")),
            Some(512 * 1024)
        );
        assert_eq!(parse_cgroup_limit("max\n", Some("0\n")), None);
        // Unlimited or unaccounted swap: the system-wide limit covers it.
        assert_eq!(parse_cgroup_limit("536870912\n", Some("max\n")), None);
        assert_eq!(parse_cgroup_limit("536870912\n", None), None);
        assert_eq!(parse_cgroup_limit("garbage", Some("0")), None);
    }

    /// The tightest cgroup on the path to the root wins: a slice-level
    /// MemoryMax binds a service inside it.
    #[test]
    fn cgroup_limit_is_the_tightest_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let slice = root.path().join("user.slice");
        let service = slice.join("alephd.service");
        std::fs::create_dir_all(&service).unwrap();
        std::fs::write(slice.join("memory.max"), "536870912\n").unwrap();
        std::fs::write(slice.join("memory.swap.max"), "0\n").unwrap();
        std::fs::write(service.join("memory.max"), "max\n").unwrap();
        std::fs::write(service.join("memory.swap.max"), "0\n").unwrap();
        assert_eq!(
            cgroup_limit_kib(root.path(), "/user.slice/alephd.service"),
            Some(512 * 1024)
        );
        assert_eq!(cgroup_limit_kib(root.path(), "/"), None);
    }

    #[test]
    fn this_machine_has_a_memory_limit() {
        assert!(memory_limit_kib().is_some_and(|l| l > 0));
    }

    #[test]
    fn oversized_params_are_rejected_before_allocating() {
        let huge = Argon2Params {
            m_kib: u32::MAX,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            derive_kek(b"pw", &[0; SALT_LEN], &huge),
            Err(Error::Kdf(_))
        ));
        let slow = Argon2Params {
            m_kib: 64,
            t: u32::MAX,
            p: 1,
        };
        assert!(matches!(
            derive_kek(b"pw", &[0; SALT_LEN], &slow),
            Err(Error::Kdf(_))
        ));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
