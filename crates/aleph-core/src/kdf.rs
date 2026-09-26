//! Argon2id key derivation for the password-like keyslots.

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
    /// Recovery keys carry 256 bits of entropy; the KDF only needs to be
    /// non-trivial, not the main defence.
    pub const RECOVERY_KEY: Self = Self {
        m_kib: 256 * 1024,
        t: 3,
        p: 4,
    };
    /// Floor for user-chosen passphrases; `tune` may raise it.
    pub const PASSPHRASE_FLOOR: Self = Self {
        m_kib: 1024 * 1024,
        t: 3,
        p: 4,
    };
    /// Floor for the no-TPM login-password fallback; must not slow login.
    pub const LOGIN_PASSWORD_FLOOR: Self = Self {
        m_kib: 64 * 1024,
        t: 2,
        p: 4,
    };
    /// Only for tests: fast, and never valid in a real vault.
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

    fn argon2(&self) -> Result<argon2::Argon2<'static>> {
        if self.m_kib > Self::MAX.m_kib || self.t > Self::MAX.t || self.p > Self::MAX.p {
            return Err(Error::Kdf(format!("parameters exceed limits: {self:?}")));
        }
        let params = argon2::Params::new(self.m_kib, self.t, self.p, Some(KEY_LEN))
            .map_err(|e| Error::Kdf(e.to_string()))?;
        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

/// Derive a KEK from a password-like secret.
pub fn derive_kek(secret: &[u8], salt: &[u8; SALT_LEN], params: &Argon2Params) -> Result<Kek> {
    let mut out = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    params
        .argon2()?
        .hash_password_into(secret, salt, out.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(Kek::from_bytes(*out))
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

    /// Known answer for the production recovery-key parameters. If this
    /// changes, existing recovery slots can no longer be opened. Verified
    /// against the reference C implementation:
    /// `printf "aleph known answer" | argon2 BBBBBBBBBBBBBBBB -id -t 3 -m 18 -p 4 -l 32 -r`
    #[test]
    fn recovery_key_params_known_answer() {
        let kek = derive_kek(
            b"aleph known answer",
            &[0x42; SALT_LEN],
            &Argon2Params::RECOVERY_KEY,
        )
        .unwrap();
        assert_eq!(
            hex(kek.expose()),
            "c9fe4f6f54f7be70ac688b57e8f6aa5d496cf378fa86f60e38176f2f77bcce1f"
        );
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
