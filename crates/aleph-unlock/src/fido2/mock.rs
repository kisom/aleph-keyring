//! Software FIDO2 keys for tests (here, in the daemon, and in the GUI).
//! They model what aleph depends on: `hmac-secret` support, PIN checks with
//! a retry counter, on-device UV, per-credential secrets scoped to an RP,
//! a no-touch existence check, and an `hmac-secret` output that differs
//! with user verification. Not a CTAP implementation; no security.

use std::collections::HashMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{Authenticator, CredProtect, DeviceInfo, Keys};
use crate::error::{Error, Result};

const PIN_RETRIES: u8 = 8;

pub struct MockAuthenticator {
    pub hmac_secret_supported: bool,
    pin: Option<String>,
    pub uv_capable: bool,
    pin_retries: u8,
    /// Credential ID → (RP ID, protection, per-credential secret).
    credentials: HashMap<Vec<u8>, (String, CredProtect, [u8; 32])>,
    /// Touches performed on this key.
    pub touches: usize,
    /// Make the no-touch preflight fail (a key unplugged mid-scan).
    pub fail_preflight: bool,
    /// Model a CTAP 2.0 key: one CredRandom, so `hmac-secret` returns the
    /// same output with and without user verification.
    pub single_cred_random: bool,
    /// Answer every preflight with "yes" (a buggy or hostile key).
    pub lie_preflight: bool,
}

impl MockAuthenticator {
    /// A key with no PIN and no built-in UV.
    pub fn new() -> Self {
        Self {
            hmac_secret_supported: true,
            pin: None,
            uv_capable: false,
            pin_retries: PIN_RETRIES,
            credentials: HashMap::new(),
            touches: 0,
            fail_preflight: false,
            single_cred_random: false,
            lie_preflight: false,
        }
    }

    pub fn with_pin(pin: &str) -> Self {
        Self {
            pin: Some(pin.to_string()),
            ..Self::new()
        }
    }

    /// A key with built-in UV (e.g. a fingerprint) and no PIN.
    pub fn with_uv() -> Self {
        Self {
            uv_capable: true,
            ..Self::new()
        }
    }

    /// PIN retries left (8 when fresh).
    pub fn pin_retries(&self) -> u8 {
        self.pin_retries
    }

    /// Check user verification as CTAP2 would, then take a touch.
    ///
    /// - A PIN, if given, must match (wrong PINs count down to a block).
    /// - `uv` without a PIN needs built-in UV.
    /// - Creating a credential on a key with a PIN set requires the PIN
    ///   (or built-in UV); an assertion may be touch-only.
    fn verify(&mut self, pin: Option<&str>, uv: bool, creating: bool) -> Result<()> {
        if self.pin_retries == 0 {
            return Err(Error::Fido2PinBlocked);
        }
        match (&self.pin, pin) {
            (None, Some(_)) => return Err(Error::Fido2PinNotSet),
            (Some(expected), Some(given)) if expected != given => {
                self.pin_retries -= 1;
                return Err(if self.pin_retries == 0 {
                    Error::Fido2PinBlocked
                } else {
                    Error::Fido2PinInvalid
                });
            }
            (Some(_), None) if creating && !(uv && self.uv_capable) => {
                return Err(Error::Fido2PinRequired);
            }
            _ => {}
        }
        if uv && pin.is_none() && !self.uv_capable {
            return Err(Error::Fido2Unsupported);
        }
        self.pin_retries = PIN_RETRIES;
        Ok(())
    }

    fn verify_and_touch(&mut self, pin: Option<&str>, uv: bool, creating: bool) -> Result<()> {
        self.verify(pin, uv, creating)?;
        self.touches += 1;
        Ok(())
    }
}

impl Default for MockAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator for MockAuthenticator {
    fn info(&mut self) -> Result<DeviceInfo> {
        Ok(DeviceInfo {
            hmac_secret: self.hmac_secret_supported,
            pin_set: self.pin.is_some(),
            uv: self.uv_capable,
        })
    }

    fn make_credential(
        &mut self,
        rp_id: &str,
        protect: CredProtect,
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Vec<u8>> {
        if !self.hmac_secret_supported {
            return Err(Error::Fido2Unsupported);
        }
        self.verify_and_touch(pin, uv, true)?;
        let id = aleph_core::crypto::random_array::<32>()?.to_vec();
        let secret = aleph_core::crypto::random_array::<32>()?;
        self.credentials
            .insert(id.clone(), (rp_id.to_string(), protect, secret));
        Ok(id)
    }

    fn has_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> Result<bool> {
        if self.fail_preflight {
            return Err(Error::Fido2("preflight failed".into()));
        }
        if self.lie_preflight {
            return Ok(true);
        }
        // A level-3 credential is invisible to an assertion without UV.
        Ok(self
            .credentials
            .get(credential_id)
            .is_some_and(|(rp, protect, _)| rp == rp_id && *protect != CredProtect::UvRequired))
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
        // As libfido2 does: the PIN is checked (for a PIN/UV token) before
        // the credential is looked up, so a wrong PIN costs a retry even
        // when this key does not hold the credential.
        self.verify(pin, uv, false)?;
        let (cred_rp, _, secret) = self
            .credentials
            .get(credential_id)
            .cloned()
            .ok_or(Error::Fido2NoCredential)?;
        if cred_rp != rp_id {
            return Err(Error::Fido2NoCredential);
        }
        self.touches += 1;
        // CTAP2: supplying a PIN performs user verification, and the
        // authenticator then uses a different secret (CredRandomWithUV).
        let verified = (uv || pin.is_some()) && !self.single_cred_random;
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("any key length");
        mac.update(&[u8::from(verified)]);
        mac.update(salt);
        Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
    }
}

/// A set of mock keys "plugged in".
#[derive(Default)]
pub struct MockKeys {
    pub devices: Vec<MockAuthenticator>,
    /// Keys that are plugged in but cannot be opened (held by another
    /// program): listed, never returned by `devices`.
    pub unopenable: usize,
}

impl MockKeys {
    pub fn one(device: MockAuthenticator) -> Self {
        Self {
            devices: vec![device],
            unopenable: 0,
        }
    }
}

impl Keys for MockKeys {
    fn devices(&mut self) -> Result<Vec<&mut dyn Authenticator>> {
        Ok(self
            .devices
            .iter_mut()
            .map(|d| d as &mut dyn Authenticator)
            .collect())
    }

    fn listed(&mut self) -> usize {
        self.devices.len() + self.unopenable
    }
}
