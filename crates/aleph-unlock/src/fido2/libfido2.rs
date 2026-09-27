//! [`Keys`] and [`Authenticator`] backed by Yubico's libfido2 (the library
//! `systemd-cryptenroll` uses), through the `fido2-rs` bindings.
//!
//! Not exercised in CI (no virtual authenticator without root); covered
//! by the opt-in hardware test and `docs/testing.md`.

use fido2_rs::assertion::AssertRequest;
use fido2_rs::credentials::{CoseType, Credential, Extensions, Opt, Protection};
use fido2_rs::device::{Device, DeviceList};
use fido2_rs::error::Error as FidoRsError;
use zeroize::Zeroizing;

use super::{Authenticator, CredProtect, DeviceInfo, Keys};
use crate::error::{Error, Result};

/// One connected key, opened when enumerated.
pub struct Libfido2Authenticator {
    device: Device,
}

impl Authenticator for Libfido2Authenticator {
    fn info(&mut self) -> Result<DeviceInfo> {
        let info = self.device.info().map_err(map_err)?;
        Ok(DeviceInfo {
            hmac_secret: info.extensions().contains(&"hmac-secret"),
            pin_set: self.device.has_pin(),
            uv: self.device.has_uv(),
        })
    }

    fn make_credential(
        &mut self,
        rp_id: &str,
        protect: CredProtect,
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Vec<u8>> {
        let mut cred = Credential::new().map_err(map_err)?;
        cred.set_client_data_hash(aleph_core::crypto::random_array::<32>()?)
            .map_err(map_err)?;
        cred.set_rp(rp_id, "aleph keyring").map_err(map_err)?;
        cred.set_user(
            aleph_core::crypto::random_array::<32>()?,
            "aleph",
            None,
            None,
        )
        .map_err(map_err)?;
        cred.set_cose_type(CoseType::ES256).map_err(map_err)?;
        cred.set_extension(Extensions::HMAC_SECRET | Extensions::CRED_PROTECT)
            .map_err(map_err)?;
        cred.set_protection(match protect {
            CredProtect::UvOptional => Protection::UvOptional,
            CredProtect::UvOptionalWithId => Protection::UvOptionalWithId,
            CredProtect::UvRequired => Protection::UvRequired,
        })
        .map_err(map_err)?;
        cred.set_rk(Opt::False).map_err(map_err)?;
        if uv {
            cred.set_uv(Opt::True).map_err(map_err)?;
        }
        self.device
            .make_credential(&mut cred, pin)
            .map_err(map_err)?;
        Ok(cred.id().to_vec())
    }

    fn has_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> Result<bool> {
        let mut req = AssertRequest::new().map_err(map_err)?;
        req.set_rp(rp_id).map_err(map_err)?;
        req.set_client_data_hash(aleph_core::crypto::random_array::<32>()?)
            .map_err(map_err)?;
        req.set_allow_credential(credential_id).map_err(map_err)?;
        req.set_up(Opt::False).map_err(map_err)?;
        match self.device.get_assertion(req, None) {
            // A key may omit the credential ID when the allow list has one
            // entry; if it names one, it must be ours.
            Ok(assertions) => Ok(assertions
                .iter()
                .all(|a| a.id().is_empty() || a.id() == credential_id)),
            Err(e) => match map_err(e) {
                Error::Fido2NoCredential => Ok(false),
                other => Err(other),
            },
        }
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let mut req = AssertRequest::new().map_err(map_err)?;
        req.set_rp(rp_id).map_err(map_err)?;
        req.set_client_data_hash(aleph_core::crypto::random_array::<32>()?)
            .map_err(map_err)?;
        req.set_allow_credential(credential_id).map_err(map_err)?;
        req.set_extensions(Extensions::HMAC_SECRET)
            .map_err(map_err)?;
        req.set_hmac_salt(salt).map_err(map_err)?;
        req.set_up(Opt::True).map_err(map_err)?;
        if uv {
            req.set_uv(Opt::True).map_err(map_err)?;
        }
        let assertions = self.device.get_assertion(req, pin).map_err(map_err)?;
        let assertion = assertions.iter().next().ok_or(Error::Fido2NoCredential)?;
        let secret: [u8; 32] = assertion
            .hmac_secret()
            .try_into()
            .map_err(|_| Error::Fido2Unsupported)?;
        Ok(Zeroizing::new(secret))
    }
}

/// The FIDO2 keys connected right now, re-enumerated on every call.
#[derive(Default)]
pub struct Libfido2Keys {
    open: Vec<Libfido2Authenticator>,
}

impl Libfido2Keys {
    pub fn new() -> Self {
        Self::default()
    }
}

// SAFETY: libfido2 device handles are not tied to the thread that opened
// them; users of `Libfido2Keys` (the daemon keeps it behind a mutex) never
// touch one from two threads at once, which `&mut self` already enforces.
unsafe impl Send for Libfido2Keys {}

impl Keys for Libfido2Keys {
    fn devices(&mut self) -> Result<Vec<&mut dyn Authenticator>> {
        self.open.clear();
        for info in DeviceList::list_devices(16).map_err(map_err)? {
            // A key that fails to open (unplugged mid-scan, not FIDO2) is
            // skipped rather than failing the whole scan.
            if let Ok(device) = info.open()
                && device.is_fido2()
            {
                self.open.push(Libfido2Authenticator { device });
            }
        }
        Ok(self
            .open
            .iter_mut()
            .map(|d| d as &mut dyn Authenticator)
            .collect())
    }

    fn listed(&mut self) -> usize {
        DeviceList::list_devices(16).map_or(0, |list| list.count())
    }
}

// libfido2 error codes (fido/err.h).
const FIDO_ERR_UNSUPPORTED_EXTENSION: i32 = 0x16;
const FIDO_ERR_OPERATION_DENIED: i32 = 0x27;
const FIDO_ERR_INVALID_CREDENTIAL: i32 = 0x22;
const FIDO_ERR_UNSUPPORTED_OPTION: i32 = 0x2b;
const FIDO_ERR_NO_CREDENTIALS: i32 = 0x2e;
const FIDO_ERR_USER_ACTION_TIMEOUT: i32 = 0x2f;
const FIDO_ERR_PIN_INVALID: i32 = 0x31;
const FIDO_ERR_PIN_BLOCKED: i32 = 0x32;
const FIDO_ERR_PIN_AUTH_INVALID: i32 = 0x33;
const FIDO_ERR_PIN_AUTH_BLOCKED: i32 = 0x34;
const FIDO_ERR_PIN_NOT_SET: i32 = 0x35;
const FIDO_ERR_PIN_REQUIRED: i32 = 0x36;
const FIDO_ERR_UV_INVALID: i32 = 0x3f;
const FIDO_ERR_ACTION_TIMEOUT: i32 = 0x3a;
const FIDO_ERR_UV_BLOCKED: i32 = 0x3c;
const FIDO_ERR_NOTFOUND: i32 = -10;

fn map_err(e: FidoRsError) -> Error {
    match e {
        FidoRsError::Fido(f) => map_code(f.code),
        FidoRsError::Unsupported => Error::Fido2Unsupported,
        other => Error::Fido2(other.to_string()),
    }
}

fn map_code(code: i32) -> Error {
    match code {
        FIDO_ERR_PIN_INVALID | FIDO_ERR_PIN_AUTH_INVALID => Error::Fido2PinInvalid,
        FIDO_ERR_UV_INVALID => Error::Fido2UvInvalid,
        FIDO_ERR_OPERATION_DENIED => Error::Fido2Denied,
        FIDO_ERR_PIN_BLOCKED | FIDO_ERR_PIN_AUTH_BLOCKED | FIDO_ERR_UV_BLOCKED => {
            Error::Fido2PinBlocked
        }
        FIDO_ERR_PIN_NOT_SET => Error::Fido2PinNotSet,
        FIDO_ERR_PIN_REQUIRED => Error::Fido2PinRequired,
        FIDO_ERR_NO_CREDENTIALS | FIDO_ERR_INVALID_CREDENTIAL => Error::Fido2NoCredential,
        FIDO_ERR_USER_ACTION_TIMEOUT | FIDO_ERR_ACTION_TIMEOUT => Error::Fido2Timeout,
        FIDO_ERR_UNSUPPORTED_EXTENSION | FIDO_ERR_UNSUPPORTED_OPTION => Error::Fido2Unsupported,
        FIDO_ERR_NOTFOUND => Error::Fido2NoDevice,
        other => Error::Fido2(format!("libfido2 error {other:#x}")),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libfido2_error_codes_map_to_user_meaningful_errors() {
        assert!(matches!(map_code(0x31), Error::Fido2PinInvalid));
        assert!(matches!(map_code(0x33), Error::Fido2PinInvalid));
        assert!(matches!(map_code(0x3f), Error::Fido2UvInvalid));
        assert!(matches!(map_code(0x27), Error::Fido2Denied));
        assert!(matches!(map_code(0x32), Error::Fido2PinBlocked));
        assert!(matches!(map_code(0x34), Error::Fido2PinBlocked));
        assert!(matches!(map_code(0x35), Error::Fido2PinNotSet));
        assert!(matches!(map_code(0x36), Error::Fido2PinRequired));
        assert!(matches!(map_code(0x2e), Error::Fido2NoCredential));
        assert!(matches!(map_code(0x2f), Error::Fido2Timeout));
        assert!(matches!(map_code(0x16), Error::Fido2Unsupported));
        assert!(matches!(map_code(-10), Error::Fido2NoDevice));
        assert!(matches!(map_code(0x7f), Error::Fido2(_)));
    }
}
