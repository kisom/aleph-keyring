//! FIDO2 keyslots via the `hmac-secret` extension (spec §5).
//!
//! - **Enrollment** needs exactly one key plugged in, one that lists
//!   `hmac-secret`. It creates a non-resident credential for the constant
//!   RP ID [`RP_ID`] with credential protection "UV optional with
//!   credential ID". By default ([`Verification::PinOrUv`]) it requires
//!   user verification: the key's PIN if it has one, else on-device UV. A
//!   key with neither is refused unless the user opts into
//!   [`Verification::TouchOnly`].
//! - **The KEK** is `HKDF(hmac-secret(salt), "aleph fido2 v1")`. The key
//!   returns a different secret with and without UV, so a slot enrolled
//!   with UV cannot be opened by a touch alone. That is why credProtect
//!   level 2 suffices: level 3 would also hide the credential from the
//!   no-touch preflight, and choosing among several keys would then burn
//!   PIN retries on the wrong ones.
//!   What level 2 gives away: anyone holding the key (no PIN) can learn
//!   that it holds a given credential ID, and can obtain the key's
//!   *non-UV* hmac-secret output for it, which opens nothing aleph
//!   enrolled with UV.
//! - **Unlock** preflights each connected key with a no-touch, no-PIN
//!   assertion to find the one holding the slot's credential, then asks
//!   only that key for a touch. This matters with one key too: a vault
//!   with a primary and a backup key has two slots, and asking the
//!   plugged key for the absent key's slot would spend a PIN retry on the
//!   wrong PIN. A key whose preflight fails (unplugged mid-scan, a
//!   firmware quirk) is treated as "not this key", unless it is the only
//!   key, which is then asked directly; if no key matches, the first such
//!   error is reported instead of "no credential".
//!
//! All hardware access goes through [`Keys`] and [`Authenticator`], so the
//! logic is tested against [`mock::MockKeys`].

pub mod libfido2;
pub mod mock;

use aleph_core::{Fido2Slot, Kek};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Every aleph FIDO2 credential uses this RP ID. It is not stored in the
/// slot, because the header it would be read from is unauthenticated
/// before unlock.
pub const RP_ID: &str = "aleph";
const KEK_INFO: &[u8] = b"aleph fido2 v1";

/// CTAP2.1 credProtect levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredProtect {
    /// Level 1: usable without UV, discoverable.
    UvOptional,
    /// Level 2: usable without UV only when the credential ID is given.
    UvOptionalWithId,
    /// Level 3: every use requires UV (so no no-touch preflight either).
    UvRequired,
}

/// The level aleph enrolls with (see the module docs for why 2).
pub const CRED_PROTECT: CredProtect = CredProtect::UvOptionalWithId;

/// What a key supports, from `authenticatorGetInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub hmac_secret: bool,
    /// A client PIN is set.
    pub pin_set: bool,
    /// Built-in user verification (fingerprint etc.) is configured.
    pub uv: bool,
}

/// One connected FIDO2 key.
pub trait Authenticator {
    fn info(&mut self) -> Result<DeviceInfo>;

    /// Create a non-resident credential with `hmac-secret` enabled and
    /// credProtect `protect`. Requires a touch.
    fn make_credential(
        &mut self,
        rp_id: &str,
        protect: CredProtect,
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Vec<u8>>;

    /// Whether this key holds `credential_id`: an assertion without user
    /// presence (no touch, no PIN).
    fn has_credential(&mut self, rp_id: &str, credential_id: &[u8]) -> Result<bool>;

    /// Evaluate `hmac-secret` for `credential_id` and `salt`. Requires a
    /// touch.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
        uv: bool,
    ) -> Result<Zeroizing<[u8; 32]>>;
}

/// The set of keys currently connected.
pub trait Keys {
    fn devices(&mut self) -> Result<Vec<&mut dyn Authenticator>>;

    /// True if any key is connected (drives the prompter's "insert your
    /// key" screen).
    fn any_present(&mut self) -> bool {
        self.devices().is_ok_and(|d| !d.is_empty())
    }
}

/// How an enrolled key must verify its user at unlock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verification {
    /// The key's PIN, or on-device UV. The default.
    #[default]
    PinOrUv,
    /// A touch alone. Anyone holding the key can unlock; opt-in only.
    TouchOnly,
}

/// Enroll the single connected key: create a credential, then evaluate it
/// once to derive the KEK (two touches, as with `systemd-cryptenroll`).
pub fn enroll(
    keys: &mut dyn Keys,
    pin: Option<&str>,
    policy: Verification,
) -> Result<(Kek, Fido2Slot)> {
    let mut devices = keys.devices()?;
    let device = match devices.len() {
        0 => return Err(Error::Fido2NoDevice),
        1 => &mut devices[0],
        _ => return Err(Error::Fido2MultipleDevices),
    };
    let info = device.info()?;
    if !info.hmac_secret {
        return Err(Error::Fido2Unsupported);
    }
    // A PIN, when the key has one, performs UV; otherwise use built-in UV.
    let (pin, uv) = match policy {
        Verification::PinOrUv if info.pin_set => (Some(pin.ok_or(Error::Fido2PinRequired)?), false),
        Verification::PinOrUv if info.uv => (None, true),
        Verification::PinOrUv => return Err(Error::Fido2PinNotSet),
        Verification::TouchOnly => (None, false),
    };
    let credential_id = device.make_credential(RP_ID, CRED_PROTECT, pin, uv)?;
    let salt = aleph_core::crypto::random_array::<32>()?;
    let secret = device.hmac_secret(RP_ID, &credential_id, &salt, pin, uv)?;
    let slot = Fido2Slot {
        credential_id,
        salt,
        uv_required: uv,
        pin_required: pin.is_some(),
    };
    Ok((derive_kek(&secret)?, slot))
}

/// Recover a FIDO2 slot's KEK from whichever connected key holds it.
pub fn unlock(keys: &mut dyn Keys, slot: &Fido2Slot, pin: Option<&str>) -> Result<Kek> {
    if slot.pin_required && pin.is_none() {
        return Err(Error::Fido2PinRequired);
    }
    // A PIN given for a slot enrolled without one would switch the key to
    // its UV secret and yield the wrong KEK: ignore it.
    let pin = if slot.pin_required { pin } else { None };
    let mut devices = keys.devices()?;
    let ask = |device: &mut &mut dyn Authenticator| {
        let secret = device.hmac_secret(
            RP_ID,
            &slot.credential_id,
            &slot.salt,
            pin,
            slot.uv_required,
        )?;
        derive_kek(&secret)
    };
    if devices.is_empty() {
        return Err(Error::Fido2NoDevice);
    }
    let lone = devices.len() == 1;
    let mut first_error = None;
    for device in devices.iter_mut() {
        match device.has_credential(RP_ID, &slot.credential_id) {
            Ok(true) => return ask(device),
            Ok(false) => {}
            // Nothing to choose between: a lone key that cannot answer
            // the preflight is asked directly.
            Err(_) if lone => return ask(device),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error.unwrap_or(Error::Fido2NoCredential))
}

fn derive_kek(secret: &[u8; 32]) -> Result<Kek> {
    Ok(Kek::try_init(|buf| {
        buf.copy_from_slice(aleph_core::crypto::hkdf(secret, KEK_INFO).as_slice());
        Ok(())
    })?)
}
