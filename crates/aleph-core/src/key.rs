//! Key types. `KeyHandle` is the only holder of the vault master key and
//! is the seam for v2 privilege separation: callers ask it to wrap, seal,
//! open, and MAC, and never see the key bytes.

use secrecy::{ExposeSecret, SecretBox};

use crate::crypto::{self, KEY_LEN, MAC_LEN, NONCE_LEN};
use crate::error::{Error, Result};

/// A key-encryption key produced by an unlock method (TPM, FIDO2, Argon2).
pub struct Kek(SecretBox<[u8; KEY_LEN]>);

impl Kek {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    pub fn generate() -> Result<Self> {
        Ok(Self::from_bytes(crypto::random_array()?))
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kek([REDACTED])")
    }
}

/// The vault master key, wrapped by a KEK: what a keyslot stores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Holds the master key in page-locked memory.
pub struct KeyHandle {
    mk: SecretBox<[u8; KEY_LEN]>,
}

impl KeyHandle {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_bytes(crypto::random_array()?))
    }

    fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let mk = SecretBox::new(Box::new(bytes));
        // Best effort: keep the master key out of swap. Failure (e.g.
        // RLIMIT_MEMLOCK exhausted) is not fatal; the vault still works.
        unsafe {
            libc::mlock(mk.expose_secret().as_ptr().cast(), KEY_LEN);
        }
        Self { mk }
    }

    /// Wrap the master key for storage in a keyslot.
    pub fn wrap(&self, kek: &Kek, aad: &[u8]) -> Result<WrappedKey> {
        let (nonce, ciphertext) = crypto::seal(kek.expose(), aad, self.mk.expose_secret())?;
        Ok(WrappedKey { nonce, ciphertext })
    }

    /// Recover the master key from a keyslot.
    pub fn unwrap(kek: &Kek, wrapped: &WrappedKey, aad: &[u8]) -> Result<Self> {
        let pt = crypto::open(kek.expose(), &wrapped.nonce, aad, &wrapped.ciphertext)
            .ok_or(Error::UnwrapFailed)?;
        let bytes: [u8; KEY_LEN] = pt.as_slice().try_into().map_err(|_| Error::UnwrapFailed)?;
        Ok(Self::from_bytes(bytes))
    }

    pub fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
        crypto::seal(&self.derive(info), aad, plaintext)
    }

    pub fn open(
        &self,
        info: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        crypto::open(&self.derive(info), nonce, aad, ct)
    }

    pub fn mac(&self, info: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
        crypto::hmac_sha256(&self.derive(info), data)
    }

    pub fn verify_mac(&self, info: &[u8], data: &[u8], tag: &[u8; MAC_LEN]) -> bool {
        crypto::hmac_sha256_verify(&self.derive(info), data, tag)
    }

    fn derive(&self, info: &[u8]) -> zeroize::Zeroizing<[u8; KEY_LEN]> {
        crypto::hkdf(self.mk.expose_secret(), info)
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        // SecretBox zeroizes on drop; release the page lock first.
        unsafe {
            libc::munlock(self.mk.expose_secret().as_ptr().cast(), KEY_LEN);
        }
    }
}

impl std::fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyHandle([REDACTED])")
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip_preserves_key() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        let back = KeyHandle::unwrap(&kek, &wrapped, b"slot-aad").unwrap();
        // Same master key => same derived MAC.
        assert_eq!(mk.mac(b"x", b"data"), back.mac(b"x", b"data"));
    }

    #[test]
    fn unwrap_fails_with_wrong_kek_or_aad() {
        let mk = KeyHandle::generate().unwrap();
        let kek = Kek::generate().unwrap();
        let wrapped = mk.wrap(&kek, b"slot-aad").unwrap();
        assert!(matches!(
            KeyHandle::unwrap(&Kek::generate().unwrap(), &wrapped, b"slot-aad"),
            Err(Error::UnwrapFailed)
        ));
        assert!(matches!(
            KeyHandle::unwrap(&kek, &wrapped, b"other-aad"),
            Err(Error::UnwrapFailed)
        ));
    }

    #[test]
    fn debug_output_is_redacted() {
        assert_eq!(
            format!("{:?}", KeyHandle::generate().unwrap()),
            "KeyHandle([REDACTED])"
        );
        assert_eq!(format!("{:?}", Kek::generate().unwrap()), "Kek([REDACTED])");
    }
}
