//! Thin wrappers over the RustCrypto primitives aleph uses. Every other
//! module goes through these so algorithm choices live in one place.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const MAC_LEN: usize = 32;

/// Fill `buf` from the OS CSPRNG. Fill secrets in place with this rather
/// than `random_array`, which returns its bytes by value on the stack.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

/// A random array for non-secret values (nonces, salts).
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

/// Encrypt `plaintext` under `key` with a fresh random nonce.
pub fn seal(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = random_array::<NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Malformed("encryption failed".into()))?;
    Ok((nonce, ct))
}

/// Decrypt and authenticate. `None` on any failure; callers map it to the
/// error that fits their context (wrong key vs. tampered body).
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

/// HKDF-SHA-256 with no salt, expanded to one 32-byte key.
pub fn hkdf(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    okm
}

pub fn hmac_sha256(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time HMAC verification.
pub fn hmac_sha256_verify(key: &[u8; KEY_LEN], data: &[u8], tag: &[u8; MAC_LEN]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = [1u8; KEY_LEN];
        let (nonce, ct) = seal(&key, b"aad", b"secret").unwrap();
        assert_eq!(
            open(&key, &nonce, b"aad", &ct).unwrap().as_slice(),
            b"secret"
        );
    }

    #[test]
    fn open_rejects_wrong_key_wrong_aad_and_tampering() {
        let key = [1u8; KEY_LEN];
        let (nonce, mut ct) = seal(&key, b"aad", b"secret").unwrap();
        assert!(open(&[2u8; KEY_LEN], &nonce, b"aad", &ct).is_none());
        assert!(open(&key, &nonce, b"other", &ct).is_none());
        ct[0] ^= 1;
        assert!(open(&key, &nonce, b"aad", &ct).is_none());
    }

    #[test]
    fn seal_uses_fresh_nonces() {
        let key = [1u8; KEY_LEN];
        let (n1, _) = seal(&key, b"", b"x").unwrap();
        let (n2, _) = seal(&key, b"", b"x").unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn hkdf_separates_by_info() {
        let a = hkdf(&[9u8; 32], b"aleph header v1");
        let b = hkdf(&[9u8; 32], b"aleph body v1");
        assert_ne!(*a, *b);
        assert_eq!(*a, *hkdf(&[9u8; 32], b"aleph header v1"));
    }

    #[test]
    fn hmac_verify() {
        let key = [3u8; KEY_LEN];
        let tag = hmac_sha256(&key, b"data");
        assert!(hmac_sha256_verify(&key, b"data", &tag));
        assert!(!hmac_sha256_verify(&key, b"datb", &tag));
    }
}
