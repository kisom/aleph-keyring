//! The recovery slot's public-key recipient: X-Wing (X25519 + ML-KEM-768,
//! draft-connolly-cfrg-xwing-kem), via RustCrypto's `x-wing` crate.
//!
//! A recipient's key pair is derived from a 32-byte seed (for aleph, from
//! the recovery key), so the daemon can wrap MK to the public key without
//! ever holding the recovery key.

use hybrid_array::AsArrayRef;
use x_wing::{Decapsulate, DecapsulationKey, Decapsulator, EncapsulationKey, KeyExport, KeyInit};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, KEY_LEN};
use crate::error::{Error, Result};

pub const PUBLIC_KEY_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;
pub const CIPHERTEXT_LEN: usize = x_wing::CIPHERTEXT_SIZE;

/// An X-Wing decapsulation key, zeroized on drop.
pub struct Recipient(DecapsulationKey);

impl Recipient {
    /// The key pair determined by `seed`, per the X-Wing spec's KeyGen.
    pub fn from_seed(seed: &Zeroizing<[u8; KEY_LEN]>) -> Self {
        // Borrowed as an `Array` without copying; the key copies it into its
        // own zeroize-on-drop storage.
        Self(DecapsulationKey::new(seed.as_array_ref()))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.encapsulation_key().to_bytes().to_vec()
    }

    /// Recover the shared secret from an encapsulation. X-Wing decapsulation
    /// never fails outright; a wrong key yields an unrelated secret, which
    /// the keyslot AEAD then rejects.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let ct = x_wing::Ciphertext::try_from(ciphertext)
            .map_err(|_| Error::Malformed("X-Wing ciphertext has the wrong length".into()))?;
        let mut ss = self.0.decapsulate(&ct);
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        out.copy_from_slice(&ss);
        ss.zeroize();
        Ok(out)
    }
}

impl std::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Recipient([REDACTED])")
    }
}

/// Encapsulate a fresh shared secret to `public_key`. Returns
/// `(ciphertext, shared_secret)`.
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; KEY_LEN]>)> {
    let ek = EncapsulationKey::try_from(public_key)
        .map_err(|_| Error::Malformed("invalid X-Wing public key".into()))?;
    let mut randomness = Zeroizing::new([0u8; x_wing::ENCAPSULATION_RANDOMNESS_SIZE]);
    crypto::fill_random(randomness.as_mut())?;
    let (ct, mut ss) = ek.encapsulate_deterministic(randomness.as_array_ref());
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&ss);
    ss.zeroize();
    Ok((ct.to_vec(), out))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        seed: String,
        eseed: String,
        ss: String,
        pk: String,
        ct: String,
    }

    /// The draft authors' test vectors
    /// (github.com/dconnolly/draft-connolly-cfrg-xwing-kem, spec/test-vectors.json).
    fn vectors() -> Vec<Vector> {
        serde_json::from_str(include_str!("../tests/data/xwing-draft-vectors.json")).unwrap()
    }

    fn seed32(hex_str: &str) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(hex::decode(hex_str).unwrap().try_into().unwrap())
    }

    #[test]
    fn keygen_and_decapsulation_match_the_draft_vectors() {
        let vs = vectors();
        assert_eq!(vs.len(), 3);
        for v in vs {
            let r = Recipient::from_seed(&seed32(&v.seed));
            assert_eq!(hex::encode(r.public_key()), v.pk);
            let ss = r.decapsulate(&hex::decode(&v.ct).unwrap()).unwrap();
            assert_eq!(hex::encode(ss.as_slice()), v.ss);
        }
    }

    #[test]
    fn deterministic_encapsulation_matches_the_draft_vectors() {
        for v in vectors() {
            let ek = EncapsulationKey::try_from(hex::decode(&v.pk).unwrap().as_slice()).unwrap();
            let eseed: [u8; 64] = hex::decode(&v.eseed).unwrap().try_into().unwrap();
            let (ct, ss) = ek.encapsulate_deterministic(&eseed.into());
            assert_eq!(hex::encode(ct.as_slice()), v.ct);
            assert_eq!(hex::encode(ss.as_slice()), v.ss);
        }
    }

    #[test]
    fn encapsulate_round_trips_and_is_randomized() {
        let r = Recipient::from_seed(&Zeroizing::new([7u8; KEY_LEN]));
        let pk = r.public_key();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
        let (ct1, ss1) = encapsulate(&pk).unwrap();
        let (ct2, ss2) = encapsulate(&pk).unwrap();
        assert_eq!(ct1.len(), CIPHERTEXT_LEN);
        assert_ne!(ct1, ct2);
        assert_ne!(*ss1, *ss2);
        assert_eq!(*r.decapsulate(&ct1).unwrap(), *ss1);
    }

    #[test]
    fn wrong_recipient_gets_a_different_secret() {
        let (ct, ss) =
            encapsulate(&Recipient::from_seed(&Zeroizing::new([1u8; 32])).public_key()).unwrap();
        let other = Recipient::from_seed(&Zeroizing::new([2u8; 32]));
        assert_ne!(*other.decapsulate(&ct).unwrap(), *ss);
    }

    #[test]
    fn malformed_inputs_are_errors() {
        assert!(matches!(encapsulate(&[0u8; 10]), Err(Error::Malformed(_))));
        let r = Recipient::from_seed(&Zeroizing::new([1u8; 32]));
        assert!(matches!(
            r.decapsulate(&[0u8; 10]),
            Err(Error::Malformed(_))
        ));
    }
}
