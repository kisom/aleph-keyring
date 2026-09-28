//! Secret Service transfer sessions (spec §6 "Secret Service").
//!
//! - `plain`: secrets travel as-is on the (per-user) session bus.
//! - `dh-ietf1024-sha256-aes128-cbc-pkcs7`, which libsecret requires:
//!   Diffie-Hellman in the 1024-bit MODP group of RFC 2409 §6.2, the
//!   shared secret (big-endian, zero-padded to 128 bytes) through
//!   HKDF-SHA-256 with no salt and no info to a 16-byte key, then
//!   AES-128-CBC with PKCS#7 padding and a random IV as the parameters.
//!   Weak by modern standards, acceptable on a per-user local bus, and
//!   documented as such. The modular exponentiation is not constant-time;
//!   each session's key is ephemeral.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const PLAIN: &str = "plain";
pub const DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// RFC 2409 §6.2, "Second Oakley Group".
const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);
const PRIME_LEN: usize = 128;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("unsupported session algorithm {0:?}")]
    Unsupported(String),
    #[error("invalid session input")]
    BadInput,
    #[error("cannot decrypt the secret (wrong session or corrupt data)")]
    Decrypt,
    #[error("system randomness unavailable")]
    Random,
}

pub enum Session {
    Plain,
    Dh { key: Zeroizing<[u8; 16]> },
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Plain => "Session::Plain",
            Self::Dh { .. } => "Session::Dh(<key>)",
        })
    }
}

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("valid prime")
}

fn random<const N: usize>() -> Result<[u8; N], SessionError> {
    aleph_core::crypto::random_array::<N>().map_err(|_| SessionError::Random)
}

/// A random DH exponent in [2, p-2].
fn exponent(p: &BigUint) -> Result<BigUint, SessionError> {
    Ok(
        BigUint::from_bytes_be(&*Zeroizing::new(random::<PRIME_LEN>()?)) % (p - BigUint::from(3u8))
            + BigUint::from(2u8),
    )
}

/// The session key from our exponent and the peer's public value (checked
/// to be in range), as both sides derive it.
fn derive(peer_bytes: &[u8], x: &BigUint, p: &BigUint) -> Result<Session, SessionError> {
    let peer = BigUint::from_bytes_be(peer_bytes);
    let one = BigUint::from(1u8);
    if peer_bytes.len() > PRIME_LEN || peer <= one || peer >= p - &one {
        return Err(SessionError::BadInput);
    }
    // The byte forms are zeroized; num-bigint cannot zeroize its own limbs
    // (the exponent and shared value), which is accepted for an ephemeral
    // per-session key.
    let shared = Zeroizing::new(peer.modpow(x, p).to_bytes_be());
    let mut ikm = Zeroizing::new([0u8; PRIME_LEN]);
    ikm[PRIME_LEN - shared.len()..].copy_from_slice(&shared);
    let mut key = Zeroizing::new([0u8; 16]);
    Hkdf::<Sha256>::new(None, &*ikm)
        .expand(&[], &mut *key)
        .expect("16 bytes is a valid HKDF length");
    Ok(Session::Dh { key })
}

/// The client half of a `dh-ietf1024-sha256-aes128-cbc-pkcs7` exchange,
/// for alephd reading another Secret Service (the gnome-keyring import).
pub struct ClientDh {
    x: BigUint,
    /// Our public value, the `OpenSession` input.
    pub public: Vec<u8>,
}

impl ClientDh {
    pub fn new() -> Result<Self, SessionError> {
        let p = prime();
        let x = exponent(&p)?;
        let public = BigUint::from(2u8).modpow(&x, &p).to_bytes_be();
        Ok(Self { x, public })
    }

    /// The session, from the server's `OpenSession` output.
    pub fn finish(self, server_public: &[u8]) -> Result<Session, SessionError> {
        derive(server_public, &self.x, &prime())
    }
}

impl Session {
    /// Negotiate a session: returns it and the output for the client (our
    /// DH public value, or nothing for `plain`).
    pub fn open(algorithm: &str, input: &[u8]) -> Result<(Self, Vec<u8>), SessionError> {
        match algorithm {
            PLAIN if input.is_empty() => Ok((Self::Plain, Vec::new())),
            PLAIN => Err(SessionError::BadInput),
            DH => {
                let p = prime();
                let x = exponent(&p)?;
                let public = BigUint::from(2u8).modpow(&x, &p);
                Ok((derive(input, &x, &p)?, public.to_bytes_be()))
            }
            other => Err(SessionError::Unsupported(other.into())),
        }
    }

    /// Encrypt a secret for the client: `(parameters, value)`.
    pub fn encrypt(&self, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SessionError> {
        match self {
            Self::Plain => Ok((Vec::new(), secret.to_vec())),
            Self::Dh { key } => {
                let iv = random::<16>()?;
                let ct = cbc::Encryptor::<aes::Aes128>::new(&(**key).into(), &iv.into())
                    .encrypt_padded_vec::<Pkcs7>(secret);
                Ok((iv.to_vec(), ct))
            }
        }
    }

    /// Decrypt a secret from the client.
    pub fn decrypt(
        &self,
        parameters: &[u8],
        value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        match self {
            Self::Plain => Ok(Zeroizing::new(value.to_vec())),
            Self::Dh { key } => {
                let iv: [u8; 16] = parameters.try_into().map_err(|_| SessionError::Decrypt)?;
                cbc::Decryptor::<aes::Aes128>::new(&(**key).into(), &iv.into())
                    .decrypt_padded_vec::<Pkcs7>(value)
                    .map(Zeroizing::new)
                    .map_err(|_| SessionError::Decrypt)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client doing its half of the exchange, as libsecret does.
    fn client_key(server_public: &[u8], x: &BigUint) -> [u8; 16] {
        let shared = BigUint::from_bytes_be(server_public)
            .modpow(x, &prime())
            .to_bytes_be();
        let mut ikm = [0u8; PRIME_LEN];
        ikm[PRIME_LEN - shared.len()..].copy_from_slice(&shared);
        let mut key = [0u8; 16];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[], &mut key)
            .unwrap();
        key
    }

    #[test]
    fn both_sides_derive_the_same_key_and_secrets_round_trip() {
        let x = BigUint::from_bytes_be(&[0x5a; 64]);
        let client_public = BigUint::from(2u8).modpow(&x, &prime()).to_bytes_be();
        let (session, server_public) = Session::open(DH, &client_public).unwrap();
        let key = client_key(&server_public, &x);
        let Session::Dh { key: server_key } = &session else {
            panic!()
        };
        assert_eq!(**server_key, key);
        let (iv, ct) = session.encrypt(b"s3cret").unwrap();
        assert_eq!(iv.len(), 16);
        assert_ne!(&ct[..], b"s3cret");
        assert_eq!(&**session.decrypt(&iv, &ct).unwrap(), b"s3cret");
        assert_eq!(session.decrypt(&iv[..8], &ct), Err(SessionError::Decrypt));
    }

    /// Our client half (the gnome-keyring import) and a server agree, and
    /// a bad server value is refused.
    #[test]
    fn the_client_half_agrees_with_a_server() {
        let client = ClientDh::new().unwrap();
        let (server, server_public) = Session::open(DH, &client.public).unwrap();
        let (iv, ct) = server.encrypt(b"from gnome-keyring").unwrap();
        let session = client.finish(&server_public).unwrap();
        assert_eq!(&**session.decrypt(&iv, &ct).unwrap(), b"from gnome-keyring");
        assert!(ClientDh::new().unwrap().finish(&[1]).is_err());
    }

    #[test]
    fn plain_passes_through_and_bad_inputs_are_refused() {
        let (plain, out) = Session::open(PLAIN, &[]).unwrap();
        assert!(out.is_empty());
        assert_eq!(plain.encrypt(b"x").unwrap(), (vec![], b"x".to_vec()));
        assert!(Session::open(PLAIN, b"junk").is_err());
        assert_eq!(Session::open(DH, &[1]).unwrap_err(), SessionError::BadInput);
        assert_eq!(
            Session::open(DH, &[0xff; 129]).unwrap_err(),
            SessionError::BadInput
        );
        let p_minus_1 = (prime() - BigUint::from(1u8)).to_bytes_be();
        assert_eq!(
            Session::open(DH, &p_minus_1).unwrap_err(),
            SessionError::BadInput
        );
        assert!(matches!(
            Session::open("rot13", &[]),
            Err(SessionError::Unsupported(_))
        ));
    }
}
