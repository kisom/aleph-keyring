//! Recovery keys: 256 random bits shown to the user once as Crockford
//! base32, `XXXX-XXXX-…`, 14 groups of 4 (52 data chars + 4 checksum).

use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{Error, Result};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const KEY_BYTES: usize = 32;
const DATA_CHARS: usize = 52; // ceil(256 / 5); the final 4 bits are zero padding
const CHECK_CHARS: usize = 4; // 20 bits of SHA-256
const GROUP: usize = 4;

pub struct RecoveryKey(SecretBox<[u8; KEY_BYTES]>);

impl RecoveryKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(SecretBox::new(Box::new(crypto::random_array()?))))
    }

    /// The bytes fed to Argon2id.
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        self.0.expose_secret()
    }

    /// Display form, e.g. `7K3M-…`. Show once; never log.
    pub fn format(&self) -> Zeroizing<String> {
        let mut chars = Zeroizing::new(encode(self.as_bytes()));
        chars.extend_from_slice(&checksum(self.as_bytes()));
        let mut out = Zeroizing::new(String::with_capacity(chars.len() + chars.len() / GROUP));
        for (i, c) in chars.iter().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(*c as char);
        }
        out
    }

    /// Parse user input. Case-insensitive; ignores `-` and whitespace;
    /// reads `O` as `0` and `I`/`L` as `1`.
    pub fn parse(input: &str) -> Result<Self> {
        let mut vals = Zeroizing::new(Vec::with_capacity(DATA_CHARS + CHECK_CHARS));
        for c in input.chars() {
            if c == '-' || c.is_whitespace() {
                continue;
            }
            vals.push(decode_char(c).ok_or(Error::InvalidRecoveryKey(
                "contains a character that is not in the recovery alphabet",
            ))?);
        }
        if vals.len() != DATA_CHARS + CHECK_CHARS {
            return Err(Error::InvalidRecoveryKey(
                "wrong length (expected 56 characters)",
            ));
        }
        let bytes = decode(&vals[..DATA_CHARS])?;
        let expected: Vec<u8> = checksum(&bytes)
            .iter()
            .map(|&c| decode_char(c as char).expect("alphabet char"))
            .collect();
        if expected[..] != vals[DATA_CHARS..] {
            return Err(Error::InvalidRecoveryKey(
                "checksum mismatch (check for a typo)",
            ));
        }
        Ok(Self(SecretBox::new(Box::new(*bytes))))
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

fn encode(bytes: &[u8; KEY_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DATA_CHARS + CHECK_CHARS);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize]);
        }
    }
    // 256 = 51*5 + 1: one leftover bit, padded with four zero bits.
    out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize]);
    out
}

fn decode(vals: &[u8]) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let mut out = Zeroizing::new([0u8; KEY_BYTES]);
    let (mut acc, mut bits, mut i) = (0u32, 0u32, 0usize);
    for &v in vals {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if i < KEY_BYTES {
                out[i] = (acc >> bits) as u8;
                i += 1;
            }
        }
    }
    // The 4 padding bits must be zero, otherwise two inputs would decode
    // to the same key.
    if acc & ((1 << bits) - 1) != 0 {
        return Err(Error::InvalidRecoveryKey("non-canonical encoding"));
    }
    Ok(out)
}

fn checksum(bytes: &[u8; KEY_BYTES]) -> [u8; CHECK_CHARS] {
    let digest = Sha256::digest(bytes);
    let v =
        (u32::from(digest[0]) << 12) | (u32::from(digest[1]) << 4) | (u32::from(digest[2]) >> 4);
    let mut out = [0u8; CHECK_CHARS];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ALPHABET[((v >> (5 * (CHECK_CHARS - 1 - i))) & 31) as usize];
    }
    out
}

fn decode_char(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|p| p as u8)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_14_groups_of_4() {
        let s = RecoveryKey::generate().unwrap().format();
        let groups: Vec<&str> = s.split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups.iter().all(|g| g.len() == 4));
    }

    /// Cross-checked against an independent Python encoder of the same
    /// scheme (big-endian bits, 4 zero pad bits, SHA-256 top 20 bits).
    #[test]
    fn known_encoding_of_bytes_0_to_31() {
        let bytes: [u8; KEY_BYTES] = std::array::from_fn(|i| i as u8);
        let k = RecoveryKey(SecretBox::new(Box::new(bytes)));
        assert_eq!(
            k.format().as_str(),
            "000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG-CC6W"
        );
    }

    #[test]
    fn parse_round_trips_format() {
        let k = RecoveryKey::generate().unwrap();
        let back = RecoveryKey::parse(&k.format()).unwrap();
        assert_eq!(k.as_bytes(), back.as_bytes());
    }

    #[test]
    fn parse_is_forgiving_about_case_separators_and_lookalikes() {
        let k = RecoveryKey(SecretBox::new(Box::new([0u8; KEY_BYTES])));
        let canonical = k.format().to_string();
        assert!(canonical.starts_with("0000-"));
        let sloppy = canonical
            .replacen('0', "o", 1)
            .replacen('0', "O", 1)
            .to_lowercase()
            .replace('-', " ");
        assert_eq!(
            RecoveryKey::parse(&sloppy).unwrap().as_bytes(),
            &[0u8; KEY_BYTES]
        );
        // I and L read as 1.
        assert_eq!(decode_char('i'), Some(1));
        assert_eq!(decode_char('L'), Some(1));
    }

    #[test]
    fn parse_rejects_typos_wrong_length_and_bad_chars() {
        let s = RecoveryKey::generate().unwrap().format().to_string();
        // Change one data character to a different valid one.
        let mut chars: Vec<char> = s.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(
            RecoveryKey::parse(&typo),
            Err(Error::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            RecoveryKey::parse(&s[..s.len() - 1]),
            Err(Error::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            RecoveryKey::parse(&s.replacen(|c: char| c.is_ascii_alphanumeric(), "U", 1)),
            Err(Error::InvalidRecoveryKey(_))
        ));
        assert!(matches!(
            RecoveryKey::parse(""),
            Err(Error::InvalidRecoveryKey(_))
        ));
    }

    #[test]
    fn nonzero_padding_bits_are_rejected() {
        let k = RecoveryKey(SecretBox::new(Box::new([0u8; KEY_BYTES])));
        let mut chars: Vec<u8> = encode(k.as_bytes());
        chars[DATA_CHARS - 1] = b'1'; // sets a padding bit
        let vals: Vec<u8> = chars
            .iter()
            .map(|&c| decode_char(c as char).unwrap())
            .collect();
        assert!(decode(&vals).is_err());
    }
}
