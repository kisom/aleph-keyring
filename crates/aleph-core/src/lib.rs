//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;
pub mod kdf;
pub mod key;
pub mod keyslot;
pub mod model;
pub mod recovery;
pub mod vault;
pub mod xwing;

pub use error::{Error, Result};
pub use kdf::{Argon2Params, derive_kek};
pub use key::{Kek, KeyHandle, WrappedKey};
pub use keyslot::{Argon2Kind, Argon2Slot, Fido2Slot, Keyslot, SlotKind, TpmAuth, TpmSlot};
pub use model::{Body, Collection, Item, SecretBytes};
pub use recovery::RecoveryKey;
pub use vault::{LockedVault, UnlockedVault};
