//! Vault format and cryptography for the aleph keyring.
//!
//! No D-Bus, no hardware access, no global state. See
//! `docs/superpowers/specs/2026-09-26-aleph-design.md` §4.

pub mod crypto;
pub mod error;

pub use error::{Error, Result};
