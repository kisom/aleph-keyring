//! Hardware unlock methods for aleph: each turns a keyslot's stored
//! parameters (plus a password, PIN, or touch) into the slot's KEK.
//! See `docs/superpowers/specs/2026-09-26-aleph-design.md` §5.

pub mod error;
pub mod tpm;

pub use error::{Error, Result};
pub use tpm::TpmClient;
