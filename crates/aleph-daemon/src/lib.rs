//! `alephd`, the aleph keyring daemon (spec §6).

pub mod config;
pub mod error;
pub mod keyring;
pub mod password;
pub mod paths;
pub mod prompt;
pub mod state;
pub mod store;

#[cfg(feature = "testing")]
pub mod testing;

pub use error::{Error, Result};
