//! `alephd`, the aleph keyring daemon (spec §6).

pub mod admin;
pub mod config;
pub mod daemon;
pub mod error;
pub mod import;
pub mod keyring;
pub mod lockpolicy;
pub mod pamsock;
pub mod password;
pub mod paths;
pub mod prompt;
pub mod secret;
pub mod state;
pub mod store;

#[cfg(feature = "testing")]
pub mod testing;

pub use error::{Error, Result};
