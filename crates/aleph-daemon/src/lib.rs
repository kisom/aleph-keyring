//! `alephd`, the aleph keyring daemon (spec §6).

pub mod config;
pub mod error;
pub mod password;
pub mod paths;
pub mod state;
pub mod store;

pub use error::{Error, Result};
