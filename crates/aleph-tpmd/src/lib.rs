//! `aleph-tpmd`: the only process that talks to the TPM for aleph
//! (spec §5, "TPM, via aleph-tpmd"). It runs as a socket-activated system
//! service with a throwaway user in the `tss` group, keeps no state on
//! disk, and binds every sealed object to the uid of the local user who
//! asked for it.

pub mod limiter;
pub mod server;
pub mod tpm;

#[cfg(feature = "testing")]
pub mod testing;

pub use server::Helper;
pub use tpm::{Tpm, TpmError};
