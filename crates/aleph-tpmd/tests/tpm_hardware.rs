//! Opt-in test against the machine's real TPM (not run in CI). Only the
//! success path is exercised: wrong-password attempts would count towards
//! the real TPM's dictionary-attack lockout. Needs access to the TPM
//! (root, or the `tss` group), as aleph-tpmd itself has.
//!
//! `cargo test -p aleph-tpmd --test tpm_hardware -- --ignored`
//! (uses `ALEPH_TCTI`, else `TPM2TOOLS_TCTI`, else `device:/dev/tpmrm0`).

#[test]
#[ignore]
fn real_tpm_status_seal_and_unseal() {
    let mut tpm = aleph_tpmd::Tpm::open_default().expect("open TPM (root or tss group?)");
    let status = tpm.status().unwrap();
    eprintln!("TPM status: {status:?}");
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let (object, kek) = tpm.seal(uid, b"aleph hw test").unwrap();
    assert_eq!(tpm.unseal(uid, &object, b"aleph hw test").unwrap(), kek);
}
