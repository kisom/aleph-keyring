//! A TPM connection is never inherited by a child the process spawns.
//! tss2 opens its sockets without close-on-exec; a child holding a copy of
//! a connection keeps it open after `Tpm` drops it, and swtpm (one client
//! at a time) then never accepts the next connection.

use std::collections::BTreeSet;

fn inheritable_fds() -> BTreeSet<i32> {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|&fd| {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            flags >= 0 && flags & libc::FD_CLOEXEC == 0
        })
        .collect()
}

#[test]
fn a_tpm_connection_is_not_inherited() {
    let sw = aleph_tpmd::testing::SwTpm::start();
    let before = inheritable_fds();
    let mut tpm = sw.tpm();
    tpm.status().unwrap();
    let new: Vec<_> = inheritable_fds()
        .difference(&before)
        .map(|fd| std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap())
        .collect();
    assert!(new.is_empty(), "inheritable after Tpm::open: {new:?}");
}
