//! The harness's children never keep another test's TPM connection open.
//! tss2 opens its sockets without close-on-exec, and a swtpm that inherits
//! one holds it for its whole life: the other test's swtpm, which serves
//! one client at a time, then waits on a connection its owner already
//! closed, and that test times out.

use std::os::fd::AsRawFd;

#[test]
fn a_spawned_swtpm_inherits_no_descriptors() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let conn = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    // Inheritable, as tss2 leaves its sockets.
    let fd = conn.as_raw_fd();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    let socket = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
    let sw = aleph_tpmd::testing::SwTpm::start();
    let held: Vec<_> = std::fs::read_dir(format!("/proc/{}/fd", sw.pid()))
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .collect();
    assert!(!held.contains(&socket), "swtpm holds {socket:?}: {held:?}");
}
