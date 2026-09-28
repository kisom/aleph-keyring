//! Children the test harness starts never inherit the test's descriptors:
//! a TPM connection one of them holds keeps that test's swtpm (one client
//! at a time) from ever accepting the next, and the test times out.

use std::os::fd::AsRawFd;

#[test]
fn a_test_bus_inherits_no_descriptors() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let conn = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    // Inheritable, as tss2 leaves its sockets.
    let fd = conn.as_raw_fd();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    let socket = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
    let bus = aleph_daemon::testing::bus();
    let held: Vec<_> = std::fs::read_dir(format!("/proc/{}/fd", bus.pid()))
        .unwrap()
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .collect();
    assert!(!held.contains(&socket), "dbus-daemon holds {socket:?}");
}
