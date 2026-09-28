//! The shipped systemd units, checked statically (the tests never start
//! them: that would touch the real user manager).

/// alephd checks login passwords with pam_unix, whose setuid `unix_chkpwd`
/// helper reads `/etc/shadow`: under no_new_privs it cannot ("user
/// unknown", PAM_AUTHINFO_UNAVAIL). In a user unit, systemd sets
/// no_new_privs for any seccomp-based option (systemd.exec(5)), not only
/// for `NoNewPrivileges=yes`, so alephd's unit must use none of them.
#[test]
fn alephd_can_run_setuid_helpers() {
    let unit = include_str!("../../../packaging/systemd/alephd.service");
    // (Each implies NoNewPrivileges=yes in a user unit.)
    const IMPLY_NNP: &[&str] = &[
        "NoNewPrivileges",
        "SystemCallFilter",
        "SystemCallArchitectures",
        "SystemCallLog",
        "RestrictAddressFamilies",
        "RestrictNamespaces",
        "RestrictRealtime",
        "RestrictSUIDSGID",
        "MemoryDenyWriteExecute",
        "LockPersonality",
        "PrivateDevices",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectKernelLogs",
        "ProtectClock",
        "ProtectHostname",
        "DynamicUser",
    ];
    let set: Vec<&str> = unit
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.trim()))
        .filter(|k| IMPLY_NNP.contains(k))
        .collect();
    assert!(set.is_empty(), "alephd.service sets {set:?}");
}
