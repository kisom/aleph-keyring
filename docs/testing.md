# Testing aleph

## Automated (CI and local)

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Requirements:

- **`swtpm`**: the TPM tests start a private software TPM per test on
  loopback TCP ports (`aleph_tpmd::testing::SwTpm`). They never touch the
  host TPM.
- **`tpm2-tools`**: the fixture uses `tpm2_dictionarylockout` to give
  swtpm realistic dictionary-attack parameters (tss-esapi 7.7 lacks
  `TPM2_DictionaryAttackParameters`).
- **`tpm2-tss`** and **`libfido2`**: build-time libraries.
- Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2`.
  Nix: `swtpm tpm2-tools tpm2-tss libfido2`.

FIDO2 logic is tested against `aleph_unlock::fido2::mock::MockKeys`; no
test in the default run needs a security key.

The systemd units in `packaging/systemd/` are checked with:

```sh
systemd-analyze verify packaging/systemd/aleph-tpmd.socket packaging/systemd/aleph-tpmd.service
systemd-analyze security --offline=true packaging/systemd/aleph-tpmd.service
```

(`verify` needs the `ExecStart` binary to exist; point it at any
executable in a temporary copy of the unit.) Expect no output from
`verify`, and an exposure level of about 0.7 ("SAFE").

## Manual, before each release

These need real hardware and a person. Record the result (pass/fail,
hardware model, firmware) in the release notes.

### FIDO2 security key

1. Plug in exactly one FIDO2 key that supports `hmac-secret` (YubiKey 5,
   SoloKey, Nitrokey 3, …) and has a PIN set (`fido2-token -S <device>`)
   or built-in UV.
2. Run `ALEPH_FIDO2_PIN=<pin, if set> cargo test -p aleph-unlock --test fido2_hardware -- --ignored`.
   Touch twice (enroll), then once (unlock). Expect `1 passed`.
3. Plug in a second FIDO2 key as well and rerun step 2. Expect a failure
   reporting `Fido2MultipleDevices`, since enrollment needs exactly one key.
4. With a wrong `ALEPH_FIDO2_PIN`, expect `Fido2PinInvalid`, and the key's
   retry counter drops by one (`fido2-token -I <device>`).

### Real TPM

As root, or as a user in the `tss` group (the same access `aleph-tpmd`
has). It exercises only the success path, since wrong-password attempts
count towards the real TPM's lockout:

1. Run `cargo test -p aleph-tpmd --test tpm_hardware -- --ignored --nocapture`.
   Expect `1 passed`. It prints the TPM `Status` (parent, whether
   `lockoutAuth` is set, the DA parameters), seals and unseals once, and
   writes nothing persistent to the TPM.

### The helper under systemd

The unit checks above are static; this runs the helper as the service
does (DynamicUser, the seccomp filter, threads). As root:

1. `cargo build --release -p aleph-tpmd`, then
   `install -Dm755 target/release/aleph-tpmd /usr/lib/aleph/aleph-tpmd`
   and copy `packaging/systemd/aleph-tpmd.{socket,service}` to
   `/etc/systemd/system/`.
2. `systemctl daemon-reload && systemctl start aleph-tpmd.socket`.
3. As a login user, connect once to trigger activation, for example
   `python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/aleph/tpm.sock")'`.
   `systemctl status aleph-tpmd.service` must show it active, with no
   seccomp (`SIGSYS`) kills, and `journalctl -u aleph-tpmd` must be
   quiet. (A full seal and unseal through the service waits for Plan 3's
   `aleph status`.)
4. Undo: `systemctl disable --now aleph-tpmd.socket aleph-tpmd.service`
   and remove the installed files.
