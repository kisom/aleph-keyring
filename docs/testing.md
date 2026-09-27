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
- **`tpm2-tss`**, **`libfido2`**, and **`pam`**: build-time libraries.
- **`dbus`** (`dbus-daemon`) and **`libsecret`** (`secret-tool`): the
  daemon and CLI tests run `alephd`'s interfaces on a private session bus
  and drive them with the real libsecret client and the real `aleph`
  binary. They never touch your session bus or keyring.
- PAM is exercised for real through a private service directory
  (`pam_start_confdir`, Linux-PAM 1.4+): `pam_unix` rejecting a wrong
  password, the shipped `packaging/pam/aleph-check`, and the built
  `pam_aleph` module loaded by libpam (`pam_exec expose_authtok` supplies
  the password it hands over). Nothing is installed and no root is
  needed; the module's privilege drop is left to Plan 6's root container.
- The lock policy runs against a stand-in logind on the private bus
  (`aleph_daemon::testing::Logind`): sleep inhibitors, `PrepareForSleep`,
  and `Session.Lock`.
- Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`.
  Nix: `swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret`.

FIDO2 logic is tested against `aleph_unlock::fido2::mock::MockKeys`; no
test in the default run needs a security key. Prompts are answered by
scripted prompters (`aleph_daemon::testing`), and the CLI reads its answers
from standard input under `ALEPH_NO_TTY=1`.

`alephd`'s user units are checked with
`systemd-analyze verify --user packaging/systemd/alephd.service packaging/systemd/alephd.socket`
(same `ExecStart` caveat as below).

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
hardware model, firmware) in [hardware-log.md](hardware-log.md); release
notes summarize it.

### FIDO2 security key

1. Plug in exactly one FIDO2 key that supports `hmac-secret` (YubiKey 5,
   SoloKey, Nitrokey 3, …) and has a PIN set (`fido2-token -S <device>`)
   or built-in UV.
2. Run `ALEPH_FIDO2_PIN=<pin, if set> cargo test -p aleph-unlock --test fido2_hardware -- --ignored`.
   Touch three times (enroll; the third checks that the key keeps
   separate secrets with and without PIN/UV), once (unlock), then twice
   more. Expect `1 passed`. A CTAP 2.0 key fails enrollment with
   `Fido2NoUvSeparation`, which is the intended refusal.
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

### alephd with real clients

Needs a vault on a test account (or a spare user), since it takes over
the Secret Service for the session. As root, install the PAM service
once: `install -Dm644 packaging/pam/aleph-check /etc/pam.d/aleph-check`.
Then, with gnome-keyring stopped (`systemctl --user stop
gnome-keyring-daemon.service gnome-keyring-daemon.socket`):

1. Run `target/debug/alephd` in one terminal and `target/debug/aleph setup`
   in another; choose the TPM (or a key) and confirm the recovery key.
2. `secret-tool store --label=t service aleph-check` (type a secret), then
   `secret-tool lookup service aleph-check` prints it.
3. `aleph lock`, then `secret-tool lookup service aleph-check`: it waits
   (no graphical prompter yet). In the other terminal, `aleph unlock`: the
   lookup then prints the secret.
4. **Chromium:** start it with `--password-store=gnome-libsecret`, save a
   site password, quit, `aleph lock`, start Chromium again, and
   `aleph unlock` when it waits. Saved passwords must still be there
   (Chromium did not create a new safe-storage key).
5. **NetworkManager:** with `nmcli` and a Wi-Fi network whose password is
   stored for the user ("Store the password only for this user"), lock,
   reconnect, and unlock when asked: the connection must come up without
   asking for the Wi-Fi password again.
6. **Login and screen unlock** (Plan 4a; setup's PAM edits come in 4c, so
   by hand for now, keeping backups):
   - `install -Dm755 target/debug/libpam_aleph.so /usr/lib/security/pam_aleph.so`
   - `/etc/pam.d/sddm`: `-auth optional pam_aleph.so` after `auth include
     system-login`, and `-session optional pam_aleph.so` after `session
     include system-login` (remove the `pam_gnome_keyring` lines)
   - `/etc/pam.d/omarchy-lock-password`: `-auth optional pam_aleph.so` at
     the end
   - `/etc/pam.d/passwd`: `-password optional pam_aleph.so` after `password
     include system-auth`
   - Never edit `system-login`, `system-auth`, or `login`: a TTY login is
     the way back in if something goes wrong (keep a root shell open while
     editing, and try the lock screen before walking away)
   - `systemctl --user enable --now alephd.socket` (with the units under
     `~/.config/systemd/user/`)

   Then: log out and in (the vault is unlocked at login, no prompt); lock
   the screen with a locker that calls `loginctl lock-session` (not
   Omarchy's own lock, which does not yet reach alephd; `aleph lock` stands
   in for it) and check `aleph status` says locked, then unlock the screen
   (unlocked, with no prompt); `passwd`
   (the TPM slot's id changes; with a FIDO2 slot, `aleph status` asks for
   `aleph keyslot rotate-master`); suspend and resume (locked).
7. `aleph status` shows the keyslots; `journalctl --user` (or the
   terminal) shows no secrets.
8. **Backup and restore** (Plan 4b):
   - `aleph backup ~/aleph.bak` (re-authenticate): the file is mode
     `0600`, and running it again refuses to overwrite it.
   - On a second test account (or after moving `~/.local/share/aleph/`
     and `~/.local/state/aleph/` aside), `aleph restore ~/aleph.bak`: type
     the recovery key, choose an unlock method, and decline or accept a
     new recovery key. `secret-tool lookup service aleph-check` prints the
     secret; `aleph status` shows one unlock method and the recovery slot.
   - Back on the first account, copy an older `vault.aleph` over the
     current one (daemon stopped): the next unlock reports a rollback and
     `aleph status` says writes are refused. `aleph restore
     --accept-rollback` accepts it, after re-authentication and the login
     password, keeping the
     previous `.bak` as `vault.aleph.bak-<time>`.
   - Truncate `vault.aleph` (daemon stopped): `aleph restore --from-bak`
     brings back the previous version, keeping the broken file as
     `vault.aleph.corrupt-<time>`.
   - Move `vault.aleph` away (daemon stopped) and `aleph restore` another
     account's backup: it asks for the login password before the recovery
     key. Delete the kept `vault.aleph.*-<time>` files afterwards (they
     still open with the old recovery key).

Record the results, and the libsecret, Chromium, and NetworkManager
versions, in `hardware-log.md`.
