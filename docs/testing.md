# Testing aleph

## Automated (CI and local)

```sh
make gate    # cargo fmt --check, clippy -D warnings, cargo test
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
  and drive them with the real libsecret client and the real `alephctl`
  binary. They never touch your session bus or keyring.
- **A GPU driver** (or Mesa's software Vulkan, `vulkan-swrast`, headless)
  and **`lua`** (`luac`): the prompter's snapshot tests render with wgpu,
  and setup's Hyprland include is checked with `luac -p`. The snapshots
  are compared pixel by pixel; on another machine, regenerate them with
  `UPDATE_SNAPSHOTS=1 cargo test -p aleph-gui --test screens` and look at
  every image before committing.
- PAM is exercised for real through a private service directory
  (`pam_start_confdir`, Linux-PAM 1.4+): `pam_unix` rejecting a wrong
  password, the shipped `packaging/pam/aleph-check`, and the built
  `pam_aleph` module loaded by libpam (`pam_exec expose_authtok` supplies
  the password it hands over). Nothing is installed and no root is
  needed; the module's privilege drop is left to Plan 6's root container.
- The lock policy runs against a stand-in logind on the private bus
  (`aleph_daemon::testing::Logind`): sleep inhibitors, `PrepareForSleep`,
  and `Session.Lock`.
- Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret lua`.
  Nix: `swtpm tpm2-tools tpm2-tss libfido2 pam dbus libsecret lua`.

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

`make gate-hw` runs the two below, and only those: the real TPM (with
sudo for the test binary alone, unless you can open `/dev/tpmrm0`), then
the FIDO2 key (it asks for the PIN without echo unless `ALEPH_FIDO2_PIN`
is set; empty for built-in UV). `make hw-tpm` and `make hw-fido2` run
one each.

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
   `alephctl status`.)
4. Undo: `systemctl disable --now aleph-tpmd.socket aleph-tpmd.service`
   and remove the installed files.

### alephd with real clients

aleph takes over the session's Secret Service, so use a test account
(or a spare user) the first time; once it is set up on your own account,
these run there too. `make && make install` installs everything (the
binaries, `aleph-gui`, the PAM service `/etc/pam.d/aleph-check`, the
units, and the Hyprland window rule) and restarts alephd, which locks the
keyring. The client is `alephctl` (`aleph` on PATH is TeX's).

1. `alephctl setup`: choose the TPM (or a key), confirm the recovery key,
   and let it switch over from gnome-keyring (step 6 checks setup in
   detail). Already set up (a keyring exists)? Run `alephctl setup` again
   anyway after installing a new version: it changes nothing that is done,
   skips the root step once it is applied, and offers what is new (Plan
   5a: the prompt's Hyprland window rule; answer yes, and
   `~/.config/hypr/hyprland.lua` gets two lines, the `pcall(dofile, …)`
   include and a comment).
2. `secret-tool store --label=t service aleph-check` (type a secret), then
   `secret-tool lookup service aleph-check` prints it.
3. **The unlock prompt** (Plan 5a). Each check starts from `alephctl
   lock`, then `secret-tool lookup service aleph-check`:
   - The prompt opens floating in the middle of the screen, with the
     keyboard on its password field. The login password: the lookup prints
     the secret.
   - A wrong password: the error shows, the field is empty and still has
     the keyboard; then the right one.
   - Escape: the window closes and the lookup ends without a secret.
   - From a fullscreen window: the prompt still gets the keyboard.
   - With a security key enrolled: "USE KEY", then the PIN and
     touch screens.
   - Switch the Omarchy theme while the prompt is open: it re-themes.
   - Leave it unanswered past `prompt.timeout` (`alephctl config set
     prompt.timeout 30` to wait less; it asks you to confirm it is you; set
     it back to 300 after): the window stays.
   - With the window open, `alephctl unlock` in a terminal: the window
     closes, the terminal asks, and the lookup prints the secret.
   - With the window open, `passwd`: the window closes and `passwd`
     completes; the lookup keeps waiting until an unlock (`alephctl
     unlock`).
   - Without a graphical session, the lookup waits and `alephctl unlock` in
     another terminal ends it: log in on a text console with Hyprland not
     running (alephd reads the display from the user manager, so unsetting
     `WAYLAND_DISPLAY` in a terminal changes nothing).
   - After a reboot with SDDM autologin (alephd starts before Hyprland),
     the first lookup opens the prompt.
4. **Chromium:** start it with `--password-store=gnome-libsecret`, save a
   site password, quit, `alephctl lock`, start Chromium again, and
   unlock in the prompt. Saved passwords must still be there
   (Chromium did not create a new safe-storage key).
5. **NetworkManager:** with `nmcli` and a Wi-Fi network whose password is
   stored for the user ("Store the password only for this user"), lock,
   reconnect, and unlock when asked: the connection must come up without
   asking for the Wi-Fi password again.
6. **Setup and login unlock** (Plan 4c), on a test account with
   gnome-keyring running and a few items in it (Seahorse), after `make &&
   make install` (it asks for sudo, then reloads the user units, restarts
   alephd, and starts `alephd.socket`).
   - `alephctl setup`: it reports the TPM, creates the keyring, imports the
     items (`secret-tool lookup` finds them through aleph), switches over
     (`alephctl status` says alephd serves the Secret Service;
     `systemctl --user is-enabled gnome-keyring-daemon.socket` says
     masked), offers the prompt's Hyprland window rule (Lua configuration
     only: `~/.config/hypr/hyprland.lua` gets the include), and offers the
     root step: answer yes, and `sudo` runs `alephctl system apply`, which
     asks the login password once and checks the lock screen and the login
     with it.
   - Keep a root shell open until the lock screen has been tried: a TTY
     login is the way back in (`system-login`, `system-auth`, and `login`
     are never edited).
   - Log out and in (the vault is unlocked at login, no prompt); lock the
     screen, then unlock it (unlocked, no prompt); `passwd` (the TPM
     slot's id changes); suspend and resume (locked). With Omarchy's lock,
     the vault locks with the screen only once Omarchy runs
     `omarchy-hook lock` (DECISIONS.md G1, omacom/omarchy PR #13513; it
     covers suspend too); until then idle and sleep lock it.
   - `alephctl setup` again changes nothing.
   - If the root step was skipped: log out and in, and check that no
     `gnome-keyring-daemon` runs (`pgrep -a gnome-keyring`) and that
     `alephctl status` still says alephd serves the Secret Service (sddm's
     `pam_gnome_keyring auto_start` can start one).
   - `sudo alephctl system apply` runs the login password through the login
     and lock-screen stacks as root: after it, check the lock screen
     itself (it runs as you) before walking away.
   - `alephctl setup --revert`: it asks the login password, copies
     everything back, and gnome-keyring serves the Secret Service again
     (with the items stored in aleph meanwhile), and the include is gone
     from `hyprland.lua` (the rest of the file as it was); `sudo alephctl
     system revert` restores the PAM files byte for byte.
7. `alephctl status` shows the keyslots; `journalctl --user` (or the
   terminal) shows no secrets.
8. **Backup and restore** (Plan 4b):
   - `alephctl backup ~/aleph.bak` (re-authenticate): the file is mode
     `0600`, and running it again refuses to overwrite it.
   - On a second test account (or after moving `~/.local/share/aleph/`
     and `~/.local/state/aleph/` aside), `alephctl restore ~/aleph.bak`: type
     the recovery key, choose an unlock method, and decline or accept a
     new recovery key. `secret-tool lookup service aleph-check` prints the
     secret; `alephctl status` shows one unlock method and the recovery slot.
   - Back on the first account, copy an older `vault.aleph` over the
     current one (daemon stopped): the next unlock reports a rollback and
     `alephctl status` says writes are refused. `alephctl restore
     --accept-rollback` accepts it, after re-authentication and the login
     password, keeping the
     previous `.bak` as `vault.aleph.bak-<time>`.
   - Truncate `vault.aleph` (daemon stopped): `alephctl restore --from-bak`
     brings back the previous version, keeping the broken file as
     `vault.aleph.corrupt-<time>`.
   - Move `vault.aleph` away (daemon stopped) and `alephctl restore` another
     account's backup: it asks for the login password before the recovery
     key. Delete the kept `vault.aleph.*-<time>` files afterwards (they
     still open with the old recovery key).

Record the results, and the libsecret, Chromium, and NetworkManager
versions, in `hardware-log.md`.

### The manager (Plan 5b)

After `make && make install` (the launcher entry and the icons are
installed with it), on the account aleph serves:

1. Open "aleph" from the Omarchy launcher (Super + Space): the manager
   opens with the aleph icon, showing the folders and items (labels and
   attributes only; no secret is fetched).
2. Search: typing part of a label or an attribute value filters the list.
3. Pick an item and SHOW: the confirmation appears inside the window
   (login password, or a security key); after it, the secret shows. HIDE,
   then SHOW again within 5 minutes: no confirmation. `alephctl lock`:
   the window shows `VAULT SEALED` and hides the secret; UNLOCK opens the
   usual prompt, and a SHOW then asks for the confirmation again.
4. COPY: `COPIED`; paste it somewhere: it is the secret. Clipboard history
   (`cliphist list`, if installed) does not list it. Switch to another
   workspace (the manager hidden) and wait 30 s: the clipboard is empty.
   (Closing the manager also clears a copy it served.)
5. `+ ITEM` in a test folder (`+ FOLDER` first: alephd's prompt asks to
   confirm): a label, a secret, an attribute; SAVE: it appears, and
   `secret-tool lookup <key> <value>` prints the secret. EDIT its label
   and (LOAD SECRET) its secret; SAVE; `secret-tool` prints the new one.
   DELETE: it asks (No leaves it); Yes removes it. DELETE FOLDER on the
   test folder: alephd's prompt asks.
6. An application storing a secret meanwhile (`secret-tool store
   --label=live service live-check`): it appears without a refresh.
7. Switch the Omarchy theme: the manager re-themes.
8. Restart alephd (`systemctl --user restart alephd.service`; the
   keyring locks): the manager shows `VAULT SEALED`; unlock; SHOW and
   `+ ITEM` still work (the manager opens a new session with the new
   alephd). (Stopping alephd shows `LINK DOWN` only briefly: the manager's
   own calls start it again, through D-Bus activation.)
9. The LOCK and EXIT buttons sit at the bottom of the sidebar. Show a
   secret, then LOCK: no confirmation; the window shows `VAULT SEALED`,
   the secret is gone (`alephctl status` says `locked`), and LOCK is greyed
   while sealed (and with alephd stopped). EXIT closes the window and does
   not lock the vault. In SETTINGS, change a value without saving and press
   EXIT: the window stays and says `Unsaved settings will be lost: press
   EXIT again to quit`; a second press closes it. With nothing edited (or
   after CANCEL) one press closes.

### The manager's settings (Plan 5c)

After `make && make install`, on the account aleph serves. Write down
`alephctl config get lock.idle_timeout` and `prompt.timeout` first; put
them back at the end.

1. Open the manager, then SETTINGS: the four VAULT values match
   `alephctl config get lock.on_suspend`, `lock.on_screen_lock`,
   `lock.idle_timeout`, `prompt.timeout`.
2. Idle lock: 5 min and prompt timeout: 15 min, then SAVE: one
   confirmation (login password or key touch), then `SETTINGS SAVED`;
   `alephctl config get` shows 300 and 900. Nothing was restarted.
3. Idle lock 5 min: leave the keyring untouched for 5 minutes
   (`alephctl status` shows `locked` afterwards). Set it back to Off.
4. Change three settings at once: one confirmation only.
5. Custom… for the prompt timeout: `0`, `1441`, `abc` each show
   `whole minutes, 1 to 1440` at once and Save stays off; `20` saves as
   1200 s.
6. Turn Lock on suspend off: the hibernation warning shows; turn it on
   again before leaving.
7. Cancel the confirmation (Cancel, or Escape): nothing changes
   (`alephctl config get`), the edits stay on screen.
8. `alephctl lock`, then SETTINGS: the values show and DISPLAY works; beside
   the buttons `VAULT SEALED :: SAVE WILL UNLOCK FIRST`. Edit something and
   SAVE: alephd's unlock window opens; after it, the confirmation opens
   (a second proof) and then `SETTINGS SAVED`. Repeat, and dismiss the
   unlock: `nothing was saved`, the edits stay.
9. `alephctl config set lock.idle_timeout 60` while the form is open with
   another value edited: SAVE sends only the edited key (the idle lock stays 60).
10. DISPLAY: Theme Neon/Auto and Scanlines switch at once and
    `~/.config/aleph/gui.toml` follows; "Every time" asks at every SHOW
    (even right after a confirmation); a SAVE in VAULT starts the 5-minute
    reveal window (SHOW right after: no second confirmation).
11. Hand-edit gui.toml to `scanline = false`: DISPLAY shows the file's error
    and RESET TO DEFAULTS; nothing is written until it is reset or fixed.
12. Stop alephd (`systemctl --user stop alephd.service alephd.socket`, then
    start them): while it is down VAULT says LINK DOWN; it reads again
    when the link returns.

### The manager's admin page (Plan 5d)

After `make && make install`, on the account aleph serves, with the test
YubiKey plugged in. Keep the terminal open with `alephctl status` to
compare.

1. Open the manager, then ADMIN: the STATUS lines and the slot list match
   `alephctl status` and `alephctl keyslot list`.
2. `+ SECURITY KEY`: alephd's confirmation opens in the window (PIN, touch);
   afterwards `KEYSLOT ADDED` and the new slot in the list. Try a wrong PIN
   once: it says so and costs one retry.
3. REMOVE the key just added: the Yes/No step first (No leaves it); Yes, then
   the confirmation; `KEYSLOT REMOVED`, the slot gone.
4. `+ TPM` (only if a TPM slot is missing), then REMOVE it again.
5. ROTATE MASTER KEY: one confirmation, `MASTER KEY ROTATED`; the vault
   still unlocks (`alephctl lock`, then unlock).
6. NEW RECOVERY KEY: the Yes/No step, the confirmation, the new key shown
   once; write it down (the old one stops working), type two groups back;
   `NEW RECOVERY KEY ISSUED`.
7. BACK UP…: the portal's save dialog opens with `aleph-backup-<date>.aleph`;
   save into a new file: `BACKED UP :: <path>`; the file is mode 600 and not
   empty. Repeat with an existing file: "choose a new name", the file
   untouched. Cancel the dialog: nothing happens.
8. Stop the portal (`systemctl --user stop xdg-desktop-portal.service`,
   after noting whether it was running), then BACK UP…: the typed-path
   field appears, prefilled; a new path works. Start the portal again.
9. `alephctl lock`, then ADMIN: STATUS and the slots show; the banner
   `VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST`; press ROTATE MASTER
   KEY: alephd's unlock window opens, then the confirmation (two proofs).
   Dismiss the unlock on a second try: `nothing was changed`.
10. Stop alephd (`systemctl --user stop alephd.service alephd.socket`, then
    start them): while it is down the page says LINK DOWN; it reads again
    when the link returns.

### The Arch packages (Plan 6)

`make pkg-test` (docker) builds and tests all three packages in an
`archlinux:base-devel` container: metadata, the file list and modes against
`packaging/arch/files.expected`, the hook's `systemctl` calls (a stub), the
removal guard through real `pacman -R`, and the refusal to co-install the
variants. It takes about 20 minutes (a cold cargo build for each of the
`-git` and release packages, and one for the local one) and printed 111 ok
checks when last run. The same script runs in CI (`packages`), and `make
gate` and `make deny` are the other two jobs. **The first CI run on GitHub
has not happened yet:** it happens after the owner pushes, and the workflow
has been validated with `actionlint` only, so the owner should confirm that
nothing else is needed for that first push (the repository settings, the
runner image, the container pull). Until then the same commands run locally.

The test prints one note that is a recorded limitation, not a check:

    note - variant switch under the guard: blocked

Switching between `aleph-keyring` and `aleph-keyring-git` (pacman removes one
to install the other) is stopped by the removal guard on a machine that is
set up: pacman runs the `Remove` hook for a conflict replacement, and the
guard refuses while the PAM changes or the Secret Service activation are in
effect. The procedure is: revert (`alephctl setup --revert` as the user,
`sudo alephctl system revert`), switch, set up again.

`make pkg` versions are
`<Cargo version>.r<commit count>[.dirty<timestamp>].g<hash>`. Two dirty
builds of one commit sort by their timestamps; a dirty build sorts older
than the clean build of the same commit, so committing the work and
installing the clean package is an upgrade, with no "downgrading"
warning.

On the owner's machine (these need `sudo`; the owner runs them, none is
automated):

1. `make pkg-test` passes, and prints the variant-switch note above.
2. Move from the `install.sh` files: revert both (`sudo alephctl system
   revert`, `alephctl setup --revert`), then `sudo make uninstall`, then
   `make pkg`, then
   `sudo pacman -U target/pkg/local/aleph-keyring-local-*.pkg.tar.zst`.
   (Installing the package over the `install.sh` files without
   uninstalling first needs an `--overwrite` naming exactly those files —
   one long argument:
   `sudo pacman -U --overwrite '/usr/bin/alephctl,/usr/bin/aleph-gui,/usr/lib/aleph/*,/usr/lib/security/pam_aleph.so,/etc/pam.d/aleph-check,/usr/share/aleph/*,/usr/share/applications/aleph-gui.desktop,/usr/share/icons/hicolor/*/apps/aleph*.svg,/usr/lib/systemd/system/aleph-tpmd.*,/usr/lib/systemd/user/alephd.*,/usr/share/dbus-1/services/io.aleph.Keyring.service' target/pkg/local/aleph-keyring-local-*.pkg.tar.zst`.)
3. `systemctl --user daemon-reload; systemctl --user start alephd.socket;
   alephctl setup`; log out and in; lock and unlock; the manager opens.
4. `sudo pacman -R aleph-keyring-local`: refused, naming both commands;
   revert both (`alephctl setup --revert`, `sudo alephctl system revert`);
   `-R` is accepted; the vault in `~/.local/share/aleph` is still there.
   To go back to aleph afterwards, reinstall the package (`sudo pacman -U
   target/pkg/local/aleph-keyring-local-*.pkg.tar.zst`) and run
   `alephctl setup` again.
5. `pacman -Ql aleph-keyring-local` matches `packaging/arch/files.expected`;
   what `install.sh` installs is that list minus the removal guard, its
   hook and the licence files (`tests/install-layout-test.sh` checks it).

## Emergency manual revert

If login or the lock screen misbehaves after `sudo alephctl system apply`,
from a TTY (Ctrl-Alt-F3) or a root shell:

1. `sudo alephctl system revert`; or by hand, for each of `sddm`,
   `sddm-autologin`, `omarchy-lock-password`, and `passwd` in
   `/etc/pam.d/`: `mv <name>.aleph-orig <name>` where a backup exists;
   where none does, take out the `pam_aleph` lines by hand (and, in `sddm`
   and `sddm-autologin`, put back the `pam_gnome_keyring` lines). Then
   `rm /var/lib/aleph/manifest.json`.
2. As the user: `rm ~/.local/share/dbus-1/services/org.freedesktop.secrets.service
   ~/.local/share/dbus-1/services/org.gnome.keyring.service
   ~/.local/share/dbus-1/services/org.freedesktop.impl.portal.Secret.service`,
   `busctl --user call org.freedesktop.DBus /org/freedesktop/DBus
   org.freedesktop.DBus ReloadConfig` (dbus-broker does not notice
   removed activation files by itself), then `systemctl --user unmask
   gnome-keyring-daemon.service
   gnome-keyring-daemon.socket` and `systemctl --user start
   gnome-keyring-daemon.socket`.
3. Items stored in aleph since setup stay in its vault
   (`~/.local/share/aleph`). To copy them back, stop gnome-keyring again
   (`systemctl --user stop gnome-keyring-daemon.service
   gnome-keyring-daemon.socket`; revert refuses while it runs), then run
   `alephctl setup --revert` (`alephctl restore` if the vault itself needs
   recovery).
