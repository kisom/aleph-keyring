# Hardware test log

Results of the manual checks in [testing.md](testing.md), newest first.
Each release's notes summarize the entries since the previous release.

## 2026-09-28, commit 587414a (the manager's settings, Plan 5c, and LOCK/EXIT)

Host: as below. Installed with `make install` after 587414a.

### The manager's settings and the sidebar's LOCK and EXIT (testing.md)

| Step | Result |
|---|---|
| The manager's settings, 1–12 | Pass, as reported by the owner (the steps were not recorded one by one) |
| The manager, LOCK and EXIT (LOCK seals the vault and hides a shown secret, greyed while sealed; EXIT closes, and warns once about unsaved settings edits) | Pass, as reported by the owner |

## 2026-09-28, commit 35b9544 (the manager, Plan 5b)

Host: as below. Installed with `make install` after 35b9544.

### The manager (testing.md)

| Step | Result |
|---|---|
| 1–8 | Pass, as reported by the owner (the steps were not recorded one by one) |

Found while testing, with the manager beside another window (Hyprland's
side-by-side tiling):

| Finding | Result |
|---|---|
| The detail pane was too narrow to use at half a screen | Fixed in 9c00a16: the list and the detail split the width evenly |
| The divider showed the resize cursor but did not move | The detail's width floor (fixed in 4bd83a2), then the real cause: long labels held the list at its widest (fixed in 35b9544, rows cut to the list's width). Confirmed by the owner: the divider drags |

## 2026-09-28, commit f07550b (Plan 5b and follow-ups)

Host: as below. Installed with `make && make install` at about 15:30.
The manager's checks in testing.md were not run one by one; these are
the owner's findings while using it.

| Finding | Result |
|---|---|
| A long secret (JSON) ran off the detail pane | Fixed in 3f0cc5b: it scrolls both ways, and JSON is indented |
| Switching to another workspace brought up Hyprland's "Application Not Responding" for the manager | Fixed in 2826d04 (no vsync: DECISIONS.md). Confirmed by the owner after installing f07550b: no dialog on switching away |
| The prompt's title should look like the manager's "VAULT SEALED" | Done in f07550b (capitals, the warning color) |
| `/tmp` full of `dbus-*` sockets | Not aleph on the live system: the test suite's private buses (10,735 sockets, removed). Fixed in 079c22e |

## 2026-09-28, commits 46686ef and f1daf20 (Plan 5a)

Host: as below (Framework Laptop 12, Intel PTT), Omarchy 4.0.4, kernel
7.2.5-3-omarchy, Hyprland 0.56.2, Mesa 26.2.2, libsecret 0.21.7,
tpm2-tss 4.2.0, libfido2 1.17.0. The owner's own account, set up on
2026-09-27 (SDDM autologin at boot).

### alephd with real clients (testing.md)

Steps 1–3 on 46686ef (installed 09:21); steps 7–8 on f1daf20 (installed
10:14, with the prompter's new words and size, DECISIONS.md H6).

| Step | Result |
|---|---|
| 1. `alephctl setup` re-run after installing | Pass: nothing redone, the root step skipped, and the new Hyprland offer accepted (`~/.config/hypr/hyprland.lua` includes `/usr/share/aleph/hyprland/aleph-prompt.lua`) |
| 2. `secret-tool store` / `lookup` | Pass |
| 3. The unlock prompt | Pass, as reported by the owner (the checks were not recorded one by one). Owner's notes: too much empty space, a label not needed, and plainer words than wanted: fixed in f1daf20 (H6) |
| 4. Chromium | n/a: not used on this machine |
| 5. NetworkManager | n/a: the Wi-Fi password is system-wide |
| 6. Setup and login unlock | Done on 2026-09-27 (below); revert not run on the live account |
| 7. `alephctl status`, the journal | Pass. `journalctl --user -u alephd` since 2026-09-27 reviewed: no passwords, PINs, keys, or item contents; before 46686ef, only the expected "no prompter" lines (no `aleph-gui` yet); after it, none, and only lines from the owner's own testing. Two findings fixed in 5b62c39: alephd took its bus name before registering its interfaces (a zbus warning on every start), and unlocks through the prompt were not logged |
| 8. Backup | `alephctl backup ~/aleph.bak`: pass (mode `0600`; the message says it holds only the recovery slot). A second run refuses to overwrite, before asking for the password (`/home/kyle/aleph.bak: File exists (os error 17)`: correct, if terse). Restore, rollback, and `--from-bak` not run (they need a second account or the vault moved aside) |

Not confirmed individually (part of step 3, reported as a whole): the
prompt after a reboot with SDDM autologin; `passwd` with the window open;
the prompt unanswered past `prompt.timeout`. Not installed during these
checks: 5b62c39.

## 2026-09-27, commit 429f5e4 (Plan 4c)

Host: Framework Laptop 12 (13th Gen Intel Core), Intel PTT (firmware
TPM 2.0), Omarchy 4.0.4, kernel 7.2.5-3-omarchy, libsecret 0.21.7,
tpm2-tss 4.2.0, libfido2 1.17.0, NetworkManager 1.58.1.

### `make gate-hw`

| Test | Result |
|---|---|
| Real TPM (`tpm_hardware`, the test binary run with sudo) | Pass |
| FIDO2: YubiKey 5 (`fido2_hardware`, with the PIN) | Pass |

Only pass or fail was kept: no timings or `Status` values this time.

### Setup and login unlock (testing.md, alephd with real clients, step 6)

The first real run, on the owner's own account (not a test account),
with gnome-keyring serving 4 items.

| Step | Result |
|---|---|
| Install (`packaging/install.sh`) | Pass, after two fixes (below) |
| `alephctl setup`: TPM reported, keyring created, items imported, switched over | Pass: TPM slot plus the recovery slot; `secret-tool` finds the 4 items through alephd; gnome-keyring's socket and service masked |
| Root step (`sudo alephctl system apply`) | Pass: manifest written; login and lock-screen stacks checked |
| Lock the screen, then unlock it | Pass: `pam.sock: unlocked`, no prompt |
| Log out and in | Pass: `pam_aleph(sddm:auth): unlock: done`; unlocked, no prompt |
| `alephctl setup` again | Nothing imported or switched again; but it offered the root step again and re-ran `system apply` (sudo, the login password): fixed since, a re-run now skips a root step that is done |
| Suspend and resume | Pass: `locked before sleep`; unlocked again by the lock screen after resume |
| `passwd` (twice: a new password, then back) | Pass: `pam_aleph: password change: done`; the TPM slot re-sealed (its id changed each time) and the master key rotated, no prompt |
| NetworkManager | Not applicable: the Wi-Fi password is system-wide, not in the keyring |
| Chromium | Not applicable: not used on this machine |

SDDM autologins at boot here: `/etc/sddm.conf.d/autologin.conf.disabled`
is honored (SDDM reads every file in the directory; this boot's first
session was `sddm-autologin`). Setup's autologin notice was right. After
a reboot the keyring stays locked until the screen is locked and
unlocked, or `alephctl unlock`; with no graphical prompter yet (Plan 5),
a client asking before then gets `no prompter` (seen once, right after
resume).

Found on the way (DECISIONS.md G5):

- `aleph setup` ran TeX: texlive-bin owns `/usr/bin/aleph`. The CLI is
  now `alephctl`.
- alephd's password check failed with PAM_AUTHINFO_UNAVAIL: the unit's
  seccomp-based options implied `NoNewPrivileges` in the user manager,
  so `unix_chkpwd` could not read `/etc/shadow`. The options are gone.
  (A reinstalled unit takes effect only once alephd restarts; `make
  install` now does that.)

## 2026-09-26, commit 080466d (Plan 2)

Host: Omarchy (Arch), kernel 7.2.5-3-omarchy, libfido2 1.17, tpm2-tss 4.2.

### FIDO2: YubiKey 5 (firmware 5.7.4)

The key reports `FIDO_2_0`, `FIDO_2_1_PRE` and `FIDO_2_1`, supports
`hmac-secret` and `credProtect`, has a client PIN, and has no built-in UV.

| Step | Result |
|---|---|
| 1–2. Enroll with the PIN, then unlock (`fido2_hardware`) | Pass: six touches, 9.8 s |
| CTAP 2.1 check: the secret without UV differs from the secret with it | Pass: the key was accepted, and the test's with-PIN versus touch-only comparison differed |
| 3. A second key makes enrollment refuse | Not run: only one key was available |
| 4. A wrong PIN gives `Fido2PinInvalid` and costs one retry | Pass: retries went 8 → 7, and the next correct PIN restored 8 |

### Real TPM (`tpm_hardware`, run through `newgrp tss`)

| Step | Result |
|---|---|
| 1. Status, then one seal and one unseal | Pass, 0.62 s |

`Status` reported:

| Field | Value |
|---|---|
| `parent` | `AlephPrimary` |
| `owner_auth_set` | false |
| `lockout_auth_set` | false |
| `in_lockout` | false |
| `max_tries` | 32 |
| `recovery_time` | 7200 s |
| `lockout_recovery` | 86400 s |
| `failed_tries` | 0 |

What these values imply for later plans:

- The per-uid window is 2 × 7200 s, so two failed unseals lock that user
  out of TPM unlock for up to 4 hours. Plan 3/4 therefore checks a typed
  password with PAM before it reaches the TPM, so typos never count
  against the TPM's budget, and shows a retry-after time in the prompter.
- `lockoutAuth` is empty, the Linux default. `aleph setup` (Plan 4)
  explains the consequence (spec §2) and offers to set it.
