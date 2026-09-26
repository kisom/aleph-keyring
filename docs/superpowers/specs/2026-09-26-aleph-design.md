# aleph — design spec

- **Date:** 2026-09-26
- **Status:** Draft, awaiting review
- **License:** Apache-2.0

> *Aleph*: in Gibson's *Mona Lisa Overdrive*, a biochip holding an entire
> world, sealed away. The crate is published as `aleph-keyring` (the `aleph`
> name on crates.io is held by a placeholder); binaries and the project are
> `aleph`.

## 1. Purpose

`aleph` is a drop-in replacement for the Secret Service half of
gnome-keyring, written in Rust, targeting Omarchy (Arch Linux) first and
NixOS second. Its distinguishing feature is hardware-bound unlocking: the
vault's master key is released by the TPM or a FIDO2 security key, with the
login password (via PAM) as a fallback, and a recovery secret as the
escape hatch.

### Success criteria for v1

1. Every existing libsecret client (browsers, VS Code, `git-credential-libsecret`,
   NetworkManager, `secret-tool`) works unmodified against `alephd`.
2. On Omarchy, after `aleph setup` and one re-login, the vault unlocks at
   login with no extra interaction (TPM + login password mode).
3. Users can alternatively choose FIDO2-touch or TPM-PIN unlock on first use.
4. Existing gnome-keyring secrets are migrated during setup.
5. A vault can be restored on a new machine from a backup file plus the
   recovery secret alone.
6. `aleph setup --revert` restores gnome-keyring exactly.

### Non-goals for v1

- SSH agent or GPG agent functionality (see §10).
- Per-application access control between processes running as the same user.
- Parsing gnome-keyring's on-disk `login.keyring` format.
- Multi-user or system-wide secrets.

## 2. Threat model

**v1 defends against:** a lost or stolen laptop, powered off or suspended.

- Omarchy mandates LUKS full-disk encryption, so a powered-off laptop
  already protects the vault file. `aleph` adds defense in depth for the
  cases FDE does not cover: the vault file leaving the encrypted disk
  (backups, sync), and a laptop stolen while suspended (disk unlocked, keys
  in RAM), handled by locking on suspend.
- TPM keyslots are bound to this machine's TPM and, by default, the login
  password as TPM authorization. Offline guessing is impossible, and online
  guessing is rate-limited by the TPM's dictionary-attack lockout.

**v1 explicitly does not defend against:**

- Malicious processes running as the same user while the vault is unlocked
  (same as gnome-keyring). The Secret Service protocol cannot reliably
  identify callers.
- An attacker with root or kernel access on the running machine.
- Physical bus interposers recording TPM or USB traffic for later quantum
  cryptanalysis. TPM sessions and FIDO2 PIN/UV protocols use classical ECC
  for session establishment. Documented, not mitigated.

**Post-quantum posture:** all at-rest protection is symmetric: 256-bit
AEAD, HKDF-SHA-256, Argon2id, TPM sealed objects under an AES-256 parent,
FIDO2 `hmac-secret`. These keep ~128-bit security under Grover. ML-KEM is
not needed for v1. It would be introduced only if a "share/export a vault
to another person's public key" feature is added.

## 3. Architecture

A single user daemon with thin clients, organized so that key custody can
later be split into a separate process (§10, privilege separation).

```
 libsecret apps ──D-Bus──┐
                         │  org.freedesktop.secrets
 aleph (CLI) ───D-Bus────┤  io.aleph.Admin1
 aleph-gui (manager) ────┤
                         ▼
                      alephd ──spawns──▶ aleph-gui prompt   (socketpair, JSON lines)
                         ▲
 pam_aleph.so ──unix socket ($XDG_RUNTIME_DIR/aleph/pam.sock)
                         │
                 aleph-core + aleph-unlock
                         │
              vault.aleph   /dev/tpmrm0   FIDO2 (hidraw)
```

### Workspace crates

| Crate | Kind | Responsibility | Depends on |
|---|---|---|---|
| `aleph-core` | lib | Vault format, AEAD, HKDF, keyslot wrap/unwrap, collections/items model. No D-Bus, no hardware, no global state. | `chacha20poly1305`, `hkdf`, `sha2`, `ciborium`, `secrecy`, `zeroize`, `uuid` |
| `aleph-unlock` | lib | Produces a KEK per keyslot type: TPM, FIDO2, Argon2id (recovery key, passphrase, login password). Defines the `Authenticator` trait for FIDO2. | `aleph-core`, `tss-esapi`, libfido2 bindings, `argon2` |
| `alephd` | bin | Secret Service + admin D-Bus interfaces, PAM socket, lock policy, prompter orchestration. | `aleph-core`, `aleph-unlock`, `zbus`, `tokio`, `tracing`, `tracing-journald` |
| `pam_aleph` | cdylib | PAM module: forwards passwords to `alephd`. Minimal, no async runtime. | `pam` bindings (or hand-written FFI), std |
| `aleph` | bin | CLI. | `zbus`, `clap`, `aleph-core` (for `restore` only) |
| `aleph-gui` | bin | egui manager + prompter. | `eframe`, `egui`, `zbus`, `notify`, Wayland clipboard crate |

**Seam for privilege separation:** `aleph-core` exposes vault operations
in terms of an opaque `KeyHandle` that can encrypt, decrypt, and derive
subkeys. Nothing else touches raw key bytes. v1 implements `KeyHandle`
in-process. v2 can implement it as an IPC client to a separate key process
without changing `alephd`'s D-Bus layer.

## 4. Vault format and cryptography

### File

- Path: `$XDG_DATA_HOME/aleph/vault.aleph` (default `~/.local/share/aleph/`).
  Directory mode `0700`, file mode `0600`.
- Encoding: CBOR.
- Writes are atomic: write `vault.aleph.tmp`, `fsync`, rename over
  `vault.aleph`, `fsync` the directory. The previous version is kept as
  `vault.aleph.bak`. Writers hold an exclusive `flock` on
  `vault.aleph.lock` for the whole sequence, so concurrent writers
  serialize instead of renaming each other's half-written temp files.

### Header (plaintext, authenticated after unlock)

**Layout:** `MAGIC ‖ CBOR([format_version, header_bytes, header_mac, body_nonce, body_ct])`.

- `MAGIC` is `"ALEPH\0"`, and `format_version` is an integer starting at 1.
- `header_bytes` is `CBOR(Header { vault_id, keyslots })`, stored as a
  byte string. `vault_id` is a UUIDv4.
- `header_mac = HMAC-SHA-256(HKDF(MK, "aleph header v1"), MAGIC ‖ be32(format_version) ‖ header_bytes)`.
  It is computed over the exact stored bytes and never over a re-encoding,
  so it does not depend on how the CBOR encoder behaves.
- Decoding is strict: exactly one CBOR item, no trailing bytes, and exactly
  five outer elements.

After unwrapping the master key (MK), the daemon verifies `header_mac`
before trusting anything else in the header. This detects keyslot
deletion, substitution, and format-version rollback.

### Master key and keyslots

- MK: 32 random bytes from the OS CSPRNG. It is never derived from user
  input and exists at rest only wrapped inside keyslots.
- Each keyslot wraps MK with XChaCha20-Poly1305 under a slot-specific KEK:
  - random 24-byte nonce
  - AAD = `vault_id ‖ slot_id ‖ slot_type`
- Common slot fields: `slot_id` (UUID), `slot_type`, `label`, `created`,
  `nonce`, `wrapped_mk`, plus type-specific parameters:

| `slot_type` | KEK source | Type-specific params |
|---|---|---|
| `tpm` | 32-byte random KEK sealed in the TPM | `tpm_public`, `tpm_private` blobs; `auth`: `none` \| `pin` \| `login-password`; optional `pcrs` (e.g. `[7]`) with PCR bank |
| `fido2` | `HKDF(hmac-secret output, info="aleph fido2 v1")` | `credential_id`, `rp_id` (`"aleph"`), `salt` (32 bytes), `uv_required`, `pin_required` |
| `recovery-key` | `Argon2id(recovery key)` | `salt`, `m=256 MiB`, `t=3`, `p=4` |
| `passphrase` | `Argon2id(passphrase)` | `salt`, params tuned at enrollment to ≈1 s, floor `m=1 GiB` |
| `login-password` | `Argon2id(login password)` | `salt`, params tuned at enrollment to ≈0.3 s, floor `m = 64 MiB, t = 2, p = 4`. Used only when no TPM is available. |

Argon2 parameters read from a vault are rejected above `m = 4 GiB`,
`t = 64`, `p = 16`, so a corrupt or hostile slot errors instead of
attempting a huge allocation.

Adding or removing an unlock method adds or removes a slot. Only
`rotate-master` re-encrypts the body.

### Body

- Plaintext structure: `collections[]`, each with `id`, `label`, `created`,
  `modified`, `items[]`. Each item has `id`, `label`, `attributes`
  (string→string map), `secret` (bytes), `content_type`, `created`,
  `modified`. Aliases (`default` → collection id) live in the body.
- Encrypted as one blob with XChaCha20-Poly1305:
  - key = `HKDF(MK, info="aleph body v1")`
  - fresh random nonce on every write
  - AAD = `vault_id ‖ be32(format_version) ‖ header_mac`. Including
    `header_mac` binds the body to the exact header it was written with,
    so an older header (for example one still listing a removed keyslot)
    cannot be spliced onto a newer body.
  - stored as the outer array's `body_nonce` and `body_ct` elements

### Locked search

Attributes are encrypted, so a locked vault cannot be searched. When
`SearchItems` (or another read that needs the body) arrives while locked,
`alephd` holds the method reply, raises the unlock prompt, and answers
after unlock, or returns empty results if the user cancels. This is
bounded by the caller's D-Bus timeout (~25 s by default). If the caller
times out, the prompt stays up and the client's next request succeeds
once unlocked. `Unlock()` itself uses Secret Service `Prompt` objects and
has no timeout.

### Memory hygiene

- All key material and plaintext secrets are held in `secrecy`/`zeroize`
  types.
- MK and the decrypted body are held in `mlock`ed memory. `aleph-core`
  mlocks MK and never leaves plaintext secrets in freed heap blocks (the
  body is encoded into an exactly sized, zeroized buffer and decoded
  without intermediate copies). Page-locking the decrypted body is
  `alephd`'s job (Plan 3).
- `alephd` calls `prctl(PR_SET_DUMPABLE, 0)` at startup (no core dumps,
  no same-uid `ptrace`).
- Locking zeroizes MK, all derived keys, and the decrypted body, and closes
  all Secret Service sessions.

## 5. Unlock methods

### TPM (`tss-esapi` against `/dev/tpmrm0`)

- **Access:** the user must be in the `tss` group (`/dev/tpmrm0` is
  `root:tss 0660` on Arch). `aleph setup` adds the user via sudo as part of
  the switchover, which already requires a re-login. On NixOS the module
  handles it.
- **Parent key:** a primary key is re-created on each use from a fixed
  template (ECC P-256, symmetric AES-256-CFB) under the owner hierarchy.
  It is never persisted with `EvictControl`, so setup does not need owner
  authorization.
- **Seal:** a keyed-hash sealed object holding the 32-byte KEK. Auth value
  = `SHA-256(HKDF(secret, info="aleph tpm auth v1"))`, where `secret` is
  the PIN or login password (empty for `auth=none`). Policy is
  `PolicyAuthValue`, optionally combined with `PolicyPCR(pcrs)`.
- **Sessions:** all commands use salted HMAC sessions with parameter
  encryption (AES-256-CFB), so neither the auth value nor the KEK crosses
  the bus in plaintext.
- **Dictionary-attack lockout:** the TPM's existing settings apply. `aleph`
  does not modify them, and documents their effect.
- **Password change:** `pam_aleph`'s `password` phase sends old and new
  passwords, and `alephd` runs `TPM2_ObjectChangeAuth` and rewrites the
  slot blobs. If the password was changed out of band (e.g. `passwd` as
  root), the slot fails. The prompter then offers the recovery secret and
  re-enrolls the slot with the new password.
- **PCR binding (opt-in):** a firmware or boot change makes unseal fail.
  The prompter falls back to another slot or the recovery secret, and
  offers to re-seal against current PCR values.

### FIDO2 (libfido2 bindings)

- **Enrollment:** `makeCredential` with the `hmac-secret` extension,
  non-resident, RP ID `aleph`. PIN/UV is used if the key requires it or the
  user opts in.
- **Unlock:** `getAssertion` with the slot's salt yields the `hmac-secret`
  output, and the KEK is `HKDF(output)`.
- Multiple keys are supported, one slot each.
- Device access relies on the udev `uaccess` rules shipped by Arch's
  `libfido2` package.
- **Prompter flow:** "Insert your key" (watches hotplug, advances
  automatically) → "Enter PIN" (only if required) → "Touch your key".
  Every screen has **Use recovery secret instead**.
- All FIDO2 access goes through the `Authenticator` trait so it can be
  mocked in tests.

### Recovery secret

At setup the user chooses one (or both, as separate slots later):

- **Recovery key (recommended default):** 256 random bits, displayed once
  as 52 Crockford base32 characters plus a 4-character checksum (the top
  20 bits of SHA-256), shown as 14 groups of 4. Input is case-insensitive
  and normalizes `O→0`, `I/L→1`.
- **Passphrase:** user-chosen, protected by heavy Argon2id.

A backup is the vault file plus the recovery secret. Losing either loses
the data.

### Unlock order

| Trigger | Slots tried, in order |
|---|---|
| Login / lock-screen unlock (password from PAM) | `tpm` with `auth=login-password`, then `login-password` |
| First use in FIDO2 / TPM-PIN mode | enrolled `fido2` slots, then `tpm` with `auth=pin` |
| Always available | `recovery-key` / `passphrase` via the prompter |

## 6. Daemon (`alephd`)

### Startup and switchover from gnome-keyring

- Runs as a systemd user service `alephd.service`, with `alephd.socket`
  owning `$XDG_RUNTIME_DIR/aleph/pam.sock`. It is started by D-Bus
  activation for `org.freedesktop.secrets` or by socket activation from
  PAM.
- `aleph setup` (Arch/Omarchy):
  1. Installs the user D-Bus activation file into `$XDG_DATA_HOME/dbus-1/services/`,
     which takes precedence over gnome-keyring's system file.
  2. Masks gnome-keyring's user units.
  3. Backs up and edits PAM: removes `pam_gnome_keyring`, adds
     `pam_aleph` (below).
  4. Adds the user to `tss`.
- `aleph setup --revert` restores all of the above from the backups.

### PAM integration

- `system-login`: `auth optional pam_aleph.so`,
  `session optional pam_aleph.so`, `password optional pam_aleph.so`.
- `hyprlock`: `auth optional pam_aleph.so`.
- **Login:** in the `auth` phase the password is stored with
  `pam_set_data`, with a zeroizing cleanup. In the `session` phase, after
  the systemd user instance is up, the module connects to `pam.sock`,
  which socket-activates `alephd`. The daemon checks `SO_PEERCRED` (uid
  must match its own), receives the password, and uses and zeroizes it.
- **Lock screen:** the daemon is already running, so the `auth` phase
  sends directly.
- **Password change:** the `password` phase sends old and new passwords.
- The module never blocks login. Every failure is logged and returns
  `PAM_IGNORE`.

### Secret Service

- Implements `org.freedesktop.Secret.Service`, `.Collection`, `.Item`,
  `.Session`, `.Prompt` per the freedesktop spec.
- Multiple collections live in one vault. By default a `login` collection
  exists, with alias `default` pointing to it.
- Session algorithms: `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`
  (required by libsecret; weak by modern standards, acceptable on a
  per-user local bus; documented).

### Admin interface `io.aleph.Admin1`

- Available on the session bus only.
- Methods: `Status`, `Lock`, `Unlock`, `ListKeyslots`, `EnrollTpm`,
  `EnrollFido2`, `EnrollRecoveryKey`, `EnrollPassphrase`, `RemoveKeyslot`,
  `RotateMaster`, `GetConfig`, `SetConfig`, `ImportGnomeKeyring`.
- Operations that are destructive or reveal secrets require fresh
  re-authentication through the prompter, even while unlocked. These are
  removing a keyslot, rotating the recovery secret, rotating the master
  key, and revealing a secret in the GUI.

### Lock policy

Configured in `~/.config/aleph/config.toml`:

```toml
[lock]
on_suspend = true        # logind PrepareForSleep(true)
on_screen_lock = true    # logind Session.Lock (hypridle → loginctl lock-session)
idle_timeout = 0         # seconds without secret access; 0 = disabled
# setting everything false/0 = lock only at logout
```

### Prompter orchestration

- `alephd` spawns `aleph-gui prompt` with one end of a socketpair and
  exchanges newline-delimited JSON messages.
- With no Wayland display, it falls back to a terminal prompt via
  `aleph unlock`, in the style of `systemd-ask-password`.

### Logging

`tracing` to journald. Secret values, passwords, PINs, and key material
are never logged. This is enforced by the `secrecy` types' `Debug`
implementations and a lint test.

## 7. Clients

### CLI (`aleph`, clap)

```
aleph setup [--revert]
aleph status | lock | unlock
aleph keyslot list
aleph keyslot add tpm [--pin | --login-password] [--pcr 7]
aleph keyslot add fido2 | recovery | passphrase
aleph keyslot remove <slot-id>
aleph keyslot rotate-master
aleph get attr=val…          # secret-tool compatible semantics
aleph search attr=val…
aleph store --label L attr=val…   # secret read from stdin, never argv
aleph delete attr=val…
aleph ls [collection]
aleph import gnome-keyring
aleph config get|set <key> [value]
aleph backup <path>
aleph restore --recovery <path>
```

- Global flags: `--json`. Shell completions are generated for bash, zsh
  and fish.
- `aleph setup` is an interactive wizard:
  1. TPM access check
  2. unlock mode (TPM + login password [default] / FIDO2 / TPM PIN)
  3. recovery key vs passphrase, with the secret shown once
  4. live import from gnome-keyring
  5. system changes (sudo)
- **Import** reads every collection and item through the Secret Service
  API while gnome-keyring still owns the bus name, before the switchover.
  This covers everything shown in Seahorse's Passwords view, which is only
  a front end to gnome-keyring.
- **`restore`** is the only command that opens a vault directly (via
  `aleph-core`). It unwraps MK with the recovery secret, drops TPM slots
  from the old machine, and enrolls new slots on this one.

### GUI (`aleph-gui`, eframe/egui)

**Theme**

- On Omarchy (detected by `~/.local/state/omarchy/current/theme/colors.toml`),
  the default theme follows the current Omarchy theme. Its palette
  (`accent`, `background`, `dark_background`, `foreground`, `selection`,
  `muted`, the ANSI colors, `mode`) maps to egui `Visuals`.
- The GUI watches the theme directory with inotify (`notify`) and
  re-themes live when the user switches Omarchy themes.
- **Aleph neon** (near-black, neon cyan/magenta, monospace) is the
  fallback off-Omarchy, and is selectable anywhere.
- The scanline overlay is an independent toggle, default on, disabled
  automatically when reduced motion is requested.
- Section headers may use Gibson vocabulary. Buttons and labels stay plain.

**Prompter (`aleph-gui prompt`)**

- Fixed-size windows with app_id `aleph-prompt`.
- Screens:
  - the FIDO2 sequence (insert → PIN → touch)
  - TPM PIN or passphrase entry
  - recovery key entry
  - confirmations (collection create/delete, re-auth for sensitive admin
    operations)
- The package ships a Hyprland snippet (float, center, pin, focus) that
  setup offers to include.

**Manager (`aleph-gui`)**

- **Secrets:** collection list, searchable item list, and a detail pane
  (label, attributes, masked secret). Reveal requires re-auth. Copy uses
  the Wayland clipboard with auto-clear after 30 s. Create, edit and
  delete are supported.
- **Keyslots:** list, plus enroll/remove wizards.
- **Settings:** lock policy, theme and scanlines, prompt timeouts.
- **Import**
- A `.desktop` entry makes it available in the Omarchy launcher.

## 8. Packaging and distribution

- **Repo:** one Cargo workspace (six crates), plus `packaging/arch/`,
  `flake.nix` and `docs/`. It targets current stable Rust.
- **Arch / Omarchy:** `PKGBUILD` in-repo, published to the AUR as
  `aleph-keyring` and `aleph-keyring-git`.
  - Depends on `tpm2-tss`, `libfido2`, `pam`, `dbus`.
  - `provides=(org.freedesktop.secrets)`. It does not conflict with
    `gnome-keyring`: setup switches between them.
  - Installs:
    - binaries to `/usr/bin`
    - `/usr/lib/security/pam_aleph.so`
    - `/usr/lib/systemd/user/alephd.{service,socket}`
    - the `.desktop` file
    - `/usr/share/aleph/hypr/aleph.conf`
- **NixOS:** the flake exposes a package (built with `crane`) and a NixOS
  module `services.aleph`. The module:
  - installs the package and the user units
  - adds `pam_aleph` via `security.pam.services.<name>.rules` for login
    and `hyprlock`
  - enables `security.tpm2`
  - adds listed users to `tss`
  - asserts `services.gnome.gnome-keyring.enable = false`

  On NixOS, `aleph setup` detects the read-only `/etc/pam.d`, skips the
  system changes, and prints the module configuration instead. Keyslots,
  the recovery secret and import work as on Arch.
- **CI (GitHub Actions):** `cargo fmt --check`, `clippy -D warnings`,
  tests (including `swtpm`), `cargo deny`, `nix flake check`, and a
  `PKGBUILD` build in an Arch container.

## 9. Testing

- **aleph-core:**
  - unit tests plus `proptest` properties: round-trip, any flipped byte →
    error, keyslot moved to another slot position fails to unwrap, header
    rollback rejected
  - golden vault files per format version, which must open forever
  - fast test-only Argon2 params, plus known-answer tests for production
    params
- **Fuzzing (`cargo-fuzz`):** vault/CBOR parser, and Secret Service
  session decoding.
- **TPM:** `swtpm` in CI. Tests cover seal/unseal, wrong auth,
  `ObjectChangeAuth`, and PCR policy (extend PCR 7 → unseal fails →
  recovery path).
- **FIDO2:** a mock `Authenticator` with a software `hmac-secret`. A manual
  checklist with a real key (`docs/testing.md`) is run before each release.
  uhid-based virtual keys are optional, not CI.
- **Daemon:** a private `dbus-daemon` running `alephd` with a temp vault and
  `swtpm`. Conformance is checked with `secret-tool` and Python
  `secretstorage`. Lock tests inject `PrepareForSleep` and `Lock`, then
  assert keys are zeroized and the next access prompts.
- **PAM / setup:** `pamtester` in an Arch container covering login, lock
  screen, and password change. `setup` followed by `--revert` must leave
  `/etc/pam.d` byte-identical.
- **GUI:** `egui_kittest` snapshots of every prompter screen in both themes,
  and `colors.toml` parsing tests.
- **Pre-1.0:** a written threat model and an external security review of
  `aleph-core`, `aleph-unlock` and `pam_aleph`.

## 10. V2 roadmap

- **Privilege separation:** move key custody (MK, TPM, FIDO2) into a
  separate minimal process behind the `KeyHandle` seam. The D-Bus-facing
  daemon never holds MK.
- **SSH:** store SSH key passphrases and unlock keys into OpenSSH's
  `ssh-agent`.
- **GPG:** a pinentry that retrieves passphrases from `aleph`. Full GPG key
  custody would be considered separately.
- **Offline import** of gnome-keyring `login.keyring` files.
- **Waybar indicator** showing lock state.
- **Per-application access control** (defending against same-uid processes).
- **Home Manager module.**
- **Vault sharing/export to a public key**, which would introduce hybrid
  ML-KEM.
- Upstreaming `aleph` as an option in Omarchy's installer.

## 11. Open items to verify during planning

These are implementation facts to confirm, not design decisions:

- The maturity and API of the Rust libfido2 bindings (vs. the pure-Rust
  `ctap-hid-fido2`). Choose whichever supports `hmac-secret` with PIN/UV
  reliably.
- The current state of the `oo7` crate: reuse its Secret Service types or
  server scaffolding where practical, rather than re-implementing the
  protocol.
- The exact gnome-keyring units and PAM lines present on a stock Omarchy
  install, which setup must handle.
