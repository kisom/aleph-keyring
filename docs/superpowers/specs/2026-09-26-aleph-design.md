# aleph — design spec

- **Date:** 2026-09-26 (revision 2, after `docs/reviews/2026-09-26-aleph-design-review.md`)
- **Status:** Draft, awaiting review
- **License:** Apache-2.0

> *Aleph*: in Gibson's *Mona Lisa Overdrive*, a biochip holding an entire
> world, sealed away. The crate is published as `aleph-keyring` (the `aleph`
> name on crates.io is held by a placeholder); binaries and the project are
> `aleph`.

**Revision 2 changes**, driven by the design review (review finding
numbers in brackets):

- Removing a slot, restoring a vault, or changing a password now rotates
  the master key [1, 3].
- The recovery slot is now a hybrid public-key recipient (X-Wing: X25519 +
  ML-KEM-768), so rotation never needs the paper key [1].
- TPM access goes through a small privileged helper, `aleph-tpmd`. Users
  are no longer added to `tss` [2, 6].
- §2 now states the real guarantees [2, 4, 16].
- The PAM design targets Omarchy's real PAM files, with separate
  password-login and autologin modes [5].
- Locked search returns `IsLocked` instead of holding replies [10].
- The header carries a generation counter, checked against a local
  high-water mark [7].
- Unknown slot types are preserved verbatim [12].
- Enrollment and configuration changes require re-authentication [8].
- Backups contain only the recovery slot [9].
- `setup --revert` exports aleph items back to gnome-keyring [14].
- Cut from v1: PCR binding, `auth=none` TPM slots, TPM-PIN mode, and
  passphrase recovery [13, 21].

## 1. Purpose

`aleph` is a drop-in replacement for the Secret Service half of
gnome-keyring, written in Rust, targeting Omarchy (Arch Linux) first and
NixOS second. Its distinguishing feature is hardware-bound unlocking: the
vault's master key is released by the TPM (combined with the login
password) or by a FIDO2 security key. A recovery key is the escape hatch.

### Success criteria for v1

1. Every existing libsecret client running unsandboxed (browsers, VS Code,
   `git-credential-libsecret`, NetworkManager, `secret-tool`) works
   unmodified against `alephd`. Flatpak apps are out of scope (see
   non-goals).
2. On Omarchy with **password login**, after `aleph setup` and one
   re-login, the vault unlocks at login with no extra interaction (TPM +
   login password). With **autologin** there is no password at login, so
   the vault stays locked until first use and then prompts for a FIDO2
   touch or the login password.
3. Users can choose FIDO2 as their unlock method instead of TPM + password.
4. Existing gnome-keyring secrets are migrated during setup.
5. A vault can be restored on a new machine from a backup file plus the
   recovery key alone.
6. `aleph setup --revert` restores gnome-keyring, with every item that was
   created or changed under aleph exported back into it first. Revert
   refuses to run if the export fails.

### Non-goals for v1

- SSH agent or GPG agent functionality (see §10).
- Per-application access control between processes running as the same user.
- Parsing gnome-keyring's on-disk `login.keyring` format.
- Multi-user or system-wide secrets.
- Flatpak/portal clients. Sandboxed apps reach secrets through
  `org.freedesktop.impl.portal.Secret`, whose backend is gnome-keyring.
  This is on the v2 roadmap.
- Live sync of one vault between machines. Backups and restore are
  supported; concurrent use of a synced file is not.
- PCR/Secure Boot binding, TPM-PIN unlock, and passphrase recovery (see
  §10).

## 2. Threat model

aleph protects secrets **at rest**. What it guarantees depends on what the
attacker holds.

| Attacker holds | Outcome |
|---|---|
| **A copy of the vault file only** (a backup, a sync peer, a stolen disk image after LUKS) | Nothing, as long as the recovery key has not also leaked. Hardware slots are useless without this machine's TPM or the enrolled FIDO2 key. The login-password slot, which exists only on machines without a TPM, is left out of `aleph backup` copies. Generic backups of the live file do contain it, and `aleph backup` warns about this (§7). |
| **The vault file and this machine, powered off** (LUKS unlocked by some other means, or a pre-boot evil maid) | TPM slots: security reduces to the strength of the login password, unless the TPM's `lockoutAuth` is set. With an empty `lockoutAuth`, which is the Linux default, anyone with raw TPM access can reset dictionary-attack protection and guess at about one TPM round-trip per guess. `aleph setup` reports whether `lockoutAuth` is set and what the lockout parameters are (§5). FIDO2 slots: the attacker also needs the key and its PIN (PIN/UV is the default, §5). |
| **This machine while suspended** (LUKS key and aleph MK in RAM) | aleph locks and zeroizes MK before suspend, holding a logind delay inhibitor until that is done (§6). Secrets that clients have already fetched (browser safe-storage keys, NetworkManager, cached git credentials) are out of aleph's reach. The attacker then holds the file and the machine, and the row above applies. |
| **A same-user process, briefly** (malware that runs once) | While the vault is unlocked it can read every secret, as with gnome-keyring. Enrolling a new slot, changing configuration, or removing a slot requires re-authentication, so the process cannot turn brief access into permanent access (§6). Removing a slot rotates MK, which revokes any keyslot the process added (§4). |
| **A different local user** | Nothing. The TPM helper binds sealed objects to the caller's uid (§5), and the vault file is mode `0600`. |

**Out of scope:**

- root or kernel compromise of the running machine
- cold-boot and DMA attacks on a running or suspended machine
- an evil maid when Secure Boot is not configured, since a modified
  initramfs can capture both the LUKS passphrase and the login password
- Flatpak/portal clients
- physical TPM or USB bus interposers:
  - passive recording for later quantum cryptanalysis: documented
  - active substitution of the TPM's primary key: detected (§5)

**Post-quantum posture:**

- **At rest:** protected with symmetric crypto (256-bit AEAD, HKDF-SHA-256,
  Argon2id, TPM sealed objects under an AES-256 parent (AES-128 only with
  the SRK fallback, §5), FIDO2
  `hmac-secret`), plus the recovery slot's hybrid X-Wing KEM (X25519 +
  ML-KEM-768). Wrapping to the recovery public key therefore stays secure
  against a quantum adversary.
- **In transit:** TPM and FIDO2 sessions use classical ECC.

## 3. Architecture

A per-user daemon with thin clients, and a small system helper that owns
the TPM. The design keeps key custody separable for v2 (§10).

```
 libsecret apps ──D-Bus──┐
                         │  org.freedesktop.secrets
 aleph (CLI) ───D-Bus────┤  io.aleph.Admin1
 aleph-gui (manager) ────┤
                         ▼
                      alephd (user) ──spawns──▶ aleph-gui prompt   (socketpair, JSON lines)
                         ▲      │
 pam_aleph.so ───────────┘      └──unix socket──▶ aleph-tpmd (system, DynamicUser + tss)
   ($XDG_RUNTIME_DIR/aleph/pam.sock)                 /run/aleph/tpm.sock ──▶ /dev/tpmrm0
                         │
                 aleph-core + aleph-unlock ──▶ FIDO2 (hidraw, uaccess)
                         │
                   vault.aleph
```

### Workspace crates

| Crate | Kind | Responsibility | Depends on |
|---|---|---|---|
| `aleph-core` | lib | Vault format and cryptography: AEAD, HKDF, Argon2id KDF, keyslot wrap/unwrap, the X-Wing recovery recipient, generation counter, collections/items model. No D-Bus, no hardware, no global state apart from the Argon2 serialization lock. | `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `argon2`, ML-KEM/X25519 (X-Wing), `ciborium`, `secrecy`, `zeroize`, `uuid` |
| `aleph-tpm-proto` | lib | The `aleph-tpmd` wire protocol: request/response types and framing. | `serde`, `ciborium` |
| `aleph-tpmd` | bin | TPM helper: seal and unseal per uid, SRK verification, rate limiting, `Status`. | `aleph-tpm-proto`, `tss-esapi` |
| `aleph-unlock` | lib | Produces a KEK per hardware keyslot: the TPM client (talks to `aleph-tpmd`) and FIDO2 (`Authenticator` trait, `libfido2` backend, mock). | `aleph-core`, `aleph-tpm-proto`, `fido2-rs` |
| `alephd` | bin | Secret Service and admin D-Bus interfaces, PAM socket, lock policy, prompter orchestration. | `aleph-core`, `aleph-unlock`, `zbus`, `tokio`, `tracing`, `tracing-journald` |
| `pam_aleph` | cdylib | PAM module: forwards passwords to `alephd` after dropping to the user's uid. Minimal, no async runtime. | PAM FFI, std |
| `aleph` | bin | CLI. | `zbus`, `clap` |
| `aleph-gui` | bin | egui manager and prompter. | `eframe`, `egui`, `zbus`, `notify`, Wayland clipboard crate |

**Seam for privilege separation:** only `KeyHandle` touches MK. Callers
ask it to wrap, seal, open, and MAC. v2 can move `KeyHandle` into a
separate process, but the gain is limited: the D-Bus-facing daemon still
holds every decrypted secret. Separation protects MK, not the secrets.

## 4. Vault format and cryptography

### File

- Path: `$XDG_DATA_HOME/aleph/vault.aleph` (default `~/.local/share/aleph/`).
  File mode `0600`. The directory is created `0700`. An existing directory
  that is group- or world-accessible is tightened to `0700` with a warning.
- Encoding: CBOR.
- Writes are atomic:
  1. write `vault.aleph.tmp` and `fsync` it
  2. rename it over `vault.aleph`
  3. `fsync` the directory

  The previous version is kept as `vault.aleph.bak`, except on the first
  write after a rotation: then the old `.bak` is removed before the rename
  and re-created from the new file, so the pre-rotation file (old MK,
  removed slots) never survives as a backup. Writers hold an exclusive
  `flock` on `vault.aleph.lock` for the whole sequence. The rename of
  `vault.aleph` is the commit point: everything that can fail happens
  before it, and what follows (re-creating `.bak`, the directory fsync) is
  best-effort, so a completed write is never reported as failed.
- `alephd` holds a second lock, `vault.aleph.daemon`, for its whole
  lifetime. A second daemon, or a CLI trying to write directly, refuses to
  run. All writes go through the running daemon.
- If `vault.aleph` is a symlink, aleph refuses to write, rather than
  silently replacing the link with a regular file.
- If `vault.aleph` fails to parse or authenticate and `vault.aleph.bak`
  opens, `alephd` does not switch over automatically. It reports the
  problem and offers `aleph restore --from-bak`.

### Layout

`MAGIC ‖ CBOR([format_version, header_bytes, header_mac, body_nonce, body_ct])`

- `MAGIC` is `"ALEPH\0"`, and `format_version` is `1`.
- `header_bytes` is the CBOR encoding of the header map, stored as a byte
  string:

  | Field | Type | Notes |
  |---|---|---|
  | `vault_id` | UUIDv4 (bytes) | |
  | `generation` | u64 | Incremented on every write. Starts at 1. |
  | `mk_id` | 16 bytes | `HKDF(MK, "aleph mk id v1")[..16]`. Changes when MK rotates. Not secret. |
  | `keyslots` | array | Each element is a byte string holding one keyslot's CBOR, so that unknown slot types can be re-emitted byte-for-byte. |

- `header_mac = HMAC-SHA-256(HKDF(MK, "aleph header v1"), MAGIC ‖ be32(format_version) ‖ header_bytes)`.
  It is computed over the exact stored bytes, never a re-encoding.
- Decoding is strict: exactly one CBOR item, no trailing bytes, and
  exactly five outer elements.

After unwrapping MK, the daemon verifies `header_mac` before trusting
anything else in the header. This detects keyslot deletion or substitution
and format-version changes within one file. Rollback of the whole file is
handled by the high-water mark below.

### Generation and high-water mark

`alephd` records `(vault_id, generation, mk_id)` in
`$XDG_STATE_HOME/aleph/highwater-<vault_id>` (one file per vault), outside
the vault's directory, so that
backups and sync do not carry it. The value is only raised, never lowered.

On unlock:
- **Lower `generation`:** the file has been rolled back. The daemon
  reports this in the prompter and in `aleph status`, and refuses to write
  until the user confirms, either with `aleph restore --accept-rollback`
  or by accepting it in the GUI.
- **Same `generation` but a different `mk_id`:** the file has been
  replaced. Same handling.
- **Higher `generation` with a different `mk_id`:** MK changed somewhere
  other than this daemon, or someone holding an old MK is replaying it
  under a forged generation (`Rekeyed`). Same handling.

Only the daemon's own writes move the mark to a new MK. The daemon writes
with `write_recorded`, which notes the intended mark before the rename
(`highwater-<vault_id>.pending`) and records it after. A file matching the
pending intent (a crash or error between rename and record) is `Pending`,
not `Rekeyed`, and is then recorded. Marks of files the daemon reads are
raised only through `HighWater::raise`, which takes an unlocked (hence
authenticated) vault, and only within the same MK; an unauthenticated
header can be checked but never raises the mark. The store is guarded by a
per-vault lock (`highwater-<vault_id>.lock`).

This defends against a sync peer or a restored backup silently undoing a
rotation. It is not tamper-proof against an attacker who can also write
`$XDG_STATE_HOME`. A TPM NV counter would be, and is on the v2 roadmap.

### Master key and keyslots

- MK is 32 random bytes from the OS CSPRNG. It is never derived from user
  input, and exists at rest only wrapped inside keyslots.
- Each keyslot wraps MK with XChaCha20-Poly1305 under a slot-specific KEK:
  - random 24-byte nonce
  - AAD = `vault_id ‖ id ‖ slot_type`
- Each keyslot is a CBOR map with the fields `id` (UUID), `label`,
  `created`, `nonce`, `wrapped_mk`, and `kind`. `kind` is a map tagged by
  `slot_type`, holding that type's parameters. The encoding is frozen when
  v1 ships. Plan 1b regenerates the (unreleased) golden file once more for
  the revision 2 changes: `generation`, `mk_id`, the `recovery` slot type,
  and the new `tpm` fields.

| `slot_type` | KEK source | Parameters in `kind` |
|---|---|---|
| `tpm` | A 32-byte random KEK sealed by `aleph-tpmd` | `public`, `private` (TPM blobs), `auth_salt` (16 bytes), `srk_name` (the parent Name verified at unseal) |
| `fido2` | `HKDF(hmac-secret output, "aleph fido2 v1")` | `credential_id`, `salt` (32 bytes), `uv_required`, `pin_required`. The RP ID is the constant `"aleph"` and is not stored. |
| `recovery` | `HKDF(X-Wing shared secret, "aleph recovery v1")` | `xwing_pk` (the recipient public key), `xwing_ct` (the encapsulation) |
| `login-password` | `Argon2id(login password)` | `salt`, `params`. Only on machines without a usable TPM. |

**Recovery recipient.**
- **Deriving the key pair:** the recovery key (256 bits, §5) goes through
  `HKDF(recovery key, "aleph recovery xwing seed v1")` to produce the
  32-byte X-Wing decapsulation seed, from which the key pair is derived
  deterministically. There is no Argon2 step, because the input already
  has full entropy.
- **Wrapping** (at creation and at every rotation):
  1. encapsulate to `xwing_pk`, giving `(ss, xwing_ct)`
  2. derive `KEK = HKDF(ss, "aleph recovery v1")`
  3. wrap MK under that KEK

  `alephd` can re-wrap MK without the recovery key. It needs only the
  public key stored in the (authenticated) header.
- **Unwrapping:** decapsulate `xwing_ct` using the key pair derived from
  the typed recovery key.

**Forward compatibility.** Keyslots whose `slot_type` this build does not
recognise are kept as raw CBOR. They are listed as "unknown" and skipped
for unlock. On rewrite they are re-emitted byte-for-byte, and their wraps
are dropped when MK rotates, since they cannot be re-wrapped. Known slot
types reject unknown fields (`deny_unknown_fields`); anything new is added
under a new `slot_type`.

**Argon2 parameters:**
- Parameters read from a vault are rejected above `m = 4 GiB`, `t = 64`,
  `p = 16`, and above the process's memory capacity (RAM plus swap, capped
  by cgroup limits), as `InsufficientMemory`.
- Enrollment enforces a minimum for each kind: `login-password` needs at
  least `m = 64 MiB, t = 2, p = 4`, tuned to about 0.3 s.
- `Argon2Params::INSECURE_TEST` is available only under `cfg(test)` or the
  `insecure-test-params` feature, and the golden-file test uses that
  feature.

### Rotation and revocation

MK is rotated, meaning a new MK is generated, the body is re-encrypted, and
every slot is re-wrapped:

- **when a keyslot is removed.** Otherwise anyone holding an old copy of
  the file and the removed credential could recover the MK that decrypts
  every later copy.
- **on `aleph restore`**
- **when the login password changes** (together with a fresh TPM seal, §5)
- **on `aleph keyslot rotate-master`**

Re-wrapping needs a KEK for every slot. The daemon never keeps
passwords, so the KEKs come from these sources:

- **The recovery slot:** re-wrapped to its public key, with no secret
  needed.
- **The TPM and login-password slots:** unsealed or derived with the login
  password. The password comes from the re-authentication that every
  rotating operation requires (§6), or from `pam_aleph` during a password
  change. It is zeroized once the rotation completes.
- **Each FIDO2 slot:** needs that key's touch. The prompter walks through
  them in turn.

A slot that cannot be presented is removed, after the user confirms. A
rotation never leaves a slot wrapping the old MK.

### Body

- Plaintext structure: `collections[]`, each with `id`, `label`,
  `created`, `modified`, `items[]`. Each item has `id`, `label`,
  `attributes` (string → string map), `secret` (bytes), `content_type`,
  `created`, `modified`. Aliases (`default` → collection id) live in the
  body.
- Encrypted as one blob with XChaCha20-Poly1305:
  - key = `HKDF(MK, "aleph body v1")`
  - a fresh random nonce on every write
  - AAD = `vault_id ‖ be32(format_version) ‖ header_mac`, which binds the
    body to its exact header
  - stored as the outer array's `body_nonce` and `body_ct` elements

### Locked search

Attributes are encrypted, so a locked vault cannot be searched. aleph
never answers a search with a false "no such item". Returning empty
results would make some clients (Chromium's safe-storage key is the
classic case) create a new key that orphans their existing data.

- `SearchItems`, `GetSecrets`, `Item.GetSecret`, and every other read that
  needs the body return `org.freedesktop.Secret.Error.IsLocked` while the
  vault is locked. Clients then call `Unlock()`, which goes through the
  normal `Prompt` flow with no reply timeout.
- No method call ever blocks waiting for the user.
- Plan 3 must verify this against real clients before it is final:
  libsecret's `secret_password_lookup` with and without
  `SECRET_SEARCH_UNLOCK`, Chromium's safe-storage lookup, and
  NetworkManager. If a client treats `IsLocked` as "not found", the
  fallback is an unlock-triggering placeholder in the `locked` list, and
  that choice is recorded in §11.

### Memory hygiene

What is guaranteed:

- MK lives in its own page. The page is `mlock`ed when permitted (best
  effort; `aleph status` reports whether it succeeded), marked
  `MADV_DONTDUMP` and `MADV_WIPEONFORK`, and zeroized on drop.
- `alephd` calls `prctl(PR_SET_DUMPABLE, 0)` at startup.
- The body is encoded into an exactly sized buffer that is zeroized after
  use, and decoded without intermediate copies. Plaintext secrets
  (`SecretBytes`) are zeroized on drop.
- Children are started only via `posix_spawn`/`exec`
  (`std::process::Command`), never a bare `fork`.
- Locking zeroizes MK, derived keys, and the decrypted body, and closes all
  Secret Service sessions.

What is not guaranteed: labels and attributes are ordinary strings and are
not zeroized. zbus, libsecret, and the GUI make their own copies of
secrets in transit. `mlock` does not keep pages out of a hibernation image
(§6 locks before hibernate). Swap should be encrypted or zram-only, and
`aleph setup` warns if it is neither.

## 5. Unlock methods

### TPM, via `aleph-tpmd`

**The helper.**
- **Service:** `aleph-tpmd` is a socket-activated system service
  (`aleph-tpmd.socket` → `/run/aleph/tpm.sock`, mode `0666`). Access
  control is by peer uid, not by file mode.
- **Sandboxing:** it runs with `DynamicUser=yes` and
  `SupplementaryGroups=tss`. Only this service can open `/dev/tpmrm0`, and
  users are not in `tss`. It is sandboxed: `ProtectSystem=strict`,
  `PrivateNetwork=yes`, `DeviceAllow=/dev/tpmrm0 rw`, `NoNewPrivileges=yes`,
  an empty `CapabilityBoundingSet`, and so on.
- **Protocol:** length-prefixed CBOR frames (`aleph-tpm-proto`):
  - `Seal { secret, uid_bound: true }` → `{ public, private, auth_salt, srk_name }`
  - `Unseal { public, private, auth_salt, srk_name, secret }` → `{ kek }`
  - `Status` → `{ srk_present, lockout_auth_set, max_tries, recovery_time, lockout_recovery, failed_tries }`

  The helper keeps no state on disk.
- **Binding to a uid:** the helper reads the caller's uid with
  `SO_PEERCRED`.
  - It seals `uid (u32 BE) ‖ KEK`, and on unseal returns the KEK only if
    the stored uid matches the caller's.
  - The auth value also includes the uid:
    `auth = HKDF(secret, salt = auth_salt, info = "aleph tpm auth v1" ‖ be32(uid))`.
    `auth_salt` is random for each slot, so the derivation is not a single
    global function that could be precomputed.

  Another local user who copies your blobs gets nothing, even if they know
  your password.
- **Parent key:**
  - By default the helper re-creates aleph's own primary on each use: ECC
    P-256 with an AES-256-CFB symmetric parent, under the owner hierarchy.
    This keeps the post-quantum margin of §2.
  - If `ownerAuth` is set, which makes that impossible, it falls back to
    the persistent TCG standard SRK at `0x81000001`. That key uses
    AES-128-CFB, and `aleph status` reports it.
  - If neither is possible, `Status` says so and TPM enrollment is refused.
  - A primary created from a fixed template on a given TPM always has the
    same Name. Whichever parent is used, its Name is recorded in the slot
    (`srk_name`) and checked before the helper uses the key to salt a
    session. A mismatch is an error: it means a different TPM, or an active
    interposer substituting a key.
- **Sessions:** HMAC sessions salted to the verified parent, with
  parameter encryption in both directions. That is AES-256-CFB with aleph's
  primary, or AES-128-CFB with the SRK fallback.
- **Sealed object:** a keyed hash with `fixedTPM`, `fixedParent`, and
  `userWithAuth`, authorized by its auth value. Dictionary-attack
  protection stays on. There are no PCR policies in v1.
- **Rate limiting:**
  - at most 5 failed unseals per uid per minute
  - after a failure, the daemon marks the slot `stale` and stops trying it
    automatically until the user re-enrolls it or explicitly retries it,
    so an outdated password does not keep consuming dictionary-attack
    attempts
  - the TPM's own counter is TPM-wide, and is shared with
    `systemd-cryptenroll` TPM2+PIN disk unlock
- **`Status` and setup:**
  - `aleph setup` displays `lockout_auth_set`, `max_tries`, and the
    recovery times.
  - If `lockoutAuth` is empty, setup explains the consequence (§2) and
    offers to set it to a random value that is printed for the user to
    record. This is opt-in, never the default, because losing it means the
    lockout counter can only be reset by waiting.
- **Password change:** when `pam_aleph` passes the old and new passwords,
  `alephd`:
  1. unseals the slot with the old password
  2. seals a **new** KEK under the new password
  3. rotates MK
  4. removes the old slot

  There is no `ObjectChangeAuth`, because the old private blob would stay
  loadable with the old password on this TPM indefinitely. If the password
  was changed out of band, the slot goes `stale`. The prompter then asks
  for the old password, or offers FIDO2, and re-seals.

### FIDO2 (libfido2 via `fido2-rs`)

- **Enrollment:**
  - `makeCredential` with the `hmac-secret` extension, non-resident, RP ID
    `"aleph"`, `credProtect = 3` (userVerificationRequired)
  - defaults to requiring user verification: the PIN, or on-device UV
    where supported. Touch-only is an explicit opt-in
    (`--touch-only`, with a warning).
  - the key's `getInfo` must list `hmac-secret`, or enrollment is refused
- **Unlock:**
  - **Device selection:** with several keys plugged in, each is
    preflighted with `getAssertion(up = false)` on the slot's credential ID
    to find the one that holds it, then only that key is asked for a touch.
  - `getAssertion` with the slot's salt yields the `hmac-secret` output,
    and the KEK is `HKDF(output, "aleph fido2 v1")`.
  - Supplying a PIN to a slot enrolled without one is ignored, because it
    would switch the key to its UV secret.
- **Keys:** multiple keys are supported, one slot each. Device access
  relies on the udev `uaccess` rules shipped by `libfido2`.
- **Prompter flow:** "Insert your key" (watches hotplug and advances
  automatically) → "Enter PIN" → "Touch your key".
- **Testing:** all FIDO2 access goes through the `Authenticator` trait so
  it can be mocked in tests.

### Recovery key

- **Format:** 256 random bits, displayed once as 52 Crockford base32
  characters plus a 4-character checksum (the top 20 bits of SHA-256),
  shown as 14 groups of 4. Input is case-insensitive and normalizes `O→0`
  and `I/L→1`.
- **The recovery slot is mandatory.** Setup creates it and
  shows the key once, then asks the user to type back two randomly chosen
  groups to confirm it was recorded.
- **Recovery is its own flow,** not a button on every prompt:
  - `aleph restore` for a new machine or a broken vault
  - "Recover…" in the GUI

  Keeping the root credential off routine prompts makes fake prompts less
  useful for phishing.
- **After recovery:**
  - MK rotates
  - `aleph` offers to issue a new recovery key, in case the old one was
    exposed while it was typed

A backup is the vault file plus the recovery key. Losing both loses the
data.

### Unlock order

| Trigger | Slots tried |
|---|---|
| Password login or lock-screen unlock (password from PAM) | `tpm`, then `login-password` (no-TPM machines). Stale slots are skipped. |
| First use: locked vault, autologin, FIDO2 users | The prompter offers every enrolled method: a FIDO2 touch, or the login password (which unlocks `tpm` or `login-password`). |
| Recovery | Only via `aleph restore` or "Recover…" |

## 6. Daemon (`alephd`)

### Startup and switchover from gnome-keyring

- Runs as a systemd user service `alephd.service`, with `alephd.socket`
  owning `$XDG_RUNTIME_DIR/aleph/pam.sock` (mode `0600`). It is started by
  D-Bus activation for `org.freedesktop.secrets`, or by socket activation
  from PAM.
- `aleph setup` (Arch/Omarchy):
  1. checks `aleph-tpmd` `Status` and reports it (§5)
  2. installs the user D-Bus activation file in
     `$XDG_DATA_HOME/dbus-1/services/`, which takes precedence over
     gnome-keyring's system file
  3. masks gnome-keyring's user units
  4. backs up and edits PAM (below)
  5. imports gnome-keyring items while gnome-keyring still runs

  It detects SDDM autologin and configures first-use mode instead of login
  unlock.
- `aleph setup --revert`:
  1. exports every aleph item created or modified since setup into
     gnome-keyring, through its Secret Service API after restarting it
  2. verifies the export
  3. only then restores the backed-up PAM files and units

  If the export fails, revert stops and nothing changes.

### PAM integration

Verified against a stock Omarchy install on 2026-09-26.

- **The shared substack.** aleph installs `/etc/pam.d/aleph`:

  ```
  auth      optional  pam_aleph.so
  password  optional  pam_aleph.so
  session   optional  pam_aleph.so
  ```

- **Which services include it**, with setup editing each and keeping a
  backup:

  | Service | Change |
  |---|---|
  | `/etc/pam.d/sddm` (graphical login) | Replace the `pam_gnome_keyring` lines with `auth include aleph` after `auth include system-login`, and `session include aleph` after `session include system-login`. |
  | `/etc/pam.d/omarchy-lock-password` (hyprlock) | Add `auth include aleph` at the very end, after `pam_faillock authsucc`, so it only ever sees a password `pam_unix` has accepted. |
  | `/etc/pam.d/passwd` | Add `password include aleph` after `password include system-auth`, so that `passwd` changes reach aleph. |
  | `system-login` and `system-remote-login` | **Not edited.** An SSH login must not unlock the desktop vault. |
  | `sddm-autologin` | **Not edited.** It has no password, so first-use mode applies. |

- **Placement:** in every service, `pam_aleph` comes after the
  `pam_unix`/`pam_faillock` success path. A mistyped password never
  reaches aleph, and never costs a TPM dictionary-attack attempt.
- **Handing over the password:**
  - `pam_aleph` stores the password with `pam_set_data`, using a cleanup
    that zeroizes it.
  - To deliver it, the module forks a child that drops to the target
    user's uid and gid (`setgroups`/`setgid`/`setuid`, as
    `pam_gnome_keyring` does) and connects to `pam.sock`. The parent waits,
    with a 5-second limit.
  - `alephd` checks `SO_PEERCRED` against its own uid.
- **When it sends:**
  - login sends at `session` open, once the user's systemd instance is up
  - the lock screen sends during `auth`
  - `passwd` sends the old and new passwords during `password`
- **Never blocks login:** every failure is logged and returns
  `PAM_IGNORE`.
- **Rate limiting:** `pam.sock` accepts at most 5 failed passwords per
  minute, which bounds same-user guessing through the socket.

### Secret Service

- Implements `org.freedesktop.Secret.Service`, `.Collection`, `.Item`,
  `.Session`, and `.Prompt` per the freedesktop spec, with the locked-read
  semantics of §4.
- Multiple collections live in one vault. By default a `login` collection
  exists, with the alias `default` pointing to it.
- Session algorithms:
  - `plain`
  - `dh-ietf1024-sha256-aes128-cbc-pkcs7`, which libsecret requires. It is
    weak by modern standards, but acceptable on a per-user local bus; this
    is documented.

### Admin interface `io.aleph.Admin1`

- On the session bus only.
- Methods: `Status`, `Lock`, `Unlock`, `ListKeyslots`, `EnrollTpm`,
  `EnrollFido2`, `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`,
  `GetConfig`, `SetConfig`, `ImportGnomeKeyring`, `ExportToGnomeKeyring`,
  `Backup`, `Restore`.
- **Fresh re-authentication through the prompter** is required for every
  method that changes keyslots, configuration, or data custody:
  `Enroll*`, `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`,
  `SetConfig`, `Backup`, `Restore`, and `Export*`. Re-authentication means
  proving an enrolled method: a FIDO2 touch, or the login password
  checked through a TPM unseal.
- **"Reveal" in the GUI** also re-authenticates. That is a UX guard, not
  security, because any same-user process can call `GetSecrets`. This is
  documented.

### Lock policy

Configured in `~/.config/aleph/config.toml`:

```toml
[lock]
on_suspend = true        # logind PrepareForSleep(true), with a delay inhibitor
on_screen_lock = true    # logind Session.Lock (hypridle → loginctl lock-session)
idle_timeout = 0         # seconds without secret access; 0 = disabled
# setting everything false/0 = lock only at logout
```

- **Suspend and hibernate:** `alephd` holds a logind `delay` inhibitor for
  `sleep` while running.
  1. On `PrepareForSleep(true)` it locks and zeroizes.
  2. Then it releases the inhibitor.
  3. On resume it takes the inhibitor again.

  Hibernate is treated the same way, regardless of `on_suspend`, because
  the hibernation image is written to disk.

### Prompter orchestration

- `alephd` spawns `aleph-gui prompt` with one end of a socketpair and
  exchanges newline-delimited JSON messages.
- **What the prompt shows:** the requesting operation and, where
  available, the calling process's name and pid, from D-Bus
  `GetConnectionUnixProcessID`. This is advisory, since it can be spoofed.
- **Where the prompt runs:** it runs only as a child of `alephd`. A window
  claiming `aleph-prompt` that `alephd` did not spawn gets nothing, because
  secrets only ever travel over the socketpair.
- With no Wayland display, it falls back to a terminal prompt via
  `aleph unlock`, in the style of `systemd-ask-password`.

### Logging

`tracing` to journald. Secret values, passwords, PINs, and key material
are never logged. This is enforced by the redacted `Debug`
implementations and a lint test.

## 7. Clients

### CLI (`aleph`, clap)

```
aleph setup [--revert]
aleph status | lock | unlock
aleph keyslot list
aleph keyslot add tpm                      # TPM + login password
aleph keyslot add fido2 [--touch-only]
aleph keyslot remove <slot-id>             # rotates MK
aleph keyslot rotate-master
aleph recovery reissue                     # new recovery key; old one stops working
aleph get attr=val…                        # secret-tool compatible semantics
aleph search attr=val…
aleph store --label L attr=val…            # secret read from stdin, never argv
aleph delete attr=val…
aleph ls [collection]
aleph import gnome-keyring
aleph export gnome-keyring
aleph config get|set <key> [value]
aleph backup <path>
aleph restore [--from-bak | --accept-rollback] [<path>]
```

- Global flags: `--json`. Shell completions are generated for bash, zsh,
  and fish.
- **`aleph setup`** is an interactive wizard:
  1. TPM status (§5)
  2. unlock method: TPM + login password (the default when a TPM is
     usable) or FIDO2
  3. autologin detection
  4. the recovery key, shown once and confirmed
  5. live import from gnome-keyring
  6. system changes (sudo)
- **Import** reads every collection and item through the Secret Service
  API while gnome-keyring still owns the bus name. That covers everything
  shown in Seahorse's Passwords view.
- **`aleph backup <path>`** writes a re-headered copy containing **only
  the recovery slot**, with its MK wrap. It also warns that generic backups
  of `~/.local/share/aleph/` contain every slot, including
  `login-password` on machines without a TPM.
- **`aleph restore`** goes through `alephd`. The daemon opens the backup
  with the recovery key, rotates MK, drops slots from the old machine,
  enrolls this machine's slots, resets the high-water mark, and writes the
  result.

### GUI (`aleph-gui`, eframe/egui)

**Theme**

- On Omarchy (detected by
  `~/.local/state/omarchy/current/theme/colors.toml`), the default theme
  follows the current Omarchy theme. Its palette (`accent`, `background`,
  `dark_background`, `foreground`, `selection`, `muted`, the ANSI colors,
  `mode`) maps to egui `Visuals`.
- The GUI watches the theme directory with inotify (`notify`) and
  re-themes live when the user switches Omarchy themes.
- **Aleph neon** (near-black, neon cyan/magenta, monospace) is the
  fallback off Omarchy, and can be selected anywhere.
- The scanline overlay is an independent toggle, on by default, and
  disabled automatically when reduced motion is requested.
- Section headers may use Gibson vocabulary. Buttons and labels stay plain.

**Prompter (`aleph-gui prompt`)**

- Fixed-size windows with app_id `aleph-prompt`.
- Screens:
  - the FIDO2 sequence (insert → PIN → touch)
  - login-password entry
  - confirmations: collection create/delete, and re-authentication for
    admin operations
  - rollback and replacement warnings (§4)
- The recovery key is never requested here, except inside the explicit
  "Recover…" flow.
- The package ships a Hyprland snippet (float, center, pin, focus) that
  setup offers to include.

**Manager (`aleph-gui`)**

- **Secrets:** a collection list, a searchable item list, and a detail
  pane (label, attributes, masked secret).
  - Revealing a secret requires re-authentication (a UX guard, §6).
  - Copying uses the Wayland clipboard with the MIME hint
    `x-kde-passwordManagerHint: secret`, so clipboard-history tools skip
    it, and clears the clipboard after 30 s.
  - Items can be created, edited, and deleted.
- **Keyslots:** a list with stale and unknown markers, enroll and remove
  wizards, and recovery-key reissue.
- **Settings:** lock policy, theme and scanlines, and prompt timeouts.
- **Import and export**, and **Recover…**.
- A `.desktop` entry makes it available in the Omarchy launcher, using the
  icons in `assets/icons/` (§8).

## 8. Packaging and distribution

- **Repo:** one Cargo workspace (eight crates), plus `packaging/arch/`,
  `flake.nix`, `assets/`, and `docs/`. It targets current stable Rust.
- **Arch / Omarchy:** `PKGBUILD` in-repo, published to the AUR as
  `aleph-keyring` and `aleph-keyring-git`.
  - Depends on `tpm2-tss`, `libfido2`, `pam`, and `dbus`.
  - `provides=(org.freedesktop.secrets)`. It does not conflict with
    `gnome-keyring`; setup switches between them.
  - Installs:
    - binaries to `/usr/bin`, plus `aleph-tpmd` to `/usr/lib/aleph/`
    - `/usr/lib/security/pam_aleph.so`
    - `/etc/pam.d/aleph` (the substack; `backup=` in the PKGBUILD)
    - `/usr/lib/systemd/user/alephd.{service,socket}`
    - `/usr/lib/systemd/system/aleph-tpmd.{service,socket}`
    - the `.desktop` file and the icons:

      | Source | Installed as |
      |---|---|
      | `assets/icons/aleph.svg` | `hicolor/scalable/apps/aleph.svg` |
      | `assets/icons/aleph-24.svg` | `hicolor/24x24/apps/aleph.svg` |
      | `assets/icons/aleph-16.svg` | `hicolor/16x16/apps/aleph.svg` |
      | `assets/icons/aleph-symbolic.svg` | `hicolor/symbolic/apps/aleph-symbolic.svg` |

    - `/usr/share/aleph/hypr/aleph.conf`
  - A post-install hook enables `aleph-tpmd.socket`.
- **NixOS:** the flake exposes a package (built with `crane`) and a NixOS
  module `services.aleph`. The module:
  - installs the package, the user units, and `aleph-tpmd` as a system
    service
  - enables `security.tpm2`
  - adds `pam_aleph` via `security.pam.services.<name>.rules` for the
    display manager, the lock screen, and `passwd`
  - asserts `services.gnome.gnome-keyring.enable = false`

  On NixOS, `aleph setup` detects the read-only `/etc/pam.d`, skips the
  system changes, and prints the module configuration instead. Keyslots,
  the recovery key, and import work as on Arch.
- **CI (GitHub Actions):**
  - `cargo fmt --check`, `clippy -D warnings`, and the tests (including
    `swtpm`)
  - `cargo deny`
  - `nix flake check`
  - a `PKGBUILD` build in an Arch container

## 9. Testing

- **aleph-core:**
  - unit tests and `proptest` properties: round-trip; any flipped bit →
    error (exhaustive); a keyslot moved to another position fails to
    unwrap; header rollback rejected
  - golden vault files per format version, which must open forever
  - fast test-only Argon2 parameters, plus known-answer tests for the
    production parameters
  - X-Wing known-answer tests from the specification's test vectors
  - rotation revokes: a removed slot's KEK cannot open any later file
  - unknown slot types are preserved byte-for-byte
  - high-water mark: rollback and replacement are detected
- **Fuzzing (`cargo-fuzz`):** the vault/CBOR parser, `aleph-tpm-proto`
  framing, and Secret Service session decoding.
- **TPM (`aleph-tpmd`):** runs against `swtpm` in CI. Tests cover:
  - seal and unseal
  - wrong auth
  - lockout
  - uid isolation: another uid's blob refuses to unseal
  - SRK Name mismatch: a substituted parent is refused
  - rate limiting
  - handle hygiene
  - a password change produces a new object, and the old blob plus the old
    password no longer opens the vault, because MK rotated
- **FIDO2:** a mock `Authenticator`, including multiple devices,
  preflight selection, and `credProtect`/UV defaults. A manual checklist
  with a real key (`docs/testing.md`) is run before each release.
- **Daemon:** a private `dbus-daemon` running `alephd` with a temporary
  vault and `swtpm`.
  - Conformance is checked with `secret-tool` and Python `secretstorage`.
  - Locked search returns the locked placeholder and `IsLocked`, never
    empty.
  - Lock tests inject `PrepareForSleep` and `Lock`, then assert that keys
    are zeroized and the inhibitor has been released.
- **PAM and setup:** `pamtester` in an Arch container against copies of
  Omarchy's `sddm`, `omarchy-lock-password`, and `passwd`, covering:
  - a wrong password never reaches `pam_aleph`
  - a right one does, after dropping to the user's uid
  - SSH (`system-remote-login`) never reaches aleph
  - `setup` followed by `--revert` leaves `/etc/pam.d` byte-identical and
    gnome-keyring holding every item
- **GUI:** `egui_kittest` snapshots of every prompter screen in both
  themes, and `colors.toml` parsing tests.
- **Before 1.0:** a written threat model and an external security review
  of `aleph-core`, `aleph-tpmd`, `aleph-unlock`, and `pam_aleph`.

## 10. V2 roadmap

- **PCR/Secure Boot binding** with signed policies (`PolicyAuthorize`,
  systemd-pcrlock), only alongside custom Secure Boot keys.
- **TPM-PIN unlock** as a separate method.
- **Passphrase recovery** as an alternative to the recovery key.
- **TPM NV counter** for the high-water mark (§4).
- **Portal backend:** implement `org.freedesktop.impl.portal.Secret` for
  Flatpak apps.
- **Privilege separation:** move `KeyHandle` out of the daemon. This
  protects MK only (§3).
- **SSH:** store SSH key passphrases and unlock keys into OpenSSH's
  `ssh-agent`.
- **GPG:** a pinentry that retrieves passphrases from aleph.
- **Offline import** of gnome-keyring `login.keyring` files.
- **Waybar indicator** showing lock state.
- **Per-application access control.**
- **Home Manager module.**
- **Vault sharing/export** to another person's X-Wing public key.
- Upstreaming aleph as an option in Omarchy's installer.

## 11. Open items to verify during planning

- **X-Wing implementation:** the `x-wing` crate (0.1) tracks
  `draft-connolly-cfrg-xwing-kem-06`. Plan 1b either adopts it, if it
  matches the published test vectors, or implements the combiner directly
  over `ml-kem` and `x25519-dalek`, pinned by those known-answer tests.
- **`oo7`/`oo7-daemon`:** check its maturity before Plan 3. It could host
  the Secret Service server instead of writing one from scratch.
- **Persistent SRK:** check how common `0x81000001` is on Omarchy installs
  where `systemd-cryptenroll --tpm2` has been used (systemd creates it),
  and how often `ownerAuth` is set. Together these decide how often the
  AES-128 fallback is used.
- **Locked search:** verify how clients react to `IsLocked` (§4) before
  Plan 3 fixes the behaviour.

**Resolved:**
- FIDO2 bindings: `fido2-rs` (Plan 2).
- The Omarchy PAM stack: §6, verified on 2026-09-26.
