# aleph — design spec

- **Date:** 2026-09-26 (revision 2, after `docs/reviews/2026-09-26-aleph-design-review.md`)
- **Status:** Draft, awaiting review
- **License:** Apache-2.0

> *Aleph*: in Gibson's *Mona Lisa Overdrive*, a biochip holding an entire
> world, sealed away. The crate is published as `aleph-keyring` (the `aleph`
> name on crates.io is held by a placeholder); the project is `aleph`, and
> its command-line client is `alephctl` (texlive-bin already installs
> `/usr/bin/aleph`, the TeX engine).

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
2. On Omarchy with **password login**, after `alephctl setup` and one
   re-login, the vault unlocks at login with no extra interaction (TPM +
   login password). With **autologin** there is no password at login, so
   the vault stays locked until first use and then prompts for a FIDO2
   touch or the login password.
3. Users can choose FIDO2 as their unlock method instead of TPM + password.
4. Existing gnome-keyring secrets are migrated during setup.
5. A vault can be restored on a new machine from a backup file plus the
   recovery key alone.
6. `alephctl setup --revert` restores gnome-keyring, with every item that was
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
| **A copy of the vault file only** (a backup, a sync peer, a stolen disk image after LUKS) | Nothing, as long as the recovery key has not also leaked. Hardware slots are useless without this machine's TPM or the enrolled FIDO2 key. The login-password slot, which exists only on machines without a TPM, is left out of `alephctl backup` copies. Generic backups of the live file do contain it, and `alephctl backup` warns about this (§7). |
| **The vault file and this machine, powered off** (LUKS unlocked by some other means, or a pre-boot evil maid) | TPM slots: security reduces to the strength of the login password, unless the TPM's `lockoutAuth` is set. With an empty `lockoutAuth`, which is the Linux default, anyone with raw TPM access can reset dictionary-attack protection and guess at about one TPM round-trip per guess. `alephctl setup` reports whether `lockoutAuth` is set and what the lockout parameters are (§5). FIDO2 slots: the attacker also needs the key and its PIN (PIN/UV is the default, §5). |
| **This machine while suspended** (LUKS key and aleph MK in RAM) | aleph locks and zeroizes MK before suspend, holding a logind delay inhibitor until that is done (§6). Secrets that clients have already fetched (browser safe-storage keys, NetworkManager, cached git credentials) are out of aleph's reach. The attacker then holds the file and the machine, and the row above applies. |
| **A same-user process, briefly** (malware that runs once) | While the vault is unlocked it can read every secret, as with gnome-keyring. Enrolling a new slot, changing configuration, or removing a slot requires re-authentication, so the process cannot turn brief access into permanent access (§6). Removing a slot rotates MK, which revokes any keyslot the process added (§4). |
| **A different local user** | No secrets. The TPM helper binds sealed objects to the caller's uid (§5), and the vault file is mode `0600`. By guessing wrong passwords from two or more uids they can spend the helper's share of the TPM's failure budget and keep TPM unlock unavailable to everyone for as long as they keep guessing; FIDO2, recovery, and password fallback still work. They cannot drive the TPM into lockout, which would also block TPM disk unlock and survive reboot (§5, rate limiting). |

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
| `aleph-prompt-proto` | lib | The prompter protocol (newline-delimited JSON) shared by `alephd`, the CLI's terminal prompter, and `aleph-gui`. | `serde`, `zeroize` |
| `aleph-pam-proto` | lib | The `pam.sock` protocol between `pam_aleph` and `alephd`: length-prefixed binary frames, strict decoding, a reply check that does not allocate. | `zeroize` |
| `aleph-daemon` (bin `alephd`) | bin | Secret Service and admin D-Bus interfaces, PAM socket, lock policy, prompter orchestration. | `aleph-core`, `aleph-unlock`, `aleph-prompt-proto`, `aleph-pam-proto`, `zbus`, `tokio`, `tracing`, `tracing-journald`, libpam |
| `pam_aleph` | cdylib | PAM module: forwards passwords to `alephd` after dropping to the user's uid. Minimal, no async runtime. | `aleph-pam-proto`, PAM FFI, `libc` |
| `aleph-cli` (bin `alephctl`) | bin | CLI. | `aleph-prompt-proto`, `zbus`, `clap` |
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
  problem and offers `alephctl restore --from-bak`.
- A file that a restore or `--from-bak` replaces is kept as
  `vault.aleph.replaced-<time>` (or `.corrupt-<time>` if it could not be
  read), never deleted. It is linked under that name before the write,
  so a crash in between leaves it in place as `vault.aleph`. `.bak` is
  kept the same way (`vault.aleph.bak-<time>`) before every custody
  write, since the write replaces it and it may be the only good copy.
  Kept files still open with the old recovery key and the old unlock
  methods; `alephctl` names them and says to delete them once the keyring
  has been checked.

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
  reports this in the prompter and in `alephctl status`, and refuses to write
  until the user confirms, either with `alephctl restore --accept-rollback`
  or by accepting it in the GUI.
- **Same `generation` but a different `mk_id`:** the file has been
  replaced. Same handling.
- **Higher `generation` with a different `mk_id`:** MK changed somewhere
  other than this daemon, or someone holding an old MK is replaying it
  under a forged generation (`Rekeyed`). Same handling.

`alephd` also records the ID of the vault this machine uses
(`$XDG_STATE_HOME/aleph/vault-id`, written at create and restore, or at
the first unlock if missing). A vault with a different ID at the path is
not trusted, with the same handling, even with no mark for its ID. (A
crash between a restore's write and recording its ID makes the next
unlock report a different vault; `alephctl restore --accept-rollback`
settles it.)

A restore or an acceptance writes the vault at generation
`max(recorded, found) + 1`, so the mark is never lowered and every older
copy stays detectable.

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
- **on `alephctl restore`**
- **when the login password changes** (together with a fresh TPM seal, §5)
- **on `alephctl keyslot rotate-master`**

Re-wrapping needs a KEK for every slot. The daemon never keeps
passwords, so the KEKs come from these sources (each is checked to
unwrap MK before it counts):

- **The recovery slot:** re-wrapped to its public key, with no secret
  needed.
- **The TPM and login-password slots:** unsealed or derived with the login
  password. The password comes from the re-authentication that every
  rotating operation requires (§6). It is zeroized once the rotation
  completes. (A password change replaces these slots instead: §5.)
- **Each FIDO2 slot:** needs that key's touch. The prompter walks through
  them in turn.

A slot that cannot be presented is removed, after the user confirms: a
FIDO2 key that is not presented, a TPM or login-password slot that
rejects the password, or a stale TPM slot (which is not tried again). A
TPM refusal that says nothing about the slot (`Busy`, `RateLimited`,
`Exhausted`, helper unavailable) stops the rotation instead. TPM slots
are only ever offered a password PAM accepted, newest slot first. A
rotation never leaves a slot wrapping the old MK, and never leaves only
the recovery slot. Reissuing the recovery key does everything that can
fail before it shows the new key.

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

- **While locked, a search returns a placeholder.** `SearchItems` puts
  one placeholder item (`/org/freedesktop/secrets/search/<n>`, always
  `Locked`) in its `locked` list, and `Collection.SearchItems` returns it.
  libsecret then calls `Unlock()` on it, and the prompt's result lists the
  items the search really finds once the vault is open. The first design,
  answering `IsLocked`, was tested against libsecret 0.21.7 in Plan 3:
  `secret-tool lookup` reported an error and never unlocked, which a
  client like Chromium could treat as "no key".
- `GetSecrets`, `Item.GetSecret`, and every other read of the body return
  `org.freedesktop.Secret.Error.IsLocked` while the vault is locked.
- While locked, only the `default` alias exists, as a locked collection
  (collection names are encrypted too). `ReadAlias("default")` returns
  it; libsecret stores to it after unlocking it. Item and collection
  objects exist only while unlocked: a client holding an item path across
  a lock gets `UnknownObject`, and searches again.
- A placeholder's query is captured when `Unlock` is called, so the
  answer survives the placeholder being cleared. A `Lock` while already
  locked changes nothing.
- No method call ever blocks waiting for the user. `Unlock()` returns a
  prompt with no reply timeout. If no prompter can start (no graphical
  session), or its conversation ends any way but the user's Cancel (the
  prompter crashed or could not open its window, a question timed out; the typed
  attempts ran out; the machine went to sleep), the prompt is not
  dismissed (only Cancel dismisses it): it waits until the vault is
  unlocked some other way (`alephctl unlock`, PAM), then completes. Every
  prompt a client may hold may wait (16), and 128 in all; a prompt starts
  once; while one unlock conversation runs, other unlock prompts wait for
  it instead of opening more prompter windows (if it is cancelled, they
  keep waiting for a later unlock). A client may hold 16 prompts.
- **Sessions outlive locks.** A session holds only its transport key, and
  nothing is readable through it while locked; libsecret keeps one session
  for the life of each process, so closing sessions at lock would break
  every long-lived client at each screen lock. A session is freed on
  `Close`, when its client disconnects, or at exit; a client may hold 32.
  A client's prompts are freed when it disconnects too.
- A dismissed prompt carries an empty value of the type a completed one
  would (`ao` for an unlock). libsecret checks the type even on
  dismissal, and hangs on a mismatch.
- Verified with `secret-tool` on a private bus (Plan 3 tests): store,
  lookup, search, and clear; a locked lookup prompts once and returns the
  secret; with no prompter it waits for an unlock elsewhere; cancelling
  ends it without a secret. Chromium's safe-storage lookup and
  NetworkManager are on the manual checklist (`docs/testing.md`).

### Memory hygiene

What is guaranteed:

- MK lives in its own page. The page is `mlock`ed when permitted (best
  effort; `alephctl status` reports whether it succeeded), marked
  `MADV_DONTDUMP` and `MADV_WIPEONFORK`, and zeroized on drop.
- `alephd` calls `prctl(PR_SET_DUMPABLE, 0)` at startup.
- The body is encoded into an exactly sized buffer that is zeroized after
  use, and decoded without intermediate copies. Plaintext secrets
  (`SecretBytes`) are zeroized on drop.
- Children are started only via `posix_spawn`/`exec`
  (`std::process::Command`), never a bare `fork`. A prompter is the one
  child that inherits a descriptor: it is started with `fork`/`exec`, and
  between the two the child only clears close-on-exec on its socket, so
  the socket is never inheritable in the daemon itself (where another
  thread's child could pick it up). One exception is outside
  aleph's code: checking a typed password, libpam's `pam_unix` forks and
  execs `unix_chkpwd`. MK's page is `MADV_WIPEONFORK`, so the child never
  sees it; the decrypted body is shared copy-on-write until the exec.
- Locking zeroizes MK, derived keys, and the decrypted body. Secret
  Service sessions stay open (§4 "Locked search"): they hold only
  transport keys.

What is not guaranteed: labels and attributes are ordinary strings and are
not zeroized. zbus, libsecret, and the GUI make their own copies of
secrets in transit. Prompter answers are read into a fixed-size buffer
that is wiped as it is consumed, but when a password or PIN contains a
JSON escape, serde_json decodes it through a scratch buffer that is freed
without being zeroized. `mlock` does not keep pages out of a hibernation image
(§6 locks before hibernate). Swap should be encrypted or zram-only, and
`alephctl setup` warns if it is neither.

## 5. Unlock methods

### TPM, via `aleph-tpmd`

**The helper.**
- **Service:** `aleph-tpmd` is a socket-activated system service
  (`aleph-tpmd.socket` → `/run/aleph/tpm.sock`, mode `0666`). Access
  control is by peer uid, not by file mode, and only login uids
  (`UID_MIN`–`UID_MAX` from `/etc/login.defs`) are served; others get
  `NotPermitted` before the helper reads their request. systemd-homed's
  range (60001–60513) is served too.
- **Connections:** each connection has its own thread (at most 64) and one
  request, which must arrive in full within 2 seconds however the client
  paces it. A uid may have one connection in progress; a second gets
  `Busy` at once, as does any connection beyond 64, and the client
  retries `Busy` for a few seconds. Only TPM access itself is serialized.
- **Sandboxing:** it runs with `DynamicUser=yes` and
  `SupplementaryGroups=tss`. Only this service can open `/dev/tpmrm0`, and
  users are not in `tss`. It is sandboxed: `ProtectSystem=strict`,
  `PrivateNetwork=yes`, `DeviceAllow=/dev/tpmrm0 rw`, `NoNewPrivileges=yes`,
  an empty `CapabilityBoundingSet`, and so on.
- **Protocol:** length-prefixed CBOR frames of at most 64 KiB
  (`aleph-tpm-proto`), decoded strictly (unknown fields are errors):
  - `Seal { secret }` → `Sealed { object: { public, private, auth_salt, srk_name }, kek }`
    (the helper generates the KEK)
  - `Unseal { object, secret }` → `Unsealed { kek }`
  - `Status {}` → `{ parent, owner_auth_set, lockout_auth_set, in_lockout, max_tries, recovery_time, lockout_recovery, failed_tries }`
  - any request → `Failed(AuthFailed | Lockout | RateLimited | Busy | Exhausted | NotPermitted | WrongUser | ParentMismatch | NoParent | Malformed | Tpm)`

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
    P-256 with an AES-256-CFB symmetric parent, under the owner hierarchy,
    with `noDA` (like the TCG SRK: using the parent needs no secret). This
    keeps the post-quantum margin of §2.
  - If `ownerAuth` is set, which makes that impossible, it falls back to
    the persistent TCG standard SRK at `0x81000001`. That key uses
    AES-128-CFB, and `alephctl status` reports it.
  - If neither is possible, `Status` says so and TPM enrollment is refused.
  - A primary created from a fixed template on a given TPM always has the
    same Name. Whichever parent is used, its Name is recorded in the slot
    (`srk_name`). To unseal, the helper uses whichever available parent has
    that Name, so slots survive `ownerAuth` being set or cleared later as
    long as their parent still exists. The Name compared is the one ESYS
    holds for the handle (`Esys_TR_GetName`), i.e. the key that will salt
    the session. No match is an error (`ParentMismatch`): a different TPM,
    or an active interposer substituting a key.
- **Sessions:** HMAC sessions salted to the verified parent, with
  AES-256-CFB parameter encryption in both directions, whichever parent is
  used. (The SRK fallback's AES-128 affects only how the TPM protects
  child blobs under that parent, not the session.)
- **Sealed object:** a keyed hash with `fixedTPM`, `fixedParent`, and
  `userWithAuth`, authorized by its auth value. Dictionary-attack
  protection stays on. There are no PCR policies in v1.
- **Rate limiting.** The TPM's failure counter is TPM-wide, shared with
  `systemd-cryptenroll` TPM2+PIN disk unlock, and a lockout survives
  reboot. So the helper budgets it in two layers:
  - **Global reserve:** once the TPM's failure count reaches
    `max_tries − max(1, ⌊max_tries / 2⌋)`, the helper refuses every
    unseal with `Exhausted` without asking the TPM. aleph can therefore
    never cause a TPM lockout, and `max(1, ⌊max_tries / 2⌋)` tries stay
    for disk unlock. The count falls by one per `recovery_time`. A TPM
    whose threshold is 0 (`max_tries` ≤ 1) refuses TPM enrollment with
    `Exhausted`. A `recovery_time` of 0 turns the TPM's counting off, and
    with it the reserve.
  - **Per uid:** at most 2 failed unseals per uid per 2 × `recovery_time`
    (at least 60 s), then `RateLimited`. One uid guessing without pause
    thus adds failures no faster than the TPM forgets them; it takes
    several uids to hold the reserve at its limit.
  - **A typed password is checked with PAM first.** Before a password
    typed into a prompt reaches the TPM, `alephd` checks it with the PAM
    service `aleph-check` (`pam_unix` only, no faillock), so a typo never
    spends the TPM's budget: on a TPM with a 7200 s recovery time, two
    typos would otherwise block TPM unlock for hours. At most 5 wrong
    typed passwords are accepted per minute. If PAM cannot check at all
    (no `/etc/pam.d/aleph-check`, or an account `pam_unix` cannot verify),
    the TPM slots are skipped rather than risked, while login-password
    slots are still tried; TPM slots therefore need `pam_unix` accounts.
    Passwords from `pam_aleph` were accepted by the login stack, but are
    checked too whenever PAM can check, so a wrong one sent to `pam.sock`
    by any same-user process never reaches the TPM or marks a slot stale.
    Only when PAM cannot check is the login stack trusted.
  - **TPM slots are tried newest first.** Once one rejects a password PAM
    accepted, it and every older TPM slot are marked stale without being
    tried, so a changed password costs one failed attempt, not one per
    slot.
  - After an `AuthFailed` or `WrongUser` failure, the daemon marks the
    slot `stale` and stops trying it automatically until the user
    re-enrolls it or explicitly retries it, so an outdated password does
    not keep consuming attempts. No other failure (`Lockout`,
    `RateLimited`, `Busy`, `Exhausted`, `NotPermitted`, `ParentMismatch`,
    `NoParent`, `Malformed`, `Tpm`) marks the slot stale; the prompter
    reports them.
- **`Status` and setup:**
  - `alephctl setup` displays `lockout_auth_set`, `max_tries`, and the
    recovery times.
  - If `lockoutAuth` is empty, setup explains the consequence (§2) and
    offers to set it to a random value that is printed for the user to
    record. This is opt-in, never the default, because losing it means the
    lockout counter can only be reset by waiting.
- **Password change:** `pam_aleph` passes the old and new passwords from
  `passwd`. It runs even when `pam_unix` failed to make the change, so
  `alephd` acts only on a new password PAM accepts (or when PAM cannot
  check). It then replaces every password slot: one **new** TPM slot
  sealed under the new password (with a fresh KEK) replaces the TPM slots,
  and one new login-password slot replaces any login-password slot.
  - If every other slot is a recovery slot, MK rotates, so the old
    password and old blobs open nothing written from then on.
  - FIDO2 slots need a touch, which `passwd` cannot give. In that case
    the old slots are removed keeping MK, and a **pending rotation** is
    recorded. `alephctl status` and every unlock say so until a rotation is
    run (`alephctl keyslot rotate-master`, which needs the keys). Until then,
    an old copy of the file, plus the old password, plus this machine's
    TPM, still yields an MK that opens newer files.
  - A locked vault is never unlocked for this: a copy is opened with the
    old password, changed, checked against the high-water mark, and
    written.

  There is no `ObjectChangeAuth`, because the old private blob would stay
  loadable with the old password on this TPM indefinitely.
- **Out-of-band change:** if the password was changed without `pam_aleph`,
  the next typed password PAM accepts opens no TPM slot (every one is
  stale, or the newest rejects it with `AuthFailed`). The prompter then
  asks for the previous password (`OldPassword`).
  - It is tried only on the newest TPM slot, straight at the TPM (PAM no
    longer knows it), at most twice per conversation, each counted by the
    typing limit.
  - Declining the question returns to the choice of method, where a FIDO2
    touch also works.
  - Either way, once the vault is open the password slots are replaced
    under the current password, as for a password change.
  - A `WrongUser` refusal does not lead to the question, since the
    previous password cannot fix it.

### FIDO2 (libfido2 via `fido2-rs`)

- **Enrollment:**
  - `makeCredential` with the `hmac-secret` extension, non-resident, RP ID
    `"aleph"`, `credProtect = 2` ("UV optional with credential ID"). Level 2
    rather than 3: a level-3 credential is invisible to the no-touch
    preflight below unless UV happens first, so choosing among several
    keys would burn PIN retries on the wrong ones (`systemd-cryptenroll`
    uses level 2 for the same reason). The protection level 3 would add is
    already provided: aleph requires UV/PIN at every unlock of a PIN/UV
    slot, and a CTAP 2.1 key's `hmac-secret` without UV is a different
    secret (CredRandomWithUV vs. CredRandomWithoutUV), so a touch alone
    derives the wrong KEK.
  - **CTAP 2.0 keys** have a single CredRandom: the same output with or
    without UV, so a PIN would not protect the slot. PIN/UV enrollment
    therefore takes a third touch, evaluating the new credential once
    without verification, and refuses the key if the outputs match
    (touch-only enrollment remains possible, with its warning).
  - defaults to requiring user verification: the PIN, or on-device UV
    where supported. Touch-only is an explicit opt-in
    (`--touch-only`, with a warning). On a key with a PIN, touch-only
    enrollment still passes the PIN to `makeCredential`, which many keys
    require, but the slot's assertions never use it.
  - the key's `getInfo` must list `hmac-secret`, or enrollment is refused
  - exactly one key must be plugged in, counting keys that cannot be
    opened (a browser may hold one), so which key is enrolled is never
    ambiguous
- **Unlock:**
  - **Device selection:** each plugged-in key is preflighted with
    `getAssertion(up = false)`, without a PIN, on the slot's credential ID
    to find the one that holds it, then only that key is asked for a PIN
    and a touch. This holds for a single key too, so the slot of an absent
    backup key never spends the plugged key's PIN retries. A key whose
    preflight errors is skipped (or, if it is the only key, asked
    directly); if no key matches, the first such error is reported. A
    preflight "yes" is checked: a key that names a different credential
    ID is not it, and a key that then cannot produce the secret
    (`NO_CREDENTIALS`) does not end the search.
  - **What level 2 exposes:** anyone holding the key, without its PIN, can
    learn whether it holds a given credential ID and obtain its non-UV
    `hmac-secret` output, which opens nothing enrolled with PIN/UV.
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
  - `alephctl restore` for a new machine or a broken vault
  - "Recover…" in the GUI

  Keeping the root credential off routine prompts makes fake prompts less
  useful for phishing.
- **After recovery:**
  - MK rotates
  - `alephctl` offers to issue a new recovery key, in case the old one was
    exposed while it was typed

A backup is the vault file plus the recovery key. Losing both loses the
data.

### Unlock order

| Trigger | Slots tried |
|---|---|
| Password login or lock-screen unlock (password from PAM) | `tpm`, then `login-password` (no-TPM machines). Stale slots are skipped. |
| First use: locked vault, autologin, FIDO2 users | The prompter offers every enrolled method: a FIDO2 touch, or the login password (which unlocks `tpm` or `login-password`). |
| Recovery | Only via `alephctl restore` or "Recover…" |

## 6. Daemon (`alephd`)

### Startup and switchover from gnome-keyring

- Runs as a systemd user service `alephd.service` (`BusName=io.aleph.Keyring`),
  with `alephd.socket` owning `$XDG_RUNTIME_DIR/aleph/pam.sock` (mode
  `0600`). It is started by D-Bus activation for `org.freedesktop.secrets`
  or `io.aleph.Keyring`, or by socket activation from PAM.
- **The Secret Service name is queued for, never taken** (DECISIONS.md
  E1): alephd owns `io.aleph.Keyring` and requests
  `org.freedesktop.secrets` without `ReplaceExisting` or
  `AllowReplacement`, so while gnome-keyring runs alephd waits in the
  queue, and the bus hands the name over the moment gnome-keyring lets go
  (the name is never unowned). alephd claims it only while setup's
  activation file exists (setup asks the running alephd to claim it once
  it has written that file): before setup, and after a revert, the Secret
  Service stays gnome-keyring's even if `pam.sock` starts alephd.
  `alephctl status` says who serves it. After setup switched over, a queued
  alephd logs a warning.
- `alephctl setup` (Arch/Omarchy), each step checking the real state, so a
  re-run does only what is still undone (E10):
  1. reports the TPM (§5) and detects SDDM autologin (E5: advisory; it
     picks the default unlock method and the summary)
  2. creates the vault (§7), if there is none
  3. imports gnome-keyring's items while it still serves the Secret
     Service, and keeps following it until the name changes hands (E1,
     E2)
  4. switches over, user-level only (E9): D-Bus activation files in
     `$XDG_DATA_HOME/dbus-1/services/` (the Secret Service name starts
     alephd; `org.gnome.keyring` and `org.freedesktop.impl.portal.Secret`
     start nothing), a bus `ReloadConfig`, gnome-keyring's user units
     recorded (once), masked, and stopped, then the name's owner checked.
     gnome-keyring's pkcs11 component goes away with it.
  5. installs Omarchy's lock hook (G1), and offers to set the TPM's
     lockoutAuth (D9)
  6. last and optional, the root side through sudo: `sudo alephctl system
     apply --user <you>` (below); declined or failed, setup says how to
     run it later, and that until then logging in does not unlock the
     keyring and the login's PAM service can still start gnome-keyring

  A gnome-keyring collection that stayed locked (its unlock dismissed)
  stops setup before step 4, unless the user says to go on: its items
  would be out of reach once aleph takes over.
- `alephctl setup --revert` (E3), refused if gnome-keyring is not installed:
  1. lists items imported from gnome-keyring and deleted in aleph since,
     offering to delete them there too
  2. with the login password, alephd pauses writes and runs its own
     gnome-keyring on a private bus over the keyring files (after checking
     that none serves the session), writes every item missing there or
     different (collections it lacks go into its default collection), and
     reads each back on a fresh connection
  3. only then: the activation files removed (if still aleph's) and the
     bus reloaded; gnome-keyring's units unmasked and restored as
     recorded; the Omarchy hook removed; alephd lets go of the name, which
     the bus hands to gnome-keyring
  4. last, `sudo alephctl system revert`

  If the export fails, nothing changes and writes resume. A revert that
  stops after step 3's switch back resumes at the release on a re-run.
  Items deleted in aleph since the import are deleted in gnome-keyring
  only if aleph holds no item with the same label and attributes (one
  deleted and stored again). The aleph vault is left in place.

### PAM integration

Verified against a stock Omarchy install on 2026-09-26.

- **The lines.** aleph's lines go straight into each service, each with
  a `-` prefix, so a missing module is silently skipped (an `include` of a
  missing substack file could make the whole service fail; DECISIONS.md
  E4):

  ```
  -auth      optional  pam_aleph.so
  -session   optional  pam_aleph.so
  -password  optional  pam_aleph.so
  ```

- **Which services get them**, edited by `sudo alephctl system apply` (E4),
  each keeping an `.aleph-orig` backup:

  | Service | Change |
  |---|---|
  | `/etc/pam.d/sddm` (graphical login) | Remove the `pam_gnome_keyring` lines; add `-auth optional pam_aleph.so` after `auth include system-login`, and `-session optional pam_aleph.so` after `session include system-login`. |
  | `/etc/pam.d/omarchy-lock-password` (hyprlock) | Add `-auth optional pam_aleph.so` at the very end, after `pam_faillock authsucc`, so it only ever sees a password `pam_unix` has accepted. |
  | `/etc/pam.d/passwd` | Add `-password optional pam_aleph.so` after `password include system-auth`, so that `passwd` changes reach aleph (`pam_gnome_keyring` stays, so a later revert still unlocks gnome-keyring at login). |
  | `system-login`, `system-auth`, `system-local-login`, `system-remote-login`, `login` | **Never edited.** An SSH login must not unlock the desktop vault, and a TTY login stays the escape hatch. |
  | `sddm-autologin` | Only its `pam_gnome_keyring` lines are removed (they would start gnome-keyring directly); nothing is added: it has no password, so first-use mode applies. |

- **Placement:** in every service, `pam_aleph` comes after the
  `pam_unix`/`pam_faillock` success path. A mistyped password never
  reaches aleph, and never costs a TPM dictionary-attack attempt.
- **Handing over the password:**
  - `pam_aleph` stores the password with `pam_set_data`, using a cleanup
    that zeroizes it, when it cannot deliver it at once.
  - To deliver it, the module forks a child that drops to the target
    user's uid and gid (`setgroups`/`setgid`/`setuid`, only when running
    as root, as `pam_gnome_keyring` does) and connects to
    `/run/user/<uid>/aleph/pam.sock`.
  - The host may be multithreaded, so the child calls only
    async-signal-safe functions on data prepared before the fork. It
    closes every descriptor it inherited but its report pipe, sends with
    `MSG_NOSIGNAL`, and has an `alarm` backstop (with `SIGALRM` reset to
    its default and unblocked).
  - The child reports its result as one byte on a pipe. The parent waits
    on the pipe with a 5-second limit, kills the child through a pidfd,
    and reaps it through the pidfd. The host's `SIGCHLD` handling is never
    touched.
  - `alephd` checks `SO_PEERCRED` against its own uid.
  - The wire format is `aleph-pam-proto` (§3). A `socket=<path>` module
    argument replaces the socket path; it exists for tests.
- **When it sends:**
  - `auth` sends at once if `pam.sock` exists (the lock screen, or a
    second login; on a second login the vault then unlocks before the
    `account` and `session` stacks run, which is harmless: it is the
    user's own vault and the password was right). Otherwise, or if that
    delivery fails, it keeps the password for `session` open, once the
    user's systemd instance is up.
  - `passwd` sends the old and new passwords in the update phase, only
    when both are known (root setting another user's password supplies no
    old one, and nothing is sent).
  - It never prompts: without a password it does nothing.
- **Listening:** `alephd.socket` owns `pam.sock` (`FileDescriptorName=pam`);
  `alephd` takes that descriptor by name, or binds the socket itself when
  not socket-activated (never replacing a socket something still serves).
  A login password opens the vault at once, even while a prompter
  conversation is open, including a security key's PIN question (the
  hardware is not held while the prompter is asked). Whichever opens
  first is kept; an open that finishes after the vault was unlocked,
  written, and locked again reopens the current file rather than
  installing its older copy. A password change waits its turn, but a new
  password PAM rejects is refused before waiting, and when PAM cannot
  vouch for the new password the old one must open the vault file
  first.
- **Never blocks login:** every failure is logged and returns
  `PAM_IGNORE`.
- **Rate limiting:** `pam.sock` accepts at most 5 rejected passwords per
  minute, which bounds same-user guessing through the socket. Refusals
  that say nothing about the password (a busy or rate-limited TPM) do not
  count. Requests still being answered count too, so parallel connections
  cannot get past the limit, and at most 5 are in flight at once.

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

- On the session bus only: bus name `io.aleph.Keyring`, object
  `/io/aleph/Admin`.
- Methods: `Status` (JSON: vault present, locked, untrusted reason,
  whether MK is `mlock`ed, TPM usability, keyslots with stale marks),
  `Lock`, `Unlock`, `Create`, `EnrollTpm`, `EnrollFido2`,
  `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`, `RetryKeyslot`,
  `GetConfig`, `SetConfig`, `Backup`, `Recover`, `RestoreBackup`,
  `RestoreFromBak`, `AcceptRollback`, `ImportGnomeKeyring`,
  `RemovedSinceImport`, `ExportToGnomeKeyring`, `ReleaseSecretService`,
  `ThawWrites`. `Status` also names who owns `org.freedesktop.secrets`.
- **Methods that need the user take a prompter:** one end of a
  socketpair, passed as a Unix fd, speaking the prompter protocol. The
  CLI answers it in the terminal, `aleph-gui` in its windows. The call
  returns once the request is accepted; the outcome arrives on the
  prompter as `Done`, so no call waits for the user or runs into a bus
  reply timeout.
- A keyslot change that would leave only the recovery slot is refused:
  routine unlock would then be impossible.
- **Fresh re-authentication through the prompter** is required for every
  method that changes keyslots, configuration, or data custody:
  `Enroll*`, `RemoveKeyslot`, `RotateMaster`, `ReissueRecoveryKey`,
  `SetConfig`, `Backup`, `Restore`, and `Export*`. Re-authentication means
  proving an enrolled method: a FIDO2 touch, or the login password
  (checked with PAM, then through a TPM unseal or the login-password
  slot).
- **"Reveal" in the GUI** also re-authenticates. That is a UX guard, not
  security, because any same-user process can call `GetSecrets`. This is
  documented.

### Lock policy

Configured in `~/.config/aleph/config.toml`:

```toml
[lock]
on_suspend = true        # every sleep, suspend or hibernate: logind PrepareForSleep(true), with a delay inhibitor
on_screen_lock = true    # logind Session.Lock (hypridle → loginctl lock-session)
idle_timeout = 0         # seconds without secret access; 0 = disabled
# setting everything false/0 = lock only at logout
```

- **Suspend and hibernate:** `alephd` holds a logind `delay` inhibitor for
  `sleep` while running.
  1. On `PrepareForSleep(true)` it locks and zeroizes (if `on_suspend`).
  2. Then it releases the inhibitor.
  3. On resume it takes the inhibitor again.

  logind does not say whether a suspend or a hibernation is coming, and
  suspend-then-hibernate moves on to hibernating without another signal.
  So `on_suspend` covers both. With it off, the master key can reach a
  hibernation image, and `alephctl config set lock.on_suspend false` warns
  about this (swap must be encrypted, §4).
- **Screen lock:** logind's `Session.Lock` for a session of this user
  (`loginctl lock-session`, which hypridle sends), sent by logind itself
  (the sender is checked against the name's owner: any peer can send a
  directed signal). Omarchy's own lock (`omarchy-system-lock`, a Quickshell
  session lock, used by its idle service and key binding) does not tell
  logind. Setup installs an Omarchy hook,
  `~/.config/omarchy/hooks/lock.d/aleph` (running `alephctl lock`), which
  takes effect once Omarchy's lock runs `omarchy-hook lock` (proposed
  upstream; DECISIONS.md G1). Until then the vault locks on idle
  (`lock.idle_timeout`) and sleep, and `alephctl lock` can be bound next to
  the lock.
- **Idle:** no secret read or written for `idle_timeout` seconds.
- Without a system bus or logind, `alephd` runs without the sleep and
  screen-lock parts.

### Prompter orchestration

- For Secret Service prompts, `alephd` spawns `<prompt.program> prompt`
  (default `aleph-gui`) with one end of a socketpair as `ALEPH_PROMPT_FD`
  and exchanges newline-delimited JSON messages (`aleph-prompt-proto`).
  Admin methods use the caller's own prompter instead (above).
- **What the prompt shows:** the requesting operation and, where
  available, the calling process's name and pid, from D-Bus
  `GetConnectionUnixProcessID`. This is advisory, since it can be spoofed.
- **Where the prompt runs:** a Secret Service prompt runs only as a
  child of `alephd`. A window claiming `aleph-prompt` that `alephd` did
  not spawn gets nothing, because secrets only ever travel over a
  socketpair, never in D-Bus message bodies.
- **The display:** the prompter runs on the session's current Wayland
  display, read at each launch from the systemd user manager's
  environment (where the compositor exports it). alephd itself is often
  started before the compositor (by `pam_aleph` during login), so its own
  environment is used only when the manager cannot be asked
  (DECISIONS.md H2).
- With no Wayland display, Secret Service prompts wait (§4), and
  `alephctl unlock` unlocks in the terminal, in the style of
  `systemd-ask-password`. With `ALEPH_NO_TTY=1` its answers are lines of
  standard input (scripts, tests).
- The prompter settings are `prompt.program` and `prompt.timeout`
  (seconds before an unanswered question ends) in `config.toml`. The
  unlock window's choice of method has no timeout (DECISIONS.md H5): it
  waits for the person, who may be away, and closes when the vault is
  unlocked another way, when another operation (`alephctl`, `passwd`)
  needs to run, or when alephd stops.

### Logging

`tracing` to journald. Secret values, passwords, PINs, and key material
are never logged. This is enforced by the redacted `Debug`
implementations and a lint test.

## 7. Clients

### CLI (`alephctl`, clap)

```
alephctl setup [--revert]
alephctl status | lock | unlock
alephctl keyslot list
alephctl keyslot add tpm                      # TPM + login password
alephctl keyslot add fido2 [--touch-only]
alephctl keyslot remove <slot-id>             # rotates MK
alephctl keyslot rotate-master
alephctl keyslot retry <slot-id>              # try a stale slot again
alephctl recovery reissue                     # new recovery key; old one stops working
alephctl get attr=val…                        # secret-tool compatible semantics
alephctl search attr=val…
alephctl store --label L attr=val…            # secret read from stdin, never argv
alephctl delete attr=val…
alephctl ls [collection]
alephctl import gnome-keyring
sudo alephctl system apply --user <you> | verify --user <you> | revert
alephctl config get|set <key> [value]
alephctl backup [--force] <path>
alephctl restore [--from-bak | --accept-rollback] [<path>]
```

- Global flags: `--json`. Shell completions are generated for bash, zsh,
  and fish (`alephctl completions <shell>`). Keyslot ids may be given as a
  unique prefix, as `alephctl status` shows them.
- **`alephctl setup`** is an interactive wizard:
  1. TPM status (§5)
  2. unlock method: TPM + login password (the default when a TPM is
     usable) or FIDO2
  3. autologin detection
  4. the recovery key, shown once and confirmed
  5. live import from gnome-keyring
  6. system changes (sudo)

  Export to gnome-keyring happens only as part of `setup --revert`.
- **Import** reads every collection and item through the Secret Service
  API while gnome-keyring still owns the bus name, over an encrypted
  session (alephd reads them itself; secrets never pass through the CLI).
  That covers everything shown in Seahorse's Passwords view. It needs the
  vault unlocked; locked gnome-keyring collections ask through
  gnome-keyring's own prompt, and are skipped (with a message) if it is
  dismissed. It is idempotent and never overwrites (E2); what it added is
  recorded in `$XDG_STATE_HOME/aleph/imported.json` for revert.
- **`sudo alephctl system apply --user <you>`** edits the PAM services above
  as pure text transformations, atomically, refusing symlinks, files that
  are not regular, and files not owned by root (manual mode: it prints
  what to add; E6), then authenticates `<you>` through the edited
  lock-screen and login stacks with real Linux-PAM, the password asked
  once; a failure restores the originals at once. What it did is recorded
  in `/var/lib/aleph/manifest.json`, each entry saved before its file is
  replaced. The login password is asked before anything changes, and the
  check runs whenever anything is recorded (a re-run after an interrupted
  check too). `revert` restores each file byte for byte if it is still
  what `apply` wrote, else takes aleph's lines out if that applies
  cleanly, else leaves it (dropping its backup) and says what to remove.
  A backup without a manifest entry is rewritten from the file as it is,
  unless that file is already exactly what apply writes (a run cut short
  before its manifest): then the backup is the original, and is kept. It reads
  no user configuration or D-Bus, and warns if its own binary is not
  root-owned and root-only-writable. On NixOS it prints the configuration
  to add instead.
- **`alephctl backup <path>`** writes a re-headered copy containing **only
  the recovery slot**, with its MK wrap. It also warns that generic backups
  of `~/.local/share/aleph/` contain every slot, including
  `login-password` on machines without a TPM.
- **`alephctl backup <path>`** needs re-authentication. The CLI creates the
  file (new, mode `0600`, never following a symlink; with `--force`, a
  temporary file renamed over `<path>` once the backup is written) and
  hands the descriptor to `alephd`, which writes to it only if it is an
  empty regular file outside aleph's data and state directories; the
  daemon never opens a path it was given, and reads a restore file only
  if it is a regular file.
- **`alephctl restore`** goes through `alephd`. The daemon opens the backup
  (a descriptor, as above), or with no path the current vault (or `.bak`
  if the vault cannot be read), with the recovery key. It keeps only the
  recovery slot, enrolls one fresh unlock method for this machine,
  rotates MK, writes the result past every recorded generation (§4), and
  offers a new recovery key. A plain `restore` is refused while the
  vault is unlocked and trusted.
- **Proof.** "The vault this machine expects" means its recorded ID
  *and* master key, not behind the recorded generation: an ID alone is
  public, and an older copy may open with an old recovery key. Recovering
  that vault, as this machine last recorded it, needs only its recovery
  key. Anything else that replaces the vault (a backup, another vault, an
  older copy of this one, or one forged with its ID) needs proof, so a
  same-user process holding an old backup and its recovery key cannot
  swap it in: the recorded vault's method (re-authentication while it is
  unlocked and trusted, or opening the file there, which must turn out to
  be the recorded vault), or else the login password checked with PAM. A
  vault that fails authentication after its slot opens proves nothing
  (a forged one fails the same way). Only a machine that has never had a
  vault (no vault files, no records, and none seen since the daemon
  started) needs no proof.
- **Re-authentication** (for every operation that asks for it) proves
  only the unlocked vault: the file it opens must be that vault (same ID
  and master key, not behind it), so a file planted at the path proves
  nothing.
- An **older backup of the same vault** (older than the file there or
  than the generation recorded for it, even with the file gone) is
  restored only after a question naming both generations, saying that
  anything written since the backup is not in it, and naming a newer
  `.bak` (Enter says no).
- If a restore succeeds but the new recovery key cannot be installed
  (cancelled, or failed), the restore is still reported, with a note
  that the old key still works.
- **`alephctl restore --from-bak`** replaces the vault with `.bak`, opened
  with the normal methods, after a question naming its generation and
  the one this machine last recorded; a `.bak` that is not the recorded
  vault under its recorded master key, at most one write behind, also
  needs the login password. **`alephctl restore --accept-rollback`**
  accepts the unlocked, untrusted vault as current, after
  re-authentication, the login password (an untrusted vault is never the
  expected one, and an older copy may hold a since-removed key), and an
  explicit yes naming what is accepted.

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
  disabled automatically when reduced motion is requested (GNOME's
  `enable-animations` set to false, which also stops spinners and
  animations).
- The GUI's settings are in `~/.config/aleph/gui.toml`: `theme = "auto"`
  (Omarchy's where there is one, else Aleph neon) or `"neon"`, and
  `scanlines = true|false`.
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
  "Recover…" flow: asked for in any other conversation, the prompter
  refuses without showing a field.
- Text from other programs (collection labels, process names) gets no
  line breaks of its own and is cut short, so it can neither draw a fake
  prompt inside the real one nor push the buttons out of view.
- If no window can open, the prompter exits without answering, and the
  prompt waits (§4). When alephd ends the conversation, the window
  closes; a closing message stays up until closed, or for 20 seconds
  (6 for a note after a successful unlock).
  Keys arriving just as a screen appears are ignored, so text typed into
  another window never becomes an answer.
- The package ships a Hyprland window rule,
  `/usr/share/aleph/hyprland/aleph-prompt.lua` (float, center, pin, and
  keep the keyboard on the prompt while it is open), which setup offers
  to include from `~/.config/hypr/hyprland.lua` (through `pcall`, so an
  uninstalled aleph never breaks Hyprland's configuration); revert
  removes it.

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
    - `alephctl` and `aleph-gui` to `/usr/bin`; `alephd` and `aleph-tpmd`
      to `/usr/lib/aleph/`
    - `/usr/lib/security/pam_aleph.so`, and `/etc/pam.d/aleph-check`
    - `/usr/share/dbus-1/services/io.aleph.Keyring.service` (only that
      name: the Secret Service name's activation file is the user's,
      written by setup)
    - `/usr/lib/systemd/user/alephd.{service,socket}`
    - `/usr/lib/systemd/system/aleph-tpmd.{service,socket}`
    - the `.desktop` file and the icons:

      | Source | Installed as |
      |---|---|
      | `assets/icons/aleph.svg` | `hicolor/scalable/apps/aleph.svg` |
      | `assets/icons/aleph-24.svg` | `hicolor/24x24/apps/aleph.svg` |
      | `assets/icons/aleph-16.svg` | `hicolor/16x16/apps/aleph.svg` |
      | `assets/icons/aleph-symbolic.svg` | `hicolor/symbolic/apps/aleph-symbolic.svg` |

    - `/usr/share/aleph/hyprland/aleph-prompt.lua`
  - A post-install hook enables `aleph-tpmd.socket`, and `alephd.socket`
    for every user (`systemctl --global enable`). `packaging/install.sh`
    does the same from a release build, until there is a package.
- **NixOS:** the flake exposes a package (built with `crane`) and a NixOS
  module `services.aleph`. The module:
  - installs the package, the user units, and `aleph-tpmd` as a system
    service
  - enables `security.tpm2`
  - adds `pam_aleph` via `security.pam.services.<name>.rules` for the
    display manager, the lock screen, and `passwd`
  - asserts `services.gnome.gnome-keyring.enable = false`

  On NixOS, `alephctl setup` detects the read-only `/etc/pam.d`, skips the
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
  preflight selection, and PIN/UV defaults. A manual checklist
  with a real key (`docs/testing.md`) is run before each release.
- **Daemon:** a private `dbus-daemon` running `alephd` with a temporary
  vault and `swtpm`.
  - Conformance is checked with `secret-tool` and Python `secretstorage`.
  - Locked search returns the locked placeholder and `IsLocked`, never
    empty.
  - Lock tests inject `PrepareForSleep` and `Lock`, then assert that keys
    are zeroized and the inhibitor has been released.
- **PAM (Plan 4a, no root):**
  - the module logic, against a fake PAM handle
  - the forked delivery, against a real socket (including a host that
    ignores `SIGCHLD`)
  - real Linux-PAM loading the built module through `pam_start_confdir`,
    with `pam_exec expose_authtok` setting `PAM_AUTHTOK` from the test's
    conversation
  - `pam.sock` against the real daemon, including the module's delivery
    code end to end
- **PAM and setup (Plan 6, root container):** `pamtester` in an Arch
  container against copies of Omarchy's `sddm`, `omarchy-lock-password`,
  and `passwd`, covering the privilege drop and a `passwd` whose
  `pam_unix` update fails (nothing may change), and:
  - a wrong password never reaches `pam_aleph`
  - a right one does, after dropping to the user's uid
  - SSH (`system-remote-login`) never reaches aleph
  - `setup` followed by `--revert` leaves `/etc/pam.d` byte-identical and
    gnome-keyring holding every item
- **GUI:** `egui_kittest` snapshots of every prompter screen in both
  themes (rendered with wgpu: the tests need a GPU driver, or Mesa's
  software Vulkan), the screens driven through AccessKit as a person
  would (typing, Enter, Escape, clicks), `colors.toml` parsing tests, and
  the binary's handling of `ALEPH_PROMPT_FD` and of a missing display.
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

- **Persistent SRK:** check how common `0x81000001` is on Omarchy installs
  where `systemd-cryptenroll --tpm2` has been used (systemd creates it),
  and how often `ownerAuth` is set. Together these decide how often the
  AES-128 fallback is used.

**Resolved:**
- FIDO2 bindings: `fido2-rs` (Plan 2).
- The Omarchy PAM stack: §6, verified on 2026-09-26.
- Locked search (Plan 3): a placeholder in the `locked` list, prompts that
  wait for an unlock, typed empty results on dismissal (§4), verified
  against libsecret 0.21.7.
- `oo7-daemon` (Plan 3): not adopted. The server is written directly on
  `zbus`, because aleph's locked behaviour (encrypted names and
  attributes, placeholder searches, waiting prompts) needs control over
  search and prompts. `oo7-daemon` was not evaluated in depth.
