# aleph design review — 2026-09-26

Scope: `docs/superpowers/specs/2026-09-26-aleph-design.md` (the spec),
`docs/superpowers/plans/2026-09-26-aleph-core.md` and
`docs/superpowers/plans/2026-09-26-aleph-unlock.md` (plans 1 and 2), and
`crates/aleph-core` as of `0e1ed34`.

Two parts:

1. **Code review of `0e1ed34`** ("fix(core): address deferred review
   minors"). Nine findings, all fixed on branch `fix/core-review-2`.
2. **Design review** of the spec and plans. Twenty-one findings, none
   addressed yet. Items 1–5 affect the Plan 2 TPM code now being written.

Verification status is marked per finding:

- **Verified**: checked against the spec, plan, code, or this host's
  configuration while writing this document.
- **Unverified**: reported by the reviewer, plausible, not independently
  checked.

---

## Part 1: code review of `0e1ed34`

| # | Finding | Resolution |
|---|---|---|
| 1 | `check_memory` compared `m_kib` against `MemAvailable` on every derivation. A 1 GiB passphrase slot failed to unlock whenever the desktop was briefly short of free RAM, with the same `Error::Kdf` as a corrupt slot. Swap was ignored. | `5cc0c73`: the limit is `MemTotal + SwapTotal`, lowered by the tightest cgroup v2 `memory.max + memory.swap.max` on the path to the root. Exceeding it is a distinct `Error::InsufficientMemory`. |
| 2 | The check ignored cgroup limits (e.g. `MemoryMax=` on the service) and concurrent derivations, so it did not prevent the OOM it was meant to prevent. | `5cc0c73`: cgroup limits as above; derivations serialized by a process-wide lock. |
| 3 | `write_file_synced` unlinks an existing `.tmp` before `create_new`, and `write_atomic` took no lock. With two writers, one could rename the other's half-written temp file over the vault. | `2b99527`: `write_atomic` holds an exclusive `flock` on `vault.aleph.lock` for the whole sequence. The new 8-writer test failed 5 of 6 runs without the lock, 0 with it. Spec §4 updated. |
| 4 | `dropping_one_key_keeps_another_key_locked` demanded a locked page, but `LockedPage` treats `mlock` as best effort. It failed under `RLIMIT_MEMLOCK=0`. | `aff1586`: the test probes `mlock` on a scratch page and skips only when that fails. Checked with `prlimit --memlock=0`. |
| 5 | Key pages lacked `MADV_WIPEONFORK`; `mlock` is not inherited across `fork`, so a forked child held an unlocked copy of the master key until `exec`. | `520943d`: pages are marked `MADV_WIPEONFORK`; a fork test checks the child sees zeroes. Spec §4 now requires `alephd` to start children via `posix_spawn`/`exec`, since the decrypted body has no such protection. |
| 6 | `RecoveryKey::generate` and `::parse` passed the secret through a by-value stack array; `Kek::from_bytes` was a public by-value constructor. | `111a342`: `try_init_secret` is the one constructor for 32-byte secrets; `Kek::from_bytes` (unused) removed. |
| 7 | CSPRNG error mapping was duplicated in three places. | `111a342`: `crypto::fill_random`. |
| 8 | `rotate_master` verified each KEK with `KeyHandle::unwrap`, mapping and mlocking a page per slot only to discard it. | `111a342`: `KeyHandle::unwraps` checks without allocating a page. |
| 9 | `munlock` immediately before `munmap` in `LockedPage::drop` was redundant. | `111a342`: removed. |

All 59 tests pass; clippy and rustfmt are clean. The branch is not merged.

---

## Part 2: design review

Labels: **[FLAW]** design flaw, **[UNDERSPEC]** underspecified,
**[OVERCLAIM]** the spec promises more than the mechanism delivers.

### Verdict: sound with changes

The file format and cryptography are sound. The threat model overclaims,
and the TPM and revocation designs must change before aleph protects what
§2 says it does.

### What is right

- MK is random, never derived from user input, and exists at rest only
  wrapped in keyslots: the LUKS key hierarchy, done correctly.
- XChaCha20-Poly1305 with random 192-bit nonces; HKDF domain separation;
  separate subkeys for the header MAC and the body.
- The header MAC covers the exact stored bytes, not a re-encoding, so CBOR
  encoding choices cannot affect it.
- Strict outer decoding (exact array length, no trailing data); a fresh
  body nonce on every write.
- Wrapped-key AAD `vault_id ‖ slot_id ‖ slot_type` prevents moving a wrap
  to another slot or vault.
- Tampering with a slot's KDF, TPM, or FIDO2 parameters yields only a
  wrong KEK; the daemon re-emits only authenticated parameters.
- Argon2 upper caps, an exhaustive bit-flip test, a golden file, and a
  known-answer test checked against the reference C implementation.
- `rotate_master` verifies every KEK before changing anything.
- Recovery key: 256 bits, 20-bit checksum, canonical padding enforced,
  lookalike characters normalized.
- TPM: parameter encryption in both directions, handles flushed on error
  paths, `fixedTPM`/`fixedParent`, DA protection left on.
- FIDO2: non-resident credential, per-slot salt, UV/PIN state recorded in
  the slot.
- Per-application access control is honestly declared a non-goal; secrets
  are read from stdin, never argv; PAM never blocks login;
  `PR_SET_DUMPABLE`; labels and attributes are encrypted, unlike
  gnome-keyring.

### Top three changes

1. **Make revocation real.** Rotate MK on slot removal, restore, and
   password change. Make the recovery slot a public-key recipient so
   rotation does not need the paper key. Replace `ObjectChangeAuth` with a
   fresh seal. Add a generation counter with an external high-water mark.
2. **Fix the TPM story.** Verify the parent key's Name before salting
   sessions. Check and report `lockoutAuth` and the DA parameters. Drop
   `auth=none` and PCR 7 binding unless Secure Boot is configured. Rewrite
   §2 to state the real guarantees.
3. **Redo the Omarchy integration against the real PAM stack.** Handle
   autologin; target `sddm`, `omarchy-lock-password`, and
   `passwd`/`system-auth`; drop to the user's uid before connecting to
   `pam.sock`; require re-auth for enrollment and config changes; return
   `IsLocked` instead of holding replies.

---

### 1. High [FLAW]: removing a keyslot revokes nothing — Verified

**Where:** spec §4: "Adding or removing an unlock method adds or removes a
slot. Only `rotate-master` re-encrypts the body." §7 restore keeps MK.
`UnlockedVault::remove_keyslot` does not rotate.

MK never changes when a slot is removed, the vault is restored, or a
password changes. Anyone holding an old copy of the file and the removed
credential recovers MK, and `HKDF(MK, "aleph body v1")` decrypts every
later version of the file. The spec's rationale for `header_mac` in the
body AAD ("an older header (for example one still listing a removed
keyslot) cannot be spliced onto a newer body") defends against a splice
the attacker does not need: the old file alone yields MK.

This matters more than for LUKS because the vault file is expected to
live in backups and sync, which §2 names as in scope.

**Attack:** a passphrase leaks; the user runs `keyslot remove`; an attacker
with any old backup reads every future backup.

**Recommendation:** rotate MK by default on slot removal, on restore, and
after a lost device or leaked secret. The body is small, so this is cheap.
The obstacle is that `rotate_master` needs every slot's KEK, including the
paper recovery key. Either:

- make the recovery slot a public-key recipient (age-style: X25519,
  optionally hybrid with ML-KEM; public key in the header, private key
  derived from the recovery key), so the daemon can re-wrap without the
  recovery secret; or
- regenerate and re-display the recovery key on every rotation.

The first is preferred: users will not re-record a paper key on every
slot change.

### 2. High [OVERCLAIM/FLAW]: TPM dictionary-attack protection is resettable; `auth=none` protects nothing against a thief — Verified (spec and plan); TPM behavior per the TPM 2.0 spec

**Where:** §2: "Offline guessing is impossible, and online guessing is
rate-limited by the TPM's dictionary-attack lockout." §5: "the TPM's
existing settings apply. `aleph` does not modify them". Unlock plan
`auth_value`.

- Linux distributions leave `lockoutAuth` empty. Anyone with raw TPM
  access can then issue `TPM2_DictionaryAttackLockReset` and guess without
  limit. Raw access includes a thief booting a live USB (no PCR policy by
  default) and any process of a user in `tss`.
- The auth value is `SHA-256(HKDF(secret, "aleph tpm auth v1"))`: fast and
  unsalted. Each guess costs one TPM round-trip, on the order of 10^6
  guesses per day. Typical login passwords fall.
- `aleph keyslot add tpm` without `--pin`/`--login-password` creates
  `auth=none`. Without PCRs, anyone holding the machine and the vault file
  unseals it.
- The DA counter is TPM-wide. aleph failures (stale slots, mistyped PINs,
  guesses via `pam.sock`) also lock out `systemd-cryptenroll` TPM2+PIN
  disk unlock.

**Recommendation:**

- Setup reads `TPM2_PT_PERMANENT.lockoutAuthSet` and the DA parameters
  and reports the real guarantee. Optionally offer to set `lockoutAuth`
  to a value derived from the recovery key.
- Rewrite §2: "TPM + password protects a copied file. Against file plus
  device, security is the password's strength unless `lockoutAuth` is set
  or a Secure Boot/PCR policy stops foreign operating systems."
- Forbid `auth=none` unless PCR-bound, or cut it from v1.
- Reconsider `tss` group membership: with an empty `lockoutAuth` it also
  lets every user process run `TPM2_Clear` (destroying LUKS TPM slots) and
  read the EK, a hardware identifier. Alternatives: a small root helper,
  or `systemd-creds --user` (systemd ≥ 256).

### 3. High [FLAW]: `TPM2_ObjectChangeAuth` leaves the old password working — Verified

**Where:** §5: "`alephd` runs `TPM2_ObjectChangeAuth` and rewrites the slot
blobs." Unlock plan `change_auth`; its test
`change_auth_keeps_the_kek_and_retires_the_old_secret` asserts
`new_slot.public == slot.public` and that the KEK is unchanged.

`ObjectChangeAuth` returns a new private blob, but the old blob remains
loadable on that TPM indefinitely. The KEK and MK are unchanged, so the
old blob plus the old password still yields MK. The old blob survives in
`vault.aleph.bak` next to the vault, in filesystem snapshots, and in
backups. The test's name ("retires the old secret") is only true for the
new blob.

**Attack:** someone observes the login password; the user changes it; the
attacker with physical access and any older vault copy still unlocks.

**Recommendation:** on password change, seal a fresh KEK in a new object,
re-wrap MK, and remove the old slot. Rotate MK as well when the change is
a response to compromise (finding 1).

### 4. High [OVERCLAIM]: "a laptop stolen while suspended … handled by locking on suspend" — Verified (spec text)

**Where:** §2; §6 lock policy (`on_suspend = true`).

- Locking zeroizes aleph's MK, but clients keep what they already fetched
  (browser safe-storage keys, git credential caches, NetworkManager).
- Cold boot and DMA attacks are not mentioned, yet this scenario depends
  on them. The LUKS key remains in RAM during suspend, so the attacker
  gets the disk and the vault file; finding 2 then applies.
- No logind delay inhibitor is specified. Without one, the system can
  suspend before `alephd` handles `PrepareForSleep`, leaving MK in RAM.
- `mlock` does not keep pages out of a hibernation image.

**Recommendation:** take a `delay` sleep inhibitor and release it only
after zeroizing. Handle hibernate explicitly. Restate §2: aleph protects
secrets clients have not already fetched; cold boot, DMA, and evil maid
are out of scope (without Secure Boot, a modified initramfs captures both
passwords).

### 5. High [UNDERSPEC]: the PAM integration does not match Omarchy — Verified on this host

**Where:** §1 criterion 2 ("the vault unlocks at login with no extra
interaction"); §6 PAM integration.

On this host:

- **Lock screen:** uses `/etc/pam.d/omarchy-lock-password`, which does not
  include `system-login`. The spec's "`hyprlock`: `auth optional
  pam_aleph.so`" does nothing.
- **Password change:** `/etc/pam.d/passwd` includes `system-auth`, not
  `system-login`, so `password optional pam_aleph.so` in `system-login`
  never sees `passwd`, and the password-change flow never runs.
- **Too broad:** `system-remote-login` (sshd) includes `system-login`, so
  an SSH login would unlock the desktop vault.
- **Autologin:** `/etc/pam.d/sddm-autologin` authenticates with
  `pam_permit` and `/etc/sddm.conf.d/autologin.conf.disabled` exists.
  With autologin there is no PAM password, so criterion 2 is reachable
  only through TPM `auth=none` (finding 2).
- **Peer credentials:** "The daemon checks `SO_PEERCRED` (uid must match
  its own)" rejects the login case, because SDDM runs PAM as root.
  `pam_gnome_keyring` forks and `setuid`s to the user for this reason;
  `pam_aleph` must do the same.
- **Placement:** the spec does not require `pam_aleph` to run after the
  `pam_unix`/`pam_faillock` success path. Placed earlier, every mistyped
  lock-screen password burns a TPM DA attempt.
- **Stale slots:** a slot whose password changed out of band burns a DA
  attempt on every unlock. Mark it stale after its first failure and stop
  trying it until re-enrolled.

**Recommendation:** resolve §11's open PAM item now. Design separate
autologin and password-login modes. Target `sddm`,
`omarchy-lock-password`, and `passwd`/`system-auth`, ideally through a
single `/etc/pam.d/aleph` substack that each includes.

### 6. Medium [FLAW]: an active TPM bus interposer defeats the salted session — Verified (plan code)

**Where:** §5: "all commands use salted HMAC sessions with parameter
encryption … so neither the auth value nor the KEK crosses the bus in
plaintext". §2 excludes only interposers "recording … for later quantum
cryptanalysis". Unlock plan `with_primary` trusts whatever key
`create_primary` returns.

**Attack:** an active interposer substitutes its own ECC key in the
`CreatePrimary` response, learns the session salt and key, reads the
unsealed KEK, and can brute-force the fast auth value offline from the
session HMACs.

**Recommendation:** record the primary's Name at enrollment and verify it
before salting (systemd stores the SRK name in its LUKS tokens for this).
Prefer the TCG standard SRK at `0x81000001` when present; re-creating a
primary under the owner hierarchy with a null session fails whenever
`ownerAuth` is set, which is also unspecified. Salt the auth-value
derivation per slot.

### 7. Medium [FLAW]: whole-file rollback is undetected and silently undoes `rotate-master` — Verified (spec text)

**Where:** §4 claims the MAC "detects keyslot deletion, substitution, and
format-version rollback". That holds only within one file.

**Attack:** an attacker with write access (sync peer, backup target, a
restore) replaces the vault with a pre-rotation copy. TPM and FIDO2 KEKs
are unchanged, so the user unlocks without noticing, and new secrets are
written under the old MK the attacker holds.

**Recommendation:** a generation counter in the MAC'd header, plus a
high-water mark (generation and an MK fingerprint) kept outside the synced
file: ideally a TPM NV counter, at minimum `$XDG_STATE_HOME`. Warn on
regression.

### 8. Medium [FLAW]: a brief same-user compromise becomes permanent — Verified (spec text)

**Where:** §6 requires re-authentication only for "removing a keyslot,
rotating the recovery secret, rotating the master key, and revealing a
secret in the GUI". §5: "Every screen has **Use recovery secret
instead**."

- `EnrollPassphrase`, `EnrollTpm`, etc., and `SetConfig` (e.g.
  `on_suspend = false`) need no re-auth. Enrolling a slot is equivalent to
  exporting MK, so a one-off infection gains permanent access to every
  future backup (MK never rotates; finding 1).
- The recovery key, the root credential, is offered on every routine
  prompt. Any same-user client can set the prompter's app_id, which
  invites phishing with a fake prompt.
- `pam.sock` is a same-user login-password guessing oracle: each guess
  costs a DA attempt on the TPM path, or ~0.3 s of Argon2 without a TPM.
- The GUI's "reveal requires re-auth" is UX, not security:
  `secret-tool lookup` bypasses it. The spec should say so.

**Recommendation:** re-auth for all enrollment and config changes. Move
recovery-key entry to an explicit recovery flow (`aleph restore`), and
rotate after use. Rate-limit `pam.sock`.

### 9. Medium [FLAW]: a backup is only as strong as its weakest slot — Verified (spec text)

**Where:** §4 keyslot table (`login-password`: `m = 64 MiB`, ≈0.3 s,
"Used only when no TPM is available"); §7 `aleph backup <path>`.

On a machine without a TPM, a leaked backup is an offline dictionary
attack on the login password at 64 MiB per guess. Success also yields the
login password itself, which for a `wheel` user means sudo. A weak
passphrase slot has the same problem.

**Recommendation:** `aleph backup` writes a re-headered copy containing
only the recovery slot(s). Warn about generic home-directory backups of
the live file. Enforce minimum strength for recovery passphrases, or
generate a diceware one.

### 10. Medium [FLAW]: locked-search semantics — Verified (spec text)

**Where:** §4 "Locked search": `alephd` "holds the method reply … or
returns empty results if the user cancels."

An empty result means "no such item". Clients that create a fresh key
when theirs is missing (Chromium's safe-storage key is the classic case)
create duplicates or new keys that orphan existing data. Holding the reply
also freezes clients that call libsecret synchronously on their UI thread,
for up to the ~25 s D-Bus timeout.

**Recommendation:** return `org.freedesktop.Secret.Error.IsLocked`, or
`(unlocked = [], locked = […])` from a small encrypted-at-rest ID index,
and let libsecret drive `Unlock()`.

### 11. Medium [UNDERSPEC]: FIDO2 policy — Unverified

**Where:** §5: "PIN/UV is used if the key requires it or the user opts
in"; unlock plan `make_credential`, `Libfido2Authenticator::open`, and
`unlock` (uses `slot.rp_id`).

- Touch-only is the default. Keys are often left plugged in, so a thief
  needs one touch.
- `credProtect` is not set.
- Only the first device is opened, so "multiple keys, one slot each"
  fails with two keys plugged in.
- `rp_id` is read from the unauthenticated header.
- hmac-secret support is not checked in `getInfo` before enrollment.

**Recommendation:** default to UV/PIN required and `credProtect = 3`.
Preflight each device with `up = false` to find which holds which
credential, as systemd does. Hardcode `rp_id`.

### 12. Medium [FLAW]: format forward-compatibility — Unverified

**Where:** `keyslot.rs` (internally tagged `SlotKind`); `vault.rs`
(the header is re-encoded from structs on write).

- A future slot type makes an older build fail to parse the whole header,
  even when it holds a recovery slot it understands.
- Unknown fields in known slot types are silently dropped when an older
  daemon rewrites the file (e.g. a future UV or signed-policy marker).

**Recommendation:** keep each slot's raw CBOR; re-emit unknown slots
verbatim and skip them for unlock; use `deny_unknown_fields` or a
per-slot version.

### 13. Medium [FLAW]: PCR 7 binding as specified adds little — Verified (spec text)

**Where:** §5: "offers to re-seal against current PCR values"; CLI
`--pcr 7`.

- With Secure Boot off, PCR 7 is constant.
- With the Microsoft UEFI CA enrolled, any shim-signed live distribution
  reproduces PCR 7.
- dbx updates (fwupd) change PCR 7 and break the slot.
- Re-sealing to current values after a mismatch is trust-on-first-use; it
  trains users to approve an evil-maid boot.

**Recommendation:** cut `--pcr` from v1, or require custom Secure Boot keys
and later adopt signed policies (systemd-pcrlock, `PolicyAuthorize`).

### 14. Medium [UNDERSPEC]: `setup --revert` loses data — Verified (spec text)

**Where:** §1 criterion 6: "`aleph setup --revert` restores gnome-keyring
exactly."

Items created while on aleph (Wi-Fi passwords, a browser safe-storage key
first created under aleph) vanish on revert, and the browser's password
database becomes undecryptable.

**Recommendation:** export aleph items into gnome-keyring on revert, or
refuse to revert until they are exported.

### 15. Low [UNDERSPEC]: concurrency and corruption handling — Partly fixed

- Concurrent writers: fixed by `2b99527` (`flock` on `vault.aleph.lock`).
  This serializes writers; it does not stop a writer with a stale
  in-memory vault from overwriting newer changes. `aleph restore` should
  go through the daemon, and a second daemon should be prevented (e.g. a
  lock held for the daemon's lifetime).
- `.bak` is a single generation, with no automatic fallback on
  `BodyTampered`/`Malformed`.
- `rename` replaces a symlinked `vault.aleph`, silently breaking a symlink
  into a sync folder.
- An existing parent directory is not tightened to `0700`.
- Live sync between machines should be declared unsupported.

### 16. Low [OVERCLAIM]: memory hygiene — Verified (spec and code)

**Where:** §4: "MK and the decrypted body are held in `mlock`ed memory."

- `mlock`/`madvise` are best effort and their failure is silent.
- The body is not locked (deferred to Plan 3).
- `Item`/`Body` derive `Clone`; labels and attributes are plain `String`s
  and are not zeroized.
- ciborium's reader uses scratch buffers that are not zeroized.
- Once zbus and the GUI handle secrets, "body in mlocked memory" is not
  achievable.

**Recommendation:** narrow the claim to "MK page-locked when possible;
`PR_SET_DUMPABLE`; `MADV_DONTDUMP`; secrets zeroized on a best-effort
basis", and recommend encrypted or zram-only swap.

### 17. Low [FLAW]: `check_memory` uses `MemAvailable` — Fixed

Fixed by `5cc0c73` (Part 1, findings 1–2). The reviewer suggested
pre-allocating Argon2 blocks with `try_reserve` instead; under Linux
overcommit that allocation succeeds and the OOM killer fires when the
pages are touched, so it would not help. The capacity check was kept.

### 18. Low [FLAW]: no Argon2 floor enforced at enrollment — Verified

**Where:** `UnlockedVault::add_argon2_keyslot`; `Argon2Params::INSECURE_TEST`
is a public constant.

Core enforces only maximums; production code can enroll a slot with test
parameters.

**Recommendation:** enforce per-kind floors in `aleph-core`, with a
test-only escape hatch.

### 19. Low: spec and plan drift — Verified

- §3's crate table puts Argon2id in `aleph-unlock`; the code deliberately
  has it in `aleph-core::kdf`. Update the table.
- §4's slot field names differ from the encoding now frozen by the golden
  file: `slot_id` is `id`; `slot_type` is nested under `kind`;
  `tpm_public`/`tpm_private` are `public`/`private`; optional `pcrs` is a
  list where empty means none.
- Core plan Task 9 still gives the body AAD as `vault_id ‖
  be32(format_version)`, without `header_mac`; its error list omits
  `WrongKek`.

### 20. Low [UNDERSPEC]: compatibility and UX — Unverified

- **Flatpak:** sandboxed libsecret clients go through the Secret portal,
  whose backend is implemented by gnome-keyring. This contradicts
  criterion 1's "every existing libsecret client" unless aleph implements
  `org.freedesktop.impl.portal.Secret`.
- **Clipboard:** clipboard-history tools persist copied secrets, and a
  30 s auto-clear does not remove history entries. Set the
  `x-kde-passwordManagerHint: secret` MIME hint.
- **Recovery-key KDF:** Argon2 over a 256-bit recovery key is unnecessary
  (HKDF suffices) but harmless.

### 21. Scope: cut for v1

Recommended cuts:

- PCR binding and `auth=none`.
- TPM-PIN mode (overlaps FIDO2).
- Passphrase recovery (ship the recovery key only).
- The manager GUI, themes, live Omarchy re-theming, and scanlines; keep a
  minimal prompter and the CLI.
- The NixOS module.
- Reply-holding locked search (finding 10).

Also check whether `oo7-daemon` (oo7's Secret Service server) is mature
enough to host the TPM/FIDO2 unlock work instead of writing a Secret
Service server from scratch.

On v2 "privilege separation": the D-Bus daemon still holds every
plaintext secret, so separation protects only MK. It is worth doing, but
the spec overstates the gain.
