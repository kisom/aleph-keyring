# Design decisions

Decisions made while the project owner was away, each proposed by the
implementer and ruled on by an independent reviewer (a fresh model
session with the spec and the code, and no part in writing them). Newest
first. The spec (`docs/superpowers/specs/2026-09-26-aleph-design.md`)
is updated to match wherever a decision changes it.

## 2026-09-27: Plan 4b split into custody (4b) and setup (4c)

### F4. The independent review of the rewritten proof rule: fixes

The rule F3 adopted was reviewed again, on its own, by a fresh reviewer,
who broke it; each attack became a test that failed first:
- **Re-authentication proved the file on disk, not the unlocked vault**
  (since Plan 3). A same-user process that planted a vault whose method
  it knew could pass it, for a restore and for every other operation
  that asks for it (enrolling its own key, say). The opened file must
  now be the unlocked vault: same ID and master key, not behind it.
- **Accepting a rollback took the untrusted vault's own methods:** an
  older copy holding a since-removed key was accepted with that key. It
  now always needs the login password too.
- **Deleting `vault-id` made "a machine with no vault"**, which needs no
  proof. That now means no vault files, no records, and none seen since
  the daemon started.
- `--from-bak` now also needs `.bak` to be at most one write behind the
  mark (else the login password).

The reviewer found no deadlocks, and confirmed the question order in
`recover` and `--from-bak` sound with these fixes.

The TPM test flake: the harness's swtpm children inherited other tests'
live TPM connections for their lifetime (seen with `ss`); they now start
with every inherited descriptor close-on-exec. A rarer busy-helper
timeout under full-suite load remains, as do two `pam.sock` listener
tests racing a concurrent fork (a dropped listener still held until the
child's exec); those tests now retry briefly, as the keyring tests
already do for the daemon lock.


### F3. The final review of the executed Plan 4b branch: fixes

Three critical and three important findings, each fixed with a test that
failed first (the proof rule then went to a second, independent
reviewer):
- **An older copy of this vault** (same ID) put back at the path, with
  its old recovery key, was "the vault this machine expects" and needed
  no proof. The expected vault now means the recorded ID and master key,
  not behind the recorded generation; anything else needs proof.
- **A plain `restore` with the vault missing deadlocked the daemon** (a
  mutex guard in a `match` scrutinee lives through its arms, and the
  `.bak` fallback locked again).
- **Opening a file with the expected ID proved nothing:** the ID is
  public, and a forged vault (an old backup recovered elsewhere onto the
  attacker's key) opens with the attacker's key; the "corrupt counts as
  proven" rule let a master-key mismatch through too. Opening proves only
  if the opened vault is the recorded one; a corrupt file asks for the
  login password. `--from-bak` applies the same rule to `.bak`.
- A cancel at the new-recovery-key offer, after the vault was replaced,
  reported failure; the restore is now reported, with a note.
- The older-backup question now compares with the recorded generation
  too (the file may be gone) and names a newer `.bak`; `--from-bak`
  names the recorded generation.

Minor fixes adopted: a backup of an untrusted vault says so; `aleph
restore` refuses a FIFO or device instead of waiting on it. Deferred:
removed items' D-Bus objects and `ItemDeleted` signals after a restore
(the Secret Service re-sync), and listing kept files in `aleph status`.


### F2. The pre-execution review of the Plan 4b document: fixes adopted

Two critical and three important findings, each fixed with a test that
failed first:
- **E7's proof could be skipped.** Moving the vault away, planting a
  vault (or a `.bak`) whose only method was the planter's own password,
  or restoring while unlocked with the file gone, let a same-user process
  holding a backup and its recovery key swap it in. Proof now comes only
  from the vault this machine expects (re-authentication, or opening it),
  or else from the login password checked with PAM; a planted vault's
  methods prove nothing, for `restore`, `--from-bak`, and
  `--accept-rollback` alike.
- **Custody writes could destroy `.bak`**, sometimes the only good copy
  (a rotation's write removes it; `--from-bak` and an acceptance replace
  it). `.bak` is now kept aside by a hard link before every custody
  write.
- **Two kept copies in the same second** collided, and the copy fallback
  wrote into the first (the old vault's own file). Names now take a
  `-<n>` suffix, and the fallback copies only into a new file, synced.
- **A restore file was read on the async runtime from any descriptor**
  (a pipe could hold a worker). Only a regular file is read, off the
  runtime.
- **Tests** for the Review Focus lines that lacked them: a file that is
  not a backup, a symlink and a refused overwrite, an older backup of the
  same vault, clients seeing the restored items, and a corrupt vault
  replaced after its slot opened; the plan's mappings are corrected.

Minor fixes adopted: kept files are named in the result, with a warning
that they still open with the old recovery key and methods; an older
backup of the same vault asks first, naming both generations; a backup
goes only into an empty file (a hard link to the vault elsewhere is
refused), and a stale `--force` temporary file is named. The crash
window between a restore's write and recording its ID is documented
(the next unlock asks for `--accept-rollback`).


### F1. Plan 4b is custody only; setup's system changes become Plan 4c — Accepted with changes

- **4b, custody:** `aleph restore` with the recovery key (from a backup,
  the current vault, or its `.bak`), `--from-bak`, `--accept-rollback`,
  and `aleph backup` (E7, E8, and their tests from E11). Nothing outside
  the user's own files; no root, no gnome-keyring.
- **4c, setup:** import and export (E1, E2), switchover and revert (E3,
  E9), PAM changes (E4–E6), step checks (E10), the wizard, explaining
  lockoutAuth (D9), and how Omarchy's screen lock reaches alephd (D13).
  4c has daemon tasks of its own: E1's queued import and E3's write
  freeze touch the keyring engine and the Admin interface.

Custody depends on nothing in 4c: the vault-id file is written at create,
at restore, and at the first unlock of a vault without one, never by
setup. 4c depends on custody: its emergency-revert docs name `aleph
restore` and `--from-bak`. Restore is not what protects a login from a
bad PAM edit (the `-` prefix, `optional`, E4's verify-and-roll-back, and
the TTY are); it helps when a bad switchover leaves the vault unreachable
by its methods.

Changes adopted:
- `Confirm` carries the answer Enter gives, so the new-recovery-key offer
  defaults to yes and everything else (accepting a rollback included)
  to no, as E7 says; the terminal shows `[Y/n]` or `[y/N]`.
- A test pins that a vault with no vault-id file gets one at unlock.
- The GUI's "Recover…" belongs to the GUI plan; `aleph restore` is the
  only recovery path until then.
- The spec's Admin method list and setup-step numbering now say 4c
  where setup is meant.

Also added while preparing 4b:
- A restore that finishes after the pre-sleep lock writes nothing and
  fails with "going to sleep", the counterpart of D13's rule for unlocks.
- The file a restore replaces is kept by a hard link made before the
  write (a copy where links fail), not moved away first: a crash between
  the two leaves the old vault in place, where a rename would have left
  no vault at all, and a later `setup` would have created an empty one.

## 2026-09-27: Plan 4b (custody and setup), design

All twelve proposals were **Accepted with changes**, and the changes are
adopted. Plan 4b is written from these.

### E1. alephd imports from gnome-keyring as a Secret Service client, and queues for the name

Secrets go straight from gnome-keyring to alephd over an encrypted
session, never through the CLI. alephd requests `org.freedesktop.secrets`
queued (never `AllowReplacement` or `ReplaceExisting`), so the bus hands
it over the moment gnome-keyring releases it, and the name is never
unowned.

Changes:
- The unit becomes `BusName=io.aleph.Keyring`, so a queued alephd is not
  killed at `TimeoutStartSec`.
- `Status` reports who owns the Secret Service name. After switchover, a
  queued alephd logs a warning.
- alephd subscribes to gnome-keyring's item and collection signals before
  listing, and keeps importing until the name changes hands, so nothing
  stored in between is lost.

### E2. Import is idempotent and never overwrites

- An item conflicting with one that existed before this run (same
  collection, label and attributes, but a different secret) is skipped and
  listed in the summary. Duplicates within gnome-keyring itself all
  arrive.
- The transient `session` collection is skipped.
- Content types and every attribute (`xdg:schema` included) are kept.
- A dismissed unlock skips that collection and says so; a re-run picks it
  up. A missing or empty gnome-keyring skips the step.

### E3. `setup --revert` exports to a private gnome-keyring, verifies, then switches back

- The export goes to a gnome-keyring instance that alephd runs itself, on
  a private bus, over the real keyring files, after checking that none
  runs for this user. The session never changes hands until the export is
  verified.
- aleph refuses writes from the start of the export to the end of the
  revert.
- What to export is decided by comparison, not by timestamp: every item
  missing from gnome-keyring or different there. Each is verified by
  reading it back on a fresh connection.
- Items imported at setup and deleted in aleph since are listed, with an
  offer to delete them from gnome-keyring too. The aleph vault is left in
  place.
- Order after a verified export: stop the private instance; remove the
  activation files and reload the bus configuration; unmask and restore
  the recorded unit states; alephd releases the name; `sudo aleph system
  revert` runs last.
- Revert is refused if gnome-keyring is not installed.

### E4. PAM edits run as root through `sudo aleph system apply/revert/verify`

- The edits are pure text transformations, tested against fixtures (this
  machine's edited files and stock Omarchy's).
- Writes are atomic (a temporary file, fsync, copied mode and owner,
  rename, fsync of the directory). Symlinks, non-regular files, and files
  not owned by root are refused and handled by hand.
- **Verify, with automatic rollback:** right after applying, a real
  Linux-PAM run through the lock screen's and sddm's stacks, with the
  password asked once (faillock counts wrong tries). Any failure restores
  the originals at once.
- **Revert is conditional:** the `.aleph-orig` backup is restored byte for
  byte only if the current file is still exactly what apply produced;
  otherwise the inverse transformation is used if it applies cleanly, and
  failing that the file is left alone and a diff is shown.
- The root side stays small: it is `sudo <this binary>`, with a warning if
  that binary is user-writable, and it reads no user configuration, no
  D-Bus, and no user-writable paths.
- Anything setup installs as root is recorded in a root-owned manifest, so
  revert removes exactly that.
- `password optional pam_gnome_keyring.so` stays in `passwd`, so
  `login.keyring` keeps following the login password and a later revert
  still unlocks at login.
- **The aleph lines go straight into each service** as `-auth optional
  pam_aleph.so` (and likewise for `session` and `password`), not as
  `include aleph`. A missing substack file could make the whole service
  fail; a missing module behind `-` is silently skipped. This replaces
  Plan 4a's substack.

### E5. Autologin detection is advisory

SDDM's file rules are uncertain: it may read every file in its
configuration directories, not only `*.conf`. So detection only picks the
default unlock method and the summary text.
- aleph is always added to `sddm`.
- The `pam_gnome_keyring` lines are always removed from `sddm-autologin`
  (which would otherwise start gnome-keyring directly, ahead of alephd),
  and nothing is added there.
- The precedence rules get a test against the SDDM source's actual rules.

**Note for the owner:** `/etc/sddm.conf.d/autologin.conf.disabled` (with
`User=kyle`) may still be read by SDDM. Check this before relying on it.

### E6. Manual mode where files are not ordinary

Any PAM target that is not a regular, root-owned file puts setup in manual
mode (it prints what to add), on any distribution. NixOS (`/etc/NIXOS`)
also skips the unit masking and prints the module configuration, and
revert there prints what to undo.

### E7. Restore, `--from-bak`, and `--accept-rollback`

- **No lowering of the high-water mark, ever.** The restored or accepted
  vault is written at generation `max(recorded, found) + 1` (core
  `advance_generation_past`), so every older copy stays detectable.
- **Replacing a vault that still opens needs re-authentication with its
  current method**, as well as the backup's recovery key. Without that, a
  same-user process could swap in a backup whose recovery key it holds.
- The replaced file is kept (`vault.aleph.replaced-<time>` or
  `.corrupt-<time>`), never deleted.
- A plain `restore` on an unreadable `vault.aleph` falls back to `.bak`,
  and is refused while the vault is unlocked and trusted.
- `--accept-rollback` shows exactly what is being accepted, and its
  confirmation defaults to no.
- A new recovery key is offered afterwards, defaulting to yes.
- The recovery-key prompt is a type-level part of the restore conversation
  only.
- Files pass as descriptors, not paths.
- The expected `vault_id` is recorded; a different vault at the path
  counts as untrusted.

### E8. Backup writes to a descriptor the CLI opened

The CLI opens the file (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600; `--force`
writes a temporary file and renames it over the target). Targets inside
aleph's data and state directories are refused. The written bytes are
checked to parse, and their vault id and generation are printed.

### E9. User-level switchover also stops gnome-keyring's other routes in

- **Activation files:** gnome-keyring's D-Bus activation files start it
  directly, bypassing systemd. So user-level files override
  `org.freedesktop.secrets` (pointing to alephd) and `org.gnome.keyring`
  and `org.freedesktop.impl.portal.Secret` (disabled).
- **Bus reload:** `ReloadConfig` is called after writing or removing
  activation files (dbus-broker does not notice new files).
- **Order:** activation files and reload; alephd started (queued); units
  masked; gnome-keyring stopped; then the name's owner is checked.
- The prior unit states are recorded for revert. The user is told that
  gnome-keyring's pkcs11 component goes away.

### E10. Setup steps check the real state on every run

Each run checks the vault, the name owner, the unit states, and the PAM
files, rather than trusting a state file. The state file records only
choices (and which items were imported, for E3). The riskiest step, the
root one, comes last and is optional.

### E11. Testing

Beyond the proposal:
- the name handoff on a private bus
- unlocking a second, password-protected gnome-keyring collection (or
  skipping with a message)
- export verification, the write freeze, deletion reporting, and a revert
  re-run after a partial failure
- PAM fixtures for both variants, with idempotence and exact revert
- the transformed stacks run through real Linux-PAM (`pam_start_confdir`,
  as in D10)
- SDDM precedence

The real gnome-keyring runs isolated on a private bus: this was checked on
this machine.

### E12. Task list

Nine tasks, with the additions above. (Split by F1: custody is Plan 4b,
the rest Plan 4c.) The switchover-and-revert task and
the wizard task are separate, and the docs task adds an emergency
manual-revert section.

## 2026-09-27: Plan 4a (session unlock)

Reviewer verdicts are given as **Accepted**, **Accepted with changes**
(the changes were adopted), or **Rejected** (the alternative was adopted).

### D1. Plan 4 is split into 4a and 4b — Accepted

- **4a, session unlock:** `pam_aleph` and `pam.sock`, login and
  screen-unlock unlocking, `passwd` changes, re-sealing after an outside
  password change, and the lock policy (suspend, screen lock, idle).
- **4b, custody and setup:** recovery unlock (`aleph restore`), backup,
  `--from-bak` and `--accept-rollback`, gnome-keyring import and export,
  setup's system changes and `setup --revert`, and lockoutAuth.

4b's setup installs the PAM lines 4a's module needs. Until then, 4a's docs
give the lines to add by hand, marked provisional. (Setup later moved to
Plan 4c: F1.)

### D2. `passwd` without FIDO2 slots rotates MK; with them, it keeps MK and marks a rotation pending — Accepted with changes

A rotation needs a KEK for every slot, and a FIDO2 slot's KEK needs a
touch, which `passwd` cannot provide.

- **Without FIDO2 (or unknown-type) slots:** the password slots are
  replaced (a new TPM slot sealed under the new password, and a new
  login-password slot if there was one) and MK rotates.
- **With them:** the new slots are added and the old ones removed without
  rotating (core `remove_keyslot_keeping_mk`, which refuses recovery slots
  and keeps the pre-change file out of `.bak`). A "rotation pending" mark
  is shown by `aleph status` and by every unlock, and any rotation clears
  it.
- **Residual risk while pending:** an old copy of the file, plus the old
  password, plus this machine's TPM, yields an MK that still opens newer
  files.

Changes adopted:
- **The daemon checks the new password with PAM first.** In Arch's stack,
  `pam_aleph` still runs when `pam_unix`'s update failed. If PAM rejects
  the new password, nothing changes. If PAM cannot check, the change goes
  ahead.
- The pending mark is repeated in the message that ends each unlock.
  Offering the touches right there is left to the GUI prompter (Plan 5).
- An unreadable `slots.json` is logged.

### D3. After an outside password change, the previous password re-seals — Accepted with changes

When a typed password PAM accepts opens no TPM slot (all stale, or one
rejects it with `AuthFailed`), the prompter asks for the previous password
(`ToPrompter::OldPassword`).

- It is tried only on the newest TPM slot, straight at the TPM with no PAM
  check.
- At most 2 tries per conversation, each counted by the typing limiter.
- Once the vault is open, the password slots are replaced under the
  current password, following D2's policy.

Changes adopted:
- **Cancelling the question returns to the choice of method.** A FIDO2
  touch then opens the vault, and it re-seals under the current password
  all the same.
- **A `WrongUser` refusal does not ask for the previous password,** which
  cannot help there.
- **With PAM unavailable and every TPM slot stale,** the attempt fails
  with the "cannot check passwords" error, which says why.

### D4. `lock.on_suspend` covers every sleep, hibernation included — Accepted

logind's `PrepareForSleep` does not say which sleep it is, and
suspend-then-hibernate moves on to hibernating without a second signal.
The spec now says so. `aleph config set lock.on_suspend false` warns that
the master key can then end up in a hibernation image.

### D5. `pam.sock` passwords skip the PAM check — Rejected

This would let one wrong password from any same-user process reach the TPM
and mark slots stale.

Adopted instead:
- `pam.sock` passwords are checked with `aleph-check` whenever PAM can
  check: `Unlock`'s password, and `ChangePassword`'s new one. (The old one
  cannot pass PAM once `passwd` has changed it; it is proven by the slot
  it opens, and only on a locked vault.)
- A rejected password fails without touching the TPM.
- The login stack is trusted only when PAM cannot check (for example, an
  account `pam_unix` cannot verify).
- The limit of 5 failed requests per minute stays, and counts only
  password rejections (not busy or rate-limited answers).

### D6. The `pam_aleph` protocol is a tiny binary crate, `aleph-pam-proto` — Accepted

It depends only on std and `zeroize`, and uses strict length-prefixed
frames. The module's forked child can read a reply without allocating.

### D7. `pam_aleph` delivers from a forked child running as the user — Accepted with changes

The child drops to the user's uid and gid (only when running as root),
calls only async-signal-safe functions, sends with `MSG_NOSIGNAL`, and has
an `alarm` backstop.
- **At auth** it delivers at once if `pam.sock` exists, and otherwise keeps
  the password (`pam_set_data`, zeroized) until session open.
- **At `passwd`** it delivers in the update phase, only when both the old
  and the new password are known.
- Every phase returns `PAM_IGNORE`.

Changes adopted:
- **The host's `SIGCHLD` disposition is never touched.** The child reports
  through a pipe; the parent waits on the pipe with the timeout, kills
  through a pidfd, and ignores `ECHILD` if the host reaped the child.
- **On a second login, delivering at auth unlocks before the `account` and
  `session` stacks run.** This is harmless (it is the user's own vault, and
  the password was right), and the spec records it.

### D8. `passwd` on a locked vault never unlocks it — Accepted with changes

The change works on a detached copy: it is opened with the old password,
changed, checked against the high-water mark, and written. It never
becomes the daemon's unlocked vault, so no Secret Service reader can use
it meanwhile.

### D9. lockoutAuth (Plan 4b) is not set through the TPM helper — Accepted with changes

Any local user can call the helper, so it gets no "set lockoutAuth"
request. On explicit opt-in, setup runs `sudo tpm2_changeauth -c lockout
file:-` itself, feeding the value on standard input, so it never appears
in `argv` or shell history. It shows the value once and asks for it to be
typed back. If the user declines, setup prints that command for them to
run.

### D10. Testing `pam_aleph` without root — Accepted

Three layers:
- unit tests of the module logic, against a fake PAM handle
- the forked delivery, against a real socket
- real Linux-PAM loading the built module through `pam_start_confdir`,
  with `pam_exec expose_authtok` setting `PAM_AUTHTOK` from the test's
  conversation

Left for Plan 6's root container:
- the privilege drop
- a `passwd` whose `pam_unix` update fails, which must change nothing

### D13. The final review of the executed Plan 4a branch: fixes and one re-scope

Nothing critical. Two important defects are fixed, each with a test that
failed first:
- **A login password did not end an open prompter conversation.** The
  prompter kept its dialog up, and cancelling it failed the app although
  the vault was open. Unlock conversations now check a few times a second
  and end, successfully, once the vault is unlocked some other way; an
  unlock that happened anyway counts as success.
- **A delivery that timed out at auth was retried at session open,** so a
  hung daemon could hold a login up for 10 s. Only a delivery that found
  no daemon is retried now.

**Re-scoped: locking with the screen on Omarchy.** Omarchy's lock
(`omarchy-system-lock`, a Quickshell session lock) never tells logind, so
`Session.Lock` never arrives there. The spec and docs now say so, and
point to `aleph lock` and the idle timeout meanwhile. How setup makes
Omarchy's lock reach alephd (a hook, a wrapper, or something upstream) is
a Plan 4b design question for its reviewer.

Minor fixes adopted:
- Nothing unlocks between `PrepareForSleep(true)` and the resume, so an
  open in flight cannot leave the vault open through a sleep. A keyring
  whose setup finishes then is written but left locked.
- `pam.sock` answers before bringing the Secret Service up to date, and
  survives accept errors.
- The logind watcher survives a failed `Inhibit` or a malformed signal.
- A `passwd` change retries once the other way if the vault was unlocked
  or locked meanwhile, and the detached write happens only while the vault
  is still locked.
- The hardware lock is not held across Argon2.
- Requests are encoded in exactly sized buffers.
- The forked child uses raw `setgroups`/`setgid`/`setuid` calls.

Left as they are: a FIDO2 touch holds the hardware for as long as it takes
(inherent), and a missing `aleph-check` still means the login stack is
trusted (D5; the spec names it).

### D12. The pre-execution review of the Plan 4a document: fixes adopted

The review of the plan and prototype found nothing critical, and six
important defects, all fixed, each with a test.

- **A login password waited behind a security key's PIN question** (the
  FIDO2 flow held the hardware lock while the prompter was asked). The lock
  is now held only for key operations.
- **"First open wins" could install an older copy** when the vault had been
  unlocked, written, and locked again in between (read as a rollback,
  hiding what was written). The late open now reopens the current file
  with its key, or asks to unlock again.
- **A `passwd` change after a login with the new password** (which had
  marked the old slot stale) failed. The change now opens the file with
  the previous password whatever the stale marks.
- **With PAM unable to vouch for the new password, a change never proved
  the old one,** so a same-user process could re-seal the vault under a
  password of its choosing. The old password must now open the file
  first.
- **`pam.sock` rate limiting could be bypassed with parallel connections,**
  and unauthenticated requests queued on the operation lock. Requests in
  flight now count against the limit (at most 5 at once), and the new
  password is checked before waiting.
- **The previous-password question could be asked more than twice per
  conversation.** Its budget now spans the conversation.

Minor fixes adopted:
- `Session.Lock` counts only when sent by logind's name owner (spoofing
  test).
- The forked child closes the host's descriptors, resets and unblocks
  `SIGALRM`, and exits rather than unwinding into the host.
- Without a pidfd, the timed-out child is killed and reaped by pid.
- A failed delivery at auth is retried at session open.
- The listener never replaces a socket something still serves.
- The pending-rotation mark is saved before the write.
- Template artifacts are gone from the plan text.

Deferred: once slots were marked stale by a `WrongUser` refusal, a later
unlock may still ask for the previous password. The case (someone else's
vault file) is rare, and the question is harmless.

### D11. Other points from the review, adopted

- **A login password from `pam.sock` does not queue behind an open
  prompter conversation.** It opens the vault at once. Whichever opens
  first is installed, and a later open is discarded, never installed over
  it. A `passwd` change still waits its turn.
- **Socket activation takes the descriptor named `pam`**
  (`FileDescriptorName=` in `alephd.socket`, `LISTEN_FDNAMES`), not just
  descriptor 3.
- **A password rejected through `pam.sock` is logged at warning level.**
  An outside password change then shows in the journal, as well as at the
  next interactive unlock.
