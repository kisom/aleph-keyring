# aleph manager: admin (Plan 5d) — design

- **Date:** 2026-09-28
- **Status:** Approved; implemented by docs/superpowers/plans/2026-09-28-aleph-admin.md
- **Extends:** `docs/superpowers/specs/2026-09-28-aleph-manager-design.md`,
  `docs/superpowers/specs/2026-09-28-aleph-settings-design.md` (Plan 5c),
  and `docs/superpowers/specs/2026-09-26-aleph-design.md` §6 and §7. Where
  this document is more specific, it wins; the plan updates the others to
  match.

## Intent

The owner looks after the vault's keyslots and custody from the manager
instead of `alephctl`. Done means the manager's `ADMIN` page shows the
keyslots and status, and does each of these with alephd's own
re-authentication: add a TPM or a security-key slot, remove a slot, retry
a stale one, rotate the master key, issue a new recovery key, and write a
backup.

**Out of the manager, on purpose:** restore, recover, `--from-bak` and
`--accept-rollback` stay in `alephctl restore`. They replace the vault,
they are what the owner reaches for when something is already broken, and
they need a file path and the recovery key: the terminal, with its plain
output, is the right place, and the daemon or the window may not be
trustworthy then. Import and export stay in `alephctl setup` and
`setup --revert` (DECISIONS.md E3). Lock and unlock need no page: LOCK is
in the sidebar, and unlock is alephd's prompt.

## Architecture

- **alephd: no change.** Every method the page needs exists: `Status`,
  `EnrollTpm`, `EnrollFido2(touch_only)`, `RemoveKeyslot(id)`,
  `RetryKeyslot(id)`, `RotateMaster`, `ReissueRecoveryKey` and
  `Backup(prompter, file)`. alephd already refuses the unsafe cases (a
  change that would leave only the recovery slot; a backup target that is
  not a new, empty, regular file; a backup inside aleph's own
  directories). The manager shows its refusals and does not repeat the
  checks.
- **`store.rs`: new requests**, each named for `Done` and the log:
  - `Status`: reads `Status` (JSON) and answers with
    `StoreEvent::Status(Result<AdminStatus, String>)`. `AdminStatus` and
    `SlotInfo` are small GUI-side structs (`Deserialize`, unknown fields
    ignored): vault present, locked, untrusted reason, memory-locked, TPM
    usable, slots (id, label, kind, created, stale), rotation pending,
    Secret Service owner.
  - Operations that converse take one end of a socketpair, as
    `SetConfigs` does: `AddTpm(fd)`, `AddFido2(fd, touch_only)`,
    `RemoveKeyslot(fd, id)`, `RotateMaster(fd)`, `ReissueRecovery(fd)`,
    `Backup(fd, file)`. The store's `Done` reports the call; the outcome
    arrives on the socket.
  - `RetryKeyslot(id)` has no conversation.
  - None of them forces a vault listing; STATUS is re-read instead.
- **`manager.rs`: one task state machine.** `saving_settings`, `pending`
  (the reveal's path and purpose) and `save_after_unlock` become one
  `Task`: `Reveal(path, want)`, `SaveSettings(changes)` or
  `Admin(AdminOp)`, with `AdminOp` one of `AddTpm`,
  `AddFido2 { touch_only }`, `Remove(slot)`, `RotateMaster`,
  `NewRecoveryKey`, `Backup(file)`. Its stages are idle, waiting (for the
  unlock of a sealed vault, or for the window to be in front),
  confirming, and finished. All three kinds share one path for the
  unlock-first step, the embedded confirmation, the wording after an
  interruption ("nothing was saved" when the person cancelled or alephd
  refused; "may not have gone through" when a lock, a link drop, focus
  loss or a closed socket ended it), and what happens on finish: a reveal
  fetches the secret, settings are read again, an admin operation reads
  STATUS again. **Behaviour the 5c tests pin does not change**: the
  refactor is guarded by them.
- **New files.**
  - `admin_page.rs`: the model and drawing (status text, slot rows, the
    Yes/No steps, the backup path field), like `settings_page.rs`. It
    never touches the store or the window.
  - `filepicker.rs`: a `FilePicker` trait, the real implementation
    (below) and a fake for tests.
  - `manager.rs` only wires them, and does not grow much.

## The screen

```
┌──────────┬────────────────────────────────────────────────────────┐
│ ALEPH    │ STATUS  // alephd                                      │
│ // VAULT │  vault  unlocked · secret service  alephd              │
│          │  TPM  usable · master key  locked in RAM               │
│ SECRETS  │  ! writes refused: rolled back to an older version     │
│ SETTINGS │  ! a password change is pending: rotate the master key │
│ ADMIN    │                                                        │
│          │ KEYSLOTS                                               │
│          │  tpm             tpm              2026-09-27  [REMOVE] │
│          │  yubikey         fido2            2026-09-27  [REMOVE] │
│          │  recovery        recovery         2026-09-26           │
│          │  login password  login-password   2026-09-27  STALE    │
│          │                                        [RETRY] [REMOVE]│
│          │  [+ TPM]  [+ SECURITY KEY]  [ ] touch alone            │
│          │                                                        │
│          │ KEEPING IT SAFE                                        │
│          │  [ROTATE MASTER KEY]  [NEW RECOVERY KEY]  [BACK UP…]   │
│ LOCK     │                                                        │
│ EXIT     │                                                        │
└──────────┴────────────────────────────────────────────────────────┘
```

One scrolling page with three sections; `ADMIN` is the sidebar's third
entry (after `SETTINGS`).

### STATUS

- Vault (none, locked, unlocked), the Secret Service owner (`alephd`,
  `another program` in the warning colour, or `nobody`), the TPM (usable,
  unavailable, or busy), and whether the master key is locked in RAM.
- Two warnings appear only when true, in the warning colour, each saying
  what to do:
  - `writes refused: <reason>`, pointing at `alephctl restore
    --accept-rollback` (restore stays in the terminal);
  - `a password change is pending: rotate the master key`, with a ROTATE
    MASTER KEY button beside it.
- With no vault at all it says so, points at `alephctl setup`, and
  disables everything below.
- STATUS and the slot list need no unlock: alephd reads them from the
  vault header.
- STATUS is read when the page opens, after every operation, when the
  vault locks or unlocks, and when the link returns. No timer.

### KEYSLOTS

- One row per slot: label, kind, created date, and STALE when marked.
- REMOVE is on every row except the recovery slot (that one is replaced
  by NEW RECOVERY KEY).
- RETRY is on stale rows. It is immediate: no confirmation, no unlock.
- `+ TPM` and `+ SECURITY KEY` add slots. The touch-alone checkbox
  carries the plain warning "anyone holding the key can unlock".

### The sealed vault

The action buttons stay enabled. One line above them, in the warning
colour: `VAULT SEALED :: ACTIONS ON THIS PAGE UNLOCK FIRST`. Each action
then asks alephd to unlock (its usual prompt), and starts its own
confirmation once the vault is open, as Save does (settings spec): two
proofs, and a dismissed or failed unlock does nothing. RETRY does not
unlock.

### Yes/No steps

Two operations are irreversible, and the manager asks first, drawn in the
page, with **No** the default and focused:

- REMOVE: "Remove keyslot '<label>'? This rotates the master key. The key
  can no longer unlock the vault."
- NEW RECOVERY KEY: "The current recovery key stops working as soon as the
  new one is issued."

Every other button goes straight to alephd's re-authentication, whose
prompt names the operation.

### BACK UP…

1. Open the portal's save dialog, suggesting `aleph-backup-<date>.aleph`.
   Cancelling does nothing.
2. Create the file with create-new and mode `0600`. An existing file that
   is not empty is refused with "choose a new name".
3. If the vault is sealed, unlock first.
4. Confirm (alephd's re-authentication).
5. Report `BACKED UP :: <path>`, with "It opens only with your recovery
   key."

**The dialog is a native save dialog through the XDG portal** (the `rfd`
crate), because that is what a person expects, at the price of a new
dependency (below). `rfd` cannot tell "no portal" from "cancelled", so the
manager decides beforehand: if `org.freedesktop.portal.Desktop` has no
owner on the session bus (or the dialog cannot be started), the page shows
the fallback instead: a text field prefilled with the suggested name in the
home directory, refusing an existing file, with a BACK UP button. With an
owner, a closed dialog is a cancel. A "type a path instead" link is always
offered. The dialog runs on its own thread, so the window never freezes.

### NEW RECOVERY KEY

The new key is shown once in the embedded confirmation (the prompter's
`ShowRecoveryKey` screen), then two of its groups are typed back. The
screen exists; the page draws it in place of its contents, as SETTINGS
does its confirmation. The manager never holds the key.

### While an operation runs

The confirmation replaces the page's contents and the sidebar's page
buttons are disabled, as for SETTINGS. When it ends, the status line says
what happened, in capitals like the rest: `KEYSLOT ADDED`,
`KEYSLOT REMOVED`, `MASTER KEY ROTATED`, `NEW RECOVERY KEY ISSUED`,
`BACKED UP`, or the reason it did not.

## Errors

- A failed STATUS read: its reason in the STATUS section, with **RETRY**;
  read again when the link returns.
- Link down: the page says `LINK DOWN` and its buttons are disabled.
- alephd refuses an operation: its message in the status line (for
  example "would leave only the recovery slot"); nothing else changes,
  and STATUS is read again.
- **Backup cleanup:** if the operation fails, is cancelled, or is
  interrupted after the manager created the file, the manager removes the
  file it created, but only while it is still empty. A half-made backup
  never sits at the path.
- Interruptions use the settings spec's wording ("may not have gone
  through") and read STATUS again, so the slot list shows what is really
  there.
- Nothing is dropped silently.

## Security

- The manager decides nothing: alephd re-authenticates every operation on
  this page, as it does for `alephctl`. The manager's Yes/No steps and
  checks are for convenience.
- The recovery key exists only inside the prompter's screens and is
  zeroized when they close. The manager never holds it, has no copy
  button for it, and never puts it on the clipboard.
- Backup files are created with mode `0600` and never overwritten.
- Logs name the operation only: no slot labels, no paths, no keys.
- **New dependency: `rfd`** (XDG-portal backend, which brings `ashpd`).
  The plan's first task is a spike that adds it and reads `cargo tree`.
  If it duplicates zbus or pulls in a heavy async runtime, the feature
  set is chosen to reuse what is there, and the owner is told before the
  work goes further. A build that cannot use the portal still has the
  typed-path fallback.

## Testing

- **Unit:** the `Task` state machine (each kind, the unlock-first step, the
  interruption wording); the `admin_page` model (status text, which rows
  get which buttons); the backup path checks (existing file, empty file,
  cleanup). The 5c tests guard the refactor.
- **The store against a real alephd** on a private bus with a scripted
  prompter: each operation (a slot added and removed, a stale slot
  retried, the master key rotated, the recovery key reissued, a real
  backup into a tempdir, a backup into aleph's own directory refused).
- **The window (kittest)** against a stand-in store and a fake
  `FilePicker`: the page in each state (normal, sealed, no vault,
  warnings, a stale row, link down); both Yes/No steps, No the default;
  the unlock-first flow for an operation; interruption wording; backup:
  a chosen path, cancelled, an existing file refused, portal absent so the
  typed-path field shows; empty-file cleanup after a failure.
- **Snapshots** in both themes: the page, the sealed page, the warnings, a
  Yes/No step, the typed-path field.
- **Manual (testing.md):** add and remove the test YubiKey (wrong-PIN
  checks are fine); rotate the master key; reissue the recovery key
  (record the new one first); a backup through the real portal, and one
  with the portal stopped.

## Decisions (for DECISIONS.md, the owner's)

- The admin page covers status, keyslots (add TPM or security key, remove,
  retry), master-key rotation, recovery-key reissue and backup. Restore,
  recover, `--from-bak` and `--accept-rollback` stay in `alephctl restore`.
- One scrolling page: STATUS, KEYSLOTS, KEEPING IT SAFE.
- The manager asks Yes/No (default No) only before REMOVE and NEW RECOVERY
  KEY; alephd's re-authentication guards everything.
- On a sealed vault an action unlocks first, then confirms: two proofs.
- Backup uses a native portal save dialog (`rfd`), with a typed-path
  fallback when the portal is unavailable; the file is new, `0600`, and
  never overwritten.
- One task state machine serves reveal, settings save and admin
  operations.
