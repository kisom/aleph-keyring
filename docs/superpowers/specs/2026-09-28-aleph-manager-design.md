# aleph manager: the window and its secrets browser (Plan 5b) — design

- **Date:** 2026-09-28
- **Status:** Draft, awaiting the owner's review
- **Extends:** `docs/superpowers/specs/2026-09-26-aleph-design.md` §7
  "Manager" (the main spec). Where this document is more specific, it
  wins; the plan updates §7 to match.

## Intent

The owner browses and fixes secrets the way Seahorse lets them, and
wants aleph's configuration and administration in the GUI too. Done
means: Seahorse is no longer needed for day-to-day secrets, and the
manager opens from the Omarchy launcher.

The manager is built in three plans:

| Plan | Scope |
|---|---|
| **5b (this document)** | The window, the secrets browser, the launcher entry |
| 5c | Settings: alephd's `config.toml` (lock policy, prompt timeout) and the GUI's `gui.toml` (theme, scanlines; the reveal window, below) |
| 5d | Admin: status, keyslots (add TPM or security key, remove, retry), master-key rotation, recovery-key reissue and backup, through alephd's own re-authentication; restore, recover, `--from-bak` and `--accept-rollback` stay in `alephctl restore` |

Import from and export to gnome-keyring stay where Plan 4c put them
(`alephctl setup` and `setup --revert`, DECISIONS.md E3): not in the
manager, whatever §7 said.

## Architecture

- **`aleph-gui`** (no arguments) opens the manager; `aleph-gui prompt`
  is unchanged. Both share the theme (Omarchy's `colors.toml`, followed
  live, or Aleph neon), the scanlines, and the reduced-motion handling.
- **The manager is an ordinary Secret Service client,** as Seahorse is.
  It reaches secrets only through `org.freedesktop.secrets`, over an
  encrypted session; alephd gets no second path to secrets. (A new
  admin method listing items or returning secrets was considered and
  rejected: a non-standard route to secrets with its own review, and
  nothing gained.)
- **`aleph-secret-session`** (new crate, lib): the Secret Service session
  crypto, `plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`, both halves:
  `Session` (open, encrypt, decrypt) and `ClientDh`. Moved from
  `aleph-daemon/src/secret/session.rs` without a change in behavior; the
  daemon (its server side and its gnome-keyring import and export) and
  the GUI both use it. Depends on `aes`, `cbc`, `hkdf`, `sha2`,
  `num-bigint`, `getrandom`, `zeroize` (randomness from `getrandom`
  directly, where the daemon's module used `aleph-core`'s: the GUI does
  not need the vault crate).
- **Admin method `Reauth(prompter: h)`** (new): runs the
  re-authentication conversation the keyslot methods already use (a
  FIDO2 touch, or the login password checked with PAM and then through
  a TPM unseal or the login-password slot), and ends it with `Done`.
  Nothing else happens (it wraps the existing `Keyring::reauth`). It
  exists for the reveal guard.
- **In `aleph-gui`:**
  - `store.rs`: the Secret Service client, on its own thread with its
    own runtime, behind a `Store` trait (the screen tests use a
    stand-in). It opens the session, lists collections and items
    (label, attributes, created, modified; never secrets), fetches one
    secret on request, creates, edits, and deletes items, creates and
    deletes collections, asks alephd to unlock, and follows
    `CollectionCreated/Deleted/Changed` and `ItemCreated/Deleted/Changed`
    so the lists stay current. Results reach the window as events, like
    the prompter's link.
  - `manager.rs`: the window (below).
  - `clipboard.rs`: the Wayland clipboard behind a `Clipboard` trait.
    The copy is offered with the MIME hint `x-kde-passwordManagerHint:
    secret` (clipboard-history tools skip it) and cleared after 30 s if
    the clipboard still holds it.
  - `reauth.rs`: the reveal window's clock: confirmed within
    the `reveal_hold` setting (default 5 minutes), and not since a lock.
- **The launcher entry:** `packaging/aleph-gui.desktop` (Name `aleph`,
  GenericName `Keyring`, `Exec=aleph-gui`, `Icon=aleph`, Categories
  `Utility;Security;`), installed to `/usr/share/applications/`, with
  the icons from `assets/icons/` at the paths §8 lists
  (`hicolor/scalable/apps/aleph.svg`, `hicolor/24x24/apps/aleph.svg`,
  `hicolor/16x16/apps/aleph.svg`, `hicolor/symbolic/apps/aleph-symbolic.svg`).
  `packaging/install.sh` installs and uninstalls them.

## The window

```
┌──────────┬──────────────────────┬─────────────────────────────┐
│ ALEPH    │ [search…]            │ GitHub token                │
│ // VAULT │ ▸ Login (default)    │ service  github.com         │
│          │   GitHub token       │ user     kyle               │
│ SECRETS  │   Mail app password  │ created 2026-09-27 · mod …  │
│          │ ▸ work               │ secret   •••••••  [SHOW]    │
│          │                      │                     [COPY]  │
│          │ [+ ITEM] [+ FOLDER]  │ [EDIT] [DELETE]             │
└──────────┴──────────────────────┴─────────────────────────────┘
```

- **Sidebar:** `SECRETS` and `SETTINGS` (5c); Admin (5d) appears
  when built. App id `aleph`, resizable, remembers nothing between runs.
- **List:** collections as folders, each with its items, sorted by
  label; the default collection first and marked. The search box filters
  by label and by attribute values, over what is already fetched; it
  never fetches a secret.
- **Detail pane:** the label, the attributes (read-only), the created
  and modified times, and the secret as dots.
- **Words:** the prompter's style (DECISIONS.md H6): `ALEPH // VAULT`,
  `SECRETS`, statuses such as `VAULT SEALED` (locked), `LINK DOWN`
  (alephd not reachable). Buttons are plain words where a misread costs
  something: every delete confirmation is `Yes` / `No`, default No.

## What each action does

- **Show:** if not confirmed within the `reveal_hold` setting (default 5
  minutes; or since a lock),
  the re-authentication runs first, drawn inside the manager with the
  prompter's screens, and says what it is: "confirm it is you (any
  program running as you can read secrets; this only guards against a
  glance)". Then the secret is fetched and shown until another item is
  picked or the pane is left. A secret that is not UTF-8 text is not
  shown ("binary secret, N bytes"); it can still be copied.
- **Copy:** the same confirmation, then the secret goes to the clipboard
  (hint, 30 s) and is wiped from the manager's memory at once.
- **Edit:** the label and the secret become editable (the secret needs
  the confirmation: it is seen), with Save and Cancel. Attributes stay
  read-only: applications find their secrets by attributes, and an
  edited attribute orphans the entry.
- **New item:** a label, the secret, and optional attribute rows (key,
  value), in the chosen collection, stored with `xdg:schema =
  org.freedesktop.Secret.Generic`. The confirmation is not needed (no
  existing secret is revealed).
- **Delete an item:** the manager asks ("Delete 'GitHub token'?", `Yes` /
  `No`, default No), then deletes.
- **New and delete collection:** alephd already confirms these itself,
  through its prompt window (default No); the manager does not ask a
  second time. A new collection needs a label.
- **Locked keyring:** at start, or when the keyring locks while the
  manager is open, the lists are cleared (they are only readable while
  unlocked), the window shows `VAULT SEALED` and an Unlock button, which
  asks alephd to unlock through the ordinary Secret Service call (the
  usual prompt window opens). A lock also ends the reveal window and
  hides any shown secret.
- **Errors:** alephd not reachable (`LINK DOWN`, and it retries), a lock
  in the middle of an edit, a refused or failed save: one line at the
  top of the window, nothing dropped silently. An edit interrupted by a
  lock stays in its form and can be saved after the unlock.
- **Live updates:** items applications add, change, or delete appear
  without a refresh; the item on screen stays selected if it still
  exists.

## Security

- The manager holds a secret only while it is shown, edited, or being
  copied, in zeroizing buffers, wiped when the pane changes or the
  window closes. (egui makes its own copies while text is edited: §4
  "Memory hygiene", not guaranteed.)
- The process is not dumpable (`PR_SET_DUMPABLE`), like the prompter.
- The reveal confirmation is a guard against a glance, not security
  (§6): the manager says so where it asks.
- Logs name operations and counts, never secrets, labels, or attribute
  values.
- Text from other programs (labels, attribute keys and values,
  collection names) is shown without line breaks of its own and cut
  short in lists, as in the prompter (DECISIONS.md H2).

## Testing

- **`aleph-secret-session`:** alephd's session tests move with it, plus
  client-against-server round trips in both algorithms.
- **Unit tests:** the store's handling of events, search filtering, the
  reveal window (a test clock: within 5 minutes, after, after a lock),
  clipboard expiry (a test clock; cleared only if still ours).
- **The store against a real alephd** on a private bus (the existing
  test daemon): list, create, edit, delete, collections, the signals,
  the locked case, unlock through a scripted prompter.
- **`Reauth`:** accepted and refused, through a scripted prompter.
- **The window (kittest)** against a stand-in store and clipboard:
  click through show, copy, edit, new, and delete, the locked state, and
  errors; snapshots of each view in both themes.
- **Manual (testing.md):** open it from the launcher; browse the real
  items; show and copy (clipboard history skips it; it clears after
  30 s); edit a test item's label and secret; create and delete a test
  item and a test collection.

## Decisions (for DECISIONS.md, the owner's)

- The manager is split into 5b (window, secrets, launcher), 5c
  (settings), and 5d (admin). The launcher, too small for a plan of its
  own, is part of 5b.
- The manager is a Secret Service client (approach A); secrets reach it
  only through `org.freedesktop.secrets`.
- Attributes are read-only in the manager; new items take the
  attributes typed.
- A reveal confirmation holds for the `reveal_hold` setting (default 5 minutes;
  not since a lock).
- Import and export stay out of the manager.
