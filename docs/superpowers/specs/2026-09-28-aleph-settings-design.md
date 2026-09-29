# aleph manager: settings (Plan 5c) — design

- **Date:** 2026-09-28
- **Status:** Draft, awaiting the owner's review
- **Extends:** `docs/superpowers/specs/2026-09-28-aleph-manager-design.md`
  (the manager spec) and `docs/superpowers/specs/2026-09-26-aleph-design.md`
  §7 (the main spec). Where this document is more specific, it wins; the
  plan updates both to match.

## Intent

The owner changes aleph's day-to-day settings in the manager instead of
with `alephctl config set` or a text editor. Done means every setting
below has a control in the manager's `SETTINGS` screen, and changing
several alephd settings costs one confirmation.

| Group | File | Settings |
|---|---|---|
| VAULT (alephd) | `~/.config/aleph/config.toml` | `lock.on_suspend`, `lock.on_screen_lock`, `lock.idle_timeout`, `prompt.timeout` |
| DISPLAY (gui) | `~/.config/aleph/gui.toml` | `theme`, `scanlines`, `reveal_hold` (new) |

`prompt.program` stays out of the manager: a wrong value stops every
prompt from opening, including the one needed to put it right. It stays
settable with `alephctl config set`.

## Architecture

- **alephd: new admin method `SetConfigs(prompter: h, values: a{ss})`.**
  1. Refuses an empty map.
  2. Applies every pair to a copy of the current configuration with
     `Config::set`, before asking anything: a bad key or value is refused
     with the message `alephctl config set` gives, and nothing is asked
     or written.
  3. Runs `with_reauth` once. The operation text lists the changes, in
     key order: `Set lock.idle_timeout = 900, prompt.timeout = 600`.
  4. On success applies the pairs to the live configuration (as it is
     then, not the copy from step 2), saves the file once (the existing
     atomic write), and takes the new configuration into use: the lock
     policy and the prompter read it each time, so nothing restarts.

  All or nothing: if any pair fails in step 4, or the save fails, the
  live configuration and the file are unchanged. `SetConfig` stays as it
  is for `alephctl`.
- **The manager sends only the values that changed** from what it last
  read, so a setting changed meanwhile through `alephctl` is not put back.
- **`gui.toml` becomes writable.** `Settings` gains `Serialize`, a
  `reveal_hold` field (seconds; `0` means ask every time; at most `3600`;
  default `300`; a larger value in the file is read as `3600`), and
  `save(path)`: the same atomic write as alephd's (temp file, then rename,
  creating the directory). Saving rewrites the whole file, so comments in
  it are lost. A `gui.toml` that does not parse is never overwritten
  (below, "DISPLAY").
- **In `aleph-gui`:**
  - `store.rs`: two requests.
    - `Config`: reads the four keys with `GetConfig` and answers with a
      `StoreEvent::Config` (the values, or the error).
    - `SetConfigs(OwnedFd, BTreeMap<String, String>)`: calls `SetConfigs`
      with one end of a socketpair; the window answers on the other, as
      for `Reauth`. The store's `Done` reports the call (accepted or
      refused); the outcome of the confirmation and the save arrives on
      the socket, as `Done` for the window's confirmation.
  - `settings_page.rs` (new): the SETTINGS screen's state (the form, the
    presets, input checking) and drawing, so `manager.rs` does not grow
    much.
  - `reauth.rs`: the fixed `HOLD` becomes the `reveal_hold` setting,
    read at each check, so a shorter hold applies at once (a confirmation
    10 minutes old ends when 5 minutes is picked). `0` means no
    confirmation is ever held.
  - A successful `SetConfigs` also starts the reveal window: it is the
    same proof.

## The screen

```
┌──────────┬────────────────────────────────────────────────────┐
│ ALEPH    │ VAULT  // alephd                                   │
│ // VAULT │  Lock on suspend       [x]  (also covers hibernate)│
│          │  Lock on screen lock   [x]                         │
│ SECRETS  │  Idle lock             [ 15 min        ▾]          │
│ SETTINGS │  Prompt timeout        [ 5 min         ▾]          │
│          │                                                    │
│          │  Saving asks you to confirm it is you, once        │
│          │  (a FIDO2 touch or your login password).           │
│          │                               [CANCEL]  [SAVE]     │
│          │                                                    │
│          │ DISPLAY  // gui · changes apply now                │
│          │  Theme                 ( ) Auto  ( ) Neon          │
│          │  Scanlines             [x]                         │
│          │  Reveal confirmation   [ 5 min         ▾]          │
│          │   lasts                                            │
└──────────┴────────────────────────────────────────────────────┘
```

- **Sidebar:** `SECRETS` and `SETTINGS` (Admin, 5d, comes later).
  SETTINGS opens while the vault is locked: the values show (`GetConfig`
  needs no unlock) and DISPLAY works. Saving VAULT needs the vault open:
  alephd's re-authentication refuses a locked one. So while it is locked
  Save stays enabled, with a note beside the buttons, in the warning
  colour: `VAULT SEALED :: SAVE WILL UNLOCK FIRST`. Save then asks alephd to
  unlock (its usual prompt window) and, once the vault is open, starts the
  confirmation with the edits as they are then. The person authenticates
  twice: to unlock and to confirm (alephd's `SetConfigs` asks for its own
  fresh proof; that guard stays). If the unlock is dismissed or fails,
  nothing is saved, the edits stay, and the error line says so. (Found
  while planning: an earlier draft said the confirmation works locked; it
  does not.)

### VAULT

- Read with `Config` when the screen is opened and after each save;
  `LOADING…` until the values arrive.
- **Save** and **Cancel** are enabled only when the form differs from
  what was read. Cancel puts the read values back.
- **Idle lock:** Off, 5 min, 15 min, 30 min, 60 min, 4 h, Custom….
- **Prompt timeout:** 1 min, 5 min, 15 min, 30 min, Custom….
- **Custom…** shows a minutes field beside the list, checked as it is
  typed: whole minutes, `0` or more for the idle lock (`0` is Off),
  `1` to `1440` for the prompt timeout (alephd's 86 400 s cap). A bad
  value gets one line under the field (`whole minutes, 1 to 1440`) and
  Save is disabled until it is fixed.
- A value read that is not a preset shows as `Custom (N min)`, or
  `Custom (N s)` if it is not whole minutes; it is kept (not sent)
  unless changed.
- **Lock on suspend off** shows, while it is off: "the master key can
  reach a hibernation image unless swap is encrypted" (the warning
  `alephctl` gives).
- The line above Save: "Saving asks you to confirm it is you, once (a
  FIDO2 touch or your login password)."
- **Saving:** Save sends the changed values; the confirmation is drawn
  inside the manager with the prompter's screens, as for Show. On
  success the form is read again and the status line says
  `SETTINGS SAVED`. A refusal or a cancelled confirmation leaves the
  edits in the form and the reason in the error line.
- **Unsaved edits are kept** when the owner goes to SECRETS and back;
  they end with Save, Cancel, or closing the window.
- While a save or a read is running, the VAULT controls are disabled.
- `SetConfigs` closes its conversation without a message (a note would
  hold the confirmation on screen for 6 s); the window says
  `SETTINGS SAVED` itself. A save that fails after the confirmation
  (the file cannot be written) closes with alephd's message, which the
  window puts in the error line.
- With alephd not reachable (`LINK DOWN`), VAULT shows the status and is
  disabled; it is read again when the link returns.

### DISPLAY

- Each change is written to `gui.toml` at once and takes effect at once
  in the manager (theme, scanlines, the reveal hold); prompts read the
  file when they open.
- **Theme:** Auto (the current Omarchy theme where there is one, else
  Aleph neon) or Neon.
- **Scanlines:** on or off (off anyway when reduced motion is asked for;
  the control says so then).
- **Reveal confirmation lasts:** Every time, 1 min, 5 min, 15 min,
  30 min, 60 min. A value in the file that is not one of these shows as
  `Custom (N s)` and stays until another is picked.
- **A `gui.toml` that does not parse:** DISPLAY shows the file's error
  and a **Reset to defaults** button, and its controls are disabled until
  the file is fixed or reset (the manager runs on the defaults
  meanwhile). Reset writes the defaults.

## Errors

- A failed read (`GetConfig`): its reason in the VAULT section, with
  **Retry**.
- A refused or failed `SetConfigs`: alephd's message in the error line
  at the top of the window; the form keeps the edits.
- A failed `gui.toml` write (disk full, permissions): the error line
  says the change was not saved; the change stays in effect for this run,
  so the window shows what is in force.
- Nothing is dropped silently.

## Security

- The VAULT settings are guarded by alephd's own re-authentication; the
  manager's checks are for convenience only.
- The DISPLAY settings need no confirmation: they change the look and the
  reveal guard, which is a guard against a glance (§6), in a file the
  owner can edit anyway.
- Logs name the keys changed, never values (none of them secret, but the
  rule stays simple).

## Testing

- **alephd, `SetConfigs` through a scripted prompter:** accepted (all
  values written, one save, the live configuration changed with no
  restart); refused at the confirmation (nothing written); one bad value
  (refused before any question, nothing written); an empty map (refused);
  a locked vault (refused, nothing written).
- **The store against a real alephd** on a private bus: `Config` reads
  the values; `SetConfigs` changes them and the file.
- **Unit tests:** presets and custom values in both directions (a preset,
  custom minutes, a value not in whole minutes, Off); checking as typed;
  `Settings` save and load round trip with `reveal_hold`; a broken
  `gui.toml` never overwritten; the reveal hold at `0`, shortened, and
  capped at `3600`.
- **The window (kittest)** against a stand-in store: edit and Save (only
  the changed keys sent, the confirmation shown); Cancel; a bad custom
  value disables Save; the suspend warning; edits kept across screens;
  the locked and link-down states; DISPLAY changes write the file and
  redraw; the broken-file reset; snapshots in both themes.
- **Manual (testing.md):** change the idle lock and watch the vault lock;
  change the prompt timeout; Save with several changes asks once; theme
  and scanlines switch live; "Every time" asks at each Show; the values
  match `alephctl config get`.

## Decisions (for DECISIONS.md, the owner's)

- One Save for the VAULT settings, one confirmation, through a new
  `SetConfigs` admin method; the screen says so above Save.
- DISPLAY settings apply at once, with no Save and no confirmation.
- `prompt.program` is not in the manager.
- The reveal hold is a setting: Every time, 1, 5, 15, 30, or 60 minutes
  (default 5, at most 60).
- Idle lock and prompt timeout are presets plus custom minutes, checked
  as typed.
- A successful settings save also starts the reveal window.
