# Design decisions

Decisions made while the project owner was away, each proposed by the
implementer and ruled on by an independent reviewer (a fresh model
session with the spec and the code, and no part in writing them). Newest
first. The spec (`docs/superpowers/specs/2026-09-26-aleph-design.md`)
is updated to match wherever a decision changes it. Decisions the owner
made directly are marked as such.

## 2026-09-28: Plan 5a (the prompter), design

### H3. The pre-execution review of the Plan 5a document: fixes adopted

An independent review of the plan and its prototype. Adopted, each with a
test that failed without it:

- **Prompter trouble waits (Important).** With a working prompter, a
  prompt that timed out (the person away after an autologin boot; a
  background client while the screen is locked) dismissed the unlock, and
  a client like Chromium would take that as "no key", which §4 exists to
  prevent. Now `Error::Prompt` (timed out, closed or crashed before an
  answer, nonsense) leaves the prompt waiting like no prompter; the
  prompts that joined it wait too (this replaces the earlier test that
  had them end with it). Only Cancel dismisses. §4 says so.
- **A window that cannot open exits without answering (Important),** so
  alephd reads "no prompter" and the prompt waits. (The plan had it send
  Cancel, which would dismiss every unlock at once on a broken GL driver.)
- **Nothing holds the keyboard with nothing to ask (Important).** An
  unlock elsewhere and prompter trouble end the conversation with no
  message (the window just closes); any other closing message stays up
  for 20 seconds or until closed.
- **Task 6's document check** is limited to the spec, testing.md, the
  README, and the code (history mentions the old names).
- **Minor, adopted:** the field keeps the keyboard when Enter is pressed
  during a back-off; keys arriving in the first 400 ms of a screen are
  ignored; white-space runs collapse in text from other programs (and the
  claim is "no line breaks of its own"); the display must be a bare name,
  never a path; `aleph-gui` is non-dumpable; the Working and
  recovery-check screens have snapshots; `gsettings` gets a second; the
  first group field takes the keyboard on the check step; AccessKit is on;
  setup warns when the rule file is not installed; testing.md's new check
  joins step 3 instead of renumbering.
- **Rulings (not changed):** Cancel during "Touch your key" closes the
  window while alephd is inside the key's own wait (it reads the Cancel
  when that ends; a touch meanwhile still unlocks, which is what the
  person did) — cost if wrong: a surprising unlock after a Cancel.
  Confirmation prompts are not serialized like unlocks, so two can be
  open — cost if wrong: two pinned windows; a later plan can queue them.
  The window rule matches any app_id `aleph-prompt` — a same-user program
  can grab the keyboard in other ways; documented, not defended.
- **Found while executing:** a confirmation's text is laid out to the
  rows that fit above the buttons, ending in "…" (the snapshot review
  showed a long label reaching the button row; a label of capitals ran
  under it). Test: `a_long_confirmation_never_covers_the_buttons`.
- **Noted for later:** §4 says prompts that joined a *cancelled*
  conversation keep waiting; the code (since Plan 3) ends them with it.
  This plan does not change Cancel; the mismatch is left for its own fix.

### H2. Calls made while prototyping Plan 5a

For the reviewers; each is argued in the plan
(`docs/superpowers/plans/2026-09-28-aleph-prompter.md`, "Decisions made
while prototyping") and pinned by a test that was seen to fail without it.

- **The prompter's display comes from the user manager.** alephd is often
  started by `pam_aleph` during login, before Hyprland exists; its own
  environment then never has `WAYLAND_DISPLAY`, and every prompt would wait
  for `alephctl unlock` until alephd restarted. At each launch alephd reads
  the systemd user manager's `Environment` (uncached, 2 s limit), where the
  compositor exports the display, and uses its own environment only when
  the manager cannot be asked. No display there means no graphical session
  now, and the prompt waits (§4), as before. Only a bare socket name is
  accepted, never a path (any process of the user can set the manager's
  environment).
- **`~/.config/aleph/gui.toml`** holds the GUI's settings (`theme = "auto" |
  "neon"`, `scanlines`): alephd's `config.toml` refuses unknown keys and
  has no use for them. An unreadable file warns and uses the defaults.
- **Reduced motion** is GNOME's `enable-animations = false`, read with
  `gsettings` (absent: not requested). It turns off scanlines, spinners, and
  animations; the scanlines themselves never move.
- **Omarchy's palette:** `background`, `foreground`, and `accent` are
  required; the other keys are used when present, blends otherwise; a file
  that does not parse means Aleph neon. The watcher follows
  `~/.local/state/omarchy/current` recursively (Omarchy rewrites the
  theme's files in place).
- **A strict conversation:** `Begin` first; the recovery-key question is
  refused outside a recovery conversation (answered `Cancel`, no field
  shown); one answer per question; `Cancel` at any time. (Closing and
  timing out: H3.)
- **Text from other programs** (collection labels, process names, key
  names, errors) gets no line breaks of its own and is cut at 80 or 400
  characters.
- **Hyprland:** only the Lua configuration (Omarchy's) gets setup's offer;
  the include is `pcall(dofile, …)`, appended in place (a symlinked dotfile
  stays one) and removed exactly by revert. The rule floats, centers, pins,
  and keeps the keyboard on the prompt (`stay_focused`), so a password is
  never typed into another window; the prompt always ends (an answer,
  Escape, `prompt.timeout`, or 20 seconds for a closing message). A `hyprland.conf` user adds the rule by
  hand. The spec's `/usr/share/aleph/hypr/aleph.conf` becomes
  `/usr/share/aleph/hyprland/aleph-prompt.lua`.
- **Snapshot tests render with wgpu:** they need a GPU driver or Mesa's
  software Vulkan, and are regenerated (and looked at) on a new machine.
- **The terminal prompter's comment** said the GUI offers "skip" while
  waiting for a key; the protocol has no such answer, and the comment now
  says Cancel ends the operation in both.

### H1. Plan 5 is split: 5a the prompter, 5b the manager — owner's decision

After the first real setup, the missing graphical prompt was the gap met
every day: SDDM logs the owner in automatically, so after each boot the
keyring is locked, and applications asking for a secret waited for
`alephctl unlock` ("no prompter" in alephd's journal). Plan 5a is the
prompter alone (`aleph-gui prompt`, the Hyprland rule, setup's offer);
Plan 5b is the manager window (items, keyslots, settings, import and
export, "Recover…", the `.desktop` file and icons), which nothing waits on.

## 2026-09-27: Plan 4c (setup), design

### G5. The CLI is `alephctl` (owner's decision)

texlive-bin installs `/usr/bin/aleph` (the TeX engine): the first real
`aleph setup` ran it, and it crashed. A package could not own that path
either. The CLI binary is now `alephctl`, and so are the commands in its
messages, the Omarchy lock hook (which would otherwise have run TeX), and
the docs. The project, the crates, `alephd`, the vault's paths, and the
cryptographic labels (`"aleph recovery v1"` and the like, part of the
vault format) keep `aleph`. The first real run also showed that nothing
installed aleph: `packaging/install.sh` lays it out as the package will,
and the spec's install list now names `alephd`'s place
(`/usr/lib/aleph/`), the `io.aleph.Keyring` activation file,
`/etc/pam.d/aleph-check`, and the global enabling of `alephd.socket`.

The same run found alephd's password check failing under systemd
(PAM_AUTHINFO_UNAVAIL; `unix_chkpwd`: "user unknown"): the unit's
seccomp-based hardening (`LockPersonality`, `MemoryDenyWriteExecute`,
`RestrictRealtime`, `SystemCallArchitectures`) implies `NoNewPrivileges`
in a user unit, so the setuid helper could not read `/etc/shadow`. The
tests run alephd directly, never under systemd. Those options are gone;
a static test (`tests/units.rs`) keeps every option that implies
`NoNewPrivileges` out of the unit.

Setup's re-run offered the root step again and re-ran `sudo alephctl
system apply` (and its login-password check) although nothing had
changed; E10 says a re-run does only what is undone. Setup now reads the
manifest and the PAM files (world-readable) and skips the step when
every file is as apply writes it and recorded, pointing to `sudo
alephctl system verify` instead. Ruled: a run whose verification was
interrupted after apply counts as done then (the manifest does not
record verification); cost if wrong, broken stacks go unchecked until
`system verify` runs, with a TTY login and `system revert` as the way
back. Also checked: SDDM does read `autologin.conf.disabled` (this
boot's first session was `sddm-autologin`), so setup's autologin
detection stands.

### G4. The final review of the executed Plan 4c branch: fixes

Nothing critical: the forward path (`aleph setup`, then `sudo aleph
system apply`) has no lockout or data-loss path the reviewer could find.
Fixed, each with a test that failed first:
- **Revert's export could overwrite the wrong gnome-keyring item:**
  `SearchItems` matches items with at least the given attributes, and two
  aleph items with the same label and attributes shared one there. The
  export now matches exact attributes, lets each gnome-keyring item stand
  for one aleph item, updates in place only items the import brought (or
  one deleted and stored again under the same label and attributes), and
  reads every item back, the unchanged ones too.
- **gnome-keyring adds `xdg:schema: org.freedesktop.Secret.Generic`** to
  an item stored without one, at times after an import first read it:
  import and export treat that item as the same one (any other schema is
  another item), so it is neither duplicated nor missed.
- **Following gnome-keyring's updates raced** (a signal can run ahead of
  its data): the import itself now updates the items it brought, and
  setup runs one last import right before stopping gnome-keyring.
- **The TPM test flake's remaining cause:** the TPM library's sockets
  were inherited by every child the tests start (the `aleph` CLI, test
  dbus-daemons, gnome-keyring), which then held them open (seen with
  `ss`). Every such child, and alephd's private gnome-keyring, now starts
  with inherited descriptors close-on-exec.

Minor fixes adopted: the revert phase is saved with the unit record; the
rollback goes on past a missing backup and reports it; revert drops a
not-ordinary file's backup; when alephd claims the name at start is a
tested function; the emergency revert says to stop gnome-keyring before
`setup --revert`; the spec's backup wording matches the code.

Ruled, not fixed: a locked (second, password-protected) gnome-keyring
collection is left out of revert's collection lookup, so its items go to
the default collection; untested (a password-protected collection cannot
be made without a prompter). Deferred: writes stay paused if the CLI is
killed between the export and the switch back, until alephd restarts or
the revert is run again.

### G3. The pre-execution review of the Plan 4c document: fixes adopted

No path was found where the PAM edits make a correct password fail or a
wrong one pass. The safety net around them, and revert, had gaps; each
fixed with a test that failed first:
- **A service that cannot be transformed** stopped `apply` part way, with
  edits unrecorded. Every transformation is computed first (a missing
  anchor is manual mode), and each manifest entry is saved before its
  file is replaced.
- **A crash before the manifest** lost the original on a re-run; a re-run
  now trusts the backup. **A stale backup** (no manifest entry) could
  later bring back an old file; it is rewritten from the current file,
  and revert drops the backup of a file it leaves alone.
- **An interrupted password prompt skipped the check for good.** The
  password is asked before anything changes, and the check runs whenever
  anything is recorded; a failure rolls back everything recorded.
- **Revert deleted items aleph still held** (deleted and stored again), or
  let gnome-keyring's replace (attributes only) take an item with another
  label. Deletions come first and skip what aleph holds; a differing item
  is updated in place; new items never replace.
- **A revert that stopped after switching back got stuck** with writes
  paused; it records its phase and resumes at the release, and writes
  resume on every failure.
- **alephd could take the Secret Service back after a revert** (started by
  `pam.sock` with `pam_aleph` still in place): it claims the name only
  while setup's activation file exists; setup asks it to claim once it
  has written the file (`ClaimSecretService`).
- **Skipping the root step** leaves sddm's `pam_gnome_keyring auto_start`,
  which can start gnome-keyring behind alephd: setup says so, and the
  hardware checklist checks it.
- **A locked gnome-keyring collection** would be stranded by the
  switchover: setup stops before it unless the user says to go on.

Minor fixes adopted: gnome-keyring's updates to imported items are
followed until the switchover; item signals are taken before the name
change; the write freeze is checked under the keyring's lock; a failing
`systemctl` is an error, never a recorded "not-found" (the CLI tests use
a stand-in script); private and test buses have no service directories
(no real prompter can start); sudo is `/usr/bin/sudo`, and the
user-writable-binary warning comes before it; revert unlocks a locked
vault first; the lockout value may be typed without dashes; the emergency
manual revert no longer claims a missing backup means an unchanged file,
and reloads the bus.

Rulings on the rest: revert says what to remove rather than showing a
diff (E4's "diff"); on NixOS the user-level unit masking still happens
(it works there; E6 said it would be skipped); the lock screen, which
runs as the user, is checked by hand (the root-side check runs as root).


### G2. Calls made while prototyping Plan 4c

Each to be weighed by the plan's reviewers:
- **Import needs the vault unlocked** and no aleph prompter: gnome-keyring
  asks for its own locked collections through its own prompt (a dismissed
  one is skipped and listed), so the admin call just returns a summary.
- **What import added is recorded** (`imported.json`: id, collection,
  label, attributes), so revert can list items deleted in aleph since.
- **Revert's export needs the login password** (checked with PAM): it
  unlocks gnome-keyring's login keyring, which `pam_gnome_keyring` kept in
  step in `passwd` (E4). If it does not open with it, nothing changes.
- **"No gnome-keyring runs" is checked on the bus** (`org.gnome.keyring`
  owned, or the Secret Service name held by another), not by listing
  processes; the private instance gets a throwaway home and runtime
  directory, and only the keyring data directory is real.
- **Collections gnome-keyring lacks go into its default collection** on
  revert: creating one would need gnome-keyring's own password prompt.
- **E3's order holds as reviewed:** gnome-keyring, started while alephd
  holds the name, waits and takes it once alephd lets go (checked with
  the real gnome-keyring).
- **`aleph export gnome-keyring` is not a command:** export happens only
  in `setup --revert` (with the write freeze and the private instance).
- **Wizard defaults:** a question left unanswered (end of input) takes its
  default; the root step defaults to yes, and a failed or declined sudo
  does not fail setup (it says how to run it later); with autologin the
  default unlock method is a security key.
- **`aleph system verify` runs the lock-screen and login stacks** (never
  `passwd`, which would change the password).
- **Tests never reach the real system:** `ALEPH_SYSTEMCTL` and
  `ALEPH_SUDO` name stand-ins, and the CLI tests run with their own home.
- **Observed on this machine:** autologin detection (every file in
  `/etc/sddm.conf.d`, E5) reports `autologin.conf.disabled`'s user; if
  SDDM does read it, that file still turns autologin on.


### G1. Omarchy's screen lock reaches alephd through an upstream `lock` hook — owner's decision

Every Omarchy lock (key binding, menu, idle) runs the package-owned
`/usr/bin/omarchy-system-lock`, which never tells logind (D13) but
already locks 1Password. Omarchy runs user hooks from
`~/.config/omarchy/hooks/<name>.d/` (`omarchy-hook`), with no `lock`
hook yet.
- aleph proposes upstream a one-line `omarchy-hook lock` in
  `omarchy-system-lock` (drafted in Plan 4c's docs task, for the owner to
  send).
- Setup installs `~/.config/omarchy/hooks/lock.d/aleph`, running `aleph
  lock`: inert until Omarchy ships the hook, and removed by revert.
- Until then the idle timeout and sleep lock the vault. Rejected: a PATH
  wrapper shadowing the package's script (fragile), and leaving it
  unwired.

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

A third reviewer verified the four fixes correct and complete (and found
no TOCTOU: every proof is made on the bytes later installed), and raised
one question, ruled here:
- **Rewriting the high-water record while the daemon runs** (putting back
  an old mark, or an old `.pending` intent) makes an older vault read as
  current, and skips the proof. **Out of scope, as the spec says of the
  mark** ("not tamper-proof against an attacker who can also write
  `$XDG_STATE_HOME`"): a same-user process can restart `alephd` at will
  (`systemctl --user restart`), so an in-memory copy of the mark would
  only move the same attack past a restart. The TPM NV counter on the v2
  roadmap is the fix. For the same reason, `seen_vault` (fix 3) only
  raises the bar for a careless deletion; it is not a boundary.
- Deferred minors: re-authentication for `SetConfig` against an
  untrusted (planted, self-unlocked) vault passes with its own method
  (the attacker can edit the config file directly anyway); during a
  pending rotation, a `.bak` one write behind still holds the old
  login-password slot, so `--from-bak` accepts the old login password
  (which the threat model does not give the attacker).

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
