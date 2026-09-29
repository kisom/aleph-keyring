# Proposed Omarchy change: a `lock` hook

aleph locks its keyring when the screen locks. On Omarchy the lock does not
go through logind, so aleph cannot see it. Omarchy already runs user hooks
(`omarchy-hook <name>` runs `~/.config/omarchy/hooks/<name>` and
`~/.config/omarchy/hooks/<name>.d/*`), so a `lock` hook lets any program
react, the way the lock script already locks 1Password.

**Status:** proposed upstream as omacom/omarchy PR #13513, open. Until
Omarchy ships it, the idle timeout and the sleep lock are what lock the
vault (DECISIONS.md G1).

## Where the hook runs

Not in `bin/omarchy-system-lock`, which was the first draft. That script
covers the key binding, the menu and the idle service, but suspend and
hibernate (the System menu entries, `systemctl suspend`, the lid) lock
through `omarchy-system-sleep-lock`, which calls the shell directly and never
runs `omarchy-system-lock`. A hook there would skip a menu suspend, which is
the case that matters most for a keyring.

Every new lock, from any of those paths, begins in `beginLock()` in
`shell/plugins/lock/Service.qml`, so the hook runs from there:

```qml
queueSessionLock()

// Let user hooks react to the lock (e.g. lock a keyring or password
// manager). Detached, so a slow hook never holds up the lock. Every new
// lock (key binding, menu, idle, suspend, lid) begins here, once.
Quickshell.execDetached(["omarchy-hook", "lock"])
```

- **Detached:** a slow hook must never delay the lock.
- **Once per lock:** `beginLock()` runs only when the session is not already
  locked, so a second call to `omarchy-system-lock`, or a sleep lock while
  locked, does not run the hook again.
- **Not on a refused lock:** it runs after the `missing-pam` check, so a lock
  the shell cannot perform runs nothing.
- **When:** the hook starts when the lock is requested, not once the session
  is secure. For aleph that is fine: locking the keyring a moment early does
  no harm.

The PR also adds a `lock` row to the hook table in the manual, a sample hook
(`lock.d/clear-gpg-passphrases.sample`), and a test
(`test/shell.d/lock-hook-test.sh`) that the hook runs from `beginLock()` and
from nowhere else.

`alephctl setup` installs `~/.config/omarchy/hooks/lock.d/aleph`, which runs
`alephctl lock`; it does nothing until Omarchy runs the hook.

Not tested on a live session: the change was checked by reading the code
paths and by the PR's tests, which run against stubs. The end-to-end check is
a menu suspend on an Omarchy that has the change: the aleph vault should be
locked when the session resumes.
