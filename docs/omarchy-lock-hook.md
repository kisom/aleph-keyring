# Proposed Omarchy change: a `lock` hook

aleph locks its keyring when the screen locks. On Omarchy every lock (the
key binding, the menu, and the idle service) runs `omarchy-system-lock`,
which does not tell logind, so aleph cannot see it. Omarchy already runs
user hooks (`omarchy-hook <name>` runs `~/.config/omarchy/hooks/<name>`
and `~/.config/omarchy/hooks/<name>.d/*`), so a `lock` hook lets any
program react, the way the script already locks 1Password.

The change, in `bin/omarchy-system-lock`, right after the screen is
locked:

```bash
omarchy-shell lock lock >/dev/null

# Let user hooks react to the lock (e.g. lock password managers).
omarchy-hook lock &
```

(`&`: a slow hook must never delay the lock.)

`aleph setup` installs `~/.config/omarchy/hooks/lock.d/aleph`, which runs
`aleph lock`; it does nothing until Omarchy runs the hook (DECISIONS.md
G1).
