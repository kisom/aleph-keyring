# aleph: Arch packaging and CI (Plan 6) — design

- **Date:** 2026-09-29
- **Status:** Draft, awaiting the owner's review
- **Extends:** `docs/superpowers/specs/2026-09-26-aleph-design.md` §8
  (packaging and distribution). Where this document is more specific, it
  wins; the plan updates §8 to match. NixOS (the flake and the
  `services.aleph` module, and `nix flake check`) is **not** in this
  document: it is its own later plan.

## Intent

aleph installs with `pacman` instead of `make install`, on Arch and
Omarchy, and a CI run proves on every push that it builds, installs, and
uninstalls the way the spec says. Done means: three `PKGBUILD`s (a
working-tree package for the owner's own machine, `aleph-keyring-git`, and
the release `aleph-keyring`), one install hook with a removal guard, one
script that builds and tests all three in an Arch container, and a GitHub
Actions workflow that runs the workspace gate, `cargo deny`, and that
script.

**Out of scope, for the owner:** cutting a `vX.Y.Z` tag, publishing to the
AUR (the account, the SSH key, the first push), moving the owner's machine
from the `install.sh` files to the package (steps are documented, and the
owner runs them with `sudo`), and everything NixOS.

## Packages

| Directory | Package | Source |
|---|---|---|
| `packaging/arch/local/` | `aleph-keyring-local` (`make pkg`) | a tarball of the working tree |
| `packaging/arch/aleph-keyring-git/` | `aleph-keyring-git` | `git+https://github.com/kisom/aleph-keyring.git` |
| `packaging/arch/aleph-keyring/` | `aleph-keyring` | the `vX.Y.Z` tag's tarball on GitHub |

- **`make pkg`** tars the working tree (tracked and untracked files, minus
  what `.gitignore` ignores, so no `target/`) into a build directory and
  runs `makepkg -f` there, as the user. `pkgver` is `0.1.0.r<commits>.g<hash>`,
  with `.dirty<YYYYMMDDHHMMSS>` (UTC) appended when there are uncommitted
  changes, so a rebuild of a changed tree gets a new version (dirty builds
  carry a timestamp). Install with `sudo pacman -U`. The package name is
  `aleph-keyring-local`, provides and conflicts as below.
- **`aleph-keyring-git`** derives `pkgver()` from `git describe` (the commit
  count and hash while there is no tag).
- **`aleph-keyring`** has `pkgver=0.1.0` and a `source` URL for the tag's
  tarball. Its checksum is a placeholder (`sha256sums=('SKIP')`, marked
  `# FILLED AT RELEASE`) in the repository until the owner tags;
  `make pkgbuild-release TAG=vX.Y.Z` downloads the tag's tarball, computes
  its checksum and writes it in. The AUR gets the file only after that.
  The test script builds this PKGBUILD against a `git archive` tarball with
  a computed checksum, so it is really built.

### Common to all three

- `pkgdesc`: A Rust Secret Service keyring backed by a TPM and FIDO2 keys.
  `url`: `https://github.com/kisom/aleph-keyring`. `license=('Apache-2.0')`.
  `arch=('x86_64')`. Maintainer line: `K. Isom <kyle@imap.cc>`.
- `depends=(tpm2-tss libfido2 pam dbus openssl hicolor-icon-theme wayland
  libxkbcommon libglvnd)` (`openssl`: alephd links `libcrypto`; `wayland`,
  `libxkbcommon`, `libglvnd`: `aleph-gui` loads `libwayland-client`,
  `libwayland-egl`, `libxkbcommon` and `libEGL` with `dlopen`;
  `hicolor-icon-theme`: the icons' directories);
  `makedepends=(rust clang pkgconf)` (`clang` because the workspace uses
  `bindgen`), plus `git` for `-git`.
- `provides=('org.freedesktop.secrets' 'aleph-keyring')`; `conflicts` with
  the other two variants; **no** `conflicts` with `gnome-keyring` (setup
  switches between them).
- `backup=('etc/pam.d/aleph-check')`. `options=('!debug')` (the release
  profile has no debug info, so a `-debug` package would be empty);
  `!lto` is not needed (the build works with makepkg's default `lto`).
- `build()`: `cargo build --release --workspace --locked`.
  `check()` does not run the test suite: it needs `swtpm` and takes minutes,
  and CI runs the full gate.
- `package()` installs exactly what `packaging/install.sh` installs, which
  is also §8's list:
  - `alephctl` and `aleph-gui` to `/usr/bin`; `alephd` and `aleph-tpmd` to
    `/usr/lib/aleph/`
  - `/usr/lib/security/pam_aleph.so` and `/etc/pam.d/aleph-check`
  - `/usr/share/dbus-1/services/io.aleph.Keyring.service` (only that name)
  - `/usr/lib/systemd/user/alephd.{service,socket}` and
    `/usr/lib/systemd/system/aleph-tpmd.{service,socket}`
  - `/usr/share/applications/aleph-gui.desktop` and the four icons
    (`hicolor/scalable`, `24x24`, `16x16`, `symbolic`)
  - `/usr/share/aleph/hyprland/aleph-prompt.lua`
  - `/usr/share/licenses/<pkgname>/LICENSE`, and `NOTICE` beside it
  - the removal-guard hook and its checker (below)
- `packaging/install.sh` stays, for machines that are not Arch; the layout
  is written once in the plan's file list and the test script compares the
  built package against it, so the two cannot drift silently.
- The `-git` and local variants build the same tree the release variant
  does, only the source differs: the `build()` and `package()` bodies are
  shared (one file, `packaging/arch/common.sh`, sourced by each PKGBUILD in
  the repository; the flattened AUR copies are generated by
  `make pkgbuild-aur`, which inlines it, because an AUR repository holds
  only the files in its own directory).

## The install hook

`packaging/arch/aleph-keyring.install` (symlinked into each package
directory, because `makepkg` reads `install=` from beside the PKGBUILD;
the AUR copies are flattened):

- **`post_install`:** `systemctl daemon-reload`;
  `systemctl enable --now aleph-tpmd.socket`;
  `systemctl --global enable alephd.socket`; then prints the next steps:
  as the user, `systemctl --user daemon-reload && systemctl --user start
  alephd.socket`, then `alephctl setup`.
- **`post_upgrade`:** `systemctl daemon-reload`, the same two idempotent
  `enable`s, and a message: "restart alephd to pick up the new binary:
  systemctl --user restart alephd.service" (a running `alephd` keeps the old
  binary).
- **`pre_remove`:** `systemctl --global disable alephd.socket`;
  `systemctl disable --now aleph-tpmd.socket aleph-tpmd.service`. These run
  before pacman deletes the files (and only if the removal guard did not
  abort), because by `post_remove` the unit files are gone and `systemctl
  disable` could fail or leave dangling `wants` symlinks.
- **`post_remove`:** `systemctl daemon-reload`; prints that the vault in
  `~/.local/share/aleph` is left in place. Failures of `systemctl` are
  reported and never fail the transaction.
- Every `systemctl` call is `|| true`-safe outside a booted systemd, and the
  message says so when it skipped a step (a chroot or a container).

## The removal guard

`/usr/share/libalpm/hooks/aleph-remove-guard.hook` is a `PreTransaction`
alpm hook with `AbortOnFail` (`Operation = Remove`, `Target =
aleph-keyring*`, `NeedsTargets` off), which runs
`/usr/lib/aleph/remove-guard` (a POSIX `sh` script). It exits non-zero, and
so aborts the removal, when either holds:

- `/var/lib/aleph/manifest.json` exists: the PAM changes are still in place,
  and removing `pam_aleph.so` under them could break logins;
- any local user's
  `~/.local/share/dbus-1/services/org.freedesktop.secrets.service` names
  `/usr/lib/aleph/alephd`: aleph still serves the Secret Service, and
  removing it would leave applications with nothing behind the bus name.
  (Users are `getent passwd` entries with a home directory that exists.)

On refusal it prints what to run first: `alephctl system revert` (as root)
and `alephctl setup --revert` (as the user), as `install.sh uninstall`
does. It is not a scriptlet because a hook's `AbortOnFail` is the documented
way to abort a transaction.

**A limitation, recorded:** switching between `aleph-keyring` and
`aleph-keyring-git` removes one package to install the other, and the guard
may block that on a machine that is set up (whether pacman runs a `Remove`
hook for a conflict replacement is pinned by the container test, and the
documentation says what it found). Then the procedure is: revert, switch,
set up again.

## The package test

`packaging/arch/test-packages.sh` runs inside an `archlinux:base-devel`
container (CI, `make pkg-test` locally with `docker`, or on straylight). As
root it prepares an unprivileged `builder` user and installs the build
dependencies; then:

1. **Build** the local-tree, `-git` (against the working tree, as a
   `git+file://` source) and release (against a `git archive` tarball with a
   computed checksum) packages with `makepkg` as `builder`.
2. **Metadata:** for each package, `pacman -Qip` gives the `depends`,
   `provides` and `conflicts` the spec lists, and the license; the three
   refuse to install together.
3. **Files:** `pacman -Qlp` and the modes equal the list in the plan
   (paths, and 755 for binaries and the guard, 644 for the rest); nothing
   else is installed.
4. **Hook, with a stub `systemctl`** (a script on the path that records its
   arguments): `pacman -U` runs `post_install`, and the recorded calls are
   exactly the four in the spec, in order; a second `-U` of the same
   version runs `post_upgrade` and prints the restart message.
5. **Guard:** with a fake `/var/lib/aleph/manifest.json`, `pacman -R` fails
   and the package stays installed; likewise with a fake activation file
   for a test user; with both gone `-R` succeeds and `pre_remove`'s and `post_remove`'s calls
   are the spec's; the variant switch is exercised and its outcome recorded.
6. **`namcap`** on each PKGBUILD and each built package, if `namcap` is
   installed: its findings are printed as warnings and never fail the run.

## CI

`.github/workflows/ci.yml`, on push and pull request to `master`. Every job
runs in `archlinux:base-devel` (the target), and third-party actions are
pinned by commit SHA (this is a keyring):

- **gate:** installs `rust clang tpm2-tss libfido2 pam swtpm tpm2-tools
  pkgconf jq`, then `make gate` (fmt, clippy `-D warnings`, the whole suite
  including `swtpm`; the hardware tests are `#[ignore]`d).
- **deny:** `cargo deny check` (Arch package `cargo-deny`) with a new
  `deny.toml`: advisories on; crates.io as the only source (no git
  sources); a license allow-list derived from `Cargo.lock` (the plan lists
  the result for the owner's review); duplicate versions warn.
- **packages:** `packaging/arch/test-packages.sh`.

The first run on GitHub happens after the owner pushes; until then the same
three commands run locally in a container, and that is the evidence.

## Documentation

- `README.md`: an install section (`make pkg` and `sudo pacman -U`, the
  AUR names once published, then `alephctl setup`).
- `docs/testing.md`: the manual checks for the owner's machine: migrate from
  the `install.sh` files (`make uninstall` refuses while set up, so revert
  first; or `pacman -U --overwrite '/usr/*,/etc/pam.d/aleph-check'` over
  them), install the package, `alephctl setup`, log out and in, lock and
  unlock, `pacman -R` refused, revert, `pacman -R` accepted.
- `DECISIONS.md`: this document's decisions.
- The main spec's §8 is updated to the layout above, and says the NixOS
  half is a separate plan.

## Risks and open points

- **The Arch `rust` package must satisfy `rust-version = "1.98"`.** If the
  container's `rust` is older on some day, the build fails with a clear
  message; the fix is to wait or use `rustup` in the container.
- **A build in the container needs network** (crates.io). The test script
  uses `cargo build --locked` and does not vendor.
- **`AbortOnFail` and replacement removals** are pinned by the test, not
  assumed.
- **Publishing** the AUR packages is the owner's; nothing here contacts the
  AUR.

## Decisions (for DECISIONS.md, the owner's)

- Arch first; NixOS is a later plan.
- Three packages: a working-tree package (`make pkg`), `-git`, and the
  release; the release PKGBUILD's checksum is filled by a helper when the
  owner tags.
- The install hook enables `aleph-tpmd.socket` and, for every user,
  `alephd.socket`, as `install.sh` does; removal is guarded by a
  `PreTransaction` hook that refuses while the PAM changes or the Secret
  Service activation still point at aleph.
- The package build does not run the tests; CI does.
- CI runs in the Arch container; actions are pinned by SHA; `cargo deny`
  with crates.io as the only source.
