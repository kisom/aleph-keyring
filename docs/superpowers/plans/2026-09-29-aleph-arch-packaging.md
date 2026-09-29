# aleph Arch packaging and CI (Plan 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** aleph installs with `pacman`: three PKGBUILDs (a working-tree package for `make pkg`, `aleph-keyring-git`, the release `aleph-keyring`), one install hook with a removal guard, one script that builds and tests all three in an Arch container, and a GitHub Actions workflow (workspace gate, `cargo deny`, the package test).

**Architecture:** The layout is the one `packaging/install.sh` already installs. `packaging/arch/common.sh` holds the shared `build()` and `package()` bodies; each PKGBUILD sets its source and sources that file. The hook (`aleph-keyring.install`) enables the two sockets as `install.sh` does; removal is guarded by a `PreTransaction` alpm hook with `AbortOnFail` that runs `/usr/lib/aleph/remove-guard`. `packaging/arch/test-packages.sh` runs in an `archlinux:base-devel` container (docker here, straylight, or CI) and pins the file list, metadata, hook calls (with a stub `systemctl`) and guard behaviour.

**Tech Stack:** POSIX `sh` and bash (PKGBUILDs), pacman/makepkg/alpm hooks, docker with `archlinux:base-devel`, GitHub Actions, `cargo-deny`, GNU make.

**Spec:** `docs/superpowers/specs/2026-09-29-aleph-arch-packaging-design.md` (read it first). Extends `docs/superpowers/specs/2026-09-26-aleph-design.md` §8.

## Global Constraints

- Rebase and fast-forward only; never a merge commit. Do not push: the owner confirms pushes.
- Commit trailer, on every commit: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (use the trailer the session's system reminder gives if it differs). Commit messages go on the command line in **single** quotes (`-m '...'`, no apostrophes): AGENTS.md rule 7.
- AGENTS.md: no piping or heredocs into an interpreter, no nested quoting; write scripts with the editor tools and run them by path. Never `curl ... | sh`.
- **Nothing here touches the host system.** No `sudo`. Never run `pacman`, `makepkg -i`, `systemctl`, `alephctl` or the hooks on the host: the package test runs them only inside a docker container. `make pkg` builds a package on the host but never installs it. Tests use a stub `systemctl` and temporary directories; `make pkg-test` mounts the repository read-only.
- aleph is live on this host: do not restart alephd, reinstall, or edit live units. The owner runs `sudo pacman -U` himself.
- Keep the FIDO2 PIN out of every command, file and message.
- Copy rules (verbatim):
  - maintainer line: `# Maintainer: K. Isom <kyle@imap.cc>`
  - package description: `A Rust Secret Service keyring backed by a TPM and FIDO2 keys`
  - url `https://github.com/kisom/aleph-keyring`; `license=('Apache-2.0')`; `arch=('x86_64')`
  - `depends=(tpm2-tss libfido2 pam dbus)`; `makedepends=(rust clang pkgconf)` (plus `git` for `-git`)
  - `provides=('org.freedesktop.secrets' 'aleph-keyring')`; the three variants `conflicts` with each other; no `conflicts` with `gnome-keyring`
  - `backup=('etc/pam.d/aleph-check')`
  - the guard's refusal names `alephctl system revert` (as root) and `alephctl setup --revert` (as the user)
  - the upgrade message: `restart alephd to pick up the new binary: systemctl --user restart alephd.service`
- The package `check()` does not run the test suite. Actions in CI are pinned by commit SHA.
- Code style: shell scripts are `set -eu`, POSIX `sh` unless they are PKGBUILDs (bash); comments explain why; each script has a header saying what it is for and how to run it.
- `make gate` (fmt, clippy `-D warnings`, the full suite, plus the packaging shell tests from Task 1) must pass at the end of every task that says so.

## Review Focus

Each line has a test in the task named after it.

1. **The removal guard's false negatives and false positives**: a user whose home has spaces or does not exist, a user with an unreadable activation file, an activation file naming some other program, a manifest that is a directory or empty, and `getent` returning nothing. It must refuse only when aleph is still wired in, and never crash into silence. (Task 1)
2. **The hook outside a booted systemd** (a chroot, a container): no `systemctl`, or one that fails, must not fail the transaction, and the message must say which step was skipped; a second run must be idempotent. (Task 1)
3. **File-list drift**: `install.sh`, the PKGBUILD's `package()` and the expected list must agree; nothing else is installed; modes are right (755 for binaries, the guard and the PAM module; 644 for the rest). (Task 2)
4. **A placeholder checksum reaching the AUR**: `make pkgbuild-aur` must refuse the release package while its checksum is `SKIP`; `make pkgbuild-release` must write a real one. (Task 3)
5. **`make pkg` from a dirty tree**: the version says so (`.dirty`), a rebuild always upgrades (`pkgver` changes with the commit count and hash), and `target/` and ignored files never enter the tarball. (Task 2)

---

## File Structure

- Create `packaging/arch/common.sh`: `aleph_build`, `aleph_package` (sourced by each PKGBUILD).
- Create `packaging/arch/aleph-keyring.install`: the hook (`post_install`, `post_upgrade`, `pre_remove`, `post_remove`).
- Create `packaging/arch/remove-guard`: the checker (installed as `/usr/lib/aleph/remove-guard`).
- Create `packaging/arch/aleph-remove-guard.hook`: the alpm hook (installed to `/usr/share/libalpm/hooks/`).
- Create `packaging/arch/local/PKGBUILD`, `packaging/arch/aleph-keyring-git/PKGBUILD`, `packaging/arch/aleph-keyring/PKGBUILD` (and a symlink `aleph-keyring.install` in each directory, plus `common.sh`).
- Create `packaging/arch/files.expected`: the canonical file list (mode and path).
- Create `packaging/arch/make-pkg.sh` (`make pkg`), `pkgbuild-release.sh` (`make pkgbuild-release`), `pkgbuild-aur.sh` (`make pkgbuild-aur`), `test-packages.sh` (`make pkg-test`).
- Create `packaging/arch/tests/hook-test.sh` and `guard-test.sh` (host-safe shell tests) and `release-test.sh`.
- Create `.github/workflows/ci.yml` and `deny.toml`.
- Modify `Makefile` (targets `pkg`, `pkg-test`, `pkg-shell-test`, `pkgbuild-release`, `pkgbuild-aur`; `gate` runs `pkg-shell-test`), `README.md`, `docs/testing.md`, `DECISIONS.md`, the main spec §8, the packaging spec Status, `packaging/install.sh` header comment.

---

### Task 1: The install hook and the removal guard

**Files:**
- Create: `packaging/arch/aleph-keyring.install`, `packaging/arch/remove-guard`, `packaging/arch/aleph-remove-guard.hook`
- Create: `packaging/arch/tests/hook-test.sh`, `packaging/arch/tests/guard-test.sh`
- Modify: `Makefile` (`pkg-shell-test`; `lint` also runs `sh -n` on the new scripts; `gate: lint test pkg-shell-test`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `remove-guard` (POSIX sh): exits 0 (allow) or 1 (refuse, with a message on stderr). Reads `ALEPH_STATE_DIR` (default `/var/lib/aleph`) and `ALEPH_PASSWD_CMD` (default `getent passwd`), for the tests.
  - `aleph-keyring.install`: functions `post_install`, `post_upgrade`, `pre_remove`, `post_remove`, using `systemctl` from the `PATH` and printing to stdout/stderr; never returning non-zero.
  - `aleph-remove-guard.hook`: the alpm hook.
  - `make pkg-shell-test`: runs both shell tests.

- [ ] **Step 1: Write the failing guard test**

Create `packaging/arch/tests/guard-test.sh`:

```sh
#!/bin/sh
# Tests for packaging/arch/remove-guard, run on any host: a temporary state
# directory and a fake passwd file stand in for /var/lib/aleph and getent.
#   sh packaging/arch/tests/guard-test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
guard="$here/../remove-guard"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

# A fresh world: no manifest, one user with a home and no activation file.
world() {
    rm -rf "$tmp/state" "$tmp/homes" "$tmp/passwd"
    mkdir -p "$tmp/state" "$tmp/homes/alice/.local/share/dbus-1/services"
    printf 'alice:x:1000:1000::%s/homes/alice:/bin/sh\n' "$tmp" >"$tmp/passwd"
}

run() {
    ALEPH_STATE_DIR="$tmp/state" ALEPH_PASSWD_CMD="cat $tmp/passwd" \
        sh "$guard" >"$tmp/out" 2>"$tmp/err"
}

expect_allow() {
    if run; then pass "$1"; else fail "$1 (refused: $(cat "$tmp/err"))"; fi
}
expect_refuse() {
    if run; then fail "$1 (allowed)"; else pass "$1"; fi
}

world
expect_allow "nothing is wired in: removal is allowed"

world
: >"$tmp/state/manifest.json"
expect_refuse "an (even empty) PAM manifest refuses"
grep -q "alephctl system revert" "$tmp/err" || fail "the refusal names alephctl system revert"

world
mkdir "$tmp/state/manifest.json"
expect_refuse "a manifest that is a directory still refuses (something is there)"

world
printf 'Name=org.freedesktop.secrets\nExec=/usr/lib/aleph/alephd\n' \
    >"$tmp/homes/alice/.local/share/dbus-1/services/org.freedesktop.secrets.service"
expect_refuse "a user whose Secret Service is aleph refuses"
grep -q "alephctl setup --revert" "$tmp/err" || fail "the refusal names alephctl setup --revert"
grep -q "alice" "$tmp/err" || fail "the refusal names the user"

world
printf 'Name=org.freedesktop.secrets\nExec=/usr/bin/gnome-keyring-daemon\n' \
    >"$tmp/homes/alice/.local/share/dbus-1/services/org.freedesktop.secrets.service"
expect_allow "an activation file naming another program allows"

# (Review Focus 1.) A home with spaces, one that does not exist, one that is
# empty, an unreadable file, and an empty passwd.
world
mkdir -p "$tmp/homes/bob smith/.local/share/dbus-1/services"
printf 'bob:x:1001:1001::%s/homes/bob smith:/bin/sh\n' "$tmp" >>"$tmp/passwd"
printf 'Exec=/usr/lib/aleph/alephd\n' \
    >"$tmp/homes/bob smith/.local/share/dbus-1/services/org.freedesktop.secrets.service"
expect_refuse "a home with a space in its name is read"
grep -q "bob" "$tmp/err" || fail "the refusal names bob"

world
printf 'carol:x:1002:1002::/nonexistent/carol:/bin/sh\ndave:x:1003:1003:::/bin/sh\n' >>"$tmp/passwd"
expect_allow "a home that does not exist, and an empty one, are skipped"

world
f="$tmp/homes/alice/.local/share/dbus-1/services/org.freedesktop.secrets.service"
printf 'Exec=/usr/lib/aleph/alephd\n' >"$f"
chmod 000 "$f"
if [ "$(id -u)" -ne 0 ]; then
    # An unreadable file cannot be read as aleph's: allow, but never crash.
    expect_allow "an unreadable activation file is not taken for aleph's"
fi
chmod 644 "$f"

world
: >"$tmp/passwd"
expect_allow "no users at all allows"

world
if ALEPH_STATE_DIR="$tmp/state" ALEPH_PASSWD_CMD="false" sh "$guard" >/dev/null 2>&1; then
    pass "a passwd command that fails does not refuse by itself"
else
    fail "a passwd command that fails does not refuse by itself"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
```

- [ ] **Step 2: Run it and watch it fail**

Run: `sh packaging/arch/tests/guard-test.sh`
Expected: it fails because `packaging/arch/remove-guard` does not exist (`sh: ... No such file`), so the first `expect_allow` reports `not ok` and the script exits 1.

- [ ] **Step 3: Write `remove-guard` and the hook file**

Create `packaging/arch/remove-guard` (mode 755 in git: `chmod +x`):

```sh
#!/bin/sh
# Refuse to remove aleph while it is still wired into the system. Run by
# aleph-remove-guard.hook before a transaction that removes the package
# (spec: docs/superpowers/specs/2026-09-29-aleph-arch-packaging-design.md).
#
#  - /var/lib/aleph/manifest.json exists: `alephctl system apply` edited
#    /etc/pam.d to call pam_aleph.so, and removing the module under those
#    lines could break logins.
#  - a user's Secret Service activation file names alephd: applications
#    would be left with nothing behind the bus name.
#
# ALEPH_STATE_DIR and ALEPH_PASSWD_CMD exist for the tests.
set -u

state_dir=${ALEPH_STATE_DIR:-/var/lib/aleph}
passwd_cmd=${ALEPH_PASSWD_CMD:-getent passwd}
refuse=0

if [ -e "$state_dir/manifest.json" ]; then
    echo "aleph: the PAM changes are still in place ($state_dir/manifest.json):" >&2
    echo "  run 'alephctl system revert' (as root) first" >&2
    refuse=1
fi

# (Command substitution, not a pipeline into `while`: the loop runs in a
# subshell, and only what it prints comes back.)
served=$($passwd_cmd 2>/dev/null | while IFS=: read -r user _ _ _ _ home _; do
    [ -n "$home" ] || continue
    file="$home/.local/share/dbus-1/services/org.freedesktop.secrets.service"
    if grep -qs /usr/lib/aleph/alephd "$file" 2>/dev/null; then
        echo "$user"
    fi
done)

if [ -n "$served" ]; then
    for user in $served; do
        echo "aleph: $user still has aleph serving the Secret Service:" >&2
    done
    echo "  as that user, run 'alephctl setup --revert' first" >&2
    refuse=1
fi

exit "$refuse"
```

Create `packaging/arch/aleph-remove-guard.hook`:

```
[Trigger]
Operation = Remove
Type = Package
Target = aleph-keyring*

[Action]
Description = Checking that aleph is no longer wired into the system...
When = PreTransaction
Exec = /usr/lib/aleph/remove-guard
AbortOnFail
```

- [ ] **Step 4: Run the guard test and watch it pass**

Run: `chmod +x packaging/arch/remove-guard && sh packaging/arch/tests/guard-test.sh`
Expected: PASS, every line `ok - ...`, exit 0. (The user whose name contains a space is a tricky one: `read -r ... home` keeps spaces because `IFS` is only `:`; if the space case fails, quote the way the loop reads it, not the test.)

- [ ] **Step 5: Write the failing hook test**

Create `packaging/arch/tests/hook-test.sh`:

```sh
#!/bin/sh
# Tests for packaging/arch/aleph-keyring.install, run on any host: a stub
# `systemctl` on the PATH records its calls, and nothing real is touched.
#   sh packaging/arch/tests/hook-test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
hook="$here/../aleph-keyring.install"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

bin="$tmp/bin"
mkdir -p "$bin"

stub_systemctl() { # $1: exit status the stub returns
    cat >"$bin/systemctl" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$tmp/calls"
exit $1
EOF
    chmod +x "$bin/systemctl"
}

# Run a scriptlet function in a fresh sh with only the stub on the PATH
# (plus the system's, for the shell's own tools), returning its output.
run() { # $1: function
    : >"$tmp/calls"
    PATH="$bin:/usr/bin:/bin" sh -c ". '$hook'; $1" >"$tmp/out" 2>"$tmp/err"
}

calls() { tr '\n' ';' <"$tmp/calls"; }

stub_systemctl 0

run post_install
[ "$(calls)" = "daemon-reload;enable --now aleph-tpmd.socket;--global enable alephd.socket;" ] \
    && pass "post_install reloads and enables both sockets, in order" \
    || fail "post_install calls: $(calls)"
grep -q "alephctl setup" "$tmp/out" && pass "post_install says what to do next" \
    || fail "post_install prints the next steps"

run post_upgrade
[ "$(calls)" = "daemon-reload;enable --now aleph-tpmd.socket;--global enable alephd.socket;" ] \
    && pass "post_upgrade re-runs the same idempotent enables" \
    || fail "post_upgrade calls: $(calls)"
grep -q "restart alephd to pick up the new binary: systemctl --user restart alephd.service" "$tmp/out" \
    && pass "post_upgrade says to restart alephd" \
    || fail "post_upgrade prints the restart message"

run pre_remove
[ "$(calls)" = "--global disable alephd.socket;disable --now aleph-tpmd.socket aleph-tpmd.service;" ] \
    && pass "pre_remove disables both sockets" \
    || fail "pre_remove calls: $(calls)"

run post_remove
[ "$(calls)" = "daemon-reload;" ] && pass "post_remove reloads" \
    || fail "post_remove calls: $(calls)"
grep -q ".local/share/aleph" "$tmp/out" && pass "post_remove says the vault is left in place" \
    || fail "post_remove mentions the vault"

# (Review Focus 2.) A systemctl that fails never fails the scriptlet, and
# each skipped step is named.
stub_systemctl 1
for fn in post_install post_upgrade pre_remove post_remove; do
    if run "$fn"; then
        pass "$fn returns success when systemctl fails"
    else
        fail "$fn failed the transaction when systemctl failed"
    fi
done
run post_install
grep -q "aleph-tpmd.socket" "$tmp/err" && pass "a failed enable names the socket" \
    || fail "a failed enable is reported (stderr: $(cat "$tmp/err"))"

# No systemctl at all (a chroot): success, and one message says so.
rm -f "$bin/systemctl"
for fn in post_install post_upgrade pre_remove post_remove; do
    if PATH="$bin:/usr/bin:/bin" sh -c ". '$hook'; $fn" >"$tmp/out" 2>"$tmp/err"; then
        pass "$fn returns success with no systemctl"
    else
        fail "$fn failed the transaction with no systemctl"
    fi
    grep -q 'systemctl is not available' "$tmp/err" && pass "$fn says systemctl was not available" \
        || fail "$fn is silent when systemctl is missing"
done

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
```

(The test assumes `/usr/bin:/bin` provide `sh`, `grep`, `command`. If the host has no `systemctl` under those directories the "no systemctl" case is real; if it has one, the stub in `$bin` shadows it in the other cases, and for the missing case the host's real `systemctl` would be found: in that final block set `PATH="$bin"` plus a directory holding symlinks to `sh` and `grep` only, so the real `systemctl` is not reachable. Do that.)

- [ ] **Step 6: Run it and watch it fail**

Run: `sh packaging/arch/tests/hook-test.sh`
Expected: FAIL: `aleph-keyring.install` does not exist, so `. '$hook'` errors and the first checks report `not ok`.

- [ ] **Step 7: Write `aleph-keyring.install`**

Create `packaging/arch/aleph-keyring.install`:

```sh
# The pacman install hook for aleph-keyring, aleph-keyring-git and
# aleph-keyring-local (spec: docs/superpowers/specs/2026-09-29-aleph-arch-packaging-design.md).
# It does what packaging/install.sh does after copying files. A failing
# systemctl is reported and never fails the transaction (a chroot or a
# container has none running), and every step is idempotent.

_aleph_systemctl() {
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "aleph: systemctl is not available: skipped 'systemctl $*'" >&2
        return 0
    fi
    systemctl "$@" || echo "aleph: 'systemctl $*' failed (an enable may still have taken effect): check it yourself" >&2
    return 0
}

_aleph_enable() {
    _aleph_systemctl daemon-reload
    _aleph_systemctl enable --now aleph-tpmd.socket
    _aleph_systemctl --global enable alephd.socket
}

post_install() {
    _aleph_enable
    echo "aleph: installed. As your user:"
    echo "  systemctl --user daemon-reload && systemctl --user start alephd.socket"
    echo "  alephctl setup"
}

post_upgrade() {
    _aleph_enable
    echo "aleph: restart alephd to pick up the new binary: systemctl --user restart alephd.service"
}

# (The disables run in pre_remove, while the unit files are still there:
# by post_remove pacman has deleted them.)
pre_remove() {
    _aleph_systemctl --global disable alephd.socket
    _aleph_systemctl disable --now aleph-tpmd.socket aleph-tpmd.service
}

post_remove() {
    _aleph_systemctl daemon-reload
    echo "aleph: removed. The vault in ~/.local/share/aleph is left in place."
}
```

- [ ] **Step 8: Run both shell tests and the Makefile wiring**

Add to `Makefile` (after the `lint` recipe) and update `gate`:

```make
# Shell tests for the package's hook and removal guard: they run on any
# host, with a stub systemctl and temporary directories.
pkg-shell-test:
	sh -n packaging/arch/aleph-keyring.install packaging/arch/remove-guard
	sh packaging/arch/tests/guard-test.sh
	sh packaging/arch/tests/hook-test.sh
```

change `gate: lint test` to `gate: lint test pkg-shell-test` and add `pkg-shell-test` to `.PHONY`. Also add `sh -n` lines for the two new test scripts to `lint`:

```make
	sh -n packaging/arch/tests/guard-test.sh packaging/arch/tests/hook-test.sh
```

Run: `make pkg-shell-test`
Expected: PASS: both scripts print only `ok - ...` lines and exit 0. (`sh -n` with several files checks only the first on some shells: run it once per file in the recipe if `dash` complains.)

- [ ] **Step 9: Commit**

```bash
chmod +x packaging/arch/remove-guard packaging/arch/tests/guard-test.sh packaging/arch/tests/hook-test.sh
git add packaging/arch Makefile
git commit -m 'feat(packaging): the pacman install hook and the removal guard' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 2: The working-tree package, `make pkg`, and the package test

**Files:**
- Create: `packaging/arch/common.sh`, `packaging/arch/local/PKGBUILD` (+ symlink `aleph-keyring.install`, `common.sh` copied by the scripts), `packaging/arch/files.expected`
- Create: `packaging/arch/make-pkg.sh`, `packaging/arch/test-packages.sh`
- Modify: `Makefile` (`pkg`, `pkg-test`), `.gitignore` if needed (`/target` already ignored: the build directory is `target/pkg/`)

**Interfaces:**
- Consumes: Task 1's `aleph-keyring.install`, `remove-guard`, `aleph-remove-guard.hook`.
- Produces:
  - `common.sh`: `aleph_build` (run in `build()`: `cargo build --release --workspace --locked` in `$_srcdir`) and `aleph_package` (run in `package()`: installs the files below into `$pkgdir` from `$_srcdir`; uses `$pkgname` for the license directory).
  - `make-pkg.sh local`: builds `target/pkg/aleph-keyring-local-<ver>-1-x86_64.pkg.tar.zst` from the working tree and prints its path.
  - `files.expected`: lines `<mode> <path>` (paths without a leading slash; the license lines use `%PKGNAME%`).
  - `test-packages.sh`: runs as root in an Arch container; exits 0 only if every check passes. Tasks 3 extends it.
  - `make pkg`, `make pkg-test`.

- [ ] **Step 1: Write `files.expected`**

Create `packaging/arch/files.expected`:

```
755 usr/bin/alephctl
755 usr/bin/aleph-gui
755 usr/lib/aleph/alephd
755 usr/lib/aleph/aleph-tpmd
755 usr/lib/aleph/remove-guard
755 usr/lib/security/pam_aleph.so
644 etc/pam.d/aleph-check
644 usr/share/aleph/hyprland/aleph-prompt.lua
644 usr/share/applications/aleph-gui.desktop
644 usr/share/icons/hicolor/scalable/apps/aleph.svg
644 usr/share/icons/hicolor/24x24/apps/aleph.svg
644 usr/share/icons/hicolor/16x16/apps/aleph.svg
644 usr/share/icons/hicolor/symbolic/apps/aleph-symbolic.svg
644 usr/lib/systemd/system/aleph-tpmd.service
644 usr/lib/systemd/system/aleph-tpmd.socket
644 usr/lib/systemd/user/alephd.service
644 usr/lib/systemd/user/alephd.socket
644 usr/share/dbus-1/services/io.aleph.Keyring.service
644 usr/share/libalpm/hooks/aleph-remove-guard.hook
644 usr/share/licenses/%PKGNAME%/LICENSE
644 usr/share/licenses/%PKGNAME%/NOTICE
```

(This is `packaging/install.sh`'s list plus the guard, its hook and the license files. If `install.sh` and this file disagree on the first 18 entries, that is a bug in one of them: fix the wrong one and say which.)

- [ ] **Step 2: Write `common.sh`**

Create `packaging/arch/common.sh` (sourced by each PKGBUILD inside `build()` and `package()`; `$_srcdir`, `$pkgdir`, `$pkgname` come from the PKGBUILD):

```bash
# Shared by the three PKGBUILDs: what to build and what to install. The
# layout is exactly packaging/install.sh's, plus the removal guard and the
# license files (spec: docs/superpowers/specs/2026-09-29-aleph-arch-packaging-design.md).

aleph_build() {
  cd "$_srcdir"
  export CARGO_TARGET_DIR=target
  cargo build --release --workspace --locked
}

aleph_package() {
  cd "$_srcdir"
  local r=target/release

  install -Dm755 "$r/alephctl" "$pkgdir/usr/bin/alephctl"
  install -Dm755 "$r/aleph-gui" "$pkgdir/usr/bin/aleph-gui"
  install -Dm755 "$r/alephd" "$pkgdir/usr/lib/aleph/alephd"
  install -Dm755 "$r/aleph-tpmd" "$pkgdir/usr/lib/aleph/aleph-tpmd"
  install -Dm755 packaging/arch/remove-guard "$pkgdir/usr/lib/aleph/remove-guard"
  install -Dm755 "$r/libpam_aleph.so" "$pkgdir/usr/lib/security/pam_aleph.so"
  install -Dm644 packaging/pam/aleph-check "$pkgdir/etc/pam.d/aleph-check"
  install -Dm644 packaging/hyprland/aleph-prompt.lua \
    "$pkgdir/usr/share/aleph/hyprland/aleph-prompt.lua"
  install -Dm644 packaging/aleph-gui.desktop "$pkgdir/usr/share/applications/aleph-gui.desktop"
  install -Dm644 assets/icons/aleph.svg "$pkgdir/usr/share/icons/hicolor/scalable/apps/aleph.svg"
  install -Dm644 assets/icons/aleph-24.svg "$pkgdir/usr/share/icons/hicolor/24x24/apps/aleph.svg"
  install -Dm644 assets/icons/aleph-16.svg "$pkgdir/usr/share/icons/hicolor/16x16/apps/aleph.svg"
  install -Dm644 assets/icons/aleph-symbolic.svg \
    "$pkgdir/usr/share/icons/hicolor/symbolic/apps/aleph-symbolic.svg"
  install -Dm644 -t "$pkgdir/usr/lib/systemd/system" \
    packaging/systemd/aleph-tpmd.service packaging/systemd/aleph-tpmd.socket
  install -Dm644 -t "$pkgdir/usr/lib/systemd/user" \
    packaging/systemd/alephd.service packaging/systemd/alephd.socket
  # (io.aleph.Keyring only: the Secret Service name's activation file is the
  # user's, written by `alephctl setup`, so gnome-keyring keeps it until then.)
  install -Dm644 packaging/dbus/io.aleph.Keyring.service \
    "$pkgdir/usr/share/dbus-1/services/io.aleph.Keyring.service"
  install -Dm644 packaging/arch/aleph-remove-guard.hook \
    "$pkgdir/usr/share/libalpm/hooks/aleph-remove-guard.hook"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 NOTICE "$pkgdir/usr/share/licenses/$pkgname/NOTICE"
}
```

- [ ] **Step 3: Write the local PKGBUILD and `make-pkg.sh`**

Create `packaging/arch/local/PKGBUILD`:

```bash
# Maintainer: K. Isom <kyle@imap.cc>
# A package of the working tree, for `make pkg` (packaging/arch/make-pkg.sh
# writes pkgver, and the tarball, into the build directory).
pkgname=aleph-keyring-local
pkgver=0.1.0
pkgrel=1
pkgdesc='A Rust Secret Service keyring backed by a TPM and FIDO2 keys'
arch=('x86_64')
url='https://github.com/kisom/aleph-keyring'
license=('Apache-2.0')
depends=(tpm2-tss libfido2 pam dbus)
makedepends=(rust clang pkgconf)
provides=('org.freedesktop.secrets' 'aleph-keyring')
conflicts=('aleph-keyring' 'aleph-keyring-git')
backup=('etc/pam.d/aleph-check')
install=aleph-keyring.install
source=("aleph-src.tar.gz")
sha256sums=('SKIP')   # the tarball is made by make-pkg.sh from the working tree

_srcdir="$srcdir/aleph-src"

build() {
  . "$startdir/common.sh"
  aleph_build
}

package() {
  . "$startdir/common.sh"
  aleph_package
}
```

Create `packaging/arch/make-pkg.sh`:

```sh
#!/bin/sh
# Build a package of the working tree (`make pkg`): tracked and untracked
# files that .gitignore does not ignore, so never target/. Builds in
# target/pkg/ as the current user and never installs anything; install the
# result yourself with `sudo pacman -U <path>`.
#   packaging/arch/make-pkg.sh local
set -eu

variant=${1:-local}
[ "$variant" = local ] || { echo "usage: make-pkg.sh local" >&2; exit 2; }

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
arch=packaging/arch

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
count=$(git rev-list --count HEAD)
hash=$(git rev-parse --short HEAD)
dirty=
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    dirty=.dirty
fi
# (pkgver may not contain a hyphen; the commit count and hash make every
# rebuild of a changed tree an upgrade.)
pkgver="$version.r$count.g$hash$dirty"

out=target/pkg/$variant
rm -rf "$out"
mkdir -p "$out"

# The working tree, as a tarball with one top directory (aleph-src).
git ls-files -z --cached --others --exclude-standard |
    tar --null -T - --transform 's,^,aleph-src/,' -czf "$out/aleph-src.tar.gz"

sed "s/^pkgver=.*/pkgver=$pkgver/" "$arch/local/PKGBUILD" >"$out/PKGBUILD"
cp "$arch/common.sh" "$arch/aleph-keyring.install" "$out/"

cd "$out"
makepkg -f --noconfirm -C
ls "$PWD"/aleph-keyring-local-*.pkg.tar.zst
```

(`makepkg` checks `makedepends` itself; the container test installs them first. The final line prints the package's path. The `sed` keeps `pkgrel=1`. `git ls-files -z ... | tar --null -T -` takes NUL-separated names.)

- [ ] **Step 4: Write the failing package test**

Create `packaging/arch/test-packages.sh` (run inside `archlinux:base-devel` as root, with the repository mounted at `/src`; writes only under `/work` and `/tmp`):

```sh
#!/bin/sh
# Build the aleph packages in a clean Arch container and check them (the
# spec's "The package test"). Run inside archlinux:base-devel as root:
#   docker run --rm -v "$PWD:/src:ro" archlinux:base-devel sh /src/packaging/arch/test-packages.sh
# (`make pkg-test` does exactly that.) Nothing on the host is touched.
set -eu

src=${ALEPH_SRC:-/src}
work=/work
export CARGO_HOME=/work/cargo
export CARGO_TARGET_DIR=/work/target

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }
check() { # check DESCRIPTION COMMAND...
    desc=$1
    shift
    if "$@" >/tmp/check.out 2>&1; then pass "$desc"; else
        cat /tmp/check.out >&2
        fail "$desc"
    fi
}

# --- environment: an unprivileged builder, the build dependencies, a copy of the tree
pacman -Syu --noconfirm --needed rust clang pkgconf git tpm2-tss libfido2 pam dbus namcap >/dev/null
id builder >/dev/null 2>&1 || useradd -m builder
mkdir -p "$work"
rm -rf "$work/tree"
mkdir -p "$work/tree"
# (The tree and its .git, but never target/: it can be tens of gigabytes.)
tar -C "$src" --exclude=./target -cf - . | tar -C "$work/tree" -xf -
# A dirty tree on purpose (Review Focus 5): an untracked file the package
# tarball must carry, and the version must say so.
echo marker >"$work/tree/untracked-marker.txt"
chown -R builder: "$work"
git config --global --add safe.directory '*'
su builder -c 'git config --global --add safe.directory "*"'

as_builder() { su builder -c "cd $work/tree && $*"; }

# --- stub systemctl: records its arguments (Task 2: hook; the container has no systemd)
mkdir -p /usr/local/bin
cat >/usr/local/bin/systemctl <<'SH'
#!/bin/sh
printf '%s\n' "$*" >>/tmp/systemctl.calls
SH
chmod +x /usr/local/bin/systemctl

# --- build the working-tree package (make pkg's own script, as builder)
as_builder 'CARGO_HOME=/work/cargo CARGO_TARGET_DIR=/work/target sh packaging/arch/make-pkg.sh local' >/tmp/pkg.path
pkg=$(tail -n 1 /tmp/pkg.path)
[ -f "$pkg" ] && pass "make pkg builds a package of the working tree" || fail "make pkg builds a package"
pkgname=aleph-keyring-local

# (Review Focus 5.) The tree was made dirty on purpose: the version says so,
# the tarball carries the untracked file and never target/ or .git.
case $pkg in
*.dirty-*|*.dirty.*) pass "a dirty tree gives a .dirty version" ;;
*) fail "a dirty tree gives a .dirty version (package: $pkg)" ;;
esac
tarball=$work/tree/target/pkg/local/aleph-src.tar.gz
tar -tzf "$tarball" >/tmp/tarball.list
grep -q '^aleph-src/untracked-marker.txt$' /tmp/tarball.list && pass "the tarball carries an untracked file" \
    || fail "the tarball carries an untracked file"
grep -q '^aleph-src/target/' /tmp/tarball.list && fail "the tarball must not contain target/" \
    || pass "the tarball never contains target/"
grep -q '^aleph-src/\.git/' /tmp/tarball.list && fail "the tarball must not contain .git" \
    || pass "the tarball never contains .git"
# A pkgver may not contain a hyphen (makepkg refuses it): the build succeeded.

# --- metadata
info=$(pacman -Qip "$pkg")
echo "$info" | grep -q '^Name *: aleph-keyring-local' && pass "the package name" || fail "the package name"
echo "$info" | grep -q '^Licenses *: Apache-2.0' && pass "the license" || fail "the license"
for dep in tpm2-tss libfido2 pam dbus; do
    echo "$info" | grep -q "^Depends On .*\\b$dep\\b" && pass "depends on $dep" || fail "depends on $dep"
done
echo "$info" | grep -q '^Provides .*org.freedesktop.secrets' && pass "provides org.freedesktop.secrets" \
    || fail "provides org.freedesktop.secrets"
echo "$info" | grep -q '^Conflicts With .*aleph-keyring-git' && pass "conflicts with the -git package" \
    || fail "conflicts with the -git package"
echo "$info" | grep -q 'gnome-keyring' && fail "must not mention gnome-keyring" || pass "no gnome-keyring conflict"

# --- files: exactly the expected list, and its modes
rm -rf /tmp/extract && mkdir /tmp/extract
bsdtar -xf "$pkg" -C /tmp/extract
(cd /tmp/extract && find . -type f ! -name '.PKGINFO' ! -name '.BUILDINFO' ! -name '.MTREE' ! -name '.INSTALL' \
    -printf '%m %P\n' | sort -k2) >/tmp/files.actual
sed "s/%PKGNAME%/$pkgname/" "$src/packaging/arch/files.expected" | sort -k2 >/tmp/files.want
if diff -u /tmp/files.want /tmp/files.actual >/tmp/files.diff; then pass "the file list and modes match files.expected"; else
    cat /tmp/files.diff >&2
    fail "the file list and modes match files.expected"
fi

# --- the hook, with the stub systemctl, through pacman
: >/tmp/systemctl.calls
pacman -U --noconfirm "$pkg" >/tmp/install.out 2>&1 || { cat /tmp/install.out >&2; fail "pacman -U installs the package"; }
want='daemon-reload;enable --now aleph-tpmd.socket;--global enable alephd.socket;'
got=$(tr '\n' ';' </tmp/systemctl.calls)
[ "$got" = "$want" ] && pass "post_install ran the spec's systemctl calls" || fail "post_install calls: $got"
grep -q 'alephctl setup' /tmp/install.out && pass "post_install printed the next steps" || fail "post_install printed the next steps"

: >/tmp/systemctl.calls
pacman -U --noconfirm "$pkg" >/tmp/upgrade.out 2>&1 || { cat /tmp/upgrade.out >&2; fail "pacman -U reinstalls"; }
grep -q 'restart alephd to pick up the new binary: systemctl --user restart alephd.service' /tmp/upgrade.out \
    && pass "post_upgrade printed the restart message" || fail "post_upgrade printed the restart message"

# --- the removal guard through pacman
mkdir -p /var/lib/aleph && : >/var/lib/aleph/manifest.json
if pacman -R --noconfirm aleph-keyring-local >/tmp/remove.out 2>&1; then
    fail "pacman -R must be refused while the PAM manifest exists"
else
    pass "pacman -R is refused while the PAM manifest exists"
fi
pacman -Q aleph-keyring-local >/dev/null 2>&1 && pass "the package is still installed after the refusal" \
    || fail "the package is still installed after the refusal"
grep -q 'alephctl system revert' /tmp/remove.out && pass "the refusal names alephctl system revert" \
    || fail "the refusal names alephctl system revert"
rm -f /var/lib/aleph/manifest.json

id tester >/dev/null 2>&1 || useradd -m tester
mkdir -p /home/tester/.local/share/dbus-1/services
printf 'Exec=/usr/lib/aleph/alephd\n' >/home/tester/.local/share/dbus-1/services/org.freedesktop.secrets.service
if pacman -R --noconfirm aleph-keyring-local >/tmp/remove2.out 2>&1; then
    fail "pacman -R must be refused while a user's Secret Service is aleph"
else
    pass "pacman -R is refused while a user's Secret Service is aleph"
fi
grep -q 'alephctl setup --revert' /tmp/remove2.out && pass "the refusal names alephctl setup --revert" \
    || fail "the refusal names alephctl setup --revert"
rm -f /home/tester/.local/share/dbus-1/services/org.freedesktop.secrets.service

: >/tmp/systemctl.calls
pacman -R --noconfirm aleph-keyring-local >/tmp/remove3.out 2>&1 && pass "pacman -R succeeds with nothing wired in" \
    || { cat /tmp/remove3.out >&2; fail "pacman -R succeeds with nothing wired in"; }
got=$(tr '\n' ';' </tmp/systemctl.calls)
want='--global disable alephd.socket;disable --now aleph-tpmd.socket aleph-tpmd.service;daemon-reload;'
[ "$got" = "$want" ] && pass "pre_remove and post_remove ran the spec's systemctl calls" || fail "removal calls: $got"

# --- namcap: warnings only
pacman -Qip "$pkg" >/dev/null && namcap "$pkg" >/tmp/namcap.out 2>&1 || true
[ -s /tmp/namcap.out ] && { echo "namcap (warnings only):"; cat /tmp/namcap.out; }

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
echo "all package checks passed"
```

(Task 3 adds the `-git` and release variants to this script.)

- [ ] **Step 5: Add the Makefile targets and run the test — it must fail first**

Add to `Makefile`:

```make
# A package of the working tree, built as the user in target/pkg (install it
# with `sudo pacman -U`; nothing is installed here).
pkg:
	packaging/arch/make-pkg.sh local

# Build and test the packages in a clean Arch container (needs docker; the
# repository is mounted read-only, nothing on the host is touched).
pkg-test:
	docker run --rm -v "$$PWD:/src:ro" archlinux:base-devel sh /src/packaging/arch/test-packages.sh
```

(add `pkg pkg-test` to `.PHONY`, and to the header comment). RED: before Step 3's PKGBUILD and `common.sh` exist the script cannot build. Since Step 3 already wrote them, prove the test can fail: temporarily delete one line from `files.expected` and run `make pkg-test`; expect `not ok - the file list and modes match files.expected` with a diff, then restore the line.

Run: `make pkg-test` (needs network for pacman and crates.io; the first run compiles the whole workspace inside the container and takes a while: run it in the background with output to a file and read its tail).
Expected: every check prints `ok - ...`, ending `all package checks passed`. If the build fails because the Arch `rust` is older than 1.98 or a `-sys` crate needs another system library, say exactly what and add the package to `depends`/`makedepends` (and the spec's list) rather than skipping the check.

- [ ] **Step 6: Commit**

```bash
git add packaging/arch Makefile
git commit -m 'feat(packaging): the working-tree package, make pkg, and the package test' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 3: The `-git` and release packages, the release and AUR helpers

**Files:**
- Create: `packaging/arch/aleph-keyring-git/PKGBUILD`, `packaging/arch/aleph-keyring/PKGBUILD` (each with a symlink `aleph-keyring.install` and `common.sh` symlinks to `../`)
- Create: `packaging/arch/pkgbuild-release.sh`, `packaging/arch/pkgbuild-aur.sh`, `packaging/arch/tests/release-test.sh`
- Modify: `packaging/arch/test-packages.sh` (build and check the two variants), `Makefile` (`pkgbuild-release`, `pkgbuild-aur`)

**Interfaces:**
- Consumes: Task 2's `common.sh`, `files.expected`, `test-packages.sh`, `aleph-keyring.install`.
- Produces:
  - `aleph-keyring-git/PKGBUILD`: source `aleph-src::git+https://github.com/kisom/aleph-keyring.git`, `pkgver()` = `<Cargo version>.r<commit count>.g<short hash>`; `depends`/`provides`/`conflicts` as the constraints say.
  - `aleph-keyring/PKGBUILD`: `pkgver=0.1.0`, `_url` and `source=("aleph-keyring-$pkgver.tar.gz::$_url/archive/refs/tags/v$pkgver.tar.gz")`, `sha256sums=('SKIP')  # FILLED AT RELEASE`.
  - `pkgbuild-release.sh <TAG>`: downloads the tag's tarball (or uses `ALEPH_RELEASE_TARBALL_URL` for tests), sets `pkgver` and the real `sha256sums` in `aleph-keyring/PKGBUILD`.
  - `pkgbuild-aur.sh`: writes `target/aur/<name>/{PKGBUILD,aleph-keyring.install,.SRCINFO}` with `common.sh` inlined; refuses the release package while its checksum is `SKIP`.
  - `make pkgbuild-release TAG=vX.Y.Z`, `make pkgbuild-aur`.

- [ ] **Step 1: Write the failing helper tests**

Create `packaging/arch/tests/release-test.sh`:

```sh
#!/bin/sh
# Tests for pkgbuild-release.sh and pkgbuild-aur.sh, host-safe: a local
# tarball stands in for GitHub's, and everything is written to a copy of the
# packaging directory.
#   sh packaging/arch/tests/release-test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
arch=$(cd "$here/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

# A scratch copy of packaging/arch (symlinks kept), so the real files stay put.
cp -a "$arch" "$tmp/arch"
tar -czf "$tmp/release.tar.gz" -C "$tmp" arch
sum=$(sha256sum "$tmp/release.tar.gz" | cut -d' ' -f1)

# (Review Focus 4.) The AUR generator refuses the release package while its
# checksum is a placeholder.
if grep -q "^sha256sums=('SKIP')" "$tmp/arch/aleph-keyring/PKGBUILD"; then
    if ALEPH_ARCH_DIR="$tmp/arch" ALEPH_AUR_OUT="$tmp/aur" \
        sh "$tmp/arch/pkgbuild-aur.sh" >"$tmp/out" 2>"$tmp/err"; then
        fail "pkgbuild-aur refuses the release package while its checksum is SKIP"
    else
        grep -qi "checksum" "$tmp/err" && pass "pkgbuild-aur refuses a SKIP checksum and says why" \
            || fail "the refusal explains the checksum"
    fi
else
    fail "the release PKGBUILD in the repository starts with the placeholder checksum"
fi

# pkgbuild-release writes the version and the real checksum.
ALEPH_ARCH_DIR="$tmp/arch" ALEPH_RELEASE_TARBALL_URL="file://$tmp/release.tar.gz" \
    sh "$tmp/arch/pkgbuild-release.sh" v0.1.7 >"$tmp/out" 2>"$tmp/err" \
    && pass "pkgbuild-release runs" || { cat "$tmp/err" >&2; fail "pkgbuild-release runs"; }
grep -q '^pkgver=0.1.7$' "$tmp/arch/aleph-keyring/PKGBUILD" && pass "pkgbuild-release sets pkgver" \
    || fail "pkgbuild-release sets pkgver"
grep -q "^sha256sums=('$sum')" "$tmp/arch/aleph-keyring/PKGBUILD" && pass "pkgbuild-release writes the tarball's checksum" \
    || fail "pkgbuild-release writes the tarball's checksum"
grep -q 'FILLED AT RELEASE' "$tmp/arch/aleph-keyring/PKGBUILD" && fail "the placeholder marker is gone once filled" \
    || pass "the placeholder marker is gone once filled"

# Now the AUR generator accepts it, and inlines common.sh.
ALEPH_ARCH_DIR="$tmp/arch" ALEPH_AUR_OUT="$tmp/aur" sh "$tmp/arch/pkgbuild-aur.sh" >"$tmp/out" 2>"$tmp/err" \
    && pass "pkgbuild-aur runs once the checksum is real" || { cat "$tmp/err" >&2; fail "pkgbuild-aur runs"; }
for name in aleph-keyring aleph-keyring-git; do
    f="$tmp/aur/$name/PKGBUILD"
    [ -f "$f" ] && pass "$name has a flattened PKGBUILD" || fail "$name has a flattened PKGBUILD"
    grep -q 'common.sh' "$f" && fail "$name's PKGBUILD no longer sources common.sh" || pass "$name inlines common.sh"
    grep -q '^aleph_build()' "$f" && grep -q '^aleph_package()' "$f" && pass "$name carries the shared functions" \
        || fail "$name carries the shared functions"
    [ -f "$tmp/aur/$name/aleph-keyring.install" ] && [ ! -L "$tmp/aur/$name/aleph-keyring.install" ] \
        && pass "$name has the install file as a real file" || fail "$name has the install file as a real file"
done
# The local package is not published.
[ ! -e "$tmp/aur/aleph-keyring-local" ] && pass "the local package is not generated for the AUR" \
    || fail "the local package is not generated for the AUR"

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
```

- [ ] **Step 2: Run it and watch it fail**

Run: `sh packaging/arch/tests/release-test.sh`
Expected: FAIL (the PKGBUILDs and both helper scripts do not exist yet: `grep` on a missing file, so the first check reports `not ok - the release PKGBUILD ... placeholder checksum`).

- [ ] **Step 3: The two PKGBUILDs**

Create `packaging/arch/aleph-keyring-git/PKGBUILD`:

```bash
# Maintainer: K. Isom <kyle@imap.cc>
pkgname=aleph-keyring-git
pkgver=0.1.0
pkgrel=1
pkgdesc='A Rust Secret Service keyring backed by a TPM and FIDO2 keys'
arch=('x86_64')
url='https://github.com/kisom/aleph-keyring'
license=('Apache-2.0')
depends=(tpm2-tss libfido2 pam dbus)
makedepends=(rust clang pkgconf git)
provides=('org.freedesktop.secrets' 'aleph-keyring')
conflicts=('aleph-keyring' 'aleph-keyring-local')
backup=('etc/pam.d/aleph-check')
install=aleph-keyring.install
source=("aleph-src::git+$url.git")
sha256sums=('SKIP')   # a git source has no checksum

_srcdir="$srcdir/aleph-src"

pkgver() {
  cd "$srcdir/aleph-src"
  local v
  v=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
  printf '%s.r%s.g%s' "$v" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
  . "$startdir/common.sh"
  aleph_build
}

package() {
  . "$startdir/common.sh"
  aleph_package
}
```

Create `packaging/arch/aleph-keyring/PKGBUILD`:

```bash
# Maintainer: K. Isom <kyle@imap.cc>
pkgname=aleph-keyring
pkgver=0.1.0
pkgrel=1
pkgdesc='A Rust Secret Service keyring backed by a TPM and FIDO2 keys'
arch=('x86_64')
url='https://github.com/kisom/aleph-keyring'
license=('Apache-2.0')
depends=(tpm2-tss libfido2 pam dbus)
makedepends=(rust clang pkgconf)
provides=('org.freedesktop.secrets')
conflicts=('aleph-keyring-git' 'aleph-keyring-local')
backup=('etc/pam.d/aleph-check')
install=aleph-keyring.install
source=("aleph-keyring-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')  # FILLED AT RELEASE by `make pkgbuild-release TAG=vX.Y.Z`

_srcdir="$srcdir/aleph-keyring-$pkgver"

build() {
  . "$startdir/common.sh"
  aleph_build
}

package() {
  . "$startdir/common.sh"
  aleph_package
}
```

Then, in each of the two new directories, make the shared files links (git stores symlinks): `ln -s ../aleph-keyring.install aleph-keyring.install` and `ln -s ../common.sh common.sh`; and give the local directory the same links (its PKGBUILD reads `$startdir/common.sh`, which `make-pkg.sh` also copies into the build directory): `packaging/arch/local/aleph-keyring.install` and `common.sh` as links too.

- [ ] **Step 4: `pkgbuild-release.sh` and `pkgbuild-aur.sh`**

Create `packaging/arch/pkgbuild-release.sh`:

```sh
#!/bin/sh
# Fill in the release PKGBUILD for a tag (`make pkgbuild-release TAG=v0.1.0`):
# set pkgver from the tag and the real sha256 of GitHub's tarball. Run it
# after the tag is pushed; it downloads to a temporary file and never runs
# what it downloaded. ALEPH_ARCH_DIR and ALEPH_RELEASE_TARBALL_URL are for
# the tests.
set -eu

tag=${1:-}
case $tag in
v[0-9]*) ;;
*) echo "usage: pkgbuild-release.sh vX.Y.Z" >&2; exit 2 ;;
esac
ver=${tag#v}

arch=${ALEPH_ARCH_DIR:-$(cd "$(dirname "$0")" && pwd)}
pkgbuild=$arch/aleph-keyring/PKGBUILD
url=${ALEPH_RELEASE_TARBALL_URL:-https://github.com/kisom/aleph-keyring/archive/refs/tags/$tag.tar.gz}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL -o "$tmp" "$url"
sum=$(sha256sum "$tmp" | cut -d' ' -f1)

# (Rewritten in place, keeping every other line as it is.)
sed -i \
    -e "s/^pkgver=.*/pkgver=$ver/" \
    -e "s/^pkgrel=.*/pkgrel=1/" \
    -e "s/^sha256sums=.*/sha256sums=('$sum')/" \
    "$pkgbuild"
echo "pkgbuild-release: $pkgbuild is now $ver, sha256 $sum"
```

Create `packaging/arch/pkgbuild-aur.sh`:

```sh
#!/bin/sh
# Generate the AUR copies (`make pkgbuild-aur`): one directory per published
# package under target/aur/, each holding a PKGBUILD with common.sh inlined
# (an AUR repository holds only the files in its own directory), the install
# file as a real file, and a .SRCINFO. Refuses the release package while its
# checksum is still the placeholder. The local package is never published.
# ALEPH_ARCH_DIR and ALEPH_AUR_OUT are for the tests.
set -eu

arch=${ALEPH_ARCH_DIR:-$(cd "$(dirname "$0")" && pwd)}
out=${ALEPH_AUR_OUT:-$arch/../../target/aur}

if grep -q "^sha256sums=('SKIP')" "$arch/aleph-keyring/PKGBUILD"; then
    echo "pkgbuild-aur: the release package's checksum is still SKIP: run" >&2
    echo "  make pkgbuild-release TAG=vX.Y.Z  (after pushing the tag) first" >&2
    exit 1
fi

for name in aleph-keyring aleph-keyring-git; do
    dir=$out/$name
    rm -rf "$dir"
    mkdir -p "$dir"
    # (The sourcing lines go; the functions they sourced come first.)
    {
        cat "$arch/common.sh"
        echo
        grep -v '^  \. "\$startdir/common.sh"$' "$arch/$name/PKGBUILD"
    } >"$dir/PKGBUILD"
    cp -L "$arch/aleph-keyring.install" "$dir/aleph-keyring.install"
    if command -v makepkg >/dev/null 2>&1; then
        (cd "$dir" && makepkg --printsrcinfo >.SRCINFO)
    fi
    echo "pkgbuild-aur: wrote $dir"
done
```

Note: the maintainer comment must stay the first line of a published PKGBUILD; move it to the top: build each file as `head -n 1 PKGBUILD`, then `common.sh`, then the rest of the PKGBUILD without its first line, so `# Maintainer:` is still first. Adjust the `{ ... }` block accordingly and keep the test's checks (`common.sh` gone, the two functions present) passing. Add the `Makefile` targets:

```make
# Fill in the release PKGBUILD for a pushed tag: make pkgbuild-release TAG=v0.1.0
pkgbuild-release:
	@test -n "$(TAG)" || { echo "usage: make pkgbuild-release TAG=vX.Y.Z" >&2; exit 2; }
	sh packaging/arch/pkgbuild-release.sh $(TAG)

# The AUR copies, flattened, in target/aur/.
pkgbuild-aur:
	sh packaging/arch/pkgbuild-aur.sh
```

(add both to `.PHONY`), and add `sh packaging/arch/tests/release-test.sh` (and `sh -n` for the three new scripts) to `pkg-shell-test`.

- [ ] **Step 5: Run the helper tests and watch them pass**

Run: `chmod +x packaging/arch/*.sh packaging/arch/tests/*.sh && sh packaging/arch/tests/release-test.sh`
Expected: PASS: every line `ok - ...`. (The scratch copy keeps symlinks, so `cp -L` in the generator follows them.)

- [ ] **Step 6: Extend the package test to the two variants**

In `packaging/arch/test-packages.sh`, before the `namcap` section, add: a function `check_variant NAME PKG` that runs the metadata and file-list checks of Task 2 for any package (refactor those checks into that function and call it for the local package), then build and check the other two:

- `-git`: `as_builder 'sh -c "cd packaging/arch/aleph-keyring-git && sed \"s|^source=.*|source=(\\\"aleph-src::git+file://$work/tree\\\")|\" PKGBUILD > /tmp/PKGBUILD.git ..."'` — simplest correct form: copy the PKGBUILD, `common.sh` and the install file to `$work/git-build/`, point its `source` at `git+file:///work/tree` (a committed tree: in the container, run `git -C $work/tree add -A && git -C $work/tree -c user.name=t -c user.email=t@t commit -qm test --allow-empty` first so uncommitted changes are included), run `makepkg -f --noconfirm` as `builder`, and check the result with `check_variant aleph-keyring-git`.
- release: `git -C $work/tree archive --prefix=aleph-keyring-0.1.0/ HEAD | gzip >$work/git-build/../release/aleph-keyring-0.1.0.tar.gz`, copy the release PKGBUILD, replace its `source=` line with the local file name and its `sha256sums=` line with the real checksum (`sha256sum`), build as `builder`, `check_variant aleph-keyring "$relpkg"`.
- **Co-install refusal:** `pacman -U --noconfirm "$pkg" "$gitpkg"` with both must fail (they conflict); `pacman -U` of the local package, then the `-git` one with `--noconfirm`, must not leave both installed (pacman asks to remove the conflicting one: with `--noconfirm` it answers no, so the second install fails: assert the failure and that only one is installed).
- **Variant switch under the guard** (the spec's recorded limitation): with the local package installed and a fake `manifest.json`, installing the `-git` package with `--ask=4` (auto-remove the conflict) — record the outcome in the test output as `note - variant switch under the guard: blocked|allowed` and do not assert either way; the plan's docs task copies what it printed into `docs/testing.md`.

Run: `make pkg-test`
Expected: every check `ok - ...`; the variant-switch note prints. RED first: comment out the release `sha256sums` replacement and see the release build fail on the checksum, then restore.

- [ ] **Step 7: Commit**

```bash
git add packaging/arch Makefile
git commit -m 'feat(packaging): the -git and release packages, and the release and AUR helpers' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 4: CI and `cargo deny`

**Files:**
- Create: `.github/workflows/ci.yml`, `deny.toml`
- Modify: `Makefile` (header comment only, `make deny` target)

**Interfaces:**
- Consumes: `make gate` (Task 1's addition included), `packaging/arch/test-packages.sh`.
- Produces: a workflow with jobs `gate`, `deny`, `packages`; a `deny.toml`; `make deny`.

- [ ] **Step 1: `deny.toml` — derive the license list from the tree**

Run `cargo deny --version` (install from Arch's `cargo-deny` package or `cargo install cargo-deny --locked` into a temporary `CARGO_HOME` under the worktree, never the host's global). Start from:

```toml
# cargo-deny policy (spec: docs/superpowers/specs/2026-09-29-aleph-arch-packaging-design.md).
[graph]
targets = [{ triple = "x86_64-unknown-linux-gnu" }]

[advisories]
version = 2
yanked = "deny"

[licenses]
version = 2
# Filled from `cargo deny check licenses` on Cargo.lock: only what the tree
# actually uses, reviewed by the owner.
allow = []
confidence-threshold = 0.9

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

Run `cargo deny check licenses 2>&1` and add each reported license identifier to `allow` (one at a time, only identifiers cargo-deny reports for crates in `Cargo.lock`; never a blanket list). Then `cargo deny check` must pass. If an advisory or a banned source is reported, do not silence it: stop with `NEEDS_CONTEXT` and the exact output (a real advisory is the owner's decision). Record the final `allow` list in the report for the owner's review.

Add to `Makefile`: `deny: ; cargo deny check` (`.PHONY`, header comment).

- [ ] **Step 2: Write the workflow**

Create `.github/workflows/ci.yml`. Pin every third-party action by the commit SHA of its current release (look each up with `gh api repos/actions/checkout/git/ref/tags/<latest tag>` and write the SHA with the tag as a comment; do not use `@v4`):

```yaml
name: ci

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

permissions:
  contents: read

# Every job runs in the Arch container: the target the package installs on.
jobs:
  gate:
    runs-on: ubuntu-latest
    container: archlinux:base-devel
    steps:
      - name: Install the build and test dependencies
        run: pacman -Syu --noconfirm --needed rust clang pkgconf git jq tpm2-tss libfido2 pam swtpm tpm2-tools
      - uses: actions/checkout@<SHA>  # <tag>
      - name: The gate
        run: |
          git config --global --add safe.directory "$GITHUB_WORKSPACE"
          make gate

  deny:
    runs-on: ubuntu-latest
    container: archlinux:base-devel
    steps:
      - name: Install cargo-deny
        run: pacman -Syu --noconfirm --needed rust cargo-deny git
      - uses: actions/checkout@<SHA>  # <tag>
      - name: cargo deny
        run: |
          git config --global --add safe.directory "$GITHUB_WORKSPACE"
          cargo deny check

  packages:
    runs-on: ubuntu-latest
    container: archlinux:base-devel
    steps:
      - name: Install git
        run: pacman -Syu --noconfirm --needed git
      - uses: actions/checkout@<SHA>  # <tag>
      - name: Build and test the packages
        run: |
          git config --global --add safe.directory "$GITHUB_WORKSPACE"
          ALEPH_SRC="$GITHUB_WORKSPACE" sh packaging/arch/test-packages.sh
```

(`test-packages.sh` runs as root and creates its own `builder` user; in CI the workspace is already the working copy, so `ALEPH_SRC` points at it. Replace `<SHA>` and `<tag>` with real values.)

- [ ] **Step 3: Validate the workflow without running it on GitHub**

Use `actionlint` (an Arch package) in the docker container: `docker run --rm -v "$PWD:/src:ro" archlinux:base-devel sh -c 'pacman -Sy --noconfirm actionlint >/dev/null && actionlint /src/.github/workflows/ci.yml'`. Expected: no output, exit 0. If `actionlint` is not packaged, say plainly in the report that the workflow's syntax is unchecked until the first run on GitHub.

- [ ] **Step 4: Run what CI will run, in the same container image**

Run: `make pkg-test` (already green from Task 3) and, in the container, `make gate`-equivalent: `docker run --rm -v "$PWD:/src:ro" archlinux:base-devel sh -c 'pacman -Syu --noconfirm --needed rust clang pkgconf git jq tpm2-tss libfido2 pam swtpm tpm2-tools make >/dev/null && cp -a /src /work && cd /work && git config --global --add safe.directory "*" && make gate'`
Expected: fmt, clippy `-D warnings` and the whole suite (including swtpm tests) pass in the container. If a test fails only in the container (a missing `/dev` node, a timing test), say which and whether it is environmental; do not skip it silently. Also run `make deny`.

- [ ] **Step 5: Commit**

```bash
git add .github deny.toml Makefile
git commit -m 'ci: the workspace gate, cargo deny, and the package test, in the Arch container' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

### Task 5: Documentation, decisions, and the gate

**Files:**
- Modify: `README.md`, `docs/testing.md`, `DECISIONS.md`, `packaging/install.sh` (header comment), `docs/superpowers/specs/2026-09-26-aleph-design.md` (§8), `docs/superpowers/specs/2026-09-29-aleph-arch-packaging-design.md` (Status)

**Interfaces:**
- Consumes: everything above.
- Produces: the docs and a green `make gate`.

- [ ] **Step 1: README**

Add an "Install" section to `README.md` before "Development", worded from what exists (read the file first and match its voice):

```markdown
## Install

On Arch or Omarchy, build a package of this checkout and install it:

    make pkg
    sudo pacman -U target/pkg/local/aleph-keyring-local-*.pkg.tar.zst

then, as your user, `systemctl --user daemon-reload && systemctl --user
start alephd.socket && alephctl setup`. The AUR packages `aleph-keyring`
and `aleph-keyring-git` are not published yet. `packaging/install.sh`
(`make install`) remains for other systems. Removing the package is
refused while `alephctl setup` and `alephctl system apply` are still in
effect: run `alephctl setup --revert` and `sudo alephctl system revert`
first. `make pkg-test` builds and tests all three packages in an Arch
container (needs docker).
```

- [ ] **Step 2: `docs/testing.md`**

Add a "The Arch packages (Plan 6)" section under the manual checks, from the spec, for the owner's machine (these need `sudo`; the owner runs them, none is automated):
1. `make pkg-test` passes (docker; record the variant-switch note it prints: paste its line here once known).
2. Migrate from the `install.sh` files: `sudo alephctl system revert`, `alephctl setup --revert`, `make uninstall`; or install over them with `sudo pacman -U --overwrite '/usr/*,/etc/pam.d/aleph-check' target/pkg/local/...`. Then `make pkg` and `sudo pacman -U`.
3. `systemctl --user daemon-reload; systemctl --user start alephd.socket; alephctl setup`; log out and in; lock and unlock; the manager opens.
4. `sudo pacman -R aleph-keyring-local`: refused, naming both commands; revert both; `-R` accepted; the vault in `~/.local/share/aleph` is still there.
5. `pacman -Ql aleph-keyring-local` matches `packaging/arch/files.expected`.

- [ ] **Step 3: `DECISIONS.md`, the main spec, the packaging spec, `install.sh`**

1. `DECISIONS.md`: read its newest entries for the letter and style (the last section is `J1`; use `K1`, newest first, above it) and add "Plan 6: Arch packaging and CI" with the spec's "Decisions" list, plus one line: "The package's removal guard is a `PreTransaction` alpm hook with `AbortOnFail`, not a scriptlet".
2. Main spec §8: change the Arch bullet to the layout the plan built (three packages: `aleph-keyring-local` via `make pkg`, `aleph-keyring-git`, `aleph-keyring`; the removal guard; `make pkg-test`; CI jobs `gate`, `deny`, `packages`) and add: "NixOS (the flake and module) is a separate plan; `nix flake check` joins CI with it."
3. Packaging spec `Status:` becomes `Approved; implemented by docs/superpowers/plans/2026-09-29-aleph-arch-packaging.md`.
4. `packaging/install.sh` header: replace "Until there is a package" with a line saying `make pkg` is the Arch way and this script stays for other systems.

- [ ] **Step 4: The gate**

Run: `make gate` on the host (fmt, clippy, the suite, the shell tests) in the background with output to a file under the worktree's `.superpowers/`, and read its tail. Then `make pkg-test` once more in the container. Expected: both green. If a run fails with `Disk quota exceeded` on `/tmp`, that is the machine's `/tmp` filling from other builds: do not delete other worktrees' or sessions' files; report it.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m 'docs: install section, manual checks and decisions for the Arch packages' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'
```

---

## Self-review

**Spec coverage.**
- Three packages (local via `make pkg`, `-git`, release), sources, `pkgver` rules, placeholder checksum + `make pkgbuild-release`: Tasks 2–3.
- Common metadata (depends, makedepends, provides, conflicts, backup, no gnome-keyring conflict), `build()` (locked release build), no `check()` suite, `package()` = `install.sh`'s layout plus guard and licenses: Task 2 (`common.sh`, `files.expected`, the test compares them).
- Shared body in `common.sh`, AUR flattening (`make pkgbuild-aur`), `.install` symlinks: Tasks 2–3.
- The install hook (`post_install`, `post_upgrade`, `pre_remove`, `post_remove`, systemctl failures never fail, messages): Task 1 (test with a stub `systemctl`, including no systemctl).
- The removal guard as an alpm `PreTransaction` hook with `AbortOnFail` + the checker (manifest, activation file for any user, messages naming both commands): Task 1 (script and its tests) and Task 2 (through pacman).
- The recorded variant-switch limitation: Task 3 (a note printed by the test), Task 5 (documented).
- The package test (build all three, metadata, files and modes, hook calls, guard, co-install refusal, namcap warnings): Tasks 2–3.
- CI (gate, deny with a new `deny.toml`, packages; pinned actions; the Arch container): Task 4. First GitHub run after the owner pushes: stated in the spec; the plan runs the same commands locally.
- Docs (README, testing.md, DECISIONS.md, §8, status): Task 5. Out of scope (tag, AUR publication, migration, NixOS): none of the tasks does them.

**Placeholders.** `<SHA>` and `<tag>` in the workflow are filled in Task 4 Step 2 (the step says how). The `allow = []` in `deny.toml` is filled in Step 1 (the step says how and forbids a blanket list). Task 3 Step 6 describes the `-git` and release builds in prose with the exact operations rather than one code block, because they extend a long script; the implementer writes them following that list. Two places name a fallback for a tool that could not be checked without running it (`actionlint`, `dash`'s `sh -n`).

**Type consistency.** File names, the `ALEPH_*` test variables (`ALEPH_STATE_DIR`, `ALEPH_PASSWD_CMD`, `ALEPH_ARCH_DIR`, `ALEPH_AUR_OUT`, `ALEPH_RELEASE_TARBALL_URL`, `ALEPH_SRC`), the package names (`aleph-keyring-local`, `aleph-keyring-git`, `aleph-keyring`), the make targets (`pkg`, `pkg-test`, `pkg-shell-test`, `pkgbuild-release`, `pkgbuild-aur`, `deny`), and the expected `systemctl` call strings are used identically in every task that names them.
