#!/bin/sh
# Build the aleph packages in a clean Arch container and check them (the
# spec's "The package test"). Run inside archlinux:base-devel as root:
#   docker run --rm -v "$PWD:/src:ro" archlinux:base-devel sh /src/packaging/arch/test-packages.sh
# (`make pkg-test` does exactly that, and also mounts a git worktree's
# shared git directory read-only at its own path.) Nothing on the host is
# touched: this writes only under /work, /tmp and the container's system.
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
# (Three tries: a mirror that drops the connection fails the whole transaction.)
for try in 1 2 3; do
    if pacman -Syu --noconfirm --needed rust clang pkgconf git tpm2-tss libfido2 pam dbus namcap >/dev/null; then
        break
    fi
    [ "$try" -lt 3 ] || { echo "test-packages.sh: pacman could not install the build dependencies" >&2; exit 1; }
    echo "test-packages.sh: pacman failed (try $try of 3), trying again" >&2
done
echo "rustc in the container: $(rustc --version)"
id builder >/dev/null 2>&1 || useradd -m builder
git config --global --add safe.directory '*'
su builder -c 'git config --global --add safe.directory "*"'
mkdir -p "$work"
rm -rf "$work/tree"
mkdir -p "$work/tree"
# (The tree and its .git, but never target/: it can be tens of gigabytes.)
tar -C "$src" --exclude=./target -cf - . | tar -C "$work/tree" -xf -
if [ -f "$work/tree/.git" ]; then
    # A git worktree: its .git file names a directory outside the tree,
    # which make pkg-test mounts read-only at the same path. Make the copy a
    # repository of its own at the worktree's commit, with the worktree's
    # changes still uncommitted (the index is reset to HEAD, the files are
    # left alone), so nothing is written to the mounted directory.
    if ! common=$(git -C "$src" rev-parse --path-format=absolute --git-common-dir) ||
        ! head=$(git -C "$src" rev-parse HEAD); then
        echo "test-packages.sh: $src is a git worktree whose git directory is not mounted" >&2
        exit 1
    fi
    rm "$work/tree/.git"
    cp -a "$common" "$work/tree/.git"
    rm -rf "$work/tree/.git/worktrees"
    git -C "$work/tree" update-ref --no-deref HEAD "$head"
    git -C "$work/tree" reset -q
fi
# A dirty tree on purpose (Review Focus 5): an untracked file the package
# tarball must carry, and the version must say so.
echo marker >"$work/tree/untracked-marker.txt"
chown -R builder: "$work"

as_builder() { su builder -c "cd $work/tree && $*"; }

# --- stub systemctl: records its arguments (the container has no systemd)
mkdir -p /usr/local/bin
cat >/usr/local/bin/systemctl <<'SH'
#!/bin/sh
printf '%s\n' "$*" >>/tmp/systemctl.calls
SH
chmod +x /usr/local/bin/systemctl

# --- build the working-tree package (make pkg's own script, as builder)
# (makepkg's messages and the path go to /tmp/pkg.out, cargo's progress to
# stderr; a failed build stops here, since nothing below can run.)
pkgname=aleph-keyring-local
if as_builder 'CARGO_HOME=/work/cargo CARGO_TARGET_DIR=/work/target sh packaging/arch/make-pkg.sh local' >/tmp/pkg.out; then
    pkg=$(tail -n 1 /tmp/pkg.out)
else
    cat /tmp/pkg.out >&2
    fail "make pkg builds a package of the working tree"
    exit 1
fi
if [ -f "$pkg" ]; then pass "make pkg builds a package of the working tree"; else
    cat /tmp/pkg.out >&2
    fail "make pkg builds a package of the working tree (no file: $pkg)"
    exit 1
fi

# (Review Focus 5.) The tree was made dirty on purpose: the version says so,
# the tarball carries the untracked file and never target/ or .git.
case $pkg in
*.dirty-*) pass "a dirty tree gives a .dirty version" ;;
*) fail "a dirty tree gives a .dirty version (package: $pkg)" ;;
esac
tarball=$work/tree/target/pkg/local/aleph-src.tar.gz
tar -tzf "$tarball" >/tmp/tarball.list
if grep -q '^aleph-src/untracked-marker.txt$' /tmp/tarball.list; then pass "the tarball carries an untracked file"; else
    fail "the tarball carries an untracked file"
fi
if grep -q '^aleph-src/Cargo.lock$' /tmp/tarball.list; then pass "the tarball carries the tracked files"; else
    fail "the tarball carries the tracked files"
fi
if grep -q '^aleph-src/target/' /tmp/tarball.list; then fail "the tarball must not contain target/"; else
    pass "the tarball never contains target/"
fi
if grep -q '^aleph-src/\.git/' /tmp/tarball.list; then fail "the tarball must not contain .git"; else
    pass "the tarball never contains .git"
fi
# (A pkgver may not contain a hyphen, and makepkg refuses one: the build
# succeeded, so it has none.)

# --- metadata
info=$(pacman -Qip "$pkg")
echo "$info" | grep -q "^Name *: $pkgname\$" && pass "the package name" || fail "the package name"
echo "$info" | grep -q '^Licenses *: Apache-2.0' && pass "the license" || fail "the license"
for dep in tpm2-tss libfido2 pam dbus; do
    echo "$info" | grep -q "^Depends On .*\\b$dep\\b" && pass "depends on $dep" || fail "depends on $dep"
done
echo "$info" | grep -q '^Provides .*org\.freedesktop\.secrets' && pass "provides org.freedesktop.secrets" \
    || fail "provides org.freedesktop.secrets"
echo "$info" | grep -q '^Provides .*\baleph-keyring\b' && pass "provides aleph-keyring" \
    || fail "provides aleph-keyring"
echo "$info" | grep -q '^Conflicts With .*aleph-keyring-git' && pass "conflicts with the -git package" \
    || fail "conflicts with the -git package"
echo "$info" | grep -Eq '^Conflicts With .*aleph-keyring( |$)' && pass "conflicts with the release package" \
    || fail "conflicts with the release package"
# (pacman -Qip lists no backup files, so .PKGINFO is read for that.)
bsdtar -xOf "$pkg" .PKGINFO | grep -qx 'backup = etc/pam.d/aleph-check' \
    && pass "etc/pam.d/aleph-check is a backup file" || fail "etc/pam.d/aleph-check is a backup file"
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
got=$(tr '\n' ';' </tmp/systemctl.calls)
[ "$got" = "$want" ] && pass "post_upgrade ran the spec's systemctl calls" || fail "post_upgrade calls: $got"
grep -q 'restart alephd to pick up the new binary: systemctl --user restart alephd.service' /tmp/upgrade.out \
    && pass "post_upgrade printed the restart message" || fail "post_upgrade printed the restart message"

# --- the removal guard through pacman
mkdir -p /var/lib/aleph && : >/var/lib/aleph/manifest.json
: >/tmp/systemctl.calls
if pacman -R --noconfirm "$pkgname" >/tmp/remove.out 2>&1; then
    fail "pacman -R must be refused while the PAM manifest exists"
else
    pass "pacman -R is refused while the PAM manifest exists"
fi
pacman -Q "$pkgname" >/dev/null 2>&1 && pass "the package is still installed after the refusal" \
    || fail "the package is still installed after the refusal"
grep -q 'alephctl system revert' /tmp/remove.out && pass "the refusal names alephctl system revert" \
    || { cat /tmp/remove.out >&2; fail "the refusal names alephctl system revert"; }
[ ! -s /tmp/systemctl.calls ] && pass "a refused removal runs no scriptlet" \
    || fail "a refused removal runs no scriptlet: $(tr '\n' ';' </tmp/systemctl.calls)"
rm -f /var/lib/aleph/manifest.json

id tester >/dev/null 2>&1 || useradd -m tester
mkdir -p /home/tester/.local/share/dbus-1/services
printf 'Exec=/usr/lib/aleph/alephd\n' >/home/tester/.local/share/dbus-1/services/org.freedesktop.secrets.service
if pacman -R --noconfirm "$pkgname" >/tmp/remove2.out 2>&1; then
    fail "pacman -R must be refused while a user's Secret Service is aleph"
else
    pass "pacman -R is refused while a user's Secret Service is aleph"
fi
pacman -Q "$pkgname" >/dev/null 2>&1 && pass "the package is still installed after the second refusal" \
    || fail "the package is still installed after the second refusal"
grep -q 'alephctl setup --revert' /tmp/remove2.out && pass "the refusal names alephctl setup --revert" \
    || { cat /tmp/remove2.out >&2; fail "the refusal names alephctl setup --revert"; }
rm -f /home/tester/.local/share/dbus-1/services/org.freedesktop.secrets.service

: >/tmp/systemctl.calls
pacman -R --noconfirm "$pkgname" >/tmp/remove3.out 2>&1 && pass "pacman -R succeeds with nothing wired in" \
    || { cat /tmp/remove3.out >&2; fail "pacman -R succeeds with nothing wired in"; }
pacman -Q "$pkgname" >/dev/null 2>&1 && fail "the package is gone after the removal" \
    || pass "the package is gone after the removal"
got=$(tr '\n' ';' </tmp/systemctl.calls)
want='--global disable alephd.socket;disable --now aleph-tpmd.socket aleph-tpmd.service;daemon-reload;'
[ "$got" = "$want" ] && pass "pre_remove and post_remove ran the spec's systemctl calls" || fail "removal calls: $got"

# --- namcap on the PKGBUILD and the package: warnings only
namcap "$work/tree/target/pkg/local/PKGBUILD" >/tmp/namcap.out 2>&1 || true
namcap "$pkg" >>/tmp/namcap.out 2>&1 || true
[ -s /tmp/namcap.out ] && { echo "namcap (warnings only):"; cat /tmp/namcap.out; }

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
echo "all package checks passed"
