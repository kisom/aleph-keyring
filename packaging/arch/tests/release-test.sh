#!/bin/sh
# Tests for pkgbuild-release.sh and pkgbuild-aur.sh, host-safe: a local
# tarball stands in for GitHub's, everything is written to a copy of the
# packaging directory, and a stub stands in for makepkg (the real
# `makepkg --printsrcinfo` of the AUR copies is checked in the container,
# by test-packages.sh).
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

# The stub makepkg: records where and how it ran, prints a marker .SRCINFO.
cat >"$tmp/makepkg" <<'SH'
#!/bin/sh
printf '%s %s\n' "$PWD" "$*" >>"${STUB_LOG:?}"
printf 'pkgbase = stub\n'
SH
chmod +x "$tmp/makepkg"
export ALEPH_MAKEPKG="$tmp/makepkg" STUB_LOG="$tmp/makepkg.log"

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
    [ ! -e "$tmp/aur" ] && pass "a refused run writes nothing" || fail "a refused run writes nothing"
else
    fail "the release PKGBUILD in the repository starts with the placeholder checksum"
fi
grep -q 'FILLED AT RELEASE' "$tmp/arch/aleph-keyring/PKGBUILD" \
    && pass "the placeholder is marked FILLED AT RELEASE" || fail "the placeholder is marked FILLED AT RELEASE"

# pkgbuild-release refuses a malformed tag and leaves the file alone.
cp "$tmp/arch/aleph-keyring/PKGBUILD" "$tmp/PKGBUILD.before"
if ALEPH_ARCH_DIR="$tmp/arch" ALEPH_RELEASE_TARBALL_URL="file://$tmp/release.tar.gz" \
    sh "$tmp/arch/pkgbuild-release.sh" 0.1.7 >"$tmp/out" 2>"$tmp/err"; then
    fail "pkgbuild-release refuses a tag without the v"
else
    pass "pkgbuild-release refuses a tag without the v"
fi
# (A download that fails: nothing is written.)
if ALEPH_ARCH_DIR="$tmp/arch" ALEPH_RELEASE_TARBALL_URL="file://$tmp/no-such.tar.gz" \
    sh "$tmp/arch/pkgbuild-release.sh" v0.1.7 >"$tmp/out" 2>"$tmp/err"; then
    fail "pkgbuild-release fails when the download fails"
else
    pass "pkgbuild-release fails when the download fails"
fi
cmp -s "$tmp/PKGBUILD.before" "$tmp/arch/aleph-keyring/PKGBUILD" \
    && pass "a refused or failed pkgbuild-release leaves the PKGBUILD alone" \
    || fail "a refused or failed pkgbuild-release leaves the PKGBUILD alone"

# pkgbuild-release writes the version and the real checksum.
ALEPH_ARCH_DIR="$tmp/arch" ALEPH_RELEASE_TARBALL_URL="file://$tmp/release.tar.gz" \
    sh "$tmp/arch/pkgbuild-release.sh" v0.1.7 >"$tmp/out" 2>"$tmp/err" \
    && pass "pkgbuild-release runs" || { cat "$tmp/err" >&2; fail "pkgbuild-release runs"; }
grep -q '^pkgver=0.1.7$' "$tmp/arch/aleph-keyring/PKGBUILD" && pass "pkgbuild-release sets pkgver" \
    || fail "pkgbuild-release sets pkgver"
grep -q '^pkgrel=1$' "$tmp/arch/aleph-keyring/PKGBUILD" && pass "pkgbuild-release sets pkgrel=1" \
    || fail "pkgbuild-release sets pkgrel=1"
grep -q "^sha256sums=('$sum')" "$tmp/arch/aleph-keyring/PKGBUILD" && pass "pkgbuild-release writes the tarball's checksum" \
    || fail "pkgbuild-release writes the tarball's checksum"
grep -q 'FILLED AT RELEASE' "$tmp/arch/aleph-keyring/PKGBUILD" && fail "the placeholder marker is gone once filled" \
    || pass "the placeholder marker is gone once filled"
# (Every other line is kept.)
grep -v -e '^pkgver=' -e '^pkgrel=' -e '^sha256sums=' "$tmp/PKGBUILD.before" >"$tmp/rest.before"
grep -v -e '^pkgver=' -e '^pkgrel=' -e '^sha256sums=' "$tmp/arch/aleph-keyring/PKGBUILD" >"$tmp/rest.after"
cmp -s "$tmp/rest.before" "$tmp/rest.after" && pass "pkgbuild-release keeps every other line" \
    || fail "pkgbuild-release keeps every other line"

# Now the AUR generator accepts it, and inlines common.sh.
ALEPH_ARCH_DIR="$tmp/arch" ALEPH_AUR_OUT="$tmp/aur" sh "$tmp/arch/pkgbuild-aur.sh" >"$tmp/out" 2>"$tmp/err" \
    && pass "pkgbuild-aur runs once the checksum is real" || { cat "$tmp/err" >&2; fail "pkgbuild-aur runs"; }
for name in aleph-keyring aleph-keyring-git; do
    f="$tmp/aur/$name/PKGBUILD"
    [ -f "$f" ] && pass "$name has a flattened PKGBUILD" || fail "$name has a flattened PKGBUILD"
    grep -q 'common.sh' "$f" && fail "$name's PKGBUILD no longer sources common.sh" || pass "$name inlines common.sh"
    grep -q '^aleph_build()' "$f" && grep -q '^aleph_package()' "$f" && pass "$name carries the shared functions" \
        || fail "$name carries the shared functions"
    head -n 1 "$f" | grep -q '^# Maintainer: ' && pass "$name's PKGBUILD starts with the maintainer line" \
        || fail "$name's PKGBUILD starts with the maintainer line"
    grep -q "^pkgname=$name\$" "$f" && pass "$name's PKGBUILD names $name" || fail "$name's PKGBUILD names $name"
    bash -n "$f" && pass "$name's PKGBUILD parses" || fail "$name's PKGBUILD parses"
    [ -f "$tmp/aur/$name/aleph-keyring.install" ] && [ ! -L "$tmp/aur/$name/aleph-keyring.install" ] \
        && pass "$name has the install file as a real file" || fail "$name has the install file as a real file"
    cmp -s "$tmp/aur/$name/aleph-keyring.install" "$arch/aleph-keyring.install" \
        && pass "$name's install file is the hook" || fail "$name's install file is the hook"
    grep -qx 'pkgbase = stub' "$tmp/aur/$name/.SRCINFO" 2>/dev/null \
        && grep -qx "$tmp/aur/$name --printsrcinfo" "$STUB_LOG" \
        && pass "$name's .SRCINFO is makepkg --printsrcinfo's, run in its directory" \
        || fail "$name's .SRCINFO is makepkg --printsrcinfo's, run in its directory"
done
grep -q "^sha256sums=('$sum')" "$tmp/aur/aleph-keyring/PKGBUILD" \
    && pass "the AUR release PKGBUILD carries the real checksum" || fail "the AUR release PKGBUILD carries the real checksum"
# The local package is not published.
[ ! -e "$tmp/aur/aleph-keyring-local" ] && [ ! -e "$tmp/aur/local" ] \
    && pass "the local package is not generated for the AUR" \
    || fail "the local package is not generated for the AUR"

# Without makepkg there is no .SRCINFO, and an AUR copy without one is not
# publishable: pkgbuild-aur fails and says so.
if ALEPH_MAKEPKG="$tmp/no-such-makepkg" ALEPH_ARCH_DIR="$tmp/arch" ALEPH_AUR_OUT="$tmp/aur2" \
    sh "$tmp/arch/pkgbuild-aur.sh" >"$tmp/out" 2>"$tmp/err"; then
    fail "pkgbuild-aur fails without makepkg"
else
    grep -q 'makepkg' "$tmp/err" && pass "pkgbuild-aur fails without makepkg and says so" \
        || fail "pkgbuild-aur fails without makepkg and says so"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
