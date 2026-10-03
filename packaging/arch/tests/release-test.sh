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

# The scratch copy's release checksum line, whatever the repository holds
# (a filled-in PKGBUILD is committed after a release).
set_sums() {
    sed "s|^sha256sums=.*|$1|" "$tmp/arch/aleph-keyring/PKGBUILD" >"$tmp/PKGBUILD.new"
    cat "$tmp/PKGBUILD.new" >"$tmp/arch/aleph-keyring/PKGBUILD"
}

# (Review Focus 4.) The AUR generator refuses the release package while its
# checksum is a placeholder, in any spelling, and writes nothing.
real=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
for line in "sha256sums=(SKIP)" "sha256sums=(\"SKIP\")" "sha256sums=('SKIP')" \
    "sha256sums=('$real' 'SKIP')" "sha256sums=('SKIP')  # FILLED AT RELEASE by make pkgbuild-release TAG=vX.Y.Z"; do
    set_sums "$line"
    rm -rf "$tmp/aur"
    if ALEPH_ARCH_DIR="$tmp/arch" ALEPH_AUR_OUT="$tmp/aur" \
        sh "$tmp/arch/pkgbuild-aur.sh" >"$tmp/out" 2>"$tmp/err"; then
        fail "pkgbuild-aur refuses the release package with $line"
    else
        grep -qi "checksum" "$tmp/err" && pass "pkgbuild-aur refuses $line and says why" \
            || fail "pkgbuild-aur's refusal of $line explains the checksum"
    fi
    [ ! -e "$tmp/aur" ] && pass "a refused run writes nothing ($line)" || fail "a refused run writes nothing ($line)"
done

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

# A sha256sums array over several lines: both scripts must read it all, and
# pkgbuild-release must replace it with one clean line.
set_sums_multi() { # each argument: one line of the array
    grep -v '^sha256sums=' "$tmp/PKGBUILD.before" >"$tmp/arch/aleph-keyring/PKGBUILD"
    for line do
        printf '%s\n' "$line" >>"$tmp/arch/aleph-keyring/PKGBUILD"
    done
}
set_sums_multi 'sha256sums=(' "  '$real'" "  'SKIP'" ')'
rm -rf "$tmp/aur"
if ALEPH_ARCH_DIR="$tmp/arch" ALEPH_AUR_OUT="$tmp/aur" \
    sh "$tmp/arch/pkgbuild-aur.sh" >"$tmp/out" 2>"$tmp/err"; then
    fail "pkgbuild-aur refuses a multi-line array with SKIP"
else
    grep -qi checksum "$tmp/err" && pass "pkgbuild-aur refuses a multi-line array with SKIP, and says why" \
        || fail "the multi-line SKIP refusal explains the checksum"
fi
[ ! -e "$tmp/aur" ] && pass "a refused multi-line run writes nothing" \
    || fail "a refused multi-line run writes nothing"

set_sums_multi 'sha256sums=(' "  'FILLED AT RELEASE by make pkgbuild-release TAG=vX.Y.Z'" "  '$real'" ')'
if ALEPH_ARCH_DIR="$tmp/arch" ALEPH_RELEASE_TARBALL_URL="file://$tmp/release.tar.gz" \
    sh "$tmp/arch/pkgbuild-release.sh" v0.1.8 >"$tmp/out" 2>"$tmp/err"; then
    pass "pkgbuild-release rewrites a multi-line checksum array"
else
    cat "$tmp/err" >&2
    fail "pkgbuild-release rewrites a multi-line checksum array"
fi
[ "$(grep -c '^sha256sums=' "$tmp/arch/aleph-keyring/PKGBUILD")" = 1 ] \
    && pass "the rewritten array is one line" || fail "the rewritten array is not one line"
grep -q "^sha256sums=('$sum')" "$tmp/arch/aleph-keyring/PKGBUILD" \
    && pass "the rewritten array carries the real checksum" \
    || fail "the rewritten array carries the wrong checksum"
grep -q 'FILLED AT RELEASE' "$tmp/arch/aleph-keyring/PKGBUILD" \
    && fail "the multi-line placeholder is gone once filled" || pass "the multi-line placeholder is gone once filled"
[ "$(grep -c "$real" "$tmp/arch/aleph-keyring/PKGBUILD")" = 0 ] \
    && pass "no orphaned continuation line is left behind" \
    || fail "an orphaned continuation line is left behind"
cp "$tmp/PKGBUILD.before" "$tmp/arch/aleph-keyring/PKGBUILD"

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
    grep -Eq '(^|[;&|[:space:]])(\.|source)[[:space:]]+"?\$\{?startdir' "$f" \
        && fail "$name's PKGBUILD no longer sources a file from \$startdir" || pass "$name sources nothing from \$startdir"
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

# The AUR copies inline this tree's common.sh: pkgbuild-aur runs only at
# the tagged commit of a clean repository (the scratch copies above sit
# outside any repository, so the check skips them there).
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
repo=$tmp/repo
mkdir -p "$repo/packaging"
# (The filled-in scratch copy: the real checksum, so the checksum check
# passes and the tag and cleanliness checks are what run.)
set_sums "sha256sums=('$sum')"
cp -a "$tmp/arch/." "$repo/packaging/arch/"
git -C "$repo" init -q
git -C "$repo" add -A
git -C "$repo" commit -q -m one
aur_in_repo() {
    ALEPH_ARCH_DIR="$repo/packaging/arch" ALEPH_AUR_OUT="$tmp/aur3" \
        sh "$repo/packaging/arch/pkgbuild-aur.sh"
}
echo dirt >>"$repo/packaging/arch/common.sh"
if aur_in_repo >"$tmp/out" 2>"$tmp/err"; then
    fail "pkgbuild-aur refuses a dirty tree"
else
    grep -q 'uncommitted' "$tmp/err" && pass "pkgbuild-aur refuses a dirty tree, and says so" \
        || fail "the dirty-tree refusal says what is wrong: $(cat "$tmp/err")"
fi
git -C "$repo" add -A
git -C "$repo" commit -q -m two
if aur_in_repo >"$tmp/out" 2>"$tmp/err"; then
    fail "pkgbuild-aur refuses an untagged HEAD"
else
    grep -q 'not exactly a tag' "$tmp/err" && pass "pkgbuild-aur refuses an untagged HEAD, and says so" \
        || fail "the untagged refusal says what is wrong: $(cat "$tmp/err")"
fi
git -C "$repo" tag v0.1.7
rm -rf "$tmp/aur3"
if aur_in_repo >"$tmp/out" 2>"$tmp/err"; then
    pass "pkgbuild-aur runs at the tagged commit"
else
    cat "$tmp/err" >&2
    fail "pkgbuild-aur runs at the tagged commit"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
