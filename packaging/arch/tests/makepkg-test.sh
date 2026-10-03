#!/bin/sh
# Tests for packaging/arch/make-pkg.sh, run on any host: a temporary git
# repository and a stub makepkg that records how it was called. The real
# build of the package it drives is checked in the container, by
# test-packages.sh.
#   sh packaging/arch/tests/makepkg-test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
arch=$(cd "$here/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

# (The user's own git configuration, such as commit signing or hooks, must
# not reach these repositories.)
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL

# A repository shaped like the workspace's: a Cargo.toml with the version,
# a tracked file, and the packaging directory the script drives.
repo=$tmp/repo
mkdir -p "$repo/packaging/arch"
git -C "$repo" init -q
printf '[workspace.package]\nversion = "0.1.0"\nedition = "2024"\n' >"$repo/Cargo.toml"
echo one >"$repo/README.md"
printf '/target\n' >"$repo/.gitignore"
cp -a "$arch/." "$repo/packaging/arch/"
git -C "$repo" add -A
git -C "$repo" commit -q -m one

# The stub makepkg: records where and how it ran, and leaves the package
# file make-pkg.sh expects to find, in the directory it was told to use.
cat >"$tmp/makepkg" <<'SH'
#!/bin/sh
printf 'PKGDEST=%s\nCWD=%s\nARGS=%s\n' "${PKGDEST-UNSET}" "$PWD" "$*" >>"${STUB_LOG:?}"
touch "${PKGDEST:?}/aleph-keyring-local-0.1.0.r1.gabc123-1-x86_64.pkg.tar.zst"
SH
chmod +x "$tmp/makepkg"
STUB_LOG=$tmp/makepkg.log
export STUB_LOG

# (The version is pinned, so the run does not depend on the clock; the
# build directory starts absent, as after a clean checkout.)
got=$(PATH="$tmp:$PATH" ALEPH_PKGVER_NOW=20260929134500 \
    sh "$repo/packaging/arch/make-pkg.sh" local)
out=$repo/target/pkg/local

grep -Fx "PKGDEST=$out" "$STUB_LOG" && pass "makepkg runs with PKGDEST pinned to the build directory" \
    || fail "PKGDEST is not the build directory: $(grep PKGDEST "$STUB_LOG" || echo 'makepkg never ran')"
grep -Fx "CWD=$out" "$STUB_LOG" && pass "makepkg runs in the build directory" \
    || fail "makepkg ran elsewhere: $(grep CWD "$STUB_LOG" || true)"
grep -F "ARGS=-f --noconfirm -C" "$STUB_LOG" && pass "makepkg is called with -f --noconfirm -C" \
    || fail "unexpected makepkg arguments: $(grep ARGS "$STUB_LOG" || true)"
[ -f "$got" ] && pass "the built package's path is printed and exists" \
    || fail "the printed package path does not exist: $got"
case $got in
*aleph-keyring-local-0.1.0.r1.gabc123-1-x86_64.pkg.tar.zst)
    pass "the package is named for the version pkgver.sh printed" ;;
*) fail "unexpected package name: $got" ;;
esac

# A variant other than local is refused.
if PATH="$tmp:$PATH" ALEPH_PKGVER_NOW=20260929134500 \
    sh "$repo/packaging/arch/make-pkg.sh" release >"$tmp/out" 2>"$tmp/err"; then
    fail "a variant other than local is refused"
else
    grep -q "usage: make-pkg.sh local" "$tmp/err" && pass "a variant other than local is refused, with usage" \
        || fail "the refusal does not say what is allowed: $(cat "$tmp/err")"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
