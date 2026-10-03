#!/bin/sh
# Tests for packaging/arch/pkgver.sh, run on any host: temporary git
# repositories only (no docker, nothing outside the temporary directory).
#   sh packaging/arch/tests/pkgver-test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
pkgver="$here/../pkgver.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# (The user's own git configuration, such as commit signing or hooks, must
# not reach these repositories.)
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

# A repository like the workspace's: a Cargo.toml with the version, a
# tracked file, a .gitignore; two commits.
new_repo() { # $1: directory
    mkdir -p "$1"
    git -C "$1" init -q
    printf '[workspace.package]\nversion = "0.1.0"\nedition = "2024"\n' >"$1/Cargo.toml"
    echo one >"$1/README.md"
    printf '/target\n' >"$1/.gitignore"
    git -C "$1" add -A
    git -C "$1" commit -q -m one
    echo two >>"$1/README.md"
    git -C "$1" commit -q -am two
}

ver() { ALEPH_PKGVER_NOW=20260929134501 sh "$pkgver" "$1"; }

repo="$tmp/repo"
new_repo "$repo"
hash=$(git -C "$repo" rev-parse --short HEAD)

got=$(ver "$repo")
[ "$got" = "0.1.0.r2.g$hash" ] && pass "a clean tree gives 0.1.0.r2.g<hash>" || fail "clean tree: $got"

mkdir -p "$repo/target" && echo x >"$repo/target/junk"
got=$(ver "$repo")
[ "$got" = "0.1.0.r2.g$hash" ] && pass "an ignored file alone leaves the version clean" || fail "ignored file: $got"

echo three >>"$repo/README.md"
got=$(ver "$repo")
[ "$got" = "0.1.0.r2.dirty20260929134501.g$hash" ] && pass "a modified tracked file gives .r2.dirty<ts>.g<hash>" \
    || fail "modified file: $got"
git -C "$repo" checkout -q README.md

echo new >"$repo/untracked.txt"
got=$(ver "$repo")
[ "$got" = "0.1.0.r2.dirty20260929134501.g$hash" ] && pass "an untracked file gives .r2.dirty<ts>.g<hash>" \
    || fail "untracked file: $got"
rm "$repo/untracked.txt"

rm "$repo/README.md"
got=$(ver "$repo")
[ "$got" = "0.1.0.r2.dirty20260929134501.g$hash" ] && pass "a deleted tracked file gives .r2.dirty<ts>.g<hash>" \
    || fail "deleted file: $got"
git -C "$repo" checkout -q README.md

echo four >>"$repo/README.md"
git -C "$repo" commit -q -am three
hash3=$(git -C "$repo" rev-parse --short HEAD)
got=$(ver "$repo")
[ "$got" = "0.1.0.r3.g$hash3" ] && [ "$hash3" != "$hash" ] \
    && pass "a new commit changes the count and the hash" || fail "new commit: $got"

# Without ALEPH_PKGVER_NOW, a dirty tree gets the current UTC time: 14 digits.
echo five >>"$repo/README.md"
got=$(sh "$pkgver" "$repo")
case $got in
"0.1.0.r3.dirty"[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]".g$hash3")
    pass "a dirty tree carries the current timestamp" ;;
*) fail "current timestamp: $got" ;;
esac
case $got in
*-*) fail "the version has a hyphen: $got" ;;
*) pass "the version has no hyphen" ;;
esac

# Run from elsewhere: the repository root is the argument.
got=$(cd "$tmp" && ALEPH_PKGVER_NOW=1 sh "$pkgver" "$repo")
[ "$got" = "0.1.0.r3.dirty1.g$hash3" ] && pass "the repository is \$1, whatever the current directory" \
    || fail "run from elsewhere: $got"

# The point of the .dirty-before-.g shape: vercmp (where pacman has it)
# sorts the clean build of the same commit newer than any dirty build of
# it, and later dirty builds newer than earlier ones.
if command -v vercmp >/dev/null 2>&1; then
    d1=$(ALEPH_PKGVER_NOW=20260929134500 sh "$pkgver" "$repo")
    d2=$(ALEPH_PKGVER_NOW=20260929134501 sh "$pkgver" "$repo")
    clean=$(git -C "$repo" checkout -q README.md; ver "$repo")
    [ "$(vercmp "$clean" "$d1")" = 1 ] && pass "vercmp: the clean same-commit build is newer than a dirty one" \
        || fail "vercmp clean vs dirty: $(vercmp "$clean" "$d1") ($clean, $d1)"
    [ "$(vercmp "$d2" "$d1")" = 1 ] && pass "vercmp: a later dirty build is newer than an earlier one" \
        || fail "vercmp dirty builds: $(vercmp "$d2" "$d1")"
else
    pass "vercmp not found: the ordering checks run in the container"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
