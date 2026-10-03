#!/bin/sh
# Tests for common.sh's rust flags, run on any host with cargo: a tiny
# crate in a directory with spaces in its name, built with the flags
# aleph_build assembles. A plain RUSTFLAGS is split on whitespace, which
# breaks such a path; the encoded form cargo also takes does not.
#   sh packaging/arch/tests/rustflags-test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
arch=$(cd "$here/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

# The flags, exactly as aleph_build assembles them.
flags_for() { # SRCDIR [TARGETDIR]
    (
        unset CARGO_ENCODED_RUSTFLAGS
        RUSTFLAGS=${RUSTFLAGS:-}
        . "$arch/common.sh"
        aleph_rustflags "$@"
        printf '%s' "$CARGO_ENCODED_RUSTFLAGS"
    )
}

# A tiny crate in a directory with spaces: what a startdir with spaces
# makes of $srcdir.
src="$tmp/dir with spaces/aleph-src"
mkdir -p "$src/src"
printf '[package]\nname = "rf"\nversion = "0.1.0"\nedition = "2021"\n' >"$src/Cargo.toml"
printf 'fn main() { println!("hi"); }\n' >"$src/src/main.rs"

target="$tmp/variant target"
flags=$(flags_for "$src" "$target")

# (The flags are one call to rustc: the space in the path must not split
# them. cargo refuses a remap without '=', so a broken split fails here.)
cd "$src"
CARGO_TARGET_DIR="$target" CARGO_ENCODED_RUSTFLAGS="$flags" cargo build -q \
    && pass "a build in a \$srcdir with spaces succeeds with the encoded flags" \
    || fail "a build in a \$srcdir with spaces fails: cargo rejected the flags"
[ -x "$target/debug/rf" ] && pass "the build produced the binary" || fail "no binary: $target/debug/rf"

# The remap is real: the binary names the remapped destination, and the
# build directories appear nowhere in it.
strings "$target/debug/rf" | grep -q /usr/src/debug/aleph-keyring \
    && pass "the binary names the remapped destination" \
    || fail "the binary does not name /usr/src/debug/aleph-keyring"
if strings "$target/debug/rf" | grep -qF "$src" || strings "$target/debug/rf" | grep -qF "$target"; then
    fail "the binary names a build directory (the remap did not take)"
else
    pass "the binary names neither build directory"
fi

# The caller's RUSTFLAGS travel along, split the way cargo would split them.
flags=$(RUSTFLAGS='-C debuginfo=0' flags_for "$src" "$target")
case $flags in
*-C*debuginfo=0*) pass "the caller's RUSTFLAGS are carried in the encoded flags" \
    || fail "the caller's RUSTFLAGS are lost" ;;
esac
first=${flags%%$'\037'*}
[ "$first" = -C ] && pass "the caller's flags come first, one per \037-separated slot" \
    || fail "the first flag is '$first'"

# Without a target directory, there is exactly one remap: the source's.
flags=$(flags_for "$src")
n=$(printf '%s' "$flags" | grep -c -- '--remap-path-prefix=')
[ "$n" = 1 ] && pass "without a target directory there is one remap" \
    || fail "expected one remap, found $n"

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
