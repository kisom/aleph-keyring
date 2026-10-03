#!/bin/sh
# The layout test: what packaging/install.sh installs, into a test root,
# is exactly packaging/arch/files.expected minus what only the package
# adds (the removal guard and its hook, the licence files). Run on any
# host: a stub pacman stands in, and nothing outside the temporary
# directory is touched.
#   sh packaging/arch/tests/install-layout-test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
arch=$(cd "$here/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

# The stub pacman: `pacman -Qi aleph-keyring` succeeds only when asked to
# pretend (INSTALLED=1), which is what the refusals check.
cat >"$tmp/pacman" <<'SH'
#!/bin/sh
[ "$1 $2" = "-Qi aleph-keyring" ] || exit 127
[ "${INSTALLED:-0}" = 1 ]
SH
chmod +x "$tmp/pacman"

# A source tree for install.sh: it needs the packaged files and a release
# build, stand-ins for the real ones (the layout is what is checked, not
# the binaries).
src=$tmp/src
mkdir -p "$src/packaging" "$src/assets/icons" "$src/target/release"
cp -r "$arch/../pam" "$arch/../hyprland" "$arch/../systemd" "$arch/../dbus" "$src/packaging/"
cp "$arch/../aleph-gui.desktop" "$arch/../install.sh" "$src/packaging/"
cp "$arch/../../assets/icons/"aleph*.svg "$src/assets/icons/"
for bin in alephctl alephd aleph-tpmd aleph-gui libpam_aleph.so; do
    : >"$src/target/release/$bin"
done

# The install, as the current user, under a test root, with pacman
# reporting aleph not installed: the paths are what files.expected holds,
# minus what only the package adds.
if INSTALLED=0 PATH="$tmp:$PATH" ALEPH_INSTALL_ROOT="$tmp/root" \
    sh "$src/packaging/install.sh" install >"$tmp/out" 2>"$tmp/err"; then
    pass "install.sh installs into a test root"
else
    cat "$tmp/err" >&2
    fail "install.sh installs into a test root"
fi
(cd "$tmp/root" && find . -type f -printf '%m %P\n' | sort -k2) >"$tmp/actual"
sed -e '/remove-guard/d' -e '/usr\/share\/libalpm\//d' -e '/usr\/share\/licenses\//d' \
    "$arch/files.expected" | sort -k2 >"$tmp/want"
if diff -u "$tmp/want" "$tmp/actual" >"$tmp/diff"; then
    pass "what install.sh installs is files.expected (minus the package-only files)"
else
    cat "$tmp/diff" >&2
    fail "what install.sh installs is files.expected (minus the package-only files)"
fi

# With pacman holding the package, install and uninstall are refused,
# naming pacman's way out.
for verb in install uninstall; do
    if INSTALLED=1 PATH="$tmp:$PATH" ALEPH_INSTALL_ROOT="$tmp/root2" \
        sh "$src/packaging/install.sh" "$verb" >"$tmp/out" 2>"$tmp/err"; then
        fail "install.sh $verb is refused while pacman owns aleph"
    else
        grep -q "pacman -R aleph-keyring" "$tmp/err" \
            && pass "install.sh $verb is refused while pacman owns aleph, and names pacman -R" \
            || fail "the $verb refusal says what to do: $(cat "$tmp/err")"
    fi
done

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
