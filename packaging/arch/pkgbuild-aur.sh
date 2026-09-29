#!/bin/sh
# Generate the AUR copies (`make pkgbuild-aur`): one directory per published
# package under target/aur/, each holding a PKGBUILD with the shared build
# and package functions inlined (an AUR repository holds only the files in
# its own directory), the install file as a real file, and the .SRCINFO
# that `makepkg --printsrcinfo` writes. Refuses the release package while
# its checksum is still the placeholder. The local package is never
# published. Nothing here contacts the AUR: publishing is the owner's.
# ALEPH_ARCH_DIR, ALEPH_AUR_OUT and ALEPH_MAKEPKG are for the tests.
set -eu

arch=${ALEPH_ARCH_DIR:-$(cd "$(dirname "$0")" && pwd)}
out=${ALEPH_AUR_OUT:-$arch/../../target/aur}
makepkg=${ALEPH_MAKEPKG:-makepkg}

if grep -q "^sha256sums=('SKIP')" "$arch/aleph-keyring/PKGBUILD"; then
    echo "pkgbuild-aur: the release package's checksum is still SKIP: run" >&2
    echo "  make pkgbuild-release TAG=vX.Y.Z  (after pushing the tag) first" >&2
    exit 1
fi
# (The AUR needs the .SRCINFO beside each PKGBUILD.)
if ! command -v "$makepkg" >/dev/null 2>&1; then
    echo "pkgbuild-aur: $makepkg not found: it writes the .SRCINFO the AUR needs" >&2
    exit 1
fi

for name in aleph-keyring aleph-keyring-git; do
    dir=$out/$name
    rm -rf "$dir"
    mkdir -p "$dir"
    # The maintainer line stays first; the lines that source common.sh go,
    # and the functions they sourced follow the PKGBUILD.
    {
        grep -v '^  \. "\$startdir/common.sh"$' "$arch/$name/PKGBUILD"
        echo
        echo "# --- Shared by the aleph packages (packaging/arch/ in the repository)."
        echo
        cat "$arch/common.sh"
    } >"$dir/PKGBUILD"
    cp -L "$arch/aleph-keyring.install" "$dir/aleph-keyring.install"
    (cd "$dir" && "$makepkg" --printsrcinfo >.SRCINFO)
    echo "pkgbuild-aur: wrote $dir"
done
