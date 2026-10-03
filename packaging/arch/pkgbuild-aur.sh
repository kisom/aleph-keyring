#!/bin/sh
# Generate the AUR copies (`make pkgbuild-aur`): one directory per published
# package under target/aur/, each holding a PKGBUILD with common.sh inlined
# (an AUR repository holds only the files in its own directory), the
# install file as a real file, and the .SRCINFO
# that `makepkg --printsrcinfo` writes. Refuses the release package while
# its checksum is still the placeholder. The local package is never
# published. Nothing here contacts the AUR: publishing is the owner's.
# ALEPH_ARCH_DIR, ALEPH_AUR_OUT and ALEPH_MAKEPKG are for the tests.
set -eu

arch=${ALEPH_ARCH_DIR:-$(cd "$(dirname "$0")" && pwd)}
out=${ALEPH_AUR_OUT:-$arch/../../target/aur}
makepkg=${ALEPH_MAKEPKG:-makepkg}

# (SKIP anywhere in the array, quoted or not, however many lines the array
# spans.)
sums=$(sed -n '/^sha256sums=(/,/)/p' "$arch/aleph-keyring/PKGBUILD")
if printf '%s\n' "$sums" | grep -Eq "[('\"]SKIP['\") ]"; then
    echo "pkgbuild-aur: the release package's checksum is still SKIP: run" >&2
    echo "  make pkgbuild-release TAG=vX.Y.Z  (after pushing the tag) first" >&2
    exit 1
fi
# (The copies inline this tree's common.sh: generate them at the tagged
# commit of a clean tree, exactly what will be published. Outside a
# repository — the tests' scratch copies — there is nothing to check.)
if toplevel=$(git -C "$arch" rev-parse --show-toplevel 2>/dev/null); then
    if [ -n "$(git -C "$toplevel" status --porcelain)" ]; then
        echo "pkgbuild-aur: the working tree has uncommitted changes: commit them, and" >&2
        echo "  generate the AUR copies at the tagged commit (git checkout vX.Y.Z)" >&2
        exit 1
    fi
    if ! git -C "$toplevel" describe --exact-match --tags HEAD >/dev/null 2>&1; then
        echo "pkgbuild-aur: HEAD is not exactly a tag: check the release tag out first" >&2
        echo "  (git checkout vX.Y.Z), then generate the AUR copies" >&2
        exit 1
    fi
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
        echo "# --- common.sh, shared by the aleph packages (packaging/arch/ in the repository)."
        echo
        cat "$arch/common.sh"
    } >"$dir/PKGBUILD"
    cp -L "$arch/aleph-keyring.install" "$dir/aleph-keyring.install"
    (cd "$dir" && "$makepkg" --printsrcinfo >.SRCINFO)
    echo "pkgbuild-aur: wrote $dir"
done
