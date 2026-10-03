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

# (0.1.0.r<count>.g<hash>, and .dirty<timestamp> for uncommitted changes.)
pkgver=$(sh "$arch/pkgver.sh" "$root")

out=target/pkg/$variant
rm -rf "$out"
mkdir -p "$out"

# The working tree, as a tarball with one top directory (aleph-src): a
# temporary index gets every change (`add -A` keeps .gitignore, adds
# untracked files, drops deleted ones), and git archive writes its tree.
# The real index and the working tree are left alone.
tmpidx=$root/$out/index.tmp
cp "$(git rev-parse --path-format=absolute --git-path index)" "$tmpidx"
GIT_INDEX_FILE=$tmpidx git add -A
tree=$(GIT_INDEX_FILE=$tmpidx git write-tree)
rm -f "$tmpidx"
git archive --prefix=aleph-src/ -o "$out/aleph-src.tar.gz" "$tree"

sed "s/^pkgver=.*/pkgver=$pkgver/" "$arch/local/PKGBUILD" >"$out/PKGBUILD"
cp "$arch/common.sh" "$arch/aleph-keyring.install" "$out/"

cd "$out"
# (PKGDEST is pinned to the build directory: a PKGDEST in the user's
# makepkg.conf would put the package somewhere else, and the path printed
# below would not exist.)
PKGDEST="$PWD" makepkg -f --noconfirm -C
# (Only the package itself: with makepkg.conf's `debug` option makepkg also
# writes aleph-keyring-local-debug-*, and a pkgver starts with a digit.)
ls "$PWD"/aleph-keyring-local-[0-9]*.pkg.tar.zst
