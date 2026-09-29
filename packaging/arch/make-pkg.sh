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

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
count=$(git rev-list --count HEAD)
hash=$(git rev-parse --short HEAD)
dirty=
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    dirty=.dirty
fi
# (pkgver may not contain a hyphen; the commit count and hash make every
# rebuild of a changed tree an upgrade.)
pkgver="$version.r$count.g$hash$dirty"

out=target/pkg/$variant
rm -rf "$out"
mkdir -p "$out"

# The working tree, as a tarball with one top directory (aleph-src).
git ls-files -z --cached --others --exclude-standard |
    tar --null -T - --transform 's,^,aleph-src/,' -czf "$out/aleph-src.tar.gz"

sed "s/^pkgver=.*/pkgver=$pkgver/" "$arch/local/PKGBUILD" >"$out/PKGBUILD"
cp "$arch/common.sh" "$arch/aleph-keyring.install" "$out/"

cd "$out"
makepkg -f --noconfirm -C
# (Only the package itself: with makepkg.conf's `debug` option makepkg also
# writes aleph-keyring-local-debug-*, and a pkgver starts with a digit.)
ls "$PWD"/aleph-keyring-local-[0-9]*.pkg.tar.zst
