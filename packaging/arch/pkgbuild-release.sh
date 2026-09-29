#!/bin/sh
# Fill in the release PKGBUILD for a tag (`make pkgbuild-release TAG=v0.1.0`):
# set pkgver from the tag, pkgrel=1, and the real sha256 of GitHub's tarball
# (which also drops the FILLED AT RELEASE placeholder). Run it after the tag
# is pushed; it downloads to a temporary file and never runs what it
# downloaded. ALEPH_ARCH_DIR and ALEPH_RELEASE_TARBALL_URL are for the tests.
#   packaging/arch/pkgbuild-release.sh vX.Y.Z
set -eu

tag=${1:-}
ver=${tag#v}
# (A pkgver is letters, digits, dots, underscores and plus signs; no hyphen.)
case $tag in
v[0-9]*) ;;
*) echo "usage: pkgbuild-release.sh vX.Y.Z" >&2; exit 2 ;;
esac
case $ver in
*[!0-9A-Za-z._+]*) echo "pkgbuild-release: $tag does not make a valid pkgver" >&2; exit 2 ;;
esac

arch=${ALEPH_ARCH_DIR:-$(cd "$(dirname "$0")" && pwd)}
pkgbuild=$arch/aleph-keyring/PKGBUILD
url=${ALEPH_RELEASE_TARBALL_URL:-https://github.com/kisom/aleph-keyring/archive/refs/tags/$tag.tar.gz}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/release.tar.gz" "$url"
sum=$(sha256sum "$tmp/release.tar.gz" | cut -d' ' -f1)

# (Written to a copy first, keeping every other line as it is; the file is
# replaced only once each of the three lines was found.)
for line in pkgver pkgrel sha256sums; do
    grep -q "^$line=" "$pkgbuild" || { echo "pkgbuild-release: no $line= line in $pkgbuild" >&2; exit 1; }
done
sed \
    -e "s/^pkgver=.*/pkgver=$ver/" \
    -e "s/^pkgrel=.*/pkgrel=1/" \
    -e "s/^sha256sums=.*/sha256sums=('$sum')/" \
    "$pkgbuild" >"$tmp/PKGBUILD"
cat "$tmp/PKGBUILD" >"$pkgbuild"
echo "pkgbuild-release: $pkgbuild is now $ver, sha256 $sum"
