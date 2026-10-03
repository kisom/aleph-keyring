#!/bin/sh
# Print the version of a package of the working tree (make-pkg.sh):
#   <Cargo.toml version>.r<commit count>[.dirty<UTC timestamp>].g<short hash>
# A tree with uncommitted changes (tracked, deleted or untracked files that
# .gitignore does not ignore) gets .dirty and the time, YYYYMMDDHHMMSS: two
# dirty builds at one commit still differ, and the later one is newer to
# pacman's vercmp. The .dirty sits before .g<hash> so a dirty build sorts
# OLDER than the clean build of the same commit (vercmp compares g against
# d at that position): committing the work and installing the clean package
# is an upgrade, with no "downgrading" warning. A pkgver may not contain a
# hyphen: this one never does.
#   packaging/arch/pkgver.sh [REPOSITORY_ROOT]
# (ALEPH_PKGVER_NOW replaces the timestamp, for the tests.)
set -eu

cd "${1:-.}"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
count=$(git rev-list --count HEAD)
hash=$(git rev-parse --short HEAD)
dirty=
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    dirty=.dirty${ALEPH_PKGVER_NOW:-$(date -u +%Y%m%d%H%M%S)}
fi
printf '%s\n' "$version.r$count$dirty.g$hash"
