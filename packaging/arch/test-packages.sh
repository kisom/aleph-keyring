#!/bin/sh
# Build the aleph packages in a clean Arch container and check them (the
# spec's "The package test"). Run inside archlinux:base-devel as root:
#   docker run --rm -v "$PWD:/src:ro" archlinux:base-devel sh /src/packaging/arch/test-packages.sh
# (`make pkg-test` does exactly that, and also mounts a git worktree's
# shared git directory read-only at its own path.) Nothing on the host is
# touched: this writes only under /work, /tmp and the container's system.
set -eu

src=${ALEPH_SRC:-/src}
work=/work
# (cargo's registry; the PKGBUILD builds in its own srcdir, common.sh sets
# CARGO_TARGET_DIR there.)
export CARGO_HOME=/work/cargo

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

# The package's depends (the PKGBUILD's list): makepkg checks them too.
rundeps='tpm2-tss libfido2 pam dbus openssl hicolor-icon-theme wayland libxkbcommon libglvnd'
# Those only aleph-gui loads with dlopen, removed again before pacman -U so
# that the install must bring them back through depends.
guideps='wayland libxkbcommon libglvnd'

# --- environment: an unprivileged builder, the build dependencies, a copy of the tree
# (Three tries: a mirror that drops the connection fails the whole transaction.)
for try in 1 2 3; do
    if pacman -Syu --noconfirm --needed rust clang pkgconf git namcap $rundeps >/dev/null; then
        break
    fi
    [ "$try" -lt 3 ] || { echo "test-packages.sh: pacman could not install the build dependencies" >&2; exit 1; }
    echo "test-packages.sh: pacman failed (try $try of 3), trying again" >&2
done
echo "rustc in the container: $(rustc --version)"
id builder >/dev/null 2>&1 || useradd -m builder
git config --global --add safe.directory '*'
su builder -c 'git config --global --add safe.directory "*"'
mkdir -p "$work"
rm -rf "$work/tree"
mkdir -p "$work/tree"
# (The tree and its .git, but never target/: it can be tens of gigabytes.)
tar -C "$src" --exclude=./target -cf - . | tar -C "$work/tree" -xf -
if [ -f "$work/tree/.git" ]; then
    # A git worktree: its .git file names a directory outside the tree,
    # which make pkg-test mounts read-only at the same path. Make the copy a
    # repository of its own at the worktree's commit, with the worktree's
    # changes still uncommitted (the index is reset to HEAD, the files are
    # left alone), so nothing is written to the mounted directory.
    if ! common=$(git -C "$src" rev-parse --path-format=absolute --git-common-dir) ||
        ! head=$(git -C "$src" rev-parse HEAD); then
        echo "test-packages.sh: $src is a git worktree whose git directory is not mounted" >&2
        exit 1
    fi
    rm "$work/tree/.git"
    cp -a "$common" "$work/tree/.git"
    rm -rf "$work/tree/.git/worktrees"
    git -C "$work/tree" update-ref --no-deref HEAD "$head"
    git -C "$work/tree" reset -q
fi
# A dirty tree on purpose (Review Focus 5): an untracked file the package
# tarball must carry, a tracked file deleted without staging the deletion
# (the tarball must leave it out, and the build must not fail on it), and
# the version must say so.
# (Every packaging file used below comes from this copy, taken once, not
# from the live mount.)
arch=$work/tree/packaging/arch
echo marker >"$work/tree/untracked-marker.txt"
rm "$work/tree/README.md"
chown -R builder: "$work"

as_builder() { su builder -c "cd $work/tree && $*"; }

# --- stub systemctl: records its arguments (the container has no systemd)
mkdir -p /usr/local/bin
cat >/usr/local/bin/systemctl <<'SH'
#!/bin/sh
printf '%s\n' "$*" >>/tmp/systemctl.calls
SH
chmod +x /usr/local/bin/systemctl

# --- build the working-tree package (make pkg's own script, as builder)
# (makepkg's messages and the path go to /tmp/pkg.out, cargo's progress to
# stderr; a failed build stops here, since nothing below can run.)
pkgname=aleph-keyring-local
if as_builder 'CARGO_HOME=/work/cargo sh packaging/arch/make-pkg.sh local' >/tmp/pkg.out; then
    pkg=$(tail -n 1 /tmp/pkg.out)
else
    cat /tmp/pkg.out >&2
    fail "make pkg builds a package of the working tree"
    exit 1
fi
if [ -f "$pkg" ]; then pass "make pkg builds a package of the working tree"; else
    cat /tmp/pkg.out >&2
    fail "make pkg builds a package of the working tree (no file: $pkg)"
    exit 1
fi

# (Review Focus 5.) The tree was made dirty on purpose: the version says so,
# the tarball carries the untracked file, not the deleted one, and never
# target/ or .git; the real index is left alone.
case ${pkg##*/} in
"$pkgname"-*.dirty[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-1-x86_64.pkg.tar.zst)
    pass "a dirty tree gives a .dirty<timestamp> version" ;;
*) fail "a dirty tree gives a .dirty<timestamp> version (package: $pkg)" ;;
esac
# (Two dirty builds a second apart: the later one must be newer to pacman.)
v1=$(as_builder 'ALEPH_PKGVER_NOW=20260929134500 sh packaging/arch/pkgver.sh .')
v2=$(as_builder 'ALEPH_PKGVER_NOW=20260929134501 sh packaging/arch/pkgver.sh .')
[ "$(vercmp "$v2" "$v1")" = 1 ] && pass "a later dirty build is newer to vercmp ($v2 > $v1)" \
    || fail "a later dirty build is newer to vercmp: vercmp $v2 $v1 = $(vercmp "$v2" "$v1")"
tarball=$work/tree/target/pkg/local/aleph-src.tar.gz
tar -tzf "$tarball" >/tmp/tarball.list
if grep -q '^aleph-src/untracked-marker.txt$' /tmp/tarball.list; then pass "the tarball carries an untracked file"; else
    fail "the tarball carries an untracked file"
fi
if grep -q '^aleph-src/README.md$' /tmp/tarball.list; then fail "the tarball must not carry a deleted tracked file"; else
    pass "the tarball leaves out a deleted tracked file"
fi
if (cd "$work/tree" && git status --porcelain -- README.md untracked-marker.txt) >/tmp/status.out &&
    grep -qx ' D README.md' /tmp/status.out && grep -qx '?? untracked-marker.txt' /tmp/status.out; then
    pass "the build left the index alone (the deletion is unstaged, the marker untracked)"
else
    cat /tmp/status.out >&2
    fail "the build left the index alone (the deletion is unstaged, the marker untracked)"
fi
if grep -q '^aleph-src/Cargo.lock$' /tmp/tarball.list; then pass "the tarball carries the tracked files"; else
    fail "the tarball carries the tracked files"
fi
if grep -q '^aleph-src/target/' /tmp/tarball.list; then fail "the tarball must not contain target/"; else
    pass "the tarball never contains target/"
fi
if grep -q '^aleph-src/\.git/' /tmp/tarball.list; then fail "the tarball must not contain .git"; else
    pass "the tarball never contains .git"
fi
# (A pkgver may not contain a hyphen, and makepkg refuses one: the build
# succeeded, so it has none.)

# --- metadata and files, for any of the three packages:
#   check_variant NAME PACKAGE BUILD_DIRECTORY...
# (Each BUILD_DIRECTORY is one no file in the package may name.)
variants='aleph-keyring-local aleph-keyring-git aleph-keyring'
check_variant() {
    name=$1 p=$2
    shift 2
    info=$(pacman -Qip "$p")
    echo "$info" | grep -q "^Name *: $name\$" && pass "$name: the package name" || fail "$name: the package name"
    echo "$info" | grep -q '^Licenses *: Apache-2.0' && pass "$name: the license" || fail "$name: the license"
    for dep in $rundeps; do
        echo "$info" | grep -q "^Depends On .*\\b$dep\\b" && pass "$name: depends on $dep" \
            || fail "$name: depends on $dep"
    done
    echo "$info" | grep -q '^Provides .*org\.freedesktop\.secrets' && pass "$name: provides org.freedesktop.secrets" \
        || fail "$name: provides org.freedesktop.secrets"
    # (The release package is aleph-keyring; the other two provide it.)
    if [ "$name" != aleph-keyring ]; then
        echo "$info" | grep -Eq '^Provides .*[: ]aleph-keyring( |$)' && pass "$name: provides aleph-keyring" \
            || fail "$name: provides aleph-keyring"
    fi
    for other in $variants; do
        [ "$other" != "$name" ] || continue
        echo "$info" | grep -Eq "^Conflicts With .*[: ]$other( |\$)" && pass "$name: conflicts with $other" \
            || fail "$name: conflicts with $other"
    done
    # (pacman -Qip lists no backup files, so .PKGINFO is read for that.)
    bsdtar -xOf "$p" .PKGINFO | grep -qx 'backup = etc/pam.d/aleph-check' \
        && pass "$name: etc/pam.d/aleph-check is a backup file" || fail "$name: etc/pam.d/aleph-check is a backup file"
    echo "$info" | grep -q 'gnome-keyring' && fail "$name: must not mention gnome-keyring" \
        || pass "$name: no gnome-keyring conflict"

    # Files: exactly the expected list, and its modes.
    rm -rf /tmp/extract && mkdir /tmp/extract
    bsdtar -xf "$p" -C /tmp/extract
    (cd /tmp/extract && find . -type f ! -name '.PKGINFO' ! -name '.BUILDINFO' ! -name '.MTREE' ! -name '.INSTALL' \
        -printf '%m %P\n' | sort -k2) >/tmp/files.actual
    sed "s/%PKGNAME%/$name/" "$arch/files.expected" | sort -k2 >/tmp/files.want
    if diff -u /tmp/files.want /tmp/files.actual >/tmp/files.diff; then
        pass "$name: the file list and modes match files.expected"
    else
        cat /tmp/files.diff >&2
        fail "$name: the file list and modes match files.expected"
    fi
    # (The build directories must not leak into the binaries: generated
    # code's panic locations name OUT_DIR, under the target directory;
    # common.sh remaps it.)
    for dir in "$@"; do
        if grep -rl "$dir" /tmp/extract/usr >/tmp/srcdir.refs; then
            cat /tmp/srcdir.refs >&2
            fail "$name: no file in the package names $dir"
        else
            pass "$name: no file in the package names $dir"
        fi
    done
}
check_variant "$pkgname" "$pkg" "$work/tree/target/pkg/local/src"

# --- the hook, with the stub systemctl, through pacman
# (The GUI's libraries go first, -dd: only the package's depends may bring
# them back.)
pacman -Rdd --noconfirm $guideps >/dev/null
for so in libwayland-client.so.0 libxkbcommon.so.0 libEGL.so.1; do
    [ ! -e "/usr/lib/$so" ] || fail "/usr/lib/$so is still there before pacman -U"
done
: >/tmp/systemctl.calls
pacman -U --noconfirm "$pkg" >/tmp/install.out 2>&1 || { cat /tmp/install.out >&2; fail "pacman -U installs the package"; }
want='daemon-reload;enable --now aleph-tpmd.socket;--global enable alephd.socket;'
got=$(tr '\n' ';' </tmp/systemctl.calls)
[ "$got" = "$want" ] && pass "post_install ran the spec's systemctl calls" || fail "post_install calls: $got"
grep -q 'alephctl setup' /tmp/install.out && pass "post_install printed the next steps" || fail "post_install printed the next steps"

# --- run-time libraries, now that pacman installed the package and its
# depends. The linked ones (NEEDED) must resolve; aleph-gui (the prompter
# alephd starts) loads its Wayland, xkbcommon and EGL libraries with
# dlopen, so they are not NEEDED: each soname it names must be installed.
for bin in /usr/bin/alephctl /usr/bin/aleph-gui /usr/lib/aleph/alephd /usr/lib/aleph/aleph-tpmd \
    /usr/lib/security/pam_aleph.so; do
    echo "NEEDED by $bin: $(readelf -d "$bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | tr '\n' ' ')"
    if ldd "$bin" >/tmp/ldd.out 2>&1 && ! grep -q 'not found' /tmp/ldd.out; then
        pass "every linked library of $bin resolves"
    else
        cat /tmp/ldd.out >&2
        fail "every linked library of $bin resolves"
    fi
done
echo "sonames named in aleph-gui (dlopen): $(strings /usr/bin/aleph-gui | grep -oE 'lib[A-Za-z0-9_+-]+\.so\.[0-9]+' | sort -u | tr '\n' ' ')"
for so in libwayland-client.so.0 libwayland-egl.so.1 libxkbcommon.so.0 libEGL.so.1; do
    if ! strings /usr/bin/aleph-gui | grep -q "$so"; then
        fail "aleph-gui names $so (the list of dlopen'd libraries is out of date)"
    elif owner=$(pacman -Qqo "/usr/lib/$so" 2>/dev/null); then
        pass "aleph-gui's $so is installed (from $owner)"
    else
        fail "aleph-gui's $so is installed"
    fi
done

# An upgrade is not a removal: with aleph wired in (the PAM manifest exists,
# as on a set-up machine) the guard must let it through.
mkdir -p /var/lib/aleph && : >/var/lib/aleph/manifest.json
: >/tmp/systemctl.calls
pacman -U --noconfirm "$pkg" >/tmp/upgrade.out 2>&1 \
    && pass "pacman -U of the same package is not blocked while the PAM manifest exists" \
    || { cat /tmp/upgrade.out >&2; fail "pacman -U reinstalls while the PAM manifest exists"; }
rm -f /var/lib/aleph/manifest.json
got=$(tr '\n' ';' </tmp/systemctl.calls)
[ "$got" = "${want}try-restart aleph-tpmd.service;" ] && pass "post_upgrade ran the spec's systemctl calls" || fail "post_upgrade calls: $got"
grep -q 'restart alephd to pick up the new binary: systemctl --user restart alephd.service' /tmp/upgrade.out \
    && pass "post_upgrade printed the restart message" || fail "post_upgrade printed the restart message"

# --- the removal guard through pacman
mkdir -p /var/lib/aleph && : >/var/lib/aleph/manifest.json
: >/tmp/systemctl.calls
if pacman -R --noconfirm "$pkgname" >/tmp/remove.out 2>&1; then
    fail "pacman -R must be refused while the PAM manifest exists"
else
    pass "pacman -R is refused while the PAM manifest exists"
fi
pacman -Q "$pkgname" >/dev/null 2>&1 && pass "the package is still installed after the refusal" \
    || fail "the package is still installed after the refusal"
grep -q 'alephctl system revert' /tmp/remove.out && pass "the refusal names alephctl system revert" \
    || { cat /tmp/remove.out >&2; fail "the refusal names alephctl system revert"; }
[ ! -s /tmp/systemctl.calls ] && pass "a refused removal runs no scriptlet" \
    || fail "a refused removal runs no scriptlet: $(tr '\n' ';' </tmp/systemctl.calls)"
rm -f /var/lib/aleph/manifest.json

id tester >/dev/null 2>&1 || useradd -m tester
mkdir -p /home/tester/.local/share/dbus-1/services
printf 'Exec=/usr/lib/aleph/alephd\n' >/home/tester/.local/share/dbus-1/services/org.freedesktop.secrets.service
if pacman -R --noconfirm "$pkgname" >/tmp/remove2.out 2>&1; then
    fail "pacman -R must be refused while a user's Secret Service is aleph"
else
    pass "pacman -R is refused while a user's Secret Service is aleph"
fi
pacman -Q "$pkgname" >/dev/null 2>&1 && pass "the package is still installed after the second refusal" \
    || fail "the package is still installed after the second refusal"
grep -q 'alephctl setup --revert' /tmp/remove2.out && pass "the refusal names alephctl setup --revert" \
    || { cat /tmp/remove2.out >&2; fail "the refusal names alephctl setup --revert"; }
rm -f /home/tester/.local/share/dbus-1/services/org.freedesktop.secrets.service

: >/tmp/systemctl.calls
pacman -R --noconfirm "$pkgname" >/tmp/remove3.out 2>&1 && pass "pacman -R succeeds with nothing wired in" \
    || { cat /tmp/remove3.out >&2; fail "pacman -R succeeds with nothing wired in"; }
pacman -Q "$pkgname" >/dev/null 2>&1 && fail "the package is gone after the removal" \
    || pass "the package is gone after the removal"
got=$(tr '\n' ';' </tmp/systemctl.calls)
want='--global disable alephd.socket;disable --now aleph-tpmd.socket aleph-tpmd.service;daemon-reload;'
[ "$got" = "$want" ] && pass "pre_remove and post_remove ran the spec's systemctl calls" || fail "removal calls: $got"

# --- the -git and release packages
# Both build in one directory, $vdir, one after the other, so their $srcdir
# is the same path; with one target directory outside it (common.sh's
# ALEPH_CARGO_TARGET_DIR) cargo's flags are the same and the release build
# reuses the dependencies the -git build compiled. The workspace's own
# crates are cleaned between the two, so each compiles them from its own
# source (checked below), and each package is checked on its own.
vdir=$work/variant
vtarget=$work/variant-target
pkgs=$work/pkgs
# ($vtarget is left for cargo to make, under /work, which is builder's:
# cargo clean refuses a target directory without the CACHEDIR.TAG that
# cargo writes when it makes one.)
rm -rf "$vdir" "$vtarget" "$pkgs"
mkdir -p "$vdir" "$pkgs/git" "$pkgs/release"
chown -R builder: "$vdir" "$pkgs"
# (makepkg in $vdir as builder; its output and cargo's go to the log.)
makepkg_variant() {
    t0=$(date +%s)
    su builder -c "cd $vdir && CARGO_HOME=/work/cargo ALEPH_CARGO_TARGET_DIR=$vtarget makepkg -f --noconfirm --nocolor" \
        >"$1" 2>&1
    rc=$?
    echo "makepkg in $vdir: $(($(date +%s) - t0))s, $(grep -c ' Compiling ' "$1") crates compiled"
    return $rc
}

# The -git package builds a git repository: the copy of the tree with its
# dirty state committed on a scratch branch, so the build sees what the
# local package saw (the marker, and no README.md), as git+file://.
as_builder 'git checkout -q -b pkg-test-git && git add -A && git -c user.name=pkg-test -c user.email=pkg-test@localhost commit -qm pkg-test-working-tree'
head=$(git -C "$work/tree" rev-parse --short HEAD)
cp "$arch/aleph-keyring-git/PKGBUILD" "$vdir/PKGBUILD"
cp -L "$arch/common.sh" "$arch/aleph-keyring.install" "$vdir/"
sed -i "s|^source=.*|source=(\"aleph-src::git+file://$work/tree\")|" "$vdir/PKGBUILD"
chown -R builder: "$vdir"
gitpkg=
if makepkg_variant /tmp/git-build.out &&
    gitpkg=$(ls "$vdir"/aleph-keyring-git-[0-9]*.pkg.tar.zst 2>/dev/null) && [ -f "$gitpkg" ]; then
    pass "aleph-keyring-git: makepkg builds the package from git+file://"
else
    tail -n 60 /tmp/git-build.out >&2
    fail "aleph-keyring-git: makepkg builds the package from git+file://"
    gitpkg=
fi
if [ -n "$gitpkg" ]; then
    case ${gitpkg##*/} in
    aleph-keyring-git-0.1.0.r[0-9]*.g"$head"-1-x86_64.pkg.tar.zst)
        pass "aleph-keyring-git: pkgver() is <version>.r<count>.g<hash> of the commit built ($head)" ;;
    *) fail "aleph-keyring-git: pkgver() is <version>.r<count>.g<hash> of $head (package: $gitpkg)" ;;
    esac
    [ -f "$vdir/src/aleph-src/untracked-marker.txt" ] && [ ! -e "$vdir/src/aleph-src/README.md" ] \
        && pass "aleph-keyring-git: the build's source is the committed working tree" \
        || fail "aleph-keyring-git: the build's source is the committed working tree"
    grep -Eq 'Compiling aleph-cli v[^ ]+ \(.*/src/aleph-src/crates/aleph-cli\)' /tmp/git-build.out \
        && pass "aleph-keyring-git: cargo compiled the workspace from its own source" \
        || fail "aleph-keyring-git: cargo compiled the workspace from its own source"
    mv "$gitpkg" "$pkgs/git/" && gitpkg=$pkgs/git/${gitpkg##*/}
    cp "$vdir/PKGBUILD" "$pkgs/git/PKGBUILD"
    check_variant aleph-keyring-git "$gitpkg" "$vdir/src" "$vtarget"
fi

# The release package builds a `git archive` tarball of that commit, as
# GitHub's tag tarball is. pkgbuild-release.sh (on a scratch copy of
# packaging/arch, reading the tarball through a file:// URL) writes its
# version and real checksum into the PKGBUILD, and makepkg must verify it;
# only the source URL is pointed at the local file.
relver=$(sed -n 's/^pkgver=//p' "$arch/aleph-keyring/PKGBUILD")
reltar=$pkgs/release/aleph-keyring-$relver.tar.gz
as_builder "git archive --prefix=aleph-keyring-$relver/ -o $reltar HEAD"
relsum=$(sha256sum "$reltar" | cut -d' ' -f1)
rm -rf "$work/arch"
cp -a "$arch" "$work/arch"
chown -R builder: "$work/arch"
if su builder -c "ALEPH_ARCH_DIR=$work/arch ALEPH_RELEASE_TARBALL_URL=file://$reltar sh $work/arch/pkgbuild-release.sh v$relver" \
    >/tmp/release-fill.out 2>&1; then
    pass "pkgbuild-release fills in the release PKGBUILD"
else
    cat /tmp/release-fill.out >&2
    fail "pkgbuild-release fills in the release PKGBUILD"
fi
# (cargo keys a workspace crate by its path relative to the workspace, and
# git archive keeps the commit's times, older than the -git build's
# outputs: without this the release build takes the -git build's binaries
# as fresh and compiles nothing. The dependencies stay.)
if [ -d "$vdir/src/aleph-src" ]; then
    su builder -c "cd $vdir/src/aleph-src && CARGO_HOME=/work/cargo cargo clean --release --workspace --target-dir $vtarget" \
        >/tmp/clean.out 2>&1 || { cat /tmp/clean.out >&2; fail "cargo clean of the workspace's crates between the builds"; }
fi
rm -rf "$vdir"
mkdir -p "$vdir"
cp "$work/arch/aleph-keyring/PKGBUILD" "$vdir/PKGBUILD"
cp -L "$arch/common.sh" "$arch/aleph-keyring.install" "$reltar" "$vdir/"
sed -i "s|^source=.*|source=(\"aleph-keyring-\$pkgver.tar.gz\")|" "$vdir/PKGBUILD"
chown -R builder: "$vdir"
grep -q "^sha256sums=('$relsum')" "$vdir/PKGBUILD" && pass "aleph-keyring: the PKGBUILD carries the tarball's checksum" \
    || fail "aleph-keyring: the PKGBUILD carries the tarball's checksum"
relpkg=
if makepkg_variant /tmp/release-build.out &&
    relpkg=$(ls "$vdir"/aleph-keyring-"$relver"-*.pkg.tar.zst 2>/dev/null) && [ -f "$relpkg" ]; then
    pass "aleph-keyring: makepkg builds the release package from the tarball"
else
    tail -n 60 /tmp/release-build.out >&2
    fail "aleph-keyring: makepkg builds the release package from the tarball"
    relpkg=
fi
if [ -n "$relpkg" ]; then
    # (Verified, not skipped: a SKIP checksum builds too.)
    grep -q "aleph-keyring-$relver.tar.gz \.\.\. Passed" /tmp/release-build.out \
        && pass "aleph-keyring: makepkg verified the tarball's checksum" \
        || { grep -A3 'Validating source' /tmp/release-build.out >&2; fail "aleph-keyring: makepkg verified the tarball's checksum"; }
    grep -Eq "Compiling aleph-cli v[^ ]+ \\(.*/src/aleph-keyring-$relver/crates/aleph-cli\\)" /tmp/release-build.out \
        && pass "aleph-keyring: cargo compiled the workspace from its own source" \
        || fail "aleph-keyring: cargo compiled the workspace from its own source"
    mv "$relpkg" "$pkgs/release/" && relpkg=$pkgs/release/${relpkg##*/}
    cp "$vdir/PKGBUILD" "$pkgs/release/PKGBUILD"
    check_variant aleph-keyring "$relpkg" "$vdir/src" "$vtarget"
fi

# The AUR copies, from the filled-in scratch copy, with the real makepkg
# writing each .SRCINFO (as builder: makepkg refuses root).
if su builder -c "ALEPH_ARCH_DIR=$work/arch ALEPH_AUR_OUT=$work/aur sh $work/arch/pkgbuild-aur.sh" >/tmp/aur.out 2>&1; then
    pass "pkgbuild-aur writes the AUR copies"
else
    cat /tmp/aur.out >&2
    fail "pkgbuild-aur writes the AUR copies"
fi
for name in aleph-keyring aleph-keyring-git; do
    grep -qx "pkgbase = $name" "$work/aur/$name/.SRCINFO" 2>/dev/null \
        && grep -qx '	depends = libglvnd' "$work/aur/$name/.SRCINFO" \
        && grep -qx '	install = aleph-keyring.install' "$work/aur/$name/.SRCINFO" \
        && pass "$name: makepkg --printsrcinfo reads the flattened PKGBUILD" \
        || { cat "$work/aur/$name/.SRCINFO" >&2 || true; fail "$name: makepkg --printsrcinfo reads the flattened PKGBUILD"; }
done
grep -qx "	sha256sums = $relsum" "$work/aur/aleph-keyring/.SRCINFO" 2>/dev/null \
    && pass "aleph-keyring: the AUR .SRCINFO carries the release checksum" \
    || fail "aleph-keyring: the AUR .SRCINFO carries the release checksum"

# What the variant switch did, from pacman's output and what is installed
# after it: switch_outcome OUTPUT INSTALLED prints `allowed` (the -git
# package replaced the local one), `blocked` (the removal guard refused it:
# its message is in the output and the local package stays), or
# `failed: <pacman's first error line>` for anything else.
# >>> switch_outcome
switch_outcome() {
    if [ "$2" = "aleph-keyring-git " ]; then
        echo allowed
    elif [ "$2" = "aleph-keyring-local " ] && grep -q 'aleph: the PAM changes are still in place' "$1"; then
        echo blocked
    else
        e=$(grep -m 1 '^error:' "$1" || head -n 1 "$1")
        echo "failed: ${e:-(no output)}"
    fi
}
# <<< switch_outcome

# --- the three refuse to install together
if [ -n "$gitpkg" ] && [ -n "$relpkg" ]; then
    # (By exact name: pacman -Q aleph-keyring also finds a package that
    # provides it.)
    installed() { pacman -Qq | grep -Ex 'aleph-keyring(-git|-local)?' | tr '\n' ' '; }
    if pacman -U --noconfirm "$pkg" "$gitpkg" "$relpkg" >/tmp/co.out 2>&1; then
        fail "pacman -U of the three packages at once must fail"
    else
        pass "pacman -U of the three packages at once fails"
    fi
    [ -z "$(installed)" ] && pass "none is installed after the refused install" \
        || fail "none is installed after the refused install: $(installed)"
    pacman -U --noconfirm "$pkg" >/tmp/co.out 2>&1 || { cat /tmp/co.out >&2; fail "pacman -U installs the local package"; }
    # (pacman asks whether to remove the conflicting package; --noconfirm
    # answers no, so the install fails.)
    for other in "$gitpkg" "$relpkg"; do
        if pacman -U --noconfirm "$other" >/tmp/co.out 2>&1; then
            fail "installing ${other##*/} over the local package must fail"
        else
            pass "installing ${other##*/} over the local package fails"
        fi
        [ "$(installed)" = "aleph-keyring-local " ] && pass "only the local package is installed after that" \
            || fail "only the local package is installed after that: $(installed)"
    done

    # The variant switch under the guard (the spec's recorded limitation):
    # with the PAM manifest in place, replace the local package with the
    # -git one, letting pacman remove the conflict (--ask=4). What happens
    # is recorded, not asserted.
    mkdir -p /var/lib/aleph && : >/var/lib/aleph/manifest.json
    pacman -U --noconfirm --ask=4 "$gitpkg" >/tmp/switch.out 2>&1 || true
    echo "note - variant switch under the guard: $(switch_outcome /tmp/switch.out "$(installed)")"
    sed -n '/remove-guard\|aleph:\|alephctl\|conflict\|^error:/p' /tmp/switch.out | sed 's/^/    /'
    rm -f /var/lib/aleph/manifest.json

    # With the -git package installed, the release one is refused too.
    pacman -Rdd --noconfirm $(installed) >/dev/null 2>&1 || true
    pacman -U --noconfirm "$gitpkg" >/tmp/co.out 2>&1 || { cat /tmp/co.out >&2; fail "pacman -U installs the -git package"; }
    if pacman -U --noconfirm "$relpkg" >/tmp/co.out 2>&1; then
        fail "installing the release package over the -git package must fail"
    else
        pass "installing the release package over the -git package fails"
    fi
    [ "$(installed)" = "aleph-keyring-git " ] && pass "only the -git package is installed after that" \
        || fail "only the -git package is installed after that: $(installed)"
    pacman -R --noconfirm aleph-keyring-git >/tmp/co.out 2>&1 || { cat /tmp/co.out >&2; fail "pacman -R removes the -git package"; }
else
    fail "the co-install and variant-switch checks need the -git and release packages"
fi

# --- namcap on each PKGBUILD and each package: warnings only
# (The repository-style PKGBUILDs, as built here, source common.sh from
# $startdir; the flattened AUR copies are the files actually published.)
: >/tmp/namcap.out
namcap_one() { # LABEL FILE
    [ -n "$2" ] && [ -f "$2" ] || return 0
    printf '== %s: %s\n' "$1" "$2" >>/tmp/namcap.out
    namcap "$2" >>/tmp/namcap.out 2>&1 || true
}
namcap_one "repository PKGBUILD (local)" "$work/tree/target/pkg/local/PKGBUILD"
namcap_one "package (local)" "$pkg"
namcap_one "repository PKGBUILD (-git)" "$pkgs/git/PKGBUILD"
namcap_one "package (-git)" "${gitpkg:-}"
namcap_one "repository PKGBUILD (release)" "$pkgs/release/PKGBUILD"
namcap_one "package (release)" "${relpkg:-}"
namcap_one "AUR PKGBUILD (published, -git)" "$work/aur/aleph-keyring-git/PKGBUILD"
namcap_one "AUR PKGBUILD (published, release)" "$work/aur/aleph-keyring/PKGBUILD"
echo "namcap (warnings only):"
cat /tmp/namcap.out

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
echo "all package checks passed"
