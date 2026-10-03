#!/bin/sh
# Install (or uninstall) aleph from a release build of this tree, the way
# the package lays it out (spec §9). On Arch, `make pkg` is the way (a
# package of this tree); this script stays for other systems:
#
#   make && make install                 # or: make uninstall
#
# (`make install` runs this with sudo, then restarts alephd as the user;
# a running alephd keeps the old binary and unit until it restarts.)
# Then `alephctl setup`.
#
# A pacman-owned aleph is refused: the package's files would make this
# install fail with "exists in filesystem", and removing them by hand
# would leave pacman holding a broken package.
#
# ALEPH_INSTALL_ROOT writes the same tree under a directory instead of /,
# touching nothing else and needing no root: it is for the tests
# (tests/install-layout-test.sh).
set -eu
cd "$(dirname "$0")/.."
R=target/release
root=${ALEPH_INSTALL_ROOT:-}

pacman_owned() {
    # (Only where pacman exists and has the package: elsewhere, and in a
    # test root, the check is about the machine this runs on.)
    command -v pacman >/dev/null 2>&1 && pacman -Qi aleph-keyring >/dev/null 2>&1
}

case "${1:-install}" in
install)
    if pacman_owned; then
        echo "install.sh: aleph is installed as a package (pacman -Qi aleph-keyring):" >&2
        echo "  update it with pacman, or move to this script with 'sudo pacman -R aleph-keyring' first" >&2
        exit 1
    fi
    if [ -z "$root" ] && [ "$(id -u)" != 0 ]; then
        echo "install.sh: run as root (after cargo build --release --workspace)" >&2
        exit 1
    fi
    for f in "$R/alephctl" "$R/alephd" "$R/aleph-tpmd" "$R/aleph-gui" "$R/libpam_aleph.so"; do
        if [ ! -f "$f" ]; then
            echo "install.sh: $f is missing: run cargo build --release --workspace first" >&2
            exit 1
        fi
    done
    install -Dm755 "$R/alephctl" "$root/usr/bin/alephctl"
    install -Dm755 "$R/aleph-gui" "$root/usr/bin/aleph-gui"
    install -Dm755 "$R/alephd" "$root/usr/lib/aleph/alephd"
    install -Dm755 "$R/aleph-tpmd" "$root/usr/lib/aleph/aleph-tpmd"
    install -Dm755 "$R/libpam_aleph.so" "$root/usr/lib/security/pam_aleph.so"
    install -Dm644 packaging/pam/aleph-check "$root/etc/pam.d/aleph-check"
    install -Dm644 packaging/hyprland/aleph-prompt.lua "$root/usr/share/aleph/hyprland/aleph-prompt.lua"
    install -Dm644 packaging/aleph-gui.desktop "$root/usr/share/applications/aleph-gui.desktop"
    install -Dm644 assets/icons/aleph.svg "$root/usr/share/icons/hicolor/scalable/apps/aleph.svg"
    install -Dm644 assets/icons/aleph-24.svg "$root/usr/share/icons/hicolor/24x24/apps/aleph.svg"
    install -Dm644 assets/icons/aleph-16.svg "$root/usr/share/icons/hicolor/16x16/apps/aleph.svg"
    install -Dm644 assets/icons/aleph-symbolic.svg "$root/usr/share/icons/hicolor/symbolic/apps/aleph-symbolic.svg"
    install -Dm644 -t "$root/usr/lib/systemd/system" \
        packaging/systemd/aleph-tpmd.service packaging/systemd/aleph-tpmd.socket
    install -Dm644 -t "$root/usr/lib/systemd/user" \
        packaging/systemd/alephd.service packaging/systemd/alephd.socket
    # (io.aleph.Keyring only: the Secret Service name's activation file is
    # the user's, written by `alephctl setup`, so gnome-keyring keeps it
    # until then.)
    install -Dm644 packaging/dbus/io.aleph.Keyring.service \
        "$root/usr/share/dbus-1/services/io.aleph.Keyring.service"
    if [ -z "$root" ]; then
        gtk-update-icon-cache -q -t /usr/share/icons/hicolor 2>/dev/null || true
        update-desktop-database -q /usr/share/applications 2>/dev/null || true
        systemctl daemon-reload
        systemctl enable --now aleph-tpmd.socket
        systemctl --global enable alephd.socket
        echo "install.sh: installed. As the user: systemctl --user daemon-reload;"
        echo "  systemctl --user start alephd.socket; alephctl setup"
    else
        echo "install.sh: installed under $root"
    fi
    ;;
uninstall)
    if pacman_owned; then
        echo "install.sh: aleph is installed as a package (pacman -Qi aleph-keyring):" >&2
        echo "  remove it with pacman: sudo pacman -R aleph-keyring" >&2
        exit 1
    fi
    if [ -z "$root" ] && [ "$(id -u)" != 0 ]; then
        echo "install.sh: run as root" >&2
        exit 1
    fi
    if [ -e /var/lib/aleph/manifest.json ]; then
        echo "install.sh: the PAM changes are still in place: run alephctl system revert first" >&2
        exit 1
    fi
    user_file="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/.local/share/dbus-1/services/org.freedesktop.secrets.service"
    if grep -qs /usr/lib/aleph/alephd "$user_file"; then
        echo "install.sh: ${SUDO_USER:-root} still has aleph serving the Secret Service: run alephctl setup --revert first" >&2
        exit 1
    fi
    if [ -z "$root" ]; then
        systemctl --global disable alephd.socket || true
        systemctl disable --now aleph-tpmd.socket aleph-tpmd.service || true
    fi
    rm -f "$root/usr/bin/alephctl" "$root/usr/bin/aleph-gui" "$root/usr/lib/aleph/alephd" "$root/usr/lib/aleph/aleph-tpmd" \
        "$root/usr/share/aleph/hyprland/aleph-prompt.lua" \
        "$root/usr/share/applications/aleph-gui.desktop" \
        "$root/usr/share/icons/hicolor/scalable/apps/aleph.svg" "$root/usr/share/icons/hicolor/24x24/apps/aleph.svg" \
        "$root/usr/share/icons/hicolor/16x16/apps/aleph.svg" "$root/usr/share/icons/hicolor/symbolic/apps/aleph-symbolic.svg" \
        "$root/usr/lib/security/pam_aleph.so" "$root/etc/pam.d/aleph-check" \
        "$root/usr/lib/systemd/system/aleph-tpmd.service" "$root/usr/lib/systemd/system/aleph-tpmd.socket" \
        "$root/usr/lib/systemd/user/alephd.service" "$root/usr/lib/systemd/user/alephd.socket" \
        "$root/usr/share/dbus-1/services/io.aleph.Keyring.service"
    if [ -z "$root" ]; then
        rmdir /usr/lib/aleph /usr/share/aleph/hyprland /usr/share/aleph 2>/dev/null || true
        gtk-update-icon-cache -q -t /usr/share/icons/hicolor 2>/dev/null || true
        update-desktop-database -q /usr/share/applications 2>/dev/null || true
        systemctl daemon-reload
        echo "install.sh: uninstalled (the vault in ~/.local/share/aleph is left in place)"
    else
        echo "install.sh: removed from $root"
    fi
    ;;
*)
    echo "usage: install.sh [install|uninstall]" >&2
    exit 2
    ;;
esac
