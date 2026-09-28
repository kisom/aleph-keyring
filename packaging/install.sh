#!/bin/sh
# Install (or uninstall) aleph from a release build of this tree, the way
# the package lays it out (spec §9). Until there is a package:
#
#   cargo build --release --workspace
#   sudo packaging/install.sh            # or: sudo packaging/install.sh uninstall
#
# Then, as the user: `systemctl --user daemon-reload`,
# `systemctl --user start alephd.socket`, and `alephctl setup`.
set -eu
cd "$(dirname "$0")/.."
R=target/release

if [ "$(id -u)" != 0 ]; then
    echo "install.sh: run as root (after cargo build --release --workspace)" >&2
    exit 1
fi

case "${1:-install}" in
install)
    for f in "$R/alephctl" "$R/alephd" "$R/aleph-tpmd" "$R/libpam_aleph.so"; do
        if [ ! -f "$f" ]; then
            echo "install.sh: $f is missing: run cargo build --release --workspace first" >&2
            exit 1
        fi
    done
    install -Dm755 "$R/alephctl" /usr/bin/alephctl
    install -Dm755 "$R/alephd" /usr/lib/aleph/alephd
    install -Dm755 "$R/aleph-tpmd" /usr/lib/aleph/aleph-tpmd
    install -Dm755 "$R/libpam_aleph.so" /usr/lib/security/pam_aleph.so
    install -Dm644 packaging/pam/aleph-check /etc/pam.d/aleph-check
    install -Dm644 -t /usr/lib/systemd/system \
        packaging/systemd/aleph-tpmd.service packaging/systemd/aleph-tpmd.socket
    install -Dm644 -t /usr/lib/systemd/user \
        packaging/systemd/alephd.service packaging/systemd/alephd.socket
    # (io.aleph.Keyring only: the Secret Service name's activation file is
    # the user's, written by `alephctl setup`, so gnome-keyring keeps it
    # until then.)
    install -Dm644 packaging/dbus/io.aleph.Keyring.service \
        /usr/share/dbus-1/services/io.aleph.Keyring.service
    systemctl daemon-reload
    systemctl enable --now aleph-tpmd.socket
    systemctl --global enable alephd.socket
    echo "install.sh: installed. As the user: systemctl --user daemon-reload;"
    echo "  systemctl --user start alephd.socket; alephctl setup"
    ;;
uninstall)
    if [ -e /var/lib/aleph/manifest.json ]; then
        echo "install.sh: the PAM changes are still in place: run alephctl system revert first" >&2
        exit 1
    fi
    user_file="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)/.local/share/dbus-1/services/org.freedesktop.secrets.service"
    if grep -qs /usr/lib/aleph/alephd "$user_file"; then
        echo "install.sh: ${SUDO_USER:-root} still has aleph serving the Secret Service: run alephctl setup --revert first" >&2
        exit 1
    fi
    systemctl --global disable alephd.socket || true
    systemctl disable --now aleph-tpmd.socket aleph-tpmd.service || true
    rm -f /usr/bin/alephctl /usr/lib/aleph/alephd /usr/lib/aleph/aleph-tpmd \
        /usr/lib/security/pam_aleph.so /etc/pam.d/aleph-check \
        /usr/lib/systemd/system/aleph-tpmd.service /usr/lib/systemd/system/aleph-tpmd.socket \
        /usr/lib/systemd/user/alephd.service /usr/lib/systemd/user/alephd.socket \
        /usr/share/dbus-1/services/io.aleph.Keyring.service
    rmdir /usr/lib/aleph 2>/dev/null || true
    systemctl daemon-reload
    echo "install.sh: uninstalled (the vault in ~/.local/share/aleph is left in place)"
    ;;
*)
    echo "usage: install.sh [install|uninstall]" >&2
    exit 2
    ;;
esac
