# Shared by the three PKGBUILDs: what to build and what to install. The
# layout is exactly packaging/install.sh's, plus the removal guard and the
# license files (spec: docs/superpowers/specs/2026-09-29-aleph-arch-packaging-design.md).
# packaging/arch/files.expected lists the result; test-packages.sh compares.
# $_srcname (the source directory under $srcdir), $pkgdir and $pkgname come
# from the PKGBUILD.

aleph_build() {
  cd "$srcdir/$_srcname"
  export CARGO_TARGET_DIR=target
  cargo build --release --workspace --locked
}

aleph_package() {
  cd "$srcdir/$_srcname"
  local r=target/release

  install -Dm755 "$r/alephctl" "$pkgdir/usr/bin/alephctl"
  install -Dm755 "$r/aleph-gui" "$pkgdir/usr/bin/aleph-gui"
  install -Dm755 "$r/alephd" "$pkgdir/usr/lib/aleph/alephd"
  install -Dm755 "$r/aleph-tpmd" "$pkgdir/usr/lib/aleph/aleph-tpmd"
  install -Dm755 packaging/arch/remove-guard "$pkgdir/usr/lib/aleph/remove-guard"
  install -Dm755 "$r/libpam_aleph.so" "$pkgdir/usr/lib/security/pam_aleph.so"
  install -Dm644 packaging/pam/aleph-check "$pkgdir/etc/pam.d/aleph-check"
  install -Dm644 packaging/hyprland/aleph-prompt.lua \
    "$pkgdir/usr/share/aleph/hyprland/aleph-prompt.lua"
  install -Dm644 packaging/aleph-gui.desktop "$pkgdir/usr/share/applications/aleph-gui.desktop"
  install -Dm644 assets/icons/aleph.svg "$pkgdir/usr/share/icons/hicolor/scalable/apps/aleph.svg"
  install -Dm644 assets/icons/aleph-24.svg "$pkgdir/usr/share/icons/hicolor/24x24/apps/aleph.svg"
  install -Dm644 assets/icons/aleph-16.svg "$pkgdir/usr/share/icons/hicolor/16x16/apps/aleph.svg"
  install -Dm644 assets/icons/aleph-symbolic.svg \
    "$pkgdir/usr/share/icons/hicolor/symbolic/apps/aleph-symbolic.svg"
  install -Dm644 -t "$pkgdir/usr/lib/systemd/system" \
    packaging/systemd/aleph-tpmd.service packaging/systemd/aleph-tpmd.socket
  install -Dm644 -t "$pkgdir/usr/lib/systemd/user" \
    packaging/systemd/alephd.service packaging/systemd/alephd.socket
  # (io.aleph.Keyring only: the Secret Service name's activation file is the
  # user's, written by `alephctl setup`, so gnome-keyring keeps it until then.)
  install -Dm644 packaging/dbus/io.aleph.Keyring.service \
    "$pkgdir/usr/share/dbus-1/services/io.aleph.Keyring.service"
  install -Dm644 packaging/arch/aleph-remove-guard.hook \
    "$pkgdir/usr/share/libalpm/hooks/aleph-remove-guard.hook"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 NOTICE "$pkgdir/usr/share/licenses/$pkgname/NOTICE"
}
