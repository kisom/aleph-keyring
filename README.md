# aleph

![](docs/images/aleph.jpg)

A Secret Service (`org.freedesktop.secrets`) keyring for
[Omarchy](https://omarchy.org), with TPM and FIDO2 unlock. It replaces
gnome-keyring's secrets store; libsecret applications work unmodified.

> *Aleph*: in William Gibson's *Mona Lisa Overdrive*, a biochip holding an
> entire world, sealed away.

**Status:** early development. The design is in
[`docs/superpowers/specs/2026-09-26-aleph-design.md`](docs/superpowers/specs/2026-09-26-aleph-design.md).

Login and screen unlock (`pam_aleph`), `passwd` changes, and locking on
sleep, screen lock, or idle are in place (Plan 4a). `alephctl setup` creates the
keyring,
imports gnome-keyring's items, takes over the Secret Service from it, and
(with `sudo alephctl system apply`) sets up login and screen unlock; `aleph
setup --revert` hands everything back (Plan 4c; see
[docs/testing.md](docs/testing.md), including an emergency manual revert). If
the login password is changed outside aleph, the next unlock asks for the
previous one to update the TPM keyslot. `alephctl backup` and `alephctl restore`
(with the recovery key, from `.bak`, or accepting a rolled-back file) are
in place (Plan 4b). Design decisions made along the way are in
[DECISIONS.md](DECISIONS.md).

## Crates

| Crate | Purpose |
|---|---|
| `aleph-core` | Vault format and cryptography (no D-Bus, no hardware) |
| `aleph-tpm-proto` | Wire protocol between `alephd` and the TPM helper |
| `aleph-tpmd` | The TPM helper service (the only process that talks to the TPM) |
| `aleph-unlock` | TPM client and FIDO2 unlock methods that produce keyslot KEKs |
| `aleph-prompt-proto` | Protocol between `alephd` and its prompters (GUI or terminal) |
| `aleph-pam-proto` | Protocol between `pam_aleph` and `alephd`'s `pam.sock` |
| `aleph-daemon` | `alephd`: the Secret Service and the `io.aleph.Admin1` interface |
| `pam_aleph` | PAM module that hands the login password to `alephd` |
| `aleph-cli` | `alephctl`: the command-line client |

## Development

Tests need `swtpm`, `tpm2-tools`, `tpm2-tss`, `libfido2`, `pam`, `dbus`
and `libsecret` (Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam
dbus libsecret`). Hardware tests are opt-in;
see [docs/testing.md](docs/testing.md).

~~~sh
make gate                # formatting, clippy, the full suite
make && make install     # release build, installed (sudo) until there is a package
~~~

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
