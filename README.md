# aleph

![](docs/images/aleph.jpg)

A Secret Service (`org.freedesktop.secrets`) keyring for
[Omarchy](https://omarchy.org), with TPM and FIDO2 unlock. It replaces
gnome-keyring's secrets store; libsecret applications work unmodified.

> *Aleph*: in William Gibson's *Mona Lisa Overdrive*, a biochip holding an
> entire world, sealed away.

**Status:** early development. The design is in
[`docs/superpowers/specs/2026-09-26-aleph-design.md`](docs/superpowers/specs/2026-09-26-aleph-design.md).

Not yet handled: changing your login password outside aleph (`passwd`).
TPM keyslots are sealed under the login password; after an outside change
they go stale, and until session integration lands (re-sealing with the
previous password, recovery-key unlock) the way back in is to set the
previous password again. A FIDO2 keyslot is unaffected.

## Crates

| Crate | Purpose |
|---|---|
| `aleph-core` | Vault format and cryptography (no D-Bus, no hardware) |
| `aleph-tpm-proto` | Wire protocol between `alephd` and the TPM helper |
| `aleph-tpmd` | The TPM helper service (the only process that talks to the TPM) |
| `aleph-unlock` | TPM client and FIDO2 unlock methods that produce keyslot KEKs |
| `aleph-prompt-proto` | Protocol between `alephd` and its prompters (GUI or terminal) |
| `aleph-daemon` | `alephd`: the Secret Service and the `io.aleph.Admin1` interface |
| `aleph-cli` | `aleph`: the command-line client |

## Development

Tests need `swtpm`, `tpm2-tools`, `tpm2-tss`, `libfido2`, `pam`, `dbus`
and `libsecret` (Arch: `pacman -S swtpm tpm2-tools tpm2-tss libfido2 pam
dbus libsecret`). Hardware tests are opt-in;
see [docs/testing.md](docs/testing.md).

~~~sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
~~~

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
