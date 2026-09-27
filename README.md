# aleph

![](docs/images/aleph.jpg)

A Secret Service (`org.freedesktop.secrets`) keyring for
[Omarchy](https://omarchy.org), with TPM and FIDO2 unlock. It replaces
gnome-keyring's secrets store; libsecret applications work unmodified.

> *Aleph*: in William Gibson's *Mona Lisa Overdrive*, a biochip holding an
> entire world, sealed away.

**Status:** early development. The design is in
[`docs/superpowers/specs/2026-09-26-aleph-design.md`](docs/superpowers/specs/2026-09-26-aleph-design.md).

## Crates

| Crate | Purpose |
|---|---|
| `aleph-core` | Vault format and cryptography (no D-Bus, no hardware) |
| `aleph-tpm-proto` | Wire protocol between `alephd` and the TPM helper |
| `aleph-tpmd` | The TPM helper service (the only process that talks to the TPM) |
| `aleph-unlock` | TPM client and FIDO2 unlock methods that produce keyslot KEKs |

## Development

Tests need `swtpm`, `tpm2-tools`, `tpm2-tss` and `libfido2` (Arch:
`pacman -S swtpm tpm2-tools tpm2-tss libfido2`). Hardware tests are opt-in;
see [docs/testing.md](docs/testing.md).

~~~sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
~~~

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
