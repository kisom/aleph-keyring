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

## Development

~~~sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
~~~

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
