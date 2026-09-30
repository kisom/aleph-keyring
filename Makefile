# Convenience targets until there is a package (spec §9).
#
#   make              build the release binaries
#   make gate         the acceptance gate: formatting, clippy, the full suite
#   make gate-hw      only the hardware tests: the real TPM (sudo, unless
#                     you can open /dev/tpmrm0) and a FIDO2 key (one
#                     plugged in; asks for its PIN unless ALEPH_FIDO2_PIN
#                     is set, empty for built-in UV)
#   make install      install the release build (sudo), then restart alephd
#   make uninstall    remove it again (after alephctl setup --revert and
#                     sudo alephctl system revert)
#   make pkg          an Arch package of the working tree, in target/pkg
#                     (install it with sudo pacman -U; nothing is installed)
#   make pkg-test     build and test the packages in an Arch container
#                     (docker; ALEPH_PKG_CACHE=1 keeps cargo's downloads in
#                     the docker volume aleph-pkg-cargo between runs)
#   make deny         cargo deny check: advisories, licenses, sources and
#                     bans, per deny.toml (needs cargo-deny)

CARGO ?= cargo
# (The TPM library's logging would flood the test output.)
export TSS2_LOG ?= all+NONE

SUDO := $(if $(filter 0,$(shell id -u)),,sudo)

.PHONY: all build test lint pkg-shell-test pkg pkg-test pkgbuild-release pkgbuild-aur deny gate gate-hw hw-tpm hw-fido2 install uninstall restart clean

all: build

build:
	$(CARGO) build --release --workspace

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	sh -n packaging/install.sh
	sh -n packaging/arch/aleph-keyring.install
	sh -n packaging/arch/remove-guard
	sh -n packaging/arch/tests/guard-test.sh
	sh -n packaging/arch/tests/hook-test.sh
	sh -n packaging/arch/tests/pkgver-test.sh
	sh -n packaging/arch/tests/release-test.sh
	sh -n packaging/arch/make-pkg.sh
	sh -n packaging/arch/pkgver.sh
	sh -n packaging/arch/pkgbuild-release.sh
	sh -n packaging/arch/pkgbuild-aur.sh
	sh -n packaging/arch/test-packages.sh
	bash -n packaging/arch/common.sh
	bash -n packaging/arch/local/PKGBUILD
	bash -n packaging/arch/aleph-keyring-git/PKGBUILD
	bash -n packaging/arch/aleph-keyring/PKGBUILD

# Shell tests for the package's hook, removal guard, version and release
# helpers: they run on any host, with a stub systemctl and makepkg, a local
# tarball, and temporary directories and git repositories.
pkg-shell-test:
	sh packaging/arch/tests/guard-test.sh
	sh packaging/arch/tests/hook-test.sh
	sh packaging/arch/tests/pkgver-test.sh
	sh packaging/arch/tests/release-test.sh

# A package of the working tree, built as the user in target/pkg (install it
# with `sudo pacman -U`; nothing is installed here).
pkg:
	packaging/arch/make-pkg.sh local

# Build and test the packages in a clean Arch container (needs docker; the
# repository is mounted read-only, nothing on the host is touched). In a git
# worktree the shared git directory is outside the tree, so it is mounted
# read-only at its own path too. ALEPH_PKG_CACHE=1 keeps cargo's registry
# in the docker volume aleph-pkg-cargo (off by default: a clean run).
pkg-test:
	@set -- -v "$$PWD:/src:ro"; \
	common=$$(git rev-parse --path-format=absolute --git-common-dir) && [ -n "$$common" ] || \
		{ echo "make pkg-test: run it in a git checkout of aleph (make-pkg.sh needs git)" >&2; exit 1; }; \
	case "$$common" in "$$PWD"/*) ;; *) set -- "$$@" -v "$$common:$$common:ro" ;; esac; \
	if [ -n "$${ALEPH_PKG_CACHE:-}" ]; then set -- "$$@" -v aleph-pkg-cargo:/work/cargo; fi; \
	set -x; docker run --rm "$$@" archlinux:base-devel sh /src/packaging/arch/test-packages.sh

# Fill in the release PKGBUILD for a pushed tag (downloads the tag's tarball
# from GitHub for its checksum): make pkgbuild-release TAG=v0.1.0
pkgbuild-release:
	@test -n "$(TAG)" || { echo "usage: make pkgbuild-release TAG=vX.Y.Z" >&2; exit 2; }
	sh packaging/arch/pkgbuild-release.sh $(TAG)

# The AUR copies, flattened, in target/aur/ (needs makepkg for .SRCINFO;
# refuses until pkgbuild-release has filled in the checksum).
pkgbuild-aur:
	sh packaging/arch/pkgbuild-aur.sh

gate: lint test pkg-shell-test

# The dependency policy (deny.toml); CI runs it as its own job.
deny:
	$(CARGO) deny check

# The hardware tests are #[ignore]d in the normal suite; each file holds
# only its hardware test, so --ignored runs just that. (golden.rs's
# ignored test regenerates a format file: not a hardware test.)
gate-hw: hw-tpm hw-fido2

# Built as the user, and only the test binary runs as root when needed,
# so target/ never gets root-owned files. Success path only: wrong
# passwords would count towards the real TPM's lockout.
hw-tpm:
	@bin=$$($(CARGO) test -p aleph-tpmd --test tpm_hardware --no-run --message-format=json \
		| jq -r 'select(.profile.test == true and .executable != null) | .executable'); \
	test -n "$$bin" || exit 1; \
	if [ -r /dev/tpmrm0 ] && [ -w /dev/tpmrm0 ]; then \
		"$$bin" --ignored --nocapture; \
	else \
		echo "hw-tpm: /dev/tpmrm0 needs root or the tss group: running the test with sudo"; \
		sudo env TSS2_LOG="$(TSS2_LOG)" $${ALEPH_TCTI:+ALEPH_TCTI="$$ALEPH_TCTI"} "$$bin" --ignored --nocapture; \
	fi

# The PIN is read without echo and passed in the environment only (never
# on a command line).
hw-fido2:
	@if [ -z "$${ALEPH_FIDO2_PIN+set}" ]; then \
		trap 'stty echo' EXIT INT TERM; \
		printf 'FIDO2 PIN (empty for built-in UV): '; stty -echo; read -r pin; stty echo; echo; \
		if [ -n "$$pin" ]; then ALEPH_FIDO2_PIN="$$pin"; export ALEPH_FIDO2_PIN; fi; \
	fi; \
	echo "hw-fido2: touch the key three times to enroll, once to unlock, then twice more"; \
	$(CARGO) test -p aleph-unlock --test fido2_hardware -- --ignored --nocapture

# Not built here: `sudo make install` would leave root-owned files in
# target/. install.sh refuses if the release build is missing.
install:
	$(SUDO) packaging/install.sh install
	@$(MAKE) --no-print-directory restart

uninstall:
	$(SUDO) packaging/install.sh uninstall

# Pick up a reinstalled alephd and its unit. (A running alephd keeps the
# old binary and the old unit's settings until it restarts.)
restart:
	@if [ "$$(id -u)" = 0 ]; then \
		echo "make restart: run as the user: systemctl --user daemon-reload && systemctl --user restart alephd.service"; \
	else \
		systemctl --user daemon-reload && \
		if systemctl --user is-active --quiet alephd.service; then \
			systemctl --user restart alephd.service; \
		fi; \
		systemctl --user start alephd.socket; \
	fi

clean:
	$(CARGO) clean
