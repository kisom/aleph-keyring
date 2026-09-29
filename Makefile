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

CARGO ?= cargo
# (The TPM library's logging would flood the test output.)
export TSS2_LOG ?= all+NONE

SUDO := $(if $(filter 0,$(shell id -u)),,sudo)

.PHONY: all build test lint pkg-shell-test gate gate-hw hw-tpm hw-fido2 install uninstall restart clean

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

# Shell tests for the package's hook and removal guard: they run on any
# host, with a stub systemctl and temporary directories.
pkg-shell-test:
	sh packaging/arch/tests/guard-test.sh
	sh packaging/arch/tests/hook-test.sh

gate: lint test pkg-shell-test

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
