# Convenience targets until there is a package (spec §9).
#
#   make              build the release binaries
#   make gate         the acceptance gate: formatting, clippy, the full suite
#   make install      install the release build (sudo), then restart alephd
#   make uninstall    remove it again (after alephctl setup --revert and
#                     sudo alephctl system revert)

CARGO ?= cargo
# (The TPM library's logging would flood the test output.)
export TSS2_LOG ?= all+NONE

SUDO := $(if $(filter 0,$(shell id -u)),,sudo)

.PHONY: all build test lint gate install uninstall restart clean

all: build

build:
	$(CARGO) build --release --workspace

test:
	$(CARGO) test --workspace

lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	sh -n packaging/install.sh

gate: lint test

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
