#!/bin/sh
# Tests for packaging/arch/aleph-keyring.install, run on any host: a stub
# `systemctl` on the PATH records its calls, and nothing real is touched.
#   sh packaging/arch/tests/hook-test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
hook="$here/../aleph-keyring.install"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

bin="$tmp/bin"
mkdir -p "$bin"

stub_systemctl() { # $1: exit status the stub returns
    cat >"$bin/systemctl" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$tmp/calls"
exit $1
EOF
    chmod +x "$bin/systemctl"
}

# Run a scriptlet function in a fresh sh with only the stub on the PATH
# (plus the system's, for the shell's own tools), returning its output.
run() { # $1: function
    : >"$tmp/calls"
    PATH="$bin:/usr/bin:/bin" sh -c ". '$hook'; $1" >"$tmp/out" 2>"$tmp/err"
}

calls() { tr '\n' ';' <"$tmp/calls"; }

stub_systemctl 0

run post_install || true
[ "$(calls)" = "daemon-reload;enable --now aleph-tpmd.socket;--global enable alephd.socket;" ] \
    && pass "post_install reloads and enables both sockets, in order" \
    || fail "post_install calls: $(calls)"
grep -q "alephctl setup" "$tmp/out" && pass "post_install says what to do next" \
    || fail "post_install prints the next steps"

run post_upgrade || true
[ "$(calls)" = "daemon-reload;enable --now aleph-tpmd.socket;--global enable alephd.socket;try-restart aleph-tpmd.service;" ] \
    && pass "post_upgrade re-runs the enables and restarts the system helper" \
    || fail "post_upgrade calls: $(calls)"
grep -q "restart alephd to pick up the new binary: systemctl --user restart alephd.service" "$tmp/out" \
    && pass "post_upgrade says to restart alephd" \
    || fail "post_upgrade prints the restart message"

run pre_remove || true
[ "$(calls)" = "--global disable alephd.socket;disable --now aleph-tpmd.socket aleph-tpmd.service;" ] \
    && pass "pre_remove disables both sockets" \
    || fail "pre_remove calls: $(calls)"

run post_remove || true
[ "$(calls)" = "daemon-reload;" ] \
    && pass "post_remove reloads" \
    || fail "post_remove calls: $(calls)"
grep -q ".local/share/aleph" "$tmp/out" && pass "post_remove says the vault is left in place" \
    || fail "post_remove mentions the vault"

# (Review Focus 2.) A systemctl that fails never fails the scriptlet, and
# each skipped step is named.
stub_systemctl 1
for fn in post_install post_upgrade pre_remove post_remove; do
    if run "$fn"; then
        pass "$fn returns success when systemctl fails"
    else
        fail "$fn failed the transaction when systemctl failed"
    fi
done
run post_install || true
grep -q "aleph-tpmd.socket.*failed (an enable may still have taken effect): check it yourself" "$tmp/err" && pass "a failed enable names the socket and says it may have worked" \
    || fail "a failed enable is reported (stderr: $(cat "$tmp/err"))"

# No systemctl at all (a chroot): success, and one message says so. The PATH
# is a directory of symlinks to sh and grep only, so the host's real
# systemctl cannot be reached (and the stub is gone).
rm -f "$bin/systemctl"
nobin="$tmp/nobin"
mkdir -p "$nobin"
for tool in sh grep; do
    ln -s "$(command -v "$tool")" "$nobin/$tool"
done
if PATH="$nobin" sh -c 'command -v systemctl' >/dev/null 2>&1; then
    fail "the no-systemctl PATH still reaches a systemctl"
fi
for fn in post_install post_upgrade pre_remove post_remove; do
    if PATH="$nobin" sh -c ". '$hook'; $fn" >"$tmp/out" 2>"$tmp/err"; then
        pass "$fn returns success with no systemctl"
    else
        fail "$fn failed the transaction with no systemctl"
    fi
    grep -q 'systemctl is not available' "$tmp/err" && pass "$fn says systemctl was not available" \
        || fail "$fn is silent when systemctl is missing"
done

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
