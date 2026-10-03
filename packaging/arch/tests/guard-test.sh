#!/bin/sh
# Tests for packaging/arch/remove-guard, run on any host: a temporary state
# directory and a fake passwd file stand in for /var/lib/aleph and getent.
#   sh packaging/arch/tests/guard-test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
guard="$here/../remove-guard"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }
pass() { printf 'ok - %s\n' "$1"; }

# A fresh world: no manifest, one user with a home and no activation file.
# The proc root is a fixture too: the real /proc carries this machine's
# live XDG_DATA_HOME values, which would leak into the check.
world() {
    rm -rf "$tmp/state" "$tmp/homes" "$tmp/passwd" "$tmp/proc"
    mkdir -p "$tmp/state" "$tmp/homes/alice/.local/share/dbus-1/services" "$tmp/proc"
    printf 'alice:x:1000:1000::%s/homes/alice:/bin/sh\n' "$tmp" >"$tmp/passwd"
}

run() {
    ALEPH_STATE_DIR="$tmp/state" ALEPH_PASSWD_CMD="cat $tmp/passwd" \
        ALEPH_PROC_ROOT="$tmp/proc" \
        timeout 5 sh "$guard" >"$tmp/out" 2>"$tmp/err"
}

expect_allow() {
    if run; then pass "$1"; else fail "$1 (refused: $(cat "$tmp/err"))"; fi
}
expect_refuse() {
    if run; then fail "$1 (allowed)"; else pass "$1"; fi
}

world
expect_allow "nothing is wired in: removal is allowed"

world
: >"$tmp/state/manifest.json"
expect_refuse "an (even empty) PAM manifest refuses"
grep -q "alephctl system revert" "$tmp/err" || fail "the refusal names alephctl system revert"

world
mkdir "$tmp/state/manifest.json"
expect_refuse "a manifest that is a directory still refuses (something is there)"

world
printf 'Name=org.freedesktop.secrets\nExec=/usr/lib/aleph/alephd\n' \
    >"$tmp/homes/alice/.local/share/dbus-1/services/org.freedesktop.secrets.service"
expect_refuse "a user whose Secret Service is aleph refuses"
grep -q "alephctl setup --revert" "$tmp/err" || fail "the refusal names alephctl setup --revert"
grep -q "alice" "$tmp/err" || fail "the refusal names the user"

world
printf 'Name=org.freedesktop.secrets\nExec=/usr/bin/gnome-keyring-daemon\n' \
    >"$tmp/homes/alice/.local/share/dbus-1/services/org.freedesktop.secrets.service"
expect_allow "an activation file naming another program allows"

# (Review Focus 1.) A home with spaces, one that does not exist, one that is
# empty, an unreadable file, and an empty passwd.
world
mkdir -p "$tmp/homes/bob smith/.local/share/dbus-1/services"
printf 'bob:x:1001:1001::%s/homes/bob smith:/bin/sh\n' "$tmp" >>"$tmp/passwd"
printf 'Exec=/usr/lib/aleph/alephd\n' \
    >"$tmp/homes/bob smith/.local/share/dbus-1/services/org.freedesktop.secrets.service"
expect_refuse "a home with a space in its name is read"
grep -q "bob" "$tmp/err" || fail "the refusal names bob"

world
printf 'carol:x:1002:1002::/nonexistent/carol:/bin/sh\ndave:x:1003:1003:::/bin/sh\n' >>"$tmp/passwd"
expect_allow "a home that does not exist, and an empty one, are skipped"
grep -q "carol's home /nonexistent/carol does not exist" "$tmp/err" \
    || fail "a missing home is warned about, naming the user"
grep -q "once the home is back" "$tmp/err" \
    || fail "the missing-home warning says what to do"

# (Review Focus 6.) A custom XDG_DATA_HOME moves the activation file out of
# ~/.local/share. The guard reads it from the user's running processes.
world
mkdir -p "$tmp/proc/4242" "$tmp/homes/alice/custom-data/dbus-1/services"
# (alice's uid is the tester's, so the fixture process counts as hers.)
printf 'alice:x:%s:%s::%s/homes/alice:/bin/sh\n' "$(id -u)" "$(id -g)" "$tmp" >"$tmp/passwd"
printf 'XDG_DATA_HOME=%s/homes/alice/custom-data\0HOME=%s/homes/alice\n' "$tmp" "$tmp" \
    >"$tmp/proc/4242/environ"
printf 'Exec=/usr/lib/aleph/alephd\n' \
    >"$tmp/homes/alice/custom-data/dbus-1/services/org.freedesktop.secrets.service"
expect_refuse "an activation file under a process's XDG_DATA_HOME refuses"
grep -q "alice" "$tmp/err" || fail "the XDG_DATA_HOME refusal names the user"

world
mkdir -p "$tmp/proc/4242"
# (The process's owner is whoever runs the test; alice's uid here is not
# that, so the environ must not be consulted for her. The activation file
# lives only where that environ's XDG_DATA_HOME points.)
printf 'alice:x:424242:424242::%s/homes/alice:/bin/sh\n' "$tmp" >"$tmp/passwd"
printf 'XDG_DATA_HOME=%s/homes/bob/data\0\n' "$tmp" >"$tmp/proc/4242/environ"
mkdir -p "$tmp/homes/bob/data/dbus-1/services"
printf 'Exec=/usr/lib/aleph/alephd\n' \
    >"$tmp/homes/bob/data/dbus-1/services/org.freedesktop.secrets.service"
expect_allow "another user's XDG_DATA_HOME is not alice's"

world
f="$tmp/homes/alice/.local/share/dbus-1/services/org.freedesktop.secrets.service"
printf 'Exec=/usr/lib/aleph/alephd\n' >"$f"
chmod 000 "$f"
if [ "$(id -u)" -ne 0 ]; then
    # An unreadable file cannot be read as aleph's: allow, but never crash.
    expect_allow "an unreadable activation file is not taken for aleph's"
    grep -q "org.freedesktop.secrets.service" "$tmp/err" \
        || fail "an unreadable activation file is warned about, naming it"
fi
chmod 644 "$f"

world
: >"$tmp/passwd"
expect_allow "no users at all allows"

world
if ALEPH_STATE_DIR="$tmp/state" ALEPH_PASSWD_CMD="false" sh "$guard" >"$tmp/out" 2>"$tmp/err"; then
    pass "a passwd command that fails does not refuse by itself"
else
    fail "a passwd command that fails does not refuse by itself"
fi
grep -q "could not list the users" "$tmp/err" \
    || fail "a passwd command that fails is warned about (stderr: $(cat "$tmp/err"))"

# A user name with a space is printed intact, one line per user.
world
mkdir -p "$tmp/homes/eve/.local/share/dbus-1/services"
printf 'eve smith:x:1004:1004::%s/homes/eve:/bin/sh\n' "$tmp" >"$tmp/passwd"
printf "Exec=/usr/lib/aleph/alephd\n" \
    >"$tmp/homes/eve/.local/share/dbus-1/services/org.freedesktop.secrets.service"
expect_refuse "a user whose name has a space refuses"
grep -q "aleph: eve smith still has aleph serving" "$tmp/err" \
    || fail "the refusal prints the name intact (stderr: $(cat "$tmp/err"))"

# A FIFO (or a symlink to one) at the activation path must not hang root.
if command -v mkfifo >/dev/null 2>&1; then
    world
    mkfifo "$tmp/homes/alice/.local/share/dbus-1/services/org.freedesktop.secrets.service"
    expect_allow "a FIFO at the activation path is not read (no hang)"
    world
    mkfifo "$tmp/fifo"
    ln -s "$tmp/fifo" "$tmp/homes/alice/.local/share/dbus-1/services/org.freedesktop.secrets.service"
    expect_allow "a symlink to a FIFO at the activation path is not read (no hang)"
    rm -f "$tmp/fifo"
fi

if [ "$failures" -ne 0 ]; then
    printf '%s failure(s)\n' "$failures" >&2
    exit 1
fi
