#!/usr/bin/env bats
# tests/unit/test_permissions.bats — Tests for user path handling and privilege logic

load ../test_helper.bats

setup() {
    require_root
    TEST_TMPDIR=$(mktemp -d)
    chmod 755 "$TEST_TMPDIR"
    export TEST_TMPDIR
    # create mocks for required tools
    cat >"$TEST_TMPDIR/natpmpc" <<'MOCK'
#!/bin/bash
if [[ "$1" == "-v" ]]; then
  echo "natpmpc 20230423"
  exit 0
fi
exit 0
MOCK
    chmod +x "$TEST_TMPDIR/natpmpc"
    cat >"$TEST_TMPDIR/wg" <<'MOCK'
#!/bin/bash
exit 0
MOCK
    chmod +x "$TEST_TMPDIR/wg"
    cat >"$TEST_TMPDIR/wg-quick" <<'MOCK'
#!/bin/bash
exit 0
MOCK
    chmod +x "$TEST_TMPDIR/wg-quick"
    cat >"$TEST_TMPDIR/ip" <<'MOCK'
#!/bin/bash
if [[ "$1" == "route" && "$2" == "show" && "$3" == "default" ]]; then
  echo "default via 192.168.1.1 dev eth0"
fi
exit 0
MOCK
    chmod +x "$TEST_TMPDIR/ip"
    export PATH="$TEST_TMPDIR:$PATH"
    SCRIPT="$BATS_TEST_DIRNAME/../../pvpnwg.sh"
}

teardown() {
    for u in testA testB testC; do
        id "$u" >/dev/null 2>&1 && userdel -r "$u" 2>/dev/null || true
    done
    rm -rf "$TEST_TMPDIR"
    rm -rf /root/.pvpnwg
}

@test "--user overrides SUDO_USER and creates owned paths" {
    homeA="$TEST_TMPDIR/homeA"
    homeB="$TEST_TMPDIR/homeB"
    useradd -m -d "$homeA" testA
    useradd -m -d "$homeB" testB
    run bash -c "SUDO_USER=testA PVPNWG_NO_MAIN=1 source '$SCRIPT' --user=testB"
    [ "$status" -eq 0 ]
    [ -d "$homeB/.pvpnwg" ]
    [ ! -e "$homeA/.pvpnwg" ]
    owner=$(stat -c %U "$homeB/.pvpnwg")
    [ "$owner" = "testB" ]
}

@test "SUDO_USER determines target user when flag omitted" {
    homeA="$TEST_TMPDIR/homeA"
    useradd -m -d "$homeA" testA
    rm -rf /root/.pvpnwg
    run bash -c "SUDO_USER=testA PVPNWG_NO_MAIN=1 source '$SCRIPT'"
    [ "$status" -eq 0 ]
    [ -d "$homeA/.pvpnwg" ]
    owner=$(stat -c %U "$homeA/.pvpnwg")
    [ "$owner" = "testA" ]
    [ ! -e "/root/.pvpnwg" ]
}

@test "init works unprivileged but status requires root" {
    homeC="$TEST_TMPDIR/homeC"
    useradd -m -d "$homeC" testC
    run runuser -u testC -- bash "$SCRIPT" --dry-run init
    [ "$status" -eq 0 ]
    [ -d "$homeC/.pvpnwg" ]
    owner=$(stat -c %U "$homeC/.pvpnwg")
    [ "$owner" = "testC" ]
    run runuser -u testC -- bash "$SCRIPT" --dry-run status
    [ "$status" -eq 1 ]
    [[ "$output" == *"Passwordless sudo required."* ]]
}
