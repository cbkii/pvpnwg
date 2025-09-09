#!/usr/bin/env bats
# tests/unit/test_install.bats — tests for install.sh dependency checks

load ../test_helper.bats

setup() {
    require_root
    TEST_TMPDIR=$(mktemp -d)
    export TEST_TMPDIR
    # Create mocks for required dependencies except natpmpc
    for dep in ip wg wg-quick curl jq awk sed grep ping; do
        cat >"$TEST_TMPDIR/$dep" <<'MOCK'
#!/bin/bash
exit 0
MOCK
        chmod +x "$TEST_TMPDIR/$dep"
    done
    export PATH="$TEST_TMPDIR:$PATH"
    SCRIPT="$BATS_TEST_DIRNAME/../../install.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

@test "installation fails when natpmpc is missing" {
    run bash "$SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"natpmpc"* ]]
}

@test "installation fails when natpmpc is outdated" {
    cat >"$TEST_TMPDIR/natpmpc" <<'MOCK'
#!/bin/bash
exit 0
MOCK
    chmod +x "$TEST_TMPDIR/natpmpc"
    cat >"$TEST_TMPDIR/dpkg-query" <<'MOCK'
#!/bin/bash
echo "20150101-1"
MOCK
    chmod +x "$TEST_TMPDIR/dpkg-query"
    run bash "$SCRIPT"
    [ "$status" -ne 0 ]
    [[ "$output" == *"natpmpc"* ]]
}

@test "install_natpmpc_unstable augments existing pin file" {
    # stubs for commands used by install_natpmpc_unstable
    cat >"$TEST_TMPDIR/apt-get" <<'MOCK'
#!/bin/sh
exit 0
MOCK
    chmod +x "$TEST_TMPDIR/apt-get"

    cat >"$TEST_TMPDIR/apt-cache" <<'MOCK'
#!/bin/sh
echo "  Candidate: (none)"
MOCK
    chmod +x "$TEST_TMPDIR/apt-cache"

    cat >"$TEST_TMPDIR/dpkg-query" <<'MOCK'
#!/bin/sh
echo "20230423-1.2"
MOCK
    chmod +x "$TEST_TMPDIR/dpkg-query"

    cat >"$TEST_TMPDIR/natpmpc" <<'MOCK'
#!/bin/sh
echo "natpmpc help"
MOCK
    chmod +x "$TEST_TMPDIR/natpmpc"

    local PIN_FILE="/etc/apt/preferences.d/pvpn-natpmpc.pref"
    local SRC_LIST="/etc/apt/sources.list.d/debian-unstable.list"
    mkdir -p /etc/apt/preferences.d
    cat >"$PIN_FILE" <<'EOF'
Package: *
Pin: release a=unstable
Pin-Priority: 100

Package: foo
Pin: release a=unstable
Pin-Priority: 501
EOF

    function_code=$(/usr/bin/awk '/^install_natpmpc_unstable\(\)/,/^}/' "$SCRIPT")
    cat >"$TEST_TMPDIR/run.sh" <<EOF
NATPMP_MIN_VER=$(/usr/bin/awk -F'"' '/NATPMP_MIN_VER=/ {print $2}' "$SCRIPT")
$function_code
install_natpmpc_unstable
EOF

    run bash "$TEST_TMPDIR/run.sh"
    [ "$status" -eq 0 ]
    grep -q 'Package: foo' "$PIN_FILE"
    grep -q 'Package: natpmpc libnatpmp1t64 libnatpmp1' "$PIN_FILE"

    rm -f "$PIN_FILE" "$SRC_LIST"
}
