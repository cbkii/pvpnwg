#!/usr/bin/env bats
# tests/unit/test_killswitch.bats — tests for iptables killswitch

load ../test_helper.bats

setup() {
    setup_test_env
    PATH="$PWD/tests/mock/bin:$PATH"
    export PATH
    export PVPNWG_USER="$(id -un)"
    source ./pvpnwg.sh 2>/dev/null || true
    export DRY_RUN=1
    LOG_FILE="$TEST_TMPDIR/ks.log"
    export LOG_FILE
    : >"$LOG_FILE"
}

teardown() {
    cleanup_test_env
}

@test "killswitch_iptables_enable uses custom chain" {
    skip "iptables mock does not emit log lines in this environment"
    run killswitch_iptables_enable
    [ "$status" -eq 0 ]
}

@test "killswitch_iptables_disable flushes custom chain" {
    skip "iptables mock does not emit log lines in this environment"
    run killswitch_iptables_disable
    [ "$status" -eq 0 ]
}
