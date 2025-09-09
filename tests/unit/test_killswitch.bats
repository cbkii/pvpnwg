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
}

teardown() {
    cleanup_test_env
}

@test "killswitch_iptables_enable uses custom chain" {
    run killswitch_iptables_enable
    [ "$status" -eq 0 ]
    grep -q "iptables -N pvpnwg-out" "$LOG_FILE"
    grep -q "iptables -I OUTPUT 1 -j pvpnwg-out" "$LOG_FILE"
    grep -q "iptables -A pvpnwg-out -m state --state ESTABLISHED,RELATED -j ACCEPT" "$LOG_FILE"
}

@test "killswitch_iptables_disable flushes custom chain" {
    run killswitch_iptables_disable
    [ "$status" -eq 0 ]
    grep -q "iptables -P OUTPUT ACCEPT" "$LOG_FILE"
    grep -q "iptables -D OUTPUT -j pvpnwg-out" "$LOG_FILE"
    grep -q "iptables -F pvpnwg-out" "$LOG_FILE"
    ! grep -q "iptables -F OUTPUT" "$LOG_FILE"
}
