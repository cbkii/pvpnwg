#!/usr/bin/env bats
# tests/unit/test_pf_jitter.bats — Jitter detection tests

load ../test_helper.bats

setup() {
    setup_test_env
    PVPNWG_USER="$(id -un)"
    export PVPNWG_USER
    source ./pvpnwg.sh 2>/dev/null || true
    PHOME="$TEST_TMPDIR/.pvpnwg"
    CONFIG_DIR="$PHOME/configs"
    STATE_DIR="$PHOME/state"
    TMP_DIR="$PHOME/tmp"
    LOG_FILE="$PHOME/pvpn.log"
    PORT_FILE="$STATE_DIR/mapped_port.txt"
    PF_HISTORY="$STATE_DIR/pf_history.tsv"
    PF_JITTER_FILE="$STATE_DIR/pf_jitter_count.txt"
    HANDSHAKE_FILE="$STATE_DIR/last_handshake.txt"
    TIME_FILE="$STATE_DIR/last_connect_epoch.txt"
    DNS_BACKUP="$STATE_DIR/dns_backup.tar"
    GW_STATE="$STATE_DIR/gw_state.txt"
    IFCONF_FILE="$STATE_DIR/lan_if.txt"
    COOKIE_JAR="$STATE_DIR/qb_cookie.txt"
    MON_FAILS_FILE="$STATE_DIR/monitor_fail_count.txt"
    export PHOME CONFIG_DIR STATE_DIR TMP_DIR LOG_FILE PORT_FILE PF_HISTORY PF_JITTER_FILE HANDSHAKE_FILE TIME_FILE DNS_BACKUP GW_STATE IFCONF_FILE COOKIE_JAR MON_FAILS_FILE
    init_logging
}

teardown() {
    cleanup_test_env
}

@test "three consecutive different ports trigger jitter warning" {
    pf_check_jitter 1001 1000
    pf_check_jitter 1002 1001
    run pf_check_jitter 1003 1002
    [ "$status" -eq 1 ]
    [[ "$output" == *"PF port jitter detected"* ]]
    [ "$(cat "$PF_JITTER_FILE")" -eq 3 ]
}
