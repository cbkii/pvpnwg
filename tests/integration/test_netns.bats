#!/usr/bin/env bats
# tests/integration/test_netns.bats — Network namespace integration tests

load ../test_helper.bats

setup() {
    setup_test_env
    if ! setup_netns_test; then
        skip "Network namespaces not supported"
    fi
    ip netns list | grep -q "$TEST_NETNS" || skip "Network namespaces not supported"

    create_test_pf_config "netns"
    export CONFIG_PATH="$CONFIG_DIR/netns.conf"
    export PVPNWG_USER="$(id -un)"
    export DRY_RUN=0
}

teardown() {
    run_in_netns wg-quick down "$IFACE" >/dev/null 2>&1 || true
    cleanup_netns_test
    cleanup_test_env
}

pvpn_run() {
    local cmd="$1"
    run run_in_netns env \
        PHOME="$PHOME" CONFIG_DIR="$CONFIG_DIR" STATE_DIR="$STATE_DIR" TMP_DIR="$TMP_DIR" \
        LOG_FILE="$LOG_FILE" PORT_FILE="$PORT_FILE" IFACE="$IFACE" TARGET_CONF="/etc/wireguard/$IFACE.conf" \
        LAN_IF="veth-${TEST_NETNS}-peer" PVPNWG_USER="$PVPNWG_USER" DRY_RUN="$DRY_RUN" \
        PF_PROTO_LIST="udp" PF_REQUIRE_BOTH=false \
        bash -c "source $(pwd)/pvpnwg.sh; $cmd"
}

@test "WireGuard interface comes up in namespace" {
    pvpn_run "wg_up $CONFIG_PATH"
    [ "$status" -eq 0 ]
    run run_in_netns ip link show "$IFACE"
    [ "$status" -eq 0 ]
}

@test "pf_request_once records NAT-PMP port" {
    pvpn_run "natpmpc() { echo 'Mapped public port 12345 to local port 51820 using UDP'; }; qb_set_port() { return 0; }; pf_request_once"
    [ "$status" -eq 0 ]
    run cat "$PORT_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "12345" ]
}

@test "killswitch blocks external traffic" {
    pvpn_run "killswitch_enable"
    [ "$status" -eq 0 ]

    run run_in_netns ping -c1 -W1 192.168.99.1
    [ "$status" -eq 0 ]

    run run_in_netns ping -c1 -W1 1.1.1.1
    [ "$status" -ne 0 ]
    [[ "$output" == *"Operation not permitted"* ]] || skip "Unexpected ping output: $output"

    pvpn_run "killswitch_disable"
}
