#!/usr/bin/env bats
# tests/unit/test_pvpnwg.bats — Unit tests for pvpnwg.sh
# Run with: bats tests/unit/test_pvpnwg.bats

load ../test_helper.bats

# Test setup
setup() {
    TEST_TMPDIR=$(mktemp -d)
    export TEST_TMPDIR
    export PHOME="$TEST_TMPDIR/.pvpnwg"
    export CONFIG_DIR="$PHOME/configs"
    export STATE_DIR="$PHOME/state"
    export TMP_DIR="$PHOME/tmp"
    export TARGET_CONF="$PHOME/target.conf"
    export VERBOSE=0
    export DRY_RUN=1
    export PVPNWG_USER="$(id -un)"

    mkdir -p "$PHOME" "$CONFIG_DIR" "$STATE_DIR" "$TMP_DIR"
    
    # Source the script functions (skip main execution)
    source ./pvpnwg.sh 2>/dev/null || true
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

# ===========================
# User inference tests
# ===========================

@test "--user flag required when run as root without inferable user" {
    run bash -c 'unset SUDO_USER PVPNWG_USER; bash pvpnwg.sh >/dev/null'
    [ "$status" -eq 1 ]
    [[ "$output" == *"--user"* ]]
}

# ===========================
# Config validation tests
# ===========================

@test "conf_validate detects missing PrivateKey" {
    cat > "$CONFIG_DIR/test.conf" <<EOF
[Interface]
Address = 10.2.0.2/32

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
EOF
    
    run conf_validate "$CONFIG_DIR/test.conf"
    [ "$status" -eq 1 ]
    [[ "$output" == *"missing PrivateKey"* ]]
}

@test "conf_validate detects missing CIDR in Address" {
    cat > "$CONFIG_DIR/test.conf" <<EOF
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
EOF
    
    run conf_validate "$CONFIG_DIR/test.conf"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Address missing CIDR"* ]]
}

@test "conf_validate accepts valid config" {
    cat > "$CONFIG_DIR/test.conf" <<EOF
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
EOF
    
    run conf_validate "$CONFIG_DIR/test.conf"
    [ "$status" -eq 0 ]
    [[ "$output" == "valid" ]]
}

@test "conf_validate detects invalid port in Endpoint" {
    cat > "$CONFIG_DIR/test.conf" <<EOF
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2/32

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:999999
AllowedIPs = 0.0.0.0/0
EOF
    
    run conf_validate "$CONFIG_DIR/test.conf"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Endpoint invalid port"* ]]
}

# ===========================
# Secure Core detection tests
# ===========================

@test "is_secure_core_name detects SC configs" {
    run is_secure_core_name "US-TXSC.conf"
    [ "$status" -eq 0 ]

    run is_secure_core_name "CH-SC-1.conf"
    [ "$status" -eq 0 ]

    run is_secure_core_name "secure-core-nl.conf"
    [ "$status" -eq 0 ]
}

@test "is_secure_core_name rejects regular configs" {
    run is_secure_core_name "US-TX-1.conf"
    [ "$status" -eq 1 ]
    
    run is_secure_core_name "NL-FREE-1.conf"
    [ "$status" -eq 1 ]
}

# ===========================
# Port Forwarding detection tests
# ===========================

@test "is_pf_name detects PF configs" {
    run is_pf_name "US-TXPF.conf"
    [ "$status" -eq 0 ]

    run is_pf_name "port-forward-de.conf"
    [ "$status" -eq 0 ]
}

@test "is_pf_name rejects non-PF configs" {
    run is_pf_name "US-TX-1.conf"
    [ "$status" -eq 1 ]
}

@test "cmd_rename_pf tags configs" {
    create_test_pf_config "pfexample"
    run cmd_rename_pf
    [ "$status" -eq 0 ]
    [ -f "$CONFIG_DIR/pfexamplePF.conf" ]
}

@test "select_conf handles P2P + PF configs" {
    create_test_pf_config "mixP2P"
    run cmd_rename_pf
    [ -f "$CONFIG_DIR/mixP2PPF.conf" ]

      # shellcheck disable=SC2317
      function ping() {
          printf '%s\n' "PING 1.2.3.4: 56 data bytes" "64 bytes from 1.2.3.4: time=50.0 ms"
      }
      export -f ping

    run select_conf "pf"
    [ "$status" -eq 0 ]
    [[ "$output" == *"mixP2PPF.conf|50"* ]]
}

# ===========================
# Port forwarding status tests
# ===========================

@test "pf_parse_status detects mapped status" {
    local output="Mapped public port 12345 to local port 51820 using UDP"
    run pf_parse_status "$output"
    [ "$status" -eq 0 ]
}

@test "pf_parse_status detects try_again status" {
    local output="External IP not found, try again later"
    run pf_parse_status "$output"
    [ "$status" -eq 2 ]
}

@test "pf_parse_status detects error status" {
    local output="Connection failed: timeout"
    run pf_parse_status "$output"
    [ "$status" -eq 1 ]
}

@test "conf_strip_ipv6_allowedips removes ::/0" {
    cat > "$TARGET_CONF" <<EOF
[Peer]
AllowedIPs = 0.0.0.0/0, ::/0
EOF
    conf_strip_ipv6_allowedips
    run grep -c '::/0' "$TARGET_CONF"
    [ "$status" -eq 1 ]
}

@test "pf_derive_gateway_from_conf prefers DNS" {
    cat > "$TARGET_CONF" <<EOF
[Interface]
Address = 10.2.3.4/32
DNS = 10.2.3.1,8.8.8.8
EOF
    run pf_derive_gateway_from_conf
    [ "$status" -eq 0 ]
    [[ "$output" == "10.2.3.1" ]]
}

@test "pf_derive_gateway_from_conf falls back to PF_GATEWAY_FALLBACK" {
    cat > "$TARGET_CONF" <<EOF
[Interface]
EOF
    PF_GATEWAY_FALLBACK="10.9.8.7"
    run pf_derive_gateway_from_conf
    [ "$status" -eq 0 ]
    [[ "$output" == "$PF_GATEWAY_FALLBACK" ]]
}

@test "pf_history_rotate_if_needed truncates file" {
    PF_HISTORY="$TMP_DIR/pf_history.log"
    PF_HISTORY_MAX=100
    PF_HISTORY_KEEP=2
    printf '%101s' "" | tr ' ' a >"$PF_HISTORY"
    pf_history_rotate_if_needed
    [ -f "$PF_HISTORY" ]
    [ -f "$PF_HISTORY.1" ]
}

# ===========================
# Interface scan tests
# ===========================

iface_mock() {
    printf '1: lo: <LOOPBACK>\n2: eth0: <UP>\n3: wlan0: <UP>\n'
}

@test "iface_scan keeps existing interface with empty input" {
    # shellcheck disable=SC2030,SC2031
    export VERBOSE=1
    LAN_IF="eth0"
    export -f iface_mock
    # shellcheck disable=SC2317
    function ip() { iface_mock; }
    export -f ip
    output_file="$BATS_TMPDIR/iface_scan_keep.txt"
    iface_scan >"$output_file" 2>&1 <<<""
    [ "$LAN_IF" = "eth0" ]
    [ ! -f "$IFCONF_FILE" ]
    grep -q "Keep eth0" "$output_file"
}

@test "iface_scan saves new interface" {
    # shellcheck disable=SC2030,SC2031
    export VERBOSE=1
    LAN_IF="eth0"
    export -f iface_mock
    # shellcheck disable=SC2317
    function ip() { iface_mock; }
    export -f ip
    output_file="$BATS_TMPDIR/iface_scan_set.txt"
    iface_scan >"$output_file" 2>&1 <<<"wlan0"
    [ "$LAN_IF" = "wlan0" ]
    [[ "$(cat "$IFCONF_FILE")" == "wlan0" ]]
    # shellcheck disable=SC2314
    ! grep -q "Keep" "$output_file"
}

@test "iface_scan reverts on save failure" {
    # shellcheck disable=SC2030,SC2031
    export VERBOSE=1
    LAN_IF="eth0"
    export -f iface_mock
    # shellcheck disable=SC2317
    function ip() { iface_mock; }
    export -f ip
    iface_save() { return 1; }
    export -f iface_save
    output_file="$BATS_TMPDIR/iface_scan_fail.txt"
    iface_scan >"$output_file" 2>&1 <<<"wlan0"
    [ "$LAN_IF" = "eth0" ]
    [ ! -f "$IFCONF_FILE" ]
    grep -q "Keep eth0" "$output_file"
}

# ===========================
# DNS backend detection tests
# ===========================

@test "detect_dns_backend detects systemd-resolved" {
    skip "requires systemd-resolved"
}

@test "detect_dns_backend detects flat file" {
    skip "requires resolvconf setup"
}

# ===========================
# Utility function tests
# ===========================

@test "human_kbps calculates correctly" {
    run human_kbps 1024000 10  # 1MB in 10 seconds = 100 KB/s
    [ "$status" -eq 0 ]
    [[ "$output" == "100" ]]
    
    run human_kbps 0 10
    [ "$status" -eq 0 ]
    [[ "$output" == "0" ]]
    
    run human_kbps 1024 0  # Division by zero
    [ "$status" -eq 0 ]
    [[ "$output" == "0" ]]
}

@test "conf_endpoint_host extracts host correctly" {
    cat > "$CONFIG_DIR/test.conf" <<EOF
[Peer]
Endpoint = example.com:51820
EOF
    
    run conf_endpoint_host "$CONFIG_DIR/test.conf"
    [ "$status" -eq 0 ]
    [[ "$output" == "example.com" ]]
}

# ===========================
# CLI argument tests
# ===========================

@test "usage shows help" {
    run usage
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
    [[ "$output" == *"connect"* ]]
    [[ "$output" == *"status"* ]]
}

@test "parse_globals handles verbose flag" {
    tmp_out="$TMP_DIR/pg_out"
    parse_globals -v connect > "$tmp_out"
    # shellcheck disable=SC2031
    [[ "$VERBOSE" -eq 1 ]]
    [[ "$(cat "$tmp_out")" == "connect" ]]
}

@test "parse_globals handles dry-run flag" {
    tmp_out="$TMP_DIR/pg_out"
    parse_globals --dry-run status > "$tmp_out"
    [[ "$DRY_RUN" -eq 1 ]]
    [[ "$(cat "$tmp_out")" == "status" ]]
}

# ===========================
# Integration test helpers
# ===========================

create_mock_natpmpc() {
    cat > "$TEST_TMPDIR/natpmpc" <<'EOF'
#!/bin/bash
case "$1" in
    -v)
        echo "natpmpc 20230423"
        exit 0
        ;;
esac
while [[ "$1" ]]; do
  case "$1" in
    -g) gateway="$2"; shift 2 ;;
    -a) int="$2"; ext="$3"; proto="$4"; shift 4 ;;
    *) shift ;;
  esac
done
if [[ "$gateway" == "10.2.0.1" ]]; then
  echo "Mapped public port 12345 to local port ${int} using ${proto^^}"
  exit 0
elif [[ "$gateway" == "192.168.1.1" ]]; then
  echo "External IP not found, try again later"
  exit 1
else
  echo "Connection failed: timeout"
  exit 1
fi
EOF
    chmod +x "$TEST_TMPDIR/natpmpc"
    export PATH="$TEST_TMPDIR:$PATH"
}

create_mock_qb_webui() {
    # Simple netcat-based mock qBittorrent WebUI
    cat > "$TEST_TMPDIR/mock_qb.sh" <<'EOF'
#!/bin/bash
# Mock qBittorrent WebUI server
port=${1:-8080}

while true; do
    response=$(cat <<'RESP'
HTTP/1.1 200 OK
Content-Type: application/json

{"listen_port": 51820}
RESP
)
    echo "$response" | nc -l -p "$port" -q 1
done
EOF
    chmod +x "$TEST_TMPDIR/mock_qb.sh"
}

# ===========================
# Integration tests (require mocks)
# ===========================

@test "pf_request_once with successful mapping" {
    create_mock_natpmpc

    function qb_set_port() { echo "qB set to $1"; }
    export -f qb_set_port

    run pf_request_once
    [ "$status" -eq 0 ]
    [[ "$(cat "$STATE_DIR/mapped_port.txt")" == "12345" ]]
}

@test "pf_request_once with try_again response" {
    create_mock_natpmpc

    function qb_set_port() { echo "qB set to $1"; }
    export -f qb_set_port

    function pf_detect_gateway() { echo "192.168.1.1"; }
    export -f pf_detect_gateway

    run pf_request_once
    [ "$status" -eq 0 ]
    [[ "$(cat "$STATE_DIR/mapped_port.txt")" == "12345" ]]
}

# ===========================
# Error handling tests
# ===========================

@test "select_conf fails with no configs" {
    # Empty config directory
    run select_conf "p2p"
    [ "$status" -eq 1 ]
    [[ "$output" == *"No .conf in"* ]]
}

@test "select_conf skips invalid configs" {
    # Create invalid config
    cat > "$CONFIG_DIR/invalid.conf" <<EOF
[Interface]
# Missing required fields
EOF
    
    # Create valid config  
    cat > "$CONFIG_DIR/valid.conf" <<EOF
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.2.0.2/32

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
EOF
    
    # Mock ping to return RTT
      # shellcheck disable=SC2317
      function ping() { printf '%s\n' "PING 1.2.3.4: 56 data bytes" "64 bytes from 1.2.3.4: time=50.0 ms"; }
      export -f ping
      function getent() { return 1; }
      export -f getent
    
    run select_conf "any"
    [ "$status" -eq 0 ]
    [[ "$output" == *"valid.conf|50"* ]]
}
