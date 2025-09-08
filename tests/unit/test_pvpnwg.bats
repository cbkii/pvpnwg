#!/usr/bin/env bats
# tests/unit/test_pvpnwg.bats — Unit tests for pvpnwg.sh
# Run with: bats tests/unit/test_pvpnwg.bats

load ../test_helper.bats

# Test setup
setup() {
    export TEST_TMPDIR=$(mktemp -d)
    export PHOME="$TEST_TMPDIR/.pvpnwg"
    export CONFIG_DIR="$PHOME/configs"
    export STATE_DIR="$PHOME/state"
    export TMP_DIR="$PHOME/tmp"
    export VERBOSE=0
    export DRY_RUN=1
    
    mkdir -p "$PHOME" "$CONFIG_DIR" "$STATE_DIR" "$TMP_DIR"
    
    # Source the script functions (skip main execution)
    source ./pvpnwg.sh 2>/dev/null || true
}

teardown() {
    rm -rf "$TEST_TMPDIR"
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
    run is_secure_core_name "US-TX-88.conf"
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
# Port forwarding status tests
# ===========================

@test "pf_parse_status detects mapped status" {
    local output="Mapped public port 12345 to local port 51820 using UDP"
    run pf_parse_status "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == "mapped" ]]
}

@test "pf_parse_status detects try_again status" {
    local output="External IP not found, try again later"
    run pf_parse_status "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == "try_again" ]]
}

@test "pf_parse_status detects error status" {
    local output="Connection failed: timeout"
    run pf_parse_status "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == "error" ]]
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
    skip "try-again scenario not supported in test env"
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
    function ping() { echo "PING 1.2.3.4: 56 data bytes\n64 bytes from 1.2.3.4: time=50.0 ms"; }
    export -f ping
    
    run select_conf "any"
    [ "$status" -eq 0 ]
    [[ "$output" == *"valid.conf|50"* ]]
}
