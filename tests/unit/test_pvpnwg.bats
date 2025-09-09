#!/usr/bin/env bats
# tests/unit/test_pvpnwg.bats — Unit tests for pvpnwg.sh
# Run with: bats tests/unit/test_pvpnwg.bats

load ../test_helper.bats

# Test setup
setup() {
    TEST_TMPDIR=$(mktemp -d)
    export TEST_TMPDIR
    PHOME="$TEST_TMPDIR/.pvpnwg"
    CONFIG_DIR="$PHOME/configs"
    STATE_DIR="$PHOME/state"
    TMP_DIR="$PHOME/tmp"
    TARGET_CONF="$PHOME/target.conf"
    VERBOSE=0
    DRY_RUN=1
    PVPNWG_USER="$(id -un)"

    mkdir -p "$PHOME" "$CONFIG_DIR" "$STATE_DIR" "$TMP_DIR"

    # Source the script functions (skip main execution)
    source ./pvpnwg.sh 2>/dev/null || true

    # Restore test paths in case sourcing reset them
    PHOME="$TEST_TMPDIR/.pvpnwg"
    CONFIG_DIR="$PHOME/configs"
    STATE_DIR="$PHOME/state"
    TMP_DIR="$PHOME/tmp"
    TARGET_CONF="$PHOME/target.conf"
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
    export PHOME CONFIG_DIR STATE_DIR TMP_DIR TARGET_CONF PORT_FILE PF_HISTORY PF_JITTER_FILE HANDSHAKE_FILE TIME_FILE DNS_BACKUP GW_STATE IFCONF_FILE COOKIE_JAR MON_FAILS_FILE VERBOSE DRY_RUN PVPNWG_USER
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

# ===========================
# User inference tests
# ===========================

@test "--user flag required when run as root without inferable user" {
    if [ "$EUID" -ne 0 ]; then
        skip "requires root"
    fi
    run bash -c 'unset SUDO_USER PVPNWG_USER; PVPNWG_NO_MAIN=1 bash pvpnwg.sh >/dev/null'
    [ "$status" -eq 1 ]
    [[ "$output" == *"--user"* ]]
}

@test "SUDO_USER suffices when running as root" {
    if [ "$EUID" -ne 0 ]; then
        skip "requires root"
    fi
    run bash -c 'unset PVPNWG_USER; SUDO_USER="$(id -un)" PVPNWG_NO_MAIN=1 bash pvpnwg.sh >/dev/null'
    [ "$status" -eq 0 ]
}

@test "PVPNWG_USER suffices when running as root" {
    if [ "$EUID" -ne 0 ]; then
        skip "requires root"
    fi
    run bash -c 'unset SUDO_USER; PVPNWG_USER="$(id -un)" PVPNWG_NO_MAIN=1 bash pvpnwg.sh >/dev/null'
    [ "$status" -eq 0 ]
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
ARGS_LOG="${ARGS_LOG:-}"
while [[ "$1" ]]; do
  case "$1" in
    -g) gateway="$2"; shift 2 ;;
    -a) int="$2"; ext="$3"; proto="$4"; shift 4 ;;
    *) shift ;;
  esac
done
if [[ -n "$ARGS_LOG" ]]; then
  echo "$int $ext" >> "$ARGS_LOG"
fi
if [[ "$gateway" == "10.2.0.1" ]]; then
  if [[ -n "$NATPMP_MISMATCH" && "$proto" == "tcp" ]]; then
    echo "Mapped public port 54321 to local port ${int} using ${proto^^}"
  else
    echo "Mapped public port 12345 to local port ${int} using ${proto^^}"
  fi
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
    ARGS_LOG="$TEST_TMPDIR/natpmpc_args.log"
    : > "$ARGS_LOG"
    export ARGS_LOG
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
# qBittorrent login tests
# ===========================

@test "qb_login handles special characters in credentials" {
    port=18080
    req_file="$BATS_TMPDIR/login_req.txt"
    cat > "$TEST_TMPDIR/mock_login_server.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
out_file = sys.argv[2]
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        with open(out_file, 'w') as f:
            f.write(body)
        self.send_response(200)
        self.send_header('Set-Cookie', 'SID=1')
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, format, *args):
        pass
if __name__ == '__main__':
    HTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()
PY
    python "$TEST_TMPDIR/mock_login_server.py" "$port" "$req_file" &
    server_pid=$!
    sleep 1
    export WEBUI_URL="http://127.0.0.1:$port"
    export WEBUI_USER='user&name'
    export WEBUI_PASS='pass%word'
    run qb_login
    kill "$server_pid"
    wait "$server_pid" 2>/dev/null || true
    [ "$status" -eq 0 ]
    [[ "$(cat "$req_file")" == "username=user%26name&password=pass%25word" ]]
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

@test "pf_request_once renew uses mapped port for both args" {
    create_mock_natpmpc

    function qb_set_port() { echo "qB set to $1"; }
    export -f qb_set_port

    run pf_request_once
    [ "$status" -eq 0 ]
    mapfile -t lines <"$ARGS_LOG"
    [[ "${lines[-2]}" == "1 0" ]]
    [[ "${lines[-1]}" == "1 0" ]]

    run pf_request_once
    [ "$status" -eq 0 ]
    mapfile -t lines <"$ARGS_LOG"
    [[ "${lines[-2]}" == "12345 12345" ]]
    [[ "${lines[-1]}" == "12345 12345" ]]
}

@test "pf_request_once prefers UDP port when TCP differs" {
    create_mock_natpmpc

    function qb_set_port() { echo "qB set to $1"; }
    export -f qb_set_port
    export NATPMP_MISMATCH=1
    export PF_REQUIRE_BOTH=true

    run pf_request_once
    [ "$status" -eq 0 ]
    [[ "$(cat "$STATE_DIR/mapped_port.txt")" == "12345" ]]
    [[ "$output" == *"different UDP (12345) and TCP (54321) ports"* ]]
}

@test "pf_request_once continues when pf_record fails" {
    create_mock_natpmpc

    function qb_set_port() { echo "qB set to $1"; }
    export -f qb_set_port

    function pf_record() { return 1; }
    export -f pf_record

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

@test "pf_request_once with error response" {
    # natpmpc always fails
    cat > "$TEST_TMPDIR/natpmpc" <<'EOF'
#!/bin/bash
echo "Connection failed: timeout"
exit 1
EOF
    chmod +x "$TEST_TMPDIR/natpmpc"
    export PATH="$TEST_TMPDIR:$PATH"

    function qb_set_port() { echo "qB set to $1"; }
    export -f qb_set_port

    function pf_detect_gateway() { echo "172.16.0.1"; }
    export -f pf_detect_gateway

    run pf_request_once
    [ "$status" -eq 1 ]
    [[ "$(cat "$STATE_DIR/mapped_port.txt")" == "51820" ]]
}

@test "pf_verify reports mapped status" {
    create_mock_natpmpc
    echo 12345 >"$PORT_FILE"

    function pf_detect_gateway() { echo "10.2.0.1"; }
    export -f pf_detect_gateway

    run pf_verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"PF OK on 10.2.0.1 (udp)"* ]]
}

@test "pf_verify reports try_again status" {
    create_mock_natpmpc
    echo 12345 >"$PORT_FILE"

    function pf_detect_gateway() { echo "192.168.1.1"; }
    export -f pf_detect_gateway

    run pf_verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"PF TRY AGAIN on 192.168.1.1"* ]]
}

@test "pf_verify reports error status" {
    create_mock_natpmpc
    echo 12345 >"$PORT_FILE"

    function pf_detect_gateway() { echo "172.16.0.1"; }
    export -f pf_detect_gateway

    run pf_verify
    [ "$status" -eq 0 ]
    [[ "$output" == *"PF FAILED on 172.16.0.1"* ]]
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
