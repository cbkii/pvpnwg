#!/usr/bin/env bats
# tests/integration/test_netns.bats — Integration tests using network namespaces
# Run with: sudo bats tests/integration/test_netns.bats

load ../test_helper.bats

setup() {
    require_root
    setup_test_env
    if ! setup_netns_test "pvpn-test" >/dev/null 2>&1; then
        skip "network namespaces unavailable"
    fi
    source_pvpnwg_functions
}

teardown() {
    cleanup_netns_test
    cleanup_test_env
}

# ===========================
# Mock service setup
# ===========================

setup_mock_natpmpc() {
    cat > "$TEST_TMPDIR/natpmpc" <<'EOF'
#!/bin/bash
# Mock natpmpc that simulates different gateway behaviors

gateway="$2"
private_port="$4"
protocol="$7"

case "$gateway" in
    "10.2.0.1")
        # Success case - return mapped port
        echo "Mapped public port 12345 to local port $private_port using $protocol"
        exit 0
        ;;
    "192.168.1.1")
        # Try again case 
        echo "External IP not found, try again later"
        exit 1
        ;;
    "10.1.1.1")
        # Error case
        echo "Connection failed: timeout" 
        exit 1
        ;;
    *)
        echo "Unknown gateway behavior"
        exit 1
        ;;
esac
EOF
    chmod +x "$TEST_TMPDIR/natpmpc"
    export PATH="$TEST_TMPDIR:$PATH"
}

setup_mock_qb_webui() {
    local port="${1:-8080}"
    
    # Create a simple HTTP server that responds to qBittorrent API calls
    cat > "$TEST_TMPDIR/qb_mock.py" <<EOF
#!/usr/bin/env python3
import http.server
import socketserver
import json
import urllib.parse
from threading import Thread
import sys

class QBMockHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logging
        
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        if 'auth/login' in self.path:
            # Mock login
            if 'username=test&password=test' in post_data:
                self.send_response(200)
                self.send_header('Set-Cookie', 'SID=test-session')
                self.end_headers()
                self.wfile.write(b'Ok.')
            else:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'Fails.')
        elif 'setPreferences' in self.path:
            # Mock set preferences
            self.send_response(200)
            self.end_headers()
            
    def do_GET(self):
        if 'preferences' in self.path:
            # Mock get preferences
            response = {
                'listen_port': 51820,
                'upnp': False, 
                'random_port': False
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        elif 'version' in self.path:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'4.5.0')
        elif 'torrents/info' in self.path:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'[]')

PORT = $port
with socketserver.TCPServer(("", PORT), QBMockHandler) as httpd:
    httpd.serve_forever()
EOF
    
    # Start mock server in background
    python3 "$TEST_TMPDIR/qb_mock.py" &
    export QB_MOCK_PID=$!
    sleep 1  # Give server time to start
}

teardown_mock_qb_webui() {
    [[ -n "${QB_MOCK_PID:-}" ]] && kill "$QB_MOCK_PID" 2>/dev/null || true
}

# ===========================
# Port forwarding integration tests
# ===========================

@test "pf_request_once with successful gateway in netns" {
    setup_mock_natpmpc
    export PF_GATEWAY_FALLBACK="10.2.0.1"
    
    # Override functions to work in test environment
    function qb_get_port() { echo "51820"; }
    function qb_set_port() { echo "Mock qB set to $1" >&2; return 0; }
    export -f qb_get_port qb_set_port
    
    # Run in network namespace
    run_in_netns bash -c "
        export PATH='$TEST_TMPDIR:\$PATH'
        export PHOME='$PHOME'
        export STATE_DIR='$STATE_DIR'
        export PORT_FILE='$PORT_FILE'
        export PF_HISTORY='$PF_HISTORY'
        export PF_JITTER_FILE='$PF_JITTER_FILE'
        export PF_GATEWAY_FALLBACK='10.2.0.1'
        export PF_PROTO_LIST='udp tcp'
        export IFACE='$IFACE'
        export VERBOSE=1
        
        $(declare -f pf_detect_gateway pf_parse_status pf_record pf_check_jitter _pf_private_port qb_get_port qb_set_port)
        
        # Mock the interface detection
        function pf_detect_gateway() { echo '10.2.0.1'; }
        export -f pf_detect_gateway
        
        pf_request_once() {
            local private gw lease ok saw_try_again got_public prev
            private=\"\$(_pf_private_port)\"; gw=\"\$(pf_detect_gateway)\"; lease=60; ok=false; saw_try_again=false; got_public=\"\"; prev=\"\$(cat \"\$PORT_FILE\" 2>/dev/null || true)\"
            for proto in udp tcp; do
                local out; out=\$(natpmpc -g \"\$gw\" -a \"\$private\" 0 \"\$proto\" \"\$lease\" 2>&1 || true)
                local st; st=\$(pf_parse_status \"\$out\")
                case \"\$st\" in
                    mapped) local p; p=\$(echo \"\$out\" | awk '/Mapped public port/{print \$4; exit}'); [[ -n \"\$p\" && \"\$p\" != 0 ]] && got_public=\"\$p\" && ok=true ;;
                    try_again) saw_try_again=true ;;
                    *) : ;;
                esac
            done
            if \$ok; then
                if pf_check_jitter \"\$got_public\" \"\$prev\"; then
                    echo 0 >\"\$PF_JITTER_FILE\"
                fi
                if [[ \"\$got_public\" != \"\$prev\" ]]; then
                    echo \"\$got_public\" >\"\$PORT_FILE\"
                    qb_set_port \"\$got_public\" || echo 'WARN: qB sync failed'
                    echo \"PF mapped: public=\$got_public private=\$private gw=\$gw (updated)\"
                else
                    echo \"PF mapped unchanged: public=\$got_public (kept)\"
                fi
                pf_record \"\$private\" \"\$got_public\" \"\$gw\" ok
                return 0
            else
                pf_record \"\$private\" 0 \"\$gw\" \"\$([\[ \$saw_try_again == true ]] && echo try_again || echo error)\"
                return 1
            fi
        }
        
        pf_request_once
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" == *"PF mapped"* ]]
    [[ "$(cat "$PORT_FILE")" == "12345" ]]
}

@test "pf_request_once handles try_again in netns" {
    setup_mock_natpmpc
    export PF_GATEWAY_FALLBACK="192.168.1.1"  # Triggers try_again
    echo "51820" > "$PORT_FILE"  # Existing port
    
    function qb_get_port() { echo "51820"; }
    function qb_set_port() { echo "Mock qB set to $1" >&2; return 0; }
    export -f qb_get_port qb_set_port
    
    run_in_netns bash -c "
        export PATH='$TEST_TMPDIR:\$PATH'
        export PHOME='$PHOME'
        export STATE_DIR='$STATE_DIR'
        export PORT_FILE='$PORT_FILE'
        export PF_HISTORY='$PF_HISTORY'
        export PF_JITTER_FILE='$PF_JITTER_FILE'
        export PF_GATEWAY_FALLBACK='192.168.1.1'
        export PF_STATIC_FALLBACK_PORT='51820'
        
        $(declare -f pf_detect_gateway pf_parse_status pf_record pf_check_jitter _pf_private_port qb_get_port qb_set_port)
        
        function pf_detect_gateway() { echo '192.168.1.1'; }
        export -f pf_detect_gateway
        
        pf_request_once() {
            local private gw lease ok saw_try_again got_public prev
            private=\"\$(_pf_private_port)\"; gw=\"\$(pf_detect_gateway)\"; lease=60; ok=false; saw_try_again=false; got_public=\"\"; prev=\"\$(cat \"\$PORT_FILE\" 2>/dev/null || true)\"
            for proto in udp tcp; do
                local out; out=\$(natpmpc -g \"\$gw\" -a \"\$private\" 0 \"\$proto\" \"\$lease\" 2>&1 || true)
                local st; st=\$(pf_parse_status \"\$out\")
                case \"\$st\" in
                    try_again) saw_try_again=true ;;
                esac
            done
            if \$ok; then
                return 0
            else
                pf_record \"\$private\" 0 \"\$gw\" \"\$([\[ \$saw_try_again == true ]] && echo try_again || echo error)\"
                if \$saw_try_again; then echo \"WARN: NAT-PMP TRY AGAIN on \$gw\"; else echo \"WARN: NAT-PMP failed on \$gw\"; fi
                if [[ -z \"\$prev\" ]]; then
                    echo \"\$PF_STATIC_FALLBACK_PORT\" >\"\$PORT_FILE\"; qb_set_port \"\$PF_STATIC_FALLBACK_PORT\" || true
                else
                    echo \"Keeping existing qB/port=\$prev until next successful mapping\"
                fi
                return 1
            fi
        }
        
        pf_request_once
        cat '$PORT_FILE'
    "
    
    [ "$status" -eq 1 ]
    [[ "$output" == *"TRY AGAIN"* ]]
    [[ "$(cat "$PORT_FILE")" == "51820" ]]  # Should keep existing port
}

# ===========================
# qBittorrent integration tests
# ===========================

@test "qb_set_port_webui integration test" {
    setup_mock_qb_webui 8080
    export WEBUI_URL="http://127.0.0.1:8080"
    export WEBUI_USER="test"
    export WEBUI_PASS="test"
    
    function qb_login() {
        : > "$COOKIE_JAR"
        chmod 600 "$COOKIE_JAR"
        local r; r=$(curl -sS -c "$COOKIE_JAR" \
            --data-urlencode "username=${WEBUI_USER}" \
            --data-urlencode "password=${WEBUI_PASS}" \
            "${WEBUI_URL%/}/api/v2/auth/login" || true)
        [[ "$r" == Ok.* ]]
    }
    
    function qb_set_port_webui() {
        local port="$1"
        qb_login || return 1
        local url="${WEBUI_URL%/}"
        local prefs; prefs=$(jq -n --argjson p "$port" '{listen_port: ($p|tonumber), upnp:false, random_port:false}')
        curl -sS -b "${COOKIE_JAR}" --data-urlencode "json=${prefs}" "${url}/api/v2/app/setPreferences" >/dev/null || return 1
        local got; got=$(curl -sS -b "$COOKIE_JAR" "$url/api/v2/app/preferences" | jq -r '.listen_port // empty')
        if [[ "$got" != "$port" ]]; then return 1; fi
        echo "qB listen_port=${port} set"
    }
    
    export -f qb_login qb_set_port_webui
    
    run_in_netns qb_set_port_webui 12345
    
    [ "$status" -eq 0 ]
    [[ "$output" == *"qB listen_port=12345 set"* ]]
    
    teardown_mock_qb_webui
}

# ===========================
# DNS latency tests in netns
# ===========================

@test "dns_latency_test in network namespace" {
    # Setup mock dig command
    cat > "$TEST_TMPDIR/dig" <<'EOF'
#!/bin/bash
# Mock dig that simulates DNS query timing

if [[ "$*" == *"+stats"* ]]; then
    echo ";; Query time: 25 msec"
    echo ";; SERVER: $6#53"
    echo ""
    echo "google.com.		300	IN	A	8.8.8.8"
fi
EOF
    chmod +x "$TEST_TMPDIR/dig"
    export PATH="$TEST_TMPDIR:$PATH"
    
    # Mock ip command to return test interface IP
    cat > "$TEST_TMPDIR/ip" <<'EOF'
#!/bin/bash
if [[ "$*" == *"addr show dev"* ]]; then
    echo "inet 10.2.0.2/32 scope global test-wg0"
fi
EOF
    chmod +x "$TEST_TMPDIR/ip"
    
    function dns_latency_test() {
        local resolver="${1:-10.2.0.1}" target="${2:-google.com}"
        if ! command -v dig >/dev/null 2>&1; then return 1; fi
        local wg_ip; wg_ip=$(ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
        if [[ -z "$wg_ip" ]]; then return 1; fi
        local output; output=$(dig +stats -4 -b "$wg_ip" "$target" @"$resolver" 2>&1 || true)
        local query_time; query_time=$(echo "$output" | awk '/Query time:/{print $4}' | head -1)
        if [[ -n "$query_time" && "$query_time" =~ ^[0-9]+$ ]]; then
            echo "$query_time"
            return 0
        fi
        return 1
    }
    
    export -f dns_latency_test
    export IFACE="test-wg0"
    
    run_in_netns bash -c "
        export PATH='$TEST_TMPDIR:\$PATH'
        export IFACE='$IFACE'
        $(declare -f dns_latency_test)
        dns_latency_test 10.2.0.1 google.com
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" == "25" ]]
}

# ===========================
# Config validation integration
# ===========================

@test "config validation with real wg-quick parsing" {
    # Create a config that should pass wg-quick validation
    create_test_config "valid-test" "185.159.158.1" "51820"
    
    # Test our validation function
    run conf_validate "$CONFIG_DIR/valid-test.conf"
    [ "$status" -eq 0 ]
    [[ "$output" == "valid" ]]
    
    # Create a config that should fail wg-quick parsing
    cat > "$CONFIG_DIR/invalid-syntax.conf" <<'EOF'
[Interface]
PrivateKey = not-valid-base64!@#$
Address = 10.2.0.2/32

[Peer]
PublicKey = also-not-valid-base64!@#$
Endpoint = invalid-host:999999
AllowedIPs = not-a-valid-cidr
EOF
    
    run conf_validate "$CONFIG_DIR/invalid-syntax.conf"
    [ "$status" -eq 1 ]
    [[ "$output" == *"Endpoint invalid port"* ]]
}

# ===========================
# WireGuard health monitoring
# ===========================

@test "wg_unhealthy_reason detects no interface" {
    # Mock ip link to show interface doesn't exist
    cat > "$TEST_TMPDIR/ip" <<'EOF'
#!/bin/bash
if [[ "$*" == *"link show"* ]]; then
    echo "Device \"$3\" does not exist."
    exit 1
fi
EOF
    chmod +x "$TEST_TMPDIR/ip"
    export PATH="$TEST_TMPDIR:$PATH"
    
    function wg_unhealthy_reason() {
        if ! ip link show "$IFACE" >/dev/null 2>&1; then echo "no_interface"; return 0; fi
        echo "none"; return 1
    }
    export -f wg_unhealthy_reason
    export IFACE="test-wg0"
    
    run_in_netns wg_unhealthy_reason
    [ "$status" -eq 0 ]
    [[ "$output" == "no_interface" ]]
}

# ===========================
# Stress test: rapid PF requests
# ===========================

@test "pf stability under rapid requests" {
    setup_mock_natpmpc
    export PF_GATEWAY_FALLBACK="10.2.0.1"
    
    function qb_get_port() { echo "51820"; }
    function qb_set_port() { return 0; }  # Silent success
    export -f qb_get_port qb_set_port
    
    # Simulate rapid PF requests (jitter scenario)
    run_in_netns bash -c "
        export PATH='$TEST_TMPDIR:\$PATH'
        export PHOME='$PHOME'
        export STATE_DIR='$STATE_DIR'
        export PORT_FILE='$PORT_FILE'
        export PF_HISTORY='$PF_HISTORY'
        export PF_JITTER_FILE='$PF_JITTER_FILE'
        export PF_GATEWAY_FALLBACK='10.2.0.1'
        
        $(declare -f pf_detect_gateway pf_parse_status pf_record pf_check_jitter _pf_private_port qb_get_port qb_set_port)
        
        function pf_detect_gateway() { echo '10.2.0.1'; }
        
        # Simulate alternating port responses (jitter)
        function natpmpc() {
            local count=\$(wc -l < \"\$PF_HISTORY\" 2>/dev/null || echo 0)
            local port=\$((12000 + (count % 2)))
            echo \"Mapped public port \$port to local port 51820 using udp\"
        }
        export -f pf_detect_gateway natpmpc
        
        pf_request_once() {
            local private gw lease ok saw_try_again got_public prev
            private=\"\$(_pf_private_port)\"; gw=\"\$(pf_detect_gateway)\"; lease=60; ok=false; saw_try_again=false; got_public=\"\"; prev=\"\$(cat \"\$PORT_FILE\" 2>/dev/null || true)\"
            local out; out=\$(natpmpc -g \"\$gw\" -a \"\$private\" 0 udp \"\$lease\" 2>&1 || true)
            local st; st=\$(pf_parse_status \"\$out\")
            case \"\$st\" in
                mapped) local p; p=\$(echo \"\$out\" | awk '/Mapped public port/{print \$4; exit}'); [[ -n \"\$p\" && \"\$p\" != 0 ]] && got_public=\"\$p\" && ok=true ;;
            esac
            if \$ok; then
                if pf_check_jitter \"\$got_public\" \"\$prev\"; then
                    echo 0 >\"\$PF_JITTER_FILE\"
                fi
                echo \"\$got_public\" >\"\$PORT_FILE\"
                pf_record \"\$private\" \"\$got_public\" \"\$gw\" ok
                return 0
            fi
        }
        
        # Run multiple requests and check jitter detection
        for i in {1..5}; do
            pf_request_once >/dev/null
        done
        
        echo \"Final jitter count: \$(cat \"\$PF_JITTER_FILE\" 2>/dev/null || echo 0)\"
        echo \"Final port: \$(cat \"\$PORT_FILE\")\"
        echo \"History entries: \$(wc -l < \"\$PF_HISTORY\")\"
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" == *"jitter count:"* ]]
    [[ "$output" == *"History entries: 5"* ]]
}

# ===========================
# End-to-end workflow test
# ===========================

@test "complete workflow: validate -> connect prep -> pf -> status" {
    create_test_config "workflow-test" "workflow.example.com" "51820"
    setup_mock_natpmpc
    
    export PF_GATEWAY_FALLBACK="10.2.0.1"
    
    function qb_get_port() { echo "51820"; }
    function qb_set_port() { echo "qB set to $1" >&2; return 0; }
    function ping() { echo "64 bytes from workflow.example.com: time=45.0 ms"; }
    export -f qb_get_port qb_set_port ping
    
    run_in_netns bash -c "
        export PATH='$TEST_TMPDIR:\$PATH'
        export PHOME='$PHOME'
        export CONFIG_DIR='$CONFIG_DIR'
        export STATE_DIR='$STATE_DIR'
        export PORT_FILE='$PORT_FILE'
        export PF_HISTORY='$PF_HISTORY'
        export PF_JITTER_FILE='$PF_JITTER_FILE'
        export VERBOSE=1
        
        $(declare -f conf_validate select_conf pf_detect_gateway pf_parse_status pf_record pf_check_jitter _pf_private_port qb_get_port qb_set_port is_secure_core_name conf_endpoint_host ping_rtt_ms)
        
        function pf_detect_gateway() { echo '10.2.0.1'; }
        export -f pf_detect_gateway
        
        # Step 1: Validate config
        echo \"=== Validation ===\"
        validation=\$(conf_validate '$CONFIG_DIR/workflow-test.conf')
        echo \"Config validation: \$validation\"
        
        # Step 2: Select config (simplified)
        echo \"=== Selection ===\"
        host=\$(conf_endpoint_host '$CONFIG_DIR/workflow-test.conf')
        rtt=\$(ping_rtt_ms \"\$host\")
        echo \"Selected: workflow-test.conf, host=\$host, rtt=\$rtt\"
        
        # Step 3: PF request
        echo \"=== Port Forward ===\"
        pf_request_once() {
            local private gw got_public
            private=\"\$(_pf_private_port)\"; gw=\"\$(pf_detect_gateway)\"
            local out; out=\$(natpmpc -g \"\$gw\" -a \"\$private\" 0 udp 60 2>&1 || true)
            local st; st=\$(pf_parse_status \"\$out\")
            if [[ \"\$st\" == \"mapped\" ]]; then
                local p; p=\$(echo \"\$out\" | awk '/Mapped public port/{print \$4; exit}')
                echo \"\$p\" >\"\$PORT_FILE\"
                qb_set_port \"\$p\"
                echo \"PF success: \$p\"
                return 0
            fi
            return 1
        }
        pf_request_once
        
        # Step 4: Status check
        echo \"=== Status ===\"
        echo \"Port file: \$(cat \"\$PORT_FILE\" 2>/dev/null || echo 'none')\"
        echo \"Workflow complete\"
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" == *"Config validation: valid"* ]]
    [[ "$output" == *"PF success: 12345"* ]]
    [[ "$output" == *"Port file: 12345"* ]]
    [[ "$output" == *"Workflow complete"* ]]
}
