# tests/test_helper.bash — Helper functions for BATS tests

# Setup test environment variables
export BATS_TEST_SKIPPED=""

# Helper functions for test setup
setup_test_env() {
    export TEST_TMPDIR=$(mktemp -d)
    export PHOME="$TEST_TMPDIR/.pvpnwg"
    export CONFIG_DIR="$PHOME/configs"
    export STATE_DIR="$PHOME/state"
    export TMP_DIR="$PHOME/tmp"
    export LOG_FILE="$PHOME/pvpn.log"
    export PORT_FILE="$STATE_DIR/mapped_port.txt"
    export PF_HISTORY="$STATE_DIR/pf_history.tsv"
    export PF_JITTER_FILE="$STATE_DIR/pf_jitter_count.txt"
    export HANDSHAKE_FILE="$STATE_DIR/last_handshake.txt"
    export TIME_FILE="$STATE_DIR/last_connect_epoch.txt"
    export DNS_BACKUP="$STATE_DIR/dns_backup.tar"
    export GW_STATE="$STATE_DIR/gw_state.txt"
    export IFCONF_FILE="$STATE_DIR/lan_if.txt"
    export COOKIE_JAR="$STATE_DIR/qb_cookie.txt"
    export PF_GW_CACHE="$STATE_DIR/pf_gateway.txt"
    export MON_FAILS_FILE="$STATE_DIR/monitor_fail_count.txt"
    
    # Test mode settings
    export VERBOSE=0
    export DRY_RUN=1
    export IFACE="test-wg0"
    export LAN_IF="test-eth0"
    export WEBUI_URL="http://127.0.0.1:8080"
    export WEBUI_USER="test"
    export WEBUI_PASS="test"
    export PF_GATEWAY_FALLBACK="10.2.0.1"
    export PF_STATIC_FALLBACK_PORT=51820
    export LOG_JSON=false
    
    mkdir -p "$PHOME" "$CONFIG_DIR" "$STATE_DIR" "$TMP_DIR"
}

cleanup_test_env() {
    [[ -n "${TEST_TMPDIR:-}" ]] && rm -rf "$TEST_TMPDIR"
}

# Create a valid WireGuard config for testing
create_test_config() {
    local name="${1:-test}"
    local host="${2:-test.example.com}"
    local port="${3:-51820}"
    
    cat > "$CONFIG_DIR/${name}.conf" <<EOF
[Interface]
PrivateKey = $(openssl rand -base64 32 2>/dev/null || echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = $(openssl rand -base64 32 2>/dev/null || echo "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
Endpoint = ${host}:${port}
AllowedIPs = 0.0.0.0/0
EOF
}

# Create a Secure-Core config for testing
create_test_sc_config() {
    local name="${1:-secure-core-test}"
    create_test_config "${name}88" "${2:-sc.example.com}" "${3:-51820}"
}

# Mock external commands for testing
mock_ping() {
    local host="$1"
    local rtt="${MOCK_PING_RTT:-50.0}"
    echo "PING $host: 56 data bytes"
    echo "64 bytes from $host: time=${rtt} ms"
}

mock_wg_show() {
    local iface="$1"
    local cmd="${2:-}"
    
    case "$cmd" in
        "latest-handshakes")
            echo "peer123 $(date +%s)"
            ;;
        "endpoints")
            echo "peer123 test.example.com:51820"
            ;;
        *)
            echo "interface: $iface"
            echo "  public key: (hidden)"
            echo "  private key: (hidden)"
            echo "  listening port: 51820"
            echo ""
            echo "peer: peer123"
            echo "  endpoint: test.example.com:51820"
            echo "  allowed ips: 0.0.0.0/0"
            echo "  latest handshake: $(date)"
            ;;
    esac
}

mock_natpmpc_success() {
    local port="${MOCK_PF_PORT:-12345}"
    echo "Mapped public port $port to local port 51820 using UDP"
}

mock_natpmpc_try_again() {
    echo "External IP not found, try again later"
    return 1
}

mock_natpmpc_error() {
    echo "Connection failed: timeout"
    return 1
}

mock_curl_qb_success() {
    case "$*" in
        *"auth/login"*)
            echo "Ok."
            ;;
        *"preferences"*)
            if [[ "$*" == *"setPreferences"* ]]; then
                echo ""  # Empty response for set
            else
                echo '{"listen_port": 51820, "upnp": false, "random_port": false}'
            fi
            ;;
        *"version"*)
            echo "4.5.0"
            ;;
        *"torrents/info"*)
            echo '[]'  # No torrents
            ;;
        *)
            echo ""
            ;;
    esac
}

mock_curl_qb_auth_fail() {
    case "$*" in
        *"auth/login"*)
            echo "Fails."
            return 1
            ;;
        *)
            echo "Unauthorized"
            return 1
            ;;
    esac
}

# Network namespace test helpers (require root)
setup_netns_test() {
    [[ ${EUID} -eq 0 ]] || skip "Requires root for network namespace tests"
    
    local ns_name="${1:-pvpn-test}"
    export TEST_NETNS="$ns_name"
    
    # Create network namespace
    ip netns add "$ns_name" 2>/dev/null || true
    
    # Setup basic networking in namespace
    ip netns exec "$ns_name" ip link set lo up
    
    # Create veth pair for connectivity
    ip link add "veth-${ns_name}" type veth peer name "veth-${ns_name}-peer" 2>/dev/null || true
    ip link set "veth-${ns_name}-peer" netns "$ns_name"
    ip addr add 192.168.99.1/24 dev "veth-${ns_name}" 2>/dev/null || true
    ip link set "veth-${ns_name}" up
    ip netns exec "$ns_name" ip addr add 192.168.99.2/24 dev "veth-${ns_name}-peer"
    ip netns exec "$ns_name" ip link set "veth-${ns_name}-peer" up
    ip netns exec "$ns_name" ip route add default via 192.168.99.1
}

cleanup_netns_test() {
    [[ -n "${TEST_NETNS:-}" ]] || return 0
    
    # Clean up veth interfaces
    ip link delete "veth-${TEST_NETNS}" 2>/dev/null || true
    
    # Delete namespace
    ip netns delete "$TEST_NETNS" 2>/dev/null || true
}

run_in_netns() {
    [[ -n "${TEST_NETNS:-}" ]] || return 1
    ip netns exec "$TEST_NETNS" "$@"
}

# Mock DNS resolution tools
mock_dig() {
    local target="$2"
    local resolver="$4"
    
    echo ";; Query time: ${MOCK_DNS_LATENCY:-25} msec"
    echo ";; SERVER: $resolver#53"
    echo ""
    echo "$target.		300	IN	A	1.2.3.4"
}

mock_drill() {
    mock_dig "$@"
}

# Assertion helpers
assert_file_exists() {
    local file="$1"
    [[ -f "$file" ]] || {
        echo "File does not exist: $file" >&2
        return 1
    }
}

assert_file_contains() {
    local file="$1"
    local pattern="$2"
    [[ -f "$file" ]] || {
        echo "File does not exist: $file" >&2
        return 1
    }
    grep -q "$pattern" "$file" || {
        echo "File $file does not contain: $pattern" >&2
        echo "File contents:" >&2
        cat "$file" >&2
        return 1
    }
}

assert_port_in_range() {
    local port="$1"
    local min="${2:-1024}"
    local max="${3:-65535}"
    
    [[ "$port" =~ ^[0-9]+$ ]] || {
        echo "Not a valid port number: $port" >&2
        return 1
    }
    
    [[ "$port" -ge "$min" && "$port" -le "$max" ]] || {
        echo "Port $port not in range $min-$max" >&2
        return 1
    }
}

# Skip test if command not available
require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || skip "$cmd not available"
}

# Skip test if not running as root
require_root() {
    [[ ${EUID} -eq 0 ]] || skip "Requires root privileges"
}

# Test data generators
generate_pf_history() {
    local count="${1:-5}"
    local base_ts=$(date +%s)
    
    for ((i=0; i<count; i++)); do
        local ts=$((base_ts + i * 60))
        local status="ok"
        [[ $((i % 3)) -eq 2 ]] && status="try_again"
        echo -e "$ts\t51820\t$((12000 + i))\t10.2.0.1\t$status"
    done > "$PF_HISTORY"
}

# Environment validation
validate_test_env() {
    [[ -n "${TEST_TMPDIR:-}" ]] || {
        echo "TEST_TMPDIR not set" >&2
        return 1
    }
    
    [[ -d "${PHOME:-}" ]] || {
        echo "PHOME directory not created" >&2
        return 1
    }
}

# Source control for functions under test
source_pvpnwg_functions() {
    # Source only the functions we want to test, not the main execution
    # This requires some careful sourcing to avoid running main()
    
    local script_path="${PVPNWG_SCRIPT:-./pvpnwg.sh}"
    [[ -f "$script_path" ]] || {
        echo "pvpnwg.sh not found at: $script_path" >&2
        return 1
    }
    
    # Extract just the function definitions, skip main execution
    sed -n '/^[a-zA-Z_][a-zA-Z0-9_]*\s*()/,/^}/p' "$script_path" | \
    grep -v '^main(' | \
    source /dev/stdin 2>/dev/null || true
}