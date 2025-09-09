#!/usr/bin/env bash
# install.sh — Install enhanced ProtonVPN WireGuard CLI
set -euo pipefail

# Pre-parse for --user override
CLI_USER=""
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user=*)
            CLI_USER="${1#*=}"
            shift
            ;;
        --user)
            CLI_USER="$2"
            shift 2
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done
set -- "${ARGS[@]}"

RUN_USER=""
if [[ -n "$CLI_USER" ]]; then
    RUN_USER="$CLI_USER"
elif [[ -n "${SUDO_USER:-}" ]]; then
    RUN_USER="$SUDO_USER"
else
    RUN_USER="$(id -un)"
fi
if ! getent passwd "$RUN_USER" >/dev/null 2>&1; then
    echo "Unknown user: $RUN_USER" >&2
    exit 1
fi
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"

INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
BIN_NAME="pvpnwg"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/pvpnwg.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[INFO]${NC}" "$@"; }
warn() { echo -e "${YELLOW}[WARN]${NC}" "$@"; }
error() { echo -e "${RED}[ERROR]${NC}" "$@"; }
die() { error "$@"; exit 1; }

check_root() {
    [[ ${EUID} -eq 0 ]] || die "Run as root (sudo)"
}

check_deps() {
    log "Checking dependencies..."
    local -a req=(ip wg wg-quick curl jq awk sed grep ping)
    local -a opt=(natpmpc vnstat nft resolvconf dig drill iptables)
    local missing=()
    
    for dep in "${req[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing[*]}"
        echo "Install with: apt update && apt install -y wireguard-tools iproute2 curl jq iputils-ping"
        exit 1
    fi
    
    log "✓ Required dependencies found"
    
    for dep in "${opt[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            warn "Optional dependency missing: $dep"
        else
            log "✓ Found optional: $dep"
        fi
    done
}

check_sudo_config() {
    log "Ensure passwordless sudo is configured for pvpnwg runtime commands"

    if command -v sudo >/dev/null 2>&1; then
        return
    fi

    if [[ ${EUID} -ne 0 ]]; then
        die "sudo is required but not installed"
    fi

    if [[ "$RUN_USER" != "root" ]]; then
        command -v su >/dev/null 2>&1 \
            || die "sudo not installed and 'su' unavailable to switch to ${RUN_USER}"
        log "sudo not installed; will fall back to 'su'"
    fi
}

run_as_user() {
    local target="$1"
    shift

    if command -v sudo >/dev/null 2>&1; then
        sudo -n -u "$target" "$@"
    elif [[ "$(id -un)" == "$target" ]]; then
        "$@"
    elif command -v su >/dev/null 2>&1; then
        su - "$target" -c "$(printf '%q ' "$@")"
    else
        die "Unable to run commands as $target: missing sudo and su"
    fi
}

install_binary() {
    log "Installing pvpnwg binary..."
    
    [[ -f "$SCRIPT_PATH" ]] || die "Script not found: $SCRIPT_PATH"
    
    cp "$SCRIPT_PATH" "${INSTALL_DIR}/${BIN_NAME}"
    chmod +x "${INSTALL_DIR}/${BIN_NAME}"
    
    log "✓ Installed to ${INSTALL_DIR}/${BIN_NAME}"
}

create_systemd_units() {
    log "Creating systemd units..."

    command -v systemctl >/dev/null 2>&1 || die "systemctl not found; systemd is required"

    # pvpn-check.service
    cat > "${SYSTEMD_DIR}/pvpn-check.service" <<'EOF'
[Unit]
Description=PVPN Health Check (reconnect if idle/aged/unhealthy)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/pvpnwg check
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "${SYSTEMD_DIR}/pvpn-check.service"
    chown root:root "${SYSTEMD_DIR}/pvpn-check.service"

    # pvpn-check.timer
    cat > "${SYSTEMD_DIR}/pvpn-check.timer" <<'EOF'
[Unit]
Description=Run PVPN Health Check every 5 minutes
Requires=pvpn-check.service

[Timer]
OnUnitActiveSec=5min
AccuracySec=1min
Unit=pvpn-check.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

    chmod 644 "${SYSTEMD_DIR}/pvpn-check.timer"
    chown root:root "${SYSTEMD_DIR}/pvpn-check.timer"

    # pvpn-pf.service
    cat > "${SYSTEMD_DIR}/pvpn-pf.service" <<'EOF'
[Unit]
Description=PVPN NAT-PMP Port Forward Renew Loop
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pvpnwg pf start
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "${SYSTEMD_DIR}/pvpn-pf.service"
    chown root:root "${SYSTEMD_DIR}/pvpn-pf.service"

    # pvpn-monitor.service
    cat > "${SYSTEMD_DIR}/pvpn-monitor.service" <<'EOF'
[Unit]
Description=PVPN Enhanced Monitor Loop (latency, WG health, DNS)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pvpnwg monitor
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "${SYSTEMD_DIR}/pvpn-monitor.service"
    chown root:root "${SYSTEMD_DIR}/pvpn-monitor.service"

    # pvpn-monitor.timer
    cat > "${SYSTEMD_DIR}/pvpn-monitor.timer" <<'EOF'
[Unit]
Description=PVPN Monitor Timer (alternative to service)
Requires=pvpn-monitor.service

[Timer]
OnUnitActiveSec=60s
AccuracySec=10s
Unit=pvpn-monitor.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

    chmod 644 "${SYSTEMD_DIR}/pvpn-monitor.timer"
    chown root:root "${SYSTEMD_DIR}/pvpn-monitor.timer"

    systemctl daemon-reload || die "Failed to reload systemd daemon"
    log "✓ Created systemd units"
}

setup_user_config() {
    local user="${RUN_USER:-$(logname 2>/dev/null || echo root)}"
    local home_dir
    local home_dir="${RUN_HOME:-$(getent passwd "$user" | cut -d: -f6)}"
    local phome="${home_dir}/.pvpnwg"

    log "Setting up user configuration for: $user"
    log "PHOME will be: $phome"

    if [[ ! -f "$phome/pvpnwg.conf" ]]; then
        log "Running init to create default config..."
        run_as_user "$user" "${INSTALL_DIR}/${BIN_NAME}" init
    else
        log "✓ Config already exists at $phome/pvpnwg.conf"
    fi

    echo
    echo "Next steps:"
    echo "1. Copy your Proton WireGuard .conf files to: $phome/configs/"
    echo "2. Edit configuration: $phome/pvpnwg.conf"
    echo "3. Test: pvpnwg validate configs"
    echo "4. Connect: pvpnwg connect"
    echo "5. Enable services: systemctl enable --now pvpn-check.timer"
}

enable_services() {
    command -v systemctl >/dev/null 2>&1 || die "systemctl not found; systemd is required"

    read -p "Enable automatic health checks? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        log "Skipping service enablement"
        return
    fi

    log "Enabling pvpn-check.timer..."
    systemctl enable pvpn-check.timer || die "Failed to enable pvpn-check.timer"
    systemctl start pvpn-check.timer || die "Failed to start pvpn-check.timer"
    
    read -p "Enable port forwarding service? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Enabling pvpn-pf.service..."
        systemctl enable pvpn-pf.service || die "Failed to enable pvpn-pf.service"
        log "Start with: systemctl start pvpn-pf.service (after connecting VPN)"
    fi
    
    read -p "Enable enhanced monitoring? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Note: Choose either service OR timer for monitoring"
        echo "  Service: systemctl enable --now pvpn-monitor.service"
        echo "  Timer:   systemctl enable --now pvpn-monitor.timer"
    fi
}

main() {
    echo "Enhanced ProtonVPN WireGuard CLI Installer"
    echo "=========================================="
    
    check_root
    check_deps
    check_sudo_config
    install_binary
    create_systemd_units
    setup_user_config
    enable_services
    
    echo
    log "Installation complete!"
    echo
    echo "Usage examples:"
    echo "  pvpnwg connect              # Connect to best P2P server"
    echo "  pvpnwg status               # Show detailed status"
    echo "  pvpnwg diag all             # Full diagnostics"
    echo "  pvpnwg pf start             # Start port forwarding loop"
    echo
    echo "Systemd management:"
    echo "  systemctl status pvpn-check.timer"
    echo "  journalctl -u pvpn-check.service -f"
    echo
    echo "Documentation: see README.md"
}

main "$@"