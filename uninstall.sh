#!/usr/bin/env bash
# uninstall.sh — Remove enhanced ProtonVPN WireGuard CLI
set -euo pipefail

# Pre-parse for --user override
CLI_USER=""
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --user=*) CLI_USER="${arg#*=}" ;;
        *) ARGS+=("$arg") ;;
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
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"

INSTALL_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
BIN_NAME="pvpnwg"

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

stop_and_disable_services() {
    command -v systemctl >/dev/null 2>&1 || { warn "systemd not available"; return; }
    log "Stopping and disabling systemd services..."
    
    local services=(
        "pvpn-check.timer"
        "pvpn-check.service" 
        "pvpn-pf.service"
        "pvpn-monitor.service"
        "pvpn-monitor.timer"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log "Stopping $service..."
            systemctl stop "$service" || true
        fi
        
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log "Disabling $service..."
            systemctl disable "$service" || true
        fi
    done
}

remove_systemd_units() {
    command -v systemctl >/dev/null 2>&1 || { warn "systemd not available"; return; }
    log "Removing systemd units..."
    
    local units=(
        "pvpn-check.service"
        "pvpn-check.timer"
        "pvpn-pf.service" 
        "pvpn-monitor.service"
        "pvpn-monitor.timer"
    )
    
    for unit in "${units[@]}"; do
        if [[ -f "${SYSTEMD_DIR}/${unit}" ]]; then
            log "Removing ${unit}..."
            rm -f "${SYSTEMD_DIR}/${unit}"
        fi
    done
    
    systemctl daemon-reload
    log "✓ Systemd units removed"
}

remove_binary() {
    log "Removing pvpnwg binary..."
    
    if [[ -f "${INSTALL_DIR}/${BIN_NAME}" ]]; then
        rm -f "${INSTALL_DIR}/${BIN_NAME}"
        log "✓ Removed ${INSTALL_DIR}/${BIN_NAME}"
    else
        warn "Binary not found at ${INSTALL_DIR}/${BIN_NAME}"
    fi
}

cleanup_vpn_state() {
    log "Cleaning up VPN state..."
    
    # Bring down VPN interface if it exists
    if ip link show pvpnwg0 >/dev/null 2>&1; then
        log "Bringing down VPN interface..."
        wg-quick down pvpnwg0 >/dev/null 2>&1 || true
    fi
    
    # Remove WireGuard config
    if [[ -f /etc/wireguard/pvpnwg0.conf ]]; then
        log "Removing WireGuard config..."
        rm -f /etc/wireguard/pvpnwg0.conf
    fi
    
    # Disable killswitch if active
    if command -v nft >/dev/null 2>&1; then
        if nft list table inet pvpnwg >/dev/null 2>&1; then
            log "Disabling killswitch..."
            nft delete table inet pvpnwg || true
        fi
    fi
    
    log "✓ VPN state cleaned up"
}

handle_user_data() {
    local user="${RUN_USER:-$(logname 2>/dev/null || echo root)}"
    local home_dir
    home_dir="${RUN_HOME:-$(getent passwd "$user" | cut -d: -f6)}"
    home_dir="${home_dir:-/root}"
    local phome="${home_dir}/.pvpnwg"
    
    if [[ -d "$phome" ]]; then
        echo
        warn "User data directory exists: $phome"
        echo "This contains:"
        echo "  - Configuration files"
        echo "  - VPN connection logs"
        echo "  - Port forwarding history"
        echo "  - Proton WireGuard configs"
        echo
        read -p "Remove user data directory? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "Removing user data..."
            rm -rf "$phome"
            log "✓ User data removed"
        else
            log "Preserving user data at: $phome"
            echo "Manual cleanup: rm -rf $phome"
        fi
    else
        log "No user data directory found"
    fi
}

dns_restore_generic() {
    if command -v resolvectl >/dev/null 2>&1; then
        resolvectl revert pvpnwg0 >/dev/null 2>&1 || true
    elif command -v resolvconf >/dev/null 2>&1; then
        resolvconf -u >/dev/null 2>&1 || true
    else
        printf '%s\n' 'nameserver 1.1.1.1' 'nameserver 8.8.8.8' >/tmp/resolv.conf.generic
        cp -f /tmp/resolv.conf.generic /etc/resolv.conf 2>/dev/null || true
    fi
    log "✓ DNS restored (generic)"
}

restore_dns_if_needed() {
    local user="${RUN_USER:-$(logname 2>/dev/null || echo root)}"
    local home_dir
    home_dir="${RUN_HOME:-$(getent passwd "$user" | cut -d: -f6)}"
    home_dir="${home_dir:-/root}"
    local dns_backup="${home_dir}/.pvpnwg/state/dns_backup.tar"

    if [[ -f "$dns_backup" ]]; then
        read -p "Restore DNS from backup? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            log "Restoring DNS..."
            if tar -tf "$dns_backup" | grep -E '(^/|(^|/)\.\.(/|$))' >/dev/null; then
                warn "Unsafe paths in DNS backup; using generic restore"
                dns_restore_generic
            else
                local tmp
                tmp=$(mktemp -d)
                if tar -xpf "$dns_backup" -C "$tmp" 2>/dev/null; then
                    cp -a "$tmp/." / 2>/dev/null || true
                    log "✓ DNS restored"
                else
                    warn "DNS restore failed; using generic restore"
                    dns_restore_generic
                fi
                rm -rf "$tmp"
            fi
        fi
    fi
}

main() {
    echo "Enhanced ProtonVPN WireGuard CLI Uninstaller"
    echo "============================================"
    
    check_root
    
    echo "This will remove:"
    echo "  - pvpnwg binary from ${INSTALL_DIR}"
    echo "  - All systemd services and timers"
    echo "  - Active VPN connections and killswitch"
    echo "  - WireGuard interface configuration"
    echo
    echo "This will preserve (unless you choose to remove):"
    echo "  - User data directory (~/.pvpnwg)"
    echo "  - Proton WireGuard config files"
    echo "  - Connection logs and history"
    echo
    
    read -p "Continue with uninstall? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Uninstall cancelled"
        exit 0
    fi
    
    stop_and_disable_services
    cleanup_vpn_state
    restore_dns_if_needed
    remove_systemd_units
    remove_binary
    handle_user_data
    
    echo
    log "Uninstall complete!"
    echo
    echo "If you had custom sudo rules for pvpnwg, you may want to remove them from /etc/sudoers"
    echo "Any remaining WireGuard packages can be removed with: apt remove --purge wireguard-tools"
}

main "$@"