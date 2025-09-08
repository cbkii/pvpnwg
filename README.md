# Enhanced ProtonVPN WireGuard CLI

A **single-file, Bash-only CLI** for managing ProtonVPN WireGuard connections with advanced port forwarding, health monitoring, and qBittorrent integration. Built for **Debian Bookworm** with **passwordless sudo**.

## Features

### Core VPN Management
- **Smart server selection**: Lowest RTT among P2P, Secure-Core, or any servers
- **Country filtering**: `--cc <CC>` for specific country codes
- **Config validation**: Pre-connection validation of WireGuard configs
- **Health monitoring**: Time limits, idle detection, handshake age, endpoint latency
- **DNS management**: Backend-aware DNS backup/restore with Proton DNS support

### Port Forwarding (Gluetun-style)
- **NAT-PMP (6A)** with autodetected gateway + `10.2.0.1` fallback
- **Stable mapping semantics**: Only update qBittorrent when port actually changes
- **TRY AGAIN classification**: Detect servers that don't support PF
- **Jitter detection**: Track and warn about unstable port mappings
- **Exponential backoff**: 5→10→20→40→60s on failures, 45s normal cadence

### qBittorrent Integration
- **WebUI sync**: Login, set listen_port, disable UPnP/random port
- **Config fallback**: Direct `qBittorrent.conf` editing if WebUI unavailable
- **Health checks**: Monitor WebUI connectivity
- **Stalled torrent helper**: Reannounce and resume stalled torrents

### Enhanced Monitoring
- **WireGuard health**: Handshake age, link state, endpoint reachability
- **DNS latency**: Optional Proton DNS response time monitoring
- **Latency-aware reconnection**: Reconnect on high RTT for N consecutive checks
- **Multiple triggers**: Time limit, idle threshold, health issues

### Security & Reliability
- **nftables killswitch** (optional): Allow only VPN + local traffic
- **iptables-nft variant** for compatibility
- **DNS leak protection**: Proton DNS enforcement with leak testing
- **State persistence**: Connection history, port mappings, monitor failures

## Installation

### Quick Install
```bash
# Clone or download the project
git clone https://github.com/cbkii/pvpnwg
cd pvpnwg

# Install (requires root)
sudo ./install.sh
```

The installer will:
- Check dependencies and sudo configuration
- Install `pvpnwg` to `/usr/local/bin/`
- Create systemd units for health checks and port forwarding
- Set up user configuration directory
- Offer to enable automatic services

### Manual Installation
```bash
# Copy script
sudo cp pvpnwg.sh /usr/local/bin/pvpnwg
sudo chmod +x /usr/local/bin/pvpnwg

# Create user directory
mkdir -p ~/.pvpnwg/configs ~/.pvpnwg/state ~/.pvpnwg/tmp
chmod 700 ~/.pvpnwg

# Initialize configuration
sudo pvpnwg init
```

### Dependencies

**Required:**
```bash
apt update && apt install -y \
  wireguard-tools iproute2 curl jq iputils-ping
```

**Optional but recommended:**
```bash
apt install -y natpmpc vnstat nftables dnsutils
```

**Passwordless sudo** (required):
```bash
# Add to /etc/sudoers via visudo:
yourusername ALL=(ALL) NOPASSWD: ALL

# Or more restrictive:
yourusername ALL=(ALL) NOPASSWD: /usr/bin/ip, /usr/bin/wg, /usr/bin/wg-quick, /usr/bin/nft
```

## Configuration

### Initial Setup
```bash
# Initialize configuration
sudo pvpnwg init

# Edit configuration file
nano ~/.pvpnwg/pvpnwg.conf

# Copy Proton WireGuard configs
cp /path/to/proton/*.conf ~/.pvpnwg/configs/

# Validate configs
pvpnwg validate configs

# Rename Secure-Core configs (optional)
sudo pvpnwg rename-sc
```

### Key Configuration Options

Edit `~/.pvpnwg/pvpnwg.conf`:

```bash
# PATHS # Explicitly hardcode your $USER
PHOME="/home/username/.pvpnwg"
CONFIG_DIR="/home/username/.pvpnwg/configs"

# Reconnection policy
TIME_LIMIT_SECS=28800          # 8 hours max connection
DL_THRESHOLD_KBPS=33           # Reconnect if < 33 KB/s download

# qBittorrent WebUI
WEBUI_URL="http://192.168.1.50:8080"
WEBUI_USER="admin"
WEBUI_PASS="your_password"        # supports special characters

# Port forwarding
PF_RENEW_SECS=45               # NAT-PMP renewal interval
PF_STATIC_FALLBACK_PORT=51820  # Fallback port if PF fails

# Health monitoring
HANDSHAKE_MAX_AGE=120          # Max handshake age (seconds)
LATENCY_THRESHOLD_MS=400       # High latency threshold
LATENCY_FAILS=3                # Consecutive failures before reconnect
MONITOR_INTERVAL=60            # Monitor check interval

# Enhanced monitoring
DNS_HEALTH=true                # Enable DNS latency checks
DNS_LAT_MS=250                 # DNS latency threshold
QBIT_HEALTH=true               # Enable qBittorrent health checks
```

`WEBUI_PASS` accepts passwords with special characters.

## Usage

### Basic VPN Operations
```bash
# Connect to best P2P server (default)
sudo pvpnwg connect

# Connect to Secure-Core server
sudo pvpnwg connect --secure-core

# Connect to any server type
sudo pvpnwg connect --any

# Connect to specific country
sudo pvpnwg connect --cc NL

# Reconnect with same settings
sudo pvpnwg reconnect

# Disconnect and cleanup
sudo pvpnwg disconnect

# Hard reset (emergency)
sudo pvpnwg reset
```

### Status and Diagnostics
```bash
# Comprehensive status
sudo pvpnwg status

# Detailed diagnostics
sudo pvpnwg diag all
sudo pvpnwg diag wg        # WireGuard health
sudo pvpnwg diag pf        # Port forwarding
sudo pvpnwg diag dns       # DNS status and latency
sudo pvpnwg diag qb        # qBittorrent status

# Health check (manual)
sudo pvpnwg check
```

### Port Forwarding
```bash
# One-time PF request
sudo pvpnwg pf once

# Start continuous PF loop
sudo pvpnwg pf start

# Verify PF capability
sudo pvpnwg pf verify

# PF status and history
sudo pvpnwg pf status
```

### DNS Management
```bash
# Set Proton DNS
sudo pvpnwg dns set proton

# Restore system DNS
sudo pvpnwg dns set system

# Test for DNS leaks
sudo pvpnwg dns test

# Check DNS latency
sudo pvpnwg dns latency
```

### qBittorrent Management
```bash
# Set listen port manually
sudo pvpnwg qb port 12345

# Fix stalled torrents
sudo pvpnwg qb fix-stalled

# Check qBittorrent health
sudo pvpnwg qb health
```

### Configuration Management
```bash
# Validate single config
sudo pvpnwg validate conf /path/to/config.conf

# Validate all configs
sudo pvpnwg validate configs

# Scan and select LAN interface
sudo pvpnwg iface-scan
```

### Security Features
```bash
# Enable killswitch (nftables)
sudo pvpnwg killswitch enable

# Enable killswitch (iptables)
sudo pvpnwg killswitch iptables-enable

# Disable killswitch
sudo pvpnwg killswitch disable

# Check killswitch status
sudo pvpnwg killswitch status
```

## Systemd Service Management

### Health Check Timer
```bash
# Enable automatic health checks every 5 minutes
sudo systemctl enable --now pvpn-check.timer

# Check status
sudo systemctl status pvpn-check.timer
sudo journalctl -u pvpn-check.service -f
```

### Port Forwarding Service
```bash
# Enable continuous port forwarding
sudo systemctl enable --now pvpn-pf.service

# Monitor logs
sudo journalctl -u pvpn-pf.service -f

# Manual control
sudo systemctl stop pvpn-pf.service
sudo systemctl start pvpn-pf.service
```

### Enhanced Monitoring
```bash
# Option 1: Continuous monitoring service
sudo systemctl enable --now pvpn-monitor.service

# Option 2: Timer-based monitoring (alternative)
sudo systemctl enable --now pvpn-monitor.timer

# Note: Use either service OR timer, not both
```

### Service Dependencies
Services automatically start after `network-online.target` and will restart on failure. The health check timer runs independently and can trigger reconnections as needed.

## Port Forwarding: Gluetun-Style Semantics

### Stable Mapping Logic
Our port forwarding implementation follows **Gluetun's proven approach**:

1. **On PF Success**: Update qBittorrent **only if port changed**
2. **On PF Failure**: Keep existing port, **never clobber**
3. **On "TRY AGAIN"**: Warn user, suggest server switch
4. **First Success**: Use static fallback if no previous mapping

### TRY AGAIN Response
When NAT-PMP returns "try again":
- **Root cause**: Server doesn't support port forwarding
- **Action**: Keep current port, log warning
- **User guidance**: Switch to a PF-capable server

### Jitter Detection
Rapid port changes trigger warnings:
- **Threshold**: 3+ consecutive different ports
- **Response**: Log jitter count, continue operation
- **Purpose**: Detect unstable server behavior

### Example Scenarios

**Successful mapping:**
```
[INFO] PF mapped: public=12345 private=51820 gw=10.2.0.1 (updated)
[INFO] qB listen_port=12345 set (UPnP/NAT-PMP disabled)
```

**TRY AGAIN response:**
```
[WARN] NAT-PMP TRY AGAIN on 10.2.0.1 (server may not support PF)
[INFO] Keeping existing qB/port=51820 until next successful mapping
```

**Network failure:**
```
[WARN] NAT-PMP failed on 10.2.0.1
[INFO] No previous PF port; setting static fallback 51820
```

## Troubleshooting

### Common Issues

**"TRY AGAIN" responses:**
```bash
# Check if server supports PF
sudo pvpnwg pf verify

# Switch to different server
sudo pvpnwg reconnect --p2p

# Check server list for PF capability
sudo pvpnwg status  # Shows current server
```

**DNS leaks:**
```bash
# Test current DNS
sudo pvpnwg dns test

# Force Proton DNS
sudo pvpnwg dns set proton

# Check resolution latency
sudo pvpnwg dns latency
```

**qBittorrent sync issues:**
```bash
# Check WebUI connectivity
sudo pvpnwg qb health

# Manual port set
sudo pvpnwg qb port 12345

# Restart qBittorrent after config changes
sudo systemctl restart qbittorrent-nox  # if systemd service
```

**High latency / slow connections:**
```bash
# Check endpoint RTT
sudo pvpnwg diag wg

# Force reconnection
sudo pvpnwg reconnect

# Try different server type
sudo pvpnwg reconnect --any
```

**Killswitch issues:**
```bash
# Check firewall status
sudo pvpnwg killswitch status

# Disable temporarily
sudo pvpnwg killswitch disable

# Re-enable after troubleshooting
sudo pvpnwg killswitch enable
```

### Debug Mode
```bash
# Verbose logging
sudo pvpnwg -v connect

# Dry-run mode (shows commands without execution)
sudo pvpnwg --dry-run connect

# JSON log mode
LOG_JSON=true sudo pvpnwg status
```

### Log Analysis
```bash
# View connection log
tail -f ~/.pvpnwg/pvpn.log

# Service logs
sudo journalctl -u pvpn-check.service -f
sudo journalctl -u pvpn-pf.service -f

# PF history
cat ~/.pvpnwg/state/pf_history.tsv
```

## Testing

### Prerequisites
```bash
# Install bats testing framework
apt install bats

# For integration tests (optional)
apt install python3 netcat-openbsd
```

### Unit Tests
```bash
# Run unit tests (no root required)
bats tests/unit/test_pvpnwg.bats

# Test specific functions
bats tests/unit/test_pvpnwg.bats -f "conf_validate"
```

### Integration Tests
```bash
# Run integration tests (requires root)
sudo bats tests/integration/test_netns.bats

# Test port forwarding with mocks
sudo bats tests/integration/test_netns.bats -f "pf_request_once"
```

### Manual Testing
```bash
# Validate configs
sudo pvpnwg validate configs

# Test DNS functionality
sudo pvpnwg dns test

# Verify PF without connection
sudo pvpnwg pf verify

# Check all diagnostics
sudo pvpnwg diag all
```

## Advanced Configuration

### Environment Overrides
```bash
# Custom home directory
PVPN_PHOME="/custom/path" sudo pvpnwg status

# JSON logging
LOG_JSON=true sudo pvpnwg connect

# Debug mode
VERBOSE=1 sudo pvpnwg pf start
```

### Multiple Configurations
```bash
# Development environment
cp ~/.pvpnwg/pvpnwg.conf ~/.pvpnwg/pvpnwg-dev.conf
# Edit dev config, then:
PVPN_PHOME="/home/user/.pvpnwg-dev" sudo pvpnwg init
```

### Custom Systemd Units
```bash
# Override default timer interval
sudo systemctl edit pvpn-check.timer
# Add:
# [Timer]
# OnUnitActiveSec=10min

# Custom PF service with different user
sudo systemctl edit pvpn-pf.service
# Add:
# [Service]
# Environment="PVPN_PHOME=/custom/path"
```

## Security Considerations

### Privileged Operations
The script requires root for:
- WireGuard interface management (`wg-quick`)
- Routing table modifications (`ip route`)
- DNS configuration changes
- Firewall rule management (`nft`, `iptables`)

### Sensitive Data
- qBittorrent passwords stored in plaintext config
- WireGuard private keys in config files
- Ensure `~/.pvpnwg/` has `700` permissions

### Network Security
- Killswitch prevents traffic leaks during reconnection
- DNS enforcement prevents DNS leaks
- Port forwarding limited to configured protocols

### Recommendations
1. Use dedicated user account for VPN operations
2. Restrict sudo access to specific commands only
3. Enable killswitch for sensitive applications
4. Regular config validation and log monitoring
5. Monitor PF port stability and server performance

## Uninstallation

```bash
# Clean removal (preserves user data by default)
sudo ./uninstall.sh

# Manual cleanup if needed
sudo systemctl disable --now pvpn-*.{service,timer}
sudo rm -f /usr/local/bin/pvpnwg
sudo rm -f /etc/systemd/system/pvpn-*
sudo systemctl daemon-reload

# Remove user data (optional)
rm -rf ~/.pvpnwg
```

## Contributing

### Development Setup
```bash
# Clone repository
git clone https://github.com/cbkii/pvpnwg
cd pvpnwg

# Set up test environment
sudo bats tests/unit/test_pvpnwg.bats

# Run linting
shellcheck pvpnwg.sh
```

### Testing Changes
```bash
# Test installation
sudo ./install.sh

# Test basic functionality
sudo pvpnwg validate configs
sudo pvpnwg -v --dry-run connect

# Run full test suite
sudo bats tests/
```

## License

[Specify license here]

## Acknowledgments

- **Gluetun project**: Port forwarding stability semantics
- **ProtonVPN**: WireGuard configuration format
- **WireGuard**: Modern VPN protocol
- **Debian**: Stable platform foundation
