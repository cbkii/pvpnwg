#!/usr/bin/env bash
# pvpnwg.sh — Enhanced ProtonVPN WireGuard CLI (Bash-only, Debian Bookworm)
# ----------------------------------------------------------------------------------
# Gluetun-style PF sync: stable NAT-PMP renew loop that keeps qB's listen_port in
# sync with the CURRENT public mapping, never clobbers it on transient failures,
# and uses Proton defaults (WG subnet 10.2.0.0/16 with NAT-PMP gateway 10.2.0.1).
# ----------------------------------------------------------------------------------
# Enhanced Features:
#  • WG health recovery (handshake age, link state, endpoint latency)
#  • Config validation before connection attempts
#  • Enhanced diagnostics with separate diag subcommands
#  • PF jitter detection and stability tracking
#  • DNS latency and qB WebUI health monitoring
#  • Comprehensive test framework support
# ----------------------------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

# Pre-parse for --user flag to set target user early
CLI_USER=""
orig_args=("$@")
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
      shift
      ;;
  esac
done
if [[ $EUID -eq 0 && -z "$CLI_USER" && -z "${SUDO_USER:-}" && -z "${PVPNWG_USER:-}" ]]; then
  echo "Error: please specify --user when running as root" >&2
  exit 1
fi
set -- "${orig_args[@]}"

# ===========================
# Defaults (derive from invoking user)
# ===========================
RUN_USER=""
if [[ -n "$CLI_USER" ]]; then
  RUN_USER="$CLI_USER"
elif [[ -n "${PVPNWG_USER:-}" ]]; then
  RUN_USER="$PVPNWG_USER"
elif [[ -n "${SUDO_USER:-}" ]]; then
  RUN_USER="$SUDO_USER"
else
  RUN_USER="$(id -un 2>/dev/null || echo root)"
fi
if ! getent passwd "$RUN_USER" >/dev/null 2>&1; then
  printf 'Unknown user: %s\n' "$RUN_USER" >&2
  exit 1
fi
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
RUN_HOME="${RUN_HOME:-$HOME}"
RUN_UID="$(id -u "$RUN_USER" 2>/dev/null || echo 0)"
RUN_GID="$(id -g "$RUN_USER" 2>/dev/null || echo 0)"
PHOME_DEFAULT="${RUN_HOME}/.pvpnwg"
CONFIG_DIR_DEFAULT="${PHOME_DEFAULT}/configs"
IFACE_DEFAULT="pvpnwg0"
LAN_IF_DEFAULT="eth0"
TIME_LIMIT_SECS_DEFAULT=$((8 * 3600))
DL_THRESHOLD_KBPS_DEFAULT=33
WEBUI_URL_DEFAULT="http://192.168.1.50:8080"
WEBUI_USER_DEFAULT="admin"
WEBUI_PASS_DEFAULT="change_me"
QB_CONF_PATH_DEFAULT="${RUN_HOME}/.config/qBittorrent/qBittorrent.conf"
PF_GATEWAY_FALLBACK_DEFAULT="10.2.0.1"
PF_RENEW_SECS_DEFAULT=45
PF_STATIC_FALLBACK_PORT_DEFAULT=51820
PF_PROTO_LIST_DEFAULT=("udp" "tcp")
PF_REQUIRE_BOTH_DEFAULT=true
KILLSWITCH_DEFAULT_DEFAULT=false
LOG_JSON_DEFAULT=false
LATENCY_THRESHOLD_MS_DEFAULT=400
LATENCY_FAILS_DEFAULT=3
MONITOR_INTERVAL_DEFAULT=60
HANDSHAKE_MAX_AGE_DEFAULT=120
DNS_HEALTH_DEFAULT=true
DNS_LAT_MS_DEFAULT=250
QBIT_HEALTH_DEFAULT=true
LOG_MAX_BYTES_DEFAULT=$((1024 * 1024))

# ===========================
# Config / Env
# ===========================
PHOME="${PHOME:-${PHOME_DEFAULT}}"
CONF_FILE="${PHOME}/pvpnwg.conf"
CONF_WARN_PERMS=""
if [[ -f "$CONF_FILE" ]]; then
  conf_perms=$(stat -c '%a' "$CONF_FILE" 2>/dev/null || echo "")
  [[ "$conf_perms" != "600" ]] && CONF_WARN_PERMS="$conf_perms"
  # shellcheck disable=SC1090
  . "$CONF_FILE"
fi
CONFIG_DIR="${CONFIG_DIR:-${CONFIG_DIR_DEFAULT}}"
IFACE="${IFACE:-${IFACE_DEFAULT}}"
TARGET_CONF="${TARGET_CONF:-/etc/wireguard/${IFACE}.conf}"
LAN_IF="${LAN_IF:-${LAN_IF_DEFAULT}}"
TIME_LIMIT_SECS="${TIME_LIMIT_SECS:-${TIME_LIMIT_SECS_DEFAULT}}"
DL_THRESHOLD_KBPS="${DL_THRESHOLD_KBPS:-${DL_THRESHOLD_KBPS_DEFAULT}}"
WEBUI_URL="${WEBUI_URL:-${WEBUI_URL_DEFAULT}}"
WEBUI_USER="${WEBUI_USER:-${WEBUI_USER_DEFAULT}}"
WEBUI_PASS="${WEBUI_PASS:-${WEBUI_PASS_DEFAULT}}"
QB_CONF_PATH="${QB_CONF_PATH:-${QB_CONF_PATH_DEFAULT}}"
PF_RENEW_SECS="${PF_RENEW_SECS:-${PF_RENEW_SECS_DEFAULT}}"
PF_GATEWAY_FALLBACK="${PF_GATEWAY_FALLBACK:-${PF_GATEWAY_FALLBACK_DEFAULT}}"
PF_STATIC_FALLBACK_PORT="${PF_STATIC_FALLBACK_PORT:-${PF_STATIC_FALLBACK_PORT_DEFAULT}}"
PF_REQUIRE_BOTH="${PF_REQUIRE_BOTH:-${PF_REQUIRE_BOTH_DEFAULT}}"
KILLSWITCH_DEFAULT="${KILLSWITCH_DEFAULT:-${KILLSWITCH_DEFAULT_DEFAULT}}"
LOG_JSON="${LOG_JSON:-${LOG_JSON_DEFAULT}}"
LATENCY_THRESHOLD_MS="${LATENCY_THRESHOLD_MS:-${LATENCY_THRESHOLD_MS_DEFAULT}}"
LATENCY_FAILS="${LATENCY_FAILS:-${LATENCY_FAILS_DEFAULT}}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-${MONITOR_INTERVAL_DEFAULT}}"
HANDSHAKE_MAX_AGE="${HANDSHAKE_MAX_AGE:-${HANDSHAKE_MAX_AGE_DEFAULT}}"
DNS_HEALTH="${DNS_HEALTH:-${DNS_HEALTH_DEFAULT}}"
DNS_LAT_MS="${DNS_LAT_MS:-${DNS_LAT_MS_DEFAULT}}"
QBIT_HEALTH="${QBIT_HEALTH:-${QBIT_HEALTH_DEFAULT}}"
LOG_MAX_BYTES="${LOG_MAX_BYTES:-${LOG_MAX_BYTES_DEFAULT}}"

if [[ -n "${PF_PROTO_LIST:-}" ]]; then IFS=', ' read -r -a PF_PROTO_LIST <<<"${PF_PROTO_LIST}"; else PF_PROTO_LIST=("${PF_PROTO_LIST_DEFAULT[@]}"); fi

# Run command as target user when invoked via sudo
run_as_user() {
  if [[ $EUID -eq "$RUN_UID" ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -n -u "#$RUN_UID" "$@"
  elif command -v su >/dev/null 2>&1; then
    local target
    target="$(getent passwd "$RUN_UID" | cut -d: -f1 || true)"
    target="${target:-$RUN_UID}"
    su -s /bin/sh "$target" -c "$(printf '%q ' "$@")"
  else
    die "Unable to run command as UID $RUN_UID: missing sudo and su"
  fi
}

# ===========================
# Runtime & paths
# ===========================
VERBOSE=0
DRY_RUN=0
STATE_DIR="${PHOME}/state"
TMP_DIR="${PHOME}/tmp"
LOG_FILE="${PHOME}/pvpn.log"
TIME_FILE="${STATE_DIR}/last_connect_epoch.txt"
PORT_FILE="${STATE_DIR}/mapped_port.txt"
PROTON_FWD_FILE="/run/user/${RUN_UID}/Proton/VPN/forwarded_port"
GLUETUN_FWD_FILE="/tmp/gluetun/forwarded_port"
DNS_BACKUP="${STATE_DIR}/dns_backup.tar"
GW_STATE="${STATE_DIR}/gw_state.txt"
IFCONF_FILE="${STATE_DIR}/lan_if.txt"
COOKIE_JAR="${STATE_DIR}/qb_cookie.txt"
MON_FAILS_FILE="${STATE_DIR}/monitor_fail_count.txt"
PF_HISTORY="${STATE_DIR}/pf_history.tsv" # ts\tprivate\tpublic\tgw\tstatus
PF_HISTORY_MAX=$((100 * 1024))
PF_HISTORY_KEEP=3
PF_JITTER_FILE="${STATE_DIR}/pf_jitter_count.txt"
HANDSHAKE_FILE="${STATE_DIR}/last_handshake.txt"

run_as_user mkdir -p "${PHOME}" "${STATE_DIR}" "${TMP_DIR}" "${CONFIG_DIR}"
run_as_user touch "$LOG_FILE" "$TIME_FILE" "$PORT_FILE" "$COOKIE_JAR" \
  "$MON_FAILS_FILE" "$PF_HISTORY" "$PF_JITTER_FILE" "$HANDSHAKE_FILE"

# ===========================
# Logging helpers
# ===========================
rotate_logs() {
  if [[ -f "$LOG_FILE" ]]; then
    local size
    size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    if ((size > LOG_MAX_BYTES)); then
      tail -c "$LOG_MAX_BYTES" "$LOG_FILE" >"${LOG_FILE}.tmp"
      mv "${LOG_FILE}.tmp" "$LOG_FILE"
    fi
  fi
}
_log_plain() {
  printf "%s %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$(printf '%s ' "$@" | sed 's/ $//')" \
    | tee -a "$LOG_FILE" >&2
}
_log_json() {
  jq -cn --arg ts "$(date -Iseconds)" --arg msg "$(printf '%s ' "$@" | sed 's/ $//')" '{ts:$ts, msg:$msg}' \
    | tee -a "$LOG_FILE" >&2
}
log() {
  rotate_logs
  if [[ "$LOG_JSON" == true ]]; then _log_json "$@"; else _log_plain "$@"; fi
}
vlog() { [[ $VERBOSE -eq 1 ]] && log "$@"; }
die() {
  log "ERROR:" "$@"
  exit 1
}
_run() {
  if [[ $VERBOSE -eq 1 || $DRY_RUN -eq 1 ]]; then log "+" "$@"; fi
  [[ $DRY_RUN -eq 1 ]] || "$@"
}
need_root() { [[ ${EUID} -eq 0 ]] || die "Passwordless sudo required."; }

check_deps() {
  local -a req=(ip wg wg-quick curl jq awk sed grep ping natpmpc)
  local -a opt=(vnstat nft resolvconf dig drill iptables)
  local miss=0
  for b in "${req[@]}"; do command -v "$b" >/dev/null 2>&1 || {
    log "Missing required tool: $b"
    miss=1
  }; done
  [[ $miss -eq 1 ]] && die "Install missing required tools and try again."
  for b in "${opt[@]}"; do command -v "$b" >/dev/null 2>&1 || vlog "Optional tool not found (OK): $b"; done
  local npv
  npv=$(natpmpc -v 2>&1 | grep -oE '[0-9]{8}' | head -1 || echo "")
  if [[ -z "$npv" || "$npv" -lt 20230423 ]]; then
    die "natpmpc >=20230423 required (found ${npv:-unknown})"
  fi
}

# Warn if config permissions are too permissive
[[ -n "${CONF_WARN_PERMS}" ]] && log "WARN: $CONF_FILE permissions are ${CONF_WARN_PERMS}; expected 600"

# ===========================
# DNS & routing state
# ===========================
dns_backend=""

detect_dns_backend() {
  if [[ -L /etc/resolv.conf ]] && readlink -f /etc/resolv.conf | grep -q systemd; then
    dns_backend="systemd-resolved"
  elif command -v resolvconf >/dev/null 2>&1 || [[ -d /etc/resolvconf ]]; then
    dns_backend="resolvconf"
  else dns_backend="flat"; fi
  vlog "DNS backend: ${dns_backend}"
}

current_gw() { ip route show default 2>/dev/null | awk '/default via/{print $3, $5; exit}'; }

save_gw_state() {
  local gwdev
  gwdev="$(current_gw || true)"
  [[ -n "$gwdev" ]] && echo "$gwdev" >"$GW_STATE" && vlog "Saved GW: $gwdev"
}
restore_gw_state() {
  if [[ -s "$GW_STATE" ]]; then
    read -r gw dev <"$GW_STATE"
    if [[ -n "${gw:-}" && -n "${dev:-}" ]]; then
      _run ip route replace default via "$gw" dev "$dev"
      log "Restored default route: $gw $dev"
    fi
  fi
}

# DNS backup/restore/dedupe
_dns_tar() { _run tar -cpf "$DNS_BACKUP" "$@" 2>/dev/null || true; }
dns_backup() {
  detect_dns_backend
  case "$dns_backend" in systemd-resolved | flat) _dns_tar /etc/resolv.conf ;; resolvconf) _dns_tar /etc/resolvconf /etc/resolv.conf ;; esac
}
dns_restore_generic() {
  detect_dns_backend
  case "$dns_backend" in
    systemd-resolved)
      _run resolvectl revert "$IFACE" || true
      ;;
    resolvconf)
      _run resolvconf -u || true
      ;;
    *)
      : >"$TMP_DIR/resolv.conf.generic"
      printf '%s\n' "nameserver 1.1.1.1" "nameserver 8.8.8.8" >>"$TMP_DIR/resolv.conf.generic"
      _run cp -f "$TMP_DIR/resolv.conf.generic" /etc/resolv.conf || true
      ;;
  esac
  log "DNS restored generically"
}
dns_restore() {
  if [[ -f "$DNS_BACKUP" ]]; then
    if tar -tf "$DNS_BACKUP" | grep -E '(^/|(^|/)\.\.(/|$))' >/dev/null; then
      log "Unsafe paths in DNS backup; using generic restore"
      dns_restore_generic
      return
    fi
    local tmp
    tmp=$(mktemp -d)
    if _run tar -xpf "$DNS_BACKUP" -C "$tmp"; then
      _run cp -a "$tmp/." /
      log "DNS restored from backup"
    else
      log "DNS backup extraction failed; using generic restore"
      dns_restore_generic
    fi
    rm -rf "$tmp"
  else
    vlog "No DNS backup"
  fi
}
dns_dedupe() {
  if [[ -f /etc/resolv.conf ]]; then
    awk '!seen[$0]++' /etc/resolv.conf >"$TMP_DIR/resolv.conf.dedup"
    _run cp -f "$TMP_DIR/resolv.conf.dedup" /etc/resolv.conf
    log "Deduped resolv.conf"
  fi
}

dns_latency_test() {
  local resolver="${1:-$(wg_conf_dns | awk '{print $1}' | head -1)}" target="${2:-google.com}"
  if ! command -v dig >/dev/null 2>&1; then
    vlog "dig not available for DNS latency test"
    return 1
  fi
  local wg_ip
  wg_ip=$(ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
  if [[ -z "$wg_ip" ]]; then
    vlog "No WG IP for DNS latency test"
    return 1
  fi
  local output rc
  if ! output=$(timeout 5 dig +stats -4 -b "$wg_ip" "$target" @"$resolver" 2>&1); then
    rc=$?
    vlog "dig to $resolver for $target failed (rc=$rc)"
    return 1
  fi
  local query_time
  query_time=$(echo "$output" | awk '/Query time:/{print $4}' | head -1)
  if [[ -n "$query_time" && "$query_time" =~ ^[0-9]+$ ]]; then
    echo "$query_time"
    return 0
  fi
  return 1
}

cmd_dns() {
  case "${1:-}" in
    backup) dns_backup ;;
    restore) dns_restore ;;
    dedupe) dns_dedupe ;;
    set)
      case "${2:-}" in
        proton)
          detect_dns_backend
          local dns_servers
          dns_servers=$(wg_conf_dns | tr ',' ' ' | xargs -n1 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | xargs)
          if [[ -z "$dns_servers" ]]; then
            log "WARN: no IPv4 DNS in $TARGET_CONF"
            return 1
          fi
          if [[ "$dns_backend" == "systemd-resolved" ]]; then
            for d in $dns_servers; do _run resolvectl dns "$IFACE" "$d" || true; done
            _run resolvectl domain "$IFACE" "~." || true
            log "DNS(v4): set on $IFACE via systemd-resolved"
          else
            if [[ -L /etc/resolv.conf ]]; then
              log "INFO: /etc/resolv.conf is a symlink; skipping write"
            else
              : >"$TMP_DIR/resolv.conf.new"
              for d in $dns_servers; do printf 'nameserver %s\n' "$d" >>"$TMP_DIR/resolv.conf.new"; done
              _run cp -f "$TMP_DIR/resolv.conf.new" /etc/resolv.conf
              log "DNS set to Proton (${dns_servers})"
            fi
          fi
          ;;
        system)
          dns_restore || true
          log "DNS restored/system"
          ;;
        *)
          echo "Usage: $0 dns set {proton|system}"
          return 1
          ;;
      esac
      ;;
    test)
      local resolver="${2:-resolver1.opendns.com}"
      local bin=""
      command -v dig >/dev/null 2>&1 && bin=dig || bin=drill
      command -v "$bin" >/dev/null 2>&1 || die "Install dnsutils (dig) or ldnsutils (drill)."
      $bin +short TXT o-o.myaddr.l.google.com @"$resolver" || true
      ;;
    latency)
      local ms
      ms=$(dns_latency_test "${2:-}" "${3:-google.com}" || echo "")
      if [[ -n "$ms" ]]; then echo "DNS latency: ${ms}ms"; else echo "DNS latency: unavailable"; fi
      ;;
    *)
      echo "Usage: $0 dns {backup|restore|dedupe|set {proton|system}|test [resolver]|latency [resolver] [target]}"
      return 1
      ;;
  esac
}

# ===========================
# Interface selection
# ===========================
iface_load() { [[ -s "$IFCONF_FILE" ]] && LAN_IF="$(cat "$IFCONF_FILE")"; }
iface_save() {
  echo "$LAN_IF" >"$IFCONF_FILE"
  log "Saved LAN_IF=$LAN_IF"
}
iface_scan() {
  echo "Interfaces:"
  ip -o link show | awk -F': ' '$2!="lo"{print $2}' | sed 's/@.*//'
  read -rp "Use interface [${LAN_IF}]: " ans
  if [[ -n "${ans:-}" ]]; then
    local prev="$LAN_IF"
    LAN_IF="$ans"
    iface_save || {
      LAN_IF="$prev"
      vlog "Keep $LAN_IF"
    }
  else
    vlog "Keep $LAN_IF"
  fi
}

# ===========================
# Config validation
# ===========================
conf_validate() {
  local file="$1" errors=0

  # Check file exists and is readable
  [[ -r "$file" ]] || {
    echo "not readable"
    return 1
  }

  # Required Interface section keys
  local private_key address
  private_key=$(awk -F'=' '/^\s*PrivateKey\s*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}' "$file")
  address=$(awk -F'=' '/^\s*Address\s*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}' "$file")

  [[ -n "$private_key" ]] || {
    echo "missing PrivateKey"
    ((errors++))
  }
  [[ -n "$address" ]] || {
    echo "missing Address"
    ((errors++))
  }

  # Address should have CIDR notation
  if [[ -n "$address" && "$address" != */* ]]; then
    echo "Address missing CIDR"
    ((errors++))
  fi

  # Required Peer section keys
  local public_key endpoint allowed_ips
  public_key=$(awk -F'=' '/^\s*PublicKey\s*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}' "$file")
  endpoint=$(awk -F'=' '/^\s*Endpoint\s*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}' "$file")
  allowed_ips=$(awk -F'=' '/^\s*AllowedIPs\s*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}' "$file")

  [[ -n "$public_key" ]] || {
    echo "missing PublicKey"
    ((errors++))
  }
  [[ -n "$endpoint" ]] || {
    echo "missing Endpoint"
    ((errors++))
  }
  [[ -n "$allowed_ips" ]] || {
    echo "missing AllowedIPs"
    ((errors++))
  }

  # Endpoint format validation: host:port
  if [[ -n "$endpoint" ]]; then
    if [[ "$endpoint" != *:* ]]; then
      echo "Endpoint missing port"
      ((errors++))
    else
      local port="${endpoint##*:}"
      if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        echo "Endpoint invalid port"
        ((errors++))
      fi
    fi
  fi

  # AllowedIPs should contain 0.0.0.0/0 for VPN usage
  if [[ -n "$allowed_ips" && "$allowed_ips" != *"0.0.0.0/0"* ]]; then
    vlog "WARN: AllowedIPs doesn't contain 0.0.0.0/0 in $file"
  fi

  # Test wg-quick parsing if available
  if command -v wg-quick >/dev/null 2>&1; then
    if ! wg-quick strip "$file" >/dev/null 2>&1; then
      echo "wg-quick parse failed"
      ((errors++))
    fi
  fi

  if [[ $errors -eq 0 ]]; then
    echo "valid"
    return 0
  else
    return 1
  fi
}

# ===========================
# Server config selection with validation
# ===========================
is_secure_core_name() {
  local n="$1"
  shopt -s nocasematch
  [[ "$n" == *SC.conf || "$n" == *sc*.conf || "$n" == *secure*core*.conf ]]
  local r=$?
  shopt -u nocasematch
  return $r
}

is_pf_name() {
  local n="$1"
  shopt -s nocasematch
  [[ "$n" == *PF.conf || "$n" == *pf*.conf || "$n" == *port*forward*.conf ]]
  local r=$?
  shopt -u nocasematch
  return $r
}
conf_endpoint_host() {
  local f="$1"
  awk -F'=' '/^\s*Endpoint\s*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2}' "$f" | awk -F':' '{print $1; exit}'
}
ping_rtt_ms() {
  local host="$1" ip now last out
  ip=$(getent ahostsv4 "$host" | awk '{print $1; exit}' 2>/dev/null || true)
  [[ -n "$ip" ]] || ip="$host"
  now=$(date +%s)
  last=$(cat "$STATE_DIR/ping_token.txt" 2>/dev/null || echo 0)
  if ((now - last < 5)); then
    echo 9999
    return
  fi
  out=$(ping -4 -n -c1 -W1 "$ip" 2>/dev/null) || {
    echo 9999
    return
  }
  echo "$now" >"$STATE_DIR/ping_token.txt"
  echo "$out" | awk -F'=' '/time=/{print $NF}' | awk '{print $1}' | sed 's/ms//' || echo 9999
}

select_conf() {
  local mode="${1:-p2p}" cc="${2:-}" best_conf="" best_rtt=999999 valid_count=0
  local _ng
  _ng=$(shopt -p nullglob)
  shopt -s nullglob
  local files=("${CONFIG_DIR}"/*.conf)
  [[ ${#files[@]} -gt 0 ]] || die "No .conf in ${CONFIG_DIR}"

  if [[ $VERBOSE -eq 1 ]]; then
    log "Config selection (mode=$mode cc=$cc):"
    printf "%-25s %-20s %-8s %-10s\n" "FILE" "HOST" "RTT" "VALID"
  fi

  for f in "${files[@]}"; do
    local base
    base="$(basename "$f")"
    case "$mode" in
      p2p) is_secure_core_name "$base" && continue ;;
      sc) is_secure_core_name "$base" || continue ;;
      pf) is_pf_name "$base" || continue ;;
      any) : ;;
    esac
    [[ -n "$cc" && "$base" != *"$cc"* ]] && continue

    # Validate config first
    local validation
    validation=$(conf_validate "$f" 2>&1 || echo "invalid")
    if [[ "$validation" != "valid" ]]; then
      vlog "SKIP $(basename "$f"): $validation"
      continue
    fi
    ((valid_count++))

    local host
    host="$(conf_endpoint_host "$f" || true)"
    [[ -n "$host" ]] || continue
    local rtt
    rtt="$(ping_rtt_ms "$host")"
    [[ "$rtt" =~ ^[0-9.]+$ ]] || rtt=999999

    if [[ $VERBOSE -eq 1 ]]; then
      printf "%-25s %-20s %-8s %-10s\n" "$(basename "$f")" "$host" "${rtt}ms" "$validation"
    fi

    if awk -v a="$rtt" -v b="$best_rtt" 'BEGIN{exit !(a<b)}'; then
      best_rtt="$rtt"
      best_conf="$f"
    fi
  done

  eval "$_ng"
  [[ $valid_count -gt 0 ]] || die "No valid configs found (mode=$mode cc=$cc)"
  [[ -n "$best_conf" ]] || die "No config matched (mode=$mode cc=$cc)"
  echo "$best_conf|$best_rtt"
}

# ===========================
# WireGuard control & health
# ===========================
wg_up() {
  local conf="$1"
  _run mkdir -p /etc/wireguard
  _run cp -f "$conf" "$TARGET_CONF"
  conf_strip_ipv6_allowedips
  _run wg-quick down "$IFACE" >/dev/null 2>&1 || true
  _run wg-quick up "$IFACE"
  date +%s >"$TIME_FILE"
  log "WG up via $(basename "$conf")"
}
wg_down() {
  _run wg-quick down "$IFACE" >/dev/null 2>&1 || true
  log "WG $IFACE down"
}

wg_handshake_age() {
  local handshake_line
  handshake_line=$(wg show "$IFACE" latest-handshakes 2>/dev/null | head -1 || true)
  if [[ -z "$handshake_line" ]]; then
    echo "never"
    return 1
  fi
  local timestamp
  timestamp=$(echo "$handshake_line" | awk '{print $2}')
  if [[ -z "$timestamp" || "$timestamp" == "0" ]]; then
    echo "never"
    return 1
  fi
  local now
  now=$(date +%s)
  local age=$((now - timestamp))
  echo "$age"
  echo "$age" >"$HANDSHAKE_FILE"
  return 0
}

wg_endpoint_host() {
  wg show "$IFACE" endpoints 2>/dev/null | awk '{print $2}' | awk -F':' '{print $1; exit}'
}

wg_conf_dns() {
  awk -F'=' '/^\s*DNS\s*=/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' "$TARGET_CONF" 2>/dev/null
}

conf_strip_ipv6_allowedips() {
  sed -i -E 's/,\s*::\/0//; s/^AllowedIPs\s*=\s*::\/0\s*$//;' "$TARGET_CONF"
}

wg_link_state() {
  local a b
  a=$(ip link show "$IFACE" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="state"){print $(i+1); exit}}')
  b=$(ip link show "$IFACE" 2>/dev/null | grep -q " state UP " && echo UP || echo DOWN)
  if [[ "$a" != "$b" ]]; then
    log "WARN: link state mismatch (parsed='$a' grep='$b'); trusting grep result"
  fi
  [[ "$b" == "UP" ]] && echo UP || echo DOWN
}

wg_unhealthy_reason() {
  # Check if interface exists and is up
  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "no_interface"
    return 1
  fi

  local link_state
  link_state=$(wg_link_state)
  if [[ "$link_state" == "DOWN" ]]; then
    echo "link_down"
    return 1
  fi

  # Check handshake age
  local handshake_age
  handshake_age=$(wg_handshake_age 2>/dev/null || echo "never")
  if [[ "$handshake_age" == "never" ]]; then
    echo "no_handshake"
    return 1
  fi
  if [[ "$handshake_age" =~ ^[0-9]+$ && "$handshake_age" -gt "$HANDSHAKE_MAX_AGE" ]]; then
    echo "handshake_old"
    return 1
  fi

  # Check endpoint latency
  local host
  host=$(wg_endpoint_host)
  if [[ -n "$host" ]]; then
    local rtt
    rtt=$(ping_rtt_ms "$host")
    if [[ "$rtt" =~ ^[0-9.]+$ ]] && awk -v a="$rtt" -v b="$LATENCY_THRESHOLD_MS" 'BEGIN{exit !(a>b)}'; then
      echo "endpoint_latency"
      return 1
    fi
  fi

  echo "none"
  return 0
}

# ===========================
# qBittorrent helpers
# ===========================
qb_login() {
  if [[ ${EUID} -eq 0 ]]; then
    install -m 600 -o "${RUN_UID}" -g "${RUN_GID}" /dev/null "$COOKIE_JAR"
  else
    install -m 600 /dev/null "$COOKIE_JAR"
  fi
  if ! curl -sS --fail --connect-timeout 10 -c "$COOKIE_JAR" \
    --data-urlencode "username=${WEBUI_USER}" \
    --data-urlencode "password=${WEBUI_PASS}" \
    "${WEBUI_URL%/}/api/v2/auth/login" >/dev/null; then
    log "WARN: qBittorrent WebUI login failed"
    return 1
  fi
}
qb_set_port_webui() {
  local port="$1"
  qb_login || return 1
  local url="${WEBUI_URL%/}"
  # Opinionated prefs: disable UPnP & random port
  local prefs
  prefs=$(jq -n --argjson p "$port" '{listen_port: ($p|tonumber), upnp:false, random_port:false}')
  curl -sS --fail --connect-timeout 10 -b "$COOKIE_JAR" \
    --data-urlencode "json=${prefs}" "${url}/api/v2/app/setPreferences" >/dev/null || return 1
  local got
  got=$(curl -sS --fail --connect-timeout 10 -b "$COOKIE_JAR" \
    "$url/api/v2/app/preferences" | jq -r '.listen_port // empty') || return 1
  if [[ "$got" != "$port" ]]; then
    log "WARN: qB listen_port verify failed want=$port got=${got:-unset}"
    return 1
  fi
  log "qB listen_port=${port} set (UPnP/NAT-PMP disabled)"
}
qb_conf_get_port() {
  local f="$QB_CONF_PATH"
  [[ -r "$f" ]] || {
    echo ""
    return 1
  }
  awk -F'=' '/^Preferences\\ListenPort=/{print $2; exit}' "$f" 2>/dev/null
}
qb_set_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] || {
    log "WARN: invalid qB port '$port'"
    return 1
  }
  qb_set_port_webui "$port" && return 0
  if [[ -n "$QB_CONF_PATH" && -w "$QB_CONF_PATH" ]]; then
    if grep -q '^Preferences\\ListenPort=' "$QB_CONF_PATH" 2>/dev/null; then
      local tmp
      tmp=$(mktemp "${QB_CONF_PATH}.XXXXXX") || return 1
      if while IFS= read -r line; do
        if [[ "$line" == "Preferences\\ListenPort="* ]]; then
          printf 'Preferences\\ListenPort=%s\n' "$port"
        else
          printf '%s\n' "$line"
        fi
      done <"$QB_CONF_PATH" >"$tmp"; then
        mv "$tmp" "$QB_CONF_PATH"
        chown "${RUN_UID}:${RUN_GID}" "$QB_CONF_PATH" 2>/dev/null || true
        log "qB conf patched listen_port=${port} (restart qB)"
        return 0
      else
        rm -f "$tmp"
      fi
    fi
  fi
  return 1
}
qb_get_port() {
  if qb_login; then
    curl -sS --fail --connect-timeout 10 -b "$COOKIE_JAR" \
      "${WEBUI_URL%/}/api/v2/app/preferences" | jq -r '.listen_port // empty' || return 1
  else
    qb_conf_get_port || echo ""
  fi
}
qb_fix_stalled() {
  qb_login || return 1
  local url="${WEBUI_URL%/}"
  local list
  list=$(curl -sS --fail --connect-timeout 10 -b "$COOKIE_JAR" \
    "$url/api/v2/torrents/info?filter=stalled" || true)
  local hashes
  hashes=$(echo "$list" | jq -r '.[].hash')
  if [[ -z "$hashes" ]]; then
    log "No stalled torrents"
    return 0
  fi
  while read -r h; do
    [[ -z "$h" ]] && continue
    curl -sS --fail --connect-timeout 10 -b "$COOKIE_JAR" \
      --data-urlencode "hashes=$h" "$url/api/v2/torrents/reannounce" >/dev/null || true
    curl -sS --fail --connect-timeout 10 -b "$COOKIE_JAR" \
      --data-urlencode "hashes=$h" "$url/api/v2/torrents/resume" >/dev/null || true
    log "Reannounced+Resumed $h"
  done <<<"$hashes"
}

qb_health_check() {
  if [[ "$QBIT_HEALTH" != "true" ]]; then return 0; fi
  if qb_login; then
    local version
    version=$(curl -sS --fail --connect-timeout 10 -b "$COOKIE_JAR" \
      "${WEBUI_URL%/}/api/v2/app/version" 2>/dev/null || echo "")
    if [[ -n "$version" ]]; then
      vlog "qB health: OK (version $version)"
      return 0
    fi
  fi
  log "WARN: qB WebUI health check failed"
  return 1
}

# ===========================
# NAT-PMP Port Forwarding (6A) — Gluetun-style stable sync with jitter detection
# ===========================
PF_BACKOFF_START=5
PF_BACKOFF_MAX=60

pf_derive_gateway_from_conf() {
  local dns addr
  dns=$(awk -F= '/^\s*DNS\s*=/{gsub(/[ \t]/,"",$2);print $2}' "$TARGET_CONF" | tr ',' ' ' | xargs -n1 \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
  if [[ -n "$dns" ]]; then
    echo "$dns"
    return 0
  fi
  addr=$(awk -F= '/^\s*Address\s*=/{gsub(/[ \t]/,"",$2);print $2}' "$TARGET_CONF" | tr ',' ' ' \
    | grep -Eo '10\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  if [[ -n "$addr" ]]; then
    IFS='.' read -r a b c d <<<"$addr"
    printf "%s.%s.%s.1\n" "$a" "$b" "$c"
    return 0
  fi
  echo "$PF_GATEWAY_FALLBACK"
}

pf_detect_gateway() {
  local derived
  derived=$(pf_derive_gateway_from_conf)
  if natpmpc -g "$derived" -a 1 0 udp 10 -q >/dev/null 2>&1; then
    echo "$derived"
  else
    echo "$PF_GATEWAY_FALLBACK"
  fi
}

pf_parse_status() {
  local out="$1"
  if grep -qi 'Mapped public port' <<<"$out"; then
    return 0
  elif grep -qi 'try again' <<<"$out"; then
    return 2
  else
    return 1
  fi
}

pf_history_rotate_if_needed() {
  local size
  size=$(stat -c '%s' "$PF_HISTORY" 2>/dev/null || echo 0)
  ((size < PF_HISTORY_MAX)) && return 0
  local i
  for i in $(seq $((PF_HISTORY_KEEP - 1)) -1 1); do
    [[ -f "${PF_HISTORY}.$i" ]] && mv "${PF_HISTORY}.$i" "${PF_HISTORY}.$((i + 1))" || true
  done
  mv "$PF_HISTORY" "${PF_HISTORY}.1" || true
  : >"$PF_HISTORY" || true
}

pf_record() {
  local ts pvt pub gw st
  ts=$(date +%s)
  pvt="$1"
  pub="$2"
  gw="$3"
  st="$4"
  pf_history_rotate_if_needed || true
  echo -e "$ts\t$pvt\t$pub\t$gw\t$st" >>"$PF_HISTORY" || true
}

pf_check_jitter() {
  local new_port="$1" prev_port="$2"
  if [[ -z "$prev_port" || "$new_port" == "$prev_port" ]]; then return 0; fi

  # Track consecutive different ports
  local jitter_count=0
  [[ -s "$PF_JITTER_FILE" ]] && jitter_count=$(cat "$PF_JITTER_FILE" 2>/dev/null || echo 0)
  jitter_count=$((jitter_count + 1))
  echo "$jitter_count" >"$PF_JITTER_FILE" || true

  if [[ $jitter_count -ge 3 ]]; then
    log "WARN: PF port jitter detected ($jitter_count consecutive changes)"
    return 1
  fi
  return 0
}

pf_request_once() {
  local gw lease prev proto out st new_port="" ok_count=0 need_count saw_try_again=false
  local try_pub try_prv mode gw_tried port udp_port tcp_port
  gw="$(pf_detect_gateway)"
  lease=60
  prev="$(cat "$PORT_FILE" 2>/dev/null || true)"
  need_count=${#PF_PROTO_LIST[@]}
  [[ "$PF_REQUIRE_BOTH" == false ]] && need_count=1

  local modes=()
  if [[ -n "$prev" ]]; then
    modes+=("renew" "any" "mirror")
  else
    modes+=("any" "mirror")
  fi

  for gw_tried in "$gw" "$PF_GATEWAY_FALLBACK"; do
    [[ -z "$gw_tried" ]] && continue
    [[ "$gw_tried" != "$gw" ]] && vlog "PF: retrying with static gateway $PF_GATEWAY_FALLBACK"

    for mode in "${modes[@]}"; do
      ok_count=0
      saw_try_again=false
      udp_port=""
      tcp_port=""
      new_port=""

      for proto in "${PF_PROTO_LIST[@]}"; do
        case "$mode" in
          renew)
            try_pub="$prev"
            try_prv="$prev"
            ;;
          any)
            try_pub=1
            try_prv=0
            ;;
          mirror)
            try_pub=0
            try_prv=0
            ;;
        esac

        out=$(natpmpc -g "$gw_tried" -a "$try_pub" "$try_prv" "$proto" "$lease" 2>&1 || true)
        if pf_parse_status "$out"; then st=0; else st=$?; fi
        vlog "natpmpc($proto gw=$gw_tried mode=$mode) => ${out//$'\n'/ }"

        if ((st == 0)); then
          port=$(echo "$out" | awk '/Mapped public port/{print $4; exit}')
          [[ "$proto" == udp ]] && udp_port="$port"
          [[ "$proto" == tcp ]] && tcp_port="$port"
          ((ok_count++))
        elif ((st == 2)); then
          saw_try_again=true
        fi
      done

      if ((ok_count >= need_count)); then
        if [[ "$PF_REQUIRE_BOTH" == true && -n "$udp_port" && -n "$tcp_port" && "$udp_port" != "$tcp_port" ]]; then
          log "WARN: PF mapped different UDP ($udp_port) and TCP ($tcp_port) ports"
        fi
        if [[ -n "$udp_port" ]]; then
          new_port="$udp_port"
        elif [[ -n "$tcp_port" ]]; then
          new_port="$tcp_port"
        fi

        if [[ -n "$new_port" ]]; then
          if pf_check_jitter "$new_port" "$prev"; then echo 0 >"$PF_JITTER_FILE" || true; fi
          if [[ "$new_port" != "$prev" ]]; then
            if qb_set_port "$new_port"; then
              echo "$new_port" >"$PORT_FILE" || true
              mkdir -p "$(dirname "$PROTON_FWD_FILE")" /tmp/gluetun || true
              echo "$new_port" >"$PROTON_FWD_FILE" || true
              echo "$new_port" >"$GLUETUN_FWD_FILE" || true
              log "PF mapped: port=$new_port gw=$gw_tried (updated via $mode)"
            else
              log "WARN: qB sync to PF port $new_port failed"
            fi
          else
            log "PF mapped unchanged: port=$new_port"
          fi
          pf_record "$new_port" "$new_port" "$gw_tried" ok || true
          return 0
        fi
      fi
    done
  done

  pf_record "${prev:-0}" 0 "$gw" "$($saw_try_again && echo try_again || echo error)" || true
  if $saw_try_again; then
    log "WARN: NAT-PMP TRY AGAIN on $gw (server may not support PF)"
  else
    log "WARN: NAT-PMP failed on $gw"
  fi
  if [[ -z "$prev" ]]; then
    log "No previous PF port; setting static fallback $PF_STATIC_FALLBACK_PORT"
    echo "$PF_STATIC_FALLBACK_PORT" >"$PORT_FILE" || true
    qb_set_port "$PF_STATIC_FALLBACK_PORT" || true
  else
    log "Keeping existing qB/port=$prev until next successful mapping"
  fi
  return 1
}

pf_verify() {
  local port gw out st
  port="$(cat "$PORT_FILE" 2>/dev/null || echo "$PF_STATIC_FALLBACK_PORT")"
  gw="$(pf_detect_gateway)"
  out=$(natpmpc -g "$gw" -a "$port" "$port" udp 30 2>&1 || true)
  if pf_parse_status "$out"; then
    st=0
  else
    st=$?
  fi
  case "$st" in
    0) echo "PF OK on $gw (udp)" ;;
    2) echo "PF TRY AGAIN on $gw (likely unsupported)" ;;
    *) echo "PF FAILED on $gw" ;;
  esac
}

pf_diag() {
  local port
  port="$(cat "$PORT_FILE" 2>/dev/null || echo "$PF_STATIC_FALLBACK_PORT")"
  echo "Gateway: $(pf_detect_gateway)"
  echo "Port: $port"
  echo "Jitter count: $(cat "$PF_JITTER_FILE" 2>/dev/null || echo 0)"
  echo "History (tail):"
  tail -n 10 "$PF_HISTORY" 2>/dev/null || echo "(no history)"
  echo
  echo "natpmpc probe:"
  natpmpc -g "$(pf_detect_gateway)" -a "$port" "$port" udp 30 2>&1 || true
}

pf_loop() {
  log "PF sync loop start (gw $(pf_detect_gateway), ${PF_RENEW_SECS}s cadence; backoff on failure)"
  local backoff=$PF_BACKOFF_START run=true
  trap 'run=false' INT TERM
  while $run; do
    if pf_request_once; then
      backoff=$PF_BACKOFF_START
      sleep "$PF_RENEW_SECS"
    else
      sleep "$backoff"
      backoff=$((backoff * 2))
      [[ $backoff -gt $PF_BACKOFF_MAX ]] && backoff=$PF_BACKOFF_MAX
    fi
  done
  trap - INT TERM
}

# ===========================
# Health-check & latency monitor (enhanced)
# ===========================
human_kbps() {
  local bytes="$1" secs="$2"
  [[ "$secs" -le 0 ]] && {
    echo 0
    return
  }
  awk -v b="$bytes" -v s="$secs" 'BEGIN{ printf("%.0f", (b/1024)/s) }'
}
bytes_rx() { awk -v IF="${LAN_IF}:" '$1==IF{print $2}' /proc/net/dev; }
active_download_kbps() {
  local b1 s=5
  b1=$(bytes_rx)
  sleep "$s"
  local b2
  b2=$(bytes_rx)
  human_kbps $((b2 - b1)) "$s"
}

should_reconnect() {
  local now last=0
  now=$(date +%s)
  [[ -s "$TIME_FILE" ]] && last=$(cat "$TIME_FILE")
  local elapsed=$((now - last))
  if [[ "$elapsed" -ge "$TIME_LIMIT_SECS" ]]; then
    echo time
    return 0
  fi
  local kbps
  kbps=$(active_download_kbps || echo 0)
  if [[ "$kbps" -lt "$DL_THRESHOLD_KBPS" ]]; then
    echo idle
    return 0
  fi
  return 1
}

monitor_once() {
  # Check WG health first
  local wg_reason
  if ! wg_reason=$(wg_unhealthy_reason 2>/dev/null); then
    wg_reason=${wg_reason:-unknown}
  fi
  if [[ "$wg_reason" != "none" ]]; then
    log "Monitor WG unhealthy (${wg_reason}) -> reconnect"
    cmd_reconnect -p2p || {
      log "WARN reconnect failed, trying --any"
      cmd_reconnect -a || true
    }
    echo 0 >"$MON_FAILS_FILE"
    return 0
  fi

  # Check time/idle policy
  local reason
  if reason=$(should_reconnect); then
    log "Monitor reconnect (${reason})"
    cmd_reconnect -p2p || {
      log "WARN reconnect failed, trying --any"
      cmd_reconnect -a || true
    }
    echo 0 >"$MON_FAILS_FILE"
    return 0
  fi

  # Enhanced monitoring checks
  local issues=0

  # DNS latency check
  if [[ "$DNS_HEALTH" == "true" ]]; then
    local dns_ms
    dns_ms=$(dns_latency_test 2>/dev/null || echo "")
    if [[ -n "$dns_ms" && "$dns_ms" =~ ^[0-9]+$ && "$dns_ms" -gt "$DNS_LAT_MS" ]]; then
      log "WARN: High DNS latency ${dns_ms}ms (>${DNS_LAT_MS}ms)"
      ((issues++))
    fi
  fi

  # qB health check
  qb_health_check || ((issues++))

  # Endpoint latency (existing logic)
  local host
  host=$(wg show "$IFACE" endpoints 2>/dev/null | awk '{print $2}' | awk -F':' '{print $1; exit}')
  if [[ -n "$host" ]]; then
    local rtt
    rtt=$(ping_rtt_ms "$host")
    local thresh="$LATENCY_THRESHOLD_MS"
    if awk -v a="$rtt" -v b="$thresh" 'BEGIN{exit !(a>b)}'; then
      local fails=0
      [[ -s "$MON_FAILS_FILE" ]] && fails=$(cat "$MON_FAILS_FILE")
      fails=$((fails + 1))
      echo "$fails" >"$MON_FAILS_FILE"
      log "Monitor high RTT=${rtt}ms (>${thresh}), fails=${fails}"
      if [[ $fails -ge $LATENCY_FAILS ]]; then
        log "Monitor threshold breached -> reconnect"
        echo 0 >"$MON_FAILS_FILE"
        cmd_reconnect -p2p || cmd_reconnect -a || true
      fi
    else echo 0 >"$MON_FAILS_FILE"; fi
  fi

  if [[ $issues -gt 0 ]]; then
    vlog "Monitor detected $issues issues (non-fatal)"
  fi
}

monitor_loop() {
  log "Monitor loop every ${MONITOR_INTERVAL}s (lat>${LATENCY_THRESHOLD_MS}ms for ${LATENCY_FAILS} tries, WG health, DNS ${DNS_LAT_MS}ms)"
  while true; do
    monitor_once || true
    sleep "$MONITOR_INTERVAL"
  done
}

# ===========================
# Killswitch templates
# ===========================
wg_endpoint_rule_add_v4() {
  local host port ip4
  if ip link show "$IFACE" >/dev/null 2>&1 && wg show "$IFACE" endpoints | grep -q ':'; then
    host=$(wg show "$IFACE" endpoints | awk '{print $2}' | awk -F: '{print $1; exit}')
    port=$(wg show "$IFACE" endpoints | awk '{print $2}' | awk -F: '{print $2; exit}')
  else
    host=$(awk -F= '/^\s*Endpoint\s*=/{gsub(/[ \t]/,"",$2);print $2}' "$TARGET_CONF" | awk -F: '{print $1}')
    port=$(awk -F= '/^\s*Endpoint\s*=/{gsub(/[ \t]/,"",$2);print $2}' "$TARGET_CONF" | awk -F: '{print $2}')
  fi
  [[ -n $host && -n $port ]] || return 0
  ip4=$(getent ahostsv4 "$host" | awk '/STREAM/ {print $1; exit}')
  [[ -n $ip4 ]] || return 0
  nft add rule inet pvpnwg output oifname "$LAN_IF" ip daddr "$ip4" udp dport "$port" accept || true
}

# nftables
killswitch_enable() {
  if ! command -v nft >/dev/null 2>&1; then
    log "nft not installed"
    return 1
  fi

  _run nft -f - <<NFT
table inet pvpnwg {
  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    oifname "${IFACE}" accept
    ip daddr 127.0.0.0/8 accept
    ip6 daddr ::1 accept
    ip daddr 10.0.0.0/8 accept
    ip daddr 172.16.0.0/12 accept
    ip daddr 192.168.0.0/16 accept
  }
}
NFT
  wg_endpoint_rule_add_v4

  log "Killswitch (nft) enabled"
}

killswitch_disable() {
  command -v nft >/dev/null 2>&1 || {
    log "nft not installed"
    return 1
  }
  _run nft delete table inet pvpnwg || true
  log "Killswitch (nft) disabled"
}

# iptables (nft backend) variant
killswitch_iptables_enable() {
  if ! command -v iptables >/dev/null 2>&1; then
    log "iptables not installed"
    return 1
  fi
  _run iptables -N pvpnwg-out >/dev/null 2>&1 || true
  _run iptables -F pvpnwg-out
  _run iptables -I OUTPUT 1 -j pvpnwg-out
  _run iptables -A pvpnwg-out -m state --state ESTABLISHED,RELATED -j ACCEPT
  _run iptables -A pvpnwg-out -o "$IFACE" -j ACCEPT
  _run iptables -A pvpnwg-out -d 127.0.0.0/8 -j ACCEPT
  _run iptables -A pvpnwg-out -d 10.0.0.0/8 -j ACCEPT
  _run iptables -A pvpnwg-out -d 172.16.0.0/12 -j ACCEPT
  _run iptables -A pvpnwg-out -d 192.168.0.0/16 -j ACCEPT
  local host port ip4
  if ip link show "$IFACE" >/dev/null 2>&1 && wg show "$IFACE" endpoints | grep -q ':'; then
    host=$(wg show "$IFACE" endpoints | awk '{print $2}' | awk -F: '{print $1; exit}')
    port=$(wg show "$IFACE" endpoints | awk '{print $2}' | awk -F: '{print $2; exit}')
  else
    host=$(awk -F= '/^\s*Endpoint\s*=/{gsub(/[ \t]/,"",$2);print $2}' "$TARGET_CONF" | awk -F: '{print $1}')
    port=$(awk -F= '/^\s*Endpoint\s*=/{gsub(/[ \t]/,"",$2);print $2}' "$TARGET_CONF" | awk -F: '{print $2}')
  fi
  if [[ -n $host && -n $port ]]; then
    ip4=$(getent ahostsv4 "$host" | awk '/STREAM/ {print $1; exit}')
    [[ -n $ip4 ]] && _run iptables -A pvpnwg-out -o "$LAN_IF" -p udp -d "$ip4" --dport "$port" -j ACCEPT
  fi
  _run iptables -P OUTPUT DROP
  log "Killswitch (iptables) enabled"
}

killswitch_iptables_disable() {
  command -v iptables >/dev/null 2>&1 || {
    log "iptables not installed"
    return 1
  }
  _run iptables -P OUTPUT ACCEPT
  _run iptables -D OUTPUT -j pvpnwg-out >/dev/null 2>&1 || true
  _run iptables -F pvpnwg-out >/dev/null 2>&1 || true
  log "Killswitch (iptables) disabled"
}

killswitch_status() {
  if command -v nft >/dev/null 2>&1 && nft list table inet pvpnwg >/dev/null 2>&1; then
    echo "nft:enabled"
  elif command -v iptables >/dev/null 2>&1; then
    if iptables -S OUTPUT 2>/dev/null | grep -q "^-P OUTPUT DROP" \
      && iptables -C OUTPUT -o "${IFACE}" -j ACCEPT >/dev/null 2>&1; then
      echo "iptables:enabled"
    else
      echo "iptables:disabled"
    fi
  else
    echo "none:disabled"
  fi
}

# ===========================
# Enhanced diagnostics
# ===========================
cmd_diag() {
  case "${1:-}" in
    wg)
      echo "=== WireGuard Diagnostics ==="
      echo "Interface: $IFACE"
      echo "State: $(wg_link_state)"
      local handshake_age
      handshake_age=$(wg_handshake_age 2>/dev/null || echo "never")
      echo "Handshake age: ${handshake_age}s (max: ${HANDSHAKE_MAX_AGE}s)"
      local endpoint
      endpoint=$(wg_endpoint_host)
      echo "Endpoint: ${endpoint:-none}"
      if [[ -n "$endpoint" ]]; then
        local rtt
        rtt=$(ping_rtt_ms "$endpoint")
        echo "Endpoint RTT: ${rtt}ms (threshold: ${LATENCY_THRESHOLD_MS}ms)"
      fi
      local reason
      if ! reason=$(wg_unhealthy_reason 2>/dev/null); then
        reason=${reason:-unknown}
      fi
      echo "Health: $reason"
      echo
      echo "Raw wg show:"
      wg show "$IFACE" 2>/dev/null || echo "Interface not found"
      ;;
    pf)
      pf_diag
      ;;
    dns)
      echo "=== DNS Diagnostics ==="
      echo "Backend: $dns_backend"
      echo "Current resolv.conf:"
      cat /etc/resolv.conf 2>/dev/null || echo "Not readable"
      echo
      if [[ "$DNS_HEALTH" == "true" ]]; then
        echo "DNS latency tests:"
        local ms resolver
        resolver=$(wg_conf_dns | awk '{print $1}' | head -1)
        ms=$(dns_latency_test "$resolver" "google.com" 2>/dev/null || echo "failed")
        echo "  Proton (${resolver:-unset}): ${ms}ms"
        ms=$(dns_latency_test "8.8.8.8" "google.com" 2>/dev/null || echo "failed")
        echo "  Google (8.8.8.8): ${ms}ms"
      fi
      echo
      echo "Leak test (via OpenDNS):"
      cmd_dns test 2>/dev/null || echo "Failed"
      ;;
    qb)
      echo "=== qBittorrent Diagnostics ==="
      local port
      port=$(qb_get_port 2>/dev/null || echo "unavailable")
      echo "Listen port: $port"
      echo "WebUI URL: $WEBUI_URL"
      if qb_login 2>/dev/null; then
        echo "WebUI auth: OK"
        local version
        version=$(curl -sS --fail --connect-timeout 10 -b "$COOKIE_JAR" "${WEBUI_URL%/}/api/v2/app/version" 2>/dev/null || echo "unknown")
        echo "Version: $version"
      else
        echo "WebUI auth: FAILED"
      fi
      if [[ -r "$QB_CONF_PATH" ]]; then
        echo "Config file: accessible"
        local conf_port
        conf_port=$(qb_conf_get_port || echo "not found")
        echo "Config port: $conf_port"
      else
        echo "Config file: not accessible"
      fi
      ;;
    all)
      cmd_diag wg
      echo
      cmd_diag pf
      echo
      cmd_diag dns
      echo
      cmd_diag qb
      ;;
    *)
      echo "Usage: $0 diag {wg|pf|dns|qb|all}"
      return 1
      ;;
  esac
}

# ===========================
# Commands
# ===========================
cmd_connect() {
  local mode="p2p" cc=""
  while [[ $# -gt 0 ]]; do case "$1" in -sc | --sc)
    mode="sc"
    shift
    ;;
  -pf | --pf)
    mode="pf"
    shift
    ;;
  -p2p | --p2p)
    mode="p2p"
    shift
    ;;
  -a | --any)
    mode="any"
    shift
    ;;
  --cc)
    cc="${2:-}"
    shift 2
    ;;
  *) break ;; esac done
  local pick conf rtt
  pick="$(select_conf "$mode" "$cc")"
  conf="${pick%%|*}"
  rtt="${pick##*|}"
  log "Selected $(basename "$conf") RTT=${rtt}ms"
  save_gw_state
  dns_backup
  wg_up "$conf"
  # Ensure qB prefs are opinionated (no UPnP, no random port); keep going if this fails.
  qb_set_port "$(qb_get_port || echo "$PF_STATIC_FALLBACK_PORT")" || true
  # Trigger PF once; long renew loop should be run via systemd service or user command
  pf_request_once || true
}

cmd_reconnect() {
  local args=("$@")
  wg_down
  cmd_connect "${args[@]}" || {
    log "Reconnect failed"
    return 1
  }
}
cmd_disconnect() {
  wg_down
  restore_gw_state
  dns_restore
}

cmd_status() {
  echo "=== WireGuard ==="
  wg show "$IFACE" || echo "IF $IFACE down"
  local handshake_age
  handshake_age=$(wg_handshake_age 2>/dev/null || echo "never")
  echo "Handshake age: ${handshake_age}s"
  echo
  echo "=== Ports ==="
  if [[ -s "$PORT_FILE" ]]; then
    local p
    p=$(cat "$PORT_FILE")
    echo "PF public (kept): $p"
    if qb_port=$(qb_get_port 2>/dev/null); then
      echo "qB listen_port: $qb_port"
      [[ "$qb_port" == "$p" ]] && echo "Port status: OK" || echo "Port status: MISMATCH"
    else echo "qB: not reachable"; fi
  else echo "No PF state yet"; fi
  echo
  echo "=== Policy ==="
  echo "Time limit: ${TIME_LIMIT_SECS}s | Idle: ${DL_THRESHOLD_KBPS} KB/s | LAN_IF=$LAN_IF"
  if [[ -s "$TIME_FILE" ]]; then
    local last
    last=$(cat "$TIME_FILE")
    echo "Last connect: $(date -d "@$last" '+%F %T') (elapsed $(($(date +%s) - last))s)"
  else echo "Last connect: unknown"; fi
  echo
  echo "=== Health ==="
  local wg_health
  if ! wg_health=$(wg_unhealthy_reason 2>/dev/null); then
    wg_health=${wg_health:-unknown}
  fi
  echo "WG health: $wg_health"
  local endpoint
  endpoint=$(wg_endpoint_host)
  if [[ -n "$endpoint" ]]; then
    local rtt
    rtt=$(ping_rtt_ms "$endpoint")
    echo "Endpoint RTT: ${rtt}ms (threshold: ${LATENCY_THRESHOLD_MS}ms)"
  fi
  echo
  echo "=== DNS/Killswitch ==="
  echo "DNS backend: $dns_backend"
  local ks ks_backend ks_state
  ks=$(killswitch_status)
  ks_backend=${ks%%:*}
  ks_state=${ks##*:}
  echo "Kill: ${ks_state} (${ks_backend})"
  echo
  echo "=== PF ==="
  echo "Gateway: $(pf_detect_gateway)"
  echo "Jitter count: $(cat "$PF_JITTER_FILE" 2>/dev/null || echo 0)"
  [[ -s "$PF_HISTORY" ]] && {
    echo "History (tail):"
    tail -n 5 "$PF_HISTORY"
  } || echo "No PF history"
}

cmd_check() {
  iface_load
  local reason
  if reason=$(should_reconnect); then
    log "Check reconnect ($reason)"
    cmd_reconnect -p2p || {
      log "WARN retry --any"
      cmd_reconnect -a || true
    }
  else log "Check: active download >= ${DL_THRESHOLD_KBPS} KB/s; skip"; fi
}

cmd_qb() {
  case "${1:-}" in
    port)
      shift
      [[ $# -lt 1 ]] && die "Usage: qb port PORT"
      [[ "$1" =~ ^[0-9]+$ ]] || die "PORT must be numeric"
      qb_set_port "$1"
      ;;
    fix-stalled)
      qb_fix_stalled
      ;;
    health)
      qb_health_check && echo "qB health: OK" || echo "qB health: FAILED"
      ;;
    *)
      echo "Usage: $0 qb {port PORT|fix-stalled|health}"
      return 1
      ;;
  esac
}

cmd_pf() {
  case "${1:-}" in
    start) pf_loop ;;
    once) pf_request_once ;;
    verify) pf_verify ;;
    diag) pf_diag ;;
    status)
      if [[ -s "$PORT_FILE" ]]; then
        echo "PF port (current/kept): $(cat "$PORT_FILE")"
      else
        echo "No PF state"
      fi
      echo "Gateway: $(pf_detect_gateway)"
      echo "Jitter: $(cat "$PF_JITTER_FILE" 2>/dev/null || echo 0)"
      ;;
    stop)
      echo "If systemd, stop pvpn-pf.service; if interactive, Ctrl+C"
      ;;
    *)
      echo "Usage: $0 pf {start|once|verify|diag|status|stop}"
      return 1
      ;;
  esac
}

# Command wrappers for CLI entry points
cmd_dns_wrapper() {
  shift || true
  cmd_dns "$@"
}

cmd_iface_scan() {
  iface_scan
}

cmd_rename_sc() {
  local _ng
  _ng=$(shopt -p nullglob)
  shopt -s nullglob
  for f in "${CONFIG_DIR}"/*.conf; do
    if grep -qi 'secure[- ]*core' "$f" && [[ "$f" != *SC.conf ]]; then
      local nf="${f%.conf}SC.conf"
      _run mv -f "$f" "$nf"
      log "Renamed $(basename "$f") -> $(basename "$nf")"
    fi
  done
  eval "$_ng"
}

cmd_rename_pf() {
  local _ng
  _ng=$(shopt -p nullglob)
  shopt -s nullglob
  for f in "${CONFIG_DIR}"/*.conf; do
    if grep -q '^# Moderate NAT = off$' "$f" \
      && grep -q '^# NAT-PMP (Port Forwarding) = on$' "$f" \
      && [[ "$f" != *PF.conf ]]; then
      local nf="${f%.conf}PF.conf"
      _run mv -f "$f" "$nf"
      log "Renamed $(basename "$f") -> $(basename "$nf")"
    fi
  done
  eval "$_ng"
}

cmd_killswitch() {
  case "${1:-}" in
    enable) killswitch_enable ;;
    disable) killswitch_disable ;;
    iptables-enable) killswitch_iptables_enable ;;
    iptables-disable) killswitch_iptables_disable ;;
    status) killswitch_status ;;
    *)
      echo "Usage: $0 killswitch {enable|disable|iptables-enable|iptables-disable|status}"
      return 1
      ;;
  esac
}

cmd_reset() {
  log "Reset: wg down + routes/DNS restore"
  wg_down
  restore_gw_state
  dns_restore
}

cmd_validate() {
  case "${1:-}" in
    conf)
      shift
      [[ $# -lt 1 ]] && die "Usage: validate conf FILE"
      local result
      result=$(conf_validate "$1" 2>&1 || echo "invalid")
      echo "$1: $result"
      [[ "$result" == "valid" ]]
      ;;
    configs)
      echo "Validating configs in $CONFIG_DIR:"
      printf "%-30s %s\n" "FILE" "STATUS"
      local total=0 valid=0
      local _ng
      _ng=$(shopt -p nullglob)
      shopt -s nullglob
      for f in "${CONFIG_DIR}"/*.conf; do
        local result
        result=$(conf_validate "$f" 2>&1 || echo "invalid")
        printf "%-30s %s\n" "$(basename "$f")" "$result"
        ((total++))
        [[ "$result" == "valid" ]] && ((valid++))
      done
      eval "$_ng"
      echo "Summary: $valid/$total valid"
      [[ $valid -eq $total ]]
      ;;
    *)
      echo "Usage: $0 validate {conf FILE|configs}"
      return 1
      ;;
  esac
}

cmd_init() {
  if [[ ${EUID} -eq 0 ]]; then
    install -d -m 700 -o "${RUN_UID}" -g "${RUN_GID}" "$PHOME" "$CONFIG_DIR"
    install -m 600 -o "${RUN_UID}" -g "${RUN_GID}" /dev/null "$CONF_FILE"
  else
    install -d -m 700 "$PHOME" "$CONFIG_DIR"
    install -m 600 /dev/null "$CONF_FILE"
  fi
  cat >"$CONF_FILE" <<EOF
# pvpnwg.conf — sourced by pvpnwg.sh
PHOME="$PHOME"
CONFIG_DIR="$CONFIG_DIR"
IFACE="$IFACE"
LAN_IF="$LAN_IF"
TIME_LIMIT_SECS=$TIME_LIMIT_SECS
DL_THRESHOLD_KBPS=$DL_THRESHOLD_KBPS
WEBUI_URL="$WEBUI_URL"
WEBUI_USER="$WEBUI_USER"
WEBUI_PASS="$WEBUI_PASS"
QB_CONF_PATH="$QB_CONF_PATH"
PF_RENEW_SECS=$PF_RENEW_SECS
PF_STATIC_FALLBACK_PORT=$PF_STATIC_FALLBACK_PORT
LOG_JSON=${LOG_JSON}
LATENCY_THRESHOLD_MS=$LATENCY_THRESHOLD_MS
LATENCY_FAILS=$LATENCY_FAILS
MONITOR_INTERVAL=$MONITOR_INTERVAL
HANDSHAKE_MAX_AGE=$HANDSHAKE_MAX_AGE
DNS_HEALTH=${DNS_HEALTH}
DNS_LAT_MS=$DNS_LAT_MS
QBIT_HEALTH=${QBIT_HEALTH}
EOF

  chmod 600 "$CONF_FILE"
  chown "${RUN_UID}:${RUN_GID}" "$CONF_FILE" 2>/dev/null || true
  log "Wrote $CONF_FILE"
  if [[ "${1:-}" == "--qb" || "${1:-}" == "--all" ]]; then
    qb_login || true
    qb_set_port "${PF_STATIC_FALLBACK_PORT}" || true
  fi
  echo "Init complete. Edit $CONF_FILE as needed."
}

cmd_monitor() { monitor_loop; }

usage() {
  cat <<EOF
Usage: $0 [global] <command> [options]

Global: -v|--verbose  --dry-run  --user=NAME --pf-proto=LIST --pf-require-both=false  [env LOG_JSON=true]

Commands:
  connect|c [--p2p|--sc|--pf|--any] [--cc CC]  Connect best server
  reconnect|r                                      Reconnect
  disconnect|d                                     Down + restore routes/DNS
  status|s                                         Enhanced status panel
  check|rr                                         Time/idle/WG health-check
  qb {port PORT|fix-stalled|health}                qB helpers + health check
  pf {start|once|verify|diag|status|stop}          PF control & diagnostics
  dns {backup|restore|dedupe|set|test|latency}     DNS helpers + latency test
  diag {wg|pf|dns|qb|all}                          Detailed diagnostics
  validate {conf FILE|configs}                     Config validation
  iface-scan                                       Pick LAN interface
  rename-sc                                        Tag Secure Core filenames
  rename-pf                                        Tag Port Forwarding filenames
  killswitch {enable|disable|iptables-enable|iptables-disable|status}
  reset                                            Hard reset
  init [--qb|--all]                                First-run config writer
  monitor                                          Enhanced monitor loop
EOF
}

parse_globals() {
  local args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -v | --verbose)
        VERBOSE=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --user=*)
        CLI_USER="${1#*=}"
        shift
        ;;
      --user)
        CLI_USER="$2"
        shift 2
        ;;
      --pf-proto=*)
        IFS=',' read -r -a PF_PROTO_LIST <<<"${1#*=}"
        shift
        ;;
      --pf-require-both=false)
        PF_REQUIRE_BOTH=false
        shift
        ;;
      --)
        shift
        break
        ;;
      *)
        args+=("$1")
        shift
        ;;
    esac
  done
  printf '%s\n' "${args[@]}"
}

main() {
  mapfile -t rest < <(parse_globals "$@")
  local cmd="${rest[0]:-}"
  rest=("${rest[@]:1}")
  if [[ "$cmd" != "init" ]]; then
    need_root
    check_deps
    iface_load
    detect_dns_backend
  fi
  case "$cmd" in
    connect | c) cmd_connect "${rest[@]:-}" ;;
    reconnect | r) cmd_reconnect "${rest[@]:-}" ;;
    disconnect | d) cmd_disconnect ;;
    status | s) cmd_status ;;
    check | rr) cmd_check ;;
    qb) cmd_qb "${rest[@]:-}" ;;
    pf) cmd_pf "${rest[@]:-}" ;;
    dns) cmd_dns "${rest[@]:-}" ;;
    diag) cmd_diag "${rest[@]:-}" ;;
    validate) cmd_validate "${rest[@]:-}" ;;
    iface-scan) cmd_iface_scan ;;
    rename-sc) cmd_rename_sc ;;
    rename-pf) cmd_rename_pf ;;
    killswitch) cmd_killswitch "${rest[@]:-}" ;;
    reset) cmd_reset ;;
    init) cmd_init "${rest[@]:-}" ;;
    monitor) cmd_monitor ;;
    help | -h | --help | "") usage ;;
    *)
      usage
      exit 1
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" && -z "${PVPNWG_NO_MAIN:-}" ]]; then
  main "$@"
fi
