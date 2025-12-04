#!/usr/bin/env bash
#
# Plex Proxy Pi automated setup
# Turns a fresh Raspberry Pi OS Lite into a WireGuard-connected Plex reverse proxy with Caddy.
# Run as root: sudo plexproxy-setup

set -euo pipefail

VERSION="2.0.0"
LOG_FILE="/var/log/plexproxy-setup.log"
CONFIG_DIR="/etc/plexproxy"
CONFIG_FILE="${CONFIG_DIR}/config.env"
WG_DIR="/etc/wireguard"
WG_IFACE="wg0"
WG_CONF="${WG_DIR}/${WG_IFACE}.conf"
WG_PRIVATE_KEY_FILE="${WG_DIR}/privatekey"
WG_PUBLIC_KEY_FILE="${WG_DIR}/publickey"
WPA_CONF="/etc/wpa_supplicant/wpa_supplicant.conf"
CADDYFILE="/etc/caddy/Caddyfile"
HEALTH_TIMER="plexproxy-health.timer"
HEALTH_SERVICE="plexproxy-health.service"
USE_WIFI="yes"

# Total number of setup steps for progress tracking
TOTAL_STEPS=12
CURRENT_STEP=0

mkdir -p "$(dirname "${LOG_FILE}")"
touch "${LOG_FILE}"
chmod 600 "${LOG_FILE}" || true
exec > >(tee -a "${LOG_FILE}") 2>&1

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Check if terminal supports colors
if [[ -t 1 ]] && [[ -n "${TERM:-}" ]] && command -v tput &>/dev/null; then
  COLORS_SUPPORTED=true
else
  COLORS_SUPPORTED=false
  RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE='' BOLD='' DIM='' NC=''
fi

trap 'echo -e "${RED}[!] Error on line ${LINENO}. Check the log: ${LOG_FILE}${NC}"' ERR

# Output functions with colors
say() { echo -e "$*"; }
info() { echo -e "${BLUE}ℹ${NC} $*"; }
success() { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC} $*"; }
error() { echo -e "${RED}✗${NC} $*"; }
header() { echo -e "\n${BOLD}${CYAN}$*${NC}"; }
dim() { echo -e "${DIM}$*${NC}"; }

# Progress indicator
step() {
  (( ++CURRENT_STEP ))
  local pct=$((CURRENT_STEP * 100 / TOTAL_STEPS))
  local bar_width=30
  local filled=$((pct * bar_width / 100))
  local empty=$((bar_width - filled))
  local bar="${GREEN}"
  for ((i=0; i<filled; i++)); do bar+="█"; done
  bar+="${DIM}"
  for ((i=0; i<empty; i++)); do bar+="░"; done
  bar+="${NC}"
  
  echo ""
  echo -e "${BOLD}[${CURRENT_STEP}/${TOTAL_STEPS}]${NC} ${WHITE}$*${NC}"
  echo -e "  ${bar} ${pct}%"
  echo ""
}

# Spinner for long-running operations
spinner() {
  local pid=$1
  local msg="${2:-Working...}"
  local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${CYAN}${spin:i++%${#spin}:1}${NC} ${msg}"
    sleep 0.1
  done
  printf "\r"
}

# Print ASCII banner
print_banner() {
  echo -e "${CYAN}"
  cat << 'BANNER'
  ____  _           ____                        ____  _ 
 |  _ \| | _____  _|  _ \ _ __ _____  ___   _  |  _ \(_)
 | |_) | |/ _ \ \/ / |_) | '__/ _ \ \/ / | | | | |_) | |
 |  __/| |  __/>  <|  __/| | | (_) >  <| |_| | |  __/| |
 |_|   |_|\___/_/\_\_|   |_|  \___/_/\_\\__, | |_|   |_|
                                        |___/           
BANNER
  echo -e "${NC}"
  echo -e "${DIM}  Automated Plex Reverse Proxy Gateway${NC}"
  echo -e "${DIM}  Version ${VERSION}${NC}"
  echo ""
}

# Print a nice box around text
print_box() {
  local text="$1"
  local width=$((${#text} + 4))
  local border=""
  for ((i=0; i<width; i++)); do border+="─"; done
  
  echo -e "${CYAN}┌${border}┐${NC}"
  echo -e "${CYAN}│${NC}  ${text}  ${CYAN}│${NC}"
  echo -e "${CYAN}└${border}┘${NC}"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    say "This script must be run as root."
    exit 1
  fi
}

check_os() {
  if [[ ! -f /etc/os-release ]]; then
    say "/etc/os-release not found. Unsupported OS."
    exit 1
  fi
  if ! grep -qiE 'raspbian|debian' /etc/os-release; then
    say "This script is intended for Raspberry Pi OS / Debian."
    exit 1
  fi
}

timestamp() { date +"%Y%m%d-%H%M%S"; }

backup_file() {
  local file="$1"
  if [[ -f "${file}" ]]; then
    local backup="${file}.bak.$(timestamp)"
    cp "${file}" "${backup}"
    say "Backup created: ${backup}"
  fi
}

read_default() {
  local prompt="$1" default="$2" var
  read -r -p "${prompt} [${default}]: " var
  echo "${var:-$default}"
}

read_secret() {
  local prompt="$1" var
  read -r -s -p "${prompt}: " var
  say ""
  echo "${var}"
}

confirm() {
  local prompt="${1:-Proceed?}"
  read -r -p "${prompt} [y/N]: " reply
  [[ "${reply}" =~ ^[Yy]$ ]]
}

valid_ipv4() {
  local ip="$1" IFS='.' octets
  read -r -a octets <<< "${ip}"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for o in "${octets[@]}"; do
    [[ "${o}" =~ ^[0-9]+$ ]] || return 1
    (( o >= 0 && o <= 255 )) || return 1
  done
}

valid_hostport() {
  local value="$1" host port
  if [[ "${value}" =~ ^\[(.+)\]:([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  else
    [[ "${value}" =~ ^([^:]+):([0-9]+)$ ]] || return 1
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  fi
  (( port >= 1 && port <= 65535 )) || return 1
  [[ -n "${host}" ]]
}

valid_public_key() {
  local key="$1"
  [[ ${#key} -ge 43 && ${#key} -le 44 && "${key}" =~ ^[A-Za-z0-9+/=]+$ ]]
}

detect_lan_ip() {
  local ip
  ip=$(ip -4 addr show eth0 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
  if [[ -z "${ip}" ]]; then
    ip=$(ip -4 addr show wlan0 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
  fi
  if [[ -z "${ip}" ]]; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  echo "${ip}"
}

wifi_available() {
  ip link show wlan0 >/dev/null 2>&1
}

validate_config_values() {
  local errors=()

  if [[ -z "${WG_ENDPOINT}" ]]; then
    errors+=("WireGuard endpoint needs the form host:port (IPv6 supported with [addr]:port).")
  elif ! valid_hostport "${WG_ENDPOINT}"; then
    errors+=("WireGuard endpoint needs the form host:port (IPv6 supported with [addr]:port).")
  fi

  if [[ -z "${SERVER_PUBLIC_KEY}" ]]; then
    errors+=("WireGuard server public key does not look valid.")
  elif ! valid_public_key "${SERVER_PUBLIC_KEY}"; then
    errors+=("WireGuard server public key does not look valid.")
  fi

  if [[ -z "${WG_SERVER_WG_IP}" ]]; then
    errors+=("WireGuard server tunnel IP must be an IPv4 address.")
  elif ! valid_ipv4 "${WG_SERVER_WG_IP}"; then
    errors+=("WireGuard server tunnel IP must be an IPv4 address.")
  fi

  if [[ -z "${PI_WG_IP}" ]]; then
    errors+=("Pi WireGuard IP must be an IPv4 address.")
  elif ! valid_ipv4 "${PI_WG_IP}"; then
    errors+=("Pi WireGuard IP must be an IPv4 address.")
  fi

  if [[ "${WG_SERVER_WG_IP}" == "${PI_WG_IP}" ]]; then
    errors+=("Pi WireGuard IP must differ from the server tunnel IP.")
  fi

  if [[ -z "${PLEX_IP}" ]]; then
    errors+=("Plex server IP must be an IPv4 address.")
  elif ! valid_ipv4 "${PLEX_IP}"; then
    errors+=("Plex server IP must be an IPv4 address.")
  fi

  if [[ -n "${FILES_IP}" ]]; then
    if ! valid_ipv4 "${FILES_IP}"; then
      errors+=("File/NAS IP must be empty or an IPv4 address.")
    fi
  fi

  if (( ${#errors[@]} )); then
    say ""
    say "Please fix the following before continuing:"
    for err in "${errors[@]}"; do
      say " - ${err}"
    done
    say ""
    return 1
  fi
  return 0
}

wait_for_lan_ip() {
  local attempts="${1:-10}" delay="${2:-3}" ip=""
  for ((i=1; i<=attempts; i++)); do
    ip=$(detect_lan_ip)
    if [[ -n "${ip}" ]]; then
      echo "${ip}"
      return 0
    fi
    sleep "${delay}"
  done
  echo ""
  return 1
}

load_existing_config() {
  if [[ -f "${CONFIG_FILE}" ]]; then
    say "Existing config found at ${CONFIG_FILE}"
    if confirm "Load existing values as defaults?"; then
      # shellcheck disable=SC1090
      source "${CONFIG_FILE}"
    fi
  fi
}

maybe_import_wg_conf() {
  if ! confirm "Optional: paste an existing wg0.conf to pre-fill values?"; then
    return
  fi

  say "Paste your wg0.conf content now. End input with a single line containing END:"
  local tmp="/tmp/wg0.import.$(timestamp)"
  : > "${tmp}"
  while IFS= read -r line; do
    [[ "${line}" == "END" ]] && break
    echo "${line}" >> "${tmp}"
  done

  if ! grep -qE "^\[Interface\]" "${tmp}"; then
    say "Did not detect a valid WireGuard config. Ignoring pasted content."
    rm -f "${tmp}"
    return
  fi

  IMPORTED_WG_CONF="${tmp}"
  say "Imported WireGuard config captured at ${IMPORTED_WG_CONF}"
  parse_imported_wg_conf "${tmp}"
}

extract_wg_value() {
  local key="$1" file="$2" strip_all="${3:-false}" line value
  line=$(grep -m1 -E "^${key}[[:space:]]*=" "${file}" || true)
  [[ -z "${line}" ]] && return
  value=$(printf '%s\n' "${line}" | sed -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//; s/[[:space:]]+$//")
  value="${value//$'\r'/}"
  if [[ "${strip_all}" == "true" ]]; then
    value="${value//[[:space:]]/}"
  fi
  echo "${value}"
}

parse_imported_wg_conf() {
  local file="$1"
  local addr endpoint pubkey privkey allowed
  addr=$(extract_wg_value "Address" "${file}" "true")
  endpoint=$(extract_wg_value "Endpoint" "${file}" "true")
  pubkey=$(extract_wg_value "PublicKey" "${file}" "true")
  privkey=$(extract_wg_value "PrivateKey" "${file}" "true")
  allowed=$(extract_wg_value "AllowedIPs" "${file}" "true")

  [[ -n "${addr:-}" ]] && PI_WG_IP="${addr%/*}"
  [[ -n "${endpoint:-}" ]] && WG_ENDPOINT="${endpoint}"
  [[ -n "${pubkey:-}" ]] && SERVER_PUBLIC_KEY="${pubkey}"
  [[ -n "${allowed:-}" ]] && WG_ALLOWED_IPS="${allowed// /}"
  if [[ -n "${privkey:-}" ]]; then
    IMPORTED_PRIVATE_KEY="${privkey}"
  fi
}

collect_config() {
  say ""
  say "=== Collecting configuration ==="
  load_existing_config
  maybe_import_wg_conf

  COUNTRY_CODE="${COUNTRY_CODE:-DE}"
  WIFI_SSID="${WIFI_SSID:-}"
  WIFI_PSK="${WIFI_PSK:-}"

  while true; do
    WG_ENDPOINT="${WG_ENDPOINT:-}"
    SERVER_PUBLIC_KEY="${SERVER_PUBLIC_KEY:-}"
    WG_SERVER_WG_IP="${WG_SERVER_WG_IP:-}"
    PI_WG_IP="${PI_WG_IP:-192.168.200.6}"
    PLEX_IP="${PLEX_IP:-}"
    FILES_IP="${FILES_IP:-}"
    USE_WIFI="${USE_WIFI:-yes}"

    local wifi_detected="no"
    if wifi_available; then
      wifi_detected="yes"
    fi

    if [[ "${wifi_detected}" == "yes" ]]; then
      USE_WIFI=$(read_default "Use Wi-Fi for connectivity? (yes/no)" "${USE_WIFI}")
      if [[ "${USE_WIFI}" =~ ^([Nn]|no)$ ]]; then
        USE_WIFI="no"
      else
        USE_WIFI="yes"
      fi
    else
      say "Wi-Fi interface wlan0 not detected; using wired mode."
      USE_WIFI="no"
    fi

    if [[ "${USE_WIFI}" == "yes" ]]; then
      COUNTRY_CODE=$(read_default "Country code" "${COUNTRY_CODE}")
      WIFI_SSID=$(read_default "Wi-Fi SSID" "${WIFI_SSID:-""}")
      while [[ -z "${WIFI_SSID}" ]]; do
        WIFI_SSID=$(read_default "Wi-Fi SSID (required)" "")
      done
      WIFI_PSK_INPUT=$(read_secret "Wi-Fi password (input hidden)")
      WIFI_PSK="${WIFI_PSK_INPUT:-${WIFI_PSK}}"
      while [[ -z "${WIFI_PSK}" ]]; do
        WIFI_PSK=$(read_secret "Wi-Fi password is required, re-enter")
      done
    fi

    WG_ENDPOINT=$(read_default "WireGuard server endpoint (host:port)" "${WG_ENDPOINT}")
    SERVER_PUBLIC_KEY=$(read_default "WireGuard server public key" "${SERVER_PUBLIC_KEY}")
    WG_SERVER_WG_IP=$(read_default "WireGuard server tunnel IP" "${WG_SERVER_WG_IP:-192.168.200.1}")
    PI_WG_IP=$(read_default "Desired WireGuard IP for this Pi" "${PI_WG_IP}")
    PLEX_IP=$(read_default "Plex server IP in home LAN" "${PLEX_IP:-192.168.10.102}")
    FILES_IP=$(read_default "File server/NAS IP (optional, leave blank if none)" "${FILES_IP:-}")

    WG_ALLOWED_IPS="${WG_SERVER_WG_IP}/32"
    [[ -n "${FILES_IP}" ]] && WG_ALLOWED_IPS+=",${FILES_IP}/32"
    [[ -n "${PLEX_IP}" ]] && WG_ALLOWED_IPS+=",${PLEX_IP}/32"
    WG_ALLOWED_IPS="${WG_ALLOWED_IPS//[[:space:]]/}"

    say ""
    say "Configuration summary:"
    cat <<EOF
Country:            ${COUNTRY_CODE}
Wi-Fi SSID:         ${WIFI_SSID}
WireGuard endpoint: ${WG_ENDPOINT}
WG server pubkey:   ${SERVER_PUBLIC_KEY}
WG server IP:       ${WG_SERVER_WG_IP}
Pi WG IP:           ${PI_WG_IP}
Allowed IPs:        ${WG_ALLOWED_IPS}
Plex server IP:     ${PLEX_IP}
File/NAS IP:        ${FILES_IP:-<none>}
Use Wi-Fi:          ${USE_WIFI}
EOF

    if ! validate_config_values; then
      continue
    fi

    if confirm "Proceed with these settings?"; then
      break
    else
      say "Aborted by user."
      exit 1
    fi
  done
}

write_config_file() {
  mkdir -p "${CONFIG_DIR}"
  cat > "${CONFIG_FILE}" <<EOF
# Generated by plexproxy-setup v${VERSION} on $(date)
COUNTRY_CODE="${COUNTRY_CODE}"
WIFI_SSID="${WIFI_SSID}"
WIFI_PSK="${WIFI_PSK}"
WG_ENDPOINT="${WG_ENDPOINT}"
SERVER_PUBLIC_KEY="${SERVER_PUBLIC_KEY}"
WG_SERVER_WG_IP="${WG_SERVER_WG_IP}"
PI_WG_IP="${PI_WG_IP}"
PLEX_IP="${PLEX_IP}"
FILES_IP="${FILES_IP}"
WG_ALLOWED_IPS="${WG_ALLOWED_IPS}"
USE_WIFI="${USE_WIFI}"
EOF
  chmod 600 "${CONFIG_FILE}"
  say "Saved config to ${CONFIG_FILE}"
}

configure_wifi() {
  if [[ "${USE_WIFI}" != "yes" ]]; then
    say "Skipping Wi-Fi configuration (wired mode selected)."
    PI_LAN_IP=$(detect_lan_ip)
    return
  fi

  say ""
  say "=== Configuring Wi-Fi ==="
  backup_file "${WPA_CONF}"
  local hashed_psk=""
  if command -v wpa_passphrase >/dev/null 2>&1; then
    hashed_psk=$(wpa_passphrase "${WIFI_SSID}" "${WIFI_PSK}" | awk -F= '/^\s*psk=/{print $2}' | tail -1)
  fi
  cat > "${WPA_CONF}" <<EOF
country=${COUNTRY_CODE}
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="${WIFI_SSID}"
    psk=${hashed_psk:-"${WIFI_PSK}"}
}
EOF
  chmod 600 "${WPA_CONF}"
  if command -v wpa_cli >/dev/null 2>&1; then
    wpa_cli -i wlan0 reconfigure || true
  else
    systemctl restart wpa_supplicant || true
  fi
  PI_LAN_IP=$(wait_for_lan_ip 10 3)
  if [[ -n "${PI_LAN_IP}" ]]; then
    say "Detected Pi LAN IP: ${PI_LAN_IP}"
  else
    say "WARNING: Could not detect a LAN IP after configuring Wi-Fi."
  fi
}

update_system() {
  say ""
  say "=== Updating system packages ==="
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade
}

install_packages() {
  say ""
  say "=== Installing dependencies ==="
  DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard caddy curl jq watchdog avahi-daemon python3
}

ensure_wireguard_keys() {
  mkdir -p "${WG_DIR}"
  chmod 700 "${WG_DIR}"
  local regenerate=false
  local private_key_changed=false

  if [[ -n "${IMPORTED_PRIVATE_KEY:-}" ]]; then
    say "Using private key from imported wg0.conf"
    echo "${IMPORTED_PRIVATE_KEY}" > "${WG_PRIVATE_KEY_FILE}"
    chmod 600 "${WG_PRIVATE_KEY_FILE}"
    private_key_changed=true
  fi

  if [[ -f "${WG_PRIVATE_KEY_FILE}" ]]; then
    say "Private key exists at ${WG_PRIVATE_KEY_FILE}"
    if confirm "Regenerate WireGuard keypair?"; then
      regenerate=true
    fi
  else
    regenerate=true
  fi

  if [[ "${regenerate}" == true ]]; then
    umask 077
    wg genkey > "${WG_PRIVATE_KEY_FILE}"
    umask 022
    private_key_changed=true
  fi

  if [[ "${private_key_changed}" == true || ! -f "${WG_PUBLIC_KEY_FILE}" ]]; then
    wg pubkey < "${WG_PRIVATE_KEY_FILE}" > "${WG_PUBLIC_KEY_FILE}"
  fi

  chmod 600 "${WG_PRIVATE_KEY_FILE}"
  chmod 644 "${WG_PUBLIC_KEY_FILE}"
  PI_PUBLIC_KEY=$(cat "${WG_PUBLIC_KEY_FILE}")
  say "Pi WireGuard public key: ${PI_PUBLIC_KEY}"
}

write_wg_conf() {
  say ""
  say "=== Writing WireGuard configuration ==="
  backup_file "${WG_CONF}"
  
  # Create a warmup script that runs after WireGuard comes up
  # This ensures the tunnel is immediately "warm" after boot/restart
  local warmup_script="/usr/local/bin/plexproxy-wg-warmup"
  cat > "${warmup_script}" <<'WARMUP'
#!/usr/bin/env bash
# WireGuard warmup script - runs after wg0 comes up to ensure tunnel is immediately active
# This prevents the need to manually run curl to "wake up" the tunnel

sleep 2  # Brief delay to ensure interface is fully ready

CONFIG_FILE="/etc/plexproxy/config.env"
WG_IFACE="wg0"

if [[ -f "${CONFIG_FILE}" ]]; then
  source "${CONFIG_FILE}"
  
  # Ping the WireGuard server to initiate handshake
  if [[ -n "${WG_SERVER_WG_IP:-}" ]]; then
    ping -I "${WG_IFACE}" -c 3 -W 2 "${WG_SERVER_WG_IP}" >/dev/null 2>&1 || true
  fi
  
  # Make HTTP request to Plex to warm up the full path
  if [[ -n "${PLEX_IP:-}" ]]; then
    curl -fsS --interface "${WG_IFACE}" --max-time 10 --connect-timeout 5 \
         -o /dev/null "http://${PLEX_IP}:32400/identity" 2>/dev/null || true
  fi
fi
WARMUP
  chmod 755 "${warmup_script}"
  
  cat > "${WG_CONF}" <<EOF
[Interface]
Address = ${PI_WG_IP}/32
PrivateKey = $(cat "${WG_PRIVATE_KEY_FILE}")
MTU = 1420
# Warmup script ensures tunnel is immediately active after start
PostUp = ${warmup_script} &

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${WG_ENDPOINT}
AllowedIPs = ${WG_ALLOWED_IPS}
PersistentKeepalive = 15
EOF
  chmod 600 "${WG_CONF}"
  say "WireGuard config written with automatic warmup on start"
}

print_server_snippet() {
  cat <<EOF
Add the following peer to your home WireGuard server configuration:

[Peer]
# Raspberry Pi at friend's home
PublicKey = ${PI_PUBLIC_KEY}
AllowedIPs = ${PI_WG_IP}/32

After updating the server config and restarting wg on the server, press Enter to continue.
EOF
  read -r -p ""
}

bring_up_wireguard() {
  say ""
  say "=== Bringing up WireGuard (${WG_IFACE}) ==="
  systemctl enable "wg-quick@${WG_IFACE}"
  wg-quick down "${WG_IFACE}" 2>/dev/null || true
  if ! wg-quick up "${WG_IFACE}"; then
    say "Failed to start WireGuard. Check ${WG_CONF} and server configuration."
    exit 1
  fi
  wg show "${WG_IFACE}"
}

test_connectivity() {
  say ""
  say "=== Testing connectivity through WireGuard ==="
  local fail=0
  if [[ -n "${PLEX_IP}" ]]; then
    if ping -I "${WG_IFACE}" -c 3 -W 2 "${PLEX_IP}"; then
      say "Plex server reachable (${PLEX_IP})"
    else
      say "WARNING: Plex server not reachable at ${PLEX_IP}"
      fail=1
    fi
  fi
  if [[ -n "${FILES_IP}" ]]; then
    if ping -I "${WG_IFACE}" -c 3 -W 2 "${FILES_IP}"; then
      say "File server reachable (${FILES_IP})"
    else
      say "WARNING: File server not reachable at ${FILES_IP}"
      fail=1
    fi
  fi
  if [[ "${fail}" -ne 0 ]]; then
    say "Connectivity checks failed. Ensure the server has the Pi peer configured and try again."
  fi
}

configure_caddy() {
  say ""
  say "=== Configuring Caddy reverse proxy ==="
  backup_file "${CADDYFILE}"
  mkdir -p /var/log/caddy
  chown caddy:caddy /var/log/caddy || true
  cat > "${CADDYFILE}" <<EOF
:32400 {
  reverse_proxy ${PLEX_IP}:32400 {
    flush_interval 250ms
    
    # Active health checking (compatible with Caddy 2.6.x)
    health_uri /identity
    health_interval 15s
    health_timeout 5s
    
    # Passive health checking
    fail_duration 30s
    max_fails 3
    unhealthy_status 502 503 504
  }

  log {
    output file /var/log/caddy/plexproxy-access.log {
      roll_size 10MiB
      roll_keep 5
    }
  }
}
EOF
  systemctl enable caddy
  systemctl restart caddy
  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:32400 || true)
  if [[ "${http_code}" != "000" && -n "${http_code}" ]]; then
    say "Caddy reverse proxy responded on localhost:32400 (HTTP ${http_code}; Plex often returns 401 without a token)"
  else
    say "WARNING: Caddy reverse proxy test failed to connect. Verify Plex is reachable through the tunnel."
  fi
}

apply_sysctl_tuning() {
  say ""
  say "=== Optional: apply safe network sysctl tuning ==="
  if ! confirm "Apply Plex Proxy Pi sysctl tuning now? (enables BBR, larger TCP buffers)"; then
    say "Skipping sysctl tuning."
    return
  fi

  if command -v plexproxy-sysctl-apply >/dev/null 2>&1; then
    plexproxy-sysctl-apply
    return
  fi

  # Fallback inline template if helper is unavailable
  cat > /etc/sysctl.d/90-plexproxy-tuning.conf <<'EOF'
# Safe network tuning for Plex Proxy Pi
# These values favor stable streaming over absolute throughput.
net.core.rmem_max = 2621440
net.core.wmem_max = 2621440
net.ipv4.tcp_rmem = 4096 87380 2097152
net.ipv4.tcp_wmem = 4096 65536 2097152
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_congestion_control = bbr
EOF
  sysctl --system >/dev/null
  sysctl net.ipv4.tcp_congestion_control
}

configure_watchdog() {
  say ""
  say "=== Configuring hardware watchdog ==="

  # Only monitor the active uplink to avoid reboots when an unused interface (e.g., eth0 without a cable)
  # stays down. Wi-Fi deployments watch wlan0; wired deployments watch eth0.
  local watchdog_interface="eth0"
  local watchdog_timeout=120   # seconds before hardware reboot (keeps this lenient: >1 minute)
  local watchdog_interval=15   # seconds between checks/kicks
  if [[ "${USE_WIFI}" == "yes" ]] && wifi_available; then
    watchdog_interface="wlan0"
  fi

  # Ensure driver loads on boot (Pi hardware watchdog)
  install -m 0644 -D /dev/null /etc/modules-load.d/plexproxy-watchdog.conf
  if ! grep -q "^bcm2835_wdt" /etc/modules-load.d/plexproxy-watchdog.conf; then
    echo "bcm2835_wdt" >> /etc/modules-load.d/plexproxy-watchdog.conf
  fi

  modprobe bcm2835_wdt || true

  local watchdog_conf="/etc/watchdog.conf"
  backup_file "${watchdog_conf}"
  cat > "${watchdog_conf}" <<EOF
# Plex Proxy Pi watchdog configuration
watchdog-device = /dev/watchdog
watchdog-timeout = ${watchdog_timeout}
interval = ${watchdog_interval}
max-load-1 = 24
# Network reachability tests (any success is enough)
ping = 1.1.1.1
ping = 8.8.8.8
# Interface check; monitor the primary uplink only
interface = ${watchdog_interface}
EOF

  systemctl enable --now watchdog
  say "Hardware watchdog enabled (auto-reboot if system hangs or loses network for prolonged period)."
}

enable_health_timer() {
  say ""
  say "=== Enabling health check, keepalive, and discovery services ==="
  systemctl daemon-reload
  
  # Enable the main health check timer (runs every minute)
  if systemctl list-unit-files | grep -q "^${HEALTH_TIMER}"; then
    systemctl enable --now "${HEALTH_TIMER}"
    say "Health check enabled (runs every minute)"
  else
    say "Health timer unit not found. Ensure install.sh has been run."
  fi
  
  # Enable the keepalive timer (runs every 15 seconds to keep tunnel warm)
  local keepalive_timer="plexproxy-keepalive.timer"
  if systemctl list-unit-files | grep -q "^${keepalive_timer}"; then
    systemctl enable --now "${keepalive_timer}"
    say "Keepalive timer enabled (runs every 15 seconds to prevent tunnel timeouts)"
  else
    say "Keepalive timer unit not found. Ensure install.sh has been run."
  fi
  
  # Enable the GDM Discovery Relay (allows Plex clients to auto-discover the proxy)
  local gdm_relay_service="plexproxy-gdm-relay.service"
  if systemctl list-unit-files | grep -q "^${gdm_relay_service}"; then
    systemctl enable --now "${gdm_relay_service}"
    say "GDM Discovery Relay enabled (Plex clients can now auto-discover the proxy)"
  else
    say "GDM Relay service not found. Ensure install.sh has been run."
  fi
  
  # Configure Avahi/mDNS for additional discovery
  configure_avahi_discovery
}

configure_avahi_discovery() {
  say ""
  say "=== Configuring Avahi/mDNS discovery ==="
  
  # Install Avahi service file for Plex discovery
  local avahi_services_dir="/etc/avahi/services"
  local avahi_service_file="${avahi_services_dir}/plexproxy.service"
  local avahi_template="${CONFIG_DIR}/plexproxy-avahi.service"
  
  mkdir -p "${avahi_services_dir}"
  
  if [[ -f "${avahi_template}" ]]; then
    cp "${avahi_template}" "${avahi_service_file}"
    say "Avahi service file installed to ${avahi_service_file}"
  else
    # Create inline if template not available
    cat > "${avahi_service_file}" <<'AVAHI'
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">Plex Media Server on %h</name>
  <service>
    <type>_plex._tcp</type>
    <port>32400</port>
    <txt-record>PlexProxy=true</txt-record>
  </service>
</service-group>
AVAHI
    say "Avahi service file created at ${avahi_service_file}"
  fi
  
  # Enable and restart Avahi
  systemctl enable avahi-daemon
  systemctl restart avahi-daemon
  say "Avahi daemon enabled for mDNS/Bonjour discovery"
}

final_summary() {
  if [[ -z "${PI_LAN_IP:-}" ]]; then
    PI_LAN_IP=$(detect_lan_ip)
  fi
  
  echo ""
  echo -e "${GREEN}"
  cat << 'SUCCESS'
   _____ _    _  _____ _____ ______  _____ _____ _ 
  / ____| |  | |/ ____/ ____|  ____|/ ____/ ____| |
 | (___ | |  | | |   | |    | |__  | (___| (___ | |
  \___ \| |  | | |   | |    |  __|  \___ \\___ \| |
  ____) | |__| | |___| |____| |____ ____) |___) |_|
 |_____/ \____/ \_____\_____|______|_____/_____/(_)
SUCCESS
  echo -e "${NC}"
  
  echo ""
  print_box "Setup Complete!"
  echo ""
  
  # Status summary
  header "📊 Configuration Summary"
  echo ""
  echo -e "  ${CYAN}Network${NC}"
  echo -e "    LAN IP:        ${GREEN}${PI_LAN_IP:-unknown}${NC}"
  echo -e "    WireGuard IP:  ${GREEN}${PI_WG_IP}${NC}"
  echo ""
  echo -e "  ${CYAN}Plex${NC}"
  echo -e "    Target Server: ${GREEN}${PLEX_IP}:32400${NC}"
  echo -e "    Proxy URL:     ${GREEN}http://${PI_LAN_IP:-<pi-ip>}:32400${NC}"
  echo ""
  
  # Services status
  header "🔧 Active Services"
  echo ""
  echo -e "  ${GREEN}✓${NC} WireGuard VPN Tunnel"
  echo -e "  ${GREEN}✓${NC} Caddy Reverse Proxy"
  echo -e "  ${GREEN}✓${NC} Health Check (every 60s)"
  echo -e "  ${GREEN}✓${NC} Keepalive (every 15s)"
  echo -e "  ${GREEN}✓${NC} GDM Discovery Relay"
  echo -e "  ${GREEN}✓${NC} Avahi/mDNS Discovery"
  echo -e "  ${GREEN}✓${NC} Hardware Watchdog"
  echo ""
  
  # Client instructions
  header "📱 Connect Your Devices"
  echo ""
  echo -e "  ${BOLD}Automatic Discovery:${NC}"
  echo -e "    Plex clients should automatically find the server."
  echo -e "    Just open the Plex app and look for '${CYAN}Plex Media Server on $(hostname)${NC}'"
  echo ""
  echo -e "  ${BOLD}Manual Connection (if needed):${NC}"
  echo -e "    URL: ${CYAN}http://${PI_LAN_IP:-<pi-ip>}:32400${NC}"
  echo ""
  
  # Server config reminder
  header "🔑 WireGuard Server Configuration"
  echo ""
  echo -e "  ${YELLOW}Add this peer to your home WireGuard server:${NC}"
  echo ""
  echo -e "  ${DIM}[Peer]${NC}"
  echo -e "  ${DIM}# Raspberry Pi Plex Proxy${NC}"
  echo -e "  ${DIM}PublicKey = ${NC}${GREEN}${PI_PUBLIC_KEY}${NC}"
  echo -e "  ${DIM}AllowedIPs = ${PI_WG_IP}/32${NC}"
  echo ""
  
  # Architecture diagram
  header "🌐 Network Architecture"
  echo ""
  echo -e "${CYAN}"
  cat << 'DIAGRAM'
  ┌─────────────┐     Wi-Fi      ┌──────────────┐    WireGuard    ┌─────────────┐
  │  Apple TV   │ ──────────────▶│ Raspberry Pi │ ───────────────▶│ Home Server │
  │  iOS/PC     │   LAN :32400   │   (Proxy)    │    UDP Tunnel   │   (Plex)    │
  └─────────────┘                └──────────────┘                 └─────────────┘
                                       │
                                       │ Auto-Discovery
                                       │ Keepalive
                                       │ Health Checks
                                       ▼
                                 Always Connected
DIAGRAM
  echo -e "${NC}"
  
  # Log file info
  echo ""
  dim "Log file: ${LOG_FILE}"
  echo ""
  
  # Final message
  echo -e "${GREEN}${BOLD}🎉 Your Plex Proxy Pi is ready!${NC}"
  echo ""
}

main() {
  clear
  print_banner
  require_root
  check_os
  
  step "Collecting Configuration"
  collect_config
  write_config_file
  
  step "Updating System Packages"
  update_system
  
  step "Installing Dependencies"
  install_packages
  
  step "Configuring Network"
  configure_wifi
  
  step "Setting Up WireGuard Keys"
  ensure_wireguard_keys
  
  step "Writing WireGuard Configuration"
  write_wg_conf
  print_server_snippet
  
  step "Starting WireGuard Tunnel"
  bring_up_wireguard
  
  step "Testing Connectivity"
  test_connectivity
  
  step "Configuring Caddy Reverse Proxy"
  configure_caddy
  
  step "Applying Network Tuning"
  apply_sysctl_tuning
  
  step "Enabling Background Services"
  enable_health_timer
  
  step "Configuring Hardware Watchdog"
  configure_watchdog
  
  final_summary
}

main "$@"
