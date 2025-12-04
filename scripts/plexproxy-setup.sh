#!/usr/bin/env bash
#
# Plex Proxy Pi automated setup
# Turns a fresh Raspberry Pi OS Lite into a WireGuard-connected Plex reverse proxy with Caddy.
# Run as root: sudo plexproxy-setup

set -euo pipefail

VERSION="1.0.0"
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

mkdir -p "$(dirname "${LOG_FILE}")"
touch "${LOG_FILE}"
chmod 600 "${LOG_FILE}" || true
exec > >(tee -a "${LOG_FILE}") 2>&1

trap 'echo "[!] Error on line ${LINENO}. Check the log: ${LOG_FILE}"' ERR

say() { echo -e "$*"; }

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
  DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard caddy curl jq watchdog
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
  cat > "${WG_CONF}" <<EOF
[Interface]
Address = ${PI_WG_IP}/32
PrivateKey = $(cat "${WG_PRIVATE_KEY_FILE}")
MTU = 1420

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${WG_ENDPOINT}
AllowedIPs = ${WG_ALLOWED_IPS}
PersistentKeepalive = 25
EOF
  chmod 600 "${WG_CONF}"
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
    # Keep the upstream warm and fail fast if Plex is not reachable
    health_checks {
      active {
        path /identity
        interval 30s
        timeout 5s
      }
      passive {
        unhealthy_status 502 503 504
        max_fails 2
        fail_duration 1m
      }
    }
    transport http {
      keepalive 30s
      keepalive_idle_conns 10
      keepalive_timeout 60s
    }
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
  say "=== Enabling health check timer ==="
  systemctl daemon-reload
  if systemctl list-unit-files | grep -q "^${HEALTH_TIMER}"; then
    systemctl enable --now "${HEALTH_TIMER}"
    say "Health check enabled (runs every minute)"
  else
    say "Health timer unit not found. Ensure install.sh has been run."
  fi
}

final_summary() {
  if [[ -z "${PI_LAN_IP:-}" ]]; then
    PI_LAN_IP=$(detect_lan_ip)
  fi
  say ""
  say "=== Setup complete ==="
  say "LAN IP: ${PI_LAN_IP:-unknown}"
  say "WireGuard IP: ${PI_WG_IP}"
  say "Plex target: ${PLEX_IP}:32400"
  say ""
  cat <<EOF
On your Apple TV Plex app:
  Settings -> Servers -> Add server manually
  Enter: http://${PI_LAN_IP:-<pi-ip>}:32400

ASCII diagram:
  Apple TV -- Wi-Fi --> Raspberry Pi -- WireGuard --> Home Network -- Plex Server
EOF
  say ""
  say "Reminder: the Pi public key must be added to your WireGuard server:"
  say "  ${PI_PUBLIC_KEY}"
  say ""
  say "Log file: ${LOG_FILE}"
}

main() {
  say "Plex Proxy Pi setup v${VERSION}"
  require_root
  check_os
  collect_config
  write_config_file
  update_system
  install_packages
  configure_wifi
  ensure_wireguard_keys
  write_wg_conf
  print_server_snippet
  bring_up_wireguard
  test_connectivity
  configure_caddy
  apply_sysctl_tuning
  enable_health_timer
  configure_watchdog
  final_summary
}

main "$@"
