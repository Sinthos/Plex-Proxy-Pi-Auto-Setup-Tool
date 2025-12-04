#!/usr/bin/env bash
#
# Lightweight keepalive for Plex Proxy Pi WireGuard tunnel
# Runs frequently (every 15 seconds via systemd timer) to keep the tunnel "warm"
# and prevent NAT/conntrack timeouts from breaking connectivity.
#
# This solves the issue where connections work after manually running:
#   curl --interface wg0 http://<PLEX_IP>:32400/identity
# but then stop working after a period of inactivity.

set -euo pipefail

CONFIG_FILE="/etc/plexproxy/config.env"
WG_IFACE="wg0"
LOG_FILE="/var/log/plexproxy-keepalive.log"
STATE_DIR="/var/run/plexproxy"
LAST_FAIL_FILE="${STATE_DIR}/keepalive.last_fail"
FAIL_LOG_INTERVAL=60  # Only log failures every 60 seconds to reduce SD wear

mkdir -p "${STATE_DIR}"

log_failure() {
  local now last=0
  now=$(date +%s)
  if [[ -f "${LAST_FAIL_FILE}" ]]; then
    last=$(cat "${LAST_FAIL_FILE}")
  fi
  # Throttle failure logging to reduce SD card wear
  if (( now - last >= FAIL_LOG_INTERVAL )); then
    echo "${now}" > "${LAST_FAIL_FILE}"
    mkdir -p "$(dirname "${LOG_FILE}")"
    echo "$(date -Iseconds) [WARN] $1" >> "${LOG_FILE}"
  fi
}

load_config() {
  if [[ ! -f "${CONFIG_FILE}" ]]; then
    exit 0  # Silent exit if not configured yet
  fi
  # shellcheck disable=SC1090
  source "${CONFIG_FILE}"
}

# Send a minimal HTTP request over the WireGuard interface to keep the tunnel warm.
# This refreshes:
# - WireGuard handshake (if needed)
# - Linux conntrack entries
# - NAT mappings on upstream routers
keepalive_request() {
  local target="${PLEX_IP:-}"
  if [[ -z "${target}" ]]; then
    return 0
  fi
  
  # Use curl with explicit interface binding and very short timeout
  # The /identity endpoint is lightweight and always available on Plex
  if ! curl -fsS \
       --interface "${WG_IFACE}" \
       --max-time 5 \
       --connect-timeout 3 \
       -o /dev/null \
       "http://${target}:32400/identity" 2>/dev/null; then
    log_failure "Keepalive request to ${target}:32400 via ${WG_IFACE} failed"
    return 1
  fi
  
  # Clear the last fail file on success to allow immediate logging of next failure
  rm -f "${LAST_FAIL_FILE}" 2>/dev/null || true
  return 0
}

# Also ping the WireGuard server IP to keep that path warm
keepalive_ping() {
  local target="${WG_SERVER_WG_IP:-}"
  if [[ -z "${target}" ]]; then
    return 0
  fi
  
  # Single ping with short timeout
  if ! ping -I "${WG_IFACE}" -c 1 -W 2 "${target}" >/dev/null 2>&1; then
    log_failure "Keepalive ping to WG server ${target} via ${WG_IFACE} failed"
    return 1
  fi
  return 0
}

main() {
  load_config
  
  # Run both keepalive methods - failures are logged but don't stop execution
  keepalive_ping || true
  keepalive_request || true
}

main "$@"
