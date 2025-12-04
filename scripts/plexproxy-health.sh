#!/usr/bin/env bash
#
# Health check and self-healing for Plex Proxy Pi
# Intended to run via systemd timer every minute.
#
# This script performs comprehensive health checks and automatically
# restarts services when issues are detected.

set -euo pipefail

LOG_FILE="/var/log/plexproxy-health.log"
CONFIG_FILE="/etc/plexproxy/config.env"
WG_IFACE="wg0"
HANDSHAKE_MAX_AGE=180   # seconds (reduced from 300 for faster detection)
SUCCESS_LOG_INTERVAL=3600
MIN_RESTART_INTERVAL=30 # seconds between restarts to avoid flapping
STATE_DIR="/var/run/plexproxy"
LAST_SUCCESS_FILE="${STATE_DIR}/health.last"
LAST_RESTART_FILE="${STATE_DIR}/health.last_restart"
LOCK_FILE="${STATE_DIR}/health.lock"

mkdir -p "${STATE_DIR}"

log() {
  local level="$1"; shift
  local msg="$*"
  echo "$(date -Iseconds) [${level}] ${msg}" >> "${LOG_FILE}"
}

log_success_throttled() {
  local now last=0
  now=$(date +%s)
  if [[ -f "${LAST_SUCCESS_FILE}" ]]; then
    last=$(cat "${LAST_SUCCESS_FILE}")
  fi
  if (( now - last >= SUCCESS_LOG_INTERVAL )); then
    echo "${now}" > "${LAST_SUCCESS_FILE}"
    log "INFO" "$1"
  fi
}

require_config() {
  if [[ ! -f "${CONFIG_FILE}" ]]; then
    log "ERROR" "Config file ${CONFIG_FILE} missing; run plexproxy-setup first."
    exit 1
  fi
  # shellcheck disable=SC1090
  source "${CONFIG_FILE}"
}

handshake_recent() {
  local now latest output
  now=$(date +%s)
  output=$(wg show "${WG_IFACE}" latest-handshakes 2>/dev/null || true)
  latest=$(awk '{print $2}' <<<"${output}" | head -1)
  if [[ -z "${latest}" || "${latest}" == "0" ]]; then
    return 1
  fi
  (( now - latest <= HANDSHAKE_MAX_AGE ))
}

ping_target() {
  local target="$1"
  if [[ -z "${target}" ]]; then
    return 0
  fi
  ping -I "${WG_IFACE}" -c 2 -W 3 "${target}" >/dev/null 2>&1
}

check_http() {
  curl -fsS --max-time 5 http://localhost:32400/identity >/dev/null 2>&1
}

# Keep the upstream Plex session warm over wg0 to avoid idle timeouts
check_upstream_identity() {
  curl -fsS --interface "${WG_IFACE}" --max-time 5 "http://${PLEX_IP}:32400/identity" >/dev/null 2>&1
}

can_restart() {
  local now last=0
  now=$(date +%s)
  if [[ -f "${LAST_RESTART_FILE}" ]]; then
    last=$(cat "${LAST_RESTART_FILE}")
  fi
  (( now - last >= MIN_RESTART_INTERVAL ))
}

mark_restart() {
  date +%s > "${LAST_RESTART_FILE}"
}

restart_wireguard() {
  if ! can_restart; then
    log "INFO" "Skipping WireGuard restart to avoid flapping."
    return
  fi
  log "INFO" "Restarting WireGuard (${WG_IFACE})."
  wg-quick down "${WG_IFACE}" >/dev/null 2>&1 || true
  wg-quick up "${WG_IFACE}"
  mark_restart
}

restart_caddy() {
  if ! can_restart; then
    log "INFO" "Skipping Caddy restart to avoid flapping."
    return
  fi
  log "INFO" "Restarting Caddy."
  systemctl restart caddy
  mark_restart
}

# Check if WireGuard routes are properly configured
check_wg_routes() {
  local target="${PLEX_IP:-}"
  if [[ -z "${target}" ]]; then
    return 0
  fi
  
  # Check if route to PLEX_IP goes through wg0
  local route_dev
  route_dev=$(ip route get "${target}" 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
  
  if [[ "${route_dev}" != "${WG_IFACE}" ]]; then
    log "WARN" "Route to ${target} goes through ${route_dev:-unknown} instead of ${WG_IFACE}"
    return 1
  fi
  return 0
}

# Check if WireGuard interface is up
check_wg_interface() {
  if ! ip link show "${WG_IFACE}" >/dev/null 2>&1; then
    log "WARN" "WireGuard interface ${WG_IFACE} is not present"
    return 1
  fi
  
  local state
  state=$(ip link show "${WG_IFACE}" 2>/dev/null | grep -oP 'state \K\S+' || echo "UNKNOWN")
  if [[ "${state}" != "UNKNOWN" && "${state}" != "UP" ]]; then
    log "WARN" "WireGuard interface ${WG_IFACE} state is ${state}"
    return 1
  fi
  return 0
}

main() {
  mkdir -p "$(dirname "${LOG_FILE}")"
  touch "${LOG_FILE}" || true
  exec {LOCKFD}>"${LOCK_FILE}"
  if ! flock -n "${LOCKFD}"; then
    log "INFO" "Another health check is running; exiting."
    exit 0
  fi

  require_config
  local failed=0

  # First check if WireGuard interface exists and is up
  if ! check_wg_interface; then
    log "WARN" "WireGuard interface check failed; restarting interface."
    restart_wireguard || failed=1
  fi

  # Check if routes are correct
  if ! check_wg_routes; then
    log "WARN" "WireGuard routes check failed; restarting interface."
    restart_wireguard || failed=1
  fi

  if ! handshake_recent; then
    log "WARN" "WireGuard handshake is stale; restarting interface."
    restart_wireguard || failed=1
  fi

  if ! ping_target "${PLEX_IP}"; then
    log "WARN" "Failed to reach Plex server ${PLEX_IP}; restarting WireGuard."
    restart_wireguard || failed=1
  fi

  if [[ -n "${FILES_IP:-}" ]] && ! ping_target "${FILES_IP}"; then
    log "WARN" "Failed to reach file server ${FILES_IP}; restarting WireGuard."
    restart_wireguard || failed=1
  fi

  if ! check_upstream_identity; then
    log "WARN" "Upstream Plex identity check via ${WG_IFACE} failed; restarting WireGuard."
    restart_wireguard || failed=1
  fi

  if ! check_http; then
    log "WARN" "HTTP check to localhost:32400 failed; restarting Caddy."
    restart_caddy || failed=1
  fi

  if (( failed == 0 )); then
    log_success_throttled "Health check OK"
  fi
}

main "$@"
