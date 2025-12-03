#!/usr/bin/env bash
#
# Health check and self-healing for Plex Proxy Pi
# Intended to run via systemd timer every minute.

set -euo pipefail

LOG_FILE="/var/log/plexproxy-health.log"
CONFIG_FILE="/etc/plexproxy/config.env"
WG_IFACE="wg0"
HANDSHAKE_MAX_AGE=300 # seconds
SUCCESS_LOG_INTERVAL=3600 # seconds
STATE_DIR="/var/run/plexproxy"
LAST_SUCCESS_FILE="${STATE_DIR}/health.last"

mkdir -p "${STATE_DIR}"

log() {
  local level="$1"; shift
  local msg="$*"
  echo "$(date -Iseconds) [${level}] ${msg}" >> "${LOG_FILE}"
}

log_success_throttled() {
  local now epoch last=0
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
  local now latest
  now=$(date +%s)
  latest=$(wg show "${WG_IFACE}" latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
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

restart_wireguard() {
  wg-quick down "${WG_IFACE}" >/dev/null 2>&1 || true
  wg-quick up "${WG_IFACE}"
}

main() {
  require_config
  local failed=0

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

  if ! check_http; then
    log "WARN" "HTTP check to localhost:32400 failed; restarting Caddy."
    systemctl restart caddy || failed=1
  fi

  if (( failed == 0 )); then
    log_success_throttled "Health check OK"
  fi
}

main "$@"
