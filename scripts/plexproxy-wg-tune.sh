#!/usr/bin/env bash
#
# WireGuard diagnostics and MTU helper for Plex Proxy Pi
# - Runs basic connectivity checks
# - Attempts MTU discovery with DF pings to the endpoint host
# - Optionally applies a chosen MTU to /etc/wireguard/wg0.conf

set -euo pipefail

LOG_FILE="/var/log/plexproxy-wg-diagnostics.log"
CONFIG_FILE="/etc/plexproxy/config.env"
WG_CONF="/etc/wireguard/wg0.conf"
WG_IFACE="wg0"
MIN_MTU=1280
MAX_MTU=1420
STEP=10

usage() {
  cat <<'EOF'
Usage: plexproxy-wg-tune.sh [--detect] [--apply <mtu>] [--log]
  --detect       Run MTU discovery (DF ping sweep) and report best value
  --apply <mtu>  Write MTU into /etc/wireguard/wg0.conf (backs up first)
  --log          Append results to log (default behavior)
EOF
}

log() {
  local msg="$*"
  echo "$(date -Iseconds) ${msg}" | tee -a "${LOG_FILE}"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
  fi
}

load_config() {
  if [[ -f "${CONFIG_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${CONFIG_FILE}"
  fi
}

endpoint_host() {
  # Extract host from Endpoint line in wg0.conf or from config.env
  local ep
  ep=$(grep -m1 '^Endpoint' "${WG_CONF}" 2>/dev/null | awk -F= '{gsub(/[[:space:]]/,"",$2);print $2}')
  ep="${ep:-${WG_ENDPOINT:-}}"
  echo "${ep%%:*}"
}

current_mtu() {
  ip link show dev "${WG_IFACE}" 2>/dev/null | awk '/mtu/ {for(i=1;i<=NF;i++){if($i=="mtu"){print $(i+1);exit}}}'
}

detect_mtu() {
  local host="$1"
  if [[ -z "${host}" ]]; then
    log "No endpoint host available for MTU detection."
    return 1
  fi

  log "Starting MTU detection against ${host} (range ${MIN_MTU}-${MAX_MTU}, step ${STEP})"
  local mtu best=0 size rc
  for ((mtu=MAX_MTU; mtu>=MIN_MTU; mtu-=STEP)); do
    size=$((mtu - 28)) # IPv4 header 20B + ICMP 8B
    if ping -4 -c1 -W1 -M do -s "${size}" "${host}" >/dev/null 2>&1; then
      best="${mtu}"
      log "MTU ${mtu} OK (payload ${size})"
      break
    else
      log "MTU ${mtu} failed (payload ${size})"
    fi
  done

  if (( best == 0 )); then
    log "No working MTU found; defaulting to ${MIN_MTU}"
    best="${MIN_MTU}"
  fi

  echo "${best}"
}

apply_mtu() {
  local mtu="$1"
  if [[ ! "${mtu}" =~ ^[0-9]+$ ]] || (( mtu < MIN_MTU || mtu > 1500 )); then
    echo "Invalid MTU: ${mtu}" >&2
    exit 1
  fi
  if [[ -f "${WG_CONF}" ]]; then
    local backup="${WG_CONF}.bak.$(date +%s)"
    cp "${WG_CONF}" "${backup}"
    log "Backed up wg0.conf to ${backup}"
    if grep -q '^MTU' "${WG_CONF}"; then
      sed -i "s/^MTU.*/MTU = ${mtu}/" "${WG_CONF}"
    else
      sed -i "/^PrivateKey/ a MTU = ${mtu}" "${WG_CONF}"
    fi
    log "Wrote MTU ${mtu} to ${WG_CONF}"
  else
    echo "wg0.conf not found at ${WG_CONF}" >&2
  fi
}

diagnostics() {
  local host="$1"
  log "=== WireGuard diagnostics ==="
  wg show "${WG_IFACE}" || log "wg show failed"
  if [[ -n "${host}" ]]; then
    ping -c3 -W2 "${host}" >/dev/null 2>&1 && log "Ping to endpoint ${host} OK" || log "Ping to endpoint ${host} failed"
  fi
  if [[ -n "${PLEX_IP:-}" ]]; then
    ping -I "${WG_IFACE}" -c3 -W2 "${PLEX_IP}" >/dev/null 2>&1 && log "Ping to Plex ${PLEX_IP} OK" || log "Ping to Plex ${PLEX_IP} failed"
  fi
  log "Current MTU: $(current_mtu || echo unknown)"
}

main() {
  local do_detect=false do_apply="" do_log=true

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --detect) do_detect=true; shift ;;
      --apply) do_apply="$2"; shift 2 ;;
      --log) do_log=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
  done

  require_root
  load_config

  local host
  host=$(endpoint_host)

  diagnostics "${host}"

  local best_mtu=""
  if [[ "${do_detect}" == true ]]; then
    best_mtu=$(detect_mtu "${host}")
    log "Detected best MTU: ${best_mtu}"
  fi

  if [[ -n "${do_apply}" ]]; then
    apply_mtu "${do_apply}"
  elif [[ -n "${best_mtu}" ]]; then
    log "To apply detected MTU: plexproxy-wg-tune --apply ${best_mtu}"
  fi
}

main "$@"
