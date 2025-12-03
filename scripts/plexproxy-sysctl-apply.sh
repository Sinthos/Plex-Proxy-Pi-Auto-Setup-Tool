#!/usr/bin/env bash
# Apply safe sysctl tuning for Plex Proxy Pi

set -euo pipefail

SYSCTL_DST="/etc/sysctl.d/90-plexproxy-tuning.conf"
SOURCE_CANDIDATES=(
  "/etc/plexproxy/90-plexproxy-tuning.conf"
  "$(dirname "${BASH_SOURCE[0]}")/../config/90-plexproxy-tuning.conf"
)

find_source() {
  for f in "${SOURCE_CANDIDATES[@]}"; do
    if [[ -f "${f}" ]]; then
      echo "${f}"
      return 0
    fi
  done
  return 1
}

main() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
  fi

  local src
  if ! src=$(find_source); then
    echo "No sysctl template found." >&2
    exit 1
  fi

  install -m 0644 -D "${src}" "${SYSCTL_DST}"
  echo "Wrote ${SYSCTL_DST}"
  sysctl --system >/dev/null
  echo "Applied sysctl settings."
  sysctl net.ipv4.tcp_congestion_control
}

main "$@"
