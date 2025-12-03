#!/usr/bin/env bash
# Installer/Updater for Plex Proxy Pi automation
# Copies scripts and systemd units into place on a Raspberry Pi OS host.
# Run as root: sudo ./install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PREFIX="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/plexproxy"

usage() {
  cat <<'EOF'
Plex Proxy Pi installer

Usage: sudo ./install.sh [--install|--update]

Actions:
  --install, --update   Copy scripts and systemd units to the host (default)

After install, run: sudo plexproxy-setup
EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "This installer must be run as root." >&2
    exit 1
  fi
}

copy_file() {
  local src="$1"
  local dst="$2"
  local mode="$3"
  install -m "${mode}" -D "${src}" "${dst}"
  echo "Installed ${dst}"
}

install_all() {
  mkdir -p "${CONFIG_DIR}"

  copy_file "${SCRIPT_DIR}/scripts/plexproxy-setup.sh" "${INSTALL_PREFIX}/plexproxy-setup" 0755
  copy_file "${SCRIPT_DIR}/scripts/plexproxy-health.sh" "${INSTALL_PREFIX}/plexproxy-health" 0755

  copy_file "${SCRIPT_DIR}/systemd/plexproxy-health.service" "${SYSTEMD_DIR}/plexproxy-health.service" 0644
  copy_file "${SCRIPT_DIR}/systemd/plexproxy-health.timer" "${SYSTEMD_DIR}/plexproxy-health.timer" 0644

  systemctl daemon-reload
  echo "Install complete. Enable the health timer after setup with: systemctl enable --now plexproxy-health.timer"
}

main() {
  local action="${1:---install}"

  case "${action}" in
    --install|--update) ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown action: ${action}" >&2; usage; exit 1 ;;
  esac

  require_root
  install_all
}

main "$@"
