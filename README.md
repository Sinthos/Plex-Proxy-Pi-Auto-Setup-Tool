# Plex Proxy Pi – Automated Reverse Proxy Gateway for Plex

Transforms a Raspberry Pi OS Lite (64-bit) install into a WireGuard-connected Plex reverse proxy with Caddy. The Pi lives in a friend's Wi‑Fi, builds a WireGuard tunnel to your home network, and exposes Plex locally on port `32400` so an Apple TV (or any LAN client) can treat it as a local Plex server.

## What this does
- Configures Wi‑Fi and saves credentials on the Pi.
- Supports wired LAN-only deployments (Wi‑Fi optional).
- Installs/updates `wireguard`, `caddy`, `curl`, `jq`.
- Generates WireGuard keys (or imports an existing `wg0.conf`), builds `/etc/wireguard/wg0.conf`, enables `wg-quick@wg0`, and verifies connectivity.
- Writes a minimal Caddy reverse proxy on port `32400` that forwards to your home Plex server via WireGuard.
- Adds a self-healing health check (systemd timer) that restarts WireGuard/Caddy if connectivity or proxy checks fail. Logs are written only on failure or once per hour to reduce SD wear.
- Produces a server-side WireGuard snippet for you to add to your home server.
- Enables the Pi hardware watchdog for auto-reboot on hangs/loss of network.

## Repository layout
- `install.sh` – installer/updater that copies scripts and systemd units into place (`/usr/local/bin`, `/etc/systemd/system`).
- `scripts/plexproxy-setup.sh` – main guided setup (Wi‑Fi, WireGuard, Caddy, health timer).
- `scripts/plexproxy-health.sh` – health/self-healing check used by the systemd timer.
- `scripts/plexproxy-wg-tune.sh` – WireGuard diagnostics and MTU helper.
- `scripts/plexproxy-sysctl-apply.sh` – applies safe TCP/BBR tuning.
- `systemd/plexproxy-health.service` / `.timer` – run the health check every minute.

## Prerequisites
- Raspberry Pi OS Lite (64-bit) on Pi 3B/3B+/4B/5 with Wi‑Fi.
- Run everything as `root` (use `sudo -i` or prefix commands with `sudo`).
- Network access to `apt` repositories from the Pi.

## Quick start
```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/Sinthos/Plex-Proxy-Pi-Auto-Setup-Tool
cd Plex-Proxy-Pi-Auto-Setup-Tool
sudo ./install.sh            # copies scripts + systemd units
sudo plexproxy-setup         # guided setup + logging to /var/log/plexproxy-setup.log
```

During setup you will be asked for:
- Wi‑Fi SSID/password and country code.
- WireGuard endpoint (host:port), server public key, server tunnel IP, desired Pi tunnel IP.
- Plex server IP (in home LAN) and optional file/NAS IP for routing.

You may optionally paste an existing `wg0.conf` when prompted to pre-fill values.

At the end you will see:
- Pi LAN IP (use this on the Apple TV): `http://<PI_LAN_IP>:32400`
- WireGuard IP for the Pi and the server-side peer snippet to add on your home WireGuard server.

### Optional tuning (after setup)
- MTU/diagnostics: `sudo plexproxy-wg-tune --detect` (logs to `/var/log/plexproxy-wg-diagnostics.log`); apply a value with `--apply <mtu>`.
- Sysctl (safe TCP/BBR buffers): `sudo plexproxy-sysctl-apply`.

## Health check
- Installed to `/usr/local/bin/plexproxy-health`.
- Timer/service installed by `install.sh`; enabled automatically by `plexproxy-setup` if present.
- Runs every minute (`systemctl enable --now plexproxy-health.timer` if you need to enable manually).
- Logs: `/var/log/plexproxy-health.log` (writes only on failure or hourly success).

## Update
- Rerun `sudo ./install.sh --update` after pulling new commits; this refreshes scripts and units.
- Re-run `sudo plexproxy-setup` anytime; it is idempotent and will back up configs before writing.

## Key file locations
- Config: `/etc/plexproxy/config.env`
- Wi‑Fi: `/etc/wpa_supplicant/wpa_supplicant.conf`
- WireGuard: `/etc/wireguard/wg0.conf`, keys in `/etc/wireguard/privatekey` and `publickey`
- Caddyfile: `/etc/caddy/Caddyfile`
- Sysctl tuning: `/etc/sysctl.d/90-plexproxy-tuning.conf`
- Watchdog: `/etc/watchdog.conf`, module load at `/etc/modules-load.d/plexproxy-watchdog.conf`
- Logs: `/var/log/plexproxy-setup.log`, `/var/log/plexproxy-health.log`

## Notes on SD card wear
- Health check logs only failures and hourly successes.
- Systemd timer runs a short oneshot check instead of a long-running loop.
- Backups of config files use timestamped copies; reruns avoid churn.

## Manual Apple TV steps
Open Plex app → Settings → Servers → Add server manually → `http://<PI_LAN_IP>:32400`.
