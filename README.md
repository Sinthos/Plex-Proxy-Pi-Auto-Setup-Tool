# Plex Proxy Pi – Automated Reverse Proxy Gateway for Plex

Transforms a Raspberry Pi OS Lite (64-bit) install into a WireGuard-connected Plex reverse proxy with Caddy. The Pi lives in a friend's Wi‑Fi, builds a WireGuard tunnel to your home network, and exposes Plex locally on port `32400` so an Apple TV (or any LAN client) can treat it as a local Plex server.

## What this does
- Configures Wi‑Fi and saves credentials on the Pi.
- Supports wired LAN-only deployments (Wi‑Fi optional).
- Installs/updates `wireguard`, `caddy`, `curl`, `jq`.
- Generates WireGuard keys (or imports an existing `wg0.conf`), builds `/etc/wireguard/wg0.conf`, enables `wg-quick@wg0`, and verifies connectivity.
- Writes a minimal Caddy reverse proxy on port `32400` that forwards to your home Plex server via WireGuard.
- Adds a self-healing health check (systemd timer) that restarts WireGuard/Caddy if connectivity or proxy checks fail. Logs are written only on failure or once per hour to reduce SD wear.
- **NEW:** Adds a keepalive mechanism that runs every 15 seconds to prevent tunnel timeouts.
- Produces a server-side WireGuard snippet for you to add to your home server.
- Enables the Pi hardware watchdog for auto-reboot on hangs/loss of network.

## Repository layout
- `install.sh` – installer/updater that copies scripts and systemd units into place (`/usr/local/bin`, `/etc/systemd/system`).
- `scripts/plexproxy-setup.sh` – main guided setup (Wi‑Fi, WireGuard, Caddy, health timer).
- `scripts/plexproxy-health.sh` – health/self-healing check used by the systemd timer.
- `scripts/plexproxy-keepalive.sh` – lightweight keepalive to prevent tunnel timeouts.
- `scripts/plexproxy-gdm-relay.py` – GDM discovery relay for automatic Plex client discovery.
- `scripts/plexproxy-wg-tune.sh` – WireGuard diagnostics and MTU helper.
- `scripts/plexproxy-sysctl-apply.sh` – applies safe TCP/BBR tuning.
- `systemd/plexproxy-health.service` / `.timer` – run the health check every minute.
- `systemd/plexproxy-keepalive.service` / `.timer` – run the keepalive every 15 seconds.
- `systemd/plexproxy-gdm-relay.service` – GDM discovery relay daemon.
- `config/90-plexproxy-tuning.conf` – sysctl tuning for TCP, conntrack, and keepalive settings.
- `config/plexproxy-avahi.service` – Avahi/mDNS service definition for Bonjour discovery.

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

## Keepalive mechanism

The keepalive timer (`plexproxy-keepalive.timer`) runs every 15 seconds and sends a small request over the WireGuard interface to keep the tunnel "warm". This prevents:

- **NAT timeout issues**: Many routers drop UDP NAT mappings after 30-60 seconds of inactivity.
- **Conntrack expiration**: Linux connection tracking entries can expire, causing routing issues.
- **WireGuard handshake staleness**: Keeps the WireGuard session active.

### Automatic warmup on boot/restart

The WireGuard configuration includes a `PostUp` hook that automatically "warms up" the tunnel immediately after the interface comes up. This means:

- **No manual intervention needed** after boot or WireGuard restart
- The tunnel is immediately ready for use
- The warmup script (`/usr/local/bin/plexproxy-wg-warmup`) pings the WireGuard server and makes an HTTP request to Plex

This solves the common issue where you previously needed to manually run:
```bash
curl --interface wg0 http://<PLEX_IP>:32400/identity
```
to "wake up" the tunnel before connections work.

### Keepalive logs
- Location: `/var/log/plexproxy-keepalive.log`
- Only logs failures (throttled to once per minute to reduce SD wear)
- No logging on success

## Health check
- Installed to `/usr/local/bin/plexproxy-health`.
- Timer/service installed by `install.sh`; enabled automatically by `plexproxy-setup` if present.
- Runs every minute (`systemctl enable --now plexproxy-health.timer` if you need to enable manually).
- Logs: `/var/log/plexproxy-health.log` (writes only on failure or hourly success).

### Health check features
- Verifies WireGuard interface is up
- Checks routing table for correct paths
- Monitors WireGuard handshake freshness
- Pings Plex server through the tunnel
- Tests HTTP connectivity to local Caddy proxy
- Automatically restarts WireGuard or Caddy on failures

## Sysctl tuning

The sysctl configuration (`90-plexproxy-tuning.conf`) includes:

### TCP Buffer Tuning
- Increased buffer sizes for high-latency tunnels
- Optimized backlog settings

### Congestion Control
- BBR congestion control for smoother streaming

### Connection Tracking (Conntrack)
- Extended UDP timeouts to prevent WireGuard session drops
- Prevents premature expiration of tunnel connections

### TCP Keepalive
- Faster dead connection detection
- Helps maintain NAT mappings

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
- Logs: `/var/log/plexproxy-setup.log`, `/var/log/plexproxy-health.log`, `/var/log/plexproxy-keepalive.log`

## Troubleshooting

### Tunnel stops working after idle period
This should be fixed by the keepalive mechanism. If issues persist:
1. Check keepalive timer status: `systemctl status plexproxy-keepalive.timer`
2. Check keepalive logs: `tail -f /var/log/plexproxy-keepalive.log`
3. Manually test: `curl --interface wg0 http://<PLEX_IP>:32400/identity`

### WireGuard handshake issues
1. Check handshake age: `wg show wg0 latest-handshakes`
2. Run diagnostics: `sudo plexproxy-wg-tune --detect`
3. Check health logs: `tail -f /var/log/plexproxy-health.log`

### Caddy not responding
1. Check Caddy status: `systemctl status caddy`
2. Check Caddy logs: `journalctl -u caddy -f`
3. Test upstream: `curl --interface wg0 http://<PLEX_IP>:32400/identity`

## Notes on SD card wear
- Health check logs only failures and hourly successes.
- Keepalive logs only failures (throttled).
- Systemd timers run short oneshot checks instead of long-running loops.
- Backups of config files use timestamped copies; reruns avoid churn.

## Automatic Plex Discovery

Plex clients (Apple TV, iOS, Android, PC, etc.) can automatically discover the proxy server without manual configuration. This is achieved through two mechanisms:

### GDM (G'Day Mate) Discovery Relay

The GDM relay (`plexproxy-gdm-relay.service`) intercepts Plex discovery broadcasts on the local network and forwards them through the WireGuard tunnel to the real Plex server. When the Plex server responds, the relay modifies the response to point to the proxy's local IP address.

**How it works:**
1. Plex client broadcasts a discovery request on UDP ports 32410-32414
2. The GDM relay receives the request and forwards it to the real Plex server over WireGuard
3. The Plex server responds with its details
4. The relay replaces the Plex server's IP with the proxy's local IP
5. The modified response is sent back to the client
6. The client sees the proxy as a local Plex server

### Avahi/mDNS (Bonjour) Discovery

For clients that use Bonjour/mDNS for discovery (common on Apple devices), the proxy advertises itself as a Plex server using Avahi. This allows iOS devices and Apple TVs to find the proxy automatically.

### Checking discovery status
```bash
# Check GDM relay status
systemctl status plexproxy-gdm-relay.service
tail -f /var/log/plexproxy-gdm-relay.log

# Check Avahi status
systemctl status avahi-daemon
avahi-browse -a | grep plex
```

### If automatic discovery doesn't work

Some Plex clients may not support local discovery or may have it disabled. In these cases:

1. **Apple TV**: Open Plex app → Settings → Advanced → Allow Insecure Connections → Always
2. **iOS/Android**: The app should find the server automatically via GDM or mDNS
3. **Web browser**: Navigate directly to `http://<PI_LAN_IP>:32400/web`
4. **Manual addition**: Some apps allow adding servers manually via IP address

## Manual Apple TV steps
If automatic discovery doesn't work, you can add the server manually:
Open Plex app → Settings → Servers → Add server manually → `http://<PI_LAN_IP>:32400`.

## Architecture diagram
```
┌─────────────┐     Wi-Fi      ┌──────────────┐    WireGuard    ┌─────────────┐
│  Apple TV   │ ──────────────▶│ Raspberry Pi │ ───────────────▶│ Home Server │
│             │   LAN :32400   │   (Caddy)    │    UDP Tunnel   │   (Plex)    │
└─────────────┘                └──────────────┘                 └─────────────┘
                                     │
                                     │ Keepalive every 15s
                                     │ Health check every 60s
                                     ▼
                               Tunnel stays warm
```
