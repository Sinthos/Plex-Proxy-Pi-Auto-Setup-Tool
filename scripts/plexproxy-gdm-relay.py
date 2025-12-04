#!/usr/bin/env python3
"""
Plex GDM (G'Day Mate) Discovery Relay for Plex Proxy Pi

This script provides both PASSIVE and ACTIVE discovery mechanisms so that
Plex clients on the local network can automatically discover the Plex server
through the WireGuard tunnel.

Features:
- PASSIVE: Listens for client discovery broadcasts and relays them to Plex
- ACTIVE: Proactively announces the server to the network every 10 seconds
- SSDP: Responds to UPnP/SSDP discovery requests (for Smart TVs, etc.)
- Dynamically detects local IP (handles DHCP changes)
- Caches IP with short TTL for performance
- Handles multiple GDM ports (32410-32414)
- Graceful shutdown on SIGTERM/SIGINT

GDM Protocol:
- Clients broadcast "M-SEARCH * HTTP/1.1" on UDP port 32414
- Plex servers respond with their details including IP address
- Servers can also proactively announce themselves

Usage:
    sudo plexproxy-gdm-relay

The script reads configuration from /etc/plexproxy/config.env
"""

import socket
import struct
import threading
import os
import sys
import signal
import logging
import re
import time
import subprocess
from typing import Optional, Tuple, List
from dataclasses import dataclass
from datetime import datetime, timedelta

# Configuration
CONFIG_FILE = "/etc/plexproxy/config.env"
GDM_PORTS = [32410, 32412, 32413, 32414]  # All GDM ports
GDM_ANNOUNCE_PORT = 32414  # Port for announcements
SSDP_PORT = 1900  # Standard SSDP port
SSDP_MULTICAST = "239.255.255.250"
BUFFER_SIZE = 4096
TIMEOUT = 2.0
LOG_FILE = "/var/log/plexproxy-gdm-relay.log"
IP_CACHE_TTL = 30  # Seconds to cache local IP (handles DHCP changes)
ANNOUNCE_INTERVAL = 10  # Seconds between active announcements

# GDM Discovery request pattern
GDM_SEARCH = b"M-SEARCH * HTTP/1.1"

# Setup logging with rotation-friendly format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class CachedIP:
    """Cached IP address with expiration."""
    ip: str
    expires: datetime


@dataclass
class PlexServerInfo:
    """Information about the Plex server for announcements."""
    name: str
    host: str
    port: int
    machine_id: str
    version: str


class IPCache:
    """Thread-safe IP cache with TTL."""
    
    def __init__(self, ttl_seconds: int = IP_CACHE_TTL):
        self.ttl = timedelta(seconds=ttl_seconds)
        self._cache: Optional[CachedIP] = None
        self._lock = threading.Lock()
    
    def get(self) -> Optional[str]:
        """Get cached IP if not expired."""
        with self._lock:
            if self._cache and datetime.now() < self._cache.expires:
                return self._cache.ip
            return None
    
    def set(self, ip: str):
        """Set IP in cache with TTL."""
        with self._lock:
            self._cache = CachedIP(ip=ip, expires=datetime.now() + self.ttl)
    
    def invalidate(self):
        """Invalidate the cache."""
        with self._lock:
            self._cache = None


def load_config() -> dict:
    """Load configuration from config.env file."""
    config = {}
    if not os.path.exists(CONFIG_FILE):
        logger.error(f"Config file {CONFIG_FILE} not found")
        sys.exit(1)
    
    with open(CONFIG_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                # Remove quotes from value
                value = value.strip().strip('"').strip("'")
                config[key.strip()] = value
    
    return config


def get_local_ip_from_interface(iface: str) -> Optional[str]:
    """Get IP address from a specific interface."""
    try:
        result = subprocess.run(
            ['ip', '-4', 'addr', 'show', iface],
            capture_output=True, text=True, timeout=5
        )
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


def get_local_ip() -> Optional[str]:
    """
    Get the local LAN IP address of the Pi.
    Tries multiple methods for robustness.
    """
    # Method 1: Try common interfaces
    for iface in ['eth0', 'wlan0', 'end0', 'wlan1']:
        ip = get_local_ip_from_interface(iface)
        if ip and not ip.startswith('127.'):
            return ip
    
    # Method 2: Parse all interfaces
    try:
        result = subprocess.run(
            ['ip', '-4', 'addr', 'show'],
            capture_output=True, text=True, timeout=5
        )
        # Find all IPs, exclude loopback and WireGuard
        for line in result.stdout.split('\n'):
            if 'inet ' in line and '127.0.0.1' not in line:
                match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    # Skip common VPN ranges
                    if not ip.startswith('192.168.200.') and not ip.startswith('10.'):
                        return ip
    except Exception:
        pass
    
    # Method 3: Connect to external address (fallback)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith('127.'):
            return ip
    except Exception:
        pass
    
    # Method 4: hostname -I (last resort)
    try:
        result = subprocess.run(
            ['hostname', '-I'],
            capture_output=True, text=True, timeout=5
        )
        ips = result.stdout.strip().split()
        for ip in ips:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                if not ip.startswith('127.') and not ip.startswith('192.168.200.'):
                    return ip
    except Exception:
        pass
    
    return None


def get_broadcast_address(ip: str) -> str:
    """Get broadcast address for the given IP (assumes /24 subnet)."""
    parts = ip.split('.')
    parts[3] = '255'
    return '.'.join(parts)


def replace_ip_in_response(response: bytes, old_ip: str, new_ip: str) -> bytes:
    """Replace the Plex server IP with the proxy IP in the GDM response."""
    try:
        response_str = response.decode('utf-8', errors='ignore')
        response_str = response_str.replace(old_ip, new_ip)
        return response_str.encode('utf-8')
    except Exception as e:
        logger.warning(f"Failed to replace IP in response: {e}")
        return response


class GDMRelay:
    """GDM Discovery Relay with both passive and active discovery."""
    
    def __init__(self, plex_ip: str, wg_interface: str = "wg0"):
        self.plex_ip = plex_ip
        self.wg_interface = wg_interface
        self.running = False
        self.sockets = []
        self.ip_cache = IPCache(ttl_seconds=IP_CACHE_TTL)
        self._stats = {'requests': 0, 'responses': 0, 'announcements': 0, 'errors': 0}
        self._stats_lock = threading.Lock()
        self._server_info: Optional[PlexServerInfo] = None
        self._cached_announcement: Optional[bytes] = None
    
    def get_current_local_ip(self) -> Optional[str]:
        """Get current local IP with caching."""
        ip = self.ip_cache.get()
        if ip:
            return ip
        
        ip = get_local_ip()
        if ip:
            self.ip_cache.set(ip)
            logger.debug(f"Cached local IP: {ip}")
            # Invalidate cached announcement when IP changes
            self._cached_announcement = None
        return ip
    
    def fetch_server_info(self) -> Optional[PlexServerInfo]:
        """Fetch server information from the real Plex server."""
        try:
            import urllib.request
            import json
            
            url = f"http://{self.plex_ip}:32400/identity"
            req = urllib.request.Request(url, headers={'Accept': 'application/json'})
            
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                media_container = data.get('MediaContainer', {})
                
                return PlexServerInfo(
                    name=media_container.get('friendlyName', 'Plex Media Server'),
                    host=self.plex_ip,
                    port=32400,
                    machine_id=media_container.get('machineIdentifier', 'unknown'),
                    version=media_container.get('version', '1.0.0')
                )
        except Exception as e:
            logger.warning(f"Could not fetch server info: {e}")
            # Return default info
            return PlexServerInfo(
                name="Plex Media Server",
                host=self.plex_ip,
                port=32400,
                machine_id="plexproxy",
                version="1.0.0"
            )
    
    def build_gdm_announcement(self, local_ip: str) -> bytes:
        """Build a GDM announcement packet."""
        if not self._server_info:
            self._server_info = self.fetch_server_info()
        
        info = self._server_info
        hostname = socket.gethostname()
        
        # GDM announcement format (similar to what Plex servers send)
        announcement = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: plex/media-server\r\n"
            f"Name: {info.name}\r\n"
            f"Host: {local_ip}\r\n"
            f"Port: 32400\r\n"
            f"Machine-Identifier: {info.machine_id}\r\n"
            f"Version: {info.version}\r\n"
            f"Resource-Identifier: {info.machine_id}\r\n"
            f"Updated-At: {int(time.time())}\r\n"
            f"Protocol: plex\r\n"
            f"Protocol-Version: 1\r\n"
            f"Protocol-Capabilities: timeline,playback,navigation,mirror,playqueues\r\n"
            f"\r\n"
        )
        
        return announcement.encode('utf-8')
    
    def build_ssdp_response(self, local_ip: str) -> bytes:
        """Build an SSDP response for UPnP discovery."""
        if not self._server_info:
            self._server_info = self.fetch_server_info()
        
        info = self._server_info
        
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"CACHE-CONTROL: max-age=1800\r\n"
            f"ST: urn:plex-tv:device:MediaServer:1\r\n"
            f"USN: uuid:{info.machine_id}::urn:plex-tv:device:MediaServer:1\r\n"
            f"Location: http://{local_ip}:32400/\r\n"
            f"Server: Plex Media Server/{info.version}\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )
        
        return response.encode('utf-8')
    
    def create_broadcast_socket(self, port: int) -> socket.socket:
        """Create a UDP socket that can receive broadcasts."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1.0)
        sock.bind(('', port))
        return sock
    
    def create_multicast_socket(self, port: int, multicast_group: str) -> socket.socket:
        """Create a UDP socket for multicast (SSDP)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        
        # Bind to all interfaces
        sock.bind(('', port))
        
        # Join multicast group
        mreq = struct.pack("4sl", socket.inet_aton(multicast_group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
        return sock
    
    def forward_to_plex(self, data: bytes, port: int) -> Optional[bytes]:
        """Forward a discovery request to the real Plex server over WireGuard."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(TIMEOUT)
            
            # Try to bind to wg0 interface (requires root)
            try:
                sock.setsockopt(socket.SOL_SOCKET, 25, self.wg_interface.encode())
            except Exception as e:
                logger.debug(f"Could not bind to {self.wg_interface}: {e}")
            
            sock.sendto(data, (self.plex_ip, port))
            response, addr = sock.recvfrom(BUFFER_SIZE)
            sock.close()
            
            return response
        except socket.timeout:
            logger.debug(f"Timeout waiting for response from Plex server on port {port}")
            return None
        except Exception as e:
            logger.error(f"Error forwarding to Plex: {e}")
            with self._stats_lock:
                self._stats['errors'] += 1
            return None
    
    def handle_discovery(self, sock: socket.socket, port: int):
        """Handle incoming discovery requests on a specific port (PASSIVE mode)."""
        while self.running:
            try:
                data, client_addr = sock.recvfrom(BUFFER_SIZE)
                
                # Check if this is a GDM search request
                if GDM_SEARCH in data or b"M-SEARCH" in data:
                    with self._stats_lock:
                        self._stats['requests'] += 1
                    
                    logger.info(f"GDM discovery request from {client_addr[0]} on port {port}")
                    
                    local_ip = self.get_current_local_ip()
                    if not local_ip:
                        logger.warning("Could not determine local IP, skipping request")
                        continue
                    
                    # Forward to real Plex server
                    response = self.forward_to_plex(data, port)
                    
                    if response:
                        modified_response = replace_ip_in_response(
                            response, self.plex_ip, local_ip
                        )
                        sock.sendto(modified_response, client_addr)
                        
                        with self._stats_lock:
                            self._stats['responses'] += 1
                        
                        logger.info(f"Sent modified GDM response to {client_addr[0]} (local IP: {local_ip})")
                    else:
                        # If Plex server doesn't respond, send our own announcement
                        announcement = self.build_gdm_announcement(local_ip)
                        sock.sendto(announcement, client_addr)
                        logger.info(f"Sent local GDM announcement to {client_addr[0]}")
                        
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error handling discovery on port {port}: {e}")
                    with self._stats_lock:
                        self._stats['errors'] += 1
    
    def handle_ssdp(self, sock: socket.socket):
        """Handle SSDP/UPnP discovery requests."""
        while self.running:
            try:
                data, client_addr = sock.recvfrom(BUFFER_SIZE)
                
                # Check if this is an SSDP M-SEARCH
                if b"M-SEARCH" in data and (b"plex" in data.lower() or b"ssdp:all" in data.lower()):
                    logger.info(f"SSDP discovery request from {client_addr[0]}")
                    
                    local_ip = self.get_current_local_ip()
                    if local_ip:
                        response = self.build_ssdp_response(local_ip)
                        sock.sendto(response, client_addr)
                        logger.debug(f"Sent SSDP response to {client_addr[0]}")
                        
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.debug(f"SSDP error: {e}")
    
    def active_announcer(self):
        """Proactively announce the server to the network (ACTIVE mode)."""
        logger.info(f"Starting active announcer (every {ANNOUNCE_INTERVAL}s)")
        
        while self.running:
            try:
                local_ip = self.get_current_local_ip()
                if not local_ip:
                    time.sleep(ANNOUNCE_INTERVAL)
                    continue
                
                broadcast_addr = get_broadcast_address(local_ip)
                announcement = self.build_gdm_announcement(local_ip)
                
                # Create broadcast socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(1.0)
                
                # Send announcement to all GDM ports
                for port in GDM_PORTS:
                    try:
                        sock.sendto(announcement, (broadcast_addr, port))
                    except Exception as e:
                        logger.debug(f"Could not send to {broadcast_addr}:{port}: {e}")
                
                # Also send to 255.255.255.255 for wider reach
                for port in GDM_PORTS:
                    try:
                        sock.sendto(announcement, ('255.255.255.255', port))
                    except Exception:
                        pass
                
                sock.close()
                
                with self._stats_lock:
                    self._stats['announcements'] += 1
                
                logger.debug(f"Sent active announcement (IP: {local_ip})")
                
            except Exception as e:
                logger.error(f"Error in active announcer: {e}")
            
            time.sleep(ANNOUNCE_INTERVAL)
    
    def log_stats(self):
        """Periodically log statistics."""
        while self.running:
            time.sleep(300)  # Every 5 minutes
            if self.running:
                with self._stats_lock:
                    logger.info(f"Stats: {self._stats['requests']} requests, "
                               f"{self._stats['responses']} responses, "
                               f"{self._stats['announcements']} announcements, "
                               f"{self._stats['errors']} errors")
    
    def start(self):
        """Start the GDM relay with both passive and active discovery."""
        self.running = True
        threads = []
        
        # Get initial local IP
        local_ip = self.get_current_local_ip()
        if not local_ip:
            logger.error("Could not determine local IP address")
            sys.exit(1)
        
        # Fetch server info
        self._server_info = self.fetch_server_info()
        
        logger.info(f"Starting GDM relay: Plex={self.plex_ip}, Local={local_ip}")
        logger.info(f"Server name: {self._server_info.name if self._server_info else 'Unknown'}")
        logger.info(f"Local IP will be refreshed every {IP_CACHE_TTL}s to handle DHCP changes")
        logger.info(f"Active announcements every {ANNOUNCE_INTERVAL}s")
        
        # Create sockets for all GDM ports (PASSIVE)
        for port in GDM_PORTS:
            try:
                sock = self.create_broadcast_socket(port)
                self.sockets.append(sock)
                
                thread = threading.Thread(
                    target=self.handle_discovery,
                    args=(sock, port),
                    daemon=True,
                    name=f"GDM-{port}"
                )
                thread.start()
                threads.append(thread)
                logger.info(f"Listening on UDP port {port} (passive)")
            except Exception as e:
                logger.error(f"Failed to bind to port {port}: {e}")
        
        # Try to set up SSDP listener
        try:
            ssdp_sock = self.create_multicast_socket(SSDP_PORT, SSDP_MULTICAST)
            self.sockets.append(ssdp_sock)
            
            ssdp_thread = threading.Thread(
                target=self.handle_ssdp,
                args=(ssdp_sock,),
                daemon=True,
                name="SSDP"
            )
            ssdp_thread.start()
            threads.append(ssdp_thread)
            logger.info(f"Listening on SSDP port {SSDP_PORT}")
        except Exception as e:
            logger.warning(f"Could not start SSDP listener: {e}")
        
        # Start active announcer thread
        announcer_thread = threading.Thread(
            target=self.active_announcer,
            daemon=True,
            name="Announcer"
        )
        announcer_thread.start()
        threads.append(announcer_thread)
        logger.info("Active announcer started")
        
        # Start stats logging thread
        stats_thread = threading.Thread(target=self.log_stats, daemon=True, name="Stats")
        stats_thread.start()
        
        if not self.sockets:
            logger.error("No sockets could be created. Exiting.")
            sys.exit(1)
        
        # Wait for threads
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        
        self.stop()
    
    def stop(self):
        """Stop the GDM relay."""
        logger.info("Stopping GDM relay...")
        self.running = False
        
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        
        self.sockets = []
        
        with self._stats_lock:
            logger.info(f"Final stats: {self._stats['requests']} requests, "
                       f"{self._stats['responses']} responses, "
                       f"{self._stats['announcements']} announcements, "
                       f"{self._stats['errors']} errors")


def main():
    """Main entry point."""
    # Check for root privileges
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)
    
    # Load configuration
    config = load_config()
    
    plex_ip = config.get('PLEX_IP')
    if not plex_ip:
        logger.error("PLEX_IP not found in config")
        sys.exit(1)
    
    logger.info("=" * 60)
    logger.info("Plex Proxy Pi GDM Relay v2.0 starting...")
    logger.info(f"  Plex Server: {plex_ip}")
    logger.info(f"  Config: {CONFIG_FILE}")
    logger.info(f"  IP Cache TTL: {IP_CACHE_TTL}s")
    logger.info(f"  Announce Interval: {ANNOUNCE_INTERVAL}s")
    logger.info("  Features: Passive Discovery, Active Announcements, SSDP")
    logger.info("=" * 60)
    
    # Create and start relay
    relay = GDMRelay(plex_ip)
    
    # Handle signals
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        relay.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    relay.start()


if __name__ == "__main__":
    main()
