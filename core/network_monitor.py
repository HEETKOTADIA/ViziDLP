"""
ViziDLP Network Outbound Monitor
Monitors outbound network connections for suspicious activity.

- Uses psutil to enumerate active connections every 5 seconds
- Detects connections to suspicious upload ports (FTP, SSH, SMB, etc.)
- Detects connections to known file-sharing domains via reverse DNS
- Read-only: does NOT block or intercept any connections
- Fires callback with connection info for logging
"""

import socket
import threading
import time
from typing import Callable, Optional

import psutil

from utils.config import SUSPICIOUS_UPLOAD_PORTS, SUSPICIOUS_DOMAINS


class NetworkMonitor:
    """
    Monitors outbound network connections for suspicious activity.

    Interface:
      - start(callback): Begin monitoring with a detection callback
      - stop(): Stop monitoring
      - is_running(): Check if the monitor is active
    """

    POLL_INTERVAL = 5  # seconds

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable] = None
        self._seen_connections = set()  # Track already-reported connections
        print("[NETWORK] Network monitor initialized.")

    def start(self, callback: Callable):
        """
        Start network monitoring.

        Args:
            callback: Function to call on suspicious connection.
                      Signature: callback(conn_info: dict)
                      conn_info keys: pid, process_name, remote_ip, remote_port,
                                      status, matched_rule
        """
        if self._running:
            return

        self._callback = callback
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        print("[NETWORK] Network monitoring started.")

    def stop(self):
        """Stop network monitoring."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        print("[NETWORK] Network monitoring stopped.")

    def is_running(self) -> bool:
        """Check if the network monitor is active."""
        return self._running

    def _poll_loop(self):
        """Main polling loop — runs in a daemon thread."""
        while self._running:
            try:
                self._check_connections()
            except Exception as e:
                print(f"[NETWORK] Poll error: {e}")
            time.sleep(self.POLL_INTERVAL)

    def _check_connections(self):
        """Check all outbound connections for suspicious activity."""
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            # May require elevated privileges on some systems
            return
        except Exception:
            return

        for conn in connections:
            # Only check ESTABLISHED outbound connections with a remote address
            if conn.status != 'ESTABLISHED' or not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid

            # Deduplication key
            conn_key = (pid, remote_ip, remote_port)
            if conn_key in self._seen_connections:
                continue

            matched_rule = self._check_suspicious(remote_ip, remote_port)
            if matched_rule:
                self._seen_connections.add(conn_key)

                # Get process name
                process_name = "unknown"
                try:
                    if pid:
                        proc = psutil.Process(pid)
                        process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                conn_info = {
                    'pid': pid,
                    'process_name': process_name,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'status': conn.status,
                    'matched_rule': matched_rule,
                }

                print(f"[NETWORK] SUSPICIOUS: {process_name} (PID {pid}) → "
                      f"{remote_ip}:{remote_port} [{matched_rule}]")

                if self._callback:
                    self._callback(conn_info)

        # Prune seen connections to prevent memory leak (keep last 500)
        if len(self._seen_connections) > 500:
            self._seen_connections = set(list(self._seen_connections)[-200:])

    # Cloud storage domains for upload detection
    CLOUD_STORAGE_DOMAINS = [
        'drive.google.com', 'docs.google.com', 'googleapis.com',
        'dropbox.com', 'dropboxapi.com',
        'onedrive.live.com', 'sharepoint.com', '1drv.ms',
        'icloud.com', 'apple.com',
        'box.com', 'boxcloud.com',
        'mega.nz', 'mega.co.nz',
    ]

    def _check_suspicious(self, remote_ip: str, remote_port: int) -> Optional[str]:
        """
        Check if a connection matches suspicious criteria.

        Returns:
            Matched rule description string, or None
        """
        # Check suspicious ports
        if remote_port in SUSPICIOUS_UPLOAD_PORTS:
            return f"suspicious_port:{remote_port}"

        # Check domain via reverse DNS
        try:
            hostname_info = socket.gethostbyaddr(remote_ip)
            hostname = hostname_info[0].lower()

            # Check file-sharing domains
            for domain in SUSPICIOUS_DOMAINS:
                if domain.lower() in hostname:
                    return f"suspicious_domain:{domain}"

            # Check cloud storage domains
            for domain in self.CLOUD_STORAGE_DOMAINS:
                if domain.lower() in hostname:
                    return f"cloud_upload_attempt:{domain}"

        except (socket.herror, socket.gaierror, OSError):
            # DNS lookup failed -- skip domain check silently
            pass

        return None

