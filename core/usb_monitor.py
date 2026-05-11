"""
ViziDLP USB Device Monitor
Detects USB drive insertion/removal events on Windows.

- Uses WMI on Windows to detect USB mass storage events
- Falls back to polling drive letters on systems without WMI
- Logs mount events with timestamp, drive letter, device info
- Fires callback on insertion during active monitoring
- Read-only: does NOT block USB access
"""

import os
import string
import threading
import time
from typing import Callable, Dict, List, Optional, Set


# ─── WMI availability ────────────────────────────────────────
WMI_AVAILABLE = False
try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    pass


class USBMonitor:
    """
    Monitors USB drive insertion/removal events.

    Interface:
      - start(callback): Begin monitoring
      - stop(): Stop monitoring
      - is_running(): Check if active
      - get_events(): Get list of all recorded USB events
    """

    POLL_INTERVAL = 5  # seconds

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable] = None
        self._known_drives: Set[str] = set()
        self._events: List[Dict] = []
        self._lock = threading.Lock()

        # Snapshot current drives on init
        self._known_drives = self._get_removable_drives()

        if WMI_AVAILABLE:
            print("[USB] USB monitor initialized (WMI mode).")
        else:
            print("[USB] USB monitor initialized (drive-letter polling mode).")
            print("[USB] Install 'wmi' package for enhanced device info: pip install wmi")

    def start(self, callback: Callable = None):
        """
        Start USB monitoring.

        Args:
            callback: Function called on USB insertion.
                      Signature: callback(event: dict)
                      event keys: drive_letter, label, event_type, timestamp, device_info
        """
        if self._running:
            return

        self._callback = callback
        self._running = True
        self._known_drives = self._get_removable_drives()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        print("[USB] USB monitoring started.")

    def stop(self):
        """Stop USB monitoring."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        print("[USB] USB monitoring stopped.")

    def is_running(self) -> bool:
        return self._running

    def get_events(self) -> List[Dict]:
        """Get all recorded USB events."""
        with self._lock:
            return list(self._events)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                'running': self._running,
                'events_count': len(self._events),
                'current_drives': list(self._known_drives),
                'wmi_available': WMI_AVAILABLE,
            }

    def _poll_loop(self):
        """Poll for USB drive changes."""
        while self._running:
            try:
                self._check_drives()
            except Exception as e:
                pass  # Silently handle polling errors
            time.sleep(self.POLL_INTERVAL)

    def _check_drives(self):
        """Check for new/removed USB drives."""
        current_drives = self._get_removable_drives()

        # Detect insertions
        new_drives = current_drives - self._known_drives
        for drive in new_drives:
            event = self._build_event(drive, 'inserted')
            with self._lock:
                self._events.append(event)
            print(f"[USB] INSERTED: {drive} ({event.get('label', 'Unknown')})")

            if self._callback:
                try:
                    self._callback(event)
                except Exception:
                    pass

        # Detect removals
        removed_drives = self._known_drives - current_drives
        for drive in removed_drives:
            event = {
                'drive_letter': drive,
                'label': '',
                'event_type': 'removed',
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
                'device_info': '',
            }
            with self._lock:
                self._events.append(event)
            print(f"[USB] REMOVED: {drive}")

        self._known_drives = current_drives

    def _get_removable_drives(self) -> Set[str]:
        """Get set of currently mounted removable drive letters (Windows)."""
        drives = set()
        try:
            if os.name == 'nt':
                # Windows: Check all drive letters
                import ctypes
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for i, letter in enumerate(string.ascii_uppercase):
                    if bitmask & (1 << i):
                        drive_path = f"{letter}:\\"
                        # Check if it's removable (type 2 = DRIVE_REMOVABLE)
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                        if drive_type == 2:  # DRIVE_REMOVABLE
                            drives.add(f"{letter}:")
            else:
                # Linux/Mac: Check /media or /mnt
                for mount_dir in ['/media', '/mnt']:
                    if os.path.isdir(mount_dir):
                        for item in os.listdir(mount_dir):
                            full_path = os.path.join(mount_dir, item)
                            if os.path.ismount(full_path):
                                drives.add(full_path)
        except Exception:
            pass
        return drives

    def _build_event(self, drive: str, event_type: str) -> Dict:
        """Build a USB event dict with device info."""
        label = ''
        device_info = ''

        try:
            if os.name == 'nt':
                # Try to get volume label
                import ctypes
                buf = ctypes.create_unicode_buffer(256)
                ret = ctypes.windll.kernel32.GetVolumeInformationW(
                    f"{drive}\\", buf, 256, None, None, None, None, 0
                )
                if ret:
                    label = buf.value or 'Unknown'

                # Try WMI for detailed device info
                if WMI_AVAILABLE:
                    try:
                        c = wmi.WMI()
                        for disk in c.Win32_LogicalDisk():
                            if disk.DeviceID == drive:
                                label = disk.VolumeName or label
                                device_info = f"Size: {int(disk.Size or 0) // (1024**3)}GB, FS: {disk.FileSystem or 'Unknown'}"
                                break
                    except Exception:
                        pass
        except Exception:
            pass

        return {
            'drive_letter': drive,
            'label': label,
            'event_type': event_type,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'device_info': device_info,
        }
