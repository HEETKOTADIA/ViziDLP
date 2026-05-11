"""
ViziDLP Screen Recording Detector
Detects screen recording software running in the background using psutil process monitoring.
"""

import threading
import time
from typing import Callable, List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class ScreenRecordingDetector:
    """Monitors running processes for known screen recording software."""

    # Known screen recording process names (lowercase)
    # NOTE: gamebarpresencewriter.exe is excluded because it is an always-on
    # Windows 10/11 background service. gamebar.exe is kept because it only
    # runs when the user actively opens Game Bar (Win+G).
    RECORDING_PROCESSES = {
        'obs64.exe': 'OBS Studio',
        'obs.exe': 'OBS Studio',
        'obs32.exe': 'OBS Studio',
        'streamlabs obs.exe': 'Streamlabs OBS',
        'gamebar.exe': 'Xbox Game Bar',
        'nvidia share.exe': 'Nvidia ShadowPlay',
        'nvspcaps64.exe': 'Nvidia ShadowPlay',
        'shadowplay.exe': 'Nvidia ShadowPlay',
        'sharex.exe': 'ShareX',
        'camtasia.exe': 'Camtasia',
        'bandicam.exe': 'Bandicam',
        'fraps.exe': 'Fraps',
        'screencastomatic.exe': 'Screencast-O-Matic',
        'loom.exe': 'Loom',
    }

    def __init__(self):
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.on_recording_detected: Optional[Callable] = None
        self._detected_processes = set()
        self._scan_interval = 10  # seconds between scans
        self._detection_count = 0

        if not PSUTIL_AVAILABLE:
            print("[RECORDING] WARNING: psutil not installed. Screen recording detection disabled.")
            print("[RECORDING] Install with: pip install psutil")
        else:
            print("[RECORDING] Screen recording detector initialized.")

    def start(self, on_detected: Callable = None):
        """Start monitoring for screen recording processes."""
        if not PSUTIL_AVAILABLE:
            return

        self.on_recording_detected = on_detected
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[RECORDING] Screen recording monitor started.")

    def stop(self):
        """Stop monitoring."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)
        print("[RECORDING] Screen recording monitor stopped.")

    def _monitor_loop(self):
        """Background loop that scans processes periodically."""
        while self.running:
            try:
                self._scan_processes()
            except Exception as e:
                print(f"[RECORDING] Scan error: {e}")
            time.sleep(self._scan_interval)

    def _scan_processes(self):
        """Scan running processes for known recording software."""
        currently_running = set()

        for proc in psutil.process_iter(['name']):
            try:
                name = proc.info['name'].lower() if proc.info['name'] else ''
                if name in self.RECORDING_PROCESSES:
                    currently_running.add(name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Detect newly started recording software
        new_detections = currently_running - self._detected_processes

        for proc_name in new_detections:
            app_name = self.RECORDING_PROCESSES[proc_name]
            self._detection_count += 1

            detection = {
                'process_name': proc_name,
                'app_name': app_name,
                'event_type': 'SCREEN_RECORDING_DETECTED',
                'severity': 'CRITICAL',
                'description': f"Screen recording software detected: {app_name} ({proc_name})"
            }

            print(f"[RECORDING] WARNING - DETECTED: {app_name} ({proc_name})")

            if self.on_recording_detected:
                self.on_recording_detected(detection)

        self._detected_processes = currently_running

    def get_active_recorders(self) -> List[str]:
        """Get list of currently active recording processes."""
        return [self.RECORDING_PROCESSES.get(p, p) for p in self._detected_processes]

    def get_detection_count(self) -> int:
        """Get total detection count."""
        return self._detection_count

    def is_running(self) -> bool:
        """Check if the monitor is running."""
        return self.running and self.thread is not None and self.thread.is_alive()
