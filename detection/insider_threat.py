"""
ViziDLP Insider Threat Detector
Detects suspicious user behavior patterns that may indicate data exfiltration.
"""

import time
import threading
from collections import deque
from typing import Callable, Dict, List, Optional

from utils.config import (
    INSIDER_THREAT_SCREENSHOT_THRESHOLD,
    INSIDER_THREAT_DETECTION_THRESHOLD,
    INSIDER_THREAT_TIME_WINDOW_SECONDS
)


class InsiderThreatDetector:
    """Monitors for suspicious behavior patterns."""

    def __init__(self):
        self.time_window = INSIDER_THREAT_TIME_WINDOW_SECONDS
        self.screenshot_threshold = INSIDER_THREAT_SCREENSHOT_THRESHOLD
        self.detection_threshold = INSIDER_THREAT_DETECTION_THRESHOLD

        # Rolling event windows
        self._screenshot_times = deque()
        self._detection_times = deque()
        self._lock = threading.Lock()

        self.on_threat_callback: Optional[Callable] = None
        self.threat_events: List[Dict] = []
        print("[THREAT] Insider threat detector initialized.")

    def set_callback(self, callback: Callable):
        """Set callback for when a threat is detected."""
        self.on_threat_callback = callback

    def record_screenshot(self):
        """Record a screenshot event and check for suspicious frequency."""
        now = time.time()
        with self._lock:
            self._screenshot_times.append(now)
            self._cleanup(self._screenshot_times)

            count = len(self._screenshot_times)
            if count >= self.screenshot_threshold:
                self._trigger_threat(
                    "excessive_screenshots",
                    f"{count} screenshots in {self.time_window}s window",
                    min(1.0, count / (self.screenshot_threshold * 2))
                )

    def record_detection(self, detection_type: str = ""):
        """Record a sensitive data detection and check frequency."""
        now = time.time()
        with self._lock:
            self._detection_times.append(now)
            self._cleanup(self._detection_times)

            count = len(self._detection_times)
            if count >= self.detection_threshold:
                self._trigger_threat(
                    "excessive_detections",
                    f"{count} sensitive data detections in {self.time_window}s window",
                    min(1.0, count / (self.detection_threshold * 2))
                )

    def _cleanup(self, queue: deque):
        """Remove events outside the time window."""
        cutoff = time.time() - self.time_window
        while queue and queue[0] < cutoff:
            queue.popleft()

    def _trigger_threat(self, event_type: str, details: str, risk_score: float):
        """Trigger an insider threat alert."""
        event = {
            'event_type': event_type,
            'details': details,
            'risk_score': risk_score,
            'timestamp': time.time()
        }
        self.threat_events.append(event)
        print(f"[THREAT] WARNING - INSIDER THREAT: {details} (risk: {risk_score:.2f})")

        if self.on_threat_callback:
            self.on_threat_callback(event_type, details, risk_score)

    def get_risk_level(self) -> str:
        """Get current overall risk level."""
        with self._lock:
            self._cleanup(self._screenshot_times)
            self._cleanup(self._detection_times)

            ss_ratio = len(self._screenshot_times) / max(1, self.screenshot_threshold)
            det_ratio = len(self._detection_times) / max(1, self.detection_threshold)
            combined = max(ss_ratio, det_ratio)

            if combined >= 1.0:
                return "CRITICAL"
            elif combined >= 0.7:
                return "HIGH"
            elif combined >= 0.4:
                return "MEDIUM"
            return "LOW"
