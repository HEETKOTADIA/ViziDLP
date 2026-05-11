"""
ViziDLP User Risk Scorer
Maintains a sliding 30-minute risk score (0–100) based on detection severity.

Score formula:
  score = min(100, sum(SEVERITY_WEIGHTS[sev] * count) / TIME_DECAY_FACTOR)

Risk bands:
  0-25:   SAFE
  25-50:  ELEVATED
  50-75:  HIGH
  75-100: CRITICAL
"""

import time
from collections import deque
from typing import List, Tuple

from utils.config import SEVERITY_LEVELS


class RiskScorer:
    """
    Calculates a rolling risk score based on detection events within
    a sliding time window.

    Interface:
      - record_event(severity): Record a new detection event
      - get_score(): Get current risk score (0-100)
      - get_risk_band(): Get risk band string ("SAFE"|"ELEVATED"|"HIGH"|"CRITICAL")
    """

    SEVERITY_WEIGHTS = {
        'LOW': 1,
        'MEDIUM': 3,
        'HIGH': 8,
        'CRITICAL': 20,
    }

    TIME_WINDOW = 30 * 60  # 30 minutes in seconds
    TIME_DECAY_FACTOR = 10  # Tunable via config

    RISK_BANDS = [
        (75, "CRITICAL"),
        (50, "HIGH"),
        (25, "ELEVATED"),
        (0, "SAFE"),
    ]

    def __init__(self, time_decay_factor: int = None):
        # Rolling window of (timestamp, severity) events
        self._events: deque = deque()
        if time_decay_factor is not None:
            self.TIME_DECAY_FACTOR = time_decay_factor
        print(f"[RISK] Risk scorer initialized (window={self.TIME_WINDOW}s, "
              f"decay_factor={self.TIME_DECAY_FACTOR}).")

    def record_event(self, severity: str):
        """
        Record a new detection event.

        Args:
            severity: Severity level ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        """
        now = time.time()
        self._events.append((now, severity.upper()))
        self._prune_window(now)

    def get_score(self) -> float:
        """
        Calculate the current risk score (0–100).

        Returns:
            Float risk score clamped to [0, 100]
        """
        now = time.time()
        self._prune_window(now)

        # Count events by severity
        severity_counts = {}
        for ts, sev in self._events:
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Compute weighted sum
        weighted_sum = sum(
            self.SEVERITY_WEIGHTS.get(sev, 1) * count
            for sev, count in severity_counts.items()
        )

        score = weighted_sum / self.TIME_DECAY_FACTOR
        return min(100.0, score)

    def get_risk_band(self) -> str:
        """
        Get the current risk band.

        Returns:
            One of "SAFE", "ELEVATED", "HIGH", "CRITICAL"
        """
        score = self.get_score()
        for threshold, band in self.RISK_BANDS:
            if score >= threshold:
                return band
        return "SAFE"

    def _prune_window(self, now: float):
        """Remove events outside the sliding time window."""
        cutoff = now - self.TIME_WINDOW
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
