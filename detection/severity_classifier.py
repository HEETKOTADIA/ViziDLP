"""
ViziDLP Severity Classifier
Classifies incident severity based on detection type and context.
"""

from typing import Dict, List
from utils.config import SEVERITY_MAP, SEVERITY_LEVELS


class SeverityClassifier:
    """Classifies detection severity and escalates based on context."""

    def __init__(self):
        self.severity_map = SEVERITY_MAP
        self.severity_levels = SEVERITY_LEVELS
        print("[SEVERITY] Severity classifier initialized.")

    def classify(self, detection_type: str) -> str:
        """Get the default severity for a detection type."""
        return self.severity_map.get(detection_type, "MEDIUM")

    def classify_batch(self, detections: List[Dict]) -> str:
        """
        Classify overall severity for a batch of detections.
        Multiple detections escalate the severity.

        Args:
            detections: List of detection dicts

        Returns:
            Overall severity level string
        """
        if not detections:
            return "LOW"

        # Get the highest individual severity
        max_sev = "LOW"
        for det in detections:
            det_sev = det.get('severity', self.classify(det.get('type', '')))
            if self.severity_levels.get(det_sev, 0) > self.severity_levels.get(max_sev, 0):
                max_sev = det_sev

        # Escalate based on count
        count = len(detections)
        if count >= 5:
            return "CRITICAL"
        elif count >= 3 and self.severity_levels.get(max_sev, 0) >= 2:
            return self._escalate(max_sev)

        return max_sev

    def _escalate(self, current: str) -> str:
        """Escalate severity by one level."""
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        idx = order.index(current) if current in order else 0
        return order[min(idx + 1, len(order) - 1)]

    def get_severity_color(self, severity: str) -> str:
        """Get display color for a severity level."""
        colors = {
            "LOW": "#4caf50",
            "MEDIUM": "#ff9800",
            "HIGH": "#f44336",
            "CRITICAL": "#9c27b0"
        }
        return colors.get(severity, "#757575")
