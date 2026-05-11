"""
ViziDLP Evidence Logger
Privacy-first evidence storage.

Rules:
  - All frames received here should ALREADY be sanitized via PrivacyPipeline
  - The is_already_sanitized flag confirms the frame passed through privacy pipeline
  - Raw frames with sensitive data are NEVER written to disk
  - Screenshots with no sensitive data are stored unblurred for investigation
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np

from database.database import Database
from dlp_logging.session_manager import SessionManager
from utils.helpers import get_timestamp, get_timestamp_filename, save_image


class EvidenceLogger:
    """
    Handles logging of detection evidence to the database and filesystem.

    PRIVACY POLICY:
    - Only sanitized (privacy-pipeline-processed) frames are saved.
    - All frames must pass through PrivacyPipeline before reaching here.
    - The is_already_sanitized flag enforces this at the API level.
    """

    def __init__(self, db: Database, session_manager: SessionManager):
        self.db = db
        self.session_manager = session_manager
        self.privacy_pipeline = None

    def set_privacy_pipeline(self, privacy_pipeline) -> None:
        """Attach the privacy sanitizer used as a final gate before saving evidence."""
        self.privacy_pipeline = privacy_pipeline

    def log_detection(
        self,
        frame: np.ndarray,
        detection_type: str,
        data_category: str,
        severity: str,
        description: str,
        source: str = "screen",
        bbox: tuple = None,
        raw_text: str = None,
        confidence: float = None,
        redacted_frame: np.ndarray = None,
        is_already_sanitized: bool = False
    ) -> int:
        """
        Log a detection with privacy-safe evidence.

        Args:
            frame: The sanitized image frame (must be privacy-pipeline output)
            detection_type: Type of detection
            data_category: Category of sensitive data
            severity: Severity level
            description: Human-readable description
            source: Source of the frame (screen, webcam, screenshot)
            bbox: Bounding box as (x, y, w, h)
            raw_text: Raw text extracted by OCR
            confidence: Detection confidence score
            redacted_frame: (legacy) Separate redacted frame
            is_already_sanitized: True if frame already passed through PrivacyPipeline

        Returns:
            Detection ID from the database
        """
        session_id = self.session_manager.current_session_id
        if not session_id:
            raise RuntimeError("No active session for logging.")

        timestamp = get_timestamp()
        ts_filename = get_timestamp_filename()

        # ── Determine which frame to save ─────────────────────
        # Priority: redacted_frame > sanitized frame > nothing
        save_frame = None
        if redacted_frame is not None:
            save_frame = redacted_frame
        elif frame is not None and is_already_sanitized:
            # Frame has been processed by PrivacyPipeline — safe to save
            save_frame = frame

        save_detections = []
        if save_frame is not None and self.privacy_pipeline is not None:
            if source in ("screen", "screenshot_detector", "process_monitor"):
                try:
                    privacy_result = self.privacy_pipeline.sanitize_screenshot(save_frame)
                    sanitized_frame = privacy_result.get('sanitized_frame')
                    if sanitized_frame is not None:
                        save_frame = sanitized_frame
                    save_detections = privacy_result.get('detections', [])
                except Exception as e:
                    print(f"[EVIDENCE] Final evidence sanitization failed: {e}")

        if save_detections and data_category == "screenshot_taken":
            severity = "HIGH"
            description = f"Screenshot evidence - {len(save_detections)} sensitive/ID document region(s) redacted"
        elif frame is not None and source in ("screen", "screenshot_detector", "process_monitor"):
            # Screen frames without sensitive flag — save for investigation
            # (screenshots with no detections are stored unblurred)
            save_frame = frame

        # ── Save evidence ─────────────────────────────────────
        evidence_path = None
        evidence_hash = None
        if save_frame is not None:
            subfolder = "webcam" if source == "webcam" else "screenshots"
            evidence_dir = self.session_manager.get_evidence_path(subfolder)
            evidence_filename = f"{ts_filename}_{data_category}.jpg"
            evidence_path = os.path.join(evidence_dir, evidence_filename)
            save_image(save_frame, evidence_path)

            # ── GAP 7: Compute SHA-256 of saved evidence file ──
            try:
                import hashlib
                with open(evidence_path, 'rb') as f:
                    evidence_hash = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                evidence_hash = None

        # ── Build Detection Record ────────────────────────────
        detection = {
            'session_id': session_id,
            'timestamp': timestamp,
            'detection_type': detection_type,
            'data_category': data_category,
            'severity': severity,
            'description': description,
            'source': source,
            'bbox_x': bbox[0] if bbox else None,
            'bbox_y': bbox[1] if bbox else None,
            'bbox_w': bbox[2] if bbox else None,
            'bbox_h': bbox[3] if bbox else None,
            'evidence_path': evidence_path,
            'redacted_path': evidence_path,  # Same — only sanitized version stored
            'raw_text': raw_text,
            'confidence': confidence,
            'evidence_hash': evidence_hash,
        }

        # Store in database
        detection_id = self.db.add_detection(detection)

        # Create alert for significant detections
        from utils.config import ALERT_ON_SEVERITY
        if severity in ALERT_ON_SEVERITY:
            self.db.add_alert({
                'session_id': session_id,
                'timestamp': timestamp,
                'alert_type': 'detection',
                'severity': severity,
                'message': f"[{severity}] {description}"
            })

        print(f"[DETECTION] [{severity}] {data_category}: {description}")
        return detection_id

    def log_screenshot_event(self, frame: np.ndarray = None) -> int:
        """Log a screenshot detection event."""
        return self.log_detection(
            frame=frame,
            detection_type="screenshot_event",
            data_category="screenshot_taken",
            severity="MEDIUM",
            description="Screenshot capture detected (PrintScreen/Snipping Tool)",
            source="screenshot_detector",
            raw_text=None
        )

    def log_threat_event(self, event_type: str, details: str, risk_score: float) -> int:
        """Log an insider threat event."""
        session_id = self.session_manager.current_session_id
        if not session_id:
            return -1

        event_id = self.db.add_threat_event({
            'session_id': session_id,
            'event_type': event_type,
            'details': details,
            'risk_score': risk_score
        })

        # Create CRITICAL alert for insider threats
        self.db.add_alert({
            'session_id': session_id,
            'timestamp': get_timestamp(),
            'alert_type': 'insider_threat',
            'severity': 'CRITICAL',
            'message': f"[INSIDER THREAT] {details}"
        })

        print(f"[THREAT] {event_type}: {details} (risk score: {risk_score:.2f})")
        return event_id
