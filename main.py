"""
ViziDLP — AI Powered Visual Data Loss Prevention System
Main pipeline orchestrator.

ALL evidence routes through the centralized PrivacyPipeline:
  - Screenshots: OCR → regex → blur ONLY sensitive regions → save
  - Webcam: face blur (always) → OCR → regex → blur sensitive → save
  - Screen recording: process scan → alert
  - Device detections (laptop, monitor): log only, NO blur
"""

import os
import sys
import time
import signal
import threading
import cv2

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── Import all modules ──────────────────────────────────────
from database.database import Database
from dlp_logging.session_manager import SessionManager
from dlp_logging.evidence_logger import EvidenceLogger
from core.ocr_engine import OCREngine
from core.object_detector import ObjectDetector
from core.redaction import RedactionEngine
from core.screen_monitor import ScreenMonitor
from core.webcam_monitor import WebcamMonitor
from core.screenshot_detector import ScreenshotDetector
from core.phone_detector import PhoneDetector
from core.screen_recording_detector import ScreenRecordingDetector
from core.privacy_pipeline import PrivacyPipeline
from core.alert_dispatcher import AlertDispatcher
from core.face_recognizer import FaceRecognizer
from core.policy_engine import PolicyEngine
from core.clipboard_monitor import ClipboardMonitor
from core.network_monitor import NetworkMonitor
from core.file_scanner import FileScanner
from core.usb_monitor import USBMonitor
from detection.pattern_detector import PatternDetector
from detection.severity_classifier import SeverityClassifier
from detection.insider_threat import InsiderThreatDetector
from detection.risk_scorer import RiskScorer
from detection.compliance_tagger import ComplianceTagger
from dashboard.app import create_app
from utils.config import (
    SCREEN_MONITOR_ENABLED,
    WEBCAM_MONITOR_ENABLED,
    FLASK_HOST,
    FLASK_PORT,
    DESKTOP_NOTIFICATIONS_ENABLED,
    DETECTION_COOLDOWN_SECONDS,
    PHONE_DETECTION_ENABLED,
    CLIPBOARD_MONITOR_ENABLED,
    NETWORK_MONITOR_ENABLED,
    FILE_SCAN_ENABLED,
    FILE_SCAN_DIR,
    USB_MONITOR_ENABLED,
)
from utils.helpers import compute_image_hash, resize_for_processing


class ViziDLPPipeline:
    """
    Main processing pipeline that orchestrates all ViziDLP components.

    ALL evidence passes through PrivacyPipeline before saving:
      Screenshot: capture → PrivacyPipeline.sanitize_screenshot() → save
      Webcam:     capture → PrivacyPipeline.sanitize_webcam() → save
      Devices:    detect → log only (no blur)
    """

    def __init__(self):
        print("=" * 60)
        print("  ViziDLP — AI Powered Visual Data Loss Prevention")
        print("=" * 60)
        print()

        # ─── Database ────────────────────────────────────────────
        print("[INIT] Initializing database...")
        self.db = Database()

        # ─── Session Manager (timestamp-based) ───────────────────
        print("[INIT] Creating session manager...")
        self.session_manager = SessionManager(self.db)

        # ─── Evidence Logger ─────────────────────────────────────
        print("[INIT] Creating evidence logger...")
        self.evidence_logger = EvidenceLogger(self.db, self.session_manager)

        # ─── Detection Engines ───────────────────────────────────
        print("[INIT] Loading OCR engine...")
        self.ocr_engine = OCREngine()

        print("[INIT] Loading object detector...")
        self.object_detector = ObjectDetector()

        print("[INIT] Loading redaction engine...")
        self.redaction_engine = RedactionEngine()

        print("[INIT] Loading pattern detector...")
        self.pattern_detector = PatternDetector()

        print("[INIT] Loading severity classifier...")
        self.severity_classifier = SeverityClassifier()

        print("[INIT] Initializing insider threat detector...")
        self.insider_threat = InsiderThreatDetector()
        self.insider_threat.set_callback(self._on_threat_detected)

        # ─── Monitors ───────────────────────────────────────────
        print("[INIT] Initializing monitors...")
        self.screen_monitor = ScreenMonitor()
        self.webcam_monitor = WebcamMonitor()
        self.screenshot_detector = ScreenshotDetector()

        print("[INIT] Initializing phone detector...")
        self.phone_detector = PhoneDetector()
        self.phone_detector.set_callback(self._on_phone_detected)

        print("[INIT] Initializing screen recording detector...")
        self.screen_recording_detector = ScreenRecordingDetector()

        # ─── Privacy Pipeline (centralized sanitizer) ────────────
        print("[INIT] Initializing privacy pipeline...")
        self.privacy_pipeline = PrivacyPipeline(
            ocr_engine=self.ocr_engine,
            pattern_detector=self.pattern_detector,
            redaction_engine=self.redaction_engine,
            phone_detector=self.phone_detector
        )
        self.evidence_logger.set_privacy_pipeline(self.privacy_pipeline)

        # ─── Alert Dispatcher (Cloud Monitoring) ──────────────────
        print("[INIT] Initializing alert dispatcher...")
        self.alert_dispatcher = AlertDispatcher()

        # ─── Face Recognizer ──────────────────────────────────────
        print("[INIT] Initializing face recognizer...")
        self.face_recognizer = FaceRecognizer()

        # ─── Policy Engine (GAP 1) ────────────────────────────────
        print("[INIT] Initializing policy engine...")
        self.policy_engine = PolicyEngine()

        # ─── Clipboard Monitor (GAP 3) ────────────────────────────
        print("[INIT] Initializing clipboard monitor...")
        self.clipboard_monitor = ClipboardMonitor()

        # ─── Network Monitor (GAP 4) ──────────────────────────────
        print("[INIT] Initializing network monitor...")
        self.network_monitor = NetworkMonitor()

        # ─── Risk Scorer (GAP 6) ──────────────────────────────────
        print("[INIT] Initializing risk scorer...")
        self.risk_scorer = RiskScorer()

        # ─── Compliance Tagger ────────────────────────────────────
        print("[INIT] Initializing compliance tagger...")
        self.compliance_tagger = ComplianceTagger()

        # ─── File Scanner ─────────────────────────────────────────
        print("[INIT] Initializing file scanner...")
        self.file_scanner = FileScanner(watch_dir=FILE_SCAN_DIR if FILE_SCAN_ENABLED else None)

        # ─── USB Monitor ──────────────────────────────────────────
        print("[INIT] Initializing USB monitor...")
        self.usb_monitor = USBMonitor()

        # ─── State ───────────────────────────────────────────────
        self.running = False
        self.monitoring = False
        self._last_hash = None
        self._last_detection_time = 0.0
        self._frame_count = 0
        self._detection_lock = threading.Lock()
        self._phone_detection_count = 0
        self._phone_poll_thread = None

        print()
        print("[INIT] All components initialized successfully.")
        print()

    def start(self):
        """Start the entire ViziDLP pipeline."""
        print("[PIPELINE] Starting ViziDLP pipeline...")

        # Create a new timestamp-based session
        session_id = self.session_manager.start_new_session()

        # Mark running
        self.running = True
        self.monitoring = True

        # Thread 1: Screen monitoring
        if SCREEN_MONITOR_ENABLED:
            self.screen_monitor.start(on_frame=self._process_frame)

        # Thread 2: Webcam capture (low frequency, no processing callback)
        if WEBCAM_MONITOR_ENABLED:
            self.webcam_monitor.start()

        # Thread 3: Phone detection polling (only processes when phone found)
        if PHONE_DETECTION_ENABLED and WEBCAM_MONITOR_ENABLED:
            self._phone_poll_thread = threading.Thread(
                target=self._phone_detection_loop, daemon=True
            )
            self._phone_poll_thread.start()

        # Thread 4: Screenshot detection (keyboard shortcuts)
        self.screenshot_detector.start(on_screenshot=self._on_screenshot)

        # Thread 5: Screen recording process scanner
        self.screen_recording_detector.start(on_detected=self._on_recording_detected)

        # Thread 6: Clipboard monitor (GAP 3)
        if CLIPBOARD_MONITOR_ENABLED:
            self.clipboard_monitor.start(callback=self._on_sensitive_clipboard)

        # Thread 7: Network monitor (GAP 4)
        if NETWORK_MONITOR_ENABLED:
            self.network_monitor.start(callback=self._on_suspicious_connection)

        # Thread 8: File scanner
        if FILE_SCAN_ENABLED and FILE_SCAN_DIR:
            self.file_scanner.start(callback=self._on_file_detection)

        # Thread 9: USB monitor
        if USB_MONITOR_ENABLED:
            self.usb_monitor.start(callback=self._on_usb_event)

        print(f"[PIPELINE] Monitoring active (session: {session_id})")
        print(f"[PIPELINE] Dashboard: http://localhost:{FLASK_PORT}")
        print()

        # Start dashboard (blocks on main thread)
        self._start_dashboard()

    def stop(self):
        """Stop all monitoring and shut down."""
        print("[PIPELINE] Stopping ViziDLP pipeline...")
        self.running = False
        self.monitoring = False

        self.screen_monitor.stop()
        self.webcam_monitor.stop()
        self.screenshot_detector.stop()
        self.screen_recording_detector.stop()
        self.clipboard_monitor.stop()
        self.network_monitor.stop()
        self.file_scanner.stop()
        self.usb_monitor.stop()
        self.session_manager.end_session()

        print("[PIPELINE] ViziDLP stopped.")

    def _start_dashboard(self):
        """Start the Flask dashboard (blocking)."""
        app = create_app(self.db, self)
        try:
            app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False)
        except KeyboardInterrupt:
            self.stop()

    # ─── Phone Detection Polling ─────────────────────────────────

    def _phone_detection_loop(self):
        """
        Poll webcam frames for phone detection.
        Only processes frames — does nothing if no phone is found.
        Also runs face detection on webcam frames.
        """
        while self.running:
            try:
                frame = self.webcam_monitor.get_latest_frame()
                if frame is not None:
                    self.phone_detector.process_webcam_frame(frame)

                    # Face detection on webcam frames
                    if self.face_recognizer.available:
                        face_results = self.face_recognizer.detect_faces(frame)
                        for face in face_results:
                            if face['matched']:
                                print(f"[FACE] Known person detected: {face['name']} (conf={face['confidence']})")
                            else:
                                print(f"[FACE] Unknown face detected")
            except Exception as e:
                print(f"[PHONE] Poll error: {e}")

            time.sleep(1)  # Check every 1 second for responsive phone detection

    def _on_phone_detected(self, detection_info: dict, privacy_frame):
        """
        Handle phone detection event.
        The privacy_frame has faces already blurred by phone_detector.
        Route it through PrivacyPipeline.sanitize_webcam() for full sanitization.
        """
        self._phone_detection_count += 1

        # Run through privacy pipeline (face blur + OCR redaction)
        sanitized = self.privacy_pipeline.sanitize_webcam(privacy_frame)

        self.evidence_logger.log_detection(
            frame=sanitized['sanitized_frame'],
            detection_type="phone_camera_exfiltration",
            data_category="phone_camera_exfiltration",
            severity="CRITICAL",
            description=detection_info['description'],
            source="webcam",
            bbox=detection_info.get('bbox'),
            confidence=detection_info.get('confidence'),
            is_already_sanitized=True  # Frame already passed through privacy pipeline
        )

        self.alert_dispatcher.dispatch(
            detection_type="phone_camera_exfiltration",
            severity="CRITICAL",
            description=detection_info['description'],
            session_id=self.session_manager.current_session_id,
            confidence=detection_info.get('confidence', 0.0)
        )

        self.insider_threat.record_detection('phone_camera_exfiltration')

        self._send_notification(
            "CRITICAL: Phone Camera Detected",
            "Possible phone camera data exfiltration detected!"
        )

    # ─── Screen Recording Detection ──────────────────────────────

    def _on_recording_detected(self, detection: dict):
        """Handle screen recording detection."""
        # Get screen frame and sanitize it
        frame = self.screen_monitor.get_latest_frame()
        sanitized_frame = None
        if frame is not None:
            result = self.privacy_pipeline.sanitize_screenshot(frame)
            sanitized_frame = result['sanitized_frame']

        self.evidence_logger.log_detection(
            frame=sanitized_frame,
            detection_type="screen_recording_detected",
            data_category="screen_recording_detected",
            severity="CRITICAL",
            description=detection['description'],
            source="process_monitor",
            is_already_sanitized=True
        )

        self.alert_dispatcher.dispatch(
            detection_type="screen_recording_detected",
            severity="CRITICAL",
            description=detection['description'],
            session_id=self.session_manager.current_session_id,
            confidence=0.0
        )

        self.insider_threat.record_detection('screen_recording_detected')
        self._send_notification("CRITICAL: Screen Recording Detected", detection['description'])

    # ─── Main Frame Processing Pipeline ──────────────────────────

    def _process_frame(self, frame, source: str = "screen"):
        """
        Main processing pipeline for screen frames.
        ALL frames go through PrivacyPipeline.sanitize_screenshot().

        Pipeline:
        1. Deduplicate frames using image hashing
        2. Run through PrivacyPipeline (orientation → OCR → regex → region blur)
        3. Run object detection (devices log only, no blur)
        4. Log evidence (only sanitized frame saved)
        """
        if not self.running:
            return

        self._frame_count += 1

        with self._detection_lock:
            try:
                # ── Step 1: Deduplicate ───────────────────────
                # Use a coarser hash (downsample first) so minor webcam noise
                # doesn't lock out reprocessing of a static card
                small = cv2.resize(frame, (64, 64)) if frame is not None else frame
                frame_hash = compute_image_hash(small)
                if frame_hash == self._last_hash:
                    return
                self._last_hash = frame_hash

                # Cooldown
                now = time.time()
                if now - self._last_detection_time < DETECTION_COOLDOWN_SECONDS:
                    return

                # ── Step 2: Preprocess ────────────────────────
                processed = resize_for_processing(frame)

                # ── Step 3: Privacy Pipeline ──────────────────
                # Runs: orientation correction → OCR → regex → blur ONLY sensitive regions
                privacy_result = self.privacy_pipeline.sanitize_screenshot(processed)
                sanitized_frame = privacy_result['sanitized_frame']
                pattern_detections = privacy_result['detections']

                # ── Step 4: Object Detection (devices) ────────
                object_detections = []
                if self.object_detector.available:
                    full_text = privacy_result.get('ocr_text', '')
                    raw_object_dets = self.object_detector.detect_documents(processed, full_text)

                    for det in raw_object_dets:
                        if det.get('is_sensitive'):
                            # Check if this is a device (laptop/monitor) → log only, no blur
                            if self.privacy_pipeline.is_device_detection(det.get('category', '')):
                                # Device detection: log normally, DO NOT blur
                                self.evidence_logger.log_detection(
                                    frame=sanitized_frame,
                                    detection_type="device_detection",
                                    data_category=det['category'],
                                    severity="LOW",
                                    description=f"{det['class_name']} detected (device — no blur needed)",
                                    source=source,
                                    bbox=det.get('bbox'),
                                    confidence=det['confidence'],
                                    is_already_sanitized=True
                                )
                            else:
                                object_detections.append(det)

                # ── Step 5: Log pattern detections ────────────
                for det in pattern_detections:
                    severity = self.severity_classifier.classify(det['type'])
                    self.evidence_logger.log_detection(
                        frame=sanitized_frame,
                        detection_type="ocr_pattern",
                        data_category=det['type'],
                        severity=severity,
                        description=det['description'],
                        source=source,
                        bbox=det.get('bbox'),
                        raw_text=det.get('matched_text', ''),
                        confidence=det.get('confidence'),
                        is_already_sanitized=True
                    )
                    self.insider_threat.record_detection(det['type'])

                    self.alert_dispatcher.dispatch(
                        detection_type=det['type'],
                        severity=severity,
                        description=det['description'],
                        session_id=self.session_manager.current_session_id,
                        confidence=det.get('confidence', 0.0)
                    )

                # ── Step 6: Log sensitive object detections ───
                for det in object_detections:
                    severity = self.severity_classifier.classify(det['category'])
                    self.evidence_logger.log_detection(
                        frame=sanitized_frame,
                        detection_type="object_detection",
                        data_category=det['category'],
                        severity=severity,
                        description=f"{det['class_name']} detected (confidence: {det['confidence']:.2f})",
                        source=source,
                        bbox=det.get('bbox'),
                        confidence=det['confidence'],
                        is_already_sanitized=True
                    )
                    self.insider_threat.record_detection(det['category'])

                # ── Step 6b: Policy Engine evaluation (GAP 1) ──
                all_detections = pattern_detections + object_detections
                for det in all_detections:
                    try:
                        self.policy_engine.evaluate(det)
                    except NotImplementedError:
                        pass  # lock_screen stub — intentional
                    except Exception:
                        pass  # Policy evaluation failure is non-critical

                # ── Step 6c: Risk scoring (GAP 6) ─────────────
                for det in all_detections:
                    det_severity = det.get('severity') or self.severity_classifier.classify(
                        det.get('type') or det.get('category', '')
                    )
                    self.risk_scorer.record_event(det_severity)

                # ── Step 7: Escalate if multiple detections ───
                if len(all_detections) >= 3:
                    self._send_notification(
                        "CRITICAL: Multiple Sensitive Data",
                        f"{len(all_detections)} sensitive items found in single frame!"
                    )

                if all_detections:
                    self._last_detection_time = now

            except Exception as e:
                print(f"[PIPELINE] Frame processing error: {e}")

    def _on_screenshot(self, method: str):
        """
        Handle screenshot detection events.
        Route through PrivacyPipeline BEFORE saving.

        Pipeline:
        1. Capture current screen
        2. Run PrivacyPipeline.sanitize_screenshot()
        3. Save ONLY sanitized evidence
        """
        print(f"[PIPELINE] Screenshot detected via {method}")

        frame = self.screen_monitor.get_latest_frame()
        self.insider_threat.record_screenshot()

        if frame is not None:
            processed = resize_for_processing(frame)

            # Route through privacy pipeline
            privacy_result = self.privacy_pipeline.sanitize_screenshot(processed)
            sanitized = privacy_result['sanitized_frame']
            detections = privacy_result['detections']

            # Determine severity
            if detections:
                severity = "HIGH"
                desc = f"Screenshot via {method} — {len(detections)} sensitive items redacted"
            else:
                severity = "MEDIUM"
                desc = f"Screenshot via {method} — no sensitive data (saved unblurred)"

            # Log with sanitized frame (sensitive regions blurred, rest intact)
            self.evidence_logger.log_detection(
                frame=sanitized,
                detection_type="screenshot_event",
                data_category="screenshot_taken",
                severity=severity,
                description=desc,
                source="screenshot_detector",
                is_already_sanitized=True
            )

            # Log individual detections
            for det in detections:
                det_severity = self.severity_classifier.classify(det['type'])
                self.evidence_logger.log_detection(
                    frame=sanitized,
                    detection_type="screenshot_sensitive_data",
                    data_category=det['type'],
                    severity=det_severity,
                    description=f"[Screenshot] {det['description']}",
                    source="screenshot_detector",
                    bbox=det.get('bbox'),
                    raw_text=det.get('matched_text', ''),
                    is_already_sanitized=True
                )
        else:
            self.evidence_logger.log_screenshot_event(frame)

        self._send_notification("Screenshot Detected", f"A screenshot was taken using {method}")

    def _on_threat_detected(self, event_type: str, details: str, risk_score: float):
        """Handle insider threat detection."""
        self.evidence_logger.log_threat_event(event_type, details, risk_score)
        self._send_notification("Insider Threat Alert", details)

    def _send_notification(self, title: str, message: str):
        """Send a desktop notification."""
        if not DESKTOP_NOTIFICATIONS_ENABLED:
            return
        try:
            from plyer import notification
            notification.notify(
                title=f"ViziDLP: {title}",
                message=message,
                app_name="ViziDLP",
                timeout=5
            )
        except Exception:
            pass  # Notification failure is non-critical

    # ─── Clipboard / Network Monitor Callbacks ─────────────────

    def _on_sensitive_clipboard(self, detections: list, text_preview: str):
        """Handle sensitive clipboard detection (GAP 3)."""
        desc = f"Clipboard contains sensitive data: {text_preview}"
        categories = [d.get('type', 'unknown') for d in detections]
        print(f"[CLIPBOARD] Sensitive data detected: {categories}")

        self.evidence_logger.log_detection(
            frame=None,
            detection_type="clipboard_sensitive_data",
            data_category=categories[0] if categories else "unknown",
            severity=detections[0].get('severity', 'HIGH') if detections else 'HIGH',
            description=desc,
            source="clipboard",
            is_already_sanitized=True
        )

        # Also run policy engine on clipboard detections
        for det in detections:
            try:
                self.policy_engine.evaluate(det)
            except NotImplementedError:
                pass
            except Exception:
                pass

    def _on_suspicious_connection(self, conn_info: dict):
        """Handle suspicious network connection detection (GAP 4)."""
        desc = (f"Suspicious connection: {conn_info['process_name']} "
                f"(PID {conn_info['pid']}) → {conn_info['remote_ip']}:{conn_info['remote_port']} "
                f"[{conn_info['matched_rule']}]")

        self.evidence_logger.log_detection(
            frame=None,
            detection_type="suspicious_network_connection",
            data_category="suspicious_network_connection",
            severity="HIGH",
            description=desc,
            source="network_monitor",
            is_already_sanitized=True
        )

    # ─── File Scanner / USB Callbacks ───────────────────────────

    def _on_file_detection(self, detections: list, file_path: str):
        """Handle sensitive data found in scanned files."""
        import os
        filename = os.path.basename(file_path)
        print(f"[FILE-DLP] Sensitive data in file: {filename} ({len(detections)} detection(s))")

        for det in detections:
            # Tag with compliance frameworks
            self.compliance_tagger.tag_detection(det)

            severity = det.get('severity', 'HIGH')
            self.evidence_logger.log_detection(
                frame=None,
                detection_type="file_scan_detection",
                data_category=det.get('type', 'unknown'),
                severity=severity,
                description=f"File: {filename} [{det.get('location', '')}] - {det.get('description', '')}",
                source="file_scan",
                is_already_sanitized=True
            )
            self.risk_scorer.record_event(severity)

    def _on_usb_event(self, event: dict):
        """Handle USB device insertion."""
        desc = (f"USB {event['event_type']}: {event['drive_letter']} "
                f"({event.get('label', 'Unknown')}) {event.get('device_info', '')}")
        print(f"[USB] Alert: {desc}")

        self.evidence_logger.log_detection(
            frame=None,
            detection_type="usb_device_event",
            data_category="usb_insertion",
            severity="HIGH",
            description=desc,
            source="usb_monitor",
            is_already_sanitized=True
        )

    def get_status(self) -> dict:
        """Get current pipeline status for the dashboard API."""
        return {
            'monitoring': self.monitoring,
            'screen_active': self.screen_monitor.is_running(),
            'webcam_active': self.webcam_monitor.is_running(),
            'screenshot_detection': self.screenshot_detector.is_running(),
            'phone_detection': self.phone_detector.is_available(),
            'phone_detections': self._phone_detection_count,
            'recording_detection': self.screen_recording_detector.is_running(),
            'active_recorders': self.screen_recording_detector.get_active_recorders(),
            'session_id': self.session_manager.current_session_id,
            'session_number': self.session_manager.session_number,
            'frames_processed': self._frame_count,
            'screenshots_detected': self.screenshot_detector.get_screenshot_count(),
            'risk_level': self.insider_threat.get_risk_level(),
            'risk_score': self.risk_scorer.get_score(),
            'risk_band': self.risk_scorer.get_risk_band(),
            'clipboard_monitor': self.clipboard_monitor.is_running(),
            'network_monitor': self.network_monitor.is_running(),
            'file_scanner': self.file_scanner.is_running(),
            'usb_monitor': self.usb_monitor.is_running(),
            'privacy_pipeline': True,
        }


# ─── Entry Point ──────────────────────────────────────────────

def main():
    pipeline = ViziDLPPipeline()

    def signal_handler(sig, frame):
        print("\n[PIPELINE] Shutting down...")
        pipeline.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        pipeline.start()
    except KeyboardInterrupt:
        pipeline.stop()


if __name__ == "__main__":
    main()
