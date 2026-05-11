"""
ViziDLP — Smoke Test (Enhanced)
Verifies all module imports, initialization, privacy pipeline,
new PII patterns, keyword detection, and basic functionality.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 50)
print("  ViziDLP Import & Core Test")
print("=" * 50)
print()

# Test 1: Database
print("[TEST 1] Database...")
from database.database import Database
db = Database()
print(f"  OK - DB at: {db.db_path}")

# Test 2: Session Manager (timestamp-based)
print("[TEST 2] Session Manager...")
from dlp_logging.session_manager import SessionManager
sm = SessionManager(db)
sid = sm.start_new_session()
assert sid.startswith("session_"), "Session ID must be timestamp-based"
print(f"  OK - Session: {sid}")

# Test 3: Pattern Detector — Existing Patterns
print("[TEST 3] Pattern Detector (existing)...")
from detection.pattern_detector import PatternDetector
pd = PatternDetector()
test_text = "My PAN is ABCDE1234F and phone 9876543210 email test@example.com"
results = pd.detect(test_text)
print(f"  OK - Found {len(results)} patterns:")
for r in results:
    print(f"    - {r['type']}: {r['masked_text']} ({r['severity']})")

pan_results = [r for r in results if r['type'] == 'pan_number']
assert len(pan_results) > 0, "PAN should be detected"
assert pan_results[0]['severity'] == 'HIGH', f"PAN should be HIGH"
print("  OK - PAN severity is HIGH")

# Test 3b: New PII Patterns — DOB
print("[TEST 3b] DOB Pattern...")
dob_text = "Date of Birth: 15/06/1990"
dob_results = pd.detect(dob_text)
dob_matches = [r for r in dob_results if r['type'] == 'dob']
assert len(dob_matches) > 0, "DOB should be detected"
assert dob_matches[0]['severity'] == 'MEDIUM'
print(f"  OK - DOB detected: {dob_matches[0]['masked_text']}")

# Test 3c: New PII Patterns — Driver Licence
print("[TEST 3c] Driver Licence Pattern...")
dl_text = "Licence No: DL0420110012345"
dl_results = pd.detect(dl_text)
dl_matches = [r for r in dl_results if r['type'] == 'driver_licence_number']
assert len(dl_matches) > 0, "Driver Licence should be detected"
assert dl_matches[0]['severity'] == 'HIGH'
print(f"  OK - DL detected: {dl_matches[0]['masked_text']}")

# Test 3d: Keyword Detection (ADDRESS, NAME, S/O)
print("[TEST 3d] Keyword Detection...")
kw_results_name = pd.detect_keywords("NAME: John Doe")
assert len(kw_results_name) > 0, "NAME keyword should be detected"
assert kw_results_name[0]['type'] == 'name_keyword'
print(f"  OK - NAME keyword detected")

kw_results_addr = pd.detect_keywords("ADDRESS: 123 Main Street")
assert len(kw_results_addr) > 0, "ADDRESS keyword should be detected"
print(f"  OK - ADDRESS keyword detected")

kw_results_so = pd.detect_keywords("S/O Rajesh Kumar")
assert len(kw_results_so) > 0, "S/O keyword should be detected"
print(f"  OK - S/O keyword detected")

kw_results_dob = pd.detect_keywords("DOB: 15/06/1990")
assert len(kw_results_dob) > 0, "DOB keyword should be detected"
print(f"  OK - DOB keyword detected")

# Test 4: Severity Classifier
print("[TEST 4] Severity Classifier...")
from detection.severity_classifier import SeverityClassifier
sc = SeverityClassifier()
print(f"  OK - PAN severity: {sc.classify('pan_number')}")

# Test 5: Insider Threat Detector
print("[TEST 5] Insider Threat Detector...")
from detection.insider_threat import InsiderThreatDetector
itd = InsiderThreatDetector()
print(f"  OK - Risk level: {itd.get_risk_level()}")

# Test 6: Redaction Engine
print("[TEST 6] Redaction Engine...")
from core.redaction import RedactionEngine
re = RedactionEngine()
print("  OK")

# Test 7: Evidence Logger
print("[TEST 7] Evidence Logger...")
from dlp_logging.evidence_logger import EvidenceLogger
el = EvidenceLogger(db, sm)
print("  OK")

# Test 8: Flask Dashboard
print("[TEST 8] Flask Dashboard...")
from dashboard.app import create_app
app = create_app(db)
print("  OK - Flask app created")

# Test 9: OCR Engine
print("[TEST 9] OCR Engine...")
from core.ocr_engine import OCREngine
ocr = OCREngine()
print(f"  OK - Available: {ocr.available}, Engine: {ocr.engine}")

# Test 10: Object Detector
print("[TEST 10] Object Detector...")
from core.object_detector import ObjectDetector
od = ObjectDetector()
print(f"  OK - Available: {od.available}")

# Test 10b: Document classification keywords
print("[TEST 10b] Document Classification...")
assert od._classify_document("aadhaar government of india") == 'aadhaar_card_object'
assert od._classify_document("permanent account number income tax") == 'pan_card_object'
assert od._classify_document("driver licence dl no") == 'driver_license_object'
assert od._classify_document("passport republic of india") == 'passport_object'
assert od._classify_document("voter identity card") == 'id_card_object'
print("  OK - All document types classified correctly")

# Test 11: Phone Detector
print("[TEST 11] Phone Detector...")
from core.phone_detector import PhoneDetector
phone = PhoneDetector()
print(f"  OK - Available: {phone.is_available()}, Face blur: {phone.face_cascade is not None}")

# Test 12: Screen Recording Detector
print("[TEST 12] Screen Recording Detector...")
from core.screen_recording_detector import ScreenRecordingDetector
srd = ScreenRecordingDetector()
print("  OK")

# Test 13: Webcam Monitor (poll-based)
print("[TEST 13] Webcam Monitor...")
from core.webcam_monitor import WebcamMonitor
wm = WebcamMonitor()
assert not hasattr(wm, 'on_frame_callback'), "Webcam should NOT have callback"
print("  OK - No callback (poll-based)")

# Test 14: Config Validation
print("[TEST 14] Config Validation...")
from utils.config import (
    YOLO_CONFIDENCE_THRESHOLD, PHONE_CONFIDENCE_THRESHOLD,
    SEVERITY_MAP, DATABASE_PATH, STORE_RAW_SCREENSHOTS
)
assert YOLO_CONFIDENCE_THRESHOLD >= 0.65, f"YOLO threshold must be >= 0.65"
assert PHONE_CONFIDENCE_THRESHOLD >= 0.65, f"Phone threshold must be >= 0.65"
assert SEVERITY_MAP['phone_camera_exfiltration'] == 'CRITICAL'
assert SEVERITY_MAP['screen_recording_detected'] == 'CRITICAL'
assert SEVERITY_MAP['pan_number'] == 'HIGH'
assert SEVERITY_MAP['aadhaar_number'] == 'CRITICAL'
assert SEVERITY_MAP['dob'] == 'MEDIUM'
assert SEVERITY_MAP['driver_licence_number'] == 'HIGH'
assert SEVERITY_MAP['name_keyword'] == 'MEDIUM'
assert SEVERITY_MAP['address_keyword'] == 'MEDIUM'
assert SEVERITY_MAP['aadhaar_card_object'] == 'CRITICAL'
assert SEVERITY_MAP['passport_object'] == 'CRITICAL'
assert STORE_RAW_SCREENSHOTS == False, "Raw screenshots must NOT be stored"
print("  OK - Severities correct, STORE_RAW=False, new maps validated")

# Test 15: Privacy Pipeline (Enhanced)
print("[TEST 15] Privacy Pipeline...")
from core.privacy_pipeline import PrivacyPipeline
pp = PrivacyPipeline(ocr, pd, re, phone)
print(f"  OK - Face cascade loaded: {pp.face_cascade is not None}")
print(f"  OK - QR detector loaded: {pp.qr_detector is not None}")

# Test 15b: Device detection filter
assert pp.is_device_detection('laptop') == True, "Laptop should be device"
assert pp.is_device_detection('monitor') == True, "Monitor should be device"
assert pp.is_device_detection('keyboard') == True, "Keyboard should be device"
assert pp.is_device_detection('pan_number') == False, "PAN should NOT be device"
print("  OK - Device filter: laptop/monitor/keyboard=True, pan=False")

# Test 16: Database heatmap queries
print("[TEST 16] Database Analytics...")
hourly = db.get_hourly_distribution()
assert len(hourly) == 24, "Hourly distribution should have 24 entries"
print(f"  OK - Hourly distribution: {len(hourly)} entries")

freq = db.get_category_frequency()
assert isinstance(freq, list), "Category frequency should be a list"
print(f"  OK - Category frequency: {len(freq)} entries")

# Cleanup
sm.end_session()
db.close()

print()
print("=" * 50)
print("  ALL 16 TESTS PASSED!")
print("=" * 50)
