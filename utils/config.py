"""
ViziDLP Configuration File
Centralizes all settings and constants for the system.
"""

import os

# ─── Base Paths ───────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")
DB_PATH = os.path.join(BASE_DIR, "vizidlp.db")
DATABASE_PATH = DB_PATH  # alias for database.py compatibility
MODELS_DIR = os.path.join(BASE_DIR, "models")
YOLO_MODEL_PATH = os.path.join(MODELS_DIR, "yolov8n.pt")

# ─── Screen Monitoring ────────────────────────────────────────
SCREEN_CAPTURE_FPS = 1          # Frames per second for screen capture
SCREEN_MONITOR_ENABLED = True   # Enable/disable screen monitoring

# ─── Webcam Monitoring ────────────────────────────────────────
WEBCAM_INDEX = 0                # Default webcam device index
WEBCAM_MONITOR_ENABLED = True   # Enable webcam for phone detection

# ─── OCR Configuration ──────────────────────────────────────────
TESSERACT_CMD = r"C:\Program Files\Tesseract-OCR\tesseract.exe"  # Windows default
OCR_LANGUAGE = "eng"
OCR_ENGINE = "paddleocr"  # Primary OCR engine: "paddleocr" or "tesseract"

# ─── YOLO / Object Detection ──────────────────────────────────
YOLO_CONFIDENCE_THRESHOLD = 0.40  # Lowered for reliable phone detection (YOLO reports phones at 0.35-0.60)
YOLO_ENABLED = True

# ─── Phone Detection Configuration ───────────────────────────
PHONE_DETECTION_ENABLED = True
PHONE_DETECTION_COOLDOWN = 10     # Seconds between phone alerts
PHONE_CONFIDENCE_THRESHOLD = 0.65 # Minimum confidence for phone detection

# ─── Redaction Configuration ──────────────────────────────────
REDACTION_BLUR_KERNEL = (99, 99)  # Gaussian blur kernel size
REDACTION_BLUR_SIGMA = 30          # Gaussian blur sigma

# ─── Evidence Storage ─────────────────────────────────────────
STORE_RAW_SCREENSHOTS = False     # PRIVACY: Never store raw unredacted screenshots
ENCRYPT_EVIDENCE = False          # Enable evidence encryption

# ─── Flask Dashboard ──────────────────────────────────────────
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000

# ─── Detection Settings ──────────────────────────────────────
DETECTION_COOLDOWN_SECONDS = 2    # Minimum seconds between detections (reduced for better ID card capture)
DESKTOP_NOTIFICATIONS_ENABLED = True

# ─── Severity Classification ─────────────────────────────────
SEVERITY_MAP = {
    # Regex-based PII patterns
    "pan_number": "HIGH",
    "aadhaar_number": "CRITICAL",
    "credit_card_number": "HIGH",
    "phone_number": "MEDIUM",
    "email_address": "MEDIUM",
    "dob": "MEDIUM",
    "driver_licence_number": "HIGH",
    "api_key": "HIGH",
    "aws_key": "CRITICAL",
    "private_key": "CRITICAL",
    "password": "HIGH",
    # Keyword-based PII
    "name_keyword": "MEDIUM",
    "address_keyword": "MEDIUM",
    "relation_keyword": "MEDIUM",
    "dob_keyword": "MEDIUM",
    # Document object detections
    "aadhaar_card_object": "CRITICAL",
    "pan_card_object": "HIGH",
    "driver_license_object": "HIGH",
    "passport_object": "CRITICAL",
    "id_card_object": "HIGH",
    "credit_card_object": "HIGH",
    # Behavioral detections
    "screenshot_taken": "MEDIUM",
    "phone_camera_exfiltration": "CRITICAL",
    "screen_recording_detected": "CRITICAL",
    # New PII patterns
    "passport_number": "CRITICAL",
    "voter_id": "HIGH",
    "ifsc_code": "MEDIUM",
    "bank_account": "HIGH",
    "upi_id": "MEDIUM",
    "gstin": "HIGH",
    "financial_keyword": "HIGH",
    "passport_keyword": "CRITICAL",
    # PII detection fix — CRITICAL keywords for card types
    "aadhaar_number_spaced": "CRITICAL",
    "aadhaar_keyword": "CRITICAL",
    "pan_keyword": "CRITICAL",
    "driver_license_keyword": "CRITICAL",
    "credit_card_keyword": "CRITICAL",
    "visual_identity_document": "HIGH",
}

# Severity levels (numeric for comparison)
SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Insider threat thresholds
SCREENSHOT_FREQUENCY_THRESHOLD = 5     # Screenshots in time window
DETECTION_FREQUENCY_THRESHOLD = 10     # Detections in time window
THREAT_TIME_WINDOW = 300                # Time window in seconds (5 min)

# Aliases for insider_threat.py
INSIDER_THREAT_SCREENSHOT_THRESHOLD = SCREENSHOT_FREQUENCY_THRESHOLD
INSIDER_THREAT_DETECTION_THRESHOLD = DETECTION_FREQUENCY_THRESHOLD
INSIDER_THREAT_TIME_WINDOW_SECONDS = THREAT_TIME_WINDOW

# Notification severity threshold
ALERT_ON_SEVERITY = ["HIGH", "CRITICAL"]

# ─── Alert Webhook (Cloud Monitoring) ─────────────────────────
ALERT_WEBHOOK_ENABLED = False       # Set True to enable webhook dispatch
ALERT_WEBHOOK_URL = "https://your-webhook-endpoint.com/vizidlp"  # Replace with your endpoint

# ─── Policy Engine (GAP 1) ───────────────────────────────────
POLICY_RULES = [
    {
        "name": "pii_critical",
        "data_categories": ["aadhaar_number", "credit_card_number", "aws_key", "private_key"],
        "severity_threshold": "CRITICAL",
        "action": "alert",
    },
    {
        "name": "screen_capture_pii",
        "data_categories": ["pan_number", "passport_number", "driver_licence_number"],
        "severity_threshold": "HIGH",
        "action": "alert",
    },
    {
        "name": "clipboard_sanitize",
        "data_categories": ["aadhaar_number", "credit_card_number"],
        "severity_threshold": "CRITICAL",
        "action": "block_clipboard",
    },
]

# ─── Dashboard Authentication (GAP 2) ────────────────────────
FLASK_SECRET_KEY = "change-me-in-production"
DASHBOARD_PASSWORD_HASH = ""  # bcrypt hash; leave empty to use default "vizidlp-admin"

# ─── Clipboard Monitor (GAP 3) ───────────────────────────────
CLIPBOARD_MONITOR_ENABLED = True

# ─── Network Monitor (GAP 4) ─────────────────────────────────
NETWORK_MONITOR_ENABLED = True
SUSPICIOUS_UPLOAD_PORTS = [21, 22, 445, 8080, 8443]
SUSPICIOUS_DOMAINS = [
    "wetransfer.com",
    "filebin.net",
    "transfer.sh",
    "gofile.io",
    "file.io",
    "uploadfiles.io",
]

# ─── Risk Scorer (GAP 6) ─────────────────────────────────────
TIME_DECAY_FACTOR = 10  # Tunable: higher = slower risk accumulation

# ─── File-Level DLP Scanner ──────────────────────────────────
FILE_SCAN_ENABLED = False  # Set True to enable file watching
FILE_SCAN_DIR = ""  # Directory to watch for sensitive files (e.g., "C:/Users/shared/uploads")

# ─── USB Device Monitor ──────────────────────────────────────
USB_MONITOR_ENABLED = True
