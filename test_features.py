"""Quick verification of all new ViziDLP features."""
import sys
sys.path.insert(0, '.')

print("=" * 60)
print("  ViziDLP Feature Verification")
print("=" * 60)
print()

# 1. Config
from utils.config import SEVERITY_MAP, ALERT_WEBHOOK_ENABLED, ALERT_WEBHOOK_URL, ALERT_ON_SEVERITY
print("[1] Config:")
print(f"    SEVERITY_MAP entries: {len(SEVERITY_MAP)}")
print(f"    ALERT_WEBHOOK_ENABLED: {ALERT_WEBHOOK_ENABLED}")
print(f"    New types present: passport_number={'passport_number' in SEVERITY_MAP}, gstin={'gstin' in SEVERITY_MAP}")
print()

# 2. Pattern Detector
from detection.pattern_detector import PatternDetector
pd = PatternDetector()
print(f"[2] Pattern Detector: {len(pd.PATTERNS)} patterns, {len(pd.KEYWORD_PATTERNS)} keyword groups")

# Test new patterns
test_cases = {
    'A1234567': 'passport_number',
    'ABC1234567': 'voter_id',
    'SBIN0001234': 'ifsc_code',
    '12345678901': 'bank_account',
    'user@paytm': 'upi_id',
    '27ABCDE1234F1ZP': 'gstin',
}
for text, expected in test_cases.items():
    dets = pd.detect(text)
    types_found = [d['type'] for d in dets]
    found = expected in types_found
    print(f"    {text:20s} -> {expected}: {'PASS' if found else 'FAIL'} ({types_found})")

# Validate false positive filter
print(f"    validate(all-same bank acct): {pd.validate({'type':'bank_account','matched_text':'111111111'})} (expect False)")
print(f"    validate(normal bank acct):   {pd.validate({'type':'bank_account','matched_text':'123456789'})} (expect True)")
print(f"    validate(phone starts 0):     {pd.validate({'type':'phone_number','matched_text':'0987654321'})} (expect False)")
print(f"    validate(IFSC wrong len):     {pd.validate({'type':'ifsc_code','matched_text':'SBIN000'})} (expect False)")

# Test keyword patterns
kw_dets = pd.detect_keywords('ACCOUNT NUMBER: 123456')
print(f"    Financial keywords: {len(kw_dets)} (expect >= 1)")
kw_dets2 = pd.detect_keywords('PASSPORT NUMBER: A1234567')
print(f"    Passport keywords: {len(kw_dets2)} (expect >= 1)")
print()

# 3. Alert Dispatcher
from core.alert_dispatcher import AlertDispatcher
ad = AlertDispatcher()
stats = ad.get_stats()
print(f"[3] Alert Dispatcher: {stats}")
print()

# 4. Face Recognizer
from core.face_recognizer import FaceRecognizer
fr = FaceRecognizer()
print(f"[4] Face Recognizer: available={fr.available}, recognition={fr.recognition_available}")
print(f"    Known names: {fr.get_known_names()}")
print()

# 5. Database search
from database.database import Database
db = Database()
results = db.search_detections('pan')
print(f"[5] Database search_detections('pan'): {len(results)} results")
print()

# 6. Flask app routes
from dashboard.app import create_app
app = create_app(db)
api_routes = [r.rule for r in app.url_map.iter_rules() if r.rule.startswith('/api')]
print(f"[6] Flask API routes ({len(api_routes)}):")
for route in sorted(api_routes):
    print(f"    {route}")
print()

# 7. Verify Flask endpoints work
with app.test_client() as client:
    print("[7] Endpoint Tests:")
    
    resp = client.get('/api/search?q=pan')
    print(f"    /api/search?q=pan -> {resp.status_code}")
    
    resp = client.get('/api/export?format=json')
    print(f"    /api/export -> {resp.status_code}, Content-Disposition: {resp.headers.get('Content-Disposition', 'N/A')}")
    
    resp = client.get('/api/timeline/grouped')
    print(f"    /api/timeline/grouped -> {resp.status_code}")
    
    resp = client.get('/api/alert-stats')
    print(f"    /api/alert-stats -> {resp.status_code}, data: {resp.get_json()}")
    
    resp = client.get('/api/faces')
    print(f"    /api/faces -> {resp.status_code}, data: {resp.get_json()}")
print()

print("=" * 60)
print("  All verifications complete!")
print("=" * 60)
