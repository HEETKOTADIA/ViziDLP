"""
ViziDLP Test Mode
Simulates detections and verifies all modules respond correctly.

Run with: python test_mode.py

Simulates:
  1. Pattern detection (Aadhaar, PAN, email, phone)
  2. Policy engine evaluation
  3. Risk scorer events
  4. Compliance tagging
  5. File scanner (creates temp test file)
  6. Database operations
  7. Dashboard app creation

Reports colored PASS/FAIL for each test.
"""

import os
import sys
import time
import tempfile

# Add project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ─── Colored output ──────────────────────────────────────────
def _green(s): return f"\033[92m{s}\033[0m"
def _red(s): return f"\033[91m{s}\033[0m"
def _yellow(s): return f"\033[93m{s}\033[0m"
def _cyan(s): return f"\033[96m{s}\033[0m"
def _bold(s): return f"\033[1m{s}\033[0m"

PASS = _green("PASS")
FAIL = _red("FAIL")
SKIP = _yellow("SKIP")

results = []

def test(name, condition, detail=""):
    status = PASS if condition else FAIL
    results.append(condition)
    detail_str = f" -- {detail}" if detail else ""
    print(f"  [{status}] {name}{detail_str}")
    return condition


def main():
    print()
    print(_bold("=" * 60))
    print(_bold("  ViziDLP Test Mode -- Full System Verification"))
    print(_bold("=" * 60))
    print()

    # ─── Test 1: Pattern Detection ────────────────────────────
    print(_cyan("[TEST 1] Pattern Detection (Aadhaar, PAN, Email, Phone)"))
    from detection.pattern_detector import PatternDetector
    pd = PatternDetector()

    test_text = "My Aadhaar is 2345 6789 0123, PAN: ABCDE1234F, email test@example.com, phone 9876543210"
    detections = pd.detect(test_text)
    det_types = {d['type'] for d in detections}

    test("Aadhaar detected", 'aadhaar_number' in det_types or 'aadhaar_number_spaced' in det_types)
    test("PAN detected", 'pan_number' in det_types)
    test("Email detected", 'email_address' in det_types)
    test("Phone detected", 'phone_number' in det_types)
    test("Total detections >= 4", len(detections) >= 4, f"found {len(detections)}")
    print()

    # ─── Test 2: Severity Classification ──────────────────────
    print(_cyan("[TEST 2] Severity Classification"))
    from detection.severity_classifier import SeverityClassifier
    sc = SeverityClassifier()

    test("Aadhaar = CRITICAL", sc.classify('aadhaar_number') == 'CRITICAL')
    test("PAN = HIGH", sc.classify('pan_number') == 'HIGH')
    test("Phone = MEDIUM", sc.classify('phone_number') == 'MEDIUM')
    print()

    # ─── Test 3: Policy Engine ────────────────────────────────
    print(_cyan("[TEST 3] Policy Engine"))
    from core.policy_engine import PolicyEngine
    pe = PolicyEngine()

    result = pe.evaluate({'type': 'aadhaar_number', 'severity': 'CRITICAL'})
    test("Critical Aadhaar triggers policy", result is not None)
    if result:
        test("Action is 'alert' or 'block_clipboard'", result.action in ('alert', 'block_clipboard'),
             f"action={result.action}")

    result_low = pe.evaluate({'type': 'phone_number', 'severity': 'LOW'})
    test("Low-severity phone does NOT trigger", result_low is None)
    print()

    # ─── Test 4: Risk Scorer ──────────────────────────────────
    print(_cyan("[TEST 4] Risk Scorer"))
    from detection.risk_scorer import RiskScorer
    rs = RiskScorer()

    test("Initial score = 0", rs.get_score() == 0.0)
    test("Initial band = SAFE", rs.get_risk_band() == "SAFE")

    for _ in range(30):
        rs.record_event("CRITICAL")
    score = rs.get_score()
    test("After 5 CRITICAL events, score > 0", score > 0, f"score={score:.1f}")
    test("Risk band elevated", rs.get_risk_band() in ("ELEVATED", "HIGH", "CRITICAL"),
         f"band={rs.get_risk_band()}")
    print()

    # ─── Test 5: Compliance Tagger ────────────────────────────
    print(_cyan("[TEST 5] Compliance Tagger"))
    from detection.compliance_tagger import ComplianceTagger
    ct = ComplianceTagger()

    aadhaar_tags = ct.tag('aadhaar_number')
    test("Aadhaar has compliance tags", len(aadhaar_tags) > 0, f"{len(aadhaar_tags)} tags")
    frameworks = ct.get_frameworks_for_type('aadhaar_number')
    test("DPDP framework applies", 'DPDP' in frameworks)

    cc_tags = ct.tag('credit_card_number')
    cc_frameworks = ct.get_frameworks_for_type('credit_card_number')
    test("Credit card -> PCI_DSS", 'PCI_DSS' in cc_frameworks)

    email_frameworks = ct.get_frameworks_for_type('email_address')
    test("Email -> GDPR", 'GDPR' in email_frameworks)

    summary = ct.get_compliance_summary(detections)
    test("Compliance summary generated", len(summary) > 0, f"frameworks: {list(summary.keys())}")
    print()

    # ─── Test 6: File Scanner ─────────────────────────────────
    print(_cyan("[TEST 6] File Scanner"))
    from core.file_scanner import FileScanner
    fs = FileScanner()

    # Create a temp test file with sensitive data
    tmp_dir = tempfile.mkdtemp(prefix="vizidlp_test_")
    test_file = os.path.join(tmp_dir, "test_sensitive.txt")
    with open(test_file, 'w') as f:
        f.write("Name: John Doe\n")
        f.write("PAN: ABCDE1234F\n")
        f.write("Aadhaar: 2345 6789 0123\n")
        f.write("Email: john@example.com\n")

    file_dets = fs.scan_file(test_file)
    test("File scan finds detections", len(file_dets) > 0, f"found {len(file_dets)}")

    file_types = {d['type'] for d in file_dets}
    test("PAN found in file", 'pan_number' in file_types)

    # Cleanup
    try:
        os.remove(test_file)
        os.rmdir(tmp_dir)
    except Exception:
        pass
    print()

    # ─── Test 7: Insider Threat Detector ──────────────────────
    print(_cyan("[TEST 7] Insider Threat / UEBA"))
    from detection.insider_threat import InsiderThreatDetector
    itd = InsiderThreatDetector()

    test("Initial risk = LOW", itd.get_risk_level() == "LOW")
    for _ in range(20):
        itd.record_detection("test")
    test("After 20 detections, risk elevated", itd.get_risk_level() != "LOW",
         f"level={itd.get_risk_level()}")
    print()

    # ─── Test 8: Database Operations ──────────────────────────
    print(_cyan("[TEST 8] Database Operations"))
    from database.database import Database

    db = Database()
    test("Database initialized", db is not None)

    stats = db.get_stats()
    test("Stats retrievable", isinstance(stats, dict))
    test("Has total_detections key", 'total_detections' in stats)
    print()

    # ─── Test 9: Dashboard App ────────────────────────────────
    print(_cyan("[TEST 9] Dashboard App"))
    from dashboard.app import create_app

    app = create_app(db)
    test("Flask app created", app is not None)

    with app.test_client() as client:
        # Login page should be accessible
        resp = client.get('/login')
        test("Login page accessible", resp.status_code == 200)

        # API stats should be accessible (public)
        resp = client.get('/api/stats')
        test("API /stats accessible", resp.status_code == 200)

        # CSV export should work
        resp = client.get('/api/export/csv')
        test("CSV export works", resp.status_code == 200)

        # Risk score API
        resp = client.get('/api/risk-score')
        test("Risk score API works", resp.status_code == 200)
    print()

    # ─── Test 10: Clipboard Monitor ───────────────────────────
    print(_cyan("[TEST 10] Clipboard Monitor"))
    from core.clipboard_monitor import ClipboardMonitor
    cm = ClipboardMonitor()
    test("Clipboard monitor created", cm is not None)
    test("Not running initially", not cm.is_running())
    print()

    # ─── Test 11: Network Monitor ─────────────────────────────
    print(_cyan("[TEST 11] Network Monitor"))
    from core.network_monitor import NetworkMonitor
    nm = NetworkMonitor()
    test("Network monitor created", nm is not None)
    test("Not running initially", not nm.is_running())
    print()

    # ─── Test 12: USB Monitor ─────────────────────────────────
    print(_cyan("[TEST 12] USB Monitor"))
    from core.usb_monitor import USBMonitor
    um = USBMonitor()
    test("USB monitor created", um is not None)
    stats = um.get_stats()
    test("Stats retrievable", isinstance(stats, dict))
    print()

    # ─── Test 13: Auth Module ─────────────────────────────────
    print(_cyan("[TEST 13] Dashboard Auth"))
    from dashboard.auth import DashboardAuth
    auth = DashboardAuth()
    test("Default password works", auth.check_password("vizidlp-admin"))
    test("Wrong password rejected", not auth.check_password("wrong-password"))
    print()

    # ─── Results Summary ──────────────────────────────────────
    passed = sum(results)
    total = len(results)
    failed = total - passed

    print(_bold("=" * 60))
    if failed == 0:
        print(_bold(_green(f"  ALL {total} TESTS PASSED!")))
    else:
        print(_bold(_red(f"  {failed} of {total} TESTS FAILED")))
        print(f"  {_green(f'{passed} passed')}, {_red(f'{failed} failed')}")
    print(_bold("=" * 60))
    print()

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
