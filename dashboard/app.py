"""
ViziDLP Dashboard — Flask Web Application (Enhanced)
Provides real-time monitoring dashboard, searchable logs, timeline view,
heatmap analytics, and evidence viewer.
Default: shows only current session data. Session history dropdown available.

GAP 2: Session-based authentication for page routes
GAP 5: CSV and PDF-report export routes
GAP 6: Risk score API route
GAP 7: Evidence integrity verification route
GAP 8: Server-Sent Events (SSE) for live detection feed
"""

import os
import sys
import csv
import json
import io
import queue
import time
import hashlib
import threading
from datetime import datetime
from collections import defaultdict
from flask import (
    Flask, render_template, jsonify, request, send_file,
    make_response, Response, session, redirect, url_for
)

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.database import Database
from dashboard.auth import DashboardAuth
from utils.config import FLASK_HOST, FLASK_PORT, EVIDENCE_DIR


def create_app(db: Database = None, pipeline_ref=None):
    """Create and configure the Flask application."""

    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
        static_folder=os.path.join(os.path.dirname(__file__), 'static')
    )

    # Store references
    app.config['db'] = db or Database()
    app.config['pipeline'] = pipeline_ref

    # ─── GAP 2: Authentication Setup ──────────────────────────
    auth = DashboardAuth()
    # Use a random key per app restart to force re-login every time.
    # This invalidates old session cookies so users MUST authenticate.
    app.secret_key = os.urandom(32)

    # ─── GAP 8: SSE Queue ─────────────────────────────────────
    app.config['sse_queue'] = queue.Queue(maxsize=1000)

    def get_db():
        return app.config['db']

    def get_current_session_id():
        """Get the current session ID from the pipeline."""
        pipeline = app.config.get('pipeline')
        if pipeline and hasattr(pipeline, 'session_manager'):
            return pipeline.session_manager.current_session_id
        return None

    # ─── GAP 2: Login/Logout Routes ──────────────────────────

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page and handler."""
        if request.method == 'POST':
            password = request.form.get('password', '')
            if auth.check_password(password):
                session['authed'] = True
                return redirect(url_for('index'))
            return render_template('login.html', error='Invalid password')
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        """Logout — clear session."""
        session.pop('authed', None)
        return redirect(url_for('login'))

    # ─── Page Routes (wrapped with @login_required) ───────────

    @app.route('/')
    @auth.login_required
    def index():
        """Main dashboard page."""
        return render_template('index.html')

    @app.route('/logs')
    @auth.login_required
    def logs():
        """Evidence logs page."""
        return render_template('logs.html')

    @app.route('/timeline')
    @auth.login_required
    def timeline():
        """Timeline view page."""
        return render_template('timeline.html')

    # ─── API Routes (remain public — localhost-only) ──────────

    @app.route('/api/stats')
    def api_stats():
        """Get dashboard statistics — defaults to current session."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        stats = db.get_stats(session_id)
        stats['current_session_id'] = get_current_session_id()
        return jsonify(stats)

    @app.route('/api/detections')
    def api_detections():
        """Get filtered detections — defaults to current session."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        severity = request.args.get('severity')
        data_type = request.args.get('data_type')
        search = request.args.get('search')
        limit = int(request.args.get('limit', 100))

        detections = db.get_detections(
            session_id=session_id,
            severity=severity,
            data_type=data_type,
            search_query=search,
            limit=limit
        )
        return jsonify(detections)

    @app.route('/api/timeline')
    def api_timeline():
        """Get timeline data — defaults to current session."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        detections = db.get_timeline_detections(session_id)
        return jsonify(detections)

    @app.route('/api/sessions')
    def api_sessions():
        """Get all sessions for the history dropdown."""
        db = get_db()
        sessions = db.get_all_sessions()
        return jsonify(sessions)

    @app.route('/api/alerts')
    def api_alerts():
        """Get recent alerts — defaults to current session."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        limit = int(request.args.get('limit', 20))
        alerts = db.get_recent_alerts(limit, session_id)
        return jsonify(alerts)

    @app.route('/api/threats')
    def api_threats():
        """Get insider threat events — defaults to current session."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        events = db.get_threat_events(session_id)
        return jsonify(events)

    @app.route('/api/status')
    def api_status():
        """Get current monitoring status."""
        pipeline = app.config.get('pipeline')
        if pipeline:
            status = pipeline.get_status()
            # GAP 8: Push to SSE queue on each status poll if new detections
            push_sse_event(app, {
                'type': 'status_update',
                'timestamp': datetime.now().isoformat(),
                'status': status
            })
            return jsonify(status)
        return jsonify({
            'monitoring': False,
            'screen_active': False,
            'webcam_active': False,
            'screenshot_detection': False,
            'phone_detection': False,
            'phone_detections': 0,
            'recording_detection': False,
            'active_recorders': [],
            'session_id': None
        })

    @app.route('/api/heatmap')
    def api_heatmap():
        """Get hourly detection distribution for heatmap analytics."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        data = db.get_hourly_distribution(session_id)
        return jsonify(data)

    @app.route('/api/pii-types')
    def api_pii_types():
        """Get most frequently detected PII types."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        limit = int(request.args.get('limit', 10))
        data = db.get_category_frequency(session_id, limit)
        return jsonify(data)

    @app.route('/api/evidence/<path:filepath>')
    def api_evidence(filepath):
        """Serve evidence image files."""
        full_path = os.path.join(EVIDENCE_DIR, filepath)
        if os.path.exists(full_path):
            pipeline = app.config.get('pipeline')
            privacy_pipeline = getattr(pipeline, 'privacy_pipeline', None) if pipeline else None
            if privacy_pipeline is not None:
                try:
                    import cv2
                    image = cv2.imread(full_path)
                    if image is not None:
                        privacy_result = privacy_pipeline.sanitize_screenshot(image)
                        if privacy_result.get('has_sensitive_data'):
                            ok, buffer = cv2.imencode('.jpg', privacy_result['sanitized_frame'])
                            if ok:
                                return send_file(io.BytesIO(buffer.tobytes()), mimetype='image/jpeg')
                except Exception as e:
                    print(f"[DASHBOARD] Evidence serve-time sanitization skipped: {e}")
            return send_file(full_path, mimetype='image/jpeg')
        return jsonify({'error': 'File not found'}), 404

    # ─── New API Routes ───────────────────────────────────────

    @app.route('/api/search')
    def api_search():
        """Search across detections (description, data_category, detection_type, raw_text)."""
        db = get_db()
        q = request.args.get('q', '').strip()
        session_id = request.args.get('session_id') or get_current_session_id()
        limit = int(request.args.get('limit', 100))
        if not q:
            return jsonify([])
        results = db.search_detections(q, session_id=session_id, limit=limit)
        return jsonify(results)

    @app.route('/api/export')
    def api_export():
        """Export all detections for a session as downloadable JSON."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        fmt = request.args.get('format', 'json')
        detections = db.get_detections(session_id=session_id, limit=10000)
        data = json.dumps(detections, indent=2, default=str)
        resp = make_response(data)
        resp.headers['Content-Type'] = 'application/json'
        resp.headers['Content-Disposition'] = f'attachment; filename=vizidlp_export_{session_id or "all"}.json'
        return resp

    @app.route('/api/timeline/grouped')
    def api_timeline_grouped():
        """Get detections grouped by 5-minute buckets for interactive timeline."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        detections = db.get_timeline_detections(session_id, limit=500)

        buckets = defaultdict(lambda: {"count": 0, "severities": {}, "events": []})
        for det in detections:
            ts = det.get('timestamp', '')
            try:
                dt = datetime.fromisoformat(ts)
                minute = (dt.minute // 5) * 5
                bucket_key = dt.strftime(f'%H:{minute:02d}')
            except Exception:
                bucket_key = "00:00"

            b = buckets[bucket_key]
            b["count"] += 1
            sev = det.get("severity", "LOW")
            b["severities"][sev] = b["severities"].get(sev, 0) + 1
            b["events"].append(det)

        result = [{"bucket": k, **v} for k, v in sorted(buckets.items())]
        return jsonify(result)

    @app.route('/api/alert-stats')
    def api_alert_stats():
        """Get alert dispatcher statistics."""
        pipeline = app.config.get('pipeline')
        if pipeline and hasattr(pipeline, 'alert_dispatcher'):
            return jsonify(pipeline.alert_dispatcher.get_stats())
        return jsonify({"enabled": False, "dispatched": 0, "endpoint_preview": ""})

    @app.route('/api/faces')
    def api_faces():
        """Get known faces list and recognition mode."""
        pipeline = app.config.get('pipeline')
        if pipeline and hasattr(pipeline, 'face_recognizer'):
            fr = pipeline.face_recognizer
            return jsonify({
                "known_faces": fr.get_known_names(),
                "recognition_available": fr.recognition_available,
                "detection_available": fr.available,
            })
        return jsonify({"known_faces": [], "recognition_available": False, "detection_available": False})

    @app.route('/api/faces/register', methods=['POST'])
    def api_faces_register():
        """Register a new known face from uploaded image."""
        pipeline = app.config.get('pipeline')
        if not pipeline or not hasattr(pipeline, 'face_recognizer'):
            return jsonify({"success": False, "error": "Face recognizer not available"}), 400

        fr = pipeline.face_recognizer
        if not fr.recognition_available:
            return jsonify({"success": False, "error": "face_recognition library not installed"}), 400

        name = request.form.get('name', '').strip()
        if not name:
            return jsonify({"success": False, "error": "Name is required"}), 400

        if 'image' not in request.files:
            return jsonify({"success": False, "error": "Image file is required"}), 400

        image_file = request.files['image']
        # Save temporarily
        import tempfile
        tmp_path = os.path.join(tempfile.gettempdir(), f"vizidlp_face_{name}.jpg")
        image_file.save(tmp_path)

        success = fr.add_known_face(name, tmp_path)
        # Clean up temp file
        try:
            os.remove(tmp_path)
        except Exception:
            pass

        return jsonify({"success": success})

    # ─── GAP 5: CSV Export ────────────────────────────────────

    @app.route('/api/export/csv')
    def api_export_csv():
        """Export detections as CSV file."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        severity = request.args.get('severity')

        detections = db.get_detections(
            session_id=session_id,
            severity=severity,
            limit=10000
        )

        # Build CSV in-memory
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'id', 'session_id', 'timestamp', 'detection_type',
            'data_category', 'severity', 'description', 'source', 'confidence'
        ])
        for det in detections:
            writer.writerow([
                det.get('id', ''),
                det.get('session_id', ''),
                det.get('timestamp', ''),
                det.get('detection_type', ''),
                det.get('data_category', ''),
                det.get('severity', ''),
                det.get('description', ''),
                det.get('source', ''),
                det.get('confidence', ''),
            ])

        csv_data = output.getvalue()
        resp = make_response(csv_data)
        resp.headers['Content-Type'] = 'text/csv'
        resp.headers['Content-Disposition'] = (
            f'attachment; filename=vizidlp_detections_{session_id or "all"}.csv'
        )
        return resp

    # ─── GAP 5: PDF Report (HTML for print-to-PDF) ────────────

    @app.route('/api/export/pdf-report')
    def api_export_pdf_report():
        """Generate incident report as printable HTML."""
        db = get_db()
        session_id = request.args.get('session_id') or get_current_session_id()
        stats = db.get_stats(session_id)
        detections = db.get_detections(session_id=session_id, limit=10000)

        # Severity breakdown
        sev_dist = stats.get('severity_distribution', {})

        # Top 10 detection types
        type_dist = stats.get('type_distribution', {})
        top_types = sorted(type_dist.items(), key=lambda x: x[1], reverse=True)[:10]

        # 20 most recent CRITICAL/HIGH events
        critical_high = [d for d in detections if d.get('severity') in ('CRITICAL', 'HIGH')][:20]

        report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>ViziDLP Incident Report</title>
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #fff; color: #1a1a2e;
           max-width: 900px; margin: 0 auto; padding: 40px 30px; }}
    h1 {{ color: #0f3460; border-bottom: 3px solid #06b6d4; padding-bottom: 8px; }}
    h2 {{ color: #16213e; margin-top: 28px; border-bottom: 1px solid #ddd; padding-bottom: 6px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 12px 0 20px; font-size: 0.9rem; }}
    th, td {{ padding: 8px 12px; text-align: left; border: 1px solid #ddd; }}
    th {{ background: #0f3460; color: #fff; }}
    tr:nth-child(even) {{ background: #f4f6f9; }}
    .critical {{ color: #dc2626; font-weight: 700; }}
    .high {{ color: #ef4444; font-weight: 600; }}
    .meta {{ color: #555; font-size: 0.85rem; margin-bottom: 4px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;
              font-weight: 600; }}
    .badge-critical {{ background: #fecaca; color: #dc2626; }}
    .badge-high {{ background: #fee2e2; color: #ef4444; }}
    .badge-medium {{ background: #fef3c7; color: #d97706; }}
    .badge-low {{ background: #dcfce7; color: #16a34a; }}
    .footer {{ margin-top: 40px; text-align: center; color: #999; font-size: 0.8rem; }}
</style></head><body>
<h1>🛡️ ViziDLP — Incident Report</h1>
<p class="meta">Generated: {report_time} | Session: {session_id or 'All Sessions'}</p>

<h2>Session Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total Detections</td><td>{stats.get('total_detections', 0)}</td></tr>
<tr><td>Total Sessions</td><td>{stats.get('total_sessions', 0)}</td></tr>
<tr><td>Critical</td><td class="critical">{sev_dist.get('CRITICAL', 0)}</td></tr>
<tr><td>High</td><td class="high">{sev_dist.get('HIGH', 0)}</td></tr>
<tr><td>Medium</td><td>{sev_dist.get('MEDIUM', 0)}</td></tr>
<tr><td>Low</td><td>{sev_dist.get('LOW', 0)}</td></tr>
</table>

<h2>Top Detection Types</h2>
<table>
<tr><th>#</th><th>Data Category</th><th>Count</th></tr>
{''.join(f'<tr><td>{i+1}</td><td>{t[0]}</td><td>{t[1]}</td></tr>' for i, t in enumerate(top_types))}
</table>

<h2>Recent Critical &amp; High Events (Top 20)</h2>
<table>
<tr><th>Time</th><th>Severity</th><th>Category</th><th>Description</th><th>Source</th></tr>
{''.join(
    f'<tr><td>{d.get("timestamp", "")[:19]}</td>'
    f'<td><span class="badge badge-{d.get("severity", "low").lower()}">{d.get("severity", "")}</span></td>'
    f'<td>{d.get("data_category", "")}</td>'
    f'<td>{d.get("description", "")[:100]}</td>'
    f'<td>{d.get("source", "")}</td></tr>'
    for d in critical_high
)}
</table>

<div class="footer">ViziDLP — AI Powered Visual Data Loss Prevention | Confidential</div>
</body></html>"""

        resp = make_response(html)
        resp.headers['Content-Type'] = 'text/html'
        return resp

    # ─── GAP 6: Risk Score API ────────────────────────────────

    @app.route('/api/risk-score')
    def api_risk_score():
        """Get current risk score with history."""
        db = get_db()
        pipeline = app.config.get('pipeline')
        session_id = request.args.get('session_id') or get_current_session_id()

        score = 0.0
        band = "SAFE"
        if pipeline and hasattr(pipeline, 'risk_scorer'):
            score = pipeline.risk_scorer.get_score()
            band = pipeline.risk_scorer.get_risk_band()

        history = db.get_risk_score_history(session_id=session_id, limit=100)

        return jsonify({
            'score': round(score, 2),
            'band': band,
            'history': history
        })

    # ─── GAP 7: Evidence Integrity Verification ──────────────

    @app.route('/api/evidence/verify/<int:detection_id>')
    def api_evidence_verify(detection_id):
        """Verify evidence file integrity via SHA-256 hash comparison."""
        db = get_db()
        conn = db._get_connection()
        row = conn.execute(
            "SELECT id, evidence_path, evidence_hash FROM detections WHERE id = ?",
            (detection_id,)
        ).fetchone()

        if not row:
            return jsonify({'error': 'Detection not found'}), 404

        detection = dict(row)
        evidence_path = detection.get('evidence_path')
        stored_hash = detection.get('evidence_hash')

        if not evidence_path or not os.path.exists(evidence_path):
            return jsonify({
                'verified': False,
                'detection_id': detection_id,
                'path': evidence_path or '',
                'hash_match': False,
                'error': 'Evidence file not found'
            })

        # Re-hash the file
        try:
            with open(evidence_path, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            return jsonify({
                'verified': False,
                'detection_id': detection_id,
                'path': evidence_path,
                'hash_match': False,
                'error': str(e)
            })

        hash_match = (stored_hash is not None and current_hash == stored_hash)

        return jsonify({
            'verified': hash_match,
            'detection_id': detection_id,
            'path': evidence_path,
            'hash_match': hash_match,
        })

    # ─── GAP 8: Server-Sent Events (SSE) ─────────────────────

    @app.route('/api/stream')
    def api_stream():
        """SSE endpoint for live detection feed."""
        def event_stream():
            sse_q = app.config.get('sse_queue')
            if not sse_q:
                return
            while True:
                try:
                    # Wait for an event with a 15-second timeout (heartbeat)
                    event = sse_q.get(timeout=15)
                    data = json.dumps(event, default=str)
                    yield f"data: {data}\n\n"
                except queue.Empty:
                    # Send heartbeat comment to keep connection alive
                    yield ": heartbeat\n\n"
                except GeneratorExit:
                    return

        return Response(
            event_stream(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive',
            }
        )

    # ─── Compliance API ───────────────────────────────────────

    @app.route('/api/compliance')
    def api_compliance():
        """Get compliance framework summary for current detections."""
        db = get_db()
        pipeline = app.config.get('pipeline')
        session_id = request.args.get('session_id') or get_current_session_id()

        detections = db.get_detections(session_id=session_id, limit=10000)

        if pipeline and hasattr(pipeline, 'compliance_tagger'):
            summary = pipeline.compliance_tagger.get_compliance_summary(detections)
        else:
            # Fallback: create a tagger locally
            from detection.compliance_tagger import ComplianceTagger
            tagger = ComplianceTagger()
            summary = tagger.get_compliance_summary(detections)

        return jsonify(summary)

    # ─── File Scanner API ─────────────────────────────────────

    @app.route('/api/file-scan')
    def api_file_scan():
        """Get file scanner stats."""
        pipeline = app.config.get('pipeline')
        if pipeline and hasattr(pipeline, 'file_scanner'):
            return jsonify(pipeline.file_scanner.get_stats())
        return jsonify({
            'files_scanned': 0,
            'detections_found': 0,
            'watching': '',
            'running': False,
        })

    # ─── USB Monitor API ──────────────────────────────────────

    @app.route('/api/usb-events')
    def api_usb_events():
        """Get USB device events."""
        pipeline = app.config.get('pipeline')
        if pipeline and hasattr(pipeline, 'usb_monitor'):
            return jsonify({
                'events': pipeline.usb_monitor.get_events(),
                'stats': pipeline.usb_monitor.get_stats(),
            })
        return jsonify({'events': [], 'stats': {}})

    return app


def push_sse_event(app, event_dict):
    """Push an event to the SSE queue if it exists."""
    sse_q = app.config.get('sse_queue')
    if sse_q is not None:
        try:
            sse_q.put_nowait(event_dict)
        except queue.Full:
            # Queue is full — discard oldest
            try:
                sse_q.get_nowait()
                sse_q.put_nowait(event_dict)
            except (queue.Empty, queue.Full):
                pass


def run_dashboard(db: Database = None, pipeline_ref=None):
    """Run the Flask dashboard server."""
    app = create_app(db, pipeline_ref)
    print(f"[DASHBOARD] Starting dashboard at http://localhost:{FLASK_PORT}")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False)
