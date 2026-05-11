"""
ViziDLP Database Module — Enhanced with Analytics
SQLite database for storing sessions, detections, alerts, and analytics data.
"""

import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.config import DATABASE_PATH


class Database:
    """Thread-safe SQLite database manager for ViziDLP."""

    _local = threading.local()

    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(self.db_path)
            self._local.connection.row_factory = sqlite3.Row
            self._local.connection.execute("PRAGMA journal_mode=WAL")
        return self._local.connection

    def _init_db(self):
        """Initialize database tables."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                status TEXT DEFAULT 'active',
                total_detections INTEGER DEFAULT 0,
                evidence_path TEXT
            )
        """)

        # Detections table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                detection_type TEXT NOT NULL,
                data_category TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                source TEXT NOT NULL,
                bbox_x INTEGER,
                bbox_y INTEGER,
                bbox_w INTEGER,
                bbox_h INTEGER,
                evidence_path TEXT,
                redacted_path TEXT,
                raw_text TEXT,
                confidence REAL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        """)

        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        """)

        # Insider threat events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT,
                risk_score REAL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        """)

        # ── GAP 7: Add evidence_hash column if not present ────
        try:
            conn.execute("ALTER TABLE detections ADD COLUMN evidence_hash TEXT")
            conn.commit()
        except Exception:
            # Column already exists — ignore silently (SQLite lacks IF NOT EXISTS on ALTER TABLE)
            pass

        conn.commit()

    # ─── Session Operations ───────────────────────────────────

    def create_session(self, session_id: str, evidence_path: str) -> None:
        """Create a new monitoring session."""
        conn = self._get_connection()
        conn.execute(
            "INSERT INTO sessions (session_id, start_time, evidence_path) VALUES (?, ?, ?)",
            (session_id, datetime.now().isoformat(), evidence_path)
        )
        conn.commit()

    def end_session(self, session_id: str) -> None:
        """Mark a session as ended."""
        conn = self._get_connection()
        conn.execute(
            "UPDATE sessions SET end_time = ?, status = 'ended' WHERE session_id = ?",
            (datetime.now().isoformat(), session_id)
        )
        conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get a session by its ID."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_sessions(self) -> List[Dict]:
        """Get all sessions, newest first."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY start_time DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def increment_session_detections(self, session_id: str) -> None:
        """Increment the detection count for a session."""
        conn = self._get_connection()
        conn.execute(
            "UPDATE sessions SET total_detections = total_detections + 1 WHERE session_id = ?",
            (session_id,)
        )
        conn.commit()

    # ─── Detection Operations ─────────────────────────────────

    def add_detection(self, detection: Dict[str, Any], on_insert: callable = None) -> int:
        """Add a new detection record. Returns the detection ID.

        Args:
            detection: Detection dict with required keys
            on_insert: Optional callback invoked after insert with (detection_id, detection)
        """
        conn = self._get_connection()
        cursor = conn.execute("""
            INSERT INTO detections 
            (session_id, timestamp, detection_type, data_category, severity, 
             description, source, bbox_x, bbox_y, bbox_w, bbox_h, 
             evidence_path, redacted_path, raw_text, confidence, evidence_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            detection['session_id'],
            detection.get('timestamp', datetime.now().isoformat()),
            detection['detection_type'],
            detection['data_category'],
            detection['severity'],
            detection.get('description', ''),
            detection.get('source', 'screen'),
            detection.get('bbox_x'),
            detection.get('bbox_y'),
            detection.get('bbox_w'),
            detection.get('bbox_h'),
            detection.get('evidence_path'),
            detection.get('redacted_path'),
            detection.get('raw_text'),
            detection.get('confidence'),
            detection.get('evidence_hash')
        ))
        conn.commit()
        self.increment_session_detections(detection['session_id'])

        detection_id = cursor.lastrowid

        # Fire optional on_insert callback (used by SSE push)
        if on_insert is not None:
            try:
                on_insert(detection_id, detection)
            except Exception:
                pass  # Callback failure is non-critical

        return detection_id

    def get_detections(self, session_id: str = None, limit: int = 100,
                       severity: str = None, data_type: str = None,
                       search_query: str = None) -> List[Dict]:
        """Get detections with optional filters."""
        conn = self._get_connection()
        query = "SELECT * FROM detections WHERE 1=1"
        params = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if data_type:
            query += " AND data_category = ?"
            params.append(data_type)
        if search_query:
            query += " AND (description LIKE ? OR raw_text LIKE ? OR data_category LIKE ?)"
            search = f"%{search_query}%"
            params.extend([search, search, search])

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_detection_count(self, session_id: str = None) -> int:
        """Get total detection count, optionally filtered by session."""
        conn = self._get_connection()
        if session_id:
            row = conn.execute(
                "SELECT COUNT(*) as count FROM detections WHERE session_id = ?",
                (session_id,)
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) as count FROM detections").fetchone()
        return row['count'] if row else 0

    def get_severity_distribution(self, session_id: str = None) -> Dict[str, int]:
        """Get count of detections per severity level."""
        conn = self._get_connection()
        query = "SELECT severity, COUNT(*) as count FROM detections"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " GROUP BY severity"

        rows = conn.execute(query, params).fetchall()
        result = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for row in rows:
            result[row['severity']] = row['count']
        return result

    def get_detection_types_distribution(self, session_id: str = None) -> Dict[str, int]:
        """Get count of detections per data category."""
        conn = self._get_connection()
        query = "SELECT data_category, COUNT(*) as count FROM detections"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " GROUP BY data_category ORDER BY count DESC"

        rows = conn.execute(query, params).fetchall()
        return {row['data_category']: row['count'] for row in rows}

    def get_timeline_detections(self, session_id: str = None, limit: int = 200) -> List[Dict]:
        """Get detections formatted for timeline view."""
        conn = self._get_connection()
        query = "SELECT id, session_id, timestamp, detection_type, data_category, severity, description FROM detections"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY timestamp ASC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def search_detections(self, query: str, session_id: str = None, limit: int = 100) -> List[Dict]:
        """
        Search detections across description, data_category, detection_type, and raw_text.
        Used by the /api/search endpoint.
        """
        conn = self._get_connection()
        sql = """SELECT id, session_id, timestamp, detection_type, data_category,
                        severity, description, evidence_path, redacted_path, raw_text, confidence
                 FROM detections WHERE
                 (description LIKE ? OR data_category LIKE ? OR detection_type LIKE ? OR raw_text LIKE ?)"""
        search = f"%{query}%"
        params = [search, search, search, search]
        if session_id:
            sql += " AND session_id = ?"
            params.append(session_id)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    # ─── Heatmap Analytics ────────────────────────────────────

    def get_hourly_distribution(self, session_id: str = None) -> List[Dict]:
        """
        Get detection counts grouped by hour for heatmap analytics.

        Returns:
            List of dicts with 'hour' (0-23) and 'count'
        """
        conn = self._get_connection()
        query = """
            SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, 
                   COUNT(*) as count
            FROM detections
        """
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " GROUP BY hour ORDER BY hour"

        rows = conn.execute(query, params).fetchall()

        # Fill all 24 hours with defaults
        hour_map = {i: 0 for i in range(24)}
        for row in rows:
            hour_map[row['hour']] = row['count']

        return [{'hour': h, 'count': c} for h, c in sorted(hour_map.items())]

    def get_category_frequency(self, session_id: str = None, limit: int = 10) -> List[Dict]:
        """
        Get most frequently detected PII types.

        Returns:
            List of dicts with 'category' and 'count', sorted by count desc
        """
        conn = self._get_connection()
        query = "SELECT data_category as category, COUNT(*) as count FROM detections"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " GROUP BY data_category ORDER BY count DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # ─── Alert Operations ─────────────────────────────────────

    def add_alert(self, alert: Dict[str, Any]) -> int:
        """Add a new alert. Returns the alert ID."""
        conn = self._get_connection()
        cursor = conn.execute("""
            INSERT INTO alerts (session_id, timestamp, alert_type, severity, message)
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert['session_id'],
            alert.get('timestamp', datetime.now().isoformat()),
            alert['alert_type'],
            alert['severity'],
            alert['message']
        ))
        conn.commit()
        return cursor.lastrowid

    def get_recent_alerts(self, limit: int = 20, session_id: str = None) -> List[Dict]:
        """Get recent alerts."""
        conn = self._get_connection()
        query = "SELECT * FROM alerts"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # ─── Threat Events ────────────────────────────────────────

    def add_threat_event(self, event: Dict[str, Any]) -> int:
        """Add an insider threat event."""
        conn = self._get_connection()
        cursor = conn.execute("""
            INSERT INTO threat_events (session_id, timestamp, event_type, details, risk_score)
            VALUES (?, ?, ?, ?, ?)
        """, (
            event['session_id'],
            event.get('timestamp', datetime.now().isoformat()),
            event['event_type'],
            event.get('details', ''),
            event.get('risk_score', 0.0)
        ))
        conn.commit()
        return cursor.lastrowid

    def get_threat_events(self, session_id: str = None, limit: int = 50) -> List[Dict]:
        """Get threat events."""
        conn = self._get_connection()
        query = "SELECT * FROM threat_events"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # ─── Statistics ───────────────────────────────────────────

    def get_stats(self, session_id: str = None) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        return {
            "total_detections": self.get_detection_count(session_id),
            "severity_distribution": self.get_severity_distribution(session_id),
            "type_distribution": self.get_detection_types_distribution(session_id),
            "total_sessions": len(self.get_all_sessions()),
            "recent_alerts": self.get_recent_alerts(5, session_id),
        }

    # ─── Risk Score History (GAP 6) ───────────────────────────

    def get_risk_score_history(self, session_id: str = None, limit: int = 100) -> List[Dict]:
        """
        Get risk score history grouped by 5-minute buckets.
        Computes score from severity counts per bucket using the standard weights.

        Returns:
            List of {bucket, score} dicts
        """
        SEVERITY_WEIGHTS = {'LOW': 1, 'MEDIUM': 3, 'HIGH': 8, 'CRITICAL': 20}
        TIME_DECAY_FACTOR = 10

        conn = self._get_connection()
        query = """
            SELECT
                strftime('%Y-%m-%d %H:', timestamp) ||
                    printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / 5) * 5)
                    AS bucket,
                severity,
                COUNT(*) as count
            FROM detections
        """
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " GROUP BY bucket, severity ORDER BY bucket DESC LIMIT ?"
        params.append(limit * 4)  # Up to 4 severity levels per bucket

        rows = conn.execute(query, params).fetchall()

        # Aggregate by bucket
        bucket_data = {}
        for row in rows:
            bucket = row['bucket']
            sev = row['severity']
            count = row['count']
            if bucket not in bucket_data:
                bucket_data[bucket] = 0.0
            bucket_data[bucket] += SEVERITY_WEIGHTS.get(sev, 1) * count

        # Compute scores and format
        result = []
        for bucket, weighted_sum in sorted(bucket_data.items()):
            score = min(100.0, weighted_sum / TIME_DECAY_FACTOR)
            result.append({'bucket': bucket, 'score': round(score, 2)})

        return result[-limit:]

    def close(self):
        """Close the thread-local database connection."""
        if hasattr(self._local, 'connection') and self._local.connection:
            self._local.connection.close()
            self._local.connection = None
