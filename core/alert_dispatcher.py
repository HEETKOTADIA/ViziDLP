"""
ViziDLP Alert Dispatcher
Sends structured alert payloads to configured webhook endpoints.
Enables integration with SIEM, Slack, Teams, or any HTTP endpoint.
"""

import json
import threading
import time
from datetime import datetime
from typing import Optional
import urllib.request
import urllib.error

from utils.config import ALERT_WEBHOOK_URL, ALERT_WEBHOOK_ENABLED, ALERT_ON_SEVERITY, SEVERITY_LEVELS


class AlertDispatcher:
    """Dispatches structured alerts to configured webhook endpoints."""

    def __init__(self):
        self.enabled = ALERT_WEBHOOK_ENABLED
        self.webhook_url = ALERT_WEBHOOK_URL
        self._queue = []
        self._lock = threading.Lock()
        self._dispatched_count = 0
        if self.enabled:
            self._worker = threading.Thread(target=self._dispatch_loop, daemon=True)
            self._worker.start()
        print(f"[ALERT] Alert dispatcher initialized (webhook={'enabled' if self.enabled else 'disabled'})")

    def dispatch(self, detection_type: str, severity: str, description: str, session_id: str, confidence: float = 0.0):
        """Queue an alert for dispatch if severity meets threshold."""
        if not self.enabled:
            return
        if severity not in ALERT_ON_SEVERITY:
            return
        payload = {
            "source": "ViziDLP",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "session_id": session_id,
            "detection_type": detection_type,
            "severity": severity,
            "description": description,
            "confidence": round(confidence, 3),
        }
        with self._lock:
            self._queue.append(payload)

    def _dispatch_loop(self):
        """Background loop to batch-send queued alerts."""
        while True:
            time.sleep(2)
            with self._lock:
                batch = self._queue[:]
                self._queue.clear()
            for payload in batch:
                self._send(payload)

    def _send(self, payload: dict):
        """Send a single alert payload to the webhook endpoint."""
        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self._dispatched_count += 1
                print(f"[ALERT] Dispatched {payload['severity']} alert → HTTP {resp.status}")
        except Exception as e:
            print(f"[ALERT] Dispatch failed: {e}")

    def get_stats(self) -> dict:
        """Return alert dispatcher statistics."""
        endpoint_preview = ""
        if self.webhook_url:
            endpoint_preview = "..." + self.webhook_url[-20:] if len(self.webhook_url) > 20 else self.webhook_url
        return {
            "enabled": self.enabled,
            "dispatched": self._dispatched_count,
            "endpoint_preview": endpoint_preview,
        }
