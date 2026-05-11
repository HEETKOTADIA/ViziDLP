"""
ViziDLP Clipboard Monitor
Polls clipboard text every 2 seconds and scans for sensitive data patterns.

- Uses pyperclip for cross-platform clipboard access
- Runs PatternDetector.detect() on clipboard content
- Fires callback on CRITICAL or HIGH severity detections
- Does NOT clear clipboard by default (that is PolicyEngine's job)
- Handles headless/no-clipboard environments gracefully
"""

import re
import threading
import time
from typing import Callable, Optional

from detection.pattern_detector import PatternDetector


class ClipboardMonitor:
    """
    Monitors system clipboard for sensitive data patterns.

    Interface:
      - start(callback): Begin monitoring with a detection callback
      - stop(): Stop monitoring
      - is_running(): Check if the monitor is active
    """

    POLL_INTERVAL = 2  # seconds
    ALERT_SEVERITIES = {"CRITICAL", "HIGH"}

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable] = None
        self._pattern_detector = PatternDetector()
        self._last_clipboard_text = ""
        print("[CLIPBOARD] Clipboard monitor initialized.")

    def start(self, callback: Callable):
        """
        Start clipboard monitoring.

        Args:
            callback: Function to call on sensitive detection.
                      Signature: callback(detections: list, text_preview: str)
        """
        if self._running:
            return

        self._callback = callback
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        print("[CLIPBOARD] Clipboard monitoring started.")

    def stop(self):
        """Stop clipboard monitoring."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print("[CLIPBOARD] Clipboard monitoring stopped.")

    def is_running(self) -> bool:
        """Check if the clipboard monitor is active."""
        return self._running

    def _poll_loop(self):
        """Main polling loop — runs in a daemon thread."""
        while self._running:
            try:
                self._check_clipboard()
            except Exception as e:
                # Silently handle all errors to avoid crashing the daemon thread
                pass
            time.sleep(self.POLL_INTERVAL)

    def _check_clipboard(self):
        """Check clipboard content for sensitive patterns."""
        try:
            import pyperclip
            text = pyperclip.paste()
        except ImportError:
            # pyperclip not installed — stop silently
            return
        except Exception:
            # PyperclipException or other clipboard access errors (headless env)
            return

        if not text or not text.strip():
            return

        # Only process if clipboard content has changed
        if text == self._last_clipboard_text:
            return
        self._last_clipboard_text = text

        # Run pattern detection
        detections = self._pattern_detector.detect(text)

        # Filter to CRITICAL and HIGH only
        sensitive = [d for d in detections if d.get('severity') in self.ALERT_SEVERITIES]

        if sensitive and self._callback:
            # Create text preview: first 80 chars with PII replaced
            text_preview = self._create_preview(text, sensitive)
            self._callback(sensitive, text_preview)

    @staticmethod
    def _create_preview(text: str, detections: list) -> str:
        """
        Create a safe text preview (first 80 chars) with PII replaced by '***'.
        """
        preview = text[:80]
        for det in detections:
            matched = det.get('matched_text', '')
            if matched and matched in preview:
                preview = preview.replace(matched, '***')
        # Also do a generic scrub of any remaining digit sequences > 8 chars
        preview = re.sub(r'\d{8,}', '***', preview)
        return preview
