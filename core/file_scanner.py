"""
ViziDLP File-Level DLP Scanner
Scans PDF, DOCX, and TXT files for sensitive data patterns.

- Watches a configurable directory for new/modified files
- Extracts text using PyPDF2 (PDF), python-docx (DOCX), or plain read (TXT)
- Runs PatternDetector.detect() on extracted text
- Logs detections with file path, page/paragraph number, and severity
- Runs as a daemon thread with configurable poll interval
"""

import os
import time
import threading
from typing import Callable, Dict, List, Optional

from detection.pattern_detector import PatternDetector
from detection.severity_classifier import SeverityClassifier

# ─── Optional imports ─────────────────────────────────────────
PDF_AVAILABLE = False
try:
    from PyPDF2 import PdfReader
    PDF_AVAILABLE = True
except ImportError:
    pass

DOCX_AVAILABLE = False
try:
    from docx import Document as DocxDocument
    DOCX_AVAILABLE = True
except ImportError:
    pass


class FileScanner:
    """
    Scans files in a watched directory for sensitive data.

    Interface:
      - start(callback): Begin watching with a detection callback
      - stop(): Stop watching
      - scan_file(path): Manually scan a single file
      - scan_directory(path): Manually scan all supported files in a directory
      - is_running(): Check if the watcher is active
    """

    SUPPORTED_EXTENSIONS = {'.pdf', '.docx', '.txt', '.csv', '.log', '.json', '.xml'}
    POLL_INTERVAL = 15  # seconds between directory scans

    def __init__(self, watch_dir: str = None):
        self._watch_dir = watch_dir
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable] = None
        self._pattern_detector = PatternDetector()
        self._severity_classifier = SeverityClassifier()
        self._scanned_files: Dict[str, float] = {}  # path -> last_modified_time
        self._scan_count = 0
        self._detection_count = 0

        caps = []
        if PDF_AVAILABLE:
            caps.append("PDF")
        if DOCX_AVAILABLE:
            caps.append("DOCX")
        caps.append("TXT")
        print(f"[FILE-DLP] File scanner initialized (formats: {', '.join(caps)}).")

    def start(self, callback: Callable = None):
        """
        Start watching the configured directory.

        Args:
            callback: Function called on detection.
                      Signature: callback(detections: list, file_path: str)
        """
        if self._running or not self._watch_dir:
            return

        if not os.path.isdir(self._watch_dir):
            print(f"[FILE-DLP] Watch directory does not exist: {self._watch_dir}")
            return

        self._callback = callback
        self._running = True
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()
        print(f"[FILE-DLP] Watching directory: {self._watch_dir}")

    def stop(self):
        """Stop watching."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        print("[FILE-DLP] File scanner stopped.")

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict:
        return {
            'files_scanned': self._scan_count,
            'detections_found': self._detection_count,
            'watching': self._watch_dir or '',
            'running': self._running,
            'pdf_support': PDF_AVAILABLE,
            'docx_support': DOCX_AVAILABLE,
        }

    def _watch_loop(self):
        """Poll the directory for new/modified files."""
        while self._running:
            try:
                self._scan_watched_directory()
            except Exception as e:
                print(f"[FILE-DLP] Watch error: {e}")
            time.sleep(self.POLL_INTERVAL)

    def _scan_watched_directory(self):
        """Scan all supported files in the watched directory."""
        if not self._watch_dir or not os.path.isdir(self._watch_dir):
            return

        for root, _dirs, files in os.walk(self._watch_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                ext = os.path.splitext(filename)[1].lower()

                if ext not in self.SUPPORTED_EXTENSIONS:
                    continue

                try:
                    mtime = os.path.getmtime(filepath)
                except OSError:
                    continue

                # Skip files we've already scanned at this mtime
                if filepath in self._scanned_files and self._scanned_files[filepath] >= mtime:
                    continue

                self._scanned_files[filepath] = mtime
                detections = self.scan_file(filepath)

                if detections and self._callback:
                    self._callback(detections, filepath)

    def scan_file(self, filepath: str) -> List[Dict]:
        """
        Scan a single file for sensitive data.

        Args:
            filepath: Absolute path to the file

        Returns:
            List of detection dicts with type, severity, matched_text, location
        """
        ext = os.path.splitext(filepath)[1].lower()
        self._scan_count += 1

        try:
            if ext == '.pdf':
                return self._scan_pdf(filepath)
            elif ext == '.docx':
                return self._scan_docx(filepath)
            else:
                return self._scan_text(filepath)
        except Exception as e:
            print(f"[FILE-DLP] Error scanning {filepath}: {e}")
            return []

    def scan_directory(self, dirpath: str) -> List[Dict]:
        """Scan all supported files in a directory (non-recursive)."""
        all_detections = []
        if not os.path.isdir(dirpath):
            return all_detections

        for filename in os.listdir(dirpath):
            filepath = os.path.join(dirpath, filename)
            if not os.path.isfile(filepath):
                continue
            ext = os.path.splitext(filename)[1].lower()
            if ext in self.SUPPORTED_EXTENSIONS:
                detections = self.scan_file(filepath)
                all_detections.extend(detections)

        return all_detections

    def _scan_pdf(self, filepath: str) -> List[Dict]:
        """Extract and scan text from a PDF file."""
        if not PDF_AVAILABLE:
            return []

        detections = []
        try:
            reader = PdfReader(filepath)
            for page_num, page in enumerate(reader.pages, 1):
                text = page.extract_text() or ""
                if text.strip():
                    matches = self._pattern_detector.detect(text)
                    for m in matches:
                        m['source_file'] = filepath
                        m['location'] = f"page {page_num}"
                        m['source'] = 'file_scan'
                        detections.append(m)
        except Exception as e:
            print(f"[FILE-DLP] PDF error ({filepath}): {e}")

        if detections:
            self._detection_count += len(detections)
            print(f"[FILE-DLP] {len(detections)} detection(s) in PDF: {os.path.basename(filepath)}")
        return detections

    def _scan_docx(self, filepath: str) -> List[Dict]:
        """Extract and scan text from a DOCX file."""
        if not DOCX_AVAILABLE:
            return []

        detections = []
        try:
            doc = DocxDocument(filepath)
            for para_num, para in enumerate(doc.paragraphs, 1):
                text = para.text or ""
                if text.strip():
                    matches = self._pattern_detector.detect(text)
                    for m in matches:
                        m['source_file'] = filepath
                        m['location'] = f"paragraph {para_num}"
                        m['source'] = 'file_scan'
                        detections.append(m)
        except Exception as e:
            print(f"[FILE-DLP] DOCX error ({filepath}): {e}")

        if detections:
            self._detection_count += len(detections)
            print(f"[FILE-DLP] {len(detections)} detection(s) in DOCX: {os.path.basename(filepath)}")
        return detections

    def _scan_text(self, filepath: str) -> List[Dict]:
        """Scan a plain text file."""
        detections = []
        try:
            # Read with size limit (10MB max)
            file_size = os.path.getsize(filepath)
            if file_size > 10 * 1024 * 1024:
                print(f"[FILE-DLP] Skipping large file ({file_size} bytes): {filepath}")
                return []

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip():
                        matches = self._pattern_detector.detect(line)
                        for m in matches:
                            m['source_file'] = filepath
                            m['location'] = f"line {line_num}"
                            m['source'] = 'file_scan'
                            detections.append(m)
        except Exception as e:
            print(f"[FILE-DLP] Text scan error ({filepath}): {e}")

        if detections:
            self._detection_count += len(detections)
            print(f"[FILE-DLP] {len(detections)} detection(s) in: {os.path.basename(filepath)}")
        return detections
