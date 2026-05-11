"""
ViziDLP Session Manager
Handles session creation with timestamp-based IDs, isolation, and evidence directory management.
"""

import os
from datetime import datetime
from typing import Optional

from database.database import Database
from utils.config import EVIDENCE_DIR
from utils.helpers import ensure_dir


class SessionManager:
    """Manages monitoring sessions with isolated evidence storage."""

    def __init__(self, db: Database):
        self.db = db
        self.current_session_id: Optional[str] = None
        self.session_folder_name: Optional[str] = None
        self.current_evidence_path: Optional[str] = None
        self.session_number: int = 0

    def start_new_session(self) -> str:
        """
        Create a new monitoring session with timestamp-based ID.
        Format: session_YYYYMMDD_HHMMSS
        Returns the session ID (same as folder name).
        """
        ensure_dir(EVIDENCE_DIR)

        # Count existing sessions
        existing = [
            d for d in os.listdir(EVIDENCE_DIR)
            if os.path.isdir(os.path.join(EVIDENCE_DIR, d)) and d.startswith("session_")
        ]
        self.session_number = len(existing) + 1

        # Create timestamp-based session ID
        now = datetime.now()
        self.session_folder_name = now.strftime("session_%Y%m%d_%H%M%S")
        self.current_session_id = self.session_folder_name
        self.current_evidence_path = os.path.join(EVIDENCE_DIR, self.session_folder_name)

        # Create evidence subdirectories
        ensure_dir(self.current_evidence_path)
        ensure_dir(os.path.join(self.current_evidence_path, "screenshots"))
        ensure_dir(os.path.join(self.current_evidence_path, "redacted"))
        ensure_dir(os.path.join(self.current_evidence_path, "webcam"))

        # Register session in database
        self.db.create_session(self.current_session_id, self.current_evidence_path)

        print(f"[SESSION] Started session: {self.current_session_id}")
        print(f"[SESSION] Evidence path: {self.current_evidence_path}")

        return self.current_session_id

    def end_session(self) -> None:
        """End the current monitoring session."""
        if self.current_session_id:
            self.db.end_session(self.current_session_id)
            print(f"[SESSION] Ended session: {self.current_session_id}")
            self.current_session_id = None

    def get_evidence_path(self, subfolder: str = "") -> str:
        """Get evidence path for the current session, optionally with a subfolder."""
        if not self.current_evidence_path:
            raise RuntimeError("No active session. Call start_new_session() first.")
        path = os.path.join(self.current_evidence_path, subfolder) if subfolder else self.current_evidence_path
        return ensure_dir(path)

    def get_session_info(self) -> dict:
        """Get current session information."""
        return {
            "session_id": self.current_session_id,
            "session_number": self.session_number,
            "evidence_path": self.current_evidence_path,
            "status": "active" if self.current_session_id else "inactive"
        }

    @staticmethod
    def get_all_session_folders() -> list:
        """Get all session folder names, newest first."""
        if not os.path.exists(EVIDENCE_DIR):
            return []
        folders = [
            d for d in os.listdir(EVIDENCE_DIR)
            if os.path.isdir(os.path.join(EVIDENCE_DIR, d)) and d.startswith("session_")
        ]
        return sorted(folders, reverse=True)
