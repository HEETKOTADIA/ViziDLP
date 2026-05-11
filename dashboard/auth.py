"""
ViziDLP Dashboard Authentication
Session-based authentication for the Flask dashboard.

- Uses bcrypt for password hashing
- Default password: "vizidlp-admin" (auto-hashed on first run with a warning)
- login_required decorator checks Flask session["authed"]
- API routes (/api/*) remain public (localhost-only, used by pipeline)
"""

import functools
import os
import sys

from flask import session, redirect, url_for, request

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import DASHBOARD_PASSWORD_HASH, FLASK_SECRET_KEY


class DashboardAuth:
    """
    Manages dashboard authentication state and password verification.

    Usage:
        auth = DashboardAuth()
        app.secret_key = auth.secret_key

        @app.route('/protected')
        @auth.login_required
        def protected():
            ...
    """

    _startup_warning_shown = False

    def __init__(self):
        self.secret_key = FLASK_SECRET_KEY
        self._password_hash = self._ensure_password_hash()

        # Show startup warnings once only
        if not DashboardAuth._startup_warning_shown:
            DashboardAuth._startup_warning_shown = True
            if FLASK_SECRET_KEY == "change-me-in-production":
                print("[AUTH] WARNING: Using default FLASK_SECRET_KEY. "
                      "Change it in utils/config.py for production!")
            if not DASHBOARD_PASSWORD_HASH:
                print("[AUTH] WARNING: No password hash configured. "
                      "Using default password 'vizidlp-admin'. "
                      "Change DASHBOARD_PASSWORD_HASH in utils/config.py!")

    def _ensure_password_hash(self) -> bytes:
        """
        Ensure we have a valid bcrypt password hash.
        If no hash configured, auto-hash the default password.
        """
        if DASHBOARD_PASSWORD_HASH:
            # If it's a string, encode to bytes
            if isinstance(DASHBOARD_PASSWORD_HASH, str):
                return DASHBOARD_PASSWORD_HASH.encode('utf-8')
            return DASHBOARD_PASSWORD_HASH

        # Auto-hash the default password
        try:
            import bcrypt
            default_hash = bcrypt.hashpw(
                "vizidlp-admin".encode('utf-8'),
                bcrypt.gensalt()
            )
            return default_hash
        except ImportError:
            print("[AUTH] WARNING: bcrypt not installed — password check will use plaintext fallback")
            return b""

    def check_password(self, plain: str) -> bool:
        """
        Verify a plaintext password against the stored hash.

        Args:
            plain: Plaintext password to check

        Returns:
            True if password matches
        """
        try:
            import bcrypt
            return bcrypt.checkpw(
                plain.encode('utf-8'),
                self._password_hash
            )
        except ImportError:
            # Fallback: compare against default plaintext
            return plain == "vizidlp-admin"
        except Exception:
            return False

    @staticmethod
    def login_required(f):
        """
        Decorator to require authentication for a route.
        Checks session["authed"] — redirects to /login if not authed.
        """
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('authed'):
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
