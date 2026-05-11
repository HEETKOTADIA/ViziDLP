"""
ViziDLP Utility Helpers
Common utility functions used across the system.
"""

import base64
import hashlib
import os
import uuid
from datetime import datetime

import cv2
import numpy as np


def generate_uuid() -> str:
    """Generate a unique identifier."""
    return str(uuid.uuid4())


def get_timestamp() -> str:
    """Get current timestamp in ISO format."""
    return datetime.now().isoformat()


def get_timestamp_filename() -> str:
    """Get a filename-safe timestamp string."""
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def image_to_base64(image: np.ndarray) -> str:
    """Convert an OpenCV image (numpy array) to a base64-encoded JPEG string."""
    _, buffer = cv2.imencode('.jpg', image, [cv2.IMWRITE_JPEG_QUALITY, 85])
    return base64.b64encode(buffer).decode('utf-8')


def base64_to_image(b64_string: str) -> np.ndarray:
    """Convert a base64-encoded string back to an OpenCV image."""
    img_data = base64.b64decode(b64_string)
    np_arr = np.frombuffer(img_data, np.uint8)
    return cv2.imdecode(np_arr, cv2.IMREAD_COLOR)


def save_image(image: np.ndarray, filepath: str) -> str:
    """Save an OpenCV image to disk. Returns the filepath."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    cv2.imwrite(filepath, image)
    return filepath


def compute_image_hash(image: np.ndarray) -> str:
    """Compute SHA-256 hash of an image for deduplication."""
    _, buffer = cv2.imencode('.jpg', image)
    return hashlib.sha256(buffer.tobytes()).hexdigest()[:16]


def resize_for_processing(image: np.ndarray, max_width: int = 1920) -> np.ndarray:
    """Resize image for processing if it exceeds max_width, preserving aspect ratio."""
    h, w = image.shape[:2]
    if w > max_width:
        scale = max_width / w
        new_w = int(w * scale)
        new_h = int(h * scale)
        return cv2.resize(image, (new_w, new_h), interpolation=cv2.INTER_AREA)
    return image


def format_severity_badge(severity: str) -> str:
    """Return HTML badge markup for a severity level."""
    colors = {
        "LOW": "#4caf50",
        "MEDIUM": "#ff9800",
        "HIGH": "#f44336",
        "CRITICAL": "#9c27b0"
    }
    color = colors.get(severity, "#757575")
    return f'<span class="badge" style="background-color:{color}">{severity}</span>'


def ensure_dir(path: str) -> str:
    """Ensure a directory exists, create if it doesn't. Returns the path."""
    os.makedirs(path, exist_ok=True)
    return path
