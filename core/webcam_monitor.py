"""
ViziDLP Webcam Monitor
Monitors live webcam feed for phone detection.
Changed: no longer runs continuous frame callbacks. Instead, capture runs internally
and the phone detector polls frames on demand. This reduces false positives.
"""

import threading
import time
from typing import Optional

import cv2
import numpy as np

from utils.config import WEBCAM_INDEX


class WebcamMonitor:
    """
    Threaded webcam capture monitor.
    Captures frames at low FPS but does NOT call any external callback.
    Instead, frames are stored internally for the phone detector to consume.
    """

    def __init__(self, camera_index: int = WEBCAM_INDEX):
        self.camera_index = camera_index
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.cap: Optional[cv2.VideoCapture] = None
        self.latest_frame: Optional[np.ndarray] = None
        self.frame_lock = threading.Lock()
        self.frame_count = 0
        self._capture_interval = 0.5  # capture every 0.5 seconds for responsive phone detection

    def start(self):
        """Start webcam capture in a background thread (no callback — just stores frames)."""
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        print(f"[WEBCAM] Webcam monitor started (camera {self.camera_index}, interval {self._capture_interval}s)")

    def stop(self):
        """Stop webcam monitoring and release camera."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)
        if self.cap and self.cap.isOpened():
            self.cap.release()
        print("[WEBCAM] Webcam monitor stopped.")

    def _capture_loop(self):
        """Main capture loop — grabs a frame every N seconds."""
        self.cap = cv2.VideoCapture(self.camera_index)

        if not self.cap.isOpened():
            print(f"[WEBCAM] WARNING: Could not open camera {self.camera_index}")
            self.running = False
            return

        while self.running:
            start_time = time.time()

            try:
                ret, frame = self.cap.read()
                if not ret:
                    time.sleep(1)
                    continue

                with self.frame_lock:
                    self.latest_frame = frame
                    self.frame_count += 1

            except Exception as e:
                print(f"[WEBCAM] Capture error: {e}")

            # Sleep until next capture interval
            elapsed = time.time() - start_time
            sleep_time = self._capture_interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

        if self.cap and self.cap.isOpened():
            self.cap.release()

    def get_latest_frame(self) -> Optional[np.ndarray]:
        """Get the most recent captured frame."""
        with self.frame_lock:
            return self.latest_frame.copy() if self.latest_frame is not None else None

    def is_running(self) -> bool:
        """Check if the webcam monitor is currently running."""
        return self.running and self.thread is not None and self.thread.is_alive()
