"""
ViziDLP Screen Monitor
Continuously captures the user's screen and provides frames for analysis.
Uses the 'mss' library for fast, cross-platform screen capture.
"""

import threading
import time
from typing import Callable, Optional

import cv2
import numpy as np

try:
    import mss
    import mss.tools
    MSS_AVAILABLE = True
except ImportError:
    MSS_AVAILABLE = False

from utils.config import SCREEN_CAPTURE_FPS


class ScreenMonitor:
    """Threaded screen capture monitor."""

    def __init__(self, fps: int = SCREEN_CAPTURE_FPS):
        self.fps = fps
        self.interval = 1.0 / fps
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.latest_frame: Optional[np.ndarray] = None
        self.frame_lock = threading.Lock()
        self.on_frame_callback: Optional[Callable] = None
        self.frame_count = 0

        if not MSS_AVAILABLE:
            print("[SCREEN] WARNING: 'mss' not installed. Screen monitoring disabled.")
            print("[SCREEN] Install with: pip install mss")

    def start(self, on_frame: Callable = None):
        """
        Start screen monitoring in a background thread.
        
        Args:
            on_frame: Callback function called with each captured frame (np.ndarray)
        """
        if not MSS_AVAILABLE:
            return

        self.on_frame_callback = on_frame
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        print(f"[SCREEN] Screen monitor started ({self.fps} FPS)")

    def stop(self):
        """Stop screen monitoring."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)
        print("[SCREEN] Screen monitor stopped.")

    def _capture_loop(self):
        """Main capture loop running in a separate thread."""
        with mss.mss() as sct:
            # Capture the primary monitor
            monitor = sct.monitors[1]  # monitors[0] is all monitors combined

            while self.running:
                start_time = time.time()

                try:
                    # Capture screen
                    screenshot = sct.grab(monitor)

                    # Convert to numpy array (BGRA → BGR)
                    frame = np.array(screenshot)
                    frame = cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)

                    # Store latest frame
                    with self.frame_lock:
                        self.latest_frame = frame
                        self.frame_count += 1

                    # Invoke callback if set
                    if self.on_frame_callback:
                        self.on_frame_callback(frame, "screen")

                except Exception as e:
                    print(f"[SCREEN] Capture error: {e}")

                # Maintain target FPS
                elapsed = time.time() - start_time
                sleep_time = self.interval - elapsed
                if sleep_time > 0:
                    time.sleep(sleep_time)

    def get_latest_frame(self) -> Optional[np.ndarray]:
        """Get the most recent captured frame."""
        with self.frame_lock:
            return self.latest_frame.copy() if self.latest_frame is not None else None

    def is_running(self) -> bool:
        """Check if the monitor is currently running."""
        return self.running and self.thread is not None and self.thread.is_alive()
