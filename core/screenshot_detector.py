"""
ViziDLP Screenshot Detector
Detects when the user takes a screenshot using keyboard shortcuts.
"""

import threading
from typing import Callable, Optional

try:
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False


class ScreenshotDetector:
    """Monitors keyboard events to detect screenshot actions."""

    def __init__(self):
        self.running = False
        self.listener = None
        self.on_screenshot_callback = None
        self.screenshot_count = 0
        self._pressed_keys = set()
        if not PYNPUT_AVAILABLE:
            print("[SCREENSHOT] WARNING: pynput not installed.")

    def start(self, on_screenshot: Callable = None):
        if not PYNPUT_AVAILABLE:
            return
        self.on_screenshot_callback = on_screenshot
        self.running = True
        self.listener = keyboard.Listener(
            on_press=self._on_key_press,
            on_release=self._on_key_release
        )
        self.listener.daemon = True
        self.listener.start()
        print("[SCREENSHOT] Screenshot detector started.")

    def stop(self):
        self.running = False
        if self.listener:
            self.listener.stop()
        print("[SCREENSHOT] Screenshot detector stopped.")

    def _on_key_press(self, key):
        if not self.running:
            return
        try:
            self._pressed_keys.add(key)
            if key == keyboard.Key.print_screen:
                self._trigger("PrintScreen")
            elif (keyboard.Key.cmd in self._pressed_keys or
                  keyboard.Key.cmd_l in self._pressed_keys or
                  keyboard.Key.cmd_r in self._pressed_keys):
                if (keyboard.Key.shift in self._pressed_keys or
                    keyboard.Key.shift_l in self._pressed_keys or
                    keyboard.Key.shift_r in self._pressed_keys):
                    if hasattr(key, 'char') and key.char and key.char.lower() == 's':
                        self._trigger("Win+Shift+S")
        except AttributeError:
            pass

    def _on_key_release(self, key):
        try:
            self._pressed_keys.discard(key)
        except (AttributeError, KeyError):
            pass

    def _trigger(self, method: str):
        self.screenshot_count += 1
        print(f"[SCREENSHOT] Detected via {method} (total: {self.screenshot_count})")
        if self.on_screenshot_callback:
            self.on_screenshot_callback(method)

    def get_screenshot_count(self) -> int:
        return self.screenshot_count

    def is_running(self) -> bool:
        return self.running and self.listener is not None and self.listener.is_alive()
