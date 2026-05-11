"""
ViziDLP Face Recognizer
Detects and optionally matches faces from webcam frames against a known-faces registry.
Uses OpenCV + face_recognition library (if available) or falls back to Haar cascade detection only.

Privacy note: Face embeddings are stored locally only. No cloud upload.
"""

import os
import cv2
import numpy as np
from typing import List, Dict, Optional

FACE_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "face_registry")


class FaceRecognizer:
    """Detects and optionally recognizes faces using Haar cascade + face_recognition library."""

    def __init__(self):
        self.available = False
        self.recognition_available = False
        self.known_faces = {}  # name -> encoding
        self._cascade = None
        self._fr = None
        os.makedirs(FACE_DB_DIR, exist_ok=True)
        self._load_cascade()
        self._try_load_recognition()
        print(f"[FACE] Face recognizer initialized (recognition={'yes' if self.recognition_available else 'cascade-only'})")

    def _load_cascade(self):
        """Load the Haar cascade classifier for face detection."""
        try:
            path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            self._cascade = cv2.CascadeClassifier(path)
            self.available = not self._cascade.empty()
        except Exception as e:
            print(f"[FACE] Cascade load failed: {e}")

    def _try_load_recognition(self):
        """Try to import face_recognition for full matching capability."""
        try:
            import face_recognition
            self._fr = face_recognition
            self.recognition_available = True
            self._load_known_faces()
        except ImportError:
            self._fr = None

    def _load_known_faces(self):
        """Load known face images from face_registry/ directory."""
        if not self.recognition_available:
            return
        for fname in os.listdir(FACE_DB_DIR):
            if fname.lower().endswith(('.jpg', '.jpeg', '.png')):
                name = os.path.splitext(fname)[0]
                img_path = os.path.join(FACE_DB_DIR, fname)
                try:
                    img = self._fr.load_image_file(img_path)
                    encs = self._fr.face_encodings(img)
                    if encs:
                        self.known_faces[name] = encs[0]
                        print(f"[FACE] Loaded known face: {name}")
                except Exception as e:
                    print(f"[FACE] Could not load {fname}: {e}")

    def detect_faces(self, frame: np.ndarray) -> List[Dict]:
        """Detect faces in frame. Returns list of {bbox, name, matched, confidence}."""
        if not self.available:
            return []
        results = []
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = self._cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(60, 60))
        except Exception as e:
            print(f"[FACE] Detection error: {e}")
            return []

        for (x, y, w, h) in faces:
            entry = {
                'bbox': (x, y, w, h),
                'name': 'Unknown',
                'matched': False,
                'confidence': 0.0,
            }
            if self.recognition_available and self.known_faces:
                try:
                    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    encodings = self._fr.face_encodings(rgb, [(y, x + w, y + h, x)])
                    if encodings:
                        enc = encodings[0]
                        for name, known_enc in self.known_faces.items():
                            dist = self._fr.face_distance([known_enc], enc)[0]
                            if dist < 0.6:
                                entry['name'] = name
                                entry['matched'] = True
                                entry['confidence'] = round(1.0 - dist, 3)
                                break
                except Exception as e:
                    print(f"[FACE] Recognition error: {e}")
            results.append(entry)
        return results

    def add_known_face(self, name: str, image_path: str) -> bool:
        """Register a new known face."""
        if not self.recognition_available:
            return False
        try:
            img = self._fr.load_image_file(image_path)
            encs = self._fr.face_encodings(img)
            if encs:
                self.known_faces[name] = encs[0]
                dest = os.path.join(FACE_DB_DIR, f"{name}.jpg")
                import shutil
                shutil.copy(image_path, dest)
                return True
        except Exception as e:
            print(f"[FACE] Failed to register {name}: {e}")
        return False

    def get_known_names(self) -> List[str]:
        """Return list of registered face names."""
        return list(self.known_faces.keys())
