"""
ViziDLP Phone Detector
Detects mobile phones in webcam feed to prevent camera-based data exfiltration.
Uses YOLOv8 to detect 'cell phone' objects. Includes face blur for privacy.
"""

import threading
import time
from typing import Callable, Dict, List, Optional

import cv2
import numpy as np

from utils.config import YOLO_CONFIDENCE_THRESHOLD


class PhoneDetector:
    """
    Detects phones in webcam frames using YOLOv8.
    When a phone is detected, triggers PHONE_CAMERA_EXFILTRATION alert.
    Also blurs faces in captured evidence frames for privacy.
    """

    PHONE_CLASS_NAMES = {'cell phone', 'cellphone', 'smartphone', 'mobile phone'}

    def __init__(self):
        self.model = None
        self.available = False
        self.face_cascade = None
        self.on_phone_detected_callback: Optional[Callable] = None
        self.detection_count = 0
        self._cooldown_time = 5  # seconds between alerts
        self._last_alert_time = 0.0
        self._lock = threading.Lock()
        self._confidence_threshold = max(YOLO_CONFIDENCE_THRESHOLD, 0.40)  # minimum 0.40 for phone detection
        self._load_model()
        self._load_face_cascade()

    def _load_model(self):
        """Load YOLOv8 model for phone detection."""
        try:
            from ultralytics import YOLO
            import os
            from utils.config import YOLO_MODEL_PATH, MODELS_DIR

            os.makedirs(MODELS_DIR, exist_ok=True)

            if os.path.exists(YOLO_MODEL_PATH):
                self.model = YOLO(YOLO_MODEL_PATH)
            else:
                print("[PHONE] Downloading YOLOv8n model for phone detection...")
                self.model = YOLO('yolov8n.pt')

            self.available = True
            print(f"[PHONE] Phone detector initialized (confidence threshold: {self._confidence_threshold}).")
        except ImportError:
            print("[PHONE] WARNING: ultralytics not installed. Phone detection disabled.")
            print("[PHONE] Install with: pip install ultralytics")
        except Exception as e:
            print(f"[PHONE] WARNING: Could not load model: {e}")

    def _load_face_cascade(self):
        """Load OpenCV Haar Cascade for face detection (privacy blur)."""
        try:
            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            self.face_cascade = cv2.CascadeClassifier(cascade_path)
            if self.face_cascade.empty():
                print("[PHONE] WARNING: Could not load face cascade.")
                self.face_cascade = None
            else:
                print("[PHONE] Face detection loaded for privacy blur.")
        except Exception as e:
            print(f"[PHONE] WARNING: Face cascade error: {e}")
            self.face_cascade = None

    def blur_faces(self, frame: np.ndarray) -> np.ndarray:
        """
        Detect and blur all faces in a frame for privacy.

        Args:
            frame: OpenCV BGR image

        Returns:
            Frame with all faces blurred
        """
        if self.face_cascade is None:
            return frame

        result = frame.copy()
        gray = cv2.cvtColor(result, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(
            gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
        )

        for (x, y, w, h) in faces:
            # Add padding around face region
            pad = int(max(w, h) * 0.2)
            x1 = max(0, x - pad)
            y1 = max(0, y - pad)
            x2 = min(result.shape[1], x + w + pad)
            y2 = min(result.shape[0], y + h + pad)

            # Apply heavy Gaussian blur to face region
            roi = result[y1:y2, x1:x2]
            blurred = cv2.GaussianBlur(roi, (99, 99), 30)
            result[y1:y2, x1:x2] = blurred

        return result

    def set_callback(self, callback: Callable):
        """Set callback for phone detection events."""
        self.on_phone_detected_callback = callback

    def detect_phone(self, frame: np.ndarray) -> List[Dict]:
        """
        Detect phones in a webcam frame.

        Args:
            frame: OpenCV BGR image from webcam

        Returns:
            List of phone detections with bbox, confidence
        """
        if not self.available or self.model is None:
            return []

        try:
            results = self.model(frame, conf=self._confidence_threshold, verbose=False)
            phone_detections = []

            for result in results:
                boxes = result.boxes
                if boxes is None:
                    continue

                # Debug: log ALL detected objects to help diagnose missed phones
                all_objects = []
                for box in boxes:
                    cls_id = int(box.cls[0])
                    class_name = self.model.names.get(cls_id, 'unknown').lower()
                    confidence = float(box.conf[0])
                    all_objects.append(f"{class_name}({confidence:.2f})")

                    if class_name in self.PHONE_CLASS_NAMES:
                        x1, y1, x2, y2 = box.xyxy[0].cpu().numpy()

                        detection = {
                            'class_name': class_name,
                            'confidence': confidence,
                            'bbox': (int(x1), int(y1), int(x2 - x1), int(y2 - y1)),
                            'category': 'phone_camera_exfiltration',
                            'severity': 'CRITICAL',
                            'description': f"Phone detected in webcam (confidence: {confidence:.2f}) -- possible camera data exfiltration"
                        }
                        phone_detections.append(detection)

                if all_objects:
                    print(f"[PHONE-DEBUG] Objects detected: {', '.join(all_objects)}")

            return phone_detections
        except Exception as e:
            print(f"[PHONE] Detection error: {e}")
            return []

    def process_webcam_frame(self, frame: np.ndarray) -> List[Dict]:
        """
        Process a webcam frame for phone detection.
        Only triggers callback if phone IS detected.
        Includes face blur on evidence frames.

        Args:
            frame: OpenCV BGR image from webcam

        Returns:
            List of phone detections (empty if no phone found)
        """
        detections = self.detect_phone(frame)

        if detections:
            with self._lock:
                now = time.time()
                if now - self._last_alert_time >= self._cooldown_time:
                    self._last_alert_time = now
                    self.detection_count += len(detections)

                    # Blur faces for privacy BEFORE sending evidence
                    privacy_frame = self.blur_faces(frame)

                    for det in detections:
                        print(f"[PHONE] WARNING - PHONE DETECTED: {det['description']}")

                        if self.on_phone_detected_callback:
                            self.on_phone_detected_callback(det, privacy_frame)

        return detections

    def get_detection_count(self) -> int:
        """Get total number of phone detections."""
        return self.detection_count

    def is_available(self) -> bool:
        """Check if phone detection is available."""
        return self.available
