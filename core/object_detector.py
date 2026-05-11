"""
ViziDLP Object Detector — Enhanced Document Detection
Uses YOLOv8 for detecting sensitive objects (ID cards, documents, phones, etc.)
Enhanced document classification with keyword detection for identity documents.
"""

import os
from typing import Dict, List, Tuple

import cv2
import numpy as np

from utils.config import YOLO_MODEL_PATH, YOLO_CONFIDENCE_THRESHOLD, MODELS_DIR


class ObjectDetector:
    """YOLOv8-based object detector for sensitive documents and objects."""

    # Mapping from COCO classes to sensitive document types
    SENSITIVE_OBJECT_MAP = {
        'cell phone': 'mobile_device',
        'laptop': 'computing_device',
        'book': 'potential_document',
        'tvmonitor': 'display_screen',
        'monitor': 'display_screen',
    }

    # Document detection classes — HIGH severity
    DOCUMENT_CLASSES = {
        'aadhaar_card': 'aadhaar_card_object',
        'pan_card': 'pan_card_object',
        'credit_card': 'credit_card_object',
        'passport': 'passport_object',
        'driver_license': 'driver_license_object',
        'id_card': 'id_card_object',
        'identity_document': 'identity_document',
    }

    def __init__(self):
        self.model = None
        self.available = False
        self._load_model()

    def _load_model(self):
        """Load the YOLOv8 model."""
        try:
            from ultralytics import YOLO

            os.makedirs(MODELS_DIR, exist_ok=True)

            if os.path.exists(YOLO_MODEL_PATH):
                self.model = YOLO(YOLO_MODEL_PATH)
            else:
                print("[YOLO] Downloading YOLOv8n model (first run only)...")
                self.model = YOLO('yolov8n.pt')
                model_dir = os.path.dirname(YOLO_MODEL_PATH)
                os.makedirs(model_dir, exist_ok=True)

            self.available = True
            print("[YOLO] YOLOv8 object detector initialized successfully.")
        except ImportError:
            print("[YOLO] WARNING: ultralytics not installed. Object detection disabled.")
            print("[YOLO] Install with: pip install ultralytics")
        except Exception as e:
            print(f"[YOLO] WARNING: Could not load YOLOv8 model: {e}")

    def detect(self, frame: np.ndarray) -> List[Dict]:
        """
        Detect objects in a frame.

        Args:
            frame: OpenCV BGR image

        Returns:
            List of detections, each containing:
                - class_name: detected object class
                - confidence: detection confidence
                - bbox: (x, y, w, h) bounding box
                - is_sensitive: whether this object is potentially sensitive
                - category: mapped sensitive category
        """
        if not self.available or self.model is None:
            return []

        try:
            results = self.model(frame, conf=YOLO_CONFIDENCE_THRESHOLD, verbose=False)

            detections = []
            for result in results:
                boxes = result.boxes
                if boxes is None:
                    continue

                for box in boxes:
                    x1, y1, x2, y2 = box.xyxy[0].cpu().numpy()
                    x, y, w, h = int(x1), int(y1), int(x2 - x1), int(y2 - y1)

                    cls_id = int(box.cls[0])
                    confidence = float(box.conf[0])
                    class_name = self.model.names.get(cls_id, 'unknown')

                    is_sensitive = class_name.lower() in self.SENSITIVE_OBJECT_MAP
                    category = self.SENSITIVE_OBJECT_MAP.get(class_name.lower(), class_name)

                    detection = {
                        'class_name': class_name,
                        'confidence': confidence,
                        'bbox': (x, y, w, h),
                        'is_sensitive': is_sensitive,
                        'category': category
                    }
                    detections.append(detection)

            return detections
        except Exception as e:
            print(f"[YOLO] Error during detection: {e}")
            return []

    def detect_documents(self, frame: np.ndarray, ocr_text: str = "") -> List[Dict]:
        """
        Detect document-shaped objects and classify them using visual + OCR cues.
        Uses aspect ratio analysis and OCR text to identify card-like objects.

        Args:
            frame: OpenCV BGR image
            ocr_text: Text extracted from OCR for classification assistance

        Returns:
            List of document detections
        """
        detections = []

        # Run standard YOLO detection first
        yolo_detections = self.detect(frame)
        detections.extend(yolo_detections)

        # Additional document detection using contour analysis
        doc_detections = self._detect_card_shapes(frame, ocr_text)
        detections.extend(doc_detections)

        return detections

    def _detect_card_shapes(self, frame: np.ndarray, ocr_text: str = "") -> List[Dict]:
        """
        Detect card-shaped rectangular objects that might be ID cards, credit cards, etc.
        Uses contour detection and aspect ratio analysis.
        """
        detections = []

        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            edges = cv2.Canny(blurred, 50, 150)

            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

            frame_area = frame.shape[0] * frame.shape[1]
            min_card_area = frame_area * 0.01
            max_card_area = frame_area * 0.5

            CARD_RATIO_RANGE = (1.4, 1.8)

            for contour in contours:
                area = cv2.contourArea(contour)
                if area < min_card_area or area > max_card_area:
                    continue

                peri = cv2.arcLength(contour, True)
                approx = cv2.approxPolyDP(contour, 0.02 * peri, True)

                if len(approx) == 4:
                    x, y, w, h = cv2.boundingRect(approx)
                    aspect_ratio = max(w, h) / min(w, h) if min(w, h) > 0 else 0

                    if CARD_RATIO_RANGE[0] <= aspect_ratio <= CARD_RATIO_RANGE[1]:
                        category = self._classify_document(ocr_text)
                        if category:
                            detections.append({
                                'class_name': category,
                                'confidence': 0.6,
                                'bbox': (x, y, w, h),
                                'is_sensitive': True,
                                'category': category
                            })
        except Exception as e:
            pass

        return detections

    def _classify_document(self, ocr_text: str) -> str:
        """
        Classify a detected document based on OCR text content.
        Enhanced with additional document types: Driver License, ID Card.
        """
        text_lower = ocr_text.lower()

        if any(kw in text_lower for kw in ['aadhaar', 'aadhar', 'uidai', 'unique identification']):
            return 'aadhaar_card_object'
        elif any(kw in text_lower for kw in ['permanent account number', 'income tax', 'pan']):
            return 'pan_card_object'
        elif any(kw in text_lower for kw in ['driver', 'licence', 'license', 'driving',
                                               'dl no', 'motor vehicle']):
            return 'driver_license_object'
        elif any(kw in text_lower for kw in ['passport', 'republic of india', 'nationality',
                                               'travel document']):
            return 'passport_object'
        elif any(kw in text_lower for kw in ['voter', 'election', 'identity card',
                                               'id card', 'identity proof']):
            return 'id_card_object'
        elif any(kw in text_lower for kw in ['visa', 'mastercard', 'credit card', 'debit card',
                                               'valid thru', 'cvv']):
            return 'credit_card_object'

        return ''
