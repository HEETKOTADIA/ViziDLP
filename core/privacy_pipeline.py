"""
ViziDLP — Centralized Privacy Pipeline (Enhanced)
Every captured image passes through this module BEFORE being stored.

Pipeline stages:
  1. Orientation correction (for rotated text)
  2. OCR text extraction with bounding boxes
  3. Regex sensitive pattern detection (PAN, Aadhaar, CC, Phone, Email, DOB, DL)
  4. Keyword-based detection (ADDRESS, NAME, S/O, D/O, FATHER, DOB labels)
  5. QR code detection and blurring
  6. Face detection and blurring (for webcam, documents, phone captures)
  7. Region-based blur of ONLY sensitive text areas
  8. Return sanitized image + detection metadata

RAW IMAGES ARE NEVER STORED. Only the output of this pipeline is saved.
"""

import cv2
import numpy as np
from typing import Dict, List, Optional, Tuple


class PrivacyPipeline:
    """
    Centralized privacy sanitizer. All evidence frames must pass through here
    before being saved to disk.

    Rules:
    - Sensitive text regions (PAN, Aadhaar, CC, etc.) → blur ONLY those regions
    - Keyword regions (ADDRESS, NAME, etc.) → blur nearby text
    - QR codes → always blur
    - Faces → blur when documents detected, phone detected, or webcam source
    - Device detections (laptop, monitor, keyboard) → do NOT blur
    - Screenshots with NO sensitive data → save unblurred for investigation
    """

    # Device classes that should NOT trigger blurring
    NON_SENSITIVE_OBJECTS = {
        'laptop', 'monitor', 'keyboard', 'mouse', 'tv',
        'cell phone',
        'remote', 'microwave', 'oven', 'toaster',
    }

    # Document types that trigger face blurring
    DOCUMENT_TYPES = {
        'aadhaar_card_object', 'pan_card_object', 'driver_license_object',
        'passport_object', 'id_card_object', 'credit_card_object',
    }

    # OCR context that identifies government ID documents. When these appear,
    # redact all OCR text on the document because names, DOBs and ID numbers
    # are often split into separate OCR regions that regex matching can miss.
    ID_DOCUMENT_CONTEXT_TYPES = {
        'aadhaar_number', 'aadhaar_number_spaced', 'aadhaar_keyword',
        'pan_number', 'pan_keyword',
        'driver_licence_number', 'driver_license_keyword',
    }

    def __init__(self, ocr_engine, pattern_detector, redaction_engine, phone_detector=None):
        """
        Args:
            ocr_engine: OCREngine instance for text extraction
            pattern_detector: PatternDetector for regex + keyword matching
            redaction_engine: RedactionEngine for blurring regions
            phone_detector: PhoneDetector (has face_cascade for face blur)
        """
        self.ocr = ocr_engine
        self.patterns = pattern_detector
        self.redaction = redaction_engine
        self.phone_detector = phone_detector

        # Load face cascade for face blurring
        self.face_cascade = None
        if phone_detector and phone_detector.face_cascade is not None:
            self.face_cascade = phone_detector.face_cascade
        else:
            self._load_face_cascade()

        # QR code detector
        self.qr_detector = cv2.QRCodeDetector()

        print("[PRIVACY] Privacy pipeline initialized (with QR detection, keyword blur, face blur).")

    def _load_face_cascade(self):
        """Load OpenCV Haar Cascade for face detection."""
        try:
            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            self.face_cascade = cv2.CascadeClassifier(cascade_path)
            if self.face_cascade.empty():
                self.face_cascade = None
                print("[PRIVACY] WARNING: Could not load face cascade.")
            else:
                print("[PRIVACY] Face cascade loaded for privacy blur.")
        except Exception as e:
            print(f"[PRIVACY] WARNING: Face cascade error: {e}")
            self.face_cascade = None

    # ─── Main Pipeline Methods ───────────────────────────────────

    def sanitize_screenshot(self, frame: np.ndarray) -> dict:
        """
        Process a screen capture or screenshot through the full privacy pipeline.

        Steps:
            1. Correct orientation
            2. Run OCR → extract text + bounding boxes
            3. Regex match → find sensitive patterns
            4. Keyword match → find ADDRESS/NAME/DOB/FATHER labels
            5. Detect and blur QR codes
            6. Blur ONLY sensitive regions (leave rest intact)
            7. If documents detected → blur faces too

        Args:
            frame: Raw BGR screenshot frame

        Returns:
            dict with keys:
                'sanitized_frame': Privacy-safe frame (only sensitive regions blurred)
                'detections': List of sensitive pattern detections
                'keyword_detections': List of keyword detections
                'has_sensitive_data': bool
                'ocr_text': Full extracted text
                'qr_detected': bool
                'faces_blurred': int
        """
        if frame is None:
            return {
                'sanitized_frame': None,
                'detections': [],
                'keyword_detections': [],
                'has_sensitive_data': False,
                'ocr_text': '',
                'qr_detected': False,
                'faces_blurred': 0
            }

        # Step 1: Orientation correction
        corrected = self._correct_orientation(frame)

        # Step 2: OCR extraction with bounding boxes
        ocr_regions = self.ocr.extract_text_regions(corrected)
        full_text = " ".join(r['text'] for r in ocr_regions)
        print(f"[PRIVACY] OCR extracted {len(ocr_regions)} text regions")
        if full_text.strip():
            preview = full_text[:200].replace('\n', ' ')
            print(f"[PRIVACY] OCR text preview: '{preview}'")

        # Debug: Show OCR extraction details for verification
        print(f"[DEBUG] Full OCR text: '{full_text[:300]}'")
        print(f"[DEBUG] OCR regions count: {len(ocr_regions)}")
        for r in ocr_regions[:5]:
            print(f"[DEBUG] Region: text='{r['text']}' conf={r['confidence']:.1f} bbox=({r['x']},{r['y']},{r['w']},{r['h']})")

        # Step 3: Regex pattern detection per bounding box
        detections = self.patterns.detect_in_regions(ocr_regions)

        # Step 4: Keyword detection (ADDRESS, NAME, S/O, DOB, etc.)
        keyword_detections = self.patterns.detect_keywords_in_regions(ocr_regions)

        # Step 5: Collect all sensitive bboxes to blur
        sensitive_bboxes = []
        for det in detections:
            bbox = det.get('bbox', (0, 0, 0, 0))
            if bbox[2] > 0 and bbox[3] > 0:
                sensitive_bboxes.append(bbox)

        # Add keyword-region bboxes (blur the region containing the keyword)
        for kw_det in keyword_detections:
            bbox = kw_det.get('bbox', (0, 0, 0, 0))
            if bbox[2] > 0 and bbox[3] > 0:
                sensitive_bboxes.append(bbox)

        document_bboxes = self._identity_document_redaction_bboxes(
            corrected, ocr_regions, detections, keyword_detections
        )
        if document_bboxes:
            print(f"[PRIVACY] ID document context found; blurring {len(document_bboxes)} document text region(s)")
            sensitive_bboxes.extend(document_bboxes)

        visual_document_bboxes = self._visual_identity_document_bboxes(corrected)
        visual_detections = []
        if visual_document_bboxes:
            print(f"[PRIVACY] Visual ID document fallback found {len(visual_document_bboxes)} card/document region(s)")
            sensitive_bboxes.extend(visual_document_bboxes)
            visual_detections = [
                {
                    'type': 'visual_identity_document',
                    'severity': 'HIGH',
                    'description': 'Visual identity document/card region detected and redacted',
                    'bbox': bbox,
                    'confidence': 50.0,
                }
                for bbox in visual_document_bboxes
            ]

        # Step 6: Blur sensitive text regions
        # Also handle CRITICAL detections with no locatable bbox (full-text-pass matches)
        critical_no_bbox = [
            d for d in detections
            if d.get('severity') == 'CRITICAL' and
               (d.get('bbox', (0,0,0,0))[2] == 0 or d.get('bbox', (0,0,0,0))[3] == 0)
        ]

        if sensitive_bboxes:
            print(f"[PRIVACY] Blurring {len(sensitive_bboxes)} sensitive region(s)")
            sanitized = self.redaction.redact_regions(corrected.copy(), sensitive_bboxes)
        else:
            sanitized = corrected.copy()

        for bbox in visual_document_bboxes:
            sanitized = self.redaction.add_redaction_overlay(sanitized, bbox)

        # Fallback: for CRITICAL detections with no located bbox, blur bottom 60% of frame
        # (ID card numbers appear in the lower portion of documents)
        if critical_no_bbox and not sensitive_bboxes:
            h, w = sanitized.shape[:2]
            fallback_bbox = (0, int(h * 0.35), w, int(h * 0.65))
            print(f"[PRIVACY] CRITICAL detection with no bbox — applying fallback region blur")
            sanitized = self.redaction.redact_region(sanitized, fallback_bbox)

        # Step 7: Detect and blur QR codes
        qr_detected = self._detect_and_blur_qr_codes(sanitized)

        # Step 8: If documents were detected or sensitive data found, blur faces
        faces_blurred = 0
        has_document = any(
            det.get('type', '').endswith('_object') or
            det.get('category', '') in self.DOCUMENT_TYPES
            for det in detections
        )
        if has_document or len(detections) >= 2:
            faces_blurred = self._blur_all_faces(sanitized)

        return {
            'sanitized_frame': sanitized,
            'detections': detections + keyword_detections + visual_detections,
            'keyword_detections': keyword_detections,
            'has_sensitive_data': (
                len(detections) > 0 or
                len(keyword_detections) > 0 or
                len(visual_detections) > 0
            ),
            'ocr_text': full_text,
            'qr_detected': qr_detected,
            'faces_blurred': faces_blurred
        }

    def sanitize_webcam(self, frame: np.ndarray) -> dict:
        """
        Process a webcam frame through the privacy pipeline.

        Steps:
            1. Detect and blur ALL faces (mandatory for webcam)
            2. Run OCR + pattern detection
            3. Detect keywords
            4. Blur sensitive text regions
            5. Blur QR codes

        Args:
            frame: Raw BGR webcam frame

        Returns:
            dict with keys:
                'sanitized_frame': Privacy-safe frame
                'detections': List of pattern + keyword detections
                'has_sensitive_data': bool
                'faces_blurred': int
                'qr_detected': bool
        """
        if frame is None:
            return {
                'sanitized_frame': None,
                'detections': [],
                'has_sensitive_data': False,
                'faces_blurred': 0,
                'qr_detected': False
            }

        result = frame.copy()

        # Step 1: MANDATORY face anonymization
        faces_blurred = self._blur_all_faces(result)

        # Step 2: OCR + pattern detection
        ocr_regions = self.ocr.extract_text_regions(result)
        detections = self.patterns.detect_in_regions(ocr_regions)

        # Step 3: Keyword detection
        keyword_detections = self.patterns.detect_keywords_in_regions(ocr_regions)

        # Step 4: Blur sensitive text regions
        sensitive_bboxes = []
        for det in detections:
            bbox = det.get('bbox', (0, 0, 0, 0))
            if bbox[2] > 0 and bbox[3] > 0:
                sensitive_bboxes.append(bbox)

        for kw_det in keyword_detections:
            bbox = kw_det.get('bbox', (0, 0, 0, 0))
            if bbox[2] > 0 and bbox[3] > 0:
                sensitive_bboxes.append(bbox)

        document_bboxes = self._identity_document_redaction_bboxes(
            result, ocr_regions, detections, keyword_detections
        )
        if document_bboxes:
            print(f"[PRIVACY] ID document context found; blurring {len(document_bboxes)} document text region(s) (webcam)")
            sensitive_bboxes.extend(document_bboxes)

        visual_document_bboxes = self._visual_identity_document_bboxes(result)
        visual_detections = []
        if visual_document_bboxes:
            print(f"[PRIVACY] Visual ID document fallback found {len(visual_document_bboxes)} card/document region(s) (webcam)")
            sensitive_bboxes.extend(visual_document_bboxes)
            visual_detections = [
                {
                    'type': 'visual_identity_document',
                    'severity': 'HIGH',
                    'description': 'Visual identity document/card region detected and redacted',
                    'bbox': bbox,
                    'confidence': 50.0,
                }
                for bbox in visual_document_bboxes
            ]

        if sensitive_bboxes:
            result = self.redaction.redact_regions(result, sensitive_bboxes)

        for bbox in visual_document_bboxes:
            result = self.redaction.add_redaction_overlay(result, bbox)

        # Fallback: for CRITICAL detections with no located bbox, blur bottom 60% of frame
        critical_no_bbox = [
            d for d in detections
            if d.get('severity') == 'CRITICAL' and
               (d.get('bbox', (0,0,0,0))[2] == 0 or d.get('bbox', (0,0,0,0))[3] == 0)
        ]
        if critical_no_bbox and not sensitive_bboxes:
            h, w = result.shape[:2]
            fallback_bbox = (0, int(h * 0.35), w, int(h * 0.65))
            print(f"[PRIVACY] CRITICAL detection with no bbox — applying fallback region blur (webcam)")
            result = self.redaction.redact_region(result, fallback_bbox)

        # Step 5: QR code blur
        qr_detected = self._detect_and_blur_qr_codes(result)

        return {
            'sanitized_frame': result,
            'detections': detections + keyword_detections + visual_detections,
            'has_sensitive_data': (
                len(detections) > 0 or
                len(keyword_detections) > 0 or
                len(visual_detections) > 0
            ),
            'faces_blurred': faces_blurred,
            'qr_detected': qr_detected
        }

    # ─── QR Code Detection & Blurring ────────────────────────────

    def _detect_and_blur_qr_codes(self, frame: np.ndarray) -> bool:
        """
        Detect and blur QR codes in the frame IN-PLACE.

        Args:
            frame: BGR image (modified in-place)

        Returns:
            True if any QR codes were detected and blurred
        """
        try:
            retval, decoded_info, points, straight_qrcode = self.qr_detector.detectAndDecodeMulti(frame)

            if retval and points is not None:
                for i, pts in enumerate(points):
                    pts = pts.astype(int)
                    x_min = max(0, int(pts[:, 0].min()))
                    y_min = max(0, int(pts[:, 1].min()))
                    x_max = min(frame.shape[1], int(pts[:, 0].max()))
                    y_max = min(frame.shape[0], int(pts[:, 1].max()))

                    if x_max > x_min and y_max > y_min:
                        # Add padding
                        pad = 10
                        x_min = max(0, x_min - pad)
                        y_min = max(0, y_min - pad)
                        x_max = min(frame.shape[1], x_max + pad)
                        y_max = min(frame.shape[0], y_max + pad)

                        roi = frame[y_min:y_max, x_min:x_max]
                        blurred = cv2.GaussianBlur(roi, (99, 99), 30)
                        frame[y_min:y_max, x_min:x_max] = blurred
                        print(f"[PRIVACY] QR code blurred at ({x_min},{y_min})-({x_max},{y_max})")

                return True
        except Exception as e:
            # detectAndDecodeMulti may not be available in older OpenCV
            try:
                data, points, _ = self.qr_detector.detectAndDecode(frame)
                if points is not None and data:
                    pts = points[0].astype(int)
                    x_min = max(0, int(pts[:, 0].min()) - 10)
                    y_min = max(0, int(pts[:, 1].min()) - 10)
                    x_max = min(frame.shape[1], int(pts[:, 0].max()) + 10)
                    y_max = min(frame.shape[0], int(pts[:, 1].max()) + 10)

                    if x_max > x_min and y_max > y_min:
                        roi = frame[y_min:y_max, x_min:x_max]
                        blurred = cv2.GaussianBlur(roi, (99, 99), 30)
                        frame[y_min:y_max, x_min:x_max] = blurred
                        print(f"[PRIVACY] QR code blurred at ({x_min},{y_min})-({x_max},{y_max})")
                        return True
            except Exception:
                pass

        return False

    # ─── Face Blurring ───────────────────────────────────────────

    def _blur_all_faces(self, frame: np.ndarray) -> int:
        """
        Detect and blur ALL faces in a frame IN-PLACE.
        Uses strong Gaussian blur: cv2.GaussianBlur(face, (99, 99), 30)

        Args:
            frame: BGR image (modified in-place)

        Returns:
            Number of faces blurred
        """
        if self.face_cascade is None:
            return 0

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(
            gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
        )

        for (x, y, w, h) in faces:
            # Add 20% padding around face
            pad = int(max(w, h) * 0.2)
            x1 = max(0, x - pad)
            y1 = max(0, y - pad)
            x2 = min(frame.shape[1], x + w + pad)
            y2 = min(frame.shape[0], y + h + pad)

            # Heavy Gaussian blur
            face_roi = frame[y1:y2, x1:x2]
            blurred = cv2.GaussianBlur(face_roi, (99, 99), 30)
            frame[y1:y2, x1:x2] = blurred

        return len(faces)

    # ─── ID Document Context Redaction ─────────────────────────────

    def _identity_document_redaction_bboxes(
        self,
        frame: np.ndarray,
        ocr_regions: List[Dict],
        detections: List[Dict],
        keyword_detections: List[Dict],
    ) -> List[Tuple[int, int, int, int]]:
        """
        Return redaction boxes for Aadhaar, PAN and driving-licence screenshots.

        Regex matches catch clean ID numbers, but screenshots of physical cards
        often OCR as separate labels and values. Once ID-card context is present,
        blur every text region inside the OCR-derived document area and add a
        conservative union fallback so separated names/numbers are covered too.
        """
        if frame is None or not ocr_regions:
            return []

        all_detection_types = {
            det.get('type', '')
            for det in (detections or []) + (keyword_detections or [])
        }
        full_text = " ".join(region.get('text', '') for region in ocr_regions)
        compact_text = "".join(full_text.upper().split())
        context_phrases = (
            'AADHAAR', 'AADHAR', 'UIDAI', 'UNIQUEIDENTIFICATION',
            'PERMANENTACCOUNTNUMBER', 'INCOMETAXDEPARTMENT',
            'DRIVINGLICENCE', 'DRIVINGLICENSE', 'DRIVERLICENCE', 'DRIVERLICENSE',
            'DLNO', 'DLNUMBER', 'LICENCENO', 'LICENSENO',
            'TRANSPORTDEPARTMENT', 'MOTORVEHICLE',
        )
        has_document_context = (
            bool(all_detection_types & self.ID_DOCUMENT_CONTEXT_TYPES) or
            any(phrase in compact_text for phrase in context_phrases)
        )
        if not has_document_context:
            return []

        frame_h, frame_w = frame.shape[:2]
        valid_regions = []
        for region in ocr_regions:
            text = region.get('text', '').strip()
            bbox = (
                int(region.get('x', 0)),
                int(region.get('y', 0)),
                int(region.get('w', 0)),
                int(region.get('h', 0)),
            )
            if not text or bbox[2] <= 0 or bbox[3] <= 0:
                continue
            if bbox[0] >= frame_w or bbox[1] >= frame_h:
                continue
            valid_regions.append((text, bbox))

        if not valid_regions:
            return []

        boxes = [self._pad_bbox(bbox, frame_w, frame_h, padding=12) for _, bbox in valid_regions]

        x1 = min(bbox[0] for _, bbox in valid_regions)
        y1 = min(bbox[1] for _, bbox in valid_regions)
        x2 = max(bbox[0] + bbox[2] for _, bbox in valid_regions)
        y2 = max(bbox[1] + bbox[3] for _, bbox in valid_regions)
        union_w = x2 - x1
        union_h = y2 - y1

        if union_w > 0 and union_h > 0:
            pad_x = max(20, int(union_w * 0.08))
            pad_y = max(20, int(union_h * 0.15))
            boxes.append(self._clip_bbox(
                x1 - pad_x,
                y1 - pad_y,
                union_w + (2 * pad_x),
                union_h + (2 * pad_y),
                frame_w,
                frame_h,
            ))

        return self._dedupe_bboxes(boxes)

    def _visual_identity_document_bboxes(self, frame: np.ndarray) -> List[Tuple[int, int, int, int]]:
        """
        Detect and redact visible card/document regions even when OCR fails.

        This is a defensive fallback for screenshots of Aadhaar/PAN/DL images
        shown inside viewers, PDFs, or the dashboard itself. It looks for
        bright, colored rectangular regions with enough internal edges to look
        like an ID card rather than a plain UI panel.
        """
        if frame is None:
            return []

        try:
            frame_h, frame_w = frame.shape[:2]
            frame_area = frame_h * frame_w
            if frame_area <= 0:
                return []

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)

            mask = np.zeros(gray.shape, dtype=np.uint8)
            mask[(gray > 65) & (hsv[:, :, 1] > 10)] = 255

            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (9, 9))
            mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel, iterations=2)
            mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel, iterations=1)

            contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            candidates = []

            for contour in contours:
                area = cv2.contourArea(contour)
                x, y, w, h = cv2.boundingRect(contour)
                bbox_area = w * h
                if bbox_area <= 0:
                    continue

                area_fraction = bbox_area / frame_area
                if area_fraction < 0.008 or area_fraction > 0.45:
                    continue
                if y + h > int(frame_h * 0.995):
                    continue

                aspect = max(w, h) / max(1, min(w, h))
                extent = area / bbox_area
                if aspect < 1.05 or aspect > 2.60 or extent < 0.20:
                    continue

                roi_gray = gray[y:y + h, x:x + w]
                roi_hsv = hsv[y:y + h, x:x + w]
                mean_brightness = float(np.mean(roi_gray))
                mean_saturation = float(np.mean(roi_hsv[:, :, 1]))
                if mean_brightness < 70 or mean_saturation < 10:
                    continue

                edges = cv2.Canny(roi_gray, 50, 150)
                edge_density = float(np.count_nonzero(edges)) / bbox_area
                if edge_density < 0.01 or edge_density > 0.35:
                    continue

                score = (area_fraction * 100.0) + (edge_density * 10.0) + (extent * 0.5)
                candidates.append((score, (x, y, w, h)))

            if not candidates:
                return []

            candidates.sort(reverse=True, key=lambda item: item[0])
            boxes = []
            for _, bbox in candidates[:3]:
                x, y, w, h = bbox
                pad = max(12, int(max(w, h) * 0.06))
                boxes.append(self._pad_bbox((x, y, w, h), frame_w, frame_h, padding=pad))

            return self._dedupe_bboxes(boxes)
        except Exception as e:
            print(f"[PRIVACY] Visual ID fallback skipped: {e}")
            return []

    @staticmethod
    def _clip_bbox(
        x: int,
        y: int,
        w: int,
        h: int,
        frame_w: int,
        frame_h: int,
    ) -> Tuple[int, int, int, int]:
        """Clip a bbox to frame bounds."""
        x = max(0, int(x))
        y = max(0, int(y))
        w = min(int(w), frame_w - x)
        h = min(int(h), frame_h - y)
        return (x, y, max(0, w), max(0, h))

    def _pad_bbox(
        self,
        bbox: Tuple[int, int, int, int],
        frame_w: int,
        frame_h: int,
        padding: int = 10,
    ) -> Tuple[int, int, int, int]:
        """Pad and clip a bbox."""
        x, y, w, h = bbox
        return self._clip_bbox(
            x - padding,
            y - padding,
            w + (2 * padding),
            h + (2 * padding),
            frame_w,
            frame_h,
        )

    @staticmethod
    def _dedupe_bboxes(bboxes: List[Tuple[int, int, int, int]]) -> List[Tuple[int, int, int, int]]:
        """Remove duplicate and empty bboxes while preserving order."""
        unique = []
        seen = set()
        for bbox in bboxes:
            if bbox[2] <= 0 or bbox[3] <= 0 or bbox in seen:
                continue
            seen.add(bbox)
            unique.append(bbox)
        return unique

    # ─── Orientation Correction ──────────────────────────────────

    def _correct_orientation(self, frame: np.ndarray) -> np.ndarray:
        """
        Detect and correct image orientation for better OCR of rotated text.
        Uses Hough line detection to estimate dominant text angle.

        Args:
            frame: Input BGR image

        Returns:
            Orientation-corrected BGR image
        """
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            edges = cv2.Canny(gray, 50, 150, apertureSize=3)

            lines = cv2.HoughLinesP(
                edges, 1, np.pi / 180, threshold=100,
                minLineLength=100, maxLineGap=10
            )

            if lines is None or len(lines) < 5:
                return frame

            angles = []
            for line in lines:
                x1, y1, x2, y2 = line[0]
                if x2 - x1 == 0:
                    continue
                angle = np.degrees(np.arctan2(y2 - y1, x2 - x1))
                if -45 < angle < 45:
                    angles.append(angle)

            if not angles:
                return frame

            median_angle = np.median(angles)

            if abs(median_angle) < 1.0 or abs(median_angle) > 30:
                return frame

            (h, w) = frame.shape[:2]
            center = (w // 2, h // 2)
            M = cv2.getRotationMatrix2D(center, median_angle, 1.0)
            corrected = cv2.warpAffine(
                frame, M, (w, h),
                flags=cv2.INTER_CUBIC,
                borderMode=cv2.BORDER_REPLICATE
            )

            print(f"[PRIVACY] Orientation corrected by {median_angle:.1f} degrees")
            return corrected

        except Exception as e:
            return frame

    # ─── Utility: Device Detection Filter ────────────────────────

    def is_device_detection(self, detection_category: str) -> bool:
        """
        Check if a detection category is a non-sensitive device.
        Device detections (laptop, monitor, keyboard) should NOT trigger blur.
        """
        return detection_category.lower() in self.NON_SENSITIVE_OBJECTS
