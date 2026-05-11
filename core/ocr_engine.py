"""
ViziDLP OCR Engine — Enhanced with PaddleOCR
Extracts text from image frames using PaddleOCR (primary) or Tesseract (fallback).
PaddleOCR provides better accuracy for ID documents like Aadhaar, PAN, etc.
"""

import os
from typing import Dict, List, Optional, Tuple

import cv2
import numpy as np

# ─── PaddleOCR Import ─────────────────────────────────────────
PADDLE_AVAILABLE = False
try:
    from paddleocr import PaddleOCR as _PaddleOCR
    PADDLE_AVAILABLE = True
except ImportError:
    pass

# ─── Tesseract Import ─────────────────────────────────────────
TESSERACT_AVAILABLE = False
try:
    import pytesseract
    from utils.config import TESSERACT_CMD
    if os.path.exists(TESSERACT_CMD):
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD
    TESSERACT_AVAILABLE = True
except ImportError:
    pass

from utils.config import OCR_ENGINE


class OCREngine:
    """Extracts text from images using PaddleOCR (primary) or Tesseract (fallback)."""

    def __init__(self):
        self.available = False
        self.engine = None  # 'paddle' or 'tesseract'
        self.paddle_ocr = None

        # Try PaddleOCR first (preferred)
        if OCR_ENGINE == "paddleocr" and PADDLE_AVAILABLE:
            try:
                self.paddle_ocr = _PaddleOCR(
                    use_angle_cls=True,
                    lang='en',
                    show_log=False,
                    use_gpu=False
                )
                self.engine = 'paddle'
                self.available = True
                print("[OCR] PaddleOCR initialized successfully (primary engine).")
            except Exception as e:
                print(f"[OCR] PaddleOCR init failed: {e}. Falling back to Tesseract.")

        # Fallback to Tesseract
        if not self.available and TESSERACT_AVAILABLE:
            try:
                pytesseract.get_tesseract_version()
                self.engine = 'tesseract'
                self.available = True
                print("[OCR] Tesseract OCR initialized (fallback engine).")
            except Exception as e:
                print(f"[OCR] Tesseract not available: {e}")

        if not self.available:
            print("[OCR] WARNING: No OCR engine available. OCR detection disabled.")
            print("[OCR] Install PaddleOCR: pip install paddleocr paddlepaddle")
            print("[OCR] Or Tesseract: pip install pytesseract")

    def preprocess_frame(self, frame: np.ndarray) -> np.ndarray:
        """
        Preprocess frame for better OCR accuracy on ID cards and documents.
        Uses adaptive thresholding instead of Otsu to handle colored card backgrounds.
        """
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            # Upscale small images — OCR needs at least ~30px per character height
            h, w = gray.shape[:2]
            if h < 600 or w < 800:
                scale = max(600 / h, 800 / w, 1.0)
                gray = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)

            # Denoise before thresholding
            gray = cv2.fastNlMeansDenoising(gray, h=10)

            # Adaptive threshold — handles colored/uneven backgrounds (yellow Aadhaar, beige PAN)
            binary = cv2.adaptiveThreshold(
                gray, 255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY,
                blockSize=31,   # Large block handles card background gradients
                C=10
            )
            return binary
        except Exception:
            # Fallback: return grayscale if preprocessing fails
            try:
                return cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            except Exception:
                return frame

    def preprocess_for_ocr(self, image: np.ndarray) -> np.ndarray:
        """
        Enhanced preprocessing to improve OCR accuracy.
        1. Upscale to 2x if either dimension < 800px
        2. Convert to grayscale
        3. Apply adaptive threshold
        4. Apply mild sharpening kernel
        """
        try:
            h, w = image.shape[:2]
            # Step 1: Upscale small images
            if h < 800 or w < 800:
                image = cv2.resize(image, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
            # Step 2: Convert to grayscale
            if len(image.shape) == 3:
                gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            else:
                gray = image
            # Step 3: Adaptive threshold
            binary = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY, blockSize=11, C=2
            )
            # Step 4: Mild sharpening
            sharpen_kernel = np.array([[0, -1, 0],
                                       [-1, 5, -1],
                                       [0, -1, 0]])
            sharpened = cv2.filter2D(binary, -1, sharpen_kernel)
            # Convert back to BGR for PaddleOCR compatibility
            return cv2.cvtColor(sharpened, cv2.COLOR_GRAY2BGR)
        except Exception as e:
            print(f"[OCR] Preprocessing failed, using original: {e}")
            return image

    def extract_text(self, frame: np.ndarray) -> str:
        """
        Extract all text from a frame.

        Args:
            frame: OpenCV BGR image

        Returns:
            Extracted text string
        """
        if not self.available:
            return ""

        try:
            if self.engine == 'paddle':
                return self._paddle_extract_text(frame)
            else:
                return self._tesseract_extract_text(frame)
        except Exception as e:
            print(f"[OCR] Error during text extraction: {e}")
            return ""

    def extract_text_regions(self, frame: np.ndarray) -> List[Dict]:
        """
        Extract text organized by line/region with bounding boxes.

        Returns:
            List of dicts with keys: text, x, y, w, h, confidence
        """
        if not self.available:
            return []

        try:
            if self.engine == 'paddle':
                return self._paddle_extract_regions(frame)
            else:
                return self._tesseract_extract_regions(frame)
        except Exception as e:
            print(f"[OCR] Error during region extraction: {e}")
            return []

    def extract_text_with_boxes(self, frame: np.ndarray) -> List[Dict]:
        """
        Extract text with bounding box information (word-level).

        Returns:
            List of dicts with keys: text, x, y, w, h, confidence
        """
        # This delegates to extract_text_regions for both engines
        return self.extract_text_regions(frame)

    # ─── PaddleOCR Methods ────────────────────────────────────────

    def _paddle_extract_text(self, frame: np.ndarray) -> str:
        """Extract text using PaddleOCR."""
        processed = self.preprocess_for_ocr(frame)
        result = self.paddle_ocr.ocr(processed, cls=True)
        if not result or not result[0]:
            return ""
        texts = []
        for line in result[0]:
            if line and len(line) >= 2:
                text_info = line[1]
                if isinstance(text_info, tuple) and len(text_info) >= 1:
                    texts.append(str(text_info[0]))
        return " ".join(texts).strip()

    def _paddle_extract_regions(self, frame: np.ndarray) -> List[Dict]:
        """Extract text regions with bounding boxes using PaddleOCR."""
        processed = self.preprocess_for_ocr(frame)
        result = self.paddle_ocr.ocr(processed, cls=True)
        if not result or not result[0]:
            return []

        regions = []
        for line in result[0]:
            if not line or len(line) < 2:
                continue

            # PaddleOCR returns: [[x1,y1],[x2,y2],[x3,y3],[x4,y4]], (text, confidence)
            box = line[0]
            text_info = line[1]

            if not isinstance(text_info, tuple) or len(text_info) < 2:
                continue

            text = str(text_info[0])
            confidence = float(text_info[1]) * 100  # Convert to 0-100 scale

            if confidence < 15 or not text.strip():   # Lowered from 30 → 15 for ID cards
                continue

            # Convert polygon to bounding rect
            xs = [pt[0] for pt in box]
            ys = [pt[1] for pt in box]
            x = int(min(xs))
            y = int(min(ys))
            w = int(max(xs) - min(xs))
            h = int(max(ys) - min(ys))

            regions.append({
                'text': text,
                'x': x,
                'y': y,
                'w': w,
                'h': h,
                'confidence': confidence
            })

        return regions

    # ─── Tesseract Methods ────────────────────────────────────────

    def _tesseract_extract_text(self, frame: np.ndarray) -> str:
        """Extract text using Tesseract."""
        processed = self.preprocess_frame(frame)
        text = pytesseract.image_to_string(processed, config='--psm 6')
        return text.strip()

    def _tesseract_extract_regions(self, frame: np.ndarray) -> List[Dict]:
        """Extract text regions using Tesseract, grouped by line."""
        processed = self.preprocess_frame(frame)
        data = pytesseract.image_to_data(processed, output_type=pytesseract.Output.DICT)

        # Group by block and line
        lines = {}
        n_boxes = len(data['level'])

        for i in range(n_boxes):
            conf = int(data['conf'][i])
            text = data['text'][i].strip()

            if conf > 30 and text:
                block_num = data['block_num'][i]
                line_num = data['line_num'][i]
                key = (block_num, line_num)

                if key not in lines:
                    lines[key] = {
                        'text': '',
                        'x': data['left'][i],
                        'y': data['top'][i],
                        'w': 0,
                        'h': data['height'][i],
                        'confidence': 0,
                        'word_count': 0
                    }

                line = lines[key]
                line['text'] += (' ' + text) if line['text'] else text
                right = max(line['x'] + line['w'], data['left'][i] + data['width'][i])
                line['x'] = min(line['x'], data['left'][i])
                line['w'] = right - line['x']
                line['h'] = max(line['h'], data['height'][i])
                line['confidence'] += conf
                line['word_count'] += 1

        # Average confidence per line
        results = []
        for line in lines.values():
            if line['word_count'] > 0:
                line['confidence'] = line['confidence'] / line['word_count']
                del line['word_count']
                results.append(line)

        return results
