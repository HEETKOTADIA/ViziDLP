"""
ViziDLP Redaction Engine
Automatically blurs/masks detected sensitive areas using OpenCV Gaussian blur.
"""

from typing import List, Tuple

import cv2
import numpy as np

from utils.config import REDACTION_BLUR_KERNEL, REDACTION_BLUR_SIGMA


class RedactionEngine:
    """Handles automatic redaction (blurring) of sensitive regions in images."""

    def __init__(self):
        self.blur_kernel = REDACTION_BLUR_KERNEL
        self.blur_sigma = REDACTION_BLUR_SIGMA
        print("[REDACTION] Redaction engine initialized.")

    def redact_region(self, frame: np.ndarray, bbox: Tuple[int, int, int, int]) -> np.ndarray:
        """
        Apply Gaussian blur to a specific region of the frame.
        
        Args:
            frame: OpenCV BGR image (will be modified in-place)
            bbox: Bounding box as (x, y, width, height)
            
        Returns:
            Modified frame with the region blurred
        """
        x, y, w, h = bbox
        
        # Ensure coordinates are within frame bounds
        frame_h, frame_w = frame.shape[:2]
        x = max(0, x)
        y = max(0, y)
        w = min(w, frame_w - x)
        h = min(h, frame_h - y)
        
        if w <= 0 or h <= 0:
            return frame

        # Extract the region of interest
        roi = frame[y:y+h, x:x+w]

        # Apply heavy Gaussian blur
        blurred_roi = cv2.GaussianBlur(roi, self.blur_kernel, self.blur_sigma)

        # Replace the region with the blurred version
        frame[y:y+h, x:x+w] = blurred_roi

        return frame

    def redact_regions(self, frame: np.ndarray, bboxes: List[Tuple[int, int, int, int]]) -> np.ndarray:
        """
        Apply Gaussian blur to multiple regions.
        
        Args:
            frame: OpenCV BGR image
            bboxes: List of (x, y, w, h) bounding boxes
            
        Returns:
            Frame with all regions blurred
        """
        result = frame.copy()
        for bbox in bboxes:
            result = self.redact_region(result, bbox)
        return result

    def redact_text_region(self, frame: np.ndarray, bbox: Tuple[int, int, int, int],
                           padding: int = 10) -> np.ndarray:
        """
        Redact a text region with extra padding around the bounding box.
        
        Args:
            frame: OpenCV BGR image
            bbox: Bounding box as (x, y, w, h)
            padding: Extra pixels around the box to ensure full coverage
            
        Returns:
            Frame with the padded region blurred
        """
        x, y, w, h = bbox
        padded_bbox = (x - padding, y - padding, w + 2 * padding, h + 2 * padding)
        return self.redact_region(frame, padded_bbox)

    def redact_full_frame(self, frame: np.ndarray) -> np.ndarray:
        """Apply full-frame blur (for extreme sensitivity cases)."""
        return cv2.GaussianBlur(frame, self.blur_kernel, self.blur_sigma)

    def add_redaction_overlay(self, frame: np.ndarray, bbox: Tuple[int, int, int, int],
                              label: str = "REDACTED") -> np.ndarray:
        """
        Add a solid color rectangle with 'REDACTED' text over a region.
        Alternative to blur-based redaction.
        
        Args:
            frame: OpenCV BGR image
            bbox: Bounding box as (x, y, w, h)
            label: Text to display on the overlay
            
        Returns:
            Frame with redaction overlay
        """
        x, y, w, h = bbox
        result = frame.copy()

        # Draw filled rectangle
        cv2.rectangle(result, (x, y), (x + w, y + h), (0, 0, 0), -1)

        # Add "REDACTED" text
        font = cv2.FONT_HERSHEY_SIMPLEX
        font_scale = min(w, h) / 100.0
        font_scale = max(0.4, min(font_scale, 2.0))
        thickness = max(1, int(font_scale * 2))

        text_size = cv2.getTextSize(label, font, font_scale, thickness)[0]
        text_x = x + (w - text_size[0]) // 2
        text_y = y + (h + text_size[1]) // 2

        cv2.putText(result, label, (text_x, text_y), font, font_scale,
                    (0, 0, 255), thickness, cv2.LINE_AA)

        return result
