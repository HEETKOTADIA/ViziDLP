"""
ViziDLP Pattern Detector — Enhanced Universal PII Detection Engine
Regex-based detection for sensitive data patterns in text.

Detects: PAN, Aadhaar, Credit Card, Phone, Email, DOB, Driver Licence,
         Names, Addresses, API Keys, Passwords, AWS Keys, Private Keys.

IMPORTANT: OCR text is normalized (spaces removed, uppercased) before
regex matching to handle OCR artifacts like 'A B C D E 1 2 3 4 F'.
"""

import re
from typing import Dict, List


class PatternDetector:
    """Detects sensitive data patterns in text using regex and keyword matching."""

    # Compiled regex patterns for each sensitive data type
    PATTERNS = {
        'aadhaar_number': {
            'regex': re.compile(r'[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}'),
            'description': 'Aadhaar Number (12-digit)',
            'severity': 'CRITICAL',
            'normalize': False,
        },
        'aadhaar_number_spaced': {
            # Handles OCR output like "2 3 4 5  6 7 8 9  0 1 2 3" (spaces between every digit)
            'regex': re.compile(r'[2-9][\s]?\d[\s]?\d[\s]?\d[\s]{1,3}\d[\s]?\d[\s]?\d[\s]?\d[\s]{1,3}\d[\s]?\d[\s]?\d[\s]?\d'),
            'description': 'Aadhaar Number (12-digit, spaced OCR)',
            'severity': 'CRITICAL',
            'normalize': False,
        },
        'pan_number': {
            'regex': re.compile(r'[A-Z]{5}\d{4}[A-Z]'),
            'description': 'PAN Number',
            'severity': 'HIGH',
            'normalize': True,
        },
        'credit_card_number': {
            'regex': re.compile(
                r'(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}'
            ),
            'description': 'Credit/Debit Card Number',
            'severity': 'HIGH',
            'normalize': False,
        },
        'phone_number': {
            'regex': re.compile(r'(?:\+91[\s\-]?)?[6-9]\d{9}'),
            'description': 'Phone Number',
            'severity': 'MEDIUM',
            'normalize': False,
        },
        'email_address': {
            'regex': re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}'),
            'description': 'Email Address',
            'severity': 'MEDIUM',
            'normalize': False,
        },
        'dob': {
            'regex': re.compile(r'\d{2}[-/]\d{2}[-/]\d{4}'),
            'description': 'Date of Birth',
            'severity': 'MEDIUM',
            'normalize': False,
        },
        'driver_licence_number': {
            'regex': re.compile(r'[A-Z]{2}\d{2}\s?\d{4}\s?\d{7}'),
            'description': 'Driver Licence Number',
            'severity': 'HIGH',
            'normalize': True,
        },
        'api_key': {
            'regex': re.compile(
                r'(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token|auth[_\-]?token)'
                r'[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
                re.IGNORECASE
            ),
            'description': 'API Key / Secret',
            'severity': 'HIGH',
            'normalize': False,
        },
        'password': {
            'regex': re.compile(
                r'(?:password|passwd|pwd|pass)[\s]*[=:]\s*["\']?(\S{4,})["\']?',
                re.IGNORECASE
            ),
            'description': 'Password / Secret',
            'severity': 'HIGH',
            'normalize': False,
        },
        'aws_key': {
            'regex': re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}'),
            'description': 'AWS Access Key',
            'severity': 'CRITICAL',
            'normalize': True,
        },
        'private_key': {
            'regex': re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
            'description': 'Private Key',
            'severity': 'CRITICAL',
            'normalize': False,
        },
        'passport_number': {
            'regex': re.compile(r'[A-Z][1-9][0-9]{7}'),
            'description': 'Indian Passport Number',
            'severity': 'CRITICAL',
            'normalize': True,
        },
        'voter_id': {
            'regex': re.compile(r'[A-Z]{3}[0-9]{7}'),
            'description': 'Voter ID Number',
            'severity': 'HIGH',
            'normalize': True,
        },
        'ifsc_code': {
            'regex': re.compile(r'[A-Z]{4}0[A-Z0-9]{6}'),
            'description': 'IFSC Code (Bank)',
            'severity': 'MEDIUM',
            'normalize': True,
        },
        'bank_account': {
            'regex': re.compile(r'\b[0-9]{9,18}\b'),
            'description': 'Bank Account Number',
            'severity': 'HIGH',
            'normalize': False,
        },
        'upi_id': {
            'regex': re.compile(r'[a-zA-Z0-9._\-]+@[a-zA-Z]{3,}'),
            'description': 'UPI ID',
            'severity': 'MEDIUM',
            'normalize': False,
        },
        'gstin': {
            'regex': re.compile(r'[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}'),
            'description': 'GSTIN Number',
            'severity': 'HIGH',
            'normalize': True,
        },
    }

    # Keyword patterns for detecting sensitive fields by label proximity
    KEYWORD_PATTERNS = {
        'name_keyword': {
            'keywords': ['NAME', 'FATHER', "FATHER'S NAME", 'HUSBAND', "HUSBAND'S NAME"],
            'description': 'Name Field Detected',
            'severity': 'MEDIUM',
        },
        'address_keyword': {
            'keywords': ['ADDRESS', 'ADDR', 'RESIDENCE', 'LOCALITY', 'DISTRICT',
                         'PINCODE', 'PIN CODE', 'STATE'],
            'description': 'Address Field Detected',
            'severity': 'MEDIUM',
        },
        'relation_keyword': {
            'keywords': ['S/O', 'D/O', 'W/O', 'C/O', 'SON OF', 'DAUGHTER OF', 'WIFE OF'],
            'description': 'Relation / Guardian Field Detected',
            'severity': 'MEDIUM',
        },
        'dob_keyword': {
            'keywords': ['DOB', 'DATE OF BIRTH', 'BIRTH DATE', 'BORN ON', 'YEAR OF BIRTH'],
            'description': 'Date of Birth Field Detected',
            'severity': 'MEDIUM',
        },
        'financial_keyword': {
            'keywords': ['ACCOUNT NO', 'ACCOUNT NUMBER', 'IFSC', 'BANK NAME', 'BRANCH', 'MICR'],
            'description': 'Financial Field Detected',
            'severity': 'HIGH',
        },
        'passport_keyword': {
            'keywords': ['PASSPORT NO', 'PASSPORT NUMBER', 'NATIONALITY', 'PLACE OF BIRTH', 'DATE OF ISSUE', 'DATE OF EXPIRY'],
            'description': 'Passport Field Detected',
            'severity': 'CRITICAL',
        },
        'aadhaar_keyword': {
            'keywords': ['AADHAAR', 'AADHAR', 'UNIQUE IDENTIFICATION', 'UIDAI', 'आधार'],
            'description': 'Aadhaar Card Keyword Detected',
            'severity': 'CRITICAL',
        },
        'pan_keyword': {
            'keywords': ['INCOME TAX DEPARTMENT', 'PERMANENT ACCOUNT NUMBER', 'GOVT. OF INDIA'],
            'description': 'PAN Card Keyword Detected',
            'severity': 'CRITICAL',
        },
        'driver_license_keyword': {
            'keywords': [
                'DRIVING LICENCE', 'DRIVING LICENSE', 'DRIVER LICENCE', 'DRIVER LICENSE',
                'DL NO', 'DL NUMBER', 'LICENCE NO', 'LICENSE NO', 'MOTOR VEHICLE',
                'TRANSPORT DEPARTMENT'
            ],
            'description': 'Driving Licence Keyword Detected',
            'severity': 'CRITICAL',
        },
        'credit_card_keyword': {
            'keywords': ['VALID THRU', 'VALID FROM', 'VISA', 'MASTERCARD', 'RUPAY', 'CVV'],
            'description': 'Credit/Debit Card Keyword Detected',
            'severity': 'CRITICAL',
        },
    }

    def __init__(self):
        print(f"[PATTERN] Pattern detector initialized with {len(self.PATTERNS)} regex patterns "
              f"and {len(self.KEYWORD_PATTERNS)} keyword groups.")

    @staticmethod
    def _normalize_text(text: str) -> str:
        """
        Normalize OCR text for pattern matching.
        Removes spaces and converts to uppercase.

        This handles OCR artifacts where characters are spaced out:
          'A B C D E 1 2 3 4 F' → 'ABCDE1234F'
        """
        return re.sub(r'\s+', '', text).upper()

    def detect(self, text: str) -> List[Dict]:
        """
        Scan text for all sensitive data patterns.
        Runs regex on both raw text AND normalized text to maximize detection.

        Args:
            text: Text to scan (e.g., from OCR extraction)

        Returns:
            List of detections with type, matched text, severity, description
        """
        if not text or not text.strip():
            return []

        detections = []
        seen_types = set()

        for pattern_name, pattern_info in self.PATTERNS.items():
            # Try matching on raw text first
            matches = list(pattern_info['regex'].finditer(text))

            # If no match on raw text AND pattern supports normalization,
            # try on normalized text
            if not matches and pattern_info.get('normalize', False):
                normalized = self._normalize_text(text)
                matches = list(pattern_info['regex'].finditer(normalized))

            for match in matches:
                dedup_key = (pattern_name, match.group(0))
                if dedup_key in seen_types:
                    continue
                seen_types.add(dedup_key)

                matched_text = match.group(0)
                # Mask middle portion for privacy
                if len(matched_text) > 6:
                    masked = matched_text[:3] + '*' * (len(matched_text) - 6) + matched_text[-3:]
                else:
                    masked = '***'

                detections.append({
                    'type': pattern_name,
                    'matched_text': matched_text,
                    'masked_text': masked,
                    'severity': pattern_info['severity'],
                    'description': f"{pattern_info['description']} detected: {masked}",
                    'start': match.start(),
                    'end': match.end()
                })

        # Filter through validation to reduce false positives
        detections = [d for d in detections if self.validate(d)]

        return detections

    def validate(self, detection: dict) -> bool:
        """Post-filter to reduce false positives."""
        t = detection.get('type', '')
        text = detection.get('matched_text', '')
        # Bank account: skip if all same digit
        if t == 'bank_account' and len(set(text)) == 1:
            return False
        # Phone number: skip if starts with 0 or 1 (not valid Indian mobile)
        if t == 'phone_number' and text and text[0] in ('0', '1'):
            return False
        # IFSC: must be exactly 11 chars
        if t == 'ifsc_code' and len(text.replace(' ', '')) != 11:
            return False
        return True

    def detect_keywords(self, text: str) -> List[Dict]:
        """
        Scan text for sensitive keyword labels (NAME, ADDRESS, S/O, DOB, etc.).

        Args:
            text: Text to scan (typically one OCR line/region)

        Returns:
            List of keyword detections with type, keyword, severity
        """
        if not text or not text.strip():
            return []

        upper_text = text.upper()
        detections = []

        for kw_type, kw_info in self.KEYWORD_PATTERNS.items():
            normalized_text = re.sub(r'\s+', '', upper_text)  # "AADHAAR" from "A A D H A A R"
            for keyword in kw_info['keywords']:
                keyword_normalized = re.sub(r'\s+', '', keyword.upper())
                if keyword.upper() in upper_text or keyword_normalized in normalized_text:
                    detections.append({
                        'type': kw_type,
                        'keyword': keyword,
                        'severity': kw_info['severity'],
                        'description': f"{kw_info['description']}: {keyword}",
                    })
                    break  # One match per keyword group per region

        return detections

    def detect_in_regions(self, ocr_regions: List[Dict]) -> List[Dict]:
        """
        Detect patterns in OCR regions, preserving bounding box info.
        For each OCR bounding box:
          1. Get the text
          2. Normalize it (remove spaces, uppercase)
          3. Run regex detection
          4. Attach the bounding box to the detection

        This ensures we know WHICH bounding box to blur.

        Args:
            ocr_regions: List of OCR results with text and bbox info
                         Each dict has: text, x, y, w, h, confidence

        Returns:
            List of detections with bbox coordinates for blurring
        """
        detections = []

        # ── Full-text pass: catch patterns split across multiple OCR lines ──
        # Concatenate all region text and run detection without bbox (bbox=None)
        full_text_parts = [r.get('text', '') for r in ocr_regions if r.get('text', '').strip()]
        full_text_combined = ' '.join(full_text_parts)
        full_text_combined_stripped = re.sub(r'\s+', '', full_text_combined).upper()  # normalized

        full_text_matches = self.detect(full_text_combined)
        # Also try normalized (handles spaced-out OCR like "A B C D E 1 2 3 4 F")
        if not full_text_matches:
            full_text_matches = self.detect(full_text_combined_stripped)

        # For full-text matches, assign the bbox of the best-matching region
        for match in full_text_matches:
            # Try to find which region contains the matched text
            matched_text = match.get('matched_text', '')
            best_region = None
            for region in ocr_regions:
                region_text_clean = re.sub(r'\s+', '', region.get('text', '')).upper()
                match_clean = re.sub(r'\s+', '', matched_text).upper()
                if match_clean and match_clean in region_text_clean:
                    best_region = region
                    break
            if best_region:
                match['bbox'] = (
                    best_region.get('x', 0),
                    best_region.get('y', 0),
                    best_region.get('w', 0),
                    best_region.get('h', 0)
                )
                match['confidence'] = best_region.get('confidence', 50.0)
            else:
                # No specific region found — use a sentinel bbox so we know to blur conservatively
                match['bbox'] = (0, 0, 0, 0)
                match['confidence'] = 50.0
            print(f"[FULL-TEXT-MATCH] {match['type']} = '{match.get('masked_text', '')}' (full-text pass)")
            detections.append(match)

        for region in ocr_regions:
            raw_text = region.get('text', '')
            if not raw_text.strip():
                continue

            # Debug log
            print(f"[OCR-DEBUG] bbox=({region.get('x',0)},{region.get('y',0)},"
                  f"{region.get('w',0)},{region.get('h',0)}) text='{raw_text}'")

            # Run regex detection on this region's text
            matches = self.detect(raw_text)

            for match in matches:
                match['bbox'] = (
                    region.get('x', 0),
                    region.get('y', 0),
                    region.get('w', 0),
                    region.get('h', 0)
                )
                match['confidence'] = region.get('confidence', 0)

                print(f"[OCR-MATCH] SENSITIVE: {match['type']} = '{match['masked_text']}' "
                      f"at bbox=({match['bbox'][0]},{match['bbox'][1]},"
                      f"{match['bbox'][2]},{match['bbox'][3]})")

                detections.append(match)

        if detections:
            print(f"[OCR-DETECT] Found {len(detections)} sensitive pattern(s) — will blur bounding boxes")
            print(f"[REGEX-OK] {len(detections)} detections: {[d['type'] for d in detections]}")
        else:
            print(f"[OCR-DETECT] No sensitive patterns found in {len(ocr_regions)} OCR regions")
            print(f"[REGEX-FAIL] No matches. Full combined text was: '{full_text_combined[:200]}'")

        return detections

    def detect_keywords_in_regions(self, ocr_regions: List[Dict]) -> List[Dict]:
        """
        Detect keyword patterns in OCR regions, preserving bounding box info.
        Used for blurring regions near ADDRESS, NAME, S/O, DOB labels.

        Args:
            ocr_regions: List of OCR results with text and bbox info

        Returns:
            List of keyword detections with bbox coordinates for blurring
        """
        detections = []

        for region in ocr_regions:
            raw_text = region.get('text', '')
            if not raw_text.strip():
                continue

            keyword_matches = self.detect_keywords(raw_text)

            for match in keyword_matches:
                match['bbox'] = (
                    region.get('x', 0),
                    region.get('y', 0),
                    region.get('w', 0),
                    region.get('h', 0)
                )
                match['confidence'] = region.get('confidence', 0)

                print(f"[KEYWORD] {match['type']}: '{match['keyword']}' "
                      f"at bbox=({match['bbox'][0]},{match['bbox'][1]},"
                      f"{match['bbox'][2]},{match['bbox'][3]})")

                detections.append(match)

        if detections:
            print(f"[KEYWORD] Found {len(detections)} keyword region(s) — will blur nearby text")

        return detections
