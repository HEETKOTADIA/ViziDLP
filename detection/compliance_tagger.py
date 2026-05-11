"""
ViziDLP Compliance Tagger
Tags detections with applicable compliance framework identifiers.

Frameworks:
  - GDPR (EU General Data Protection Regulation)
  - PCI-DSS (Payment Card Industry Data Security Standard)
  - IT Act 2000 / DPDP Act (India — Digital Personal Data Protection)
  - HIPAA (Health Insurance Portability and Accountability Act)

Each detection type is mapped to one or more frameworks with article references.
"""

from typing import Dict, List, Set


class ComplianceTagger:
    """
    Tags detection events with applicable compliance frameworks.

    Usage:
        tagger = ComplianceTagger()
        tags = tagger.tag("aadhaar_number")
        # Returns: [{"framework": "DPDP", "article": "Section 2(t)", ...}, ...]
    """

    # Mapping: detection_type -> list of compliance tags
    COMPLIANCE_MAP = {
        # ─── Indian PII (DPDP Act / IT Act) ───────────────────
        'aadhaar_number': [
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Sensitive Personal Data',
             'description': 'Aadhaar number is classified as sensitive personal data under DPDP Act'},
            {'framework': 'IT_ACT', 'article': 'Section 43A', 'category': 'Sensitive Personal Data',
             'description': 'Government-issued identifier protected under IT Act 2000'},
        ],
        'aadhaar_number_spaced': [
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Sensitive Personal Data',
             'description': 'Aadhaar number (spaced OCR variant)'},
        ],
        'pan_number': [
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Financial Identifier',
             'description': 'PAN is a financial identifier under DPDP Act'},
            {'framework': 'IT_ACT', 'article': 'Section 43A', 'category': 'Sensitive Personal Data',
             'description': 'Tax identifier protected under IT Act 2000'},
        ],
        'voter_id': [
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Government ID',
             'description': 'Government-issued identification document'},
        ],
        'passport_number': [
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Government ID',
             'description': 'Passport number is sensitive personal data'},
            {'framework': 'GDPR', 'article': 'Article 87', 'category': 'National ID',
             'description': 'National identification number under GDPR'},
        ],
        'driver_licence_number': [
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Government ID',
             'description': 'Driver licence is a government-issued identifier'},
        ],

        # ─── Financial Data (PCI-DSS) ─────────────────────────
        'credit_card_number': [
            {'framework': 'PCI_DSS', 'article': 'Req 3.4', 'category': 'Cardholder Data',
             'description': 'Primary Account Number must be rendered unreadable'},
            {'framework': 'PCI_DSS', 'article': 'Req 4.1', 'category': 'Cardholder Data',
             'description': 'PAN must be encrypted during transmission'},
        ],
        'bank_account': [
            {'framework': 'PCI_DSS', 'article': 'Req 3', 'category': 'Financial Data',
             'description': 'Bank account numbers are sensitive financial data'},
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Financial Data',
             'description': 'Financial data protected under DPDP Act'},
        ],
        'ifsc_code': [
            {'framework': 'PCI_DSS', 'article': 'Req 3', 'category': 'Financial Metadata',
             'description': 'Bank routing code — financial metadata'},
        ],
        'upi_id': [
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Financial Identifier',
             'description': 'UPI ID is a financial identifier'},
        ],
        'gstin': [
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Tax Identifier',
             'description': 'GST Identification Number — business tax identifier'},
        ],

        # ─── Personal Data (GDPR) ─────────────────────────────
        'email_address': [
            {'framework': 'GDPR', 'article': 'Article 4(1)', 'category': 'Personal Data',
             'description': 'Email address is personal data under GDPR'},
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Personal Data',
             'description': 'Contact information is personal data'},
        ],
        'phone_number': [
            {'framework': 'GDPR', 'article': 'Article 4(1)', 'category': 'Personal Data',
             'description': 'Phone number is personal data under GDPR'},
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Personal Data',
             'description': 'Contact information is personal data'},
        ],
        'dob': [
            {'framework': 'GDPR', 'article': 'Article 4(1)', 'category': 'Personal Data',
             'description': 'Date of birth is personal data'},
            {'framework': 'DPDP', 'article': 'Section 2(t)', 'category': 'Personal Data',
             'description': 'Date of birth is personal data under DPDP Act'},
        ],

        # ─── Keyword-based detections ─────────────────────────
        'name_keyword': [
            {'framework': 'GDPR', 'article': 'Article 4(1)', 'category': 'Personal Data',
             'description': 'Name field indicates personal data processing'},
        ],
        'address_keyword': [
            {'framework': 'GDPR', 'article': 'Article 4(1)', 'category': 'Personal Data',
             'description': 'Address field indicates personal data processing'},
        ],
        'relation_keyword': [
            {'framework': 'GDPR', 'article': 'Article 4(1)', 'category': 'Personal Data',
             'description': 'Family relation field indicates sensitive data processing'},
        ],
        'dob_keyword': [
            {'framework': 'GDPR', 'article': 'Article 4(1)', 'category': 'Personal Data',
             'description': 'DOB label indicates personal data processing'},
        ],
        'financial_keyword': [
            {'framework': 'PCI_DSS', 'article': 'Req 3', 'category': 'Financial Data',
             'description': 'Financial field label detected'},
        ],

        # ─── Security Credentials ─────────────────────────────
        'api_key': [
            {'framework': 'GDPR', 'article': 'Article 32', 'category': 'Security Credential',
             'description': 'API key exposure violates security measures requirement'},
        ],
        'password': [
            {'framework': 'GDPR', 'article': 'Article 32', 'category': 'Security Credential',
             'description': 'Password exposure violates security measures requirement'},
        ],
        'aws_key': [
            {'framework': 'GDPR', 'article': 'Article 32', 'category': 'Cloud Credential',
             'description': 'AWS key exposure — cloud infrastructure security breach'},
        ],
        'private_key': [
            {'framework': 'GDPR', 'article': 'Article 32', 'category': 'Cryptographic Key',
             'description': 'Private key exposure — cryptographic security breach'},
        ],

        # ─── Network/Behavioral ────────────────────────────────
        'suspicious_network_connection': [
            {'framework': 'GDPR', 'article': 'Article 33', 'category': 'Data Breach Risk',
             'description': 'Suspicious outbound connection may indicate data exfiltration'},
        ],
        'cloud_upload_attempt': [
            {'framework': 'GDPR', 'article': 'Article 44-49', 'category': 'Cross-border Transfer',
             'description': 'Cloud upload may involve cross-border data transfer'},
        ],
    }

    def __init__(self):
        print(f"[COMPLIANCE] Compliance tagger initialized "
              f"({len(self.COMPLIANCE_MAP)} detection types mapped).")

    def tag(self, detection_type: str) -> List[Dict]:
        """
        Get compliance tags for a detection type.

        Args:
            detection_type: The detection type string (e.g., 'aadhaar_number')

        Returns:
            List of compliance tag dicts, or empty list if no mapping exists
        """
        return self.COMPLIANCE_MAP.get(detection_type, [])

    def tag_detection(self, detection: dict) -> dict:
        """
        Add compliance_tags field to a detection dict (in-place + return).

        Args:
            detection: Detection dict with at least a 'type' or 'data_category' key

        Returns:
            The same detection dict with 'compliance_tags' added
        """
        det_type = detection.get('type') or detection.get('data_category', '')
        tags = self.tag(det_type)
        detection['compliance_tags'] = tags
        detection['compliance_frameworks'] = list({t['framework'] for t in tags})
        return detection

    def get_frameworks_for_type(self, detection_type: str) -> Set[str]:
        """Get the set of framework names that apply to a detection type."""
        tags = self.tag(detection_type)
        return {t['framework'] for t in tags}

    def get_compliance_summary(self, detections: List[dict]) -> Dict:
        """
        Generate a compliance summary for a list of detections.

        Returns:
            Dict with framework -> {count, categories, articles} mapping
        """
        summary = {}
        for det in detections:
            det_type = det.get('type') or det.get('data_category', '')
            tags = self.tag(det_type)
            for tag in tags:
                fw = tag['framework']
                if fw not in summary:
                    summary[fw] = {
                        'count': 0,
                        'categories': set(),
                        'articles': set(),
                    }
                summary[fw]['count'] += 1
                summary[fw]['categories'].add(tag['category'])
                summary[fw]['articles'].add(tag['article'])

        # Convert sets to lists for JSON serialization
        for fw in summary:
            summary[fw]['categories'] = sorted(summary[fw]['categories'])
            summary[fw]['articles'] = sorted(summary[fw]['articles'])

        return summary
