"""
Rule-Based Detector for PriVoke Phase 1

Fast, regex-based pattern matching for common PII and sensitive data.
Used as first-pass screening before LLM analysis.
"""

import re
from typing import Tuple, List


def bump(sev: str, new_sev: str) -> str:
    """
    Compares two severity levels and returns the higher one.
    Scale: LOW (1) < MEDIUM (2) < HIGH (3)
    """
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    inv = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}
    return inv[max(rank.get(sev, 1), rank.get(new_sev, 1))]


class RuleDetector:
    """
    Pattern-based detector using regex rules for common PII types.
    Detects: emails, phones, SSN, credit cards, IDs, personal narratives, etc.
    Works across all privacy-sensitive datasets.
    """

    def __init__(self):
        """Initialize regex patterns for various PII types."""
        self.patterns = self._compile_patterns()

    def _compile_patterns(self) -> dict:
        """Compile all regex patterns for efficiency."""
        return {
            # DIRECT PII - HIGH RISK
            "email": (r'\b[\w\.-]+@[\w\.-]+\.\w+\b', "HIGH", "email"),
            "phone_us": (r'(\+?1[\s\-]?)?\(?[2-9]\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b', "HIGH", "phone"),
            "phone_intl": (r'\+\d{1,3}([\s\-]?\d{2,4}){2,3}\b', "HIGH", "phone"),
            "ssn_formatted": (r'\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b', "HIGH", "ssn"),
            "credit_card": (r'\b(?:\d{4}[\s\-]?){3}\d{4}\b', "HIGH", "credit_card"),
            "passport": (r'\b[A-Z]{1,2}\d{6,9}\b', "HIGH", "passport"),
            "iban": (r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b', "HIGH", "iban"),
            
            # QUASI-PII - MEDIUM RISK
            "structured_identity": (
                r'\b(name|username|user|handle|account|login|email|phone|location|address)\s*[:=]\s*[\w\s\.\-@]+',
                "MEDIUM",
                "structured_field"
            ),
            "date_field": (
                r'\b(birth[\s_]?date|dob|date[\s_]?of[\s_]?birth|birthday|born|age)\s*[:=]?\s*[\d\s\/-]+',
                "MEDIUM",
                "date_field"
            ),
            "location_keyword": (
                r'\b(lives?|lives? in|located in|from|address|hometown|residence)\s*(?:in|at)?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?',
                "MEDIUM",
                "location"
            ),
            "social_handle": (r'(?<![a-zA-Z0-9.])@[\w\-\.]{2,}(?![a-zA-Z0-9_])', "MEDIUM", "social_handle"),
            
            # CONTEXTUAL PII - MEDIUM RISK
            "family_disclosure": (
                r'\b(spouse|husband|wife|partner|boyfriend|girlfriend|children|kids|son|daughter|mother|father|siblings?|family)\b',
                "MEDIUM",
                "family_info"
            ),
            "health_keyword": (
                r'\b(hospital|doctor|medication|disease|cancer|diabetes|depression|anxiety|therapy|psychiatric|diagnosis|prognosis|allergy)\b',
                "MEDIUM",
                "health_info"
            ),
            "financial_keyword": (
                r'\b(salary|income|bonus|bank|account|credit|loan|mortgage|debt|investment|stock|crypto|bitcoin|ethereum)\b',
                "MEDIUM",
                "financial_info"
            ),
            "workplace_keyword": (
                r'\b(work(?:s|ing)?|employ(?:ee|er|ment)|company|office|boss|colleague|manager|department)\b',
                "LOW",
                "workplace_info"
            ),
            
            # BEHAVIORAL PATTERNS - MEDIUM/LOW RISK
            "timestamp_field": (
                r'\b(timestamp|visited|accessed|logged|created|modified|updated|date|time)\s*[:=]\s*[\d\s\-/:T.Z]+',
                "LOW",
                "timestamp"
            ),
            "personal_narrative": ({
                "pattern": r'.',  # Matched by word count
                "min_words": 80,
                "severity": "LOW",
                "category": "personal_narrative"
            }),
        }

    def analyze(self, text: str) -> Tuple[str, str, str]:
        """
        Analyze text for PII and sensitive content.
        
        Returns:
        (category, severity, signals_string)
        """
        category = "NORMAL"
        severity = "LOW"
        signals = []
        
        # Check text length for personal narrative
        word_count = len(text.split())
        if word_count > 80:
            severity = bump(severity, "LOW")
            signals.append(f"long_personal_narrative({word_count}_words)")
        
        # Check all patterns
        for pattern_name, pattern_info in self.patterns.items():
            if pattern_name == "personal_narrative":
                # Already handled above
                continue
            
            pattern, pattern_severity, signal_type = pattern_info
            
            if re.search(pattern, text, re.IGNORECASE):
                category = "PII"
                severity = bump(severity, pattern_severity)
                signals.append(signal_type)
        
        # Additional heuristic: multiple identity fields
        identity_field_count = len(re.findall(
            r'\b(name|email|phone|username|location|address)\s*[:=]\s*',
            text,
            re.IGNORECASE
        ))
        if identity_field_count >= 2:
            category = "PII"
            severity = bump(severity, "MEDIUM")
            signals.append(f"multiple_identity_fields({identity_field_count})")
        
        # Additional heuristic: very short text with high-confidence PII
        if word_count < 10 and len(signals) > 0:
            severity = bump(severity, "MEDIUM")
            signals.append("concentrated_pii")
        
        # Deduplicate signals while preserving order (e.g., "phone, phone" → "phone")
        signals = list(dict.fromkeys(signals))
        
        signals_str = ", ".join(signals) if signals else "no_rule_match"
        
        return category, severity, signals_str
