from typing import List

from .rule_types import RuleDefinition
from ..classification import Category, Sensitivity, Visibility, initialise_unpacked


def identity_rules() -> List[RuleDefinition]:
    """Direct and quasi identity rules."""
    return [
        RuleDefinition(
            "email",
            r"\b[\w\.-]+@[\w\.-]+\.\w+\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "email",
        ),
        RuleDefinition(
            "phone_us",
            r"(?<![\w])(?:\+?1[\s\-]?)?\(?[2-9]\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "phone",
        ),
        RuleDefinition(
            "phone_intl",
            r"\+\d{1,3}([\s\-]?\d{2,4}){2,3}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "phone",
        ),
        RuleDefinition(
            "ssn_formatted",
            r"\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "ssn",
        ),
        RuleDefinition(
            "itin",
            r"\b9\d{2}[\s\-]?(?:7\d|8[0-8]|9[0-2]|9[4-9])[\s\-]?\d{4}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "itin",
        ),
        RuleDefinition(
            "passport",
            r"\b(?:passport|pass(?:port)? no\.?|passport number)\s*[:#=]?\s*[A-Z]{1,2}\d{6,9}\b|\b[A-Z]{1,2}\d{6,9}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "passport",
        ),
        RuleDefinition(
            "driver_license",
            r"\b(?:driver'?s?\s+licen[cs]e|dl)\s*[:#=]?\s*[A-Z0-9\-]{5,15}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "driver_license",
        ),
        RuleDefinition(
            "government_id",
            r"\b(?:national\s+id|tax\s+id|tin|id\s+number|identity\s+number)\s*[:#=]?\s*[A-Z0-9\-]{5,20}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "government_id",
        ),
        RuleDefinition(
            "api_key",
            r"\b(?:sk|pk|ghp|xoxb|akia)[-_a-z0-9]{16,}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "api_key",
        ),
        RuleDefinition(
            "url_with_token",
            r"https?://\S*(?:token|key|secret|auth|session)=\S+",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "url_token",
        ),
        RuleDefinition(
            "password_assignment",
            r"\b(?:password|passwd|pwd|passcode)\s*[:=]\s*\S+",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "password",
        ),
        RuleDefinition(
            "mac_address",
            r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.IDENTITY]),
            "mac_address",
        ),
        RuleDefinition(
            "vin",
            r"\b[A-HJ-NPR-Z0-9]{17}\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.IDENTITY]),
            "vin",
        ),
        RuleDefinition(
            "social_handle",
            r"(?<![a-zA-Z0-9.])@[\w\-\.]{2,}(?![a-zA-Z0-9_])",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.IDENTITY]),
            "social_handle",
        ),
        RuleDefinition(
            "structured_identity",
            r"\b(name|username|user|handle|account|login|email|phone|location|address)\s*[:=]\s*[\w\s\.\-@]+",
            initialise_unpacked(Sensitivity.S2, Visibility.P2, [Category.IDENTITY]),
            "structured_field",
        ),
        RuleDefinition(
            "date_field",
            r"\b(birth[\s_]?date|dob|date[\s_]?of[\s_]?birth|birthday|born|age)\s*[:=]?\s*[\d\s\/-]+",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.IDENTITY]),
            "date_field",
        ),
    ]
