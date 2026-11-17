"""
Import regex-based recognizers from Microsoft Presidio and expose them as
PriVoke RuleDefinitions.
"""

from collections import Counter
from typing import List

from presidio_analyzer import PatternRecognizer, RecognizerRegistry

from .rule_types import MatchValidator, RuleDefinition
from .rule_validators import (
    checksum_validator,
    context_required_validator,
    digits_or_context_validator,
    iban_valid,
    luhn_valid,
    nhs_number_valid,
    us_ssn_valid,
)
from ..classification import (
    Category,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)

# Map Presidio entity types -> PriVoke categories
ENTITY_MAP = {
    "EMAIL_ADDRESS": Category.IDENTITY,
    "PHONE_NUMBER": Category.IDENTITY,
    "CREDIT_CARD": Category.FINANCIAL,
    "US_BANK_NUMBER": Category.FINANCIAL,
    "IBAN_CODE": Category.FINANCIAL,
    "US_DRIVER_LICENSE": Category.IDENTITY,
    "US_PASSPORT": Category.IDENTITY,
    "US_SSN": Category.IDENTITY,
    "US_ITIN": Category.IDENTITY,
    "IP_ADDRESS": Category.IDENTITY,
    "MAC_ADDRESS": Category.IDENTITY,
    "URL": Category.IDENTITY,
    "CRYPTO": Category.FINANCIAL,
    "DATE_TIME": Category.IDENTITY,
    "MEDICAL_LICENSE": Category.HEALTH,
    "UK_NHS": Category.HEALTH,
}

# Map Presidio entity types -> PriVoke sensitivity
SENSITIVITY_MAP = {
    "CREDIT_CARD": Sensitivity.S3,
    "US_BANK_NUMBER": Sensitivity.S3,
    "IBAN_CODE": Sensitivity.S3,
    "US_SSN": Sensitivity.S3,
    "US_ITIN": Sensitivity.S3,
    "UK_NHS": Sensitivity.S3,
    "MEDICAL_LICENSE": Sensitivity.S3,

    "US_DRIVER_LICENSE": Sensitivity.S2,
    "US_PASSPORT": Sensitivity.S2,
    "EMAIL_ADDRESS": Sensitivity.S2,
    "PHONE_NUMBER": Sensitivity.S2,
    "CRYPTO": Sensitivity.S2,

    "IP_ADDRESS": Sensitivity.S1,
    "MAC_ADDRESS": Sensitivity.S1,
    "URL": Sensitivity.S1,
    "DATE_TIME": Sensitivity.S1,
}


# Entities whose values carry a checksum or fixed invalid ranges; the generic
# digit-run patterns only count when the value could actually be issued.
ENTITY_CHECKSUMS = {
    "CREDIT_CARD": luhn_valid,
    "IBAN_CODE": iban_valid,
    "UK_NHS": nhs_number_valid,
    "US_SSN": us_ssn_valid,
}

# The alphanumeric driver-licence pattern is a letter plus a short digit run,
# which also matches part numbers and codes. Keep it only with enough digits
# or an explicit licence context word. Presidio's own context list also holds
# ambiguous nouns ("driver", "permit", "identification", "driving") that occur
# in unrelated phrases, so only licence-specific terms are used.
DRIVER_LICENSE_CONTEXT = (
    "license", "licence", "lic", "lic#", "dl", "dls", "cdl", "cdls",
)

DATE_SHORT_PATTERN_NAMES = ("mm/yy or m/yy",)
DATE_CONTEXT_WORDS = (
    "date", "dated", "expiry", "expires", "expiration", "exp", "valid", "due",
    "born", "birth", "birthday", "dob", "issued", "since", "until", "deadline",
)


def _presidio_validator(entity: str, pattern) -> MatchValidator | None:
    check = ENTITY_CHECKSUMS.get(entity)
    if check is not None:
        return checksum_validator(check)
    pattern_name = pattern.name.lower()
    if entity == "US_DRIVER_LICENSE" and "alphanumeric" in pattern_name:
        return digits_or_context_validator(5, DRIVER_LICENSE_CONTEXT)
    if entity == "DATE_TIME" and pattern_name in DATE_SHORT_PATTERN_NAMES:
        # "7/10" is as likely a score as a month/year.
        return context_required_validator(DATE_CONTEXT_WORDS)
    return None


def presidio_rules() -> List[RuleDefinition]:
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()

    rules: List[RuleDefinition] = []
    seen_patterns = set()

    for recognizer in registry.recognizers:

        # Skip spaCy recognizer (already handled by PriVoke NER)
        if recognizer.__class__.__name__ == "SpacyRecognizer":
            continue

        # Only import regex-based recognizers
        if not isinstance(recognizer, PatternRecognizer):
            continue

        entity = recognizer.supported_entities[0]

        category = ENTITY_MAP.get(entity, Category.IDENTITY)
        sensitivity = SENSITIVITY_MAP.get(entity, Sensitivity.S2)

        for pattern in recognizer.patterns:

            # Avoid duplicate regex patterns
            if pattern.regex in seen_patterns:
                continue
            seen_patterns.add(pattern.regex)

            rules.append(
                RuleDefinition(
                    name=f"presidio_{recognizer.name.lower()}_{pattern.name.lower()}",
                    pattern=pattern.regex,
                    classification=initialise_unpacked(
                        sensitivity,
                        Visibility.PU,
                        [category],
                    ),
                    signal=f"presidio_{entity.lower()}",
                    validator=_presidio_validator(entity, pattern),
                )
            )

    return rules


if __name__ == "__main__":
    rules = presidio_rules()

    print(f"\nImported {len(rules)} Presidio regex rules.\n")

    counts = Counter(rule.signal for rule in rules)

    for signal, count in sorted(counts.items()):
        print(f"{signal:<35} {count}")