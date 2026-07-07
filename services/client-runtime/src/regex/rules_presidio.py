"""
Import regex-based recognizers from Microsoft Presidio and expose them as
PriVoke RuleDefinitions.
"""

from collections import Counter
from typing import List

from presidio_analyzer import PatternRecognizer, RecognizerRegistry

from .rule_types import RuleDefinition
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
                )
            )

    return rules


if __name__ == "__main__":
    rules = presidio_rules()

    print(f"\nImported {len(rules)} Presidio regex rules.\n")

    counts = Counter(rule.signal for rule in rules)

    for signal, count in sorted(counts.items()):
        print(f"{signal:<35} {count}")