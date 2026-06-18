import re
from typing import List, Sequence, Tuple

from src import (
    Category,
    Sensitivity,
    Visibility,
    dedupe_categories,
    initialise_unpacked,
)
from src import RuleMatch


def heuristic_matches(
    text: str,
    matches: Sequence[RuleMatch],
) -> List[RuleMatch]:
    generated = []
    word_count = len(text.split())

    if word_count > 80:
        generated.append(
            synthetic_match(
                "personal_narrative",
                f"long_personal_narrative({word_count}_words)",
                text,
                (0, len(text)),
                Sensitivity.S1,
                Visibility.PU,
                [Category.IDENTITY],
                0.60,
            )
        )

    identity_field_count = len(
        re.findall(
            r"\b(name|email|phone|username|location|address)\s*[:=]\s*",
            text,
            re.IGNORECASE,
        )
    )
    if identity_field_count >= 2:
        generated.append(
            synthetic_match(
                "multiple_identity_fields",
                f"multiple_identity_fields({identity_field_count})",
                text,
                (0, len(text)),
                Sensitivity.S2,
                Visibility.PU,
                [Category.IDENTITY],
                0.70,
            )
        )

    high_confidence_matches = [
        match
        for match in matches
        if match.classification.sensitivity() == Sensitivity.S3
    ]
    if word_count < 10 and high_confidence_matches:
        categories = dedupe_categories(
            category
            for match in high_confidence_matches
            for category in match.classification.categories()
        )
        generated.append(
            synthetic_match(
                "concentrated_sensitive_data",
                "concentrated_pii",
                text,
                (0, len(text)),
                Sensitivity.S2,
                Visibility.PU,
                categories,
                0.70,
            )
        )

    return generated


def synthetic_match(
    rule_name: str,
    signal: str,
    text: str,
    span: Tuple[int, int],
    sensitivity: Sensitivity,
    visibility: Visibility,
    categories: Sequence[Category],
    confidence: float,
) -> RuleMatch:
    return RuleMatch(
        rule_name=rule_name,
        signal=signal,
        text=text,
        span=span,
        classification=initialise_unpacked(
            sensitivity,
            visibility,
            list(categories),
        ),
        confidence=confidence,
    )
