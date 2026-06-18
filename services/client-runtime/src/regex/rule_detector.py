"""
Rule-based detector for PriVoke Phase 1.

This module orchestrates regex rule execution. Rule schemas live in
rule_types.py and rule definitions are grouped by concern in rules_*.py files.
"""

from __future__ import annotations

import re
from typing import Dict, List, Sequence, Tuple

from src.classification import (
    Category,
    Sensitivity,
    Visibility,
    dedupe_categories,
    initialise_unpacked,
    merge_classifications,
)
from src.regex.rule_registry import all_rule_definitions
from src.regex.rule_types import RuleMatch


def _signals(matches: Sequence[RuleMatch]) -> List[str]:
    signals = [match.signal for match in matches]
    return list(dict.fromkeys(signals))


class RuleDetector:
    """
    Pattern-based detector using regex rules for common sensitive categories.
    """

    def __init__(self):
        self.rules = [definition.compile() for definition in all_rule_definitions()]
        self.patterns = {rule.name: rule.pattern.pattern for rule in self.rules}

    def analyze(self, text: str) -> Dict:
        """
        Analyze text and return structured enum-backed classification details.

        Returns:
            classification: merged Classification object
            packed_classification: 16-bit packed classification
            matches: list[RuleMatch]
            match_details: JSON-friendly match dictionaries
            signals: ordered list of matched rule signal names
        """
        matches = self._collect_matches(text)
        matches.extend(self._heuristic_matches(text, matches))

        matches = self._dedupe_matches(matches)
        classification = merge_classifications(
            match.classification for match in matches
        )

        return {
            "classification": classification,
            "packed_classification": classification.pack(),
            "matches": matches,
            "match_details": [match.to_dict() for match in matches],
            "signals": _signals(matches),
        }

    def _collect_matches(self, text: str) -> List[RuleMatch]:
        matches = []
        for rule in self.rules:
            for regex_match in rule.pattern.finditer(text):
                matches.append(
                    RuleMatch(
                        rule_name=rule.name,
                        signal=rule.signal,
                        text=regex_match.group(0),
                        span=regex_match.span(),
                        classification=rule.classification,
                    )
                )
        return matches

    def _heuristic_matches(
        self,
        text: str,
        matches: Sequence[RuleMatch],
    ) -> List[RuleMatch]:
        heuristic_matches = []
        word_count = len(text.split())

        if word_count > 80:
            heuristic_matches.append(
                self._synthetic_match(
                    "personal_narrative",
                    f"long_personal_narrative({word_count}_words)",
                    "",
                    (0, min(len(text), 1)),
                    Sensitivity.S1,
                    Visibility.PU,
                    [Category.IDENTITY],
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
            heuristic_matches.append(
                self._synthetic_match(
                    "multiple_identity_fields",
                    f"multiple_identity_fields({identity_field_count})",
                    "",
                    (0, 0),
                    Sensitivity.S2,
                    Visibility.PU,
                    [Category.IDENTITY],
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
            heuristic_matches.append(
                self._synthetic_match(
                    "concentrated_sensitive_data",
                    "concentrated_pii",
                    "",
                    (0, len(text)),
                    Sensitivity.S2,
                    Visibility.PU,
                    categories,
                )
            )

        return heuristic_matches

    def _synthetic_match(
        self,
        rule_name: str,
        signal: str,
        text: str,
        span: Tuple[int, int],
        sensitivity: Sensitivity,
        visibility: Visibility,
        categories: Sequence[Category],
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
        )

    def _dedupe_matches(self, matches: Sequence[RuleMatch]) -> List[RuleMatch]:
        seen = set()
        deduped = []
        for match in matches:
            key = (match.rule_name, match.signal, match.span, match.text)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(match)
        return deduped
