"""
Rule-based detector for PriVoke Phase 1.

This module orchestrates regex rule execution. Rule schemas live in
rule_types.py and rule definitions are grouped by concern in rules_*.py files.
"""

from __future__ import annotations

from typing import List, Sequence

from ..classification import ClassificationResult
from ..detection.context import is_clean_discussion_context
from .rule_heuristics import heuristic_matches
from .rule_registry import all_rule_definitions
from .rule_types import RuleMatch


WEAK_CONTEXT_RULES = {
    "financial_keyword",
    "money_amount",
    "health_keyword",
    "politics",
    "religion",
    "criminal",
    "sexual",
    "child",
    "family_disclosure",
    "workplace_keyword",
}


class RuleDetector:
    """
    Pattern-based detector using regex rules for common sensitive categories.
    """

    def __init__(self):
        self.rules = [definition.compile() for definition in all_rule_definitions()]
        self.patterns = {rule.name: rule.pattern.pattern for rule in self.rules}

    def analyze(self, text: str) -> List[ClassificationResult]:
        """
        Analyze text and return one ClassificationResult per regex/heuristic hit.
        """
        matches = self._collect_matches(text)
        matches = self._suppress_clean_context_matches(text, matches)
        matches.extend(heuristic_matches(text, matches))

        matches = self._dedupe_matches(matches)
        return [match.to_classification_result() for match in matches]

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
                        confidence=0.95,
                    )
                )
        return matches

    def _suppress_clean_context_matches(
        self,
        text: str,
        matches: Sequence[RuleMatch],
    ) -> List[RuleMatch]:
        if not is_clean_discussion_context(text):
            return list(matches)
        return [
            match
            for match in matches
            if match.rule_name not in WEAK_CONTEXT_RULES
        ]

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
