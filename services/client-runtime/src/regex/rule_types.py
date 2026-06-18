from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Pattern, Tuple

from src.classification import Classification


@dataclass(frozen=True)
class RuleDefinition:
    """Regex rule plus its resulting classification."""

    name: str
    pattern: str
    classification: Classification
    signal: str
    flags: int = re.IGNORECASE

    def compile(self) -> "CompiledRule":
        return CompiledRule(
            name=self.name,
            pattern=re.compile(self.pattern, self.flags),
            classification=self.classification,
            signal=self.signal,
        )


@dataclass(frozen=True)
class CompiledRule:
    """Compiled regex rule used by RuleDetector."""

    name: str
    pattern: Pattern[str]
    classification: Classification
    signal: str


@dataclass(frozen=True)
class RuleMatch:
    """One regex or heuristic hit and its enum-backed classification."""

    rule_name: str
    signal: str
    text: str
    span: Tuple[int, int]
    classification: Classification

    def to_dict(self) -> Dict:
        return {
            "rule_name": self.rule_name,
            "signal": self.signal,
            "text": self.text,
            "span": self.span,
            "sensitivity": self.classification.sensitivity().name,
            "visibility": self.classification.visibility().name,
            "categories": [
                category.name for category in self.classification.categories()
            ],
            "packed_classification": self.classification.pack(),
        }
