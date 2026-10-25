from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Pattern, Tuple

from ..classification import Classification, ClassificationResult


# A validator receives the regex match (with its full source string available as
# ``match.string``) and returns False to reject a structurally plausible hit.
MatchValidator = Callable[["re.Match[str]"], bool]


@dataclass(frozen=True)
class Downgrade:
    """What a hit that fails its rule's validator is reported as instead of being dropped.

    A checksum failure shows the value is not a valid number of the rule's kind; it does
    not show the value is not an identifier. A rule lists downgrades in priority order and
    the first whose ``accept`` test passes (always, when ``accept`` is None) keeps the hit
    under its own rule name and classification, typically at a lower sensitivity than the
    validated rule. A hit that no downgrade accepts is dropped.
    """

    name: str
    classification: Classification
    signal: str
    accept: Optional[MatchValidator] = None
    confidence: float = 0.80


@dataclass(frozen=True)
class RuleDefinition:
    """Regex rule plus its resulting classification."""

    name: str
    pattern: str
    classification: Classification
    signal: str
    flags: int = re.IGNORECASE
    validator: Optional[MatchValidator] = None
    downgrades: Tuple[Downgrade, ...] = ()

    def compile(self) -> "CompiledRule":
        return CompiledRule(
            name=self.name,
            pattern=re.compile(self.pattern, self.flags),
            classification=self.classification,
            signal=self.signal,
            validator=self.validator,
            downgrades=self.downgrades,
        )


@dataclass(frozen=True)
class CompiledRule:
    """Compiled regex rule used by RuleDetector."""

    name: str
    pattern: Pattern[str]
    classification: Classification
    signal: str
    validator: Optional[MatchValidator] = None
    downgrades: Tuple[Downgrade, ...] = ()


@dataclass(frozen=True)
class RuleMatch:
    """One regex or heuristic hit and its enum-backed classification."""

    rule_name: str
    signal: str
    text: str
    span: Tuple[int, int]
    classification: Classification
    confidence: float = 0.95

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

    def to_classification_result(self) -> ClassificationResult:
        return ClassificationResult(
            classification=self.classification,
            section_of_text=self.text,
            reasoning=f"Matched rule '{self.rule_name}'",
            span=self.span,
            confidence=self.confidence,
            metadata={"rule_name": self.rule_name},
        )
