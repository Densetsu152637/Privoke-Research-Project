from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from .classification_policy import action_for_classification_result
from .classification_types import (
    Category,
    Classification,
    PriVokeAction,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)


@dataclass
class ClassificationResult:
    """Common result returned by all prompt classifiers."""

    classification: Classification
    section_of_text: str
    reasoning: str
    span: Tuple[int, int] | None = None
    confidence: float | None = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.metadata = _parse_metadata(self.metadata)

    def action(self) -> PriVokeAction:
        return action_for_classification_result(self)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification.to_dict(),
            "action": self.action().name,
            "section_of_text": self.section_of_text,
            "reasoning": self.reasoning,
            "span": self.span,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


def build_results(content: Dict | List[Dict]) -> List[ClassificationResult]:
    if isinstance(content, dict):
        raw_results = content.get("results")
        if raw_results is None:
            raw_results = content.get("classification_results")
        if raw_results is None:
            raw_results = [content]
    else:
        raw_results = content

    if not isinstance(raw_results, list):
        return []

    return [
        parse_result(item)
        for item in raw_results
        if isinstance(item, dict)
    ]


def parse_result(parsed: Dict) -> ClassificationResult:
    sensitivity = _enum_value(Sensitivity, parsed.get("sensitivity"), Sensitivity.S0)
    visibility = _enum_value(Visibility, parsed.get("visibility"), Visibility.PU)

    categories = []
    raw_categories = parsed.get("categories", [])
    if isinstance(raw_categories, list):
        for raw_category in raw_categories:
            category = _enum_value(Category, raw_category, None)
            if category is not None:
                categories.append(category)

    classification = initialise_unpacked(sensitivity, visibility, categories)

    return ClassificationResult(
        classification=classification,
        section_of_text=parsed.get("section_of_text", parsed.get("text", "")),
        reasoning=parsed.get("reasoning", "Unknown reason"),
        span=_parse_span(parsed.get("span")),
        confidence=parsed.get("confidence"),
        metadata=_parse_metadata(parsed.get("metadata", {})),
    )


def _enum_value(enum_type, raw_value, default):
    if isinstance(raw_value, enum_type):
        return raw_value
    if isinstance(raw_value, str):
        try:
            return enum_type[raw_value]
        except KeyError:
            return default
    return default


def _parse_span(raw_span) -> Tuple[int, int] | None:
    if (
        isinstance(raw_span, (list, tuple))
        and len(raw_span) == 2
        and all(isinstance(item, int) for item in raw_span)
    ):
        return (raw_span[0], raw_span[1])
    return None


def _parse_metadata(raw_metadata) -> Dict[str, Any]:
    if not isinstance(raw_metadata, dict):
        return {}

    reserved_keys = {"signal", "signals", "source"}
    return {
        key: value
        for key, value in raw_metadata.items()
        if key not in reserved_keys
    }
