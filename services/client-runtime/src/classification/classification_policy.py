from typing import Any, Iterable, List

from .classification_types import (
    Category,
    Classification,
    PriVokeAction,
    Sensitivity,
    Visibility,
    initialise_unpacked,
    compact_categories,
    extract_categories
)


def sensitivity_score(s: Sensitivity) -> int:
    return s.value


def visibility_score(v: Visibility) -> int:
    if v == Visibility.PU:
        return 0
    return v.value


def is_restricted_or_private(v: Visibility) -> bool:
    return visibility_score(v) >= visibility_score(Visibility.P2)


def is_group_or_personal_private(v: Visibility) -> bool:
    return visibility_score(v) >= visibility_score(Visibility.P3)


def strongest_sensitivity(sensitivities: Iterable[Sensitivity]) -> Sensitivity:
    return max(sensitivities, key=sensitivity_score, default=Sensitivity.S0)


def strongest_visibility(visibilities: Iterable[Visibility]) -> Visibility:
    return max(visibilities, key=visibility_score, default=Visibility.PU)


def dedupe_categories(categories: Iterable[Category]) -> List[Category]:
    return extract_categories(compact_categories(categories)) # pack and unpack them linear time


def merge_classifications(classifications: Iterable[Classification]) -> Classification:
    classifications = list(classifications)
    if not classifications:
        return initialise_unpacked(Sensitivity.S0, Visibility.PU, [])

    return initialise_unpacked(
        strongest_sensitivity(item.sensitivity() for item in classifications),
        strongest_visibility(item.visibility() for item in classifications),
        dedupe_categories(
            category
            for item in classifications
            for category in item.categories()
        ),
    )


def describe_categories(categories: Iterable[Category]) -> str:
    category_names = [category.name for category in categories]
    return ", ".join(category_names) if category_names else "NORMAL"


def action_for_classification_result(result: Any) -> PriVokeAction:
    """
    Map a ClassificationResult to the enforcement action it encourages.

    Current policy preserves the previous classification mapping:
    - S3 content blocks.
    - S2 content warns.
    - Identifier/location categories become warning-level when combined with
      restricted/private visibility or with each other, matching old quasi-PII
      handling.
    - Context-only S0/S1 content stays allowed.

    Result-level context is intentionally part of the boundary. Today it only
    moderates very low-confidence S3/S2 results; source, span, and metadata can
    be used for more specific detector policies without changing callers again.
    """
    classification = result.classification
    confidence = _result_confidence(result)

    if _is_low_confidence(confidence):
        return _low_confidence_result_action(classification)

    return _baseline_action(
        classification.sensitivity(),
        classification.visibility(),
        classification.categories(),
    )


def _baseline_action(
    sensitivity: Sensitivity,
    visibility: Visibility,
    result_categories: Iterable[Category],
) -> PriVokeAction:
    categories = set(result_categories)
    if sensitivity == Sensitivity.S0 and not categories:
        return PriVokeAction.ALLOW

    identifier_categories = {
        Category.IDENTITY,
        Category.LOCATION,
    }

    has_identifier = bool(categories & identifier_categories)

    if sensitivity == Sensitivity.S3:
        return PriVokeAction.BLOCK

    if sensitivity == Sensitivity.S2:
        return PriVokeAction.WARN

    if (
        has_identifier
        and (
            len(categories & identifier_categories) > 1
            or is_restricted_or_private(visibility)
        )
    ):
        return PriVokeAction.WARN

    return PriVokeAction.ALLOW


def _low_confidence_result_action(
    classification: Classification,
) -> PriVokeAction:
    if classification.sensitivity() == Sensitivity.S3:
        return PriVokeAction.WARN
    if classification.sensitivity() == Sensitivity.S2:
        categories = set(classification.categories())
        if categories & {Category.IDENTITY, Category.LOCATION}:
            return PriVokeAction.WARN
    return PriVokeAction.ALLOW


def _result_confidence(result: Any) -> float | None:
    confidence = getattr(result, "confidence", None)
    if isinstance(confidence, (int, float)):
        return float(confidence)
    return None


def _is_low_confidence(confidence: float | None) -> bool:
    return confidence is not None and confidence < 0.5
