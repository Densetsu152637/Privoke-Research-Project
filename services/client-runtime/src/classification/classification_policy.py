from typing import Iterable, List

from src.classification.classification_types import (
    Category,
    Classification,
    PriVokeAction,
    Sensitivity,
    Visibility,
    initialise_unpacked,
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
    seen = set()
    deduped = []
    for category in categories:
        if category not in seen:
            seen.add(category)
            deduped.append(category)
    return deduped


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


def action_for_classification(classification: Classification) -> PriVokeAction:
    """
    Map a fused Classification directly to the enforcement action it encourages.

    Precedent from the previous enforcement policy:
    - S3 content blocks.
    - S2 content warns.
    - Identifier/location categories become warning-level when combined with
      restricted/private visibility or with each other, matching old quasi-PII
      handling.
    - Context-only S0/S1 content stays allowed.
    """
    categories = set(classification.categories())
    sensitivity = classification.sensitivity()
    visibility = classification.visibility()

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
