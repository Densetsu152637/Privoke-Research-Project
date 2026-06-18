from typing import Iterable, List

from src.classification.classification_types import (
    Category,
    Classification,
    RiskVector,
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


def risk_vector_for_classification(classification: Classification) -> RiskVector:
    categories = set(classification.categories())
    sensitivity = classification.sensitivity()
    visibility = classification.visibility()

    if sensitivity == Sensitivity.S0 and not categories:
        return RiskVector.NORMAL

    identifier_categories = {
        Category.IDENTITY,
        Category.LOCATION,
    }

    contextual_categories = {
        Category.HEALTH,
        Category.POLITICS,
        Category.RELIGION,
        Category.CRIMINAL,
        Category.FINANCIAL,
        Category.SEXUAL,
        Category.CHILD,
        Category.THIRD_PARTY,
    }

    has_identifier = bool(categories & identifier_categories)
    has_contextual = bool(categories & contextual_categories)

    if sensitivity == Sensitivity.S3 and (
        has_identifier or Category.FINANCIAL in categories
    ):
        return RiskVector.DIRECT_PII

    if (
        Category.IDENTITY in categories
        and visibility == Visibility.P2
        and sensitivity_score(sensitivity) >= sensitivity_score(Sensitivity.S2)
    ):
        return RiskVector.AUTH

    if (
        has_identifier
        and (
            len(categories & identifier_categories) > 1
            or is_restricted_or_private(visibility)
            or sensitivity_score(sensitivity) >= sensitivity_score(Sensitivity.S2)
        )
    ):
        return RiskVector.QUASI_PII

    if has_contextual or categories:
        return RiskVector.CONTEXTUAL

    return RiskVector.NORMAL
