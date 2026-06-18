"""Compatibility exports for classification primitives and result types."""

from src.classification.classification_policy import (
    dedupe_categories,
    describe_categories,
    is_group_or_personal_private,
    is_restricted_or_private,
    merge_classifications,
    risk_vector_for_classification,
    sensitivity_score,
    strongest_sensitivity,
    strongest_visibility,
    visibility_score,
)

from src.classification.classification_results import (
    ClassificationResult,
    build_results,
    parse_result,
)

from src.classification.classification_types import (
    Category,
    Classification,
    DefEnum,
    RiskVector,
    Sensitivity,
    Visibility,
    compact_categories,
    compact_category,
    compact_sensitivity,
    compact_visibility,
    extract_categories,
    extract_sensitivity,
    extract_visibility,
    initialise_packed,
    initialise_unpacked,
)

__all__ = [
    "Category",
    "Classification",
    "ClassificationResult",
    "DefEnum",
    "RiskVector",
    "Sensitivity",
    "Visibility",
    "build_results",
    "compact_categories",
    "compact_category",
    "compact_sensitivity",
    "compact_visibility",
    "dedupe_categories",
    "describe_categories",
    "extract_categories",
    "extract_sensitivity",
    "extract_visibility",
    "initialise_packed",
    "initialise_unpacked",
    "is_group_or_personal_private",
    "is_restricted_or_private",
    "merge_classifications",
    "parse_result",
    "risk_vector_for_classification",
    "sensitivity_score",
    "strongest_sensitivity",
    "strongest_visibility",
    "visibility_score",
]
