from __future__ import annotations

from privoke_contracts.classification import (
    Category,
    Classification,
    Visibility,
    visibility_rank,
)


def classification_loss(target: Classification, predicted: Classification) -> float:
    target_categories = set(target.categories())
    predicted_categories = set(predicted.categories())

    sensitivity_loss = (
        abs(target.sensitivity().value - predicted.sensitivity().value) / 3.0
    )
    visibility_loss = (
        abs(
            visibility_rank(target.visibility())
            - visibility_rank(predicted.visibility())
        )
        / visibility_rank(Visibility.P4)
    )
    category_loss = len(target_categories ^ predicted_categories) / max(
        1,
        len(list(Category)),
    )
    return sensitivity_loss + 0.5 * visibility_loss + 0.25 * category_loss
