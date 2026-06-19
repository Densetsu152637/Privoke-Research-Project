from __future__ import annotations

from typing import Dict, List

from privoke_client_runtime.LLM.privoke.streamed_model import (
    ParameterBackedPrivacyModel,
)
from privoke_client_runtime.LLM.privoke.semantic_features import (
    extract_semantic_signals,
    visibility_rank,
)
from privoke_client_runtime.classification import Category, Classification, Visibility

from .classifications import (
    empty_classification,
    merge_classifications,
)
from .types import ParameterDict


def predict_classification(
    model: ParameterBackedPrivacyModel,
    text: str,
) -> Classification:
    results = model.classify(text)
    if not results:
        return empty_classification()
    return merge_classifications(result.classification for result in results)


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


def accumulate_gradient(
    gradients: Dict[str, List[float]],
    parameters: ParameterDict,
    text: str,
    target: Classification,
    predicted: Classification,
    weight: float,
) -> None:
    categories = list(Category)
    text_categories = {
        signal.category
        for signal in extract_semantic_signals(text)
        if signal.category is not None
    }
    target_categories = set(target.categories())
    predicted_categories = set(predicted.categories())
    missed_categories = target_categories - predicted_categories
    extra_categories = predicted_categories - target_categories

    sensitivity_delta = (
        target.sensitivity().value - predicted.sensitivity().value
    ) / 3.0
    visibility_delta = (
        visibility_rank(target.visibility())
        - visibility_rank(predicted.visibility())
    ) / visibility_rank(Visibility.P4)

    for name, values in parameters.items():
        lower_name = name.lower()
        for index, _ in enumerate(values):
            if "bias" in lower_name or len(values) == 1:
                update_signal = sensitivity_delta * 0.8 + visibility_delta * 0.2
            else:
                category = categories[index % len(categories)]
                update_signal = sensitivity_delta * 0.20 + visibility_delta * 0.05
                if category in missed_categories:
                    update_signal += 1.0
                if category in extra_categories:
                    update_signal -= 0.7
                if category in target_categories:
                    update_signal += sensitivity_delta * 0.25
                if category in text_categories:
                    update_signal += sensitivity_delta * 0.15

            gradients[name][index] += update_signal * weight
