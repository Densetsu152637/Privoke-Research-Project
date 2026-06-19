from __future__ import annotations

from typing import Any, Iterable, List, Mapping, Sequence

from client_runtime_imports import import_client_module


PACKED_CLASSIFICATION_KEYS = (
    "packed_classification",
    "expected_packed_classification",
    "classification_packed",
    "packed",
)


def classification_module():
    return import_client_module("classification")


def semantic_features_module():
    return import_client_module("LLM.privoke.semantic_features")


def classification_from_packed(packed: Any):
    classification = classification_module()
    return classification.initialise_packed(int(packed))


def classification_from_components(
    sensitivity: Any,
    visibility: Any,
    categories: Iterable[Any] = (),
):
    classification = classification_module()
    return classification.initialise_unpacked(
        enum_value(classification.Sensitivity, sensitivity, classification.Sensitivity.S0),
        enum_value(classification.Visibility, visibility, classification.Visibility.PU),
        [
            category
            for category in (
                enum_value(classification.Category, item, None)
                for item in categories
            )
            if category is not None
        ],
    )


def classification_from_mapping(item: Mapping[str, Any]) -> Any | None:
    packed = packed_classification_value(item)
    if packed is not None:
        return classification_from_packed(packed)

    payload = nested_classification_payload(item)
    packed = packed_classification_value(payload)
    if packed is not None:
        return classification_from_packed(packed)

    sensitivity = first_present(
        item,
        payload,
        "sensitivity",
        "expected_sensitivity",
    )
    visibility = first_present(
        item,
        payload,
        "visibility",
        "expected_visibility",
    )
    categories = first_present(
        item,
        payload,
        "categories",
        "expected_categories",
    )

    if sensitivity is None and visibility is None and categories is None:
        return None

    return classification_from_components(
        sensitivity or "S0",
        visibility or "PU",
        category_values(categories),
    )


def semantic_target_classification(text: str):
    classification = classification_module()
    semantic_features = semantic_features_module()
    signals = semantic_features.extract_semantic_signals(text)

    categories = dedupe_categories(
        signal.category for signal in signals if signal.category is not None
    )
    sensitivity = semantic_features.strongest_sensitivity(signals)
    visibility = semantic_features.strongest_visibility(signals)

    if not categories and visibility == classification.Visibility.PU:
        sensitivity = classification.Sensitivity.S0

    return classification.initialise_unpacked(sensitivity, visibility, categories)


def empty_classification():
    classification = classification_module()
    return classification.initialise_unpacked(
        classification.Sensitivity.S0,
        classification.Visibility.PU,
        [],
    )


def merge_classifications(classifications: Iterable[Any]):
    classification = classification_module()
    return classification.merge_classifications(classifications)


def dedupe_categories(categories: Iterable[Any]) -> List[Any]:
    classification = classification_module()
    category_set = set(categories)
    return [category for category in classification.Category if category in category_set]


def enum_value(enum_type: Any, value: Any, default: Any):
    if value is None:
        return default
    if isinstance(value, enum_type):
        return value

    key = str(value).strip().upper()
    return enum_type.__members__.get(key, default)


def category_values(value: Any) -> Sequence[Any]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip().upper() for part in value.split(",") if part.strip())
    if isinstance(value, Sequence):
        return tuple(value)
    return ()


def packed_classification_value(item: Mapping[str, Any]) -> Any | None:
    for key in PACKED_CLASSIFICATION_KEYS:
        value = item.get(key)
        if value is not None:
            return value
    for key in ("classification", "expected_classification", "target"):
        value = item.get(key)
        if isinstance(value, int):
            return value
    return None


def nested_classification_payload(item: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("classification", "expected_classification", "target"):
        payload = item.get(key)
        if isinstance(payload, Mapping):
            return payload
    return {}


def first_present(
    item: Mapping[str, Any],
    payload: Mapping[str, Any],
    *keys: str,
) -> Any | None:
    for key in keys:
        if key in item:
            return item[key]
        if key in payload:
            return payload[key]
    return None
