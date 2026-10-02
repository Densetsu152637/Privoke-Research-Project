from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import TypeVar

from privoke_contracts.classification import (
    Category,
    Classification,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)

EnumValue = TypeVar("EnumValue")
JsonObject = Mapping[str, object]

PACKED_CLASSIFICATION_KEYS = (
    "packed_classification",
    "expected_packed_classification",
    "classification_packed",
    "packed",
)


def classification_from_packed(packed: int | str) -> Classification:
    return Classification(int(packed))


def classification_from_components(
    sensitivity: Sensitivity,
    visibility: Visibility,
    categories: Iterable[Category] = (),
) -> Classification:
    return initialise_unpacked(sensitivity, visibility, list(categories))


def classification_from_mapping(item: JsonObject) -> Classification | None:
    packed = packed_classification_value(item)
    if packed is not None:
        return classification_from_packed(packed)

    payload = nested_classification_payload(item)
    packed = packed_classification_value(payload)
    if packed is not None:
        return classification_from_packed(packed)

    sensitivity = enum_from_mapping(
        Sensitivity,
        item,
        payload,
        "sensitivity",
        "expected_sensitivity",
    )
    visibility = enum_from_mapping(
        Visibility,
        item,
        payload,
        "visibility",
        "expected_visibility",
    )
    categories = categories_from_value(
        first_present(
            item,
            payload,
            "categories",
            "expected_categories",
        )
    )

    if sensitivity is None and visibility is None and not categories:
        return None

    return initialise_unpacked(
        sensitivity or Sensitivity.S0,
        visibility or Visibility.PU,
        categories,
    )


def enum_from_mapping(
    enum_type: type[EnumValue],
    item: JsonObject,
    payload: JsonObject,
    *keys: str,
) -> EnumValue | None:
    return enum_value(enum_type, first_present(item, payload, *keys))


def enum_value(enum_type: type[EnumValue], value: object) -> EnumValue | None:
    if value is None:
        return None
    if isinstance(value, enum_type):
        return value

    key = str(value).strip().upper()
    return getattr(enum_type, "__members__", {}).get(key)


def categories_from_value(value: object) -> list[Category]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_values = [part.strip().upper() for part in value.split(",")]
    elif isinstance(value, Sequence):
        raw_values = list(value)
    else:
        return []

    return [
        category
        for category in (enum_value(Category, item) for item in raw_values)
        if category is not None
    ]


def packed_classification_value(item: JsonObject) -> int | str | None:
    for key in PACKED_CLASSIFICATION_KEYS:
        value = item.get(key)
        if value is not None:
            return value
    for key in ("classification", "expected_classification", "target"):
        value = item.get(key)
        if isinstance(value, int):
            return value
    return None


def nested_classification_payload(item: JsonObject) -> JsonObject:
    for key in ("classification", "expected_classification", "target"):
        payload = item.get(key)
        if isinstance(payload, Mapping):
            return payload
    return {}


def first_present(
    item: JsonObject,
    payload: JsonObject,
    *keys: str,
) -> object | None:
    for key in keys:
        if key in item:
            return item[key]
        if key in payload:
            return payload[key]
    return None
