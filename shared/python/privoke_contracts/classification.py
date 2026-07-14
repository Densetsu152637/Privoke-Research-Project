from __future__ import annotations

from enum import Enum
from typing import Iterable


class DefEnum(Enum):
    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}.{self.name}"


class Sensitivity(DefEnum):
    S0 = 0b00
    S1 = 0b01
    S2 = 0b10
    S3 = 0b11


class Visibility(DefEnum):
    P0 = 0b00100
    P1 = 0b01000
    P2 = 0b01100
    P3 = 0b10000
    P4 = 0b10100
    PU = 0b11100


class Category(DefEnum):
    HEALTH = 0b000000000100000
    POLITICS = 0b000000001000000
    RELIGION = 0b000000010000000
    CRIMINAL = 0b000000100000000
    FINANCIAL = 0b000001000000000
    SEXUAL = 0b000010000000000
    CHILD = 0b000100000000000
    LOCATION = 0b001000000000000
    IDENTITY = 0b010000000000000
    THIRD_PARTY = 0b100000000000000


class PriVokeAction(DefEnum):
    ALLOW = 0
    WARN = 1
    BLOCK = 2


SENSITIVITY_MASK = 0b00011
VISIBILITY_MASK = 0b11100
CATEGORY_MASK = 0x7FE0
CLASSIFICATION_MASK = 0xFFFF


class Classification:
    def __init__(self, packed: int | None = None):
        self.n = int(
            Visibility.PU.value if packed is None else packed
        ) & CLASSIFICATION_MASK

    def sensitivity(self) -> Sensitivity:
        return extract_sensitivity(self.n)

    def visibility(self) -> Visibility:
        return extract_visibility(self.n)

    def categories(self) -> list[Category]:
        return extract_categories(self.n)

    def pack(self) -> int:
        return self.n

    def is_sensitive(self) -> bool:
        return self.sensitivity() != Sensitivity.S0 or bool(
            self.n & CATEGORY_MASK
        )

    def has_category(self, category: Category) -> bool:
        return bool(self.n & category.value)

    def has_any_category(self, categories: Iterable[Category]) -> bool:
        return any(self.has_category(category) for category in categories)

    def to_dict(self) -> dict[str, object]:
        return {
            "sensitivity": self.sensitivity().name,
            "visibility": self.visibility().name,
            "categories": [category.name for category in self.categories()],
        }


def compact_sensitivity(value: Sensitivity) -> int:
    return value.value


def compact_visibility(value: Visibility) -> int:
    return value.value


def compact_category(value: Category) -> int:
    return value.value


def compact_categories(values: Iterable[Category]) -> int:
    compacted = 0
    for category in values:
        compacted |= category.value
    return compacted


def extract_sensitivity(packed: int) -> Sensitivity:
    return Sensitivity(packed & SENSITIVITY_MASK)


def extract_visibility(packed: int) -> Visibility:
    return Visibility(packed & VISIBILITY_MASK)


def extract_categories(packed: int) -> list[Category]:
    unmasked = packed & CATEGORY_MASK
    return [category for category in Category if unmasked & category.value]


def initialise_packed(packed: int) -> Classification:
    return Classification(packed)


def initialise_unpacked(
    sensitivity: Sensitivity,
    visibility: Visibility,
    categories: Iterable[Category],
) -> Classification:
    return Classification(
        compact_sensitivity(sensitivity)
        | compact_visibility(visibility)
        | compact_categories(categories)
    )


def visibility_rank(value: Visibility) -> int:
    return 0 if value == Visibility.PU else value.value


def strongest_sensitivity(values: Iterable[Sensitivity]) -> Sensitivity:
    return max(values, key=lambda value: value.value, default=Sensitivity.S0)


def strongest_visibility(values: Iterable[Visibility]) -> Visibility:
    return max(values, key=visibility_rank, default=Visibility.PU)


def dedupe_categories(values: Iterable[Category]) -> list[Category]:
    categories = set(values)
    return [category for category in Category if category in categories]


def merge_classifications(values: Iterable[Classification]) -> Classification:
    classifications = list(values)
    if not classifications:
        return Classification()
    sensitivity = strongest_sensitivity(
        value.sensitivity() for value in classifications
    )
    visibility = strongest_visibility(
        value.visibility() for value in classifications
    )
    categories = dedupe_categories(
        category
        for value in classifications
        for category in value.categories()
    )
    return initialise_unpacked(sensitivity, visibility, categories)
