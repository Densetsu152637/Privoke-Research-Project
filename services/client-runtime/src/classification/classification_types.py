from enum import Enum
from typing import Iterable, List

from ..util import typeof

class DefEnum(Enum):
    def __str__(self):
        return f"{self.name}"

    def __repr__(self):
        return f"{typeof(self)}.{self.name}"

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

s_mask = 0b00011
v_mask = 0b11100
c_mask = 0x7FE0
n_mask = 0xFFFF

class Classification:
    n: int

    def __init__(self, packed: int | None = None):
        if packed is None:
            packed = compact_sensitivity(Sensitivity.S0) | compact_visibility(
                Visibility.PU
            )
        self.n = packed & n_mask

    def sensitivity(self) -> Sensitivity:
        return extract_sensitivity(self.n)

    def visibility(self) -> Visibility:
        return extract_visibility(self.n)

    def categories(self) -> List[Category]:
        return extract_categories(self.n)

    def pack(self) -> int:
        return self.n

    def is_sensitive(self) -> bool:
        return self.sensitivity() != Sensitivity.S0 or bool(self.n & c_mask)

    def has_category(self, category: Category) -> bool:
        return bool(self.n & category.value)

    def has_any_category(self, categories: Iterable[Category]) -> bool:
        return any(self.has_category(category) for category in categories)

    def to_dict(self) -> dict:
        return {
            "sensitivity": self.sensitivity().name,
            "visibility": self.visibility().name,
            "categories": [category.name for category in self.categories()],
        }

def compact_sensitivity(s: Sensitivity) -> int:
    return s.value

def compact_visibility(v: Visibility) -> int:
    return v.value

def compact_category(c: Category) -> int:
    return c.value

def compact_categories(c: Iterable[Category]) -> int:
    compacted = 0
    for category in c:
        compacted |= category.value
    return compacted

def extract_sensitivity(n: int) -> Sensitivity:
    return Sensitivity(n & s_mask)

def extract_visibility(n: int) -> Visibility:
    return Visibility(n & v_mask)

def extract_categories(n: int) -> List[Category]:
    unmasked = n & c_mask
    return [cat for cat in Category if (unmasked & cat.value)]

def initialise_packed(n: int) -> Classification:
    return Classification(n & n_mask)

def initialise_unpacked(
    s: Sensitivity,
    v: Visibility,
    c: List[Category],
) -> Classification:
    return Classification(
        compact_sensitivity(s) | compact_visibility(v) | compact_categories(c)
    )

class PriVokeAction(DefEnum):

    ALLOW = 0
    WARN = 1
    BLOCK = 2
