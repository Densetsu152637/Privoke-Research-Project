
from enum import Enum
from typing import Iterable, List

class DefEnum(Enum):

    def __str__(self):
        return f"{self.name}"

    def __repr__(self):
        return f"{self.__class__}.{self.name}"

class Sensitivity(DefEnum):

    S0 = 0b00 # None / Benign
    S1 = 0b01 # Low: mild personal opinions, non-identifying
    S2 = 0b10 # Medium: personal information that could cause targeting / harm
    S3 = 0b11 # High: explicit sensitive categories + identifiable details

class Visibility(DefEnum):

    P0 = 0b00100 # Public: visible to anyone
    P1 = 0b01000 # Semi-public: public but context limited (community page / thread)
    P2 = 0b01100 # Restricted: behind authentication
    P3 = 0b10000 # Group-Private: shared dms / group chats
    P4 = 0b10100 # Personal Private: not shared with anyone
    PU = 0b11100 # Unknown: cannot verify from stored metadata

class Category(DefEnum):

    # PDPA-sensitive
    HEALTH      = 0b000000000100000 # physical / mental condition
    POLITICS    = 0b000000001000000
    RELIGION    = 0b000000010000000
    CRIMINAL    = 0b000000100000000
    # Harm-sensitive
    FINANCIAL   = 0b000001000000000 # bank acct, debts, salary, scams
    SEXUAL      = 0b000010000000000
    CHILD       = 0b000100000000000
    LOCATION    = 0b001000000000000 # exact address, “alone tonight”, routes
    IDENTITY    = 0b010000000000000 # passport, ID numbers, phone, email
    THIRD_PARTY = 0b100000000000000 # talking about someone else’s sensitive info

class RiskVector(DefEnum):

    NORMAL = 0
    CONTEXTUAL = 1
    AUTH = 2
    QUASI_PII = 3
    DIRECT_PII = 4
    UNKNOWN = 5

class Classification:

    n: int

    def __init__(self, packed: int | None = None):
        if packed is None:
            packed = compact_sensitivity(Sensitivity.S0) | compact_visibility(Visibility.PU)

        self.n = packed & n_mask

    def sensitivity(self) -> Sensitivity:
        return extract_sensitivity(self.n)

    def visibility(self) -> Visibility:
        return extract_visibility(self.n)

    def categories(self) -> List[Category]:
        return extract_categories(self.n)

    def pack(self) -> int:
        """
        fits a classification containing a sensitivity, visibility and category into 16 bits!
        :return:
        """
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

s_mask = 0b00011 # Extract sensitivity using mask (lowest 2 bits)
v_mask = 0b11100 # Extract visibility using mask  (3-5 bits)
c_mask = 0x7FE0  # Extract category using mask    (bits 5-14)
n_mask = 0xFFFF  # 16 bit mask

def compact_sensitivity(s: Sensitivity) -> int:
    return s.value

def compact_visibility(v: Visibility) -> int:
    return v.value

def compact_category(c: Category) -> int:
    return c.value

def compact_categories(c: List[Category]) -> int:
    compacted = 0
    for category in c:
        compacted |= category.value
    return compacted

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
    """
    Derive the operational risk vector from the packed classification dimensions.

    RiskVector is not another input dimension. It is the result of joining:
    sensitivity x visibility x categories.
    """
    categories = set(classification.categories())
    sensitivity = classification.sensitivity()
    visibility = classification.visibility()

    if sensitivity == Sensitivity.S0 and not categories:
        return RiskVector.NORMAL

    identifier_categories = {
        Category.IDENTITY,
        Category.LOCATION
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

def extract_sensitivity(n: int) -> Sensitivity:
    global s_mask
    return Sensitivity(n & s_mask)

def extract_visibility(n: int) -> Visibility:
    global v_mask
    return Visibility(n & v_mask)

def extract_categories(n: int) -> List[Category]:
    global c_mask
    unmasked = n & c_mask
    return [cat for cat in Category if (unmasked & cat.value)]

def initialise_packed(n: int) -> Classification:
    global n_mask
    return Classification(n & n_mask)

def initialise_unpacked(s: Sensitivity, v: Visibility, c: List[Category]) -> Classification:
    return Classification(compact_sensitivity(s) | compact_visibility(v) | compact_categories(c))


class ClassificationResult:

    classification: Classification
    risk_vector: RiskVector
    reasoning: str

    def __init__(self, classification: Classification, risk_vector: RiskVector, reasoning: str):
        self.classification = classification
        self.risk_vector = risk_vector
        self.reasoning = reasoning
