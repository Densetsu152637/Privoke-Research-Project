from dataclasses import dataclass
from typing import Dict

from src import (
    Category,
    Classification,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)


@dataclass(frozen=True)
class EntityUseCase:
    """How a backend NER label maps into PriVoke classification."""

    entity_type: str
    classification: Classification
    confidence: float


NER_LABEL_USE_CASES: Dict[str, EntityUseCase] = {
    "PERSON": EntityUseCase(
        entity_type="name",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.IDENTITY],
        ),
        confidence=0.85,
    ),
    "GPE": EntityUseCase(
        entity_type="location",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
        ),
        confidence=0.85,
    ),
    "LOC": EntityUseCase(
        entity_type="location",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
        ),
        confidence=0.85,
    ),
    "FAC": EntityUseCase(
        entity_type="location",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
        ),
        confidence=0.80,
    ),
    "ORG": EntityUseCase(
        entity_type="organization",
        classification=initialise_unpacked(
            Sensitivity.S1,
            Visibility.PU,
            [Category.IDENTITY],
        ),
        confidence=0.75,
    ),
}
