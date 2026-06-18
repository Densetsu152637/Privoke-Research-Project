"""
NER detector for PriVoke.

This layer only consumes the configured NER backend. Deterministic patterns
such as emails, phones, cards, SSNs, URLs, and handles belong in the regex rule
pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

import spacy

from classification import (
    Category,
    Classification,
    RiskVector,
    Sensitivity,
    Visibility,
    initialise_unpacked,
    merge_classifications,
    risk_vector_for_classification,
)


@dataclass(frozen=True)
class EntityUseCase:
    """How a backend NER label maps into PriVoke classification."""

    signal: str
    classification: Classification
    confidence: float


NER_LABEL_USE_CASES: Dict[str, EntityUseCase] = {
    "PERSON": EntityUseCase(
        signal="name",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.IDENTITY],
        ),
        confidence=0.85,
    ),
    "GPE": EntityUseCase(
        signal="location",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
        ),
        confidence=0.85,
    ),
    "LOC": EntityUseCase(
        signal="location",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
        ),
        confidence=0.85,
    ),
    "FAC": EntityUseCase(
        signal="location",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
        ),
        confidence=0.80,
    ),
    "ORG": EntityUseCase(
        signal="organization",
        classification=initialise_unpacked(
            Sensitivity.S1,
            Visibility.PU,
            [Category.IDENTITY],
        ),
        confidence=0.75,
    ),
}


class EntityNERDetector:
    """Entity extraction backed by spaCy NER labels."""

    def __init__(self, model_name: str = "en_core_web_sm"):
        self.backend_name = "spacy"
        self.model_name = model_name
        self.nlp = spacy.load(model_name)

    def extract_entities(self, text: str) -> Dict:
        """
        Extract NER-backed entities as classification-backed evidence.
        """
        doc = self.nlp(text)
        model_entities = list(doc.ents)
        raw_entities = [self._raw_entity(ent) for ent in model_entities]
        classified_entities = self._classified_entities(model_entities)
        classification = merge_classifications(
            entity["classification"] for entity in classified_entities
        )
        risk_vector: RiskVector = risk_vector_for_classification(classification)

        return {
            "classification": classification,
            "packed_classification": classification.pack(),
            "risk_vector": risk_vector,
            "entities": classified_entities,
            "raw_entities": raw_entities,
            "signals": self._signals(classified_entities),
            "backend": {
                "name": self.backend_name,
                "model": self.model_name,
            },
        }

    def _classified_entities(self, ents: Iterable) -> List[Dict]:
        entities = []
        seen_spans = set()

        for ent in ents:
            use_case = NER_LABEL_USE_CASES.get(ent.label_)
            if use_case is None:
                continue

            span_key = (ent.start_char, ent.end_char, ent.label_, ent.text)
            if span_key in seen_spans:
                continue
            seen_spans.add(span_key)

            entities.append(self._classified_entity(ent, use_case))

        return entities

    def _classified_entity(self, ent, use_case: EntityUseCase) -> Dict:
        classification = use_case.classification
        risk_vector: RiskVector = risk_vector_for_classification(classification)

        return {
            "text": ent.text,
            "span": (ent.start_char, ent.end_char),
            "label": ent.label_,
            "signal": use_case.signal,
            "confidence": use_case.confidence,
            "source": self.backend_name,
            "classification": classification,
            "packed_classification": classification.pack(),
            "risk_vector": risk_vector,
            "categories": [category.name for category in classification.categories()],
        }

    def _raw_entity(self, ent) -> Dict:
        return {
            "text": ent.text,
            "span": (ent.start_char, ent.end_char),
            "label": ent.label_,
        }

    def _signals(self, entities: Iterable[Dict]) -> List[str]:
        return list(
            dict.fromkeys(entity["signal"] for entity in entities if entity.get("signal"))
        )


def initialize_ner_detector() -> EntityNERDetector:
    """Factory function for the NER detector."""
    return EntityNERDetector()
