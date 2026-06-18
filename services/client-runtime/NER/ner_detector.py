"""
NER detector for PriVoke.

This layer only consumes the configured NER backend. Deterministic patterns
such as emails, phones, cards, SSNs, URLs, and handles belong in the regex rule
pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

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

    bucket: str
    signal: str
    classification: Classification
    confidence: float


NER_LABEL_USE_CASES: Dict[str, EntityUseCase] = {
    "PERSON": EntityUseCase(
        bucket="names",
        signal="name",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.IDENTITY],
        ),
        confidence=0.85,
    ),
    "GPE": EntityUseCase(
        bucket="locations",
        signal="location",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
        ),
        confidence=0.85,
    ),
    "LOC": EntityUseCase(
        bucket="locations",
        signal="location",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
        ),
        confidence=0.85,
    ),
    "FAC": EntityUseCase(
        bucket="locations",
        signal="location",
        classification=initialise_unpacked(
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
        ),
        confidence=0.80,
    ),
    "ORG": EntityUseCase(
        bucket="organizations",
        signal="organization",
        classification=initialise_unpacked(
            Sensitivity.S1,
            Visibility.PU,
            [Category.IDENTITY],
        ),
        confidence=0.75,
    ),
}


EMPTY_ENTITY_BUCKETS = (
    "emails",
    "phones",
    "names",
    "locations",
    "usernames",
    "credit_cards",
    "ssns",
    "urls",
    "organizations",
)


class EntityNERDetector:
    """
    Entity extraction backed by spaCy NER labels.

    Regex-compatible buckets remain in the return shape for pipeline
    compatibility, but this detector does not populate them from patterns.
    """

    def __init__(self, model_name: str = "en_core_web_sm"):
        try:
            import spacy

            self.nlp = spacy.load(model_name)
            self.backend_available = True
            self.spacy_available = True
            self.backend_name = "spacy"
            self.model_name = model_name

        except Exception as exc:
            print(f"spaCy NER model not available: {exc}. NER layer disabled.")
            self.nlp = None
            self.backend_available = False
            self.spacy_available = False
            self.backend_name = "spacy"
            self.model_name = model_name

    def extract_entities(self, text: str) -> Dict:
        """
        Extract NER-backed entities and return classification-backed evidence.
        """
        entities = self._empty_result()

        if not self.backend_available:
            self._finalize_result(entities, [])
            return entities

        doc = self.nlp(text)
        entity_classifications: List[Classification] = []
        raw_entities: Dict[str, List[Dict]] = {}
        seen_spans = set()

        for ent in doc.ents:
            raw_entity = {
                "text": ent.text,
                "span": (ent.start_char, ent.end_char),
                "label": ent.label_,
            }
            raw_entities.setdefault(ent.label_, []).append(raw_entity)

            use_case = NER_LABEL_USE_CASES.get(ent.label_)
            if use_case is None:
                continue

            span_key = (use_case.bucket, ent.start_char, ent.end_char, ent.text)
            if span_key in seen_spans:
                continue
            seen_spans.add(span_key)

            entity_record = self._entity_record(ent, use_case)
            entities[use_case.bucket].append(entity_record)
            entity_classifications.append(use_case.classification)

        entities["raw_entities"] = raw_entities
        self._finalize_result(entities, entity_classifications)
        return entities

    def get_entity_risk_signals(self, entities: Dict) -> Dict:
        """
        Return compatibility risk signals derived from the NER classification.
        """
        summary = entities.get("entity_summary", {})
        classification = entities.get("classification")
        if not isinstance(classification, Classification):
            classification = initialise_unpacked(Sensitivity.S0, Visibility.PU, [])

        flags = {
            "email": bool(summary.get("has_email")),
            "phone": bool(summary.get("has_phone")),
            "name": bool(summary.get("has_name")),
            "location": bool(summary.get("has_location")),
            "username": bool(summary.get("has_username")),
            "credential": bool(
                summary.get("has_credit_card") or summary.get("has_ssn")
            ),
            "organization": bool(summary.get("has_organization")),
        }

        return {
            "entity_flags": flags,
            "high_risk_combinations": self._high_risk_combinations(flags),
            "strongest_entity": self._strongest_entity(summary),
            "entity_count": summary.get("total_entities", 0),
            "classification": classification,
            "packed_classification": classification.pack(),
            "risk_vector": risk_vector_for_classification(classification),
        }

    def _empty_result(self) -> Dict:
        classification = initialise_unpacked(Sensitivity.S0, Visibility.PU, [])
        result = {bucket: [] for bucket in EMPTY_ENTITY_BUCKETS}
        result.update(
            {
                "raw_entities": {},
                "entity_summary": {},
                "classification": classification,
                "packed_classification": classification.pack(),
                "signals": [],
                "backend": {
                    "name": self.backend_name,
                    "model": self.model_name,
                    "available": self.backend_available,
                },
            }
        )
        return result

    def _entity_record(self, ent, use_case: EntityUseCase) -> Dict:
        classification = use_case.classification
        return {
            "text": ent.text,
            "span": (ent.start_char, ent.end_char),
            "confidence": use_case.confidence,
            "source": self.backend_name,
            "label": ent.label_,
            "entity_type": use_case.signal,
            "classification": classification,
            "packed_classification": classification.pack(),
            "categories": [category.name for category in classification.categories()],
        }

    def _finalize_result(
        self,
        entities: Dict,
        classifications: Iterable[Classification],
    ) -> None:
        classification = merge_classifications(classifications)
        entities["classification"] = classification
        entities["packed_classification"] = classification.pack()
        entities["signals"] = self._signals(entities)
        entities["entity_summary"] = {
            "has_email": bool(entities["emails"]),
            "has_phone": bool(entities["phones"]),
            "has_name": bool(entities["names"]),
            "has_location": bool(entities["locations"]),
            "has_username": bool(entities["usernames"]),
            "has_credit_card": bool(entities["credit_cards"]),
            "has_ssn": bool(entities["ssns"]),
            "has_url": bool(entities["urls"]),
            "has_organization": bool(entities["organizations"]),
            "total_entities": sum(
                len(entities[bucket]) for bucket in EMPTY_ENTITY_BUCKETS
            ),
        }
        entities["total_entities"] = entities["entity_summary"]["total_entities"]

    def _signals(self, entities: Dict) -> List[str]:
        signals = []
        for bucket in ("names", "locations", "organizations"):
            for entity in entities[bucket]:
                signals.append(entity["entity_type"])
        return list(dict.fromkeys(signals))

    def _high_risk_combinations(self, flags: Dict[str, bool]) -> List[str]:
        combinations = []
        if flags["name"] and flags["location"]:
            combinations.append("name_location")
        if flags["name"] and flags["organization"]:
            combinations.append("name_organization")
        if flags["location"] and flags["organization"]:
            combinations.append("location_organization")
        return combinations

    def _strongest_entity(self, summary: Dict) -> str | None:
        priority = [
            ("name", "has_name"),
            ("location", "has_location"),
            ("organization", "has_organization"),
        ]
        for entity_type, flag in priority:
            if summary.get(flag):
                return entity_type
        return None


def initialize_ner_detector() -> EntityNERDetector:
    """Factory function for the NER detector."""
    return EntityNERDetector()
