"""
NER detector for PriVoke.

This layer only consumes the configured NER backend. Deterministic patterns
such as emails, phones, cards, SSNs, URLs, and handles belong in the regex rule
pass.
"""

from __future__ import annotations

from typing import Iterable, List

import spacy

from .use_cases import NER_LABEL_USE_CASES, EntityUseCase
from ..classification import ClassificationResult

class EntityNERDetector:
    """Entity extraction backed by spaCy NER labels."""

    def __init__(self, model_name: str = "en_core_web_sm"):
        self.backend_name = "spacy"
        self.model_name = model_name
        self.nlp = spacy.load(model_name)

    def extract_entities(self, text: str) -> List[ClassificationResult]:
        """
        Extract NER-backed entities as classification-backed results.
        """
        doc = self.nlp(text)
        model_entities = list(doc.ents)
        return self._classified_entities(model_entities)

    def _classified_entities(self, ents: Iterable) -> List[ClassificationResult]:
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

    def _classified_entity(self, ent, use_case: EntityUseCase) -> ClassificationResult:
        return ClassificationResult(
            classification=use_case.classification,
            section_of_text=ent.text,
            reasoning=f"spaCy labelled this span as {ent.label_}",
            span=(ent.start_char, ent.end_char),
            confidence=use_case.confidence,
            metadata={
                "label": ent.label_,
                "entity_type": use_case.entity_type,
                "model": self.model_name,
            },
        )
