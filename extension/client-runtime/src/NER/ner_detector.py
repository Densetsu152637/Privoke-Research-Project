"""
NER detector for PriVoke.

This layer only consumes the configured NER backend. Deterministic patterns
such as emails, phones, cards, SSNs, URLs, and handles belong in the regex rule
pass.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import threading
from typing import Iterable, List

import spacy

from .use_cases import NER_LABEL_USE_CASES, EntityUseCase
from ..classification import ClassificationResult


_MAX_CACHED_PIPELINES = 2
_PIPELINE_CACHE_LOCK = threading.RLock()


@dataclass
class _PipelineEntry:
    nlp: object
    inference_lock: threading.Lock = field(default_factory=threading.Lock)


_PIPELINES: OrderedDict[str, _PipelineEntry] = OrderedDict()


def _pipeline_entry(model_name: str) -> _PipelineEntry:
    """Load each recent spaCy model once and serialize its shared inference."""
    with _PIPELINE_CACHE_LOCK:
        cached = _PIPELINES.get(model_name)
        if cached is not None:
            _PIPELINES.move_to_end(model_name)
            return cached

        # Load under the cache lock so concurrent first users share exactly one
        # initialized model. Failed loads are not inserted and may be retried.
        loaded = spacy.load(model_name)
        entry = _PipelineEntry(loaded)
        _PIPELINES[model_name] = entry
        _PIPELINES.move_to_end(model_name)
        while len(_PIPELINES) > _MAX_CACHED_PIPELINES:
            _PIPELINES.popitem(last=False)
        return entry


class EntityNERDetector:
    """Entity extraction backed by spaCy NER labels."""

    def __init__(self, model_name: str = "en_core_web_sm"):
        self.backend_name = "spacy"
        self.model_name = model_name
        self._pipeline_entry = _pipeline_entry(model_name)
        # Retain the attribute for callers/tests that inspect or replace it.
        self.nlp = self._pipeline_entry.nlp

    def extract_entities(self, text: str) -> List[ClassificationResult]:
        """
        Extract NER-backed entities as classification-backed results.
        """
        # spaCy pipelines may retain mutable component state and Docs reference
        # pipeline-owned vocabulary. Keep both inference and conversion under
        # one model-specific lock; each Doc/results list stays request-local.
        with self._pipeline_entry.inference_lock:
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
