"""
GLiNER NER backend (default off; ``PRIVOKE_NER_BACKEND=gliner``).

An evaluation candidate for the NER layer, not a shipped default. A zero-shot
GLiNER checkpoint returns character spans for the label strings it is asked
about. This module

* asks for a fixed, pre-registered label set (``core``: names, places and
  organisations; ``pii``: ``core`` plus non-name personal identifiers),
* maps ``core`` labels onto the spaCy label scheme (``PERSON``, ``GPE``, ``FAC``,
  ``ORG``) so they share ``NER_LABEL_USE_CASES`` and the NER post-filter,
* maps the extra ``pii`` labels onto fixed ``EntityUseCase`` rows below, which are
  emitted directly (the post-filter's rules are linguistic rules about names,
  places and organisations and do not apply to identifiers).

The post-filter needs a spaCy ``Doc`` (dependency and POS information). When it
is enabled the text is parsed with the configured spaCy model (``PRIVOKE_NER_MODEL``,
default ``en_core_web_sm``) with its own ``ner`` component disabled, and the GLiNER
spans are attached with ``Doc.char_span(..., alignment_mode="expand")``. When it
is disabled no spaCy model is loaded. Structured identifiers remain owned by the
regex layer; the ``pii`` preset overlaps it on purpose so the two can be compared.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Tuple

from .ner_detector import EntityNERDetector, _pipeline_entry
from .use_cases import EntityUseCase
from ..classification import (
    Category,
    ClassificationResult,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)
from ..config import GLOBAL_CONFIG

# GLiNER label string -> spaCy-scheme label (shares NER_LABEL_USE_CASES and the post-filter).
CORE_LABELS: Dict[str, str] = {
    "name": "PERSON",
    "location city": "GPE",
    "location state": "GPE",
    "location country": "GPE",
    "location street": "FAC",
    "location address": "FAC",
    "organization": "ORG",
}


def _use_case(entity_type: str, sensitivity: Sensitivity, category: Category, confidence: float) -> EntityUseCase:
    return EntityUseCase(
        entity_type=entity_type,
        classification=initialise_unpacked(sensitivity, Visibility.PU, [category]),
        confidence=confidence,
    )


# Extra identifier labels of the ``pii`` preset. Sensitivities follow the regex layer's
# conventions for the same kinds of values (government/financial/secret S3, contact S2).
PII_EXTRA_USE_CASES: Dict[str, EntityUseCase] = {
    "phone number": _use_case("phone", Sensitivity.S2, Category.IDENTITY, 0.8),
    "email address": _use_case("email", Sensitivity.S2, Category.IDENTITY, 0.8),
    "ip address": _use_case("ip_address", Sensitivity.S2, Category.IDENTITY, 0.8),
    "username": _use_case("username", Sensitivity.S2, Category.IDENTITY, 0.75),
    "dob": _use_case("date_of_birth", Sensitivity.S2, Category.IDENTITY, 0.8),
    "ssn": _use_case("government_id", Sensitivity.S3, Category.IDENTITY, 0.8),
    "passport number": _use_case("government_id", Sensitivity.S3, Category.IDENTITY, 0.8),
    "driver license": _use_case("government_id", Sensitivity.S3, Category.IDENTITY, 0.8),
    "password": _use_case("secret", Sensitivity.S3, Category.IDENTITY, 0.8),
    "credit card": _use_case("payment_card", Sensitivity.S3, Category.FINANCIAL, 0.8),
    "account number": _use_case("financial_account", Sensitivity.S3, Category.FINANCIAL, 0.8),
    "medical condition": _use_case("health_condition", Sensitivity.S3, Category.HEALTH, 0.75),
}

LABEL_PRESETS: Dict[str, Tuple[str, ...]] = {
    "core": tuple(CORE_LABELS),
    "pii": tuple(CORE_LABELS) + tuple(PII_EXTRA_USE_CASES),
}

# GLiNER truncates long inputs; texts are scored in windows of at most this many
# whitespace-separated words (the checkpoint's whitespace word splitter).
MAX_WINDOW_WORDS = 300

_GLINER_CACHE_LOCK = threading.RLock()
_GLINER_MODELS: "OrderedDict[str, _GlinerEntry]" = OrderedDict()
_MAX_CACHED_GLINER = 1


@dataclass
class _GlinerEntry:
    model: object
    inference_lock: threading.Lock


@dataclass(frozen=True)
class RawSpan:
    """A GLiNER span with the attribute names the post-filter and results use."""

    text: str
    label_: str
    start_char: int
    end_char: int
    score: float
    source_label: str


def _load_gliner(model_ref: str) -> _GlinerEntry:
    with _GLINER_CACHE_LOCK:
        cached = _GLINER_MODELS.get(model_ref)
        if cached is not None:
            _GLINER_MODELS.move_to_end(model_ref)
            return cached
        from gliner import GLiNER  # optional dependency, imported on first use

        # A local directory is loaded without network access. pytorch_model.bin
        # checkpoints are read by GLiNER with ``torch.load(weights_only=True)``.
        local = os.path.isdir(model_ref)
        model = GLiNER.from_pretrained(model_ref, local_files_only=local)
        entry = _GlinerEntry(model, threading.Lock())
        _GLINER_MODELS[model_ref] = entry
        _GLINER_MODELS.move_to_end(model_ref)
        while len(_GLINER_MODELS) > _MAX_CACHED_GLINER:
            _GLINER_MODELS.popitem(last=False)
        return entry


def word_windows(text: str, max_words: int = MAX_WINDOW_WORDS) -> Iterator[Tuple[int, str]]:
    """Yield ``(offset, window)`` pieces of at most ``max_words`` words that cover ``text``."""
    count = 0
    start = 0
    in_word = False
    for index, char in enumerate(text):
        if char.isspace():
            in_word = False
            continue
        if not in_word:
            in_word = True
            count += 1
            if count > max_words:
                yield start, text[start:index]
                start, count = index, 1
    if text[start:].strip():
        yield start, text[start:]


class GlinerEntityDetector(EntityNERDetector):
    """GLiNER-backed entity extraction with the same output contract as the spaCy detector."""

    reasoning_source = "GLiNER"

    def __init__(
        self,
        model_ref: str | None = None,
        *,
        threshold: float | None = None,
        label_preset: str | None = None,
    ):
        self.backend_name = "gliner"
        self.model_name = model_ref or GLOBAL_CONFIG.ner_gliner_model
        self.threshold = GLOBAL_CONFIG.ner_gliner_threshold if threshold is None else threshold
        preset = label_preset or GLOBAL_CONFIG.ner_gliner_labels
        if preset not in LABEL_PRESETS:
            raise ValueError(f"Unknown GLiNER label preset {preset!r}; expected one of {sorted(LABEL_PRESETS)}")
        self.label_preset = preset
        self.labels = list(LABEL_PRESETS[preset])
        self._gliner = _load_gliner(self.model_name)
        self.nlp = None
        self._syntax_entry = None
        self._syntax_lock = threading.Lock()

    # ------------------------------------------------------------------ model calls

    def predict_raw(self, text: str) -> List[RawSpan]:
        """GLiNER spans at ``self.threshold`` over the preset label set (absolute offsets)."""
        spans: List[RawSpan] = []
        with self._gliner.inference_lock:
            for offset, window in word_windows(text):
                for found in self._gliner.model.predict_entities(window, self.labels, threshold=self.threshold):
                    if found["score"] < self.threshold or found["label"] not in LABEL_PRESETS[self.label_preset]:
                        continue
                    target = CORE_LABELS.get(found["label"])
                    spans.append(RawSpan(
                        text=window[found["start"]:found["end"]],
                        label_=target or found["label"],
                        start_char=offset + found["start"],
                        end_char=offset + found["end"],
                        score=float(found["score"]),
                        source_label=found["label"],
                    ))
        spans.sort(key=lambda s: (s.start_char, s.end_char))
        return spans

    def _syntax(self):
        """The spaCy pipeline used only to give the post-filter a Doc (loaded on first use)."""
        with self._syntax_lock:
            if self._syntax_entry is None:
                self._syntax_entry = _pipeline_entry(GLOBAL_CONFIG.ner_model)
                self.nlp = self._syntax_entry.nlp
            return self._syntax_entry

    # ------------------------------------------------------------------ detector contract

    def extract_entities(self, text: str) -> List[ClassificationResult]:
        spans = self.predict_raw(text)
        results: List[ClassificationResult] = []
        core = [s for s in spans if s.source_label in CORE_LABELS]
        extra = [s for s in spans if s.source_label in PII_EXTRA_USE_CASES]
        if core:
            if GLOBAL_CONFIG.ner_postfilter:
                results.extend(self._postfiltered_core(text, core))
            else:
                results.extend(self._classified_entities(core))
        results.extend(self._extra_entity(s) for s in extra)
        results.sort(key=lambda r: (r.span or (0, 0)))
        return results

    def _postfiltered_core(self, text: str, core: Iterable[RawSpan]) -> List[ClassificationResult]:
        entry = self._syntax()
        with entry.inference_lock:
            with entry.nlp.select_pipes(disable=[n for n in ("ner",) if n in entry.nlp.pipe_names]):
                doc = entry.nlp(text)
            attached = []
            seen = set()
            for raw in core:
                span = doc.char_span(raw.start_char, raw.end_char, label=raw.label_, alignment_mode="expand")
                if span is None:
                    continue
                key = (span.start_char, span.end_char, span.label_)
                if key not in seen:
                    seen.add(key)
                    attached.append(span)
            return self._postfiltered_entities(doc, attached)

    def _classified_entity(self, ent, use_case: EntityUseCase) -> ClassificationResult:
        result = super()._classified_entity(ent, use_case)
        result.metadata = {**result.metadata, "backend": self.backend_name}
        return result

    def _extra_entity(self, span: RawSpan) -> ClassificationResult:
        use_case = PII_EXTRA_USE_CASES[span.source_label]
        return ClassificationResult(
            classification=use_case.classification,
            section_of_text=span.text,
            reasoning=f"GLiNER labelled this span as {span.source_label}",
            span=(span.start_char, span.end_char),
            confidence=use_case.confidence,
            metadata={
                "label": span.source_label,
                "entity_type": use_case.entity_type,
                "model": self.model_name,
                "backend": self.backend_name,
                "score": round(span.score, 4),
            },
        )
