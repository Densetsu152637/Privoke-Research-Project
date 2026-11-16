"""GLiNER NER backend: default-off flags, label mapping, thresholds, windows, post-filter.

Uses a stub GLiNER model (no weights, no ``gliner`` package needed); the post-filter
test needs a spaCy model and is skipped when none is installed.
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

import spacy  # noqa: F401  (pre-import in the main thread)

from src import NER
from src.NER import gliner_detector
from src.NER.gliner_detector import (
    CORE_LABELS,
    LABEL_PRESETS,
    PII_EXTRA_USE_CASES,
    GlinerEntityDetector,
    word_windows,
)
from src.NER.ner_detector import EntityNERDetector
from src.config import GLOBAL_CONFIG, GlobalConfig


class FakeGliner:
    """Returns canned spans for the first window of any text and records calls."""

    def __init__(self, spans):
        self.spans = spans
        self.calls = []

    def predict_entities(self, text, labels, threshold=0.5, **kwargs):
        self.calls.append((text, list(labels), threshold))
        return [dict(s) for s in self.spans if s["score"] >= threshold]


def _span(text, whole, label, score):
    start = whole.index(text)
    return {"text": text, "start": start, "end": start + len(text), "label": label, "score": score}


def _detector(spans, **kwargs):
    model = FakeGliner(spans)
    entry = gliner_detector._GlinerEntry(model, threading.Lock())
    with patch.object(gliner_detector, "_load_gliner", return_value=entry):
        detector = GlinerEntityDetector("stub-model", **kwargs)
    return detector, model


class ConfigDefaultsTests(unittest.TestCase):
    def test_backend_is_off_by_default(self):
        with patch.dict(os.environ, {}, clear=False):
            for name in ("PRIVOKE_NER_BACKEND", "PRIVOKE_NER_GLINER_MODEL",
                         "PRIVOKE_NER_GLINER_THRESHOLD", "PRIVOKE_NER_GLINER_LABELS"):
                os.environ.pop(name, None)
            config = GlobalConfig()
        self.assertEqual(config.ner_backend, "spacy")
        self.assertEqual(config.ner_gliner_threshold, 0.3)
        self.assertEqual(config.ner_gliner_labels, "core")
        self.assertEqual(config.ner_gliner_model, "knowledgator/gliner-pii-small-v1.0")

    def test_environment_selects_backend_options(self):
        env = {"PRIVOKE_NER_BACKEND": " GLiNER ", "PRIVOKE_NER_GLINER_THRESHOLD": "0.55",
               "PRIVOKE_NER_GLINER_LABELS": "PII", "PRIVOKE_NER_GLINER_MODEL": "C:/models/x"}
        with patch.dict(os.environ, env):
            config = GlobalConfig()
        self.assertEqual(config.ner_backend, "gliner")
        self.assertEqual(config.ner_gliner_threshold, 0.55)
        self.assertEqual(config.ner_gliner_labels, "pii")
        self.assertEqual(config.ner_gliner_model, "C:/models/x")

    def test_factory_defaults_to_spacy_and_rejects_unknown_backend(self):
        with patch.object(GLOBAL_CONFIG, "ner_backend", "spacy"), \
                patch.object(NER.ner_detector.spacy, "load", return_value=object()):
            self.assertIs(type(NER.build_ner_detector()), EntityNERDetector)
        with patch.object(GLOBAL_CONFIG, "ner_backend", "bogus"):
            with self.assertRaises(ValueError):
                NER.build_ner_detector()

    def test_factory_builds_gliner_backend_when_selected(self):
        entry = gliner_detector._GlinerEntry(FakeGliner([]), threading.Lock())
        with patch.object(GLOBAL_CONFIG, "ner_backend", "gliner"), \
                patch.object(gliner_detector, "_load_gliner", return_value=entry):
            self.assertIsInstance(NER.build_ner_detector(), GlinerEntityDetector)


class LabelTableTests(unittest.TestCase):
    def test_presets_are_nested_and_known(self):
        self.assertEqual(set(LABEL_PRESETS["core"]), set(CORE_LABELS))
        self.assertEqual(set(LABEL_PRESETS["pii"]), set(CORE_LABELS) | set(PII_EXTRA_USE_CASES))
        self.assertFalse(set(CORE_LABELS) & set(PII_EXTRA_USE_CASES))

    def test_core_labels_map_to_spacy_scheme_use_cases(self):
        for target in CORE_LABELS.values():
            self.assertIn(target, NER.ner_detector.NER_LABEL_USE_CASES)

    def test_unknown_preset_is_rejected(self):
        with self.assertRaises(ValueError):
            _detector([], label_preset="everything")


class WordWindowTests(unittest.TestCase):
    def test_short_text_is_one_window(self):
        self.assertEqual(list(word_windows("one two three", 5)), [(0, "one two three")])

    def test_windows_cover_text_with_absolute_offsets(self):
        text = "a b c d e f g\nh i"
        windows = list(word_windows(text, 3))
        self.assertTrue(all(len(w.split()) <= 3 for _, w in windows))
        self.assertEqual("".join(w for _, w in windows), text)
        for offset, window in windows:
            self.assertEqual(text[offset:offset + len(window)], window)

    def test_blank_text_has_no_windows(self):
        self.assertEqual(list(word_windows("  \n ")), [])


class ExtractionTests(unittest.TestCase):
    text = "Contact Dana Whitfield in Lisbon on 555-0100 or at dana@example.test."

    def spans(self):
        return [
            _span("Dana Whitfield", self.text, "name", 0.9),
            _span("Lisbon", self.text, "location city", 0.6),
            _span("555-0100", self.text, "phone number", 0.4),
        ]

    def run_detector(self, preset, threshold=0.3, postfilter=False):
        detector, model = _detector(self.spans(), label_preset=preset, threshold=threshold)
        with patch.object(GLOBAL_CONFIG, "ner_postfilter", postfilter):
            return detector.extract_entities(self.text), model

    def test_core_preset_asks_only_core_labels_and_drops_extra_spans(self):
        results, model = self.run_detector("core")
        self.assertEqual(model.calls[0][1], list(LABEL_PRESETS["core"]))
        self.assertEqual([(r.section_of_text, r.metadata["label"]) for r in results],
                         [("Dana Whitfield", "PERSON"), ("Lisbon", "GPE")])
        self.assertTrue(all(r.metadata["backend"] == "gliner" for r in results))
        self.assertTrue(all("GLiNER labelled" in r.reasoning for r in results))

    def test_pii_preset_emits_identifier_labels_directly(self):
        results, _ = self.run_detector("pii")
        by_text = {r.section_of_text: r for r in results}
        phone = by_text["555-0100"]
        self.assertEqual(phone.metadata["label"], "phone number")
        self.assertEqual(phone.metadata["entity_type"], "phone")
        self.assertEqual(phone.span, (self.text.index("555-0100"), self.text.index("555-0100") + 8))

    def test_threshold_filters_spans_and_is_passed_to_the_model(self):
        results, model = self.run_detector("pii", threshold=0.5)
        self.assertEqual(model.calls[0][2], 0.5)
        self.assertEqual([r.section_of_text for r in results], ["Dana Whitfield", "Lisbon"])

    def test_long_text_is_scored_in_windows_with_absolute_offsets(self):
        detector, model = _detector([], label_preset="core")
        words = " ".join(f"w{i}" for i in range(gliner_detector.MAX_WINDOW_WORDS * 2 + 5))
        with patch.object(GLOBAL_CONFIG, "ner_postfilter", False):
            detector.extract_entities(words)
        self.assertEqual(len(model.calls), 3)

    def test_empty_prediction_returns_no_results(self):
        detector, _ = _detector([], label_preset="pii")
        self.assertEqual(detector.extract_entities("nothing here"), [])


class PostfilterIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            spacy.load(GLOBAL_CONFIG.ner_model)
        except OSError as exc:
            raise unittest.SkipTest(f"spaCy model unavailable: {exc}")

    def setUp(self):
        # Other NER tests may leave stub pipelines in the shared cache.
        with NER.ner_detector._PIPELINE_CACHE_LOCK:
            NER.ner_detector._PIPELINES.clear()
        self.addCleanup(NER.ner_detector._PIPELINES.clear)

    def test_postfilter_keeps_linked_entities_and_drops_placeholders(self):
        text = "Hello, I'm Dana Whitfield and I live in Lisbon. The XXXX office is closed."
        spans = [
            _span("Dana Whitfield", text, "name", 0.9),
            _span("Lisbon", text, "location city", 0.8),
            _span("XXXX", text, "organization", 0.7),
        ]
        detector, _ = _detector(spans, label_preset="core")
        with patch.object(GLOBAL_CONFIG, "ner_postfilter", True):
            kept = {r.section_of_text: r.metadata.get("postfilter_rule") for r in detector.extract_entities(text)}
        self.assertEqual(set(kept), {"Dana Whitfield", "Lisbon"})
        self.assertTrue(all(rule for rule in kept.values()))
        with patch.object(GLOBAL_CONFIG, "ner_postfilter", False):
            raw = {r.section_of_text for r in detector.extract_entities(text)}
        self.assertEqual(raw, {"Dana Whitfield", "Lisbon", "XXXX"})

    def test_extra_labels_bypass_the_postfilter(self):
        text = "Reach me on 555-0100 please."
        detector, _ = _detector([_span("555-0100", text, "phone number", 0.9)], label_preset="pii")
        with patch.object(GLOBAL_CONFIG, "ner_postfilter", True):
            results = detector.extract_entities(text)
        self.assertEqual([r.section_of_text for r in results], ["555-0100"])


if __name__ == "__main__":
    unittest.main()
