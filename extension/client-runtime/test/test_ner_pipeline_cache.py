from __future__ import annotations
import importlib.util
import sys
import threading
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
for path in (PACKAGE_ROOT, REPO_ROOT / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

# The cache behavior is testable without downloading/installing spaCy on a host.
if importlib.util.find_spec("spacy") is None:
    spacy_stub = types.ModuleType("spacy")
    spacy_stub.load = lambda model_name: (_ for _ in ()).throw(RuntimeError("mock spacy.load required"))
    sys.modules["spacy"] = spacy_stub

from src.NER import ner_detector
from src.NER.ner_detector import EntityNERDetector


class FakeNLP:
    def __init__(self, name):
        self.name = name

    def __call__(self, text):
        entity = SimpleNamespace(start_char=0, end_char=len(text), label_="PERSON", text=text)
        return SimpleNamespace(ents=(entity,))


class EntityNERPipelineCacheTests(unittest.TestCase):
    def setUp(self):
        with ner_detector._PIPELINE_CACHE_LOCK:
            ner_detector._PIPELINES.clear()

    def tearDown(self):
        with ner_detector._PIPELINE_CACHE_LOCK:
            ner_detector._PIPELINES.clear()

    def test_instances_share_one_loaded_pipeline_and_keep_request_docs_separate(self):
        pipeline = FakeNLP("en_core_web_sm")
        with patch.object(ner_detector.spacy, "load", return_value=pipeline) as load:
            first = EntityNERDetector()
            second = EntityNERDetector()
            one = first.extract_entities("Alice")
            two = second.extract_entities("Bob")
        load.assert_called_once_with("en_core_web_sm")
        self.assertIs(first.nlp, second.nlp)
        self.assertEqual(one[0].section_of_text, "Alice")
        self.assertEqual(two[0].section_of_text, "Bob")
        self.assertNotEqual(one[0].section_of_text, two[0].section_of_text)

    def test_concurrent_first_use_loads_model_once(self):
        calls = []
        calls_lock = threading.Lock()
        def load(name):
            with calls_lock:
                calls.append(name)
            time.sleep(0.02)
            return FakeNLP(name)
        with patch.object(ner_detector.spacy, "load", side_effect=load):
            with ThreadPoolExecutor(max_workers=12) as pool:
                detectors = list(pool.map(lambda _: EntityNERDetector(), range(12)))
        self.assertEqual(calls, ["en_core_web_sm"])
        self.assertTrue(all(item._pipeline_entry is detectors[0]._pipeline_entry for item in detectors))

    def test_inference_and_entity_conversion_are_serialized_per_pipeline(self):
        pipeline = FakeNLP("shared")
        active = 0
        max_active = 0
        counter_lock = threading.Lock()
        with patch.object(ner_detector.spacy, "load", return_value=pipeline):
            detectors = [EntityNERDetector(), EntityNERDetector()]
        original = EntityNERDetector._classified_entities
        def checked(self, entities):
            nonlocal active, max_active
            self.assert_pipeline_lock = self._pipeline_entry.inference_lock.locked()
            with counter_lock:
                active += 1
                max_active = max(max_active, active)
            try:
                time.sleep(0.01)
                return original(self, entities)
            finally:
                with counter_lock:
                    active -= 1
        with patch.object(EntityNERDetector, "_classified_entities", checked):
            with ThreadPoolExecutor(max_workers=10) as pool:
                outputs = list(pool.map(lambda pair: detectors[pair[0] % 2].extract_entities(f"Name{pair[0]}"), enumerate(range(10))))
        self.assertEqual(max_active, 1)
        self.assertTrue(all(getattr(detector, "assert_pipeline_lock", False) for detector in detectors))
        self.assertEqual([items[0].section_of_text for items in outputs], [f"Name{i}" for i in range(10)])

    def test_model_names_are_separate_and_cache_evicts_lru_at_two(self):
        loaded = {}
        def load(name):
            loaded[name] = loaded.get(name, 0) + 1
            return FakeNLP(name)
        with patch.object(ner_detector.spacy, "load", side_effect=load):
            first_a = EntityNERDetector("model-a")
            b = EntityNERDetector("model-b")
            a_again = EntityNERDetector("model-a")  # refresh A, so B is least recent
            c = EntityNERDetector("model-c")
            final_a = EntityNERDetector("model-a")
            final_b = EntityNERDetector("model-b")
        self.assertIs(first_a.nlp, a_again.nlp)
        self.assertIs(a_again.nlp, final_a.nlp)
        self.assertIsNot(final_b.nlp, b.nlp)
        self.assertEqual(loaded, {"model-a": 1, "model-b": 2, "model-c": 1})
        self.assertEqual(list(ner_detector._PIPELINES), ["model-a", "model-b"])
        self.assertLessEqual(len(ner_detector._PIPELINES), 2)

    def test_failed_load_is_not_cached_and_can_be_retried(self):
        with patch.object(ner_detector.spacy, "load", side_effect=[RuntimeError("missing model"), FakeNLP("ok")]) as load:
            with self.assertRaisesRegex(RuntimeError, "missing model"):
                EntityNERDetector("custom")
            self.assertNotIn("custom", ner_detector._PIPELINES)
            detector = EntityNERDetector("custom")
        self.assertEqual(detector.nlp.name, "ok")
        self.assertEqual(load.call_count, 2)


if __name__ == "__main__":
    unittest.main()
