"""PRIVOKE_NER_MODEL selects the spaCy model; the default stays en_core_web_sm."""

from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

if importlib.util.find_spec("spacy") is None:
    spacy_stub = types.ModuleType("spacy")
    spacy_stub.load = lambda model_name: (_ for _ in ()).throw(RuntimeError("mock spacy.load required"))
    sys.modules["spacy"] = spacy_stub

from src.NER import ner_detector
from src.NER.ner_detector import EntityNERDetector
from src.config import GLOBAL_CONFIG, GlobalConfig


class NerModelOptionTests(unittest.TestCase):
    def setUp(self):
        with ner_detector._PIPELINE_CACHE_LOCK:
            ner_detector._PIPELINES.clear()
        self.addCleanup(ner_detector._PIPELINES.clear)

    def test_default_model_is_the_small_english_model(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PRIVOKE_NER_MODEL", None)
            self.assertEqual(GlobalConfig().ner_model, "en_core_web_sm")

    def test_environment_selects_the_model(self):
        with patch.dict(os.environ, {"PRIVOKE_NER_MODEL": " en_core_web_lg "}):
            self.assertEqual(GlobalConfig().ner_model, "en_core_web_lg")
        with patch.dict(os.environ, {"PRIVOKE_NER_MODEL": "   "}):
            self.assertEqual(GlobalConfig().ner_model, "en_core_web_sm")

    def test_detector_uses_config_unless_a_name_is_passed(self):
        with patch.object(GLOBAL_CONFIG, "ner_model", "en_core_web_lg"), \
                patch.object(ner_detector.spacy, "load", return_value=object()) as load:
            detector = EntityNERDetector()
            self.assertEqual(detector.model_name, "en_core_web_lg")
            explicit = EntityNERDetector("en_core_web_sm")
            self.assertEqual(explicit.model_name, "en_core_web_sm")
        self.assertEqual([c.args[0] for c in load.call_args_list], ["en_core_web_lg", "en_core_web_sm"])


if __name__ == "__main__":
    unittest.main()
