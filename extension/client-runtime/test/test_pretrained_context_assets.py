"""Opt-in official-asset integration; no datasets, training or quality claims."""
import os
from pathlib import Path
import sys
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
for path in (ROOT / "shared/python", ROOT / "extension/client-runtime"):
    sys.path.insert(0, str(path))

from privoke_model.artifact import load_artifact
from src.detection.preprocessing import normalize_text
from src.pretrained_context import FrozenPretrainedEncoder, PretrainedContextModel


@unittest.skipUnless(os.getenv("PRIVOKE_PRETRAINED_CONTEXT_DIR"), "Official asset integration requires an explicit local directory.")
class OfficialPretrainedAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.encoder = FrozenPretrainedEncoder()

    def test_actual_graph_features_normalization_repeatability_and_serialized_heads(self):
        text = "Ｓｙｎｔｈｅｔｉｃ [at] example.test is an invented contact."
        first = self.encoder.encode(text)
        np.testing.assert_array_equal(first, self.encoder.encode_normalized(normalize_text(text)))
        np.testing.assert_array_equal(first, self.encoder.encode(text))
        self.assertEqual(first.shape, (384,))
        self.assertTrue(np.isfinite(first).all())
        self.assertAlmostEqual(float(np.linalg.norm(first)), 1., places=6)
        artifact = load_artifact(ROOT / "shared/python/tests/fixtures/pretrained-context-minilm.json")
        model = PretrainedContextModel(artifact["config"], {n: t["values"] for n, t in artifact["parameters"].items()},
                                       {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()}, self.encoder)
        prediction = model.predict(normalize_text(text))
        self.assertEqual(prediction.pooled, tuple(float(value) for value in first))
        self.assertEqual(prediction.sensitivity_probabilities, (.25,) * 4)

    def test_actual_tokenizer_maximum_and_overlength_are_explicit(self):
        maximum = "hello " * 254
        self.assertEqual(len(self.encoder._tokenizer.encode(maximum).ids), 256)
        self.assertEqual(self.encoder.encode(maximum).shape, (384,))
        with self.assertRaisesRegex(ValueError, "256-token"):
            self.encoder.encode("hello " * 255)


if __name__ == "__main__":
    unittest.main()
