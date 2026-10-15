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
from privoke_model.pretrained_context import build_head_artifact, head_tensor_shapes
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

    def test_extended_pinned_context_boundaries_and_short_prediction_parity(self):
        extended = FrozenPretrainedEncoder(max_tokens=512)
        for tokens in (256, 257, 512):
            text = "hello " * (tokens - 2)
            self.assertEqual(len(extended._tokenizer.encode(text).ids), tokens)
            vector = extended.encode(text)
            self.assertEqual(vector.shape, (384,))
            self.assertTrue(np.isfinite(vector).all())
            self.assertAlmostEqual(float(np.linalg.norm(vector)), 1., places=6)
        with self.assertRaisesRegex(ValueError, "512-token"):
            extended.encode("hello " * 511)
        text = normalize_text("Synthetic short [at] example.test contact.")
        np.testing.assert_array_equal(self.encoder.encode_normalized(text), extended.encode_normalized(text))
        parameters = {name: (np.arange(np.prod(shape), dtype=np.float32) % 13 - 6) * .01
                      for name, shape in head_tensor_shapes().items()}
        predictions = []
        for encoder in (self.encoder, extended):
            artifact = build_head_artifact(parameters, version="v1.synthetic", generated_at_unix=1,
                                           metadata={}, max_tokens=encoder.max_tokens)
            model = PretrainedContextModel(artifact["config"],
                {name: tensor["values"] for name, tensor in artifact["parameters"].items()},
                {name: tuple(tensor["shape"]) for name, tensor in artifact["parameters"].items()}, encoder)
            predictions.append(model.predict(text))
        self.assertEqual(predictions[0], predictions[1])


if __name__ == "__main__":
    unittest.main()
