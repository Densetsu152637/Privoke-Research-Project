from __future__ import annotations
import hashlib
import math
import re
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

import numpy as np

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
for path in (PACKAGE_ROOT, PACKAGE_ROOT.parents[1] / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.classification import Sensitivity, Visibility, Category
from src.model import ModelConfig, TinyTransformerModel
from src.transformer_encoder import EncoderConfig, NumpyTransformerEncoder, encoder_tensor_shapes, token_ids

PROFILES = ((512, 24, 48, 64, 1, 2), (512, 32, 64, 96, 2, 4), (768, 32, 64, 128, 3, 4))


def arrays_for(config):
    rng = np.random.default_rng(913)
    return {name: rng.normal(0, .08, shape).astype(np.float32)
            for name, shape in encoder_tensor_shapes(config).items()}


def legacy_ids(text, config):
    pattern = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?|\d+|[^\w\s]", re.UNICODE)
    return np.asarray([0] + [1 + int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest()[:4], "big")
                            % (config.vocab_size - 1) for token in pattern.findall(text.lower())[:config.max_tokens - 1]], dtype=np.int64)


def legacy_encode(text, config, parameters):
    # Independent frozen NumPy equations from base 61f12995; do not delegate to
    # production helpers. Compare exact bytes on the same numeric environment.
    ids = legacy_ids(text, config)
    hidden = parameters["token_embedding"][ids] + parameters["position_embedding"][:len(ids)]
    def norm(value):
        mean = value.mean(axis=-1, keepdims=True)
        variance = ((value - mean) ** 2).mean(axis=-1, keepdims=True)
        return (value - mean) / np.sqrt(variance + 1e-5)
    for index in range(config.num_layers):
        prefix = "" if config.num_layers == 1 else f"layers.{index}."
        heads, size = config.num_attention_heads, config.hidden_size // config.num_attention_heads
        query = (hidden @ parameters[prefix + "attention.query.weight"]).reshape(len(hidden), heads, size).transpose(1, 0, 2)
        key = (hidden @ parameters[prefix + "attention.key.weight"]).reshape(len(hidden), heads, size).transpose(1, 0, 2)
        value = (hidden @ parameters[prefix + "attention.value.weight"]).reshape(len(hidden), heads, size).transpose(1, 0, 2)
        scores = query @ key.transpose(0, 2, 1) / math.sqrt(size)
        exponents = np.exp(scores - np.max(scores, axis=-1, keepdims=True))
        attention = exponents / np.sum(exponents, axis=-1, keepdims=True)
        attended = (attention @ value).transpose(1, 0, 2).reshape(hidden.shape)
        attended = attended @ parameters[prefix + "attention.output.weight"] + parameters[prefix + "attention.output.bias"]
        hidden = norm(hidden + attended)
        value = hidden @ parameters[prefix + "ffn.input.weight"] + parameters[prefix + "ffn.input.bias"]
        intermediate = 0.5 * value * (1.0 + np.tanh(math.sqrt(2.0 / math.pi) * (value + 0.044715 * value**3)))
        hidden = norm(hidden + intermediate @ parameters[prefix + "ffn.output.weight"] + parameters[prefix + "ffn.output.bias"])
    return (hidden[0] * 0.5 + hidden.mean(axis=0) * 0.5).astype(np.float32)


class TransformerEncoderTests(unittest.TestCase):
    def test_exact_legacy_cpu_equations_and_tokenization_all_profiles(self):
        for dimensions in PROFILES:
            config = EncoderConfig(*dimensions)
            arrays = arrays_for(config)
            encoder = NumpyTransformerEncoder(config, arrays)
            contextual_config = ModelConfig(
                *dimensions[:4], tuple(Sensitivity.__members__), tuple(Visibility.__members__),
                tuple(Category.__members__), num_layers=dimensions[4], num_attention_heads=dimensions[5],
            )
            rng = np.random.default_rng(37)
            for name, labels in (("sensitivity", 4), ("visibility", 6), ("category", 10)):
                arrays[f"head.{name}.weight"] = rng.normal(0, .08, (config.hidden_size, labels)).astype(np.float32)
                arrays[f"head.{name}.bias"] = rng.normal(0, .08, labels).astype(np.float32)
            contextual = TinyTransformerModel(contextual_config, {name: value.ravel() for name, value in arrays.items()},
                                             {name: value.shape for name, value in arrays.items()}, device="cpu")
            for text in ("", "Email [AT] example. 1 2 3\n\u212a\ufb03", "x " * 300):
                with self.subTest(dimensions=dimensions, text_length=len(text)):
                    expected = legacy_encode(text, config, arrays)
                    self.assertEqual(token_ids(text, config).tobytes(), legacy_ids(text, config).tobytes())
                    self.assertEqual(encoder.encode(text).tobytes(), expected.tobytes())
                    self.assertEqual(contextual.encode(text).tobytes(), expected.tobytes())
                    self.assertEqual(np.asarray(contextual.predict(text).pooled, dtype=np.float32).tobytes(), expected.tobytes())

    def test_real_first_zero_and_padding_masks_preserve_exact_batch_pooling(self):
        config = EncoderConfig(*PROFILES[1])
        encoder = NumpyTransformerEncoder(config, arrays_for(config))
        rows = [token_ids(text, config) for text in ("", "two words", "three more words")]
        ids = np.zeros((3, 7), dtype=np.int64)
        mask = np.zeros_like(ids, dtype=np.bool_)
        for index, row in enumerate(rows):
            ids[index, :len(row)] = row
            mask[index, :len(row)] = True
        pooled = encoder.encode_tokens(ids, mask)
        for index, row in enumerate(rows):
            self.assertEqual(pooled[index].tobytes(), encoder.encode_tokens(row).tobytes())
        self.assertEqual(encoder.encode_many(()).shape, (0, config.hidden_size))
        invalid = ((np.array([0, 0]), None), (np.array([1]), None),
                   (np.array([0, 1, 0]), np.array([True, False, True])),
                   (np.array([0, 1]), np.array([False, False])),
                   (np.array([0, 1]), np.array([True, False])),
                   (np.array([0, config.vocab_size]), None))
        for row, bad_mask in invalid:
            with self.assertRaises(ValueError):
                encoder.encode_tokens(row, bad_mask)

    def test_encoder_owns_readonly_arrays_and_config(self):
        config = EncoderConfig(*PROFILES[0])
        arrays = arrays_for(config)
        encoder = NumpyTransformerEncoder(config, arrays)
        before = encoder.encode("test").tobytes()
        arrays["token_embedding"].fill(100)
        self.assertEqual(encoder.encode("test").tobytes(), before)
        with self.assertRaises(ValueError):
            encoder.parameters["token_embedding"].setflags(write=True)
        with self.assertRaises(TypeError):
            encoder.parameters["token_embedding"] = arrays["token_embedding"]
        with self.assertRaises(FrozenInstanceError):
            encoder.config = config

    def test_rejects_capacity_bad_dtype_and_nonfinite_output(self):
        for dimensions in ((True, 24, 48, 64, 1, 2), (512, 24, 48, 513, 1, 2),
                           (100000, 24, 48, 64, 1, 2), (512, 25, 48, 64, 1, 2)):
            with self.assertRaises(ValueError):
                EncoderConfig(*dimensions)
        config = EncoderConfig(*PROFILES[0])
        for bad in (np.zeros((512, 24), dtype=np.float64), np.full((512, 24), np.nan, dtype=np.float32)):
            arrays = arrays_for(config)
            arrays["token_embedding"] = bad
            with self.assertRaises(ValueError):
                NumpyTransformerEncoder(config, arrays)
        arrays = arrays_for(config)
        arrays["attention.query.weight"].fill(np.finfo(np.float32).max)
        encoder = NumpyTransformerEncoder(config, arrays)
        with np.errstate(over="ignore", invalid="ignore"), self.assertRaises(ValueError):
            encoder.encode("overflow")
        # Variance overflow could otherwise yield finite all-zero normalization;
        # reject the intermediate overflow rather than accept a clean output.
        hidden = np.full((2, config.hidden_size), 1e20, dtype=np.float32)
        hidden[:, ::2] *= -1
        encoder = NumpyTransformerEncoder(config, arrays_for(config))
        with self.assertRaises(ValueError):
            encoder.encoder_block(hidden, "")


if __name__ == "__main__":
    unittest.main()
