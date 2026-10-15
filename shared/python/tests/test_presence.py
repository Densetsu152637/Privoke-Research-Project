import json
import math
import sys
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privoke_model.artifact import ModelArtifactError, apply_parameter_update, artifact_checksum, validate_artifact
from privoke_model.presence import (
    BLOCK_SIZE, NORMALIZATION, PRESENCE_ARCHITECTURE, PRESENCE_TASK,
    PROFILE_MAX_FEATURES, TOKEN_PATTERN, SparsePresenceModel,
    presence_tensor_shapes, validate_presence_config, validate_presence_parameters,
)


def config_fixture(profile="efficient"):
    common = {"max_features": PROFILE_MAX_FEATURES[profile], "sublinear_tf": True,
              "use_idf": True, "smooth_idf": True, "norm": "l2", "lowercase": False}
    return {"task": PRESENCE_TASK, "profile": profile, "threshold": 0.5,
            "normalization": NORMALIZATION, "column_order": ["word", "char"],
            "coefficient_block_size": BLOCK_SIZE, "branches": {
                "word": dict(common, analyzer="word", ngram_range=[1, 2],
                             features=["café", "mail", "café mail", "1234"], token_pattern=TOKEN_PATTERN),
                "char": dict(common, analyzer="char", ngram_range=[3, 5], features=["caf", "afé", "123", "@ex"]),
            }}


def artifact_fixture(profile="efficient"):
    config = config_fixture(profile)
    tensors = {name: {"shape": list(shape), "values": [1.0 if name.startswith("features.") else 0.0] * shape[0],
                      "trainable": name.startswith("head.presence.")}
               for name, shape in presence_tensor_shapes(config).items()}
    tensors["head.presence.weight.000"]["values"] = [1, -1, 0.5, 2, 1, 0, -2, 3]
    payload = {"schema_version": 1, "architecture": PRESENCE_ARCHITECTURE,
               "model_id": f"privoke-presence-{profile}", "version": "v1", "generated_at_unix": 1,
               "config": config, "parameters": tensors, "metadata": {}}
    payload["checksum"] = artifact_checksum(payload)
    return payload


class PresenceModelTests(unittest.TestCase):
    def model(self):
        return SparsePresenceModel.from_artifact(artifact_fixture())

    def test_committed_cross_language_fixture(self):
        path = Path(__file__).parent / "fixtures" / "presence-efficient.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload, artifact_fixture())
        self.assertGreater(SparsePresenceModel.from_artifact(payload).predict_probability("café"), 0.5)

    def test_independent_branch_norms_and_global_column_order(self):
        values = self.model().features("café mail")
        self.assertEqual(set(values), {0, 1, 2, 4, 5})
        self.assertAlmostEqual(sum(values[index] ** 2 for index in (0, 1, 2)), 1)
        self.assertAlmostEqual(sum(values[index] ** 2 for index in (4, 5)), 1)
        self.assertAlmostEqual(values[0], 1 / math.sqrt(3))

    def test_repetition_uses_sublinear_tf_and_canonical_unicode(self):
        values = self.model().features("ＣＡＦÉ café mail")
        expected = 1 + math.log(2)
        self.assertAlmostEqual(values[0] / values[1], expected)
        self.assertEqual(self.model().features("1 2 3 4 [at]example"),
                         self.model().features("1234 @example"))

    def test_unknown_and_empty_feature_documents_use_bias(self):
        model = self.model()
        for text in ("", "zz", "🧪", "x"):
            self.assertEqual(model.features(text), {})
            self.assertEqual(model.predict_probability(text), 0.5)
            self.assertTrue(model.classify(text))

    def test_probability_uses_known_linear_logit(self):
        model = self.model()
        features = model.features("café mail")
        weights = artifact_fixture()["parameters"]["head.presence.weight.000"]["values"]
        logit = math.fsum(weights[index] * features[index] for index in sorted(features))
        self.assertAlmostEqual(model.predict_probability("café mail"), 1 / (1 + math.exp(-logit)))

    def test_model_defensively_copies_and_freezes_inputs(self):
        payload = artifact_fixture()
        model = SparsePresenceModel.from_artifact(payload)
        old_probability = model.predict_probability("café")
        payload["parameters"]["head.presence.weight.000"]["values"][0] = -100
        payload["config"]["branches"]["word"]["features"][0] = "other"
        self.assertEqual(model.predict_probability("café"), old_probability)
        with self.assertRaises(TypeError):
            model.config["threshold"] = 0.1
        with self.assertRaises(FrozenInstanceError):
            model.parameters = {}
        # Candidate reconstruction from frozen configuration is supported.
        clone = SparsePresenceModel(model.config, model.parameters, model.shapes)
        self.assertEqual(clone.predict_probability("café"), old_probability)

    def test_stable_sigmoid_and_float32_parameters(self):
        payload = artifact_fixture()
        for bias, expected in ((1e30, 1), (-1e30, 0)):
            payload["parameters"]["head.presence.bias"]["values"] = [bias]
            payload["checksum"] = artifact_checksum({key: value for key, value in payload.items() if key != "checksum"})
            self.assertEqual(SparsePresenceModel.from_artifact(payload).predict_probability(""), expected)

    def test_head_delta_direction_and_update_frozen_guard(self):
        model = self.model()
        delta = model.presence_head_deltas("café", True)
        self.assertGreater(delta["head.presence.weight.000"][0], 0)
        self.assertGreater(delta["head.presence.bias"][0], 0)
        self.assertEqual(delta["head.presence.weight.000"][1], 0)
        with self.assertRaises(ValueError):
            model.presence_head_deltas("café", 1)
        payload = artifact_fixture()
        updated = apply_parameter_update(payload, base_version="v1", deltas=delta, source_id="test")
        self.assertGreater(SparsePresenceModel.from_artifact(updated).predict_probability("café"), model.predict_probability("café"))
        with self.assertRaises(ModelArtifactError):
            apply_parameter_update(payload, base_version="v1", deltas={"features.word.idf": [0] * 4}, source_id="test")

    def test_config_invalid_values_and_unknown_fields_fail_closed(self):
        mutations = [lambda c: c.update(extra=1), lambda c: c.update(threshold=True),
                     lambda c: c.update(threshold=float("nan")), lambda c: c.update(threshold=2),
                     lambda c: c.update(profile="other"), lambda c: c.update(coefficient_block_size=True),
                     lambda c: c.update(column_order=["char", "word"]),
                     lambda c: c["branches"]["word"].update(ngram_range=[True, 2]),
                     lambda c: c["branches"]["word"].update(features=["a"]),
                     lambda c: c["branches"]["char"].update(features=["too long"]),
                     lambda c: c["branches"]["word"].update(features=["café", "café"]),
                     lambda c: c["branches"]["char"].update(sublinear_tf=1),
                     lambda c: c["branches"]["char"].update(features=["\ud800ab"])]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                config = config_fixture()
                mutate(config)
                with self.assertRaises(ModelArtifactError):
                    validate_presence_config(config)

    def test_parameter_invalid_values_shape_flags_manifest_fail_closed(self):
        for mutate in (lambda p: p["parameters"].pop("head.presence.bias"),
                       lambda p: p["parameters"]["features.word.idf"].update(trainable=True),
                       lambda p: p["parameters"]["head.presence.bias"].update(trainable=1),
                       lambda p: p["parameters"]["features.word.idf"].update(values=[0] * 4),
                       lambda p: p["parameters"]["head.presence.bias"].update(values=[1e100]),
                       lambda p: p["parameters"]["head.presence.bias"].update(shape=[1, 1]),
                       lambda p: p.update(model_id="privoke-presence-quality")):
            payload = artifact_fixture()
            mutate(payload)
            payload["checksum"] = artifact_checksum({key: value for key, value in payload.items() if key != "checksum"})
            with self.assertRaises(ModelArtifactError):
                validate_artifact(payload)

    def test_multiblock_quality_manifest_stays_within_existing_caps(self):
        config = config_fixture("quality")
        config["branches"]["word"]["features"] = [f"word{index}" for index in range(16000)]
        # Exactly 16,000 distinct legal four-codepoint character features.
        config["branches"]["char"]["features"] = [f"a{chr(0x400 + index // 256)}{chr(0x400 + index % 256)}z" for index in range(16000)]
        shapes = presence_tensor_shapes(config)
        self.assertEqual(sum(shape[0] for shape in shapes.values()), 64001)
        heads = [shape[0] for name, shape in shapes.items() if name.startswith("head.")]
        self.assertTrue(all(size <= 4096 for size in heads))
        self.assertEqual(shapes["head.presence.weight.007"], (3328,))

    def test_config_size_limit(self):
        config = config_fixture()
        config["branches"]["word"]["features"] = ["w" * (2 * 1024 * 1024)]
        with self.assertRaises(ModelArtifactError):
            validate_presence_config(config)

    def test_sklearn_feature_parity_when_available(self):
        try:
            import numpy as np
            from sklearn.feature_extraction.text import TfidfVectorizer
        except ImportError:
            self.skipTest("Optional sklearn reference unavailable; Docker evaluator supplies it.")
        model = self.model()
        text = "café café mail 1 2 3 4 [at]example"
        from privoke_model.training_data import training_text_key
        expected = []
        for name in ("word", "char"):
            branch = config_fixture()["branches"][name]
            vectorizer = TfidfVectorizer(analyzer=name, ngram_range=tuple(branch["ngram_range"]),
                                        vocabulary={feature: index for index, feature in enumerate(branch["features"])},
                                        lowercase=False, sublinear_tf=True, token_pattern=TOKEN_PATTERN)
            vectorizer.fit([training_text_key(text)])
            vectorizer.idf_ = np.array(model.parameters[f"features.{name}.idf"])
            expected.extend(vectorizer.transform([training_text_key(text)]).toarray()[0])
        actual = model.features(text)
        for index, value in enumerate(expected):
            self.assertAlmostEqual(actual.get(index, 0), value, places=14)


if __name__ == "__main__":
    unittest.main()
