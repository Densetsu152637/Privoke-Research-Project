import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))

from privoke_model.artifact import apply_parameter_update, float32
from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE, StreamedTransformerPrivacyModel
from src.LLM.privoke.training import SemanticTrainingExample, compute_semantic_gradients, _parameter_fingerprint, _safety_regression_rate
from src.classification import Category, Sensitivity, Visibility, initialise_unpacked
from src.hosting.grpc_server import PrivokeRuntimeService
from src.model import ModelConfig, ModelArtifactError
from privoke.v1 import runtime_pb2
from test_streamed_transformer import _snapshot


class TrainingSafetyTests(unittest.TestCase):
    def test_invalid_streamed_configuration_cannot_silently_map_to_clean(self):
        for name, value in (
            ("sensitivity_labels", ["BAD", "S1", "S2", "S3"]),
            ("sensitivity_labels", ["S0", "S1", "S2", "S2"]),
            ("visibility_labels", "PU"),
            ("vocab_size", 1),
            ("hidden_size", True),
            ("category_threshold", float("nan")),
            ("num_layers", 1000000000),
            ("max_tokens", 1000000000),
        ):
            config = dict(self.artifact["config"])
            config[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ModelArtifactError):
                ModelConfig.from_mapping(config)
    def test_detects_safety_downgrade_even_when_both_predictions_are_nonexact(self):
        target = initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH])
        before = initialise_unpacked(Sensitivity.S2, Visibility.PU, [])
        after = initialise_unpacked(Sensitivity.S1, Visibility.PU, [])
        self.assertTrue(before.is_sensitive())
        self.assertTrue(after.is_sensitive())
        self.assertEqual(_safety_regression_rate([target], [before], [after]), 1.0)
        self.assertEqual(_safety_regression_rate([target], [after], [before]), 0.0)

    def test_detects_policy_downgrade_without_sensitivity_change(self):
        target = initialise_unpacked(Sensitivity.S1, Visibility.P4, [Category.IDENTITY, Category.LOCATION])
        before = initialise_unpacked(Sensitivity.S1, Visibility.P4, [Category.IDENTITY])
        after = initialise_unpacked(Sensitivity.S1, Visibility.P0, [Category.HEALTH])
        self.assertEqual(_safety_regression_rate([target], [before], [after]), 1.0)

    def test_detects_action_loss_from_lower_candidate_confidence(self):
        target = initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.HEALTH])
        self.assertEqual(_safety_regression_rate(
            [target], [target], [target], before_confidence=[0.9], after_confidence=[0.4]
        ), 1.0)
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads((ROOT.parents[1] / "models/privoke-balanced.json").read_text())
        cls.model = StreamedTransformerPrivacyModel(_snapshot(cls.artifact))
        cls.sensitive = initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH])
        cls.clean = initialise_unpacked(Sensitivity.S0, Visibility.PU, [])
        cls.training = [SemanticTrainingExample("my private diagnosis", cls.sensitive, 1.0)]
        cls.heldout = [
            SemanticTrainingExample("my doctor prescribed medication for cancer", cls.sensitive, 1.0),
            SemanticTrainingExample("write a friendly email about tomorrow meeting", cls.clean, 1.0),
        ]

    def compute(self, heldout):
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=self.model):
            return compute_semantic_gradients(self.training, model_id=self.model.snapshot.model_id, learning_rate=0.03, max_gradient=0.05, heldout_examples=heldout)

    def test_quality_evaluates_exact_published_candidate_without_mutating_cached_model(self):
        before = self.model.model.predict_many(tuple(item.text for item in self.heldout))
        batch = self.compute(self.heldout)
        published = apply_parameter_update(self.artifact, base_version=self.artifact["version"], deltas=batch.gradients, source_id="test")
        streamed_parameters = {name: tuple(float32(value) for value in tensor["values"]) for name, tensor in published["parameters"].items()}
        self.assertEqual(batch.metadata["updated_parameter_fingerprint"], _parameter_fingerprint(streamed_parameters))
        self.assertEqual(before, self.model.model.predict_many(tuple(item.text for item in self.heldout)))
        self.assertEqual(batch.metrics["heldout_sensitive_examples"], 1.0)
        self.assertEqual(batch.metrics["heldout_clean_examples"], 1.0)

    def test_rejects_training_overlap_missing_labels_strata_and_invalid_weight(self):
        cases = (
            [self.training[0], self.heldout[1]],
            [SemanticTrainingExample("unlabeled", None, 1.0), self.heldout[1]],
            [self.heldout[0]],
            [self.heldout[0], SemanticTrainingExample("clean prompt", self.clean, float("nan"))],
            [self.heldout[0], self.heldout[1], self.heldout[1]],
        )
        for examples in cases:
            with self.subTest(examples=examples), self.assertRaises(ValueError):
                self.compute(examples)

    def test_training_rpc_bounds_include_heldout_data(self):
        request = runtime_pb2.ComputeSemanticGradientsRequest(
            model_id="privoke-balanced",
            examples=[runtime_pb2.RuntimeTrainingExample(text="training", weight=1.0)],
            heldout_examples=[runtime_pb2.RuntimeTrainingExample(text="x" * 20001, weight=1.0)],
            learning_rate=0.03, max_gradient=0.05,
        )
        response = PrivokeRuntimeService().ComputeSemanticGradients(request, None)
        self.assertIn("characters", response.error)
