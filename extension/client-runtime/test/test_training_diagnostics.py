"""Passive diagnostic identity and exact transported-state regression checks."""
import copy
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

import numpy as np
from privoke_model.artifact import updated_parameter_values, float32, validate_artifact, ModelArtifactError
from privoke_model.contextual_training import (prepare_training_policy_artifact, LEGACY_OBJECTIVE,
    CLASS_BALANCED_OBJECTIVE, TRAIN_DIAGNOSTICS_POLICY, DIAGNOSTICS_POLICY_KEY, DIAGNOSTICS_KEY,
    validate_training_diagnostics)
from src.LLM.privoke.training import (compute_semantic_gradients, compute_underlying_model_gradients,
    _class_balanced_examples, normalize_text)
from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel, GLOBAL_STREAMED_MODEL_CACHE
from src.model import TinyTransformerModel
from test_training_adaptation import snapshot
import test_full_encoder_training as full_fixture


@unittest.skipUnless(full_fixture.torch is not None, "Optional CPU training dependency torch is unavailable")
class TrainingDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        full_fixture.FullEncoderTrainingTests.setUp(self)

    def compute(self, artifact, trainer, bound):
        wrapper = StreamedTransformerPrivacyModel(snapshot(artifact))
        before = {name: value.copy() for name, value in wrapper.model.parameters.items()}
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper):
            result = trainer(self.rows, model_id=artifact["model_id"], learning_rate=.03,
                             max_gradient=bound, heldout_examples=self.heldout)
        for name, values in before.items():
            np.testing.assert_array_equal(wrapper.model.parameters[name], values)
        return result, wrapper

    def test_passive_identity_and_independent_transported_losses_for_both_policies_scopes(self):
        for objective in (LEGACY_OBJECTIVE, CLASS_BALANCED_OBJECTIVE):
            for trainer in (compute_semantic_gradients, compute_underlying_model_gradients):
                for bound in (.05, .000001):
                    with self.subTest(objective=objective, trainer=trainer.__name__, bound=bound):
                        base = prepare_training_policy_artifact(self.artifact, objective=objective)
                        enabled = prepare_training_policy_artifact(base, objective=objective, diagnostics=TRAIN_DIAGNOSTICS_POLICY)
                        original, _ = self.compute(base, trainer, bound)
                        actual, wrapper = self.compute(enabled, trainer, bound)
                        self.assertEqual(original.gradients, actual.gradients)
                        self.assertEqual(original.metrics, actual.metrics)
                        self.assertEqual(original.metadata["updated_parameter_fingerprint"], actual.metadata["updated_parameter_fingerprint"])
                        self.assertEqual(original.executions, actual.executions)
                        record = json.loads(actual.metadata[DIAGNOSTICS_KEY])
                        self.assertEqual(record["counts"], [2, 1, 1])
                        self.assertEqual(record["update"][0], sum(map(len, actual.gradients.values())))
                        if bound == .000001:
                            self.assertGreater(record["update"][1], 0)
                        parameters = {name: tuple(float32(v) for v in updated_parameter_values(values, actual.gradients[name]))
                                      if name in actual.gradients else values for name, values in wrapper.snapshot.parameters.items()}
                        candidate = TinyTransformerModel(wrapper.model.config, parameters, wrapper.snapshot.shapes,
                                                         reject_overlength=wrapper.model.reject_overlength)
                        rows = tuple(replace(row, text=normalize_text(row.text)) for row in self.rows)
                        if objective == CLASS_BALANCED_OBJECTIVE:
                            rows, _ = _class_balanced_examples(rows)
                        expected = [0.] * 3
                        total = math.fsum(row.weight for row in rows)
                        for row, prediction in zip(rows, candidate.predict_many(tuple(row.text for row in rows))):
                            for index, head in enumerate(("sensitivity", "visibility", "category")):
                                logits = prediction.pooled @ candidate.parameters[f"head.{head}.weight"] + candidate.parameters[f"head.{head}.bias"]
                                if head == "category":
                                    target = np.array([float(label in {c.name for c in row.target.categories()}) for label in candidate.config.category_labels])
                                    loss = math.fsum(float(max(v, 0) - v * y + math.log1p(math.exp(-abs(v)))) for v, y in zip(logits, target))
                                else:
                                    target = getattr(candidate.config, head + "_labels").index(getattr(row.target, head)().name)
                                    maximum = float(max(logits))
                                    loss = maximum + math.log(math.fsum(math.exp(float(v) - maximum) for v in logits)) - float(logits[target])
                                expected[index] += loss * row.weight / total
                        np.testing.assert_allclose(record["loss"][1][:3], expected, atol=1e-6, rtol=1e-6)
                        predictions = candidate.predict_many(tuple(row.text for row in rows))
                        from src.LLM.privoke.training import _classification_from_prediction
                        self.assertEqual(record["accuracy"][1][0], sum(row.target.pack() == _classification_from_prediction(p).pack()
                                         for row, p in zip(rows, predictions)) / len(rows))

    def test_cache_metadata_toggle_and_preflight_failures(self):
        enabled = prepare_training_policy_artifact(self.artifact, diagnostics=TRAIN_DIAGNOSTICS_POLICY)
        off, on = snapshot(self.artifact), snapshot(enabled)
        self.assertNotEqual(off.cache_key, on.cache_key)
        first = GLOBAL_STREAMED_MODEL_CACHE._model_for_snapshot(off)
        second = GLOBAL_STREAMED_MODEL_CACHE._model_for_snapshot(on)
        self.assertIsNot(first, second)
        self.assertEqual(second.snapshot.metadata[DIAGNOSTICS_POLICY_KEY], TRAIN_DIAGNOSTICS_POLICY)
        with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=first):
            legacy = compute_semantic_gradients((self.rows[0],), model_id=self.artifact["model_id"], learning_rate=.03, max_gradient=.05)
        self.assertNotIn(DIAGNOSTICS_KEY, legacy.metadata)
        self.assertEqual(legacy.executions, (("training", 1),))
        for rows in ((self.rows[0],), (replace(self.rows[0], target=None), self.rows[1])):
            with patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=second), \
                 patch.object(second.model, "predict_many") as prediction, self.assertRaises(ValueError):
                compute_semantic_gradients(rows, model_id=enabled["model_id"], learning_rate=.03, max_gradient=.05)
            prediction.assert_not_called()
        broken = copy.deepcopy(enabled)
        broken["metadata"][DIAGNOSTICS_POLICY_KEY] = "unknown"
        with self.assertRaises(ModelArtifactError):
            validate_artifact(broken)

    def test_record_tampering_is_rejected(self):
        enabled = prepare_training_policy_artifact(self.artifact, diagnostics=TRAIN_DIAGNOSTICS_POLICY)
        result, _ = self.compute(enabled, compute_semantic_gradients, .05)
        original = json.loads(result.metadata[DIAGNOSTICS_KEY])
        for key, value in (("counts", [2, 0, 2]), ("loss", [[0, 0, 0, 1]] * 2),
                           ("phases", []), ("objective", "unknown"), ("accuracy", [[float("nan")] * 6] * 2)):
            changed = {**original, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_training_diagnostics(json.dumps(changed), objective=LEGACY_OBJECTIVE, examples=2,
                    base_fingerprint=original["fingerprints"][0], candidate_fingerprint=original["fingerprints"][1])

    def test_actual_taxonomy_runtime_to_publication_wire_stays_bounded(self):
        root = Path(__file__).resolve().parents[3]
        for path in (root / "services/privoke-fuzzer/src", root / "services/privoke-fuzzer/tests"):
            sys.path.insert(0, str(path))
        from test_taxonomy_coverage import fixture
        from prompt_generation import taxonomy_coverage as taxonomy
        from training.trainer import train_parameter_batch
        from training.types import BatchTrainingConfig
        from training.evidence import persist_cycle_evidence
        from training.parameter_updates import emit_training_update
        from src.hosting.grpc_server import PrivokeRuntimeService
        from privoke.v1 import parameters_pb2
        dataset = taxonomy.load_snapshot(taxonomy.canonical_bytes(fixture()))
        originals, guard = taxonomy.generate_partition(dataset, 42)
        prepared = prepare_training_policy_artifact(self.artifact, objective=CLASS_BALANCED_OBJECTIVE, diagnostics=TRAIN_DIAGNOSTICS_POLICY)
        wrapper = StreamedTransformerPrivacyModel(snapshot(prepared))
        server = PrivokeRuntimeService()
        for scope in ("heads", "full_encoder"):
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"PRIVOKE_FUZZER_DUMP_DIR": directory}), \
                 patch.object(GLOBAL_STREAMED_MODEL_CACHE, "model_for_training", return_value=wrapper), \
                 patch("runtime_client.grpc.insecure_channel"), patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
                rpc = stub.return_value.ComputeUnderlyingModelGradients if scope == "full_encoder" else stub.return_value.ComputeSemanticGradients
                rpc.side_effect = lambda request, timeout: (server.ComputeUnderlyingModelGradients(request, None)
                    if scope == "full_encoder" else server.ComputeSemanticGradients(request, None))
                update = train_parameter_batch(prepared["model_id"], originals, heldout_examples=guard,
                    taxonomy_dataset=dataset, config=BatchTrainingConfig(seed=42), training_scope=scope, request_id="wire",
                    expected_objective=CLASS_BALANCED_OBJECTIVE, expected_diagnostics_policy=TRAIN_DIAGNOSTICS_POLICY)
                self.assertEqual(update.metrics["examples"], 64)
                self.assertEqual([e["examples"] for e in update.execution_evidence["executions"]], [64, 16, 16])
                request = parameters_pb2.FuzzerTrainingRequest(source_id="test", request_id="wire")
                extra = {"request_source_id": "test", "request_id": "wire", "training_request_fingerprint": "d" * 64,
                         "requested_prompt_count": "32", "generated_prompt_count": "32", "training_pipeline": "semantic"}
                original_union = {**update.metadata, **{k: str(v) for k, v in update.metrics.items()}, **extra}
                self.assertGreater(len(original_union), 64)
                persist_cycle_evidence(request, update, scope, gate_passed=True)
                with patch("privoke.v1.parameters_pb2_grpc.ParamUpdateServiceStub") as updater:
                    emit_training_update("unused", "fixture", update, extra)
                wire = updater.return_value.SubmitParameterUpdate.call_args.args[0]
                self.assertLessEqual(len(wire.metadata), 64)
                self.assertTrue(all(len(value.encode()) <= 2048 for value in wire.metadata.values()))
                print(json.dumps({"offline_fixture": "taxonomy_policy_publication", "scope": scope,
                    "actual_train_rows": 64, "guard_rows": 16, "unprojected_entries": len(original_union),
                    "published_entries": len(wire.metadata), "max_value_bytes": max(len(v.encode()) for v in wire.metadata.values())}))


if __name__ == "__main__":
    unittest.main()
