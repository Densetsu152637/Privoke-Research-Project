from __future__ import annotations

import json
import math
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
for path in (PACKAGE_ROOT, PACKAGE_ROOT / "generated", REPO_ROOT / "shared/python"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from privoke_model.artifact import apply_parameter_update, artifact_checksum
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.presence import (
    BLOCK_SIZE,
    NORMALIZATION,
    PRESENCE_ARCHITECTURE,
    PRESENCE_TASK,
    PROFILE_MAX_FEATURES,
    SparsePresenceModel,
    TOKEN_PATTERN,
    presence_tensor_shapes,
)
from src.LLM.privoke.parameter_stream import ParameterSnapshot
from src.LLM.privoke.presence_model import StreamedPresenceModel
from src.LLM.privoke.presence_training import (
    PresenceTrainingExample,
    compute_presence_gradients,
)
from src.LLM.privoke.streamed_model import (
    StreamedModelCache,
    StreamedTransformerPrivacyModel,
)
from privoke.v1 import runtime_pb2
from src.hosting.grpc_server import PrivokeRuntimeService


def _artifact():
    profile = "efficient"
    common = {
        "max_features": PROFILE_MAX_FEATURES[profile],
        "sublinear_tf": True,
        "use_idf": True,
        "smooth_idf": True,
        "norm": "l2",
        "lowercase": False,
    }
    config = {
        "task": PRESENCE_TASK,
        "profile": profile,
        "threshold": 0.5,
        "normalization": NORMALIZATION,
        "column_order": ["word", "char"],
        "coefficient_block_size": BLOCK_SIZE,
        "branches": {
            "word": dict(
                common,
                analyzer="word",
                ngram_range=[1, 2],
                features=["mail", "diagnosis", "safe", "meeting"],
                token_pattern=TOKEN_PATTERN,
            ),
            "char": dict(
                common,
                analyzer="char",
                ngram_range=[3, 5],
                features=["mai", "ail", "dia", "agn", "saf", "afe"],
            ),
        },
    }
    parameters = {}
    for name, shape in presence_tensor_shapes(config).items():
        params = [1.0] * shape[0] if name.startswith("features.") else [0.0] * shape[0]
        if name == "head.presence.weight.000":
            params[0:4] = [0.75, 0.75, -0.75, -0.75]
            params[4:10] = [0.5, 0.5, 0.5, -0.5, -0.5, -0.5]
        parameters[name] = {
            "shape": list(shape),
            "values": params,
            "trainable": name.startswith("head.presence."),
        }
    payload = {
        "schema_version": 1,
        "model_id": "privoke-presence-efficient",
        "version": "v1",
        "generated_at_unix": 1,
        "architecture": PRESENCE_ARCHITECTURE,
        "config": config,
        "parameters": parameters,
        "metadata": {},
    }
    payload["checksum"] = artifact_checksum(payload)
    return payload


def _snapshot(artifact=None):
    artifact = artifact or _artifact()
    return ParameterSnapshot(
        model_id=artifact["model_id"],
        version=artifact["version"],
        generated_at_unix=artifact["generated_at_unix"],
        parameters={name: tuple(tensor["values"]) for name, tensor in artifact["parameters"].items()},
        shapes={name: tuple(tensor["shape"]) for name, tensor in artifact["parameters"].items()},
        metadata={
            "architecture": artifact["architecture"],
            "model_config": json.dumps(artifact["config"]),
            "artifact_checksum": artifact["checksum"],
            "trainable_parameters": ",".join(
                name for name, tensor in artifact["parameters"].items() if tensor["trainable"]
            ),
        },
    )


def _assert_started(test_case, timer, model):
    test_case.assertEqual(timer.call_count, 1)
    return model


class PresenceRuntimeTests(unittest.TestCase):
    def test_additive_presence_fields_keep_existing_wire_numbers(self):
        messages=runtime_pb2.DESCRIPTOR.message_types_by_name
        self.assertEqual(messages["DetectAnnotationPresenceRequest"].fields_by_name["layers"].number,4)
        self.assertEqual(messages["DetectAnnotationPresenceResponse"].fields_by_name["executions"].number,11)
        self.assertEqual(messages["ComputePresenceGradientsRequest"].fields_by_name["layers"].number,7)
        self.assertEqual(messages["ComputePresenceGradientsResponse"].fields_by_name["executions"].number,8)
        legacy=runtime_pb2.DetectAnnotationPresenceRequest.FromString(b"\x0a\x03old")
        self.assertEqual(legacy.request_id,"old")
        self.assertFalse(legacy.layers)

    def test_presence_selection_and_nonempty_guard_are_required_before_compute(self):
        for layers in ([], [runtime_pb2.DETECTION_LAYER_REGEX], [4, 2], [4, 4]):
            with self.subTest(layers=layers), patch("src.hosting.grpc_server.ModelParameterStreamer") as stream, patch("src.hosting.grpc_server.compute_presence_gradients") as compute:
                inference = PrivokeRuntimeService().DetectAnnotationPresence(
                    runtime_pb2.DetectAnnotationPresenceRequest(request_id="p", text="clean", model_id="privoke-presence-efficient", layers=layers), None)
                training = PrivokeRuntimeService().ComputePresenceGradients(
                    runtime_pb2.ComputePresenceGradientsRequest(request_id="t", model_id="privoke-presence-efficient", layers=layers), None)
                for response in (inference, training):
                    self.assertIn("semantic-only", response.error)
                    self.assertFalse(response.executions)
                stream.assert_not_called()
                compute.assert_not_called()
        with patch("src.hosting.grpc_server.compute_presence_gradients") as compute:
            response = PrivokeRuntimeService().ComputePresenceGradients(
                runtime_pb2.ComputePresenceGradientsRequest(request_id="t", model_id="privoke-presence-efficient", layers=[4]), None)
            self.assertIn("heldout", response.error)
            compute.assert_not_called()

    def test_real_presence_computation_records_training_and_both_guard_phases(self):
        model = StreamedPresenceModel(_snapshot())
        def row(text, label, group):
            return runtime_pb2.PresenceTrainingExample(text=text, target=label, group_id=group, weight=1)
        request = runtime_pb2.ComputePresenceGradientsRequest(request_id="actual", model_id=model.model_id,
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC], learning_rate=.03, max_gradient=.05,
            examples=[row("diagnosis mail",2,"t1"), row("safe meeting",1,"t2")],
            heldout_examples=[row("diagnosis safe",2,"h1"), row("mail meeting",1,"h2")])
        from src.LLM.privoke import presence_training
        with patch.object(presence_training.GLOBAL_STREAMED_MODEL_CACHE,"presence_model_for_training",return_value=model), patch.object(presence_training,"_heldout_metrics", wraps=presence_training._heldout_metrics) as guards:
            response = PrivokeRuntimeService().ComputePresenceGradients(request, None)
        self.assertFalse(response.error)
        self.assertEqual(guards.call_count, 2)
        self.assertIs(guards.call_args_list[0].args[0], model.model)
        self.assertIsNot(guards.call_args_list[1].args[0], model.model)
        self.assertEqual([(e.phase,e.layer,e.status,e.examples,e.error) for e in response.executions],
            [(phase,4,"ok",2,"") for phase in ("training","base_heldout","candidate_heldout")])
        self.assertEqual(set(g.name for g in response.gradients), {"head.presence.bias","head.presence.weight.000"})

    def test_stream_wrapper_rejects_contextual_artifact(self):
        snapshot = _snapshot()
        wrong = replace(snapshot, metadata={**snapshot.metadata, "architecture": "privoke_tiny_transformer_v1"})
        with self.assertRaisesRegex(ValueError, "not an annotation-presence"):
            StreamedPresenceModel(wrong)
        with self.assertRaisesRegex(ValueError, "not a supported PriVoke transformer"):
            StreamedTransformerPrivacyModel(snapshot)
        wrong_profile = replace(snapshot, model_id="privoke-presence-quality")
        with self.assertRaisesRegex(ValueError, "does not match its profile"):
            StreamedPresenceModel(wrong_profile)
        wrong_manifest = replace(
            snapshot,
            metadata={
                **snapshot.metadata,
                "trainable_parameters": snapshot.metadata["trainable_parameters"] + ",unknown",
            },
        )
        with self.assertRaisesRegex(ValueError, "trainable manifest"):
            StreamedPresenceModel(wrong_manifest)
        missing_checksum = replace(
            snapshot,
            metadata={key: value for key, value in snapshot.metadata.items() if key != "artifact_checksum"},
        )
        with self.assertRaisesRegex(ValueError, "artifact checksum"):
            StreamedPresenceModel(missing_checksum)

    def test_presence_cache_is_separate_and_coalesces_only_presence_models(self):
        cache = StreamedModelCache(refresh_interval_seconds=30)
        snapshot = _snapshot()
        calls = 0

        def fetch():
            nonlocal calls
            calls += 1
            return snapshot

        streamer = type("Streamer", (), {"target": "stream:50051", "model_id": snapshot.model_id, "fetch": staticmethod(fetch)})()
        first = cache.presence_model_for_streamer(streamer)
        second = cache.presence_model_for_streamer(streamer)
        self.assertIs(first, second)
        self.assertEqual(calls, 1)
        self.assertEqual(cache._models, {})
        self.assertEqual(len(cache._presence_models), 1)
        original_probability = first.predict_probability("diagnosis mail")

        updated = _artifact()
        updated["version"] = "v2"
        updated["config"]["threshold"] = 0.8
        updated["parameters"]["head.presence.bias"]["values"] = [1.0]
        updated["checksum"] = artifact_checksum(
            {key: value for key, value in updated.items() if key != "checksum"}
        )
        snapshot = _snapshot(updated)
        refreshed = cache.presence_model_for_streamer(streamer, force_refresh=True)
        self.assertIsNot(refreshed, first)
        self.assertEqual(refreshed.version, "v2")
        self.assertEqual(refreshed.threshold, 0.8)
        self.assertNotEqual(refreshed.predict_probability("diagnosis mail"), original_probability)
        self.assertEqual(first.predict_probability("diagnosis mail"), original_probability)
        self.assertEqual(calls, 2)

        checksum_changed = _artifact()
        checksum_changed["version"] = "v2"
        checksum_changed["metadata"]["source_revision"] = "new-provenance"
        checksum_changed["config"]["threshold"] = 0.8
        checksum_changed["parameters"]["head.presence.bias"]["values"] = [1.0]
        checksum_changed["checksum"] = artifact_checksum(
            {key: value for key, value in checksum_changed.items() if key != "checksum"}
        )
        old_checksum = refreshed.snapshot.metadata["artifact_checksum"]
        old_refreshed_probability = refreshed.predict_probability("diagnosis mail")
        snapshot = _snapshot(checksum_changed)
        provenance_refreshed = cache.presence_model_for_streamer(streamer, force_refresh=True)
        self.assertIsNot(provenance_refreshed, refreshed)
        self.assertEqual(provenance_refreshed.snapshot.metadata["artifact_checksum"], checksum_changed["checksum"])
        self.assertNotEqual(provenance_refreshed.snapshot.metadata["artifact_checksum"], old_checksum)
        self.assertEqual(provenance_refreshed.predict_probability("diagnosis mail"), old_refreshed_probability)
        self.assertEqual(refreshed.predict_probability("diagnosis mail"), old_refreshed_probability)
        self.assertEqual(calls, 3)

    def test_binary_gradient_train_and_holdout_group_guards(self):
        artifact = _artifact()
        artifact["version"] = "release-v3+train.7"
        artifact["checksum"] = artifact_checksum(
            {key: value for key, value in artifact.items() if key != "checksum"}
        )
        snapshot = _snapshot(artifact)
        snapshot = replace(
            snapshot,
            metadata={
                **snapshot.metadata,
                "source_revision": "source-sha",
                "protocol_sha256": "protocol-sha",
                "prepared_manifest_sha256": "prepared-sha",
                "train_sha256": "train-sha",
                "validation_sha256": "validation-sha",
            },
        )
        model = StreamedPresenceModel(snapshot)
        training = (
            PresenceTrainingExample("mail meeting", False, 1.0, "train-a"),
            PresenceTrainingExample("diagnosis mail", True, 1.0, "train-b"),
        )
        heldout = (
            PresenceTrainingExample("safe meeting", False, 1.0, "test-a"),
            PresenceTrainingExample("diagnosis safe", True, 1.0, "test-b"),
        )
        with patch(
            "src.LLM.privoke.presence_training.GLOBAL_STREAMED_MODEL_CACHE.presence_model_for_training",
            return_value=model,
        ):
            batch = compute_presence_gradients(
                training,
                model_id=model.model_id,
                learning_rate=0.1,
                max_gradient=0.2,
                heldout_examples=heldout,
            )
        self.assertEqual(set(batch.gradients), {"head.presence.weight.000", "head.presence.bias"})
        self.assertIn("candidate_heldout_present_recall", batch.metrics)
        self.assertIn("candidate_heldout_absent_specificity", batch.metrics)
        self.assertEqual(batch.metadata["profile"], "efficient")
        self.assertEqual(batch.metadata["release_version"], "release-v3")
        self.assertEqual(batch.metadata["training_revision"], "7")
        self.assertEqual(batch.metadata["prepared_manifest_sha256"], "prepared-sha")
        self.assertNotEqual(
            batch.metadata["base_parameter_fingerprint"],
            batch.metadata["updated_parameter_fingerprint"],
        )

        for invalid_heldout in (
            (PresenceTrainingExample("diagnosis safe", True, 1.0, "train-b"),
             PresenceTrainingExample("safe meeting", False, 1.0, "test-b")),
            (PresenceTrainingExample("diagnosis mail", True, 1.0, "test-a"),
             PresenceTrainingExample("safe meeting", False, 1.0, "test-b")),
        ):
            with patch(
                "src.LLM.privoke.presence_training.GLOBAL_STREAMED_MODEL_CACHE.presence_model_for_training",
                return_value=model,
            ), self.assertRaises(ValueError):
                compute_presence_gradients(
                    training,
                    model_id=model.model_id,
                    learning_rate=0.1,
                    max_gradient=0.2,
                    heldout_examples=invalid_heldout,
                )

        invalid_weight = (
            PresenceTrainingExample("mail meeting", False, True, "train-a"),
            PresenceTrainingExample("diagnosis mail", True, 1.0, "train-b"),
        )
        with patch(
            "src.LLM.privoke.presence_training.GLOBAL_STREAMED_MODEL_CACHE.presence_model_for_training",
            return_value=model,
        ), self.assertRaisesRegex(ValueError, "weights"):
            compute_presence_gradients(
                invalid_weight,
                model_id=model.model_id,
                learning_rate=0.1,
                max_gradient=0.2,
            )

    def test_candidate_gradient_matches_artifact_publication_rounding(self):
        artifact = _artifact()
        model = StreamedPresenceModel(_snapshot(artifact))
        training = (
            PresenceTrainingExample("mail meeting", False, 1.0, "train-a"),
            PresenceTrainingExample("diagnosis mail", True, 1.0, "train-b"),
        )
        heldout = (
            PresenceTrainingExample("safe meeting", False, 1.0, "test-a"),
            PresenceTrainingExample("diagnosis safe", True, 1.0, "test-b"),
        )
        with patch(
            "src.LLM.privoke.presence_training.GLOBAL_STREAMED_MODEL_CACHE.presence_model_for_training",
            return_value=model,
        ):
            batch = compute_presence_gradients(
                training,
                model_id=model.model_id,
                learning_rate=0.1,
                max_gradient=0.2,
                heldout_examples=heldout,
            )
        updated = apply_parameter_update(
            artifact,
            base_version=artifact["version"],
            deltas=batch.gradients,
            source_id="presence-runtime-test",
        )
        self.assertEqual(updated["parameters"]["head.presence.bias"]["shape"], [1])
        self.assertTrue(all(name.startswith("head.presence.") for name in batch.gradients))
        reloaded_model = SparsePresenceModel.from_artifact(updated)
        self.assertEqual(
            parameter_fingerprint(reloaded_model.parameters, reloaded_model.shapes),
            batch.metadata["candidate_parameter_fingerprint"],
        )
        predictions = [
            reloaded_model.predict_probability(item.text) >= reloaded_model.threshold
            for item in heldout
        ]
        probabilities = [reloaded_model.predict_probability(item.text) for item in heldout]
        expected_heldout_loss = math.fsum(
            -math.log(
                min(1.0 - 1e-15, max(1e-15, probability))
                if item.target
                else 1.0 - min(1.0 - 1e-15, max(1e-15, probability))
            ) * item.weight
            for probability, item in zip(probabilities, heldout)
        ) / math.fsum(item.weight for item in heldout)
        self.assertAlmostEqual(
            batch.metrics["candidate_heldout_average_loss"],
            expected_heldout_loss,
            places=12,
        )
        self.assertEqual(
            batch.metrics["candidate_heldout_exact_match_rate"],
            sum(predicted == item.target for predicted, item in zip(predictions, heldout)) / len(heldout),
        )
        self.assertEqual(
            batch.metrics["candidate_heldout_present_recall"],
            sum(predicted for predicted, item in zip(predictions, heldout) if item.target)
            / sum(item.target for item in heldout),
        )
        self.assertEqual(
            batch.metrics["candidate_heldout_absent_specificity"],
            sum(not predicted for predicted, item in zip(predictions, heldout) if not item.target)
            / sum(not item.target for item in heldout),
        )

    def test_detection_rpc_returns_only_presence_and_rejects_contextual_model(self):
        model = StreamedPresenceModel(_snapshot())
        request = runtime_pb2.DetectAnnotationPresenceRequest(
            request_id="presence-1",
            text="diagnosis mail",
            model_id="privoke-presence-efficient",
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC])
        with (
            patch("src.hosting.grpc_server.ModelParameterStreamer"),
            patch("src.hosting.grpc_server.time.perf_counter", side_effect=[10.0, 10.75]) as timer,
            patch.object(
                StreamedModelCache,
                "presence_model_for_streamer",
                side_effect=lambda streamer: _assert_started(self, timer, model),
            ),
        ):
            response = PrivokeRuntimeService().DetectAnnotationPresence(request, None)
        self.assertFalse(response.error)
        self.assertEqual([(e.layer,e.status,e.error) for e in response.executions], [(4,"ok","")])
        self.assertEqual(response.model_id, model.model_id)
        self.assertEqual(response.model_version, model.version)
        self.assertIn(response.predicted_label, (
            runtime_pb2.ANNOTATION_PRESENCE_PRESENT,
            runtime_pb2.ANNOTATION_PRESENCE_ABSENT,
        ))
        self.assertAlmostEqual(response.probability, model.predict_probability(request.text))
        self.assertAlmostEqual(response.elapsed_ms, 750.0)
        self.assertTrue(response.parameter_fingerprint)
        self.assertEqual(response.artifact_checksum, model.snapshot.metadata["artifact_checksum"])

        wrong_request = runtime_pb2.DetectAnnotationPresenceRequest(
            request_id=request.request_id,
            text=request.text,
            model_id="privoke-balanced",
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC])
        with patch("src.hosting.grpc_server.ModelParameterStreamer") as streamer:
            failed = PrivokeRuntimeService().DetectAnnotationPresence(wrong_request, None)
        self.assertIn("privoke-presence", failed.error)
        streamer.assert_not_called()
        self.assertEqual(failed.predicted_label, runtime_pb2.ANNOTATION_PRESENCE_UNSPECIFIED)

    def test_gradient_rpc_rejects_unspecified_binary_label_and_converts_valid_targets(self):
        invalid = runtime_pb2.ComputePresenceGradientsRequest(
            request_id="presence-train-bad",
            model_id="privoke-presence-efficient",
            examples=[
                runtime_pb2.PresenceTrainingExample(
                    text="diagnosis mention", target=runtime_pb2.ANNOTATION_PRESENCE_UNSPECIFIED,
                    weight=1.0, group_id="group-a",
                )
            ],
            learning_rate=0.1,
            max_gradient=0.2,
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC], heldout_examples=[runtime_pb2.PresenceTrainingExample(text="held clean", target=runtime_pb2.ANNOTATION_PRESENCE_ABSENT, weight=1, group_id="h1"), runtime_pb2.PresenceTrainingExample(text="held present", target=runtime_pb2.ANNOTATION_PRESENCE_PRESENT, weight=1, group_id="h2")])
        rejected = PrivokeRuntimeService().ComputePresenceGradients(invalid, None)
        self.assertIn("PRESENT or ABSENT", rejected.error)
        self.assertFalse(rejected.gradients)

        valid = runtime_pb2.ComputePresenceGradientsRequest(
            request_id="presence-train-ok",
            model_id="privoke-presence-efficient",
            examples=[
                runtime_pb2.PresenceTrainingExample(text="a positive sample", target=runtime_pb2.ANNOTATION_PRESENCE_PRESENT, weight=1.0, group_id="g1"),
                runtime_pb2.PresenceTrainingExample(text="a negative sample", target=runtime_pb2.ANNOTATION_PRESENCE_ABSENT, weight=1.0, group_id="g2"),
            ],
            learning_rate=0.1,
            max_gradient=0.2,
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC], heldout_examples=[runtime_pb2.PresenceTrainingExample(text="held clean", target=runtime_pb2.ANNOTATION_PRESENCE_ABSENT, weight=1, group_id="h1"), runtime_pb2.PresenceTrainingExample(text="held present", target=runtime_pb2.ANNOTATION_PRESENCE_PRESENT, weight=1, group_id="h2")])
        fake_batch = type("Batch", (), {
            "model_id": valid.model_id,
            "base_version": "v1",
            "gradients": {"head.presence.bias": (0.1,)},
            "shapes": {"head.presence.bias": (1,)},
            "metrics": {"examples": 2.0},
            "metadata": {"task": "annotation_presence"},
            "executions": (("training",2),("base_heldout",2),("candidate_heldout",2)),
        })()
        with patch(
            "src.hosting.grpc_server.compute_presence_gradients",
            return_value=fake_batch,
        ) as compute:
            response = PrivokeRuntimeService().ComputePresenceGradients(valid, None)
        self.assertFalse(response.error)
        self.assertEqual([(e.phase,e.layer,e.status,e.examples,e.error) for e in response.executions], [(p,4,"ok",2,"") for p in ("training","base_heldout","candidate_heldout")])
        converted = compute.call_args.args[0]
        self.assertEqual([item.target for item in converted], [True, False])
        self.assertEqual([item.group_id for item in converted], ["g1", "g2"])
        self.assertEqual(response.gradients[0].shape, [1])


if __name__ == "__main__":
    unittest.main()
