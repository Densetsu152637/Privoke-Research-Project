from __future__ import annotations

import json
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


class PresenceRuntimeTests(unittest.TestCase):
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

    def test_binary_gradient_train_and_holdout_group_guards(self):
        model = StreamedPresenceModel(_snapshot())
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
        with patch(
            "src.LLM.privoke.presence_training.GLOBAL_STREAMED_MODEL_CACHE.presence_model_for_training",
            return_value=model,
        ):
            batch = compute_presence_gradients(
                training,
                model_id=model.model_id,
                learning_rate=0.1,
                max_gradient=0.2,
            )
        updated = apply_parameter_update(
            artifact,
            base_version=artifact["version"],
            deltas=batch.gradients,
            source_id="presence-runtime-test",
        )
        self.assertEqual(updated["parameters"]["head.presence.bias"]["shape"], [1])
        self.assertTrue(all(name.startswith("head.presence.") for name in batch.gradients))
        published_parameters = {
            name: tuple(tensor["values"])
            for name, tensor in updated["parameters"].items()
        }
        published_shapes = {
            name: tuple(tensor["shape"])
            for name, tensor in updated["parameters"].items()
        }
        self.assertEqual(
            parameter_fingerprint(published_parameters, published_shapes),
            batch.metadata["candidate_parameter_fingerprint"],
        )

    def test_detection_rpc_returns_only_presence_and_rejects_contextual_model(self):
        model = StreamedPresenceModel(_snapshot())
        request = runtime_pb2.DetectAnnotationPresenceRequest(
            request_id="presence-1",
            text="diagnosis mail",
            model_id="privoke-presence-efficient",
        )
        with (
            patch("src.hosting.grpc_server.ModelParameterStreamer"),
            patch.object(
                StreamedModelCache,
                "presence_model_for_streamer",
                return_value=model,
            ),
        ):
            response = PrivokeRuntimeService().DetectAnnotationPresence(request, None)
        self.assertFalse(response.error)
        self.assertEqual(response.model_id, model.model_id)
        self.assertEqual(response.model_version, model.version)
        self.assertIn(response.predicted_label, (
            runtime_pb2.ANNOTATION_PRESENCE_PRESENT,
            runtime_pb2.ANNOTATION_PRESENCE_ABSENT,
        ))
        self.assertAlmostEqual(response.probability, model.predict_probability(request.text))
        self.assertTrue(response.parameter_fingerprint)
        self.assertEqual(response.artifact_checksum, model.snapshot.metadata["artifact_checksum"])

        wrong_request = runtime_pb2.DetectAnnotationPresenceRequest(
            request_id=request.request_id,
            text=request.text,
            model_id="privoke-balanced",
        )
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
        )
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
        )
        fake_batch = type("Batch", (), {
            "model_id": valid.model_id,
            "base_version": "v1",
            "gradients": {"head.presence.bias": (0.1,)},
            "shapes": {"head.presence.bias": (1,)},
            "metrics": {"examples": 2.0},
            "metadata": {"task": "annotation_presence"},
        })()
        with patch(
            "src.hosting.grpc_server.compute_presence_gradients",
            return_value=fake_batch,
        ) as compute:
            response = PrivokeRuntimeService().ComputePresenceGradients(valid, None)
        self.assertFalse(response.error)
        converted = compute.call_args.args[0]
        self.assertEqual([item.target for item in converted], [True, False])
        self.assertEqual([item.group_id for item in converted], ["g1", "g2"])
        self.assertEqual(response.gradients[0].shape, [1])


if __name__ == "__main__":
    unittest.main()
