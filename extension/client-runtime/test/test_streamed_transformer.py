from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
SHARED_ROOT = REPO_ROOT / "shared/python"
for path in (PACKAGE_ROOT, SHARED_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.LLM.privoke.parameter_stream import ParameterSnapshot
from src.LLM.privoke.streamed_model import (
    GLOBAL_STREAMED_MODEL_CACHE,
    StreamedModelCache,
    StreamedTransformerPrivacyModel,
)
from src.LLM.privoke.training import SemanticTrainingExample, compute_semantic_gradients
from src.classification import Category, Sensitivity, Visibility, initialise_unpacked


class StreamedTransformerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        artifact = json.loads(
            (REPO_ROOT / "models/privoke-baseline.json").read_text(encoding="utf-8")
        )
        cls.model = StreamedTransformerPrivacyModel(_snapshot(artifact))

    def test_executes_streamed_transformer_weights(self) -> None:
        results = self.model.classify("my diagnosis is cancer")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].classification.sensitivity().name, "S3")
        self.assertIn("HEALTH", [item.name for item in results[0].classification.categories()])
        self.assertEqual(
            results[0].metadata["classifier"],
            "privoke_streamed_transformer",
        )

    def test_clean_prompt_has_no_semantic_result(self) -> None:
        self.assertEqual(
            self.model.classify("write a friendly email about tomorrow meeting"),
            [],
        )

    def test_clean_semantic_rpc_retains_exact_used_identity_without_a_finding(self):
        from privoke.v1 import runtime_pb2
        from src.hosting.grpc_server import PrivokeRuntimeService
        from src.LLM.privoke_classifier import PriVokeClassifier

        snapshot = self.model.snapshot
        request = runtime_pb2.AnalyzePromptRequest(
            text="write a friendly email about tomorrow meeting", request_id="clean-identity",
            semantic_model_id=snapshot.model_id, layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC],
            metadata={"privoke.semantic.model_id": "spoofed"})
        with patch("src.pipeline.get_llm_choice", return_value=PriVokeClassifier(model_id=snapshot.model_id)), \
                patch("src.pipeline._streamed_model_for_semantic_detector", return_value=self.model), \
                patch.object(self.model.model, "predict", wraps=self.model.model.predict) as predict:
            response = PrivokeRuntimeService().AnalyzePrompt(request, None)
        self.assertEqual(predict.call_count, 1)
        self.assertEqual(response.error, "")
        self.assertEqual(response.action, "ALLOW")
        self.assertEqual(len(response.layers), 1)
        self.assertEqual(response.layers[0].layer, runtime_pb2.DETECTION_LAYER_SEMANTIC)
        self.assertEqual(response.layers[0].status, "ok")
        self.assertEqual(len(response.layers[0].results), 0)
        self.assertEqual({key: response.metadata["privoke.semantic." + key] for key in
                          ("model_id", "model_version", "artifact_checksum", "parameter_fingerprint")},
                         {"model_id": snapshot.model_id, "model_version": snapshot.version,
                          "artifact_checksum": snapshot.metadata["artifact_checksum"],
                          "parameter_fingerprint": snapshot.fingerprint})

    def test_failed_semantic_rpc_cannot_echo_caller_identity(self):
        from privoke.v1 import runtime_pb2
        from src.hosting.grpc_server import PrivokeRuntimeService

        request = runtime_pb2.AnalyzePromptRequest(text="synthetic", request_id="failed-identity",
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC], semantic_model_id="privoke-baseline",
            metadata={"privoke.semantic.model_id": "spoofed", "caller_tag": "retained"})
        with patch("src.pipeline.get_llm_choice", side_effect=RuntimeError("synthetic unavailable")):
            response = PrivokeRuntimeService().AnalyzePrompt(request, None)
        self.assertEqual(len(response.layers), 1)
        self.assertEqual(response.layers[0].status, "error")
        self.assertFalse(any(key.startswith("privoke.semantic.") for key in response.metadata))

    def test_all_quality_profiles_execute_with_their_expected_capacity(self) -> None:
        expected = {
            "privoke-efficient": (1, 2),
            "privoke-balanced": (2, 4),
            "privoke-quality": (3, 4),
        }
        for model_id, (layers, heads) in expected.items():
            with self.subTest(model_id=model_id):
                artifact = json.loads(
                    (REPO_ROOT / f"models/{model_id}.json").read_text(encoding="utf-8")
                )
                model = StreamedTransformerPrivacyModel(_snapshot(artifact))
                self.assertEqual(model.model.config.num_layers, layers)
                self.assertEqual(model.model.config.num_attention_heads, heads)
                self.assertEqual(
                    model.classify("write a friendly email about tomorrow meeting"),
                    [],
                )
                sensitive_result = model.classify("my diagnosis is cancer")[0]
                self.assertEqual(
                    sensitive_result.classification.sensitivity().name,
                    "S3",
                )

    def test_runtime_cache_coalesces_parameter_fetches(self) -> None:
        fetch_count = 0

        def fetch():
            nonlocal fetch_count
            fetch_count += 1
            return self.model.snapshot

        streamer = SimpleNamespace(
            target="streaming:50051",
            model_id=self.model.snapshot.model_id,
            fetch=fetch,
        )
        cache = StreamedModelCache(refresh_interval_seconds=30.0)

        cache.classify("my diagnosis is cancer", streamer)
        cache.classify("my diagnosis is cancer", streamer)

        self.assertEqual(fetch_count, 1)

    def test_cached_snapshot_cannot_hide_invalid_configuration(self):
        cache = StreamedModelCache()
        snapshot = self.model.snapshot
        cache._model_for_snapshot(snapshot)
        config = json.loads(snapshot.metadata["model_config"])
        config["vocab_size"] = 1
        malformed = replace(snapshot, metadata={
            **snapshot.metadata, "model_config": json.dumps(config),
        })
        with self.assertRaises(ValueError):
            cache._model_for_snapshot(malformed)

    def test_cache_reconstructs_on_contract_change_but_ignores_provenance(self):
        cache = StreamedModelCache(refresh_interval_seconds=0)
        snapshot = self.model.snapshot
        original = cache._model_for_snapshot(snapshot)
        provenance = replace(snapshot, metadata={**snapshot.metadata, "served_by": "new-server"})
        self.assertIs(cache._model_for_snapshot(provenance), original)
        config = json.loads(snapshot.metadata["model_config"])
        config["category_threshold"] = 0.99
        changed = replace(snapshot, metadata={
            **snapshot.metadata, "model_config": json.dumps(config),
        })
        rebuilt = cache._model_for_snapshot(changed)
        self.assertIsNot(rebuilt, original)
        self.assertEqual(rebuilt.model.config.category_threshold, 0.99)
        streamer = SimpleNamespace(target="streaming:50051", model_id=snapshot.model_id, fetch=lambda: snapshot)
        initial = cache._model_for_streamer(streamer)
        streamer.fetch = lambda: changed
        self.assertIsNot(cache._model_for_streamer(streamer), initial)
        for field in ("architecture", "trainable_parameters"):
            altered = replace(snapshot, metadata={**snapshot.metadata, field: "changed"})
            self.assertNotEqual(snapshot.cache_key, altered.cache_key)

    def test_latest_alias_accepts_the_resolved_model_id(self) -> None:
        streamer = SimpleNamespace(
            target="streaming:50051",
            model_id="latest",
            fetch=lambda: self.model.snapshot,
        )
        cache = StreamedModelCache(refresh_interval_seconds=30.0)

        results = cache.classify("my diagnosis is cancer", streamer)

        self.assertEqual(len(results), 1)

    def test_unavailable_accelerator_falls_back_to_cpu(self) -> None:
        if importlib.util.find_spec("torch") is None:
            model = StreamedTransformerPrivacyModel(self.model.snapshot)
        else:
            with (
                patch("torch.cuda.is_available", return_value=False),
                patch("torch.backends.mps.is_available", return_value=False),
            ):
                model = StreamedTransformerPrivacyModel(self.model.snapshot)

        self.assertEqual(model.model.compute_device, "cpu")

    def test_runtime_computes_versioned_head_gradients_from_cached_model(self) -> None:
        target = initialise_unpacked(
            Sensitivity.S3,
            Visibility.P4,
            [Category.HEALTH],
        )
        with patch.object(
            GLOBAL_STREAMED_MODEL_CACHE,
            "model_for_training",
            return_value=self.model,
        ):
            batch = compute_semantic_gradients(
                [SemanticTrainingExample("my private diagnosis", target, 1.0)],
                model_id=self.model.snapshot.model_id,
                learning_rate=0.03,
                max_gradient=0.05,
            )

        self.assertEqual(batch.base_version, self.model.snapshot.version)
        self.assertEqual(
            set(batch.gradients),
            {
                "head.sensitivity.weight",
                "head.sensitivity.bias",
                "head.visibility.weight",
                "head.visibility.bias",
                "head.category.weight",
                "head.category.bias",
            },
        )
        self.assertGreater(
            sum(abs(value) for values in batch.gradients.values() for value in values),
            0.0,
        )
        self.assertNotEqual(
            batch.metadata["base_parameter_fingerprint"],
            batch.metadata["updated_parameter_fingerprint"],
        )


def _snapshot(artifact: dict) -> ParameterSnapshot:
    return ParameterSnapshot(
        model_id=artifact["model_id"],
        version=artifact["version"],
        generated_at_unix=artifact["generated_at_unix"],
        parameters={
            name: tuple(tensor["values"])
            for name, tensor in artifact["parameters"].items()
        },
        shapes={
            name: tuple(tensor["shape"])
            for name, tensor in artifact["parameters"].items()
        },
        metadata={
            "architecture": artifact["architecture"],
            "model_config": json.dumps(artifact["config"]),
            "artifact_checksum": artifact["checksum"],
            "trainable_parameters": ",".join(
                name
                for name, tensor in artifact["parameters"].items()
                if tensor["trainable"]
            ),
        },
    )


if __name__ == "__main__":
    unittest.main()
