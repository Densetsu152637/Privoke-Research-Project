from __future__ import annotations

import importlib.util
import json
import sys
import unittest
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
    StreamedModelCache,
    StreamedTransformerPrivacyModel,
)


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
        },
    )


if __name__ == "__main__":
    unittest.main()
