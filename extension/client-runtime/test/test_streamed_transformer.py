from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
SHARED_ROOT = REPO_ROOT / "shared/python"
for path in (PACKAGE_ROOT, SHARED_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.LLM.privoke.parameter_stream import ParameterSnapshot
from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel


class StreamedTransformerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        artifact = json.loads(
            (REPO_ROOT / "models/privoke-baseline.json").read_text(encoding="utf-8")
        )
        cls.model = StreamedTransformerPrivacyModel(
            ParameterSnapshot(
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
        )

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


if __name__ == "__main__":
    unittest.main()
