from __future__ import annotations

import sys
import unittest
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]
for path in (
    SERVICE_ROOT / "src",
    SERVICE_ROOT / "generated",
    REPO_ROOT / "shared/python",
):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from privoke_contracts.classification import (
    Category,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)
from training.trainer import train_parameter_batch
from training.types import BatchTrainingConfig, BatchTrainingExample


class _GradientRuntime:
    def __init__(self):
        self.calls = []

    def compute_semantic_gradients(self, examples, **options):
        self.calls.append((tuple(examples), options))
        return {
            "model_id": options["model_id"],
            "base_version": "v1",
            "gradients": {"head.sensitivity.bias": (0.01, 0.0, 0.0, -0.01)},
            "shapes": {"head.sensitivity.bias": (4,)},
            "metrics": {
                "examples": float(len(examples)),
                "average_loss": 0.25,
                "exact_match_rate": 0.5,
                "total_weight": sum(item.weight for item in examples),
            },
            "metadata": {
                "strategy": "transformer_classification_head_finetune",
                "base_parameter_fingerprint": "base",
                "updated_parameter_fingerprint": "updated",
            },
        }


class TransformerTrainingTests(unittest.TestCase):
    def test_training_delegates_model_execution_and_descent_to_runtime(self) -> None:
        target = initialise_unpacked(
            Sensitivity.S3,
            Visibility.P4,
            [Category.HEALTH],
        )
        runtime = _GradientRuntime()
        update = train_parameter_batch(
            model_id="privoke-balanced",
            new_examples=[BatchTrainingExample("my private diagnosis", target)],
            config=BatchTrainingConfig(transformations_per_example=0),
            runtime_client=runtime,
        )

        self.assertEqual(len(runtime.calls), 1)
        examples, options = runtime.calls[0]
        self.assertEqual([item.text for item in examples], ["my private diagnosis"])
        self.assertEqual(options["model_id"], "privoke-balanced")
        self.assertEqual(update.base_version, "v1")
        self.assertEqual(update.metadata["base_parameter_fingerprint"], "base")
        self.assertEqual(update.metadata["updated_parameter_fingerprint"], "updated")

    def test_training_sends_transformed_examples_as_one_runtime_batch(self) -> None:
        runtime = _GradientRuntime()
        examples = [
            BatchTrainingExample("first"),
            BatchTrainingExample("second"),
        ]
        update = train_parameter_batch(
            model_id="privoke-balanced",
            new_examples=examples,
            config=BatchTrainingConfig(transformations_per_example=1),
            runtime_client=runtime,
        )

        self.assertEqual(len(runtime.calls), 1)
        self.assertEqual(len(runtime.calls[0][0]), 4)
        self.assertEqual(update.metrics["examples"], 4.0)
        self.assertEqual(update.metrics["new_examples"], 2.0)


if __name__ == "__main__":
    unittest.main()
