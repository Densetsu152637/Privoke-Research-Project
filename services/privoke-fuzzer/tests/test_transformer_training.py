from __future__ import annotations

import json
import sys
import types
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
    Classification,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)
from training.trainer import train_parameter_batch
from training.types import BatchTrainingConfig, BatchTrainingExample


class TransformerTrainingTests(unittest.TestCase):
    def test_training_produces_real_head_weight_deltas(self) -> None:
        artifact = json.loads(
            (REPO_ROOT / "models/privoke-baseline.json").read_text(encoding="utf-8")
        )
        snapshot = types.SimpleNamespace(
            model_id=artifact["model_id"],
            version=artifact["version"],
            generated_at_unix=artifact["generated_at_unix"],
            parameters=[
                types.SimpleNamespace(
                    name=name,
                    values=tensor["values"],
                    shape=tensor["shape"],
                )
                for name, tensor in artifact["parameters"].items()
            ],
            metadata={
                **artifact["metadata"],
                "architecture": artifact["architecture"],
                "model_config": json.dumps(artifact["config"]),
                "trainable_parameters": ",".join(
                    name
                    for name, tensor in artifact["parameters"].items()
                    if tensor["trainable"]
                ),
            },
        )
        target = initialise_unpacked(
            Sensitivity.S3,
            Visibility.P4,
            [Category.HEALTH],
        )
        runtime = types.SimpleNamespace(
            classify=lambda *args, **kwargs: Classification()
        )

        update = train_parameter_batch(
            snapshot,
            [BatchTrainingExample("my private diagnosis", target)],
            config=BatchTrainingConfig(transformations_per_example=0),
            runtime_client=runtime,
        )

        self.assertEqual(set(update.gradients), {
            "head.sensitivity.weight",
            "head.sensitivity.bias",
            "head.visibility.weight",
            "head.visibility.bias",
            "head.category.weight",
            "head.category.bias",
        })
        self.assertGreater(
            sum(abs(value) for values in update.gradients.values() for value in values),
            0.0,
        )
        self.assertNotEqual(
            update.metadata["base_parameter_fingerprint"],
            update.metadata["updated_parameter_fingerprint"],
        )


if __name__ == "__main__":
    unittest.main()
