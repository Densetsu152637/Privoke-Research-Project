from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
for path in (
    PACKAGE_ROOT,
    PACKAGE_ROOT / "generated",
    REPO_ROOT / "shared/python",
):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from privoke.v1 import runtime_pb2
from src.hosting.grpc_server import PrivokeRuntimeService


class RuntimeTrainingRpcTests(unittest.TestCase):
    def test_returns_runtime_owned_versioned_gradient_batch(self) -> None:
        batch = SimpleNamespace(
            model_id="privoke-balanced",
            base_version="v1",
            gradients={"head.sensitivity.bias": (0.01, 0.0, 0.0, -0.01)},
            shapes={"head.sensitivity.bias": (4,)},
            metrics={"examples": 1.0},
            metadata={"model_cache_key": "privoke-balanced:v1:fingerprint"},
        )
        request = runtime_pb2.ComputeSemanticGradientsRequest(
            request_id="training-1",
            model_id="privoke-balanced",
            examples=[
                runtime_pb2.RuntimeTrainingExample(
                    text="my private diagnosis",
                    target=runtime_pb2.RuntimeClassification(packed=3),
                    has_target=True,
                    weight=1.0,
                )
            ],
            learning_rate=0.03,
            max_gradient=0.05,
        )

        with patch(
            "src.hosting.grpc_server.compute_semantic_gradients",
            return_value=batch,
        ) as compute:
            response = PrivokeRuntimeService().ComputeSemanticGradients(request, None)

        self.assertFalse(response.error)
        self.assertEqual(response.base_version, "v1")
        self.assertEqual(response.gradients[0].shape, [4])
        self.assertEqual(compute.call_args.kwargs["model_id"], "privoke-balanced")

    def test_rejects_empty_training_batch(self) -> None:
        response = PrivokeRuntimeService().ComputeSemanticGradients(
            runtime_pb2.ComputeSemanticGradientsRequest(
                model_id="privoke-balanced",
                learning_rate=0.03,
                max_gradient=0.05,
            ),
            None,
        )

        self.assertIn("At least one", response.error)


if __name__ == "__main__":
    unittest.main()
