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
            executions=(("training", 1), ("base_heldout", 1), ("candidate_heldout", 1)),
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
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC],
            heldout_examples=[runtime_pb2.RuntimeTrainingExample(text="heldout", weight=1)],
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
        self.assertEqual([item.phase for item in response.executions], ["training", "base_heldout", "candidate_heldout"])
        self.assertTrue(all(item.layer == runtime_pb2.DETECTION_LAYER_SEMANTIC and item.status == "ok"
                            and item.examples == 1 and not item.error for item in response.executions))

    def test_both_endpoints_reject_missing_extra_wrong_layers_before_model_execution(self):
        service = PrivokeRuntimeService()
        for method in (service.ComputeSemanticGradients, service.ComputeUnderlyingModelGradients):
            for layers in ([], [runtime_pb2.DETECTION_LAYER_REGEX],
                           [runtime_pb2.DETECTION_LAYER_SEMANTIC, runtime_pb2.DETECTION_LAYER_NER],
                           [runtime_pb2.DETECTION_LAYER_SEMANTIC] * 2):
                request = runtime_pb2.ComputeSemanticGradientsRequest(model_id="privoke-balanced",
                    examples=[runtime_pb2.RuntimeTrainingExample(text="x", weight=1)], layers=layers,
                    heldout_examples=[runtime_pb2.RuntimeTrainingExample(text="heldout", weight=1)])
                response = method(request, None)
                self.assertIn("semantic-only", response.error)
                self.assertFalse(response.executions)
            request.layers[:] = [runtime_pb2.DETECTION_LAYER_SEMANTIC]
            request.ClearField("heldout_examples")
            response = method(request, None)
            self.assertIn("heldout", response.error)
            self.assertFalse(response.executions)

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
