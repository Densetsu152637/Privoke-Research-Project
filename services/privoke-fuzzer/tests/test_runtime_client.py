from __future__ import annotations

import sys
import threading
import time
import unittest
from concurrent import futures
from pathlib import Path

import grpc


SERVICE_ROOT = Path(__file__).resolve().parents[1]
for path in (SERVICE_ROOT / "src", SERVICE_ROOT / "generated"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from privoke.v1 import runtime_pb2, runtime_pb2_grpc
from runtime_client import PrivokeRuntimeClient, RuntimeAnalysisError, _validate_requested_execution
from training.types import BatchTrainingExample


class _RuntimeService(runtime_pb2_grpc.PrivokeRuntimeServiceServicer):
    def __init__(self):
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def AnalyzePrompt(self, request, context):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            time.sleep(0.02)
            return runtime_pb2.AnalyzePromptResponse(
                layers=[runtime_pb2.RuntimeLayerExecution(layer=runtime_pb2.DETECTION_LAYER_SEMANTIC, status="ok")],
                classification=runtime_pb2.RuntimeClassification(
                    sensitivity="S1",
                    visibility="PU",
                )
            )
        finally:
            with self._lock:
                self.active -= 1

    def ComputeSemanticGradients(self, request, context):
        from test_dual_runtime_contract import contract
        _, response = contract()
        response.request_id = request.request_id
        response.model_id = request.model_id
        response.base_version = "v1"
        self.training_layers = list(request.layers)
        return response


class RuntimeClientBatchTests(unittest.TestCase):
    def test_default_semantic_request_and_explicit_product_selection(self):
        client = PrivokeRuntimeClient("unused")
        self.assertEqual(list(client._request({"text": "test"}).layers), [runtime_pb2.DETECTION_LAYER_SEMANTIC])
        self.assertEqual(list(client._request({}, layers=["runtime"]).layers), [runtime_pb2.DETECTION_LAYER_RUNTIME])
        for layers in ([], (), [""], ["unknown"], "semantic"):
            with self.subTest(layers=layers), self.assertRaises(ValueError):
                client._request({}, layers=layers)

    def test_semantic_execution_contract_rejects_missing_extra_failed_and_skipped_layers(self):
        request = PrivokeRuntimeClient("unused")._request({})
        good = runtime_pb2.RuntimeLayerExecution(layer=runtime_pb2.DETECTION_LAYER_SEMANTIC, status="ok")
        for layers in ([], [good, runtime_pb2.RuntimeLayerExecution(layer=runtime_pb2.DETECTION_LAYER_REGEX, status="ok")],
                       [runtime_pb2.RuntimeLayerExecution(layer=runtime_pb2.DETECTION_LAYER_SEMANTIC, status="skipped")],
                       [runtime_pb2.RuntimeLayerExecution(layer=runtime_pb2.DETECTION_LAYER_SEMANTIC, status="error")]):
            with self.subTest(layers=layers), self.assertRaises(RuntimeAnalysisError):
                _validate_requested_execution(request, runtime_pb2.AnalyzePromptResponse(layers=layers))
        _validate_requested_execution(request, runtime_pb2.AnalyzePromptResponse(layers=[good]))

    def test_classify_many_reuses_a_bounded_concurrent_channel(self) -> None:
        service = _RuntimeService()
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
        runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(service, server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        try:
            client = PrivokeRuntimeClient(
                f"127.0.0.1:{port}",
                timeout_seconds=1.0,
                max_in_flight=2,
            )
            classifications = client.classify_many(
                ("one", "two", "three", "four"),
                model_id="privoke-baseline",
            )
        finally:
            server.stop(0).wait()

        self.assertEqual(
            [classification.sensitivity().name for classification in classifications],
            ["S1", "S1", "S1", "S1"],
        )
        self.assertEqual(service.max_active, 2)

    def test_compute_semantic_gradients_uses_runtime_training_rpc(self) -> None:
        service = _RuntimeService()
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
        runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(service, server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        try:
            batch = PrivokeRuntimeClient(
                f"127.0.0.1:{port}", timeout_seconds=1.0
            ).compute_semantic_gradients(
                [BatchTrainingExample("example")],
                heldout_examples=[BatchTrainingExample("held-out")],
                model_id="privoke-balanced",
                learning_rate=0.03,
                max_gradient=0.05,
            )
        finally:
            server.stop(0).wait()

        self.assertEqual(batch["base_version"], "v1")
        self.assertEqual(service.training_layers, [runtime_pb2.DETECTION_LAYER_SEMANTIC])
        self.assertEqual(batch["shapes"]["head.sensitivity.bias"], (4,))


if __name__ == "__main__":
    unittest.main()
