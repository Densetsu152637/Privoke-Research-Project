from __future__ import annotations

import sys
import unittest
from concurrent import futures
from pathlib import Path
from unittest.mock import Mock

import grpc


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))
GENERATED_DIR = PACKAGE_ROOT / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import parameters_pb2, parameters_pb2_grpc, runtime_pb2
from src.main import PrivokeRuntimeControlService, _model_streaming_health


class ServingModelService(parameters_pb2_grpc.ModelStreamingServiceServicer):
    def Health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="test-model-streaming-service",
            status="SERVING",
        )


class RuntimeControlServiceTests(unittest.TestCase):
    def test_model_streaming_health_check_is_lazy(self) -> None:
        health_check = Mock(return_value=("model-streaming-service", "SERVING"))
        service = PrivokeRuntimeControlService(Mock(), health_check)

        health_check.assert_not_called()

        response = service.ModelStreamingHealth(
            runtime_pb2.RuntimeHealthRequest(),
            None,
        )

        health_check.assert_called_once_with()
        self.assertEqual(response.service, "model-streaming-service")
        self.assertEqual(response.status, "SERVING")

    def test_python_supervisor_performs_model_streaming_health_rpc(self) -> None:
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
        parameters_pb2_grpc.add_ModelStreamingServiceServicer_to_server(
            ServingModelService(),
            server,
        )
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        try:
            self.assertEqual(
                _model_streaming_health(f"127.0.0.1:{port}", 1.0),
                ("test-model-streaming-service", "SERVING"),
            )
        finally:
            server.stop(0).wait()

    def test_unavailable_model_streaming_service_is_not_serving(self) -> None:
        self.assertEqual(
            _model_streaming_health("127.0.0.1:1", 0.1),
            ("model-streaming-service", "NOT_SERVING"),
        )


if __name__ == "__main__":
    unittest.main()
