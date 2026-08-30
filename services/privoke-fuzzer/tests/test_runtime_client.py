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
from runtime_client import PrivokeRuntimeClient


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
                classification=runtime_pb2.RuntimeClassification(
                    sensitivity="S1",
                    visibility="PU",
                )
            )
        finally:
            with self._lock:
                self.active -= 1


class RuntimeClientBatchTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
