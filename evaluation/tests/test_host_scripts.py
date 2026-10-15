"""Exercise standalone host commands against real synthetic loopback RPCs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from host_environment import configure_imports

configure_imports()
import grpc
from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc
from privoke.v1 import runtime_pb2 as runtime_pb, runtime_pb2_grpc as runtime_rpc

ROOT = Path(__file__).resolve().parents[2]


class Fuzzer(rpc.FuzzerServiceServicer):
    def Health(self, request, context):
        return pb.HealthResponse(service="privoke-fuzzer", status="SERVING")

    def RunTrainingCycle(self, request, context):
        self.request = request
        return pb.FuzzerTrainingResponse(accepted=False, model_id=request.model_id,
                                        message="synthetic quality rejection")


class HostScriptTests(unittest.TestCase):
    def setUp(self):
        self.service = Fuzzer()
        server = grpc.server(ThreadPoolExecutor(max_workers=2))
        rpc.add_FuzzerServiceServicer_to_server(self.service, server)
        self.port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        self.addCleanup(lambda: server.stop(0).wait())

    def run_script(self, *arguments):
        return subprocess.run(
            [sys.executable, str(ROOT / "evaluation/run-fuzzer-tests.py"), *arguments,
             "--target", f"127.0.0.1:{self.port}"],
            cwd=ROOT, text=True, capture_output=True, timeout=20)

    def test_health_script_reaches_local_fuzzer(self):
        result = self.run_script("health")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SERVING", result.stdout)

    def test_training_rejection_is_nonzero_and_preserves_request(self):
        result = self.run_script("train", "--model-id", "synthetic-model",
                                 "--request-id", "synthetic-request", "--prompt-count", "8")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("synthetic quality rejection", result.stdout)
        self.assertEqual(self.service.request.model_id, "synthetic-model")
        self.assertEqual(self.service.request.request_id, "synthetic-request")
        self.assertEqual(self.service.request.prompt_count, 8)

    def test_prompt_script_connects_to_runtime_and_writes_host_report(self):
        class Runtime(runtime_rpc.PrivokeRuntimeServiceServicer):
            def AnalyzePrompt(self, request, context):
                self.request = request
                response = runtime_pb.AnalyzePromptResponse(action="ALLOW", request_id=request.request_id)
                response.classification.sensitivity = "S0"
                response.classification.visibility = "PU"
                response.layers.add(layer=runtime_pb.DETECTION_LAYER_REGEX, status="ok")
                return response

        service = Runtime()
        server = grpc.server(ThreadPoolExecutor(max_workers=1))
        runtime_rpc.add_PrivokeRuntimeServiceServicer_to_server(service, server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        self.addCleanup(lambda: server.stop(0).wait())
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_script("test-prompts", "--runtime-target", f"127.0.0.1:{port}",
                                     "--layer", "regex", "--prompt", "Synthetic greeting",
                                     "--dump-dir", directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list(Path(directory).glob("*.json"))), 1)
        self.assertEqual(service.request.text, "Synthetic greeting")
        self.assertEqual(list(service.request.layers), [runtime_pb.DETECTION_LAYER_REGEX])


if __name__ == "__main__":
    unittest.main()
