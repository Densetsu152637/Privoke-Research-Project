from __future__ import annotations

import unittest
from unittest.mock import patch

from concurrent.futures import ThreadPoolExecutor
import grpc
from grpc_runtime_client import runtime_pb2 as pb, runtime_pb2_grpc as rpc, handle

from privoke_eval import runners
from privoke_eval.runners import run_pipeline


class RunnerTests(unittest.TestCase):
    def test_bridge_defaults_semantic_and_preserves_explicit_product_selection(self):
        class Stub:
            def AnalyzePrompt(self, request, timeout):
                self.request = request
                return pb.AnalyzePromptResponse(layers=self.layers)
        stub = Stub()
        stub.layers = [pb.RuntimeLayerExecution(layer=pb.DETECTION_LAYER_SEMANTIC, status="ok")]
        handle(stub, {"operation": "analyze", "text": "test"})
        self.assertEqual(list(stub.request.layers), [pb.DETECTION_LAYER_SEMANTIC])
        handle(stub, {"operation": "analyze", "text": "test", "layer": "pipeline"})
        self.assertEqual(list(stub.request.layers), [pb.DETECTION_LAYER_RUNTIME])
        for layer in ("", None, "unknown"):
            with self.subTest(layer=layer), self.assertRaises(ValueError):
                handle(stub, {"operation": "analyze", "text": "test", "layer": layer})
        for layers in ([], [pb.RuntimeLayerExecution(layer=pb.DETECTION_LAYER_REGEX, status="ok")],
                       [pb.RuntimeLayerExecution(layer=pb.DETECTION_LAYER_SEMANTIC, status="error")]):
            stub.layers = layers
            with self.subTest(layers=layers), self.assertRaisesRegex(RuntimeError, "Semantic-only"):
                handle(stub, {"operation": "analyze", "text": "test"})

    def test_semantic_runner_rejects_extra_missing_and_skipped_execution(self):
        response = {"action": "ALLOW", "classification": {"sensitivity": "S0", "categories": []}}
        for layers in ([], [{"layer": "DETECTION_LAYER_REGEX", "status": "ok"}],
                       [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "skipped"}],
                       [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok"}, {"layer": "DETECTION_LAYER_NER", "status": "ok"}]):
            with patch("privoke_eval.runners._request_grpc", return_value={**response, "layers": layers}):
                with self.assertRaisesRegex(RuntimeError, "Semantic-only"):
                    run_pipeline("test", "streamed")

    def test_default_report_endpoint_is_localhost(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(runners.runtime_url(), "grpc://127.0.0.1:50054")

    def setUp(self) -> None:
        patcher = patch("privoke_eval.runners.configure_backend")
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_host_requests_reach_local_grpc_without_docker(self):
        class Runtime(rpc.PrivokeRuntimeServiceServicer):
            def Health(self, request, context):
                return pb.RuntimeHealthResponse(service="client-runtime", status="SERVING")

            def AnalyzePrompt(self, request, context):
                self.request = request
                response = pb.AnalyzePromptResponse(action="WARN", elapsed_ms=3)
                response.classification.sensitivity = "S2"
                response.classification.visibility = "P3"
                response.classification.categories.append("HEALTH")
                return response

        service = Runtime()
        server = grpc.server(ThreadPoolExecutor(max_workers=2))
        rpc.add_PrivokeRuntimeServiceServicer_to_server(service, server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        self.addCleanup(lambda: server.stop(0).wait())
        self.addCleanup(runners._close_client)
        with patch.dict("os.environ", {"PRIVOKE_RUNTIME_TARGET": f"127.0.0.1:{port}"}), \
                patch("subprocess.Popen", side_effect=AssertionError("No subprocess transport")):
            runners.check_runtime_available()
            outcome = run_pipeline("Synthetic medical example", "streamed", "regex-ner")
        self.assertEqual(outcome.sensitivity, "S2")
        self.assertEqual(list(service.request.layers), [pb.DETECTION_LAYER_REGEX, pb.DETECTION_LAYER_NER])

    def test_grpc_rejection_is_reported_as_failure(self):
        class Runtime(rpc.PrivokeRuntimeServiceServicer):
            def Health(self, request, context):
                context.abort(grpc.StatusCode.UNAVAILABLE, "synthetic unavailable")

        server = grpc.server(ThreadPoolExecutor(max_workers=1))
        rpc.add_PrivokeRuntimeServiceServicer_to_server(Runtime(), server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        self.addCleanup(lambda: server.stop(0).wait())
        self.addCleanup(runners._close_client)
        with patch.dict("os.environ", {"PRIVOKE_RUNTIME_TARGET": f"127.0.0.1:{port}"}):
            with self.assertRaisesRegex(RuntimeError, "UNAVAILABLE.*synthetic unavailable"):
                runners.check_runtime_available()

    def test_uses_returned_classification_even_when_action_is_allow(self) -> None:
        response = {
            "action": "ALLOW",
            "classification": {
                "sensitivity": "S1",
                "visibility": "PU",
                "categories": ["IDENTITY"],
            },
            "confidence": 0.8,
            "elapsed_ms": 1.0,
            "layers": [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok"}],
        }
        with patch("privoke_eval.runners._request_grpc", return_value=response) as request:
            outcome = run_pipeline("example", "streamed")
            self.assertEqual(request.call_args.args[0]["layer"], "semantic")

        self.assertTrue(outcome.detected_sensitive)
        self.assertFalse(outcome.intervened)

    def test_rejects_invalid_classification_instead_of_scoring_it(self) -> None:
        response = {
            "action": "ALLOW",
            "classification": {"sensitivity": "unknown", "categories": []},
        }
        with patch("privoke_eval.runners._request_grpc", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "invalid classification sensitivity"):
                run_pipeline("example", "streamed")


if __name__ == "__main__":
    unittest.main()
