"""Mocked fixture RPC boundaries using genuine generated protobuf messages."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("fixture_rpc_study", ROOT / "evaluation/run-contextual-fuzzer-study.py")
STUDY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STUDY)

import grpc
from privoke.v1 import runtime_pb2 as PB, runtime_pb2_grpc as API


class FixtureRpcTests(unittest.TestCase):
    def setUp(self):
        self.artifact = {"model_id": "synthetic-contextual", "version": "synthetic-v1",
                         "checksum": "synthetic-checksum",
                         "parameters": {"head": {"shape": [1], "values": [0.0]}}}
        self.identity = STUDY.artifact_identity(self.artifact)
        self.args = SimpleNamespace(allow_product_pipeline=True, project_name="synthetic", runtime_target="fake.invalid:1")
        self.state = {"prefix": "fixture-test", "prepared": "unused-synthetic-curriculum",
                      "runtime_target": self.args.runtime_target}
        self.requests = []

    def case(self, name="synthetic-case", **extra):
        return {"case_id": name, "text": "Synthetic context only", "ambiguous": False,
                "required_sensitive": True, "minimum_action": "BLOCK", **extra}

    def semantic(self, *, status="ok", error="", results=None):
        if results is None:
            results = [PB.RuntimeDetectionResult(metadata=self.identity)]
        return PB.RuntimeLayerExecution(layer=PB.DETECTION_LAYER_SEMANTIC,
                                        status=status, error=error, results=results)

    def response(self, request, *, action="ALLOW", layers=None, error="", request_id=None):
        return PB.AnalyzePromptResponse(request_id=request.request_id if request_id is None else request_id,
                                       action=action, error=error,
                                       layers=[self.semantic()] if layers is None else layers)

    def collect(self, factories, cases=None):
        cases = cases or [self.case(f"case-{index}") for index in range(len(factories))]
        pending = iter(factories)
        client = MagicMock()

        def analyze(request, *, timeout):
            self.assertIsInstance(request, PB.AnalyzePromptRequest)
            self.assertEqual(list(request.layers), [PB.DETECTION_LAYER_REGEX,
                             PB.DETECTION_LAYER_NER, PB.DETECTION_LAYER_SEMANTIC])
            self.assertEqual(timeout, 120)
            self.requests.append(request)
            return next(pending)(request)

        client.AnalyzePrompt.side_effect = analyze
        channel = MagicMock()
        with tempfile.TemporaryDirectory(prefix=".fixture-rpc-", dir=ROOT / "evaluation/tests") as temporary:
            directory = Path(temporary)
            directory.resolve().relative_to((ROOT / "evaluation/tests").resolve())
            path = directory / "fixture-output.json"
            driver = STUDY.Driver(self.args, self.state)
            with patch.object(STUDY, "load_artifact", return_value=copy.deepcopy(self.artifact)), \
                 patch.object(grpc, "insecure_channel", return_value=channel) as connect, \
                 patch.object(API, "PrivokeRuntimeServiceStub", return_value=client):
                observations = driver.fixture(directory / "unused-artifact.json", cases, path)
            connect.assert_called_once_with(self.args.runtime_target)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), observations)
            return observations

    def test_regex_block_explanatory_skips_are_accepted_with_collection_identity(self):
        def blocked(request):
            layers = [PB.RuntimeLayerExecution(layer=PB.DETECTION_LAYER_REGEX, status="ok",
                                              results=[PB.RuntimeDetectionResult(action="BLOCK")])]
            layers.extend(PB.RuntimeLayerExecution(layer=layer, status="skipped",
                                                   error="Skipped after regex returned BLOCK.")
                          for layer in (PB.DETECTION_LAYER_NER, PB.DETECTION_LAYER_SEMANTIC))
            return self.response(request, action="BLOCK", layers=layers)

        result = self.collect([blocked, self.response])
        self.assertEqual(result["case-0"]["action"], "BLOCK")
        self.assertEqual(result["case-0"]["raw"]["layers"][2]["status"], "skipped")
        self.assertEqual(result["case-0"]["raw"]["layers"][2]["error"],
                         "Skipped after regex returned BLOCK.")
        self.assertEqual(result["case-1"]["raw"]["layers"][0]["results"][0]["metadata"], self.identity)

    def test_all_skipped_collection_without_semantic_identity_is_rejected(self):
        def skipped(request):
            return self.response(request, action="BLOCK", layers=[self.semantic(status="skipped", results=[])])

        with self.assertRaises(ValueError):
            self.collect([skipped, skipped])

    def test_collection_without_layers_or_semantic_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            self.collect([lambda request: self.response(request, layers=[])])

    def test_successful_empty_semantic_response_is_valid_with_collection_identity(self):
        result = self.collect([self.response,
                               lambda request: self.response(request, layers=[self.semantic(results=[])])])
        self.assertEqual(result["case-1"]["action"], "ALLOW")
        self.assertNotIn("results", result["case-1"]["raw"]["layers"][0])

    def test_all_empty_semantic_collection_without_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no returned semantic model identity"):
            self.collect([lambda request: self.response(request, layers=[self.semantic(results=[])])])

    def continuation(self, corruption=None, *, resume=True):
        cases = [self.case("case-0"), self.case("case-1")]
        client = MagicMock()
        with tempfile.TemporaryDirectory(prefix=".fixture-resume-", dir=ROOT / "evaluation/tests") as temporary:
            path = Path(temporary) / "fixture.json"
            driver = STUDY.Driver(self.args, self.state)
            with patch.object(STUDY, "load_artifact", return_value=self.artifact), \
                 patch.object(grpc, "insecure_channel"), \
                 patch.object(API, "PrivokeRuntimeServiceStub", return_value=client):
                client.AnalyzePrompt.side_effect = lambda request, timeout: self.response(request)
                prefix = driver.fixture("unused", cases[:1], path)
                original_request = prefix["case-0"]["request_id"]
                if corruption:
                    corruption(prefix)
                    STUDY.write(path, prefix)
                client.AnalyzePrompt.reset_mock()
                client.AnalyzePrompt.side_effect = lambda request, timeout: self.response(
                    request, layers=[self.semantic(results=[])])
                if corruption or not resume:
                    with self.assertRaises(ValueError):
                        driver.fixture("unused", cases, path, resume=resume)
                    client.AnalyzePrompt.assert_not_called()
                else:
                    result = driver.fixture("unused", cases, path, resume=True)
                    client.AnalyzePrompt.assert_called_once()
                    self.assertEqual(result["case-0"], prefix["case-0"])
                    self.assertEqual(result["case-0"]["request_id"], original_request)
                    request = client.AnalyzePrompt.call_args.args[0]
                    expected = "ctx-fixture-" + STUDY.hashlib.sha256((str(path) + "case-1").encode()).hexdigest()[:40]
                    self.assertEqual(request.request_id, expected)
                    self.assertEqual(list(result), ["case-0", "case-1"])

    def test_resume_reuses_prefix_and_counts_its_identity_without_reissuing_it(self):
        self.continuation()

    def test_default_collection_refuses_existing_output(self):
        self.continuation(resume=False)

    def test_resume_rejects_changed_identity_or_request_before_rpc(self):
        def wrong_identity(prefix):
            prefix["case-0"]["raw"]["layers"][0]["results"][0]["metadata"]["model_id"] = "wrong"
        def wrong_request(prefix):
            prefix["case-0"]["request_id"] = "wrong"
        for corrupt in (wrong_identity, wrong_request):
            with self.subTest(corruption=corrupt.__name__):
                self.continuation(corrupt)

    def test_resume_rejects_nonprefix_before_rpc(self):
        self.continuation(lambda prefix: prefix.update({"other-case": prefix.pop("case-0")}))

    def test_wrong_semantic_identity_is_rejected(self):
        for field in self.identity:
            with self.subTest(field=field):
                identity = {**self.identity, field: "different-identity"}
                with self.assertRaises(ValueError):
                    self.collect([lambda request: self.response(request, layers=[self.semantic(
                        results=[PB.RuntimeDetectionResult(metadata=identity)])])])

    def test_real_error_and_failed_status_are_rejected(self):
        for status, error in (("error", ""), ("failed", ""), ("ok", "RPC execution failed")):
            with self.subTest(status=status, error=error), self.assertRaises(ValueError):
                self.collect([lambda request: self.response(request, layers=[self.semantic(
                    status=status, error=error)])])
        with self.assertRaises(ValueError):
            self.collect([lambda request: self.response(request, error="Aggregate runtime failure")])

    def test_request_id_and_action_must_correlate_with_the_rpc(self):
        with self.assertRaises(ValueError):
            self.collect([lambda request: self.response(request, request_id="different-request")])
        with self.assertRaises(ValueError):
            self.collect([lambda request: self.response(request, action="UNKNOWN")])
        case = self.case(visibility_hint="P3")
        result = self.collect([self.response], [case])
        observation = result[case["case_id"]]
        request = self.requests[-1]
        self.assertEqual(request.visibility_hint, "P3")
        self.assertEqual(request.semantic_model_id, self.artifact["model_id"])
        self.assertEqual(request.source, "contextual-fuzzer-study")
        self.assertEqual(observation["request_id"], request.request_id)
        self.assertEqual(observation["raw"]["request_id"], request.request_id)
        self.assertEqual(observation["action"], observation["raw"]["action"])
        # Collection retains a below-minimum action; the caller owns the retention gate.
        self.assertEqual(observation["action"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
