"""Byte parity between the worker pipe path and the existing gRPC server path (stage W1).

Both paths run the same pipeline over the same read-only model files. The oracle is
``create_grpc_server`` (the code ``grpc_main.py`` serves) in this process; the worker is a
separate child over dedicated pipes. Responses are compared as serialized protobuf bytes.
The wall-clock values (``elapsed_ms`` and its copy in the response metadata map) are cleared on both sides and
maps are serialized deterministically; nothing else is normalised.

LLM-only results (semantic selection, gradient and presence RPCs) are counted apart from
detector-ablation and product-pipeline selections.
"""
from __future__ import annotations

import tempfile
import unittest
from collections import Counter
from pathlib import Path

from privoke.v1 import runtime_pb2 as pb
from src import worker_protocol as proto
import worker_cases as cases
from worker_harness import LEGACY_MODEL_ROOT, V3_MODEL_ID, GrpcOracle, WorkerProcess, normalised, v3_model_root

SCOREBOARD = Counter()


def tearDownModule():
    print("\nW1 parity scoreboard (byte-identical/compared):")
    for key in sorted({name.rsplit(":", 1)[0] for name in SCOREBOARD if name.endswith(":compared")}):
        print(f"  {key}: {SCOREBOARD[key + ':identical']}/{SCOREBOARD[key + ':compared']}")
    for name in sorted(SCOREBOARD):
        if name.startswith("gradient_payload_bytes:"):
            print(f"  {name}: {SCOREBOARD[name]}")


class ParityBase(unittest.TestCase):
    worker = None
    oracle = None

    def compare(self, case):
        worker_frame = self.worker.call(case.method, case.payload, metadata=case.metadata)
        self.assertEqual(worker_frame.kind, proto.Kind.RESPONSE,
                         f"{case.label}: worker answered {worker_frame.kind}: {worker_frame.payload[:200]!r}")
        self.assertEqual(worker_frame.method, case.method)
        oracle_payload = self.oracle.call(case.method, case.payload, metadata=case.metadata)
        identical = normalised(case.method, worker_frame.payload) == normalised(case.method, oracle_payload)
        key = f"{case.method.name}[{case.scope}]"
        SCOREBOARD[key + ":compared"] += 1
        SCOREBOARD[key + ":identical"] += int(identical)
        self.assertTrue(identical, f"{case.label}: worker and gRPC responses differ")
        return worker_frame.payload


def replay_capture(test, worker, name, skip_v3=False):
    """Send each committed request frame to the live worker and compare response digests."""
    import hashlib
    if not cases.capture_matches_environment():
        test.skipTest("capture was made with a different torch build")
    replayed = 0
    for record in cases.load_capture(name)["cases"]:
        if skip_v3 and V3_MODEL_ID in record["label"]:
            continue
        with test.subTest(record["label"]):
            worker.send_raw(bytes.fromhex(record["request_frame_hex"]))
            answer = worker.read_frame()
            test.assertEqual(int(answer.kind), record["response_kind"])
            test.assertEqual(answer.request_id, record["request_id"])
            if answer.kind == proto.Kind.RESPONSE:
                body = normalised(proto.Method(record["method_tag"]), answer.payload)
                test.assertEqual(hashlib.sha256(body).hexdigest(), record["response_payload_sha256"])
                test.assertEqual(len(body), record["response_payload_bytes"])
            else:
                test.assertEqual(proto.decode_error(answer), record["error"])
            replayed += 1
    return replayed


class AnalysisParityTests(ParityBase):
    @classmethod
    def setUpClass(cls):
        cls.v3_root = v3_model_root()
        roots = [LEGACY_MODEL_ROOT] + ([cls.v3_root] if cls.v3_root else [])
        warm = ["--warm-semantic-model", cases.TINY_MODEL] + (["--warm-semantic-model", V3_MODEL_ID] if cls.v3_root else [])
        cls.worker = WorkerProcess(roots, arguments=warm)
        cls.worker.wait_ready()
        cls.oracle = GrpcOracle(roots)

    @classmethod
    def tearDownClass(cls):
        cls.oracle.close()
        cls.worker.close()

    def test_every_explicit_layer_selection_matches_the_grpc_server(self):
        selection = cases.analyze_cases(include_v3=self.v3_root is not None)
        self.assertGreater(len(selection), 140)
        for case in selection:
            with self.subTest(case.label):
                self.compare(case)

    def test_semantic_only_responses_execute_only_the_semantic_layer(self):
        for case in cases.analyze_cases(include_v3=self.v3_root is not None):
            if case.scope != "llm_only" or not case.label.startswith("analyze/"):
                continue
            with self.subTest(case.label):
                payload = self.compare(case)
                response = pb.AnalyzePromptResponse.FromString(payload)
                if response.error and not response.layers:
                    continue  # rejected before any layer ran (empty, blank or overlong text): same on both paths
                self.assertEqual([item.layer for item in response.layers], [pb.DETECTION_LAYER_SEMANTIC])

    def test_committed_worker_frames_replay_to_the_recorded_digests(self):
        replayed = replay_capture(self, self.worker, "analysis.json", skip_v3=self.v3_root is None)
        self.assertGreater(replayed, 100)

    def test_health_matches(self):
        self.compare(cases.health_case())

    def test_empty_layer_list_runs_the_whole_pipeline_on_grpc_and_is_refused_by_the_worker(self):
        request = pb.AnalyzePromptRequest(request_id="empty", text="Email bob@example.com", semantic_model_id=cases.TINY_MODEL
                                          ).SerializeToString()
        grpc_response = pb.AnalyzePromptResponse.FromString(self.oracle.call(proto.Method.ANALYZE_PROMPT, request))
        self.assertEqual(len(grpc_response.layers), 3, "the legacy path treats an empty list as the full pipeline")
        frame = self.worker.call(proto.Method.ANALYZE_PROMPT, request)
        self.assertEqual((frame.kind, proto.decode_error(frame)["code"]), (proto.Kind.ERROR, proto.CODE_INVALID_LAYERS))

    def test_unknown_model_error_responses_match(self):
        # Presence artifacts live in the training root; here the model is absent on both paths,
        # so this compares the error response.
        case = cases.presence_cases()[0]
        self.compare(case)


class TrainingAndPresenceParityTests(ParityBase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = cases.build_training_root(Path(cls.directory.name))
        cls.worker = WorkerProcess([cls.root], arguments=["--warm-layers", ""])
        cls.worker.wait_ready()
        cls.oracle = GrpcOracle([cls.root])

    @classmethod
    def tearDownClass(cls):
        cls.oracle.close()
        cls.worker.close()
        cls.directory.cleanup()

    def test_committed_training_frames_replay_to_the_recorded_digests(self):
        self.assertGreater(replay_capture(self, self.worker, "training.json"), 8)

    def test_presence_inference_matches(self):
        for case in cases.presence_cases():
            if case.method == proto.Method.DETECT_ANNOTATION_PRESENCE:
                with self.subTest(case.label):
                    payload = self.compare(case)
                    response = pb.DetectAnnotationPresenceResponse.FromString(payload)
                    if "not-a-presence-model" in case.label:
                        self.assertTrue(response.error)
                    else:
                        self.assertFalse(response.error, response.error)
                        self.assertEqual([item.layer for item in response.executions], [pb.DETECTION_LAYER_SEMANTIC])

    def test_semantic_underlying_and_presence_gradients_match_byte_for_byte(self):
        for case in cases.training_cases() + [item for item in cases.presence_cases()
                                              if item.method == proto.Method.COMPUTE_PRESENCE_GRADIENTS]:
            with self.subTest(case.label):
                payload = self.compare(case)
                response = type(pb.ComputeSemanticGradientsResponse()).FromString(payload) \
                    if case.method != proto.Method.COMPUTE_PRESENCE_GRADIENTS else \
                    pb.ComputePresenceGradientsResponse.FromString(payload)
                if "error" not in case.label and "bad-admission" not in case.label and "duplicate" not in case.label:
                    self.assertFalse(response.error, response.error)
                    self.assertGreater(len(response.gradients), 0)
                    SCOREBOARD["gradient_payload_bytes:max"] = max(SCOREBOARD["gradient_payload_bytes:max"], len(payload))
                    SCOREBOARD[f"gradient_payload_bytes:{case.label}"] = len(payload)

    def test_full_encoder_gradients_cover_every_parameter_and_heads_cover_only_heads(self):
        by_label = {case.label: case for case in cases.training_cases()}
        full = pb.ComputeSemanticGradientsResponse.FromString(
            self.worker.call(proto.Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS,
                             by_label["gradients/underlying/full_encoder"].payload).payload)
        heads = pb.ComputeSemanticGradientsResponse.FromString(
            self.worker.call(proto.Method.COMPUTE_SEMANTIC_GRADIENTS,
                             by_label["gradients/semantic/heads"].payload).payload)
        self.assertFalse(full.error + heads.error)
        self.assertGreater(len(full.gradients), len(heads.gradients))
        self.assertTrue(all(name.startswith("head.") for name in (item.name for item in heads.gradients)))
        self.assertIn("token_embedding", {item.name for item in full.gradients})

    def test_repeated_gradient_requests_are_deterministic_on_the_worker(self):
        case = {item.label: item for item in cases.training_cases()}["gradients/underlying/full_encoder"]
        first = self.worker.call(case.method, case.payload).payload
        second = self.worker.call(case.method, case.payload).payload
        self.assertEqual(normalised(case.method, first), normalised(case.method, second))


if __name__ == "__main__":
    unittest.main()
