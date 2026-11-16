"""Process-level tests of the worker: framing survival, rejection, deadlines and sandbox check.

Each class starts a real worker child over dedicated pipes (host Python only). Warm-up is
disabled where models are irrelevant, so start-up cost is the import time only.
"""
from __future__ import annotations

import json
import struct
import unittest

from privoke.v1 import runtime_pb2 as pb
from src import worker_protocol as proto
from worker_harness import LEGACY_MODEL_ROOT, WorkerProcess

SEMANTIC_ONLY = [pb.DETECTION_LAYER_SEMANTIC]


def health_request():
    return pb.RuntimeHealthRequest().SerializeToString()


def regex_request(text="Contact me at alice@example.com", layers=(pb.DETECTION_LAYER_REGEX,), rid="r"):
    return pb.AnalyzePromptRequest(request_id=rid, text=text, layers=list(layers)).SerializeToString()


class StockWorkerTests(unittest.TestCase):
    """Malformed input, rejected layer lists and recovery on one long-lived worker."""

    @classmethod
    def setUpClass(cls):
        cls.worker = WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", "regex"])
        cls.ready = cls.worker.wait_ready()

    @classmethod
    def tearDownClass(cls):
        cls.exit_code = cls.worker.close()

    def assert_alive(self):
        frame = self.worker.call(proto.Method.HEALTH, health_request())
        self.assertEqual(frame.kind, proto.Kind.RESPONSE)
        response = pb.RuntimeHealthResponse.FromString(frame.payload)
        self.assertEqual((response.service, response.status), ("client-runtime", "SERVING"))

    def test_ready_frame_announces_limits_and_disabled_telemetry(self):
        body = json.loads(self.ready.payload)
        self.assertEqual(self.ready.kind, proto.Kind.READY)
        self.assertEqual((body["protocol_version"], body["telemetry"], body["sandbox_self_check"]),
                         (1, "disabled", "not_requested"))
        self.assertEqual(body["loaded"], ["regex"])
        self.assertEqual(body["limits"]["ComputeUnderlyingModelGradients"]["max_response_payload"], 64 * 1024 * 1024)

    def test_empty_layer_list_is_rejected_for_every_layer_bearing_method(self):
        analyse = pb.AnalyzePromptRequest(request_id="x", text="hello there").SerializeToString()
        presence = pb.DetectAnnotationPresenceRequest(request_id="x", text="t", model_id="privoke-presence-efficient").SerializeToString()
        semantic = pb.ComputeSemanticGradientsRequest(request_id="x", model_id="privoke-balanced").SerializeToString()
        presence_training = pb.ComputePresenceGradientsRequest(request_id="x", model_id="privoke-presence-efficient").SerializeToString()
        for method, payload in ((proto.Method.ANALYZE_PROMPT, analyse),
                                (proto.Method.DETECT_ANNOTATION_PRESENCE, presence),
                                (proto.Method.COMPUTE_SEMANTIC_GRADIENTS, semantic),
                                (proto.Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS, semantic),
                                (proto.Method.COMPUTE_PRESENCE_GRADIENTS, presence_training)):
            with self.subTest(method=method.name):
                frame = self.worker.call(method, payload)
                self.assertEqual(frame.kind, proto.Kind.ERROR)
                self.assertEqual(proto.decode_error(frame)["code"], proto.CODE_INVALID_LAYERS)
        self.assert_alive()

    def test_runtime_layer_value_is_rejected_because_it_selects_the_whole_pipeline(self):
        frame = self.worker.call(proto.Method.ANALYZE_PROMPT,
                                 regex_request(layers=(pb.DETECTION_LAYER_RUNTIME,)))
        self.assertEqual((frame.kind, proto.decode_error(frame)["code"]), (proto.Kind.ERROR, proto.CODE_INVALID_LAYERS))
        self.assert_alive()

    def test_explicit_layer_request_is_answered(self):
        frame = self.worker.call(proto.Method.ANALYZE_PROMPT, regex_request())
        self.assertEqual(frame.kind, proto.Kind.RESPONSE)
        response = pb.AnalyzePromptResponse.FromString(frame.payload)
        self.assertEqual([item.layer for item in response.layers], [pb.DETECTION_LAYER_REGEX])
        self.assertEqual(response.layers[0].status, "ok")

    def test_malformed_frames_get_error_frames_and_the_worker_survives(self):
        worker = self.worker
        cases = [
            ("unknown method", proto.HEADER.pack(3, 1, 1, 0xEE, 0, 41, 0) + b"abc", proto.CODE_UNKNOWN_METHOD, 41),
            ("wrong version", proto.HEADER.pack(3, 7, 1, 3, 0, 42, 0) + b"abc", proto.CODE_UNSUPPORTED_VERSION, 42),
            ("response kind sent as request", proto.HEADER.pack(3, 1, 2, 3, 0, 43, 0) + b"abc", proto.CODE_INVALID_KIND, 43),
            ("unknown flag bits", proto.HEADER.pack(3, 1, 1, 3, 0x40, 44, 0) + b"abc", proto.CODE_INVALID_FLAGS, 44),
            ("oversized health payload",
             proto.HEADER.pack(5000, 1, 1, 3, 0, 45, 0) + bytes(5000), proto.CODE_FRAME_TOO_LARGE, 45),
            ("bad metadata", proto.HEADER.pack(4, 1, 1, 4, 1, 46, 0) + b"\xff\xff\xff\xff", proto.CODE_INVALID_METADATA, 46),
            ("protobuf garbage", proto.encode_frame(proto.Kind.REQUEST, proto.Method.ANALYZE_PROMPT, 47, b"\xff\xff\xff\xff\xff\xff"),
             proto.CODE_INVALID_PAYLOAD, 47),
        ]
        for label, data, code, request_id in cases:
            with self.subTest(label):
                worker.send_raw(data)
                frame = worker.read_frame()
                self.assertEqual((frame.kind, frame.request_id), (proto.Kind.ERROR, request_id))
                self.assertEqual(proto.decode_error(frame)["code"], code)
                self.assert_alive()
        self.assertIsNone(self.worker.process.poll())

    def test_committed_protocol_cases_replay(self):
        import worker_cases
        for record in worker_cases.load_capture("protocol.json")["cases"]:
            with self.subTest(record["label"]):
                self.worker.send_raw(bytes.fromhex(record["request_frame_hex"]))
                frame = self.worker.read_frame()
                self.assertEqual(proto.decode_error(frame), record["error"])
                self.assertTrue(record["worker_alive_after"])
                self.assert_alive()

    def test_back_to_back_garbage_and_valid_frames_stay_in_step(self):
        worker = self.worker
        worker.send_raw(proto.HEADER.pack(2, 1, 1, 0xEE, 0, 61, 0) + b"zz"
                        + proto.encode_frame(proto.Kind.REQUEST, proto.Method.HEALTH, 62, health_request())
                        + proto.HEADER.pack(0, 1, 1, 0xEF, 0, 63, 0)
                        + proto.encode_frame(proto.Kind.REQUEST, proto.Method.HEALTH, 64, health_request()))
        frames = [worker.read_frame() for _ in range(4)]
        self.assertEqual([(frame.kind, frame.request_id) for frame in frames],
                         [(proto.Kind.ERROR, 61), (proto.Kind.RESPONSE, 62), (proto.Kind.ERROR, 63), (proto.Kind.RESPONSE, 64)])


class StrayOutputTests(unittest.TestCase):
    def test_print_and_raw_fd1_writes_do_not_corrupt_framing(self):
        with WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", "regex"], entry="patched",
                           patch="stray-output") as worker:
            worker.wait_ready()
            for index in range(3):
                frame = worker.call(proto.Method.ANALYZE_PROMPT, regex_request(rid=f"stray-{index}"))
                self.assertEqual(frame.kind, proto.Kind.RESPONSE)
                response = pb.AnalyzePromptResponse.FromString(frame.payload)
                self.assertEqual(response.request_id, f"stray-{index}")
                self.assertEqual(response.layers[0].status, "ok")
            health = worker.call(proto.Method.HEALTH, health_request())
            self.assertEqual(health.kind, proto.Kind.RESPONSE)
        self.assertEqual(worker.final_stdout, b"", "nothing may reach the worker's real stdout")
        self.assertIn("STRAY PRINT inside the worker", worker.final_stderr)
        self.assertIn("STRAY PRINT during startup", worker.final_stderr)
        self.assertIn("raw C-level write to fd 1", worker.final_stderr)


class DeadlineAndFaultTests(unittest.TestCase):
    def test_late_answer_becomes_deadline_exceeded_and_worker_continues(self):
        with WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", ""], entry="patched",
                           patch="slow-handler", environment={"PRIVOKE_WORKER_TEST_DELAY": "1.2"}) as worker:
            worker.wait_ready()
            late = worker.call(proto.Method.HEALTH, health_request(), deadline_ms=200)
            self.assertEqual((late.kind, proto.decode_error(late)["code"]), (proto.Kind.ERROR, proto.CODE_DEADLINE_EXCEEDED))
            on_time = worker.call(proto.Method.HEALTH, health_request(), deadline_ms=4000)
            self.assertEqual(on_time.kind, proto.Kind.RESPONSE)

    def test_unexpected_handler_exception_is_an_internal_error_frame(self):
        with WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", ""], entry="patched",
                           patch="crashing-handler") as worker:
            worker.wait_ready()
            frame = worker.call(proto.Method.HEALTH, health_request())
            self.assertEqual((frame.kind, proto.decode_error(frame)["code"]), (proto.Kind.ERROR, proto.CODE_INTERNAL))
            again = worker.call(proto.Method.HEALTH, health_request())
            self.assertEqual(proto.decode_error(again)["code"], proto.CODE_INTERNAL)  # still alive and answering

    def test_truncated_frame_ends_the_worker_with_an_error_frame_and_exit_code(self):
        worker = WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", ""])
        try:
            worker.wait_ready()
            worker.send_raw(proto.encode_frame(proto.Kind.REQUEST, proto.Method.HEALTH, 9, b"\x00" * 3)[:-2])
            worker.requests.close()
            frame = worker.read_frame()
            self.assertEqual(proto.decode_error(frame)["code"], proto.CODE_STREAM_TRUNCATED)
        finally:
            code = worker.close()
        self.assertEqual(code, 5)

    def test_clean_close_exits_zero(self):
        worker = WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", ""])
        worker.wait_ready()
        self.assertEqual(worker.close(), 0)


class SandboxSelfCheckTests(unittest.TestCase):
    def test_worker_refuses_to_start_when_it_can_open_sockets(self):
        with WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", ""],
                           environment={"PRIVOKE_WORKER_SANDBOX": "1"}) as worker:
            frame = worker.read_frame()
            self.assertEqual(frame.kind, proto.Kind.ERROR)
            self.assertEqual(proto.decode_error(frame)["code"], "SANDBOX_VIOLATION")
            self.assertEqual(worker.process.wait(60), 3)
        self.assertIn("Sandbox self-check failed", worker.final_stderr)

    def test_worker_starts_when_the_sandbox_layer_refuses_sockets(self):
        with WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", ""], entry="patched",
                           patch="sockets-refused", environment={"PRIVOKE_WORKER_SANDBOX": "1"}) as worker:
            ready = json.loads(worker.wait_ready().payload)
            self.assertEqual(ready["sandbox_self_check"], "passed")

    def test_self_check_is_not_run_without_the_flag(self):
        with WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", ""]) as worker:
            self.assertEqual(json.loads(worker.wait_ready().payload)["sandbox_self_check"], "not_requested")

    def test_sandbox_probe_reports_each_open_socket_family(self):
        from src import worker_main

        class Handle:
            closed = False

            def close(self):
                Handle.closed = True

        self.assertEqual(worker_main.sandbox_self_check(lambda family, kind: Handle()), ["tcp4", "udp4", "tcp6"])

        def refuse(family, kind):
            raise PermissionError("denied")

        self.assertEqual(worker_main.sandbox_self_check(refuse), [])


class StartupFailureTests(unittest.TestCase):
    def test_unavailable_warm_model_fails_start_before_ready(self):
        worker = WorkerProcess([LEGACY_MODEL_ROOT], arguments=["--warm-layers", "", "--warm-semantic-model", "privoke-nonexistent"])
        try:
            frame = worker.read_frame()
            self.assertEqual((frame.kind, proto.decode_error(frame)["code"]), (proto.Kind.ERROR, "STARTUP_FAILED"))
            self.assertEqual(worker.process.wait(60), 4)
        finally:
            worker.close()

    def test_pipe_descriptors_below_three_are_refused(self):
        import subprocess
        import sys
        from worker_harness import WORKER_SCRIPT, _environment
        done = subprocess.run([sys.executable, str(WORKER_SCRIPT), "--request-fd", "1", "--response-fd", "5"],
                              env=_environment(), capture_output=True, timeout=120)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, b"")


if __name__ == "__main__":
    unittest.main()
