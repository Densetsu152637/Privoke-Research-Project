from __future__ import annotations

import hashlib
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_contextual_cascade_study", ROOT / "evaluation/run-contextual-cascade-study.py")
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class FakeBackend:
    def __init__(self, *, timeout_write=False, changed_image=False, fail_context_restore=False,
                 timeout_stage=False, timeout_restore=False, fail_preflight=False, invalid_freeze=False):
        self.catalog = {key: f"prior-bytes-{key}".encode() for key in runner.CATALOG_IDS}
        self.admin_mutation_outcome_unknown = False
        self.evaluator_job_outcome_unknown = False
        self.timeout_write = timeout_write
        self.changed_image = changed_image
        self.fail_context_restore = fail_context_restore
        self.timeout_stage = timeout_stage
        self.timeout_restore = timeout_restore
        self.fail_preflight = fail_preflight
        self.invalid_freeze = invalid_freeze
        self.writes, self.restores, self.probes, self.stages = [], [], [], []
        self.image_calls = 0
        self.job_images = {"sha256:" + "e" * 64}
        self.calls, self.jobs = [], []

    def ensure_services(self):
        pass

    def evaluator_image(self):
        return "sha256:" + "e" * 64

    def preflight_fit(self, *, inputs, binding, output):
        if self.fail_preflight:
            raise ValueError("simulated fit binding failure")
        return {"sha256": "f" * 64}

    def images(self):
        self.image_calls += 1
        version = "a" if not self.changed_image or self.image_calls == 1 else "b"
        return {"client-runtime": "sha256:" + version * 64,
                "model-streaming-service": "sha256:" + "c" * 64,
                "param-update-service": "sha256:" + "d" * 64}

    def read_raw(self, model_id):
        return self.catalog[model_id]

    def write_artifact(self, artifact, *, expected_checksum):
        if self.timeout_write:
            self.admin_mutation_outcome_unknown = True
            raise TimeoutError("write timeout")
        self.writes.append(artifact["model_id"])
        self.catalog[artifact["model_id"]] = json.dumps(artifact, sort_keys=True).encode()

    def restore_exact(self, model_id, raw):
        self.restores.append(model_id)
        if self.timeout_restore:
            self.admin_mutation_outcome_unknown = True
            raise TimeoutError("simulated remote restore timeout")
        if self.fail_context_restore and model_id == "privoke-balanced":
            raise OSError("simulated restore failure")
        self.catalog[model_id] = raw

    def probe(self, expected):
        self.probes.append(expected)

    def run_stage(self, *, stage, pair, study_root, inputs, binding, output):
        self.stages.append((stage, pair))
        if stage == "calibrate":
            choices = {name: ({"status": "ineligible", "chosen": None} if name == "original-efficient"
                               else {"status": "eligible", "chosen": {"threshold": .8}})
                       for name in runner.PAIRS}
            if self.invalid_freeze:
                choices["original-balanced"]["chosen"]["threshold"] = float("nan")
            path = study_root / "calibration/selection.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"status": "frozen", "choices": choices}), encoding="utf-8")
            return {"status": "frozen", "choices": choices, "image_id": "sha256:" + "e" * 64}
        if self.timeout_stage:
            self.evaluator_job_outcome_unknown = True
            raise TimeoutError("simulated unresolved evaluator job")
        choice = None
        if stage in ("evaluate-validation", "evaluate-development") and pair == "original-efficient":
            choice = {"status": "skipped_ineligible"}
        elif stage == "collect-validation":
            choice = {"status": "complete"}
        else:
            choice = {"status": "complete"}
        return {**choice, "report_sha256": "f" * 64, "image_id": "sha256:" + "e" * 64,
                "container_id": "a" * 12, "exit_code": 0, "logs_sha256": "1" * 64}


def fake_inputs():
    controls = {}
    for name in runner.CONTROLS:
        identity = {"model_id": "privoke-balanced", "model_version": "v0.3.0" if name == "original" else "v0.3.0+train.1",
                    "artifact_checksum": runner.CONTEXT_CHECKSUMS[name], "parameter_fingerprint": name * 8}
        controls[name] = {"identity": identity, "artifact": {"model_id": "privoke-balanced",
                          "checksum": runner.CONTEXT_CHECKSUMS[name]}}
    presence = {}
    for profile in runner.PROFILES:
        identity = {"model_id": runner.PRESENCE_IDS[profile], "model_version": "v1",
                    "artifact_checksum": profile * 8, "parameter_fingerprint": profile * 8,
                    "threshold": .5}
        presence[profile] = {"identity": identity, "artifact": {"model_id": identity["model_id"],
                               "checksum": identity["artifact_checksum"]}}
    return {"controls": controls, "presence": presence}


class ContextualCascadeRunnerTests(unittest.TestCase):
    def run_fake(self, backend):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "study"
        output.mkdir()
        inputs = fake_inputs()
        prior = dict(backend.catalog)
        binding = {"runtime_image_id": "sha256:" + "a" * 64,
                   "evaluator_image_id": "sha256:" + "e" * 64,
                   "source_revision": "a" * 40}
        with patch.object(runner, "check_prior_catalog", return_value={}):
            state = runner.run_sequence(backend=backend, output=output,
                study_root=output / "cascade", inputs=inputs, binding=binding)
        return state, prior, backend

    def test_fixed_phases_complete_with_exact_restore_and_development_last(self):
        state, prior, backend = self.run_fake(FakeBackend())
        self.assertEqual(state["status"], "complete")
        self.assertTrue(state["restoration_verified"])
        self.assertEqual(backend.catalog, prior)
        self.assertEqual(backend.stages[:6], [("collect-validation", p) for p in runner.PAIRS])
        self.assertEqual(backend.stages[6], ("calibrate", None))
        validation = [s for s, _ in backend.stages if s == "evaluate-validation"]
        development = [s for s, _ in backend.stages if s == "evaluate-development"]
        self.assertEqual(len(validation), 6)
        self.assertEqual(len(development), 6)
        outcomes = {(job["stage"], job["pair"]): job["status"] for job in state["phase_jobs"]}
        self.assertEqual(outcomes[("evaluate-validation", "original-efficient")], "skipped_ineligible")
        self.assertEqual(outcomes[("evaluate-development", "original-efficient")], "skipped_ineligible")
        self.assertGreater(min(i for i, item in enumerate(backend.stages) if item[0] == "evaluate-development"),
                           max(i for i, item in enumerate(backend.stages) if item[0] == "evaluate-validation"))
        self.assertEqual(len([x for x in backend.restores if x == "privoke-balanced"]), 7)

    def test_admin_timeout_prevents_all_restoration_claims_and_writes(self):
        backend = FakeBackend(timeout_write=True)
        state, prior, _ = self.run_fake(backend)
        self.assertEqual(state["status"], "failed")
        self.assertTrue(state["admin_mutation_outcome_unknown"])
        self.assertFalse(state["restoration_verified"])
        self.assertEqual(backend.restores, [])
        self.assertNotIn("prior_raw", state)

    def test_unresolved_evaluator_job_prevents_context_and_final_restore(self):
        backend = FakeBackend(timeout_stage=True)
        state, _prior, _ = self.run_fake(backend)
        self.assertEqual(state["status"], "failed")
        self.assertTrue(state["evaluator_job_outcome_unknown"])
        self.assertFalse(state["restoration_verified"])
        self.assertEqual(backend.restores, [])

    def test_restore_timeout_stops_all_subsequent_restore_writes(self):
        backend = FakeBackend(timeout_restore=True)
        state, _prior, _ = self.run_fake(backend)
        self.assertEqual(state["status"], "failed")
        self.assertTrue(state["admin_mutation_outcome_unknown"])
        self.assertFalse(state["restoration_verified"])
        self.assertEqual(backend.restores, ["privoke-balanced"])

    def test_preflight_failure_prevents_any_model_writes_or_scoring(self):
        backend = FakeBackend(fail_preflight=True)
        state, _prior, _ = self.run_fake(backend)
        self.assertEqual(state["status"], "failed")
        self.assertFalse(state["restoration_verified"])
        self.assertEqual(backend.writes, [])
        self.assertEqual(backend.restores, [])
        self.assertEqual(backend.stages, [])

    def test_invalid_frozen_choice_prevents_endpoint_or_development_scoring(self):
        backend = FakeBackend(invalid_freeze=True)
        state, _prior, _ = self.run_fake(backend)
        self.assertEqual(state["status"], "failed")
        self.assertFalse(any(stage.startswith("evaluate-") for stage, _ in backend.stages))
        self.assertFalse(any(stage == "evaluate-development" for stage, _ in backend.stages))

    def test_image_change_fails_study_but_exact_restore_still_succeeds(self):
        state, prior, backend = self.run_fake(FakeBackend(changed_image=True))
        self.assertEqual(state["status"], "failed")
        self.assertTrue(state["restoration_verified"])
        self.assertEqual(backend.catalog, prior)

    def test_context_restore_failure_is_recorded_and_study_remains_failed(self):
        state, _prior, backend = self.run_fake(FakeBackend(fail_context_restore=True))
        self.assertEqual(state["status"], "failed")
        self.assertFalse(state["restoration_verified"])
        self.assertTrue(state["restoration_failures"])
        self.assertEqual(set(backend.catalog), set(runner.CATALOG_IDS))

    def test_result_paths_are_confined_and_fresh(self):
        with tempfile.TemporaryDirectory() as temp:
            outside = Path(temp) / "outside"
            with self.assertRaisesRegex(ValueError, "evaluation/results"):
                runner.inside_results(outside)

    def test_evaluator_image_uses_resolved_compose_service_image(self):
        backend = runner.DockerBackend(Path("unused"))
        image_id = "sha256:" + "a" * 64
        calls = []
        def fake_call(args, *, direct=False, **kwargs):
            calls.append((args, direct))
            if args[:2] == ["config", "--format"]:
                return json.dumps({"name": "resolved-project", "services": {
                    "evaluation-tests": {"build": {"context": "."}}}})
            return image_id
        with patch.object(backend, "call", side_effect=fake_call):
            self.assertEqual(backend.evaluator_image(), image_id)
        self.assertEqual(calls[1], (["docker", "image", "inspect", "--format", "{{.Id}}",
                                    "resolved-project-evaluation-tests"], True))

    def test_existing_service_preflight_is_read_only_and_requires_training_disabled(self):
        backend = runner.DockerBackend(Path("unused"))
        seen = []
        def fake_call(args, *, direct=False, **kwargs):
            seen.append(args)
            if args[0:3] == ["ps", "--status", "running"]:
                return "a" * 12 if args[-1] in ("client-runtime", "model-streaming-service", "param-update-service") else ""
            if args[:3] == ["docker", "inspect", "--format"] and args[3] == "{{json .State}}":
                return json.dumps({"Running": True, "Status": "running", "Health": {"Status": "healthy"}})
            if args[:3] == ["ps", "--all", "--quiet"]:
                return "a" * 12
            if args[:3] == ["docker", "inspect", "--format"] and args[3] == "{{json .Config.Env}}":
                return json.dumps(["MODEL_STREAMING_CACHE_TTL_SECONDS=2.5", "FUZZER_PROMPT_COUNT=0"])
            raise AssertionError(args)
        with patch.object(backend, "call", side_effect=fake_call):
            backend.ensure_services()
        self.assertFalse(any(args and args[0] == "up" for args in seen))
        self.assertEqual(backend.runtime_cache_ttl_seconds, 2.5)
        self.assertEqual(seen[-2:], [["ps", "--status", "running", "--quiet", "presence-fuzzer"],
                                     ["ps", "--status", "running", "--quiet", "presence-update-service"]])

    def test_failed_oneoff_launch_requires_positive_named_cleanup(self):
        backend = runner.DockerBackend(Path("unused"))
        with patch.object(backend, "call", side_effect=RuntimeError("compose launcher failed")), \
             patch.object(backend, "_quiesce_named_job", return_value=False):
            with self.assertRaises(RuntimeError):
                backend._job(["compose", "run"], name="cascade-test-one", stage="collect-validation",
                    pair="original-efficient", study_root=Path("unused"), output=Path("unused"))
        self.assertTrue(backend.evaluator_job_outcome_unknown)

    def test_failed_launch_is_safe_when_named_container_is_proven_absent(self):
        backend = runner.DockerBackend(Path("unused"))
        with patch.object(backend, "call", side_effect=RuntimeError("compose launcher failed")), \
             patch.object(backend, "_quiesce_named_job", return_value=True):
            with self.assertRaises(RuntimeError):
                backend._job(["compose", "run"], name="cascade-test-absent", stage="collect-validation",
                    pair="original-efficient", study_root=Path("unused"), output=Path("unused"))
        self.assertFalse(backend.evaluator_job_outcome_unknown)

    def test_timed_out_launch_stays_unknown_when_only_absence_is_observed(self):
        backend = runner.DockerBackend(Path("unused"))
        timeout = subprocess.TimeoutExpired(["docker", "compose", "run"], 120)
        with patch.object(backend, "call", side_effect=timeout), \
             patch.object(backend, "_quiesce_named_job", return_value=True):
            with self.assertRaises(subprocess.TimeoutExpired):
                backend._job(["compose", "run"], name="cascade-timeout", stage="collect-validation",
                    pair="original-efficient", study_root=Path("unused"), output=Path("unused"))
        self.assertTrue(backend.evaluator_job_outcome_unknown)

    def test_identity_probe_against_real_generated_protobuf_and_mocked_stub(self):
        generated = ROOT / "extension/client-runtime/generated"
        if not (generated / "privoke/v1/runtime_pb2.py").is_file():
            self.skipTest("Generated runtime protobuf package is supplied in the evaluator image.")
        sys.path.insert(0, str(generated))
        import grpc
        from privoke.v1 import runtime_pb2 as pb, runtime_pb2_grpc as stubs

        expected = {
            "context": {"model_id": "privoke-balanced", "model_version": "v0.3.0",
                        "artifact_checksum": "c" * 64, "parameter_fingerprint": "f" * 64},
            "presence": {"model_id": "privoke-presence-efficient", "model_version": "v1",
                         "artifact_checksum": "a" * 64, "parameter_fingerprint": "b" * 64,
                         "threshold": .5},
            "_probe_retry_seconds": 1.0,
        }
        trace = pb.SemanticPresenceGateTrace(
            status=pb.SEMANTIC_PRESENCE_GATE_STATUS_APPLIED,
            model_id=expected["presence"]["model_id"], model_version=expected["presence"]["model_version"],
            artifact_checksum=expected["presence"]["artifact_checksum"],
            parameter_fingerprint=expected["presence"]["parameter_fingerprint"],
            probability=.75, model_threshold=.5, decision_threshold=0.0,
            predicted_label=pb.ANNOTATION_PRESENCE_PRESENT,
            contextual_model_id=expected["context"]["model_id"],
            contextual_model_version=expected["context"]["model_version"],
            contextual_artifact_checksum=expected["context"]["artifact_checksum"],
            contextual_parameter_fingerprint=expected["context"]["parameter_fingerprint"],
        )
        response = pb.AnalyzePromptResponse(request_id="cascade-identity-probe", error="", layers=[
            pb.RuntimeLayerExecution(layer=pb.DETECTION_LAYER_SEMANTIC, status="ok", error="",
                                     semantic_presence_gate=trace)])
        response_with_unrequested_error = pb.AnalyzePromptResponse(
            request_id="cascade-identity-probe", error="", layers=[
                *response.layers,
                pb.RuntimeLayerExecution(layer=pb.DETECTION_LAYER_NER, status="error", error="injected")])
        class Stub:
            calls = 0
            def AnalyzePrompt(self, request, timeout):
                self.request = request
                self.timeout = timeout
                self.calls += 1
                return response_with_unrequested_error if self.calls == 1 else response
        stub = Stub()
        class Channel:
            def __enter__(self): return self
            def __exit__(self, *_args): return False
        out = io.StringIO()
        # The script imports from the generated package itself; only the channel and stub are replaced.
        with patch.object(grpc, "insecure_channel", return_value=Channel()), \
             patch.object(stubs, "PrivokeRuntimeServiceStub", return_value=stub), \
             patch.object(sys, "stdin", io.StringIO(json.dumps(expected))), \
             contextlib.redirect_stdout(out):
            exec(runner.IDENTITY_PROBE, {"__name__": "__main__"})
        self.assertEqual(stub.request.request_id, "cascade-identity-probe")
        self.assertEqual(stub.calls, 2, "Probe must reject any errored returned layer before accepting identities.")
        self.assertEqual(stub.request.semantic_presence_gate.threshold, 0.0)
        self.assertEqual(list(stub.request.layers), [pb.DETECTION_LAYER_SEMANTIC])
        self.assertEqual(json.loads(out.getvalue()), {"context": expected["context"], "presence": expected["presence"]})


if __name__ == "__main__":
    unittest.main()
