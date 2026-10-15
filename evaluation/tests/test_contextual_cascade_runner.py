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
        self.assertEqual(state["status"], "complete", state["errors"])
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

    def _fixture_plan(self):
        choices = {pair: {"status": "eligible", "chosen": {"threshold": .5}}
                   for pair in runner.PAIRS}
        choices[runner.PAIRS[0]] = {"status": "ineligible", "chosen": None}
        support = {
            "fixture.jsonl": {"sha256": runner.FIXTURE_SHA256, "relative_path": "support/fixture.jsonl"},
            "rubric.md": {"sha256": runner.RUBRIC_SHA256, "relative_path": "support/rubric.md"},
            "fixture-review.json": {"sha256": runner.FIXTURE_REVIEW_SHA256,
                                     "relative_path": "support/fixture-review.json"},
        }
        case_ids = [f"case-{i}" for i in range(48)]
        case_rows = [{"case_id": case_id, "text": case_id,
                      "visibility_hint": "P2" if i < 4 else None}
                     for i, case_id in enumerate(case_ids)]
        pair_bindings = {pair: {"pair": pair, "source_revision": "b" * 40} for pair in runner.PAIRS}
        primary = {"manifest_sha256": "1" * 64, "selection_sha256": "2" * 64,
                   "source_revision": "a" * 40}
        return {"primary": primary, "secondary_binding": {"mode": "secondary_contextual_fixtures",
                "execution_source_revision": "b" * 40},
            "support": support, "selection": {"choices": choices},
            "choices_compact": {pair: choices[pair] for pair in runner.PAIRS},
            "case_counts": {"total": 48}, "case_ids": case_ids,
            "case_rows": case_rows,
            "pair_bindings": pair_bindings, "validation_file": "unused",
            "source_revision": "b" * 40, "runtime_image_id": "sha256:" + "a" * 64,
            "evaluator_image_id": "sha256:" + "e" * 64,
            "integrity_check": lambda: None}

    def _run_fixture_sequence(self, backend):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "study"
        output.mkdir()
        inputs = fake_inputs()
        prior = dict(backend.catalog)
        binding = {"runtime_image_id": "sha256:" + "a" * 64,
                   "evaluator_image_id": "sha256:" + "e" * 64,
                   "source_revision": "a" * 40}
        plan = self._fixture_plan()
        plan["primary"]["scorer_binding"] = binding
        preflight_receipt = {"binding": binding, "selection_sha256": plan["primary"]["selection_sha256"],
            "fixture_sha256": runner.FIXTURE_SHA256, "rubric_sha256": runner.RUBRIC_SHA256,
            "review_sha256": runner.FIXTURE_REVIEW_SHA256, "case_counts": plan["case_counts"],
            "choices": plan["choices_compact"]}
        def fixture_preflight(**kwargs):
            if getattr(backend, "fixture_preflight_error", False):
                raise ValueError("frozen primary selection mismatch")
            return {"status": "frozen_study_verified", "receipt": preflight_receipt,
                    "report_sha256": "f" * 64}
        backend.run_fixture_preflight = fixture_preflight
        backend.run_fixture_stage = lambda **kwargs: backend.fixture_stage(**kwargs)
        def fixture_stage(**kwargs):
            pair = kwargs["pair"]
            backend.fixture_calls.append((pair, kwargs["eligible"]))
            return {"status": "complete" if kwargs["eligible"] else "skipped_ineligible",
                    "report_sha256": "f" * 64, "image_id": "sha256:" + "e" * 64,
                    "container_id": "a" * 12, "exit_code": 0, "logs_sha256": "1" * 64}
        backend.fixture_stage = fixture_stage
        backend.fixture_calls = []
        primary_receipt = output / "primary-controller-manifest.json"
        primary_receipt.write_bytes(b"frozen-primary-receipt")
        events = []
        original_write, original_probe = backend.write_artifact, backend.probe
        context_name = [None]
        checksum_to_context = {runner.CONTEXT_CHECKSUMS[name]: name for name in runner.CONTROLS}
        def write(artifact, *, expected_checksum):
            if artifact["model_id"] == "privoke-balanced":
                context_name[0] = checksum_to_context.get(artifact["checksum"])
            else:
                events.append(("write", context_name[0], artifact["model_id"]))
            original_write(artifact, expected_checksum=expected_checksum)
        def probe(expected):
            events.append(("probe", context_name[0], expected.get("presence", {}).get("model_id")))
            original_probe(expected)
        backend.write_artifact, backend.probe = write, probe
        prior_catalog = {runner.PRESENCE_IDS[name]: {"checksum": inputs["presence"][name]["identity"]["artifact_checksum"]}
                         for name in runner.PROFILES}
        with patch.object(runner, "check_prior_catalog", return_value=prior_catalog), \
             patch.object(runner, "safe_error", side_effect=lambda exc: {"error_type": type(exc).__name__, "message": str(exc)}):
            state = runner.run_sequence(backend=backend, output=output,
                study_root=output / "primary", inputs=inputs, binding=binding, fixture_plan=plan)
        self.assertEqual(primary_receipt.read_bytes(), b"frozen-primary-receipt")
        backend.fixture_events = events
        return state, prior, backend

    def test_fixture_mode_runs_fixed_six_pairs_and_restores_shared_catalog(self):
        backend = FakeBackend()
        state, prior, _ = self._run_fixture_sequence(backend)
        self.assertEqual(state["status"], "complete", state["errors"])
        self.assertTrue(state["restoration_verified"])
        self.assertEqual(backend.catalog, prior)
        self.assertEqual(backend.fixture_calls, [(pair, pair != runner.PAIRS[0]) for pair in runner.PAIRS])
        jobs = [job for job in state["phase_jobs"] if job["stage"] == "fixture-score"]
        self.assertEqual([job["pair"] for job in jobs], list(runner.PAIRS))
        self.assertEqual(jobs[0]["status"], "skipped_ineligible")
        self.assertEqual(state["primary_manifest_sha256"], "1" * 64)
        self.assertIn("secondary_binding", state)
        self.assertEqual(state["binding"]["source_revision"], "a" * 40)
        self.assertEqual(state["secondary_binding"]["execution_source_revision"], "b" * 40)
        self.assertFalse(any(context == "original" and model_id == runner.PRESENCE_IDS["efficient"]
                             for _kind, context, model_id in backend.fixture_events))

    def test_fixture_mode_preflight_rejection_occurs_before_backup_or_model_write(self):
        backend = FakeBackend()
        backend.fixture_preflight_error = True
        state, _prior, _ = self._run_fixture_sequence(backend)
        self.assertEqual(state["status"], "failed")
        self.assertEqual(backend.writes, [])
        self.assertEqual(backend.restores, [])
        self.assertFalse(any(call[0] == "fixture-score" for call in backend.stages))

    def test_fixture_mode_runtime_or_evaluator_image_mismatch_prevents_writes(self):
        for mismatch in ("runtime", "evaluator"):
            backend = FakeBackend()
            binding = {"runtime_image_id": "sha256:" + "a" * 64,
                       "evaluator_image_id": "sha256:" + "e" * 64,
                       "source_revision": "a" * 40}
            plan = self._fixture_plan()
            plan["primary"]["scorer_binding"] = binding
            if mismatch == "runtime":
                binding["runtime_image_id"] = "sha256:" + "b" * 64
            else:
                backend.evaluator_image = lambda: "sha256:" + "f" * 64
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / "study"
                output.mkdir()
                with patch.object(runner, "check_prior_catalog", return_value={}):
                    state = runner.run_sequence(backend=backend, output=output,
                        study_root=output / "primary", inputs=fake_inputs(), binding=binding,
                        fixture_plan=plan)
            self.assertEqual(state["status"], "failed", mismatch)
            self.assertEqual(backend.writes, [], mismatch)
            self.assertEqual(backend.restores, [], mismatch)

    def test_fixture_support_hash_mismatch_fails_before_scoring(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "results"
            support = root / "support"
            support.mkdir(parents=True)
            (support / "fixture.jsonl").write_text("unexpected fixture bytes", encoding="utf-8")
            output = root / "secondary"
            output.mkdir()
            with patch.object(runner, "RESULTS", root):
                with self.assertRaisesRegex(ValueError, "support copy"):
                    runner.copy_fixture_support(support, output)
            self.assertFalse((output / "support" / "rubric.md").exists())

    def _fixture_pair_evidence(self, root):
        output = root / "pair"
        raw_dir = output / "raw"
        raw_dir.mkdir(parents=True)
        cases = [{"case_id": f"case-{i}", "text": f"private fixture {i}",
                  "visibility_hint": "P2" if i < 4 else None,
                  "required_sensitive": False, "allowed_actions": ["ALLOW"]} for i in range(48)]
        identity = {"model_id": runner.PRESENCE_IDS["efficient"], "model_version": "v1",
            "artifact_checksum": "a" * 64, "parameter_fingerprint": "b" * 64, "threshold": .5}
        semantic_identity = {"model_id": "privoke-balanced", "model_version": "v0.3.0",
            "artifact_checksum": "8" * 64, "parameter_fingerprint": "9" * 64}
        binding = {"source_revision": "c" * 40, "study_binding": {
            "controls": {"original": {"identity": semantic_identity}},
            "presence": {"efficient": {"identity": identity}}}, "selection_sha256": "d" * 64,
            "pair": "original-efficient", "case_file_sha256": "e" * 64,
            "rubric_sha256": "f" * 64, "fixture_review_sha256": "1" * 64,
            "caller_sha256": "2" * 64, "cascade_helper_sha256": "3" * 64,
            "runtime_image_id": "sha256:" + "4" * 64,
            "evaluator_image_id": "sha256:" + "5" * 64,
            "validation_file_sha256": "6" * 64}
        normalized_predictions, raw_hashes = [], {}
        scorer_path = runner.container_path(output)
        for case in cases:
            row = {"case": case}
            digest = hashlib.sha256(case["case_id"].encode()).hexdigest()
            for tag in ("ordinary", "gated"):
                request_id = "cascade-" + hashlib.sha256(
                    f"cascade-{scorer_path}-{tag}-{case['case_id']}".encode()).hexdigest()[:48]
                request = {"request_id": request_id, "text": case["text"]}
                if case["visibility_hint"] is not None:
                    request["visibility_hint"] = case["visibility_hint"]
                if tag == "gated":
                    request["semantic_presence_gate"] = {"model_id": identity["model_id"], "threshold": .3}
                layers = [
                    {"layer": "DETECTION_LAYER_REGEX", "status": "ok", "results": []},
                    {"layer": "DETECTION_LAYER_NER", "status": "ok", "results": []},
                    {"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok", "results": []},
                ]
                layer = layers[-1]
                if tag == "gated":
                    layer["semantic_presence_gate"] = {"status": "SEMANTIC_PRESENCE_GATE_STATUS_APPLIED",
                        "predicted_label": "ANNOTATION_PRESENCE_ABSENT", "model_id": identity["model_id"],
                        "model_version": identity["model_version"], "artifact_checksum": identity["artifact_checksum"],
                        "parameter_fingerprint": identity["parameter_fingerprint"],
                        "model_threshold": .5, "decision_threshold": .3, "probability": .1,
                        "error": "", "semantic_results": [],
                        "contextual_model_id": semantic_identity["model_id"],
                        "contextual_model_version": semantic_identity["model_version"],
                        "contextual_artifact_checksum": semantic_identity["artifact_checksum"],
                        "contextual_parameter_fingerprint": semantic_identity["parameter_fingerprint"]}
                response = {"request_id": request_id,
                    "classification": {"sensitivity": "S0", "categories": []},
                    "action": "ALLOW", "allowed": True, "masked_text": case["text"],
                    "evidence": [], "layers": layers}
                normalized = json.loads(json.dumps(response))
                for normalized_layer, layer_name in zip(normalized["layers"], ("regex", "ner", "semantic")):
                    normalized_layer["layer"] = layer_name
                if tag == "gated":
                    normalized["layers"][-1]["semantic_presence_gate"]["status"] = "applied"
                    normalized["layers"][-1]["semantic_presence_gate"]["predicted_label"] = "absent"
                    row["trace"] = normalized["layers"][-1]["semantic_presence_gate"]
                row[tag] = normalized
                path = raw_dir / f"{tag}-{digest}.json"
                path.write_text(json.dumps({"request": request, "response": response,
                    "request_binary_sha256": "7" * 64}), encoding="utf-8")
                raw_hashes[path.name] = runner.sha_file(path)
            normalized_predictions.append(row)
        predictions = output / "predictions.json"
        predictions.write_text(json.dumps(normalized_predictions), encoding="utf-8")
        report = {**binding, "status": "complete", "errors": [], "rows": 48,
            "pair": "original-efficient", "decision_threshold": .3,
            "predictions_sha256": runner.sha_file(predictions),
            "raw_rpc_sha256": raw_hashes}
        (output / "report.json").write_text(json.dumps(report), encoding="utf-8")
        (output / "binding.json").write_text(json.dumps(binding), encoding="utf-8")
        return output, binding, cases, identity

    def test_fixture_pair_validator_binds_raw_text_hints_gate_and_predictions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(runner, "RESULTS", root):
                output, binding, cases, identity = self._fixture_pair_evidence(root)
                result = runner.validate_fixture_pair_output(output_dir=output, pair="original-efficient",
                    eligible=True, expected_binding=binding, cases=cases, presence_identity=identity,
                    decision_threshold=.3)
                self.assertEqual(result["raw_rpc_count"], 96)

    def test_fixture_pair_validator_rejects_raw_error_text_hint_threshold_and_prediction_tampering(self):
        for mutation in ("error", "text", "hint", "request_threshold", "decision_threshold",
                         "model_threshold", "context_identity", "arbitrary_skip", "prediction",
                         "case_annotation"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                with patch.object(runner, "RESULTS", root):
                    output, binding, cases, identity = self._fixture_pair_evidence(root)
                    path = output / "raw" / f"gated-{hashlib.sha256(b'case-0').hexdigest()}.json"
                    record = json.loads(path.read_text(encoding="utf-8"))
                    if mutation == "error":
                        record["response"]["error"] = "synthetic runtime failure"
                    elif mutation == "text":
                        record["request"]["text"] = "changed"
                    elif mutation == "hint":
                        record["request"]["visibility_hint"] = "P1"
                    elif mutation == "request_threshold":
                        record["request"]["semantic_presence_gate"]["threshold"] = .5
                    elif mutation == "decision_threshold":
                        record["response"]["layers"][-1]["semantic_presence_gate"]["decision_threshold"] = .5
                    elif mutation == "model_threshold":
                        record["response"]["layers"][-1]["semantic_presence_gate"]["model_threshold"] = .3
                    elif mutation == "context_identity":
                        record["response"]["layers"][-1]["semantic_presence_gate"]["contextual_model_id"] = "wrong-context"
                        prediction_path = output / "predictions.json"
                        predictions = json.loads(prediction_path.read_text(encoding="utf-8"))
                        trace = predictions[0]["gated"]["layers"][-1]["semantic_presence_gate"]
                        trace["contextual_model_id"] = "wrong-context"
                        predictions[0]["trace"]["contextual_model_id"] = "wrong-context"
                        prediction_path.write_text(json.dumps(predictions), encoding="utf-8")
                    elif mutation == "arbitrary_skip":
                        record["response"]["layers"][-1]["status"] = "skipped"
                        record["response"]["layers"][-1]["error"] = "unapproved skip"
                    elif mutation == "case_annotation":
                        prediction_path = output / "predictions.json"
                        predictions = json.loads(prediction_path.read_text(encoding="utf-8"))
                        predictions[0]["case"]["required_sensitive"] = True
                        prediction_path.write_text(json.dumps(predictions), encoding="utf-8")
                    else:
                        prediction_path = output / "predictions.json"
                        predictions = json.loads(prediction_path.read_text(encoding="utf-8"))
                        predictions[0]["gated"]["action"] = "BLOCK"
                        prediction_path.write_text(json.dumps(predictions), encoding="utf-8")
                    path.write_text(json.dumps(record), encoding="utf-8")
                    report_path = output / "report.json"
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    report["raw_rpc_sha256"][path.name] = runner.sha_file(path)
                    report["predictions_sha256"] = runner.sha_file(output / "predictions.json")
                    report_path.write_text(json.dumps(report), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        runner.validate_fixture_pair_output(output_dir=output, pair="original-efficient",
                            eligible=True, expected_binding=binding, cases=cases, presence_identity=identity,
                            decision_threshold=.3)

    def test_completed_primary_requires_successful_restore_and_terminal_pair_outcomes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "results"
            results_patcher = patch.object(runner, "RESULTS", root)
            results_patcher.start()
            self.addCleanup(results_patcher.stop)
            primary_path = root / "primary"
            study = primary_path / "cascade-evidence"
            selection_path = study / "calibration/selection.json"
            selection_path.parent.mkdir(parents=True)
            binding = {"controls": {name: {} for name in runner.CONTROLS},
                "presence": {name: {} for name in runner.PROFILES},
                "runtime_image_id": "sha256:" + "a" * 64,
                "evaluator_image_id": "sha256:" + "e" * 64}
            for index, name in enumerate(runner.CONTROLS):
                binding["controls"][name] = {"path": str(root / f"{name}.json"),
                    "file_sha256": str(index) * 64,
                    "identity": {"model_id": "privoke-balanced", "artifact_checksum": str(index + 3) * 64,
                                 "parameter_fingerprint": str(index + 5) * 64}}
            scorer_binding = runner.linux_scorer_binding(binding)
            self.assertEqual(binding["controls"]["original"]["path"], str(root / "original.json"))
            self.assertEqual(scorer_binding["controls"]["original"]["path"],
                "/workspace/evaluation/results/original.json")
            choices = {pair: {"status": "eligible", "chosen": {"threshold": .5}}
                       for pair in runner.PAIRS}
            selection = {"status": "frozen", "binding": scorer_binding, "choices": choices,
                         "frozen_before_development": True}
            selection_path.write_text(json.dumps(selection), encoding="utf-8")
            (study / "study-manifest.json").write_text(json.dumps({"binding": scorer_binding}), encoding="utf-8")
            (primary_path / "input-binding.json").write_text(json.dumps(binding), encoding="utf-8")
            jobs = [{"image_id": binding["evaluator_image_id"]}]
            phases = [{"stage": stage, "pair": pair, "status": "complete"}
                      for stage in ("collect-validation", "evaluate-validation", "evaluate-development")
                      for pair in runner.PAIRS]
            manifest = {"status": "complete", "restoration_verified": True,
                "admin_mutation_outcome_unknown": False, "evaluator_job_outcome_unknown": False,
                "binding": binding, "images_before": {"client-runtime": binding["runtime_image_id"]},
                "images_after": {"client-runtime": binding["runtime_image_id"]}, "jobs": jobs,
                "calibration_sha256": runner.sha_file(selection_path), "phase_jobs": phases}
            (primary_path / "study-run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            immutable_receipts = {path: path.read_bytes() for path in (
                primary_path / "study-run-manifest.json", primary_path / "input-binding.json",
                study / "study-manifest.json", selection_path)}
            with patch.object(runner, "RESULTS", root):
                loaded = runner.load_completed_primary(primary_path)
                self.assertEqual(loaded["selection_sha256"], runner.sha_file(selection_path))
                self.assertEqual(loaded["binding"], binding)
                self.assertEqual(loaded["scorer_binding"], scorer_binding)
                self.assertEqual({path: path.read_bytes() for path in immutable_receipts}, immutable_receipts)
                manifest["phase_jobs"] = manifest["phase_jobs"][:-1]
                (primary_path / "study-run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "all-six terminal"):
                    runner.load_completed_primary(primary_path)
                manifest["phase_jobs"] = phases
                manifest["restoration_verified"] = False
                (primary_path / "study-run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "complete, restored primary"):
                    runner.load_completed_primary(primary_path)
                manifest["restoration_verified"] = True
                (primary_path / "study-run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                selection["binding"]["controls"]["original"]["identity"]["parameter_fingerprint"] = "9" * 64
                selection_path.write_text(json.dumps(selection), encoding="utf-8")
                manifest["calibration_sha256"] = runner.sha_file(selection_path)
                (primary_path / "study-run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "frozen selection"):
                    runner.load_completed_primary(primary_path)

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
