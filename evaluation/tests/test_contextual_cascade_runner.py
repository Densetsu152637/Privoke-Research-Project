from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_contextual_cascade_study", ROOT / "evaluation/run-contextual-cascade-study.py")
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class FakeBackend:
    def __init__(self, *, timeout_write=False, changed_image=False, fail_context_restore=False):
        self.catalog = {key: f"prior-bytes-{key}".encode() for key in runner.CATALOG_IDS}
        self.admin_mutation_outcome_unknown = False
        self.evaluator_job_outcome_unknown = False
        self.timeout_write = timeout_write
        self.changed_image = changed_image
        self.fail_context_restore = fail_context_restore
        self.writes, self.restores, self.probes, self.stages = [], [], [], []
        self.image_calls = 0
        self.job_images = {"sha256:" + "e" * 64}
        self.calls, self.jobs = [], []

    def ensure_services(self):
        pass

    def evaluator_image(self):
        return "sha256:" + "e" * 64

    def preflight_fit(self, *, inputs, binding, output):
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
            path = study_root / "calibration/selection.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"status": "frozen", "choices": choices}), encoding="utf-8")
            return {"status": "frozen", "choices": choices, "image_id": "sha256:" + "e" * 64}
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


if __name__ == "__main__":
    unittest.main()
