"""Execute archived-attempt recovery in an isolated tree without any live services."""
from contextlib import redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
RECOVERY = ROOT / "evaluation/results/contextual_fuzzer_20261006_preflight/recover_score.py"
SPEC = importlib.util.spec_from_file_location("recovery_contract", ROOT / "evaluation/run-contextual-fuzzer-study.py")
STUDY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STUDY)


class FakeRequest:
    """Only deterministic request framing is needed by this lifecycle test."""

    def __init__(self, **fields):
        self.fields = fields

    def SerializeToString(self, *, deterministic):
        if not deterministic:
            raise AssertionError("Recovery must verify deterministic request identity.")
        return json.dumps(self.fields, sort_keys=True, separators=(",", ":")).encode()


class ContextualRecoveryTests(unittest.TestCase):
    @unittest.skipUnless(RECOVERY.is_file(), "Local one-time recovery script is unavailable")
    def test_existing_accepted_attempt_is_scored_once_without_training(self):
        with tempfile.TemporaryDirectory(prefix=".contextual-recovery-", dir=ROOT / "evaluation/tests") as temporary:
            root = Path(temporary)
            root.resolve().relative_to((ROOT / "evaluation/tests").resolve())
            output = root / "evaluation/results/contextual_fuzzer_20261006_v2"
            target = output / "attempt-00"
            target.mkdir(parents=True)
            recovery = root / "evaluation/results/preflight/recover_score.py"
            recovery.parent.mkdir()
            recovery.write_bytes(RECOVERY.read_bytes())
            controller = root / "evaluation/run-contextual-fuzzer-study.py"
            controller.write_text("from _contextual_recovery_test_support import *\n", encoding="utf-8")
            old_controller = output / "old-controller.py"
            old_controller.write_text("# frozen failed controller\n", encoding="utf-8")
            scorer = root / "evaluation/scorer.py"
            scorer.write_text("# unchanged scorer\n", encoding="utf-8")
            protocol = root / "docs/fuzzer-model-study-20261006.md"
            protocol.parent.mkdir()
            protocol.write_text("Frozen protocol\n", encoding="utf-8")
            overlay = root / "evaluation/compose.contextual-fuzzer-study.yml"
            overlay.write_text("services: {}\n", encoding="utf-8")

            planned = list(STUDY.attempts("isolated-recovery"))
            record = planned[0]
            base = {"schema_version": 1, "architecture": "privoke_tiny_transformer_v1",
                    "model_id": "privoke-efficient", "version": "v0.3.0", "config": {},
                    "parameters": {f"head.{head}.{part}": {"shape": [1], "values": [0.0], "trainable": True}
                                   for head in ("sensitivity", "visibility", "category")
                                   for part in ("weight", "bias")}, "metadata": {}}
            candidate = copy.deepcopy(base)
            candidate["version"] = "v0.3.0+train.1"
            candidate["parameters"]["head.sensitivity.bias"]["values"] = [.01]
            for artifact in (base, candidate):
                artifact["checksum"] = STUDY.hashlib.sha256(json.dumps(
                    artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            request = FakeRequest(request_id=record["request_id"], source_id=record["source_id"],
                                  model_id=base["model_id"], prompt_count=256, seed=record["seed"],
                                  metadata={"initiator": "contextual-study-controller"})
            response = {"request": record, "request_fingerprint": hashlib.sha256(
                request.SerializeToString(deterministic=True)).hexdigest(), "accepted": True,
                "base_version": base["version"], "applied_version": candidate["version"],
                "model_id": base["model_id"], "prompts_generated": 256,
                "metadata": {"base_parameter_fingerprint": STUDY.training_value_fingerprint(base),
                             "updated_parameter_fingerprint": STUDY.training_value_fingerprint(candidate)},
                "receipt": {"found": True, "accepted": True, "model_id": base["model_id"],
                            "base_version": base["version"], "applied_version": candidate["version"],
                            "prompts_generated": 256}, "partition_inventory": {"already_archived": True}}
            for name, value in (("request.json", record), ("base.json", base),
                                ("candidate.json", candidate), ("response.json", response)):
                STUDY.write(target / name, value)
            archived_hashes = {path.name: STUDY.sha(path) for path in target.iterdir()}
            catalog = {profile: ("original-" + profile + "\r\n").encode()
                       for profile in STUDY.PROFILES}
            original_catalog = dict(catalog)
            backups = {}
            for profile, raw in catalog.items():
                path = output / f"backup-{profile}.json"
                path.write_bytes(raw)
                backups[profile] = {"path": str(path), "sha256": STUDY.sha(path)}
            images = {name: "immutable-" + name for name in STUDY.SERVICES}
            state = {"prefix": "isolated-recovery", "planned_attempts": planned, "records": [],
                     "failure": {"message": "Published candidate differs from the exact base/candidate guarded by training."},
                     "source_revision": "frozen-commit", "controller_sha256": STUDY.sha(old_controller),
                     "source_freeze": {"controller.py": {"path": str(old_controller), "sha256": STUDY.sha(old_controller)}},
                     "computation_source_sha256": {"evaluation/scorer.py": STUDY.sha(scorer)},
                     "protocol_canonical_lf_sha256": hashlib.sha256(protocol.read_text(encoding="utf-8").encode()).hexdigest(), "base_override_sha256": {},
                     "overlay_sha256": STUDY.sha(overlay), "live_backups": backups, "images": images,
                     "project_name": "isolated", "runtime_target": "fake.invalid:1", "validation": "fake-validation",
                     "baselines": {"efficient": {"validation": {"pipeline": {"tn": 100}}}}}
            STUDY.write(output / "state.json", state)
            failed_state_bytes = (output / "state.json").read_bytes()
            events = []

            def forbidden(*args, **kwargs):
                raise AssertionError("Recovery must never train or resample.")

            class FakeDriver:
                train = forbidden
                generate_training_partition = forbidden

                def __init__(self, args, current_state):
                    self.log = None

                def images(self):
                    return images

                def live(self, profile):
                    return catalog[profile]

                def configure_images(self, expected):
                    self.expected_images = expected

                def stop_jobs(self):
                    events.append("stop")

                def install_raw(self, profile, raw):
                    events.append(("install", profile))
                    catalog[profile] = raw

                def refresh(self):
                    events.append("refresh")

                def restore_services(self):
                    events.append("restore-services")

                def measure(self, artifact, dataset, reference, run_name):
                    events.append("measure")
                    if Path(artifact) != target / "candidate.json":
                        raise AssertionError("Only the archived candidate can be measured.")
                    if catalog["efficient"] != (target / "candidate.json").read_bytes():
                        raise AssertionError("Archived bytes must be installed unchanged.")
                    counts = {layer: {"tp": 428, "tn": 101, "fp": 392, "fn": 47}
                              for layer in ("semantic", "pipeline")}
                    report = output / "fake-report.json"
                    STUDY.write(report, counts)
                    return counts, {layer: {"path": str(report), "sha256": STUDY.sha(report)}
                                    for layer in counts}

            support = ModuleType("_contextual_recovery_test_support")
            for name in ("sha", "write", "read", "attempts", "load_artifact", "verify_guarded_publication",
                         "artifact_identity", "candidate_key", "restored_catalog"):
                setattr(support, name, getattr(STUDY, name))
            support.hashlib = hashlib
            support.subprocess = SimpleNamespace(check_output=lambda *args, **kwargs: "frozen-commit\n")
            support.computation_sources = lambda: [scorer]
            support.bound_inputs = lambda current_state: [{"id": "synthetic-validation"}]
            support.Driver = FakeDriver
            support.train = forbidden
            support.generate_training_partition = forbidden
            pb = ModuleType("privoke.v1.parameters_pb2")
            pb.FuzzerTrainingRequest = FakeRequest
            privoke = ModuleType("privoke")
            version = ModuleType("privoke.v1")
            privoke.v1 = version
            version.parameters_pb2 = pb
            modules = {support.__name__: support, "privoke": privoke, "privoke.v1": version,
                       "privoke.v1.parameters_pb2": pb}
            with patch.dict(sys.modules, modules), redirect_stdout(io.StringIO()):
                runpy.run_path(str(recovery), run_name="__main__")

            recovered = STUDY.read(output / "state.json")
            self.assertEqual(events.count("measure"), 1)
            self.assertEqual(events[0], "stop")
            self.assertEqual(catalog, original_catalog)
            self.assertEqual(events[-1], "restore-services")
            self.assertEqual(recovered["planned_attempts"], planned)
            self.assertEqual([row["index"] for row in recovered["records"]], [0])
            self.assertEqual([row["index"] for row in planned if row["index"] not in
                              {item["index"] for item in recovered["records"]}], list(range(1, 54)))
            self.assertTrue(recovered["restoration_verified"])
            revision = output / "execution-revision-01"
            self.assertEqual((revision / "state-before.json").read_bytes(), failed_state_bytes)
            self.assertEqual(recovered["execution_amendments"][0]["previous_failure"], state["failure"])
            self.assertEqual(STUDY.sha(old_controller), state["controller_sha256"])
            self.assertEqual({path.name: STUDY.sha(path) for path in target.iterdir()}, archived_hashes)
            self.assertIsNone(recovered["records"][0]["wall_seconds"])
            self.assertGreaterEqual(recovered["records"][0]["recovery_scoring_seconds"], 0)
            self.assertEqual(recovered["records"][0]["recovery_manifest"]["sha256"],
                             STUDY.sha(revision / "amendment.json"))
            with patch.dict(sys.modules, modules), self.assertRaisesRegex(RuntimeError, "known pre-score"):
                runpy.run_path(str(recovery), run_name="__main__")
            self.assertEqual(events.count("measure"), 1)


if __name__ == "__main__":
    unittest.main()
