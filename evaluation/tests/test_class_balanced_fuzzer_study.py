"""Read-only synthetic lifecycle checks: no Docker, RPC, or model training."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("class_balanced_study", Path(__file__).parents[1] / "run-class-balanced-fuzzer-study.py")
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def artifact():
    return {"model_id": "privoke-balanced", "version": "v0.3.0+train.2", "checksum": "original", "config": {}, "metadata": {}, "parameters": {"head": {"shape": [1], "values": [0.0], "trainable": True}, "encoder": {"shape": [1], "values": [0.0], "trainable": False}}}


def prepare(base, record):
    result = copy.deepcopy(base)
    if record["strategy"] == "last_block":
        result["parameters"]["encoder"]["trainable"] = True
    if record["objective"] != "uniform":
        result["metadata"]["contextual_training_objective"] = record["objective"]
    return result


def inventory(seed=42):
    return {"group_overlap": 0, "train": {"rows": 256, "groups": 256, "sensitivity_counts": {"S0": 248, "S3": 8}, "role_counts": {"clean": 248, "sensitive": 8}, "opaque_group_labels": {f"train-{seed}-{i}": ["S0" if i < 248 else "S3"] for i in range(256)}, "texts_sha256": str(seed).zfill(64), "ordered_samples_sha256": str(seed + 2).zfill(64)}, "heldout": {"rows": 16, "groups": 16, "sensitivity_counts": {"S0": 8, "S3": 8}, "role_counts": {"clean": 8, "sensitive": 8}, "opaque_group_labels": {f"heldout-{seed}-{i}": ["S0" if i < 8 else "S3"] for i in range(16)}, "texts_sha256": str(seed + 1).zfill(64), "ordered_samples_sha256": str(seed + 3).zfill(64)}}


def audit_metadata(record):
    result = {"learning_rate": str(record["rate"]), "max_gradient": ".05"}
    if record["objective"] != "uniform":
        result.update(contextual_training_objective=record["objective"], objective_strata="classification_is_sensitive")
        result.update({key: str(value) for key, value in zip(S.OBJECTIVE_AUDITS, (248, 8, 248, 8, 256, 128, 128, .5, .5))})
    return result


def verified(report, reference, model):
    rows = report["metadata"]["predictions"]
    if len(rows) != len(reference) or [(r["example_id"], r["expected_has_pii"], r["group_id"]) for r in rows] != [(r["id"], r["expected_has_pii"], r["group_id"]) for r in reference]:
        raise ValueError("Unmatched synthetic report")
    return {"tp": sum(r["expected_has_pii"] and r["detected_sensitive"] for r in rows), "tn": sum(not r["expected_has_pii"] and not r["detected_sensitive"] for r in rows), "fp": sum(not r["expected_has_pii"] and r["detected_sensitive"] for r in rows), "fn": sum(r["expected_has_pii"] and not r["detected_sensitive"] for r in rows)}


class FakeDriver:
    def __init__(self, args, state):
        self.args, self.state = args, state
        self.catalog = {key: Path(binding["path"]).read_bytes() for key, binding in state["catalog_backups"].items()}
        self.active_images = copy.deepcopy(state["images"])
        self.events, self.unknown, self.fail_measure, self.fail_restore = [], False, False, False

    def images(self):
        return self.active_images

    def model_bytes(self, key):
        return self.catalog[key]

    def install_model(self, key, raw):
        self.events.append(("restore-model", key))
        self.catalog[key] = raw

    def configure_images(self, images):
        self.state["study_images"] = {key: "feature-" + value for key, value in images.items()}

    def install_raw(self, profile, raw):
        self.catalog["privoke-" + profile] = raw

    def live(self, profile):
        return self.catalog["privoke-" + profile]

    def stop_jobs(self):
        self.events.append(("stop",))

    def refresh(self):
        self.active_images = copy.deepcopy(self.state["study_images"])

    def restore_services(self):
        if self.fail_restore:
            raise RuntimeError("restore failed")
        self.active_images = copy.deepcopy(self.state["images"])

    def train(self, record):
        self.events.append(("fit", record["index"]))
        if self.unknown:
            raise S.C.UnknownUpdateOutcome("synthetic unknown receipt")
        base = json.loads(self.live("balanced"))
        candidate = copy.deepcopy(base)
        candidate["version"] = "v0.3.0+train.3"
        candidate["checksum"] = "candidate"
        candidate["parameters"]["head"]["values"] = [.001]
        self.install_raw("balanced", json.dumps(candidate).encode())
        response = {"accepted": True, "request": record, "model_id": base["model_id"], "base_version": base["version"], "applied_version": candidate["version"], "prompts_generated": 256, "metadata": audit_metadata(record), "partition_inventory": inventory(record["seed"])}
        response["receipt"] = {"found": True, "accepted": True, **{key: response[key] for key in ("model_id", "base_version", "applied_version", "prompts_generated")}}
        return response

    def measure(self, model_path, dataset, reference, run_name):
        self.events.append(("measure", len(reference)))
        if self.fail_measure:
            raise RuntimeError("scoring failed after fit")
        tp, tn = (428, 144) if len(reference) == 968 else (238, 70)
        positive = negative = 0
        rows = []
        for row in reference:
            if row["expected_has_pii"]:
                detected = positive < tp
                positive += 1
            else:
                detected = negative >= tn
                negative += 1
            rows.append({"example_id": row["id"], "group_id": row["group_id"], "expected_has_pii": row["expected_has_pii"], "detected_sensitive": detected, "status": "ok", "layers": [{"status": "ok", "error": None}]})
        report = {"errors": [], "metadata": {"predictions": rows}, "metrics": {"runtime_errors": 0, "evaluated_samples": len(reference)}}
        counts, reports = {}, {}
        for layer in ("semantic", "pipeline"):
            path = self.args.output / (run_name + "-" + layer + ".json")
            S.write(path, report)
            counts[layer] = verified(report, reference, None)
            reports[layer] = {"path": str(path), "sha256": S.sha(path)}
        return counts, reports

    def fixture(self, model_path, cases, path):
        self.events.append(("fixture", len(cases)))
        result = {case["case_id"]: {"action": "WARN" if case["required_sensitive"] else "ALLOW"} for case in cases}
        S.write(path, result)
        return result


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.args = SimpleNamespace(output=self.output, limit=24)
        self.validation = [{"id": str(i), "expected_has_pii": i < 475, "group_id": "piimb:synthetic:" + str(i)} for i in range(968)]
        self.development = [{"id": "dev-" + str(i), "expected_has_pii": i < 264, "group_id": "piimb:synthetic:" + str(i)} for i in range(502)]
        self.cases = [{"case_id": str(i), "required_sensitive": i < 17, "minimum_action": "WARN" if i < 17 else "ALLOW", "ambiguous": i >= 41} for i in range(48)]
        self.state = {"prefix": S.PREFIX, "planned_attempts": list(S.attempts()), "records": [], "baseline_complete": True, "restoration_verified": True, "images": {key: key + "-original" for key in S.SERVICES}, "catalog_backups": {}, "validation": "validation", "development": "development", "fixture": "fixture", "baselines": {"balanced": {"validation": {"pipeline": {"tp": 427, "tn": 143, "fp": 350, "fn": 48}}}}}
        for key in S.MODEL_IDS:
            path = self.output / (key + ".json")
            S.write(path, artifact())
            self.state["catalog_backups"][key] = {"path": str(path), "sha256": S.sha(path)}
        self.driver = FakeDriver(self.args, self.state)
        for target, replacement in (("load_artifact", S.read), ("bound_inputs", lambda state: self.validation), ("bound_rows", lambda path, *args: self.development if path == "development" else self.cases), ("verified_report", verified), ("verify_guarded_publication", lambda *args: None)):
            guard = patch.object(S.C, target, replacement, create=True)
            guard.start()
            self.addCleanup(guard.stop)
        guard = patch.object(S, "prepare_base", prepare)
        guard.start()
        self.addCleanup(guard.stop)
        guard = patch.object(S, "LIVE_BASE_SHA", self.state["catalog_backups"]["privoke-balanced"]["sha256"])
        guard.start()
        self.addCleanup(guard.stop)

    def assert_restored(self):
        S.assert_originals(self.driver, self.state, S.backup_bytes(self.state))
        self.assertTrue(self.state["restoration_verified"])
        self.assertTrue(all(event[1] == "privoke-balanced" for event in self.driver.events if event[0] == "restore-model"))

    def test_full_grid_freezes_before_candidate_endpoint(self):
        S.candidates(self.args, self.state, self.driver)
        self.assertEqual(24, len(self.state["records"]))
        self.assertEqual(list(range(24)), [event[1] for event in self.driver.events if event[0] == "fit"])
        self.assertTrue(all(event[1] == 968 for event in self.driver.events if event[0] == "measure"))
        self.assertFalse(any(event[0] == "fixture" for event in self.driver.events))
        self.assert_restored()
        S.freeze(self.args, self.state)
        self.assertEqual(0, S.read(self.state["selection"]["path"])["winner"]["index"])
        counts, reports = self.driver.measure(Path(self.state["catalog_backups"]["privoke-balanced"]["path"]), "development", self.development, "reference-development")
        counts["pipeline"]["tn"] = 70  # The fake raw reference legitimately has TN70.
        fixture_path = self.output / "fixture-live.json"
        self.driver.fixture(None, self.cases, fixture_path)
        self.state["reference_endpoint"] = {"counts": counts, "reports": reports, "fixture": {"path": str(fixture_path), "sha256": S.sha(fixture_path)}}
        self.driver.events.clear()
        S.finalize(self.args, self.state, self.driver)
        self.assertEqual([502], [event[1] for event in self.driver.events if event[0] == "measure"])
        self.assertEqual([48], [event[1] for event in self.driver.events if event[0] == "fixture"])
        self.assertFalse(self.state["finalized"]["retained"])  # A specificity tie cannot pass.
        self.assert_restored()
        with self.assertRaises(ValueError):
            S.finalize(self.args, self.state, self.driver)

    def test_incomplete_grid_cannot_freeze(self):
        self.args.limit = 1
        S.candidates(self.args, self.state, self.driver)
        with self.assertRaises(ValueError):
            S.freeze(self.args, self.state)
        self.assertFalse((self.output / "selection.json").exists())

    def test_unknown_receipt_stops_and_is_not_retried(self):
        self.driver.unknown = True
        with self.assertRaises(S.C.UnknownUpdateOutcome):
            S.candidates(self.args, self.state, self.driver)
        self.assertEqual(1, sum(event[0] == "fit" for event in self.driver.events))
        self.assertTrue(self.state["unknown_outcome"]["request_reuse_forbidden"])
        self.assert_restored()
        with self.assertRaises(ValueError):
            S.candidates(self.args, self.state, self.driver)

    def test_scoring_failure_restores_and_reserved_fit_is_not_repeated(self):
        self.driver.fail_measure = True
        with self.assertRaises(RuntimeError):
            S.candidates(self.args, self.state, self.driver)
        self.assert_restored()
        self.driver.fail_measure = False
        with self.assertRaises(FileExistsError):
            S.candidates(self.args, self.state, self.driver)
        self.assertEqual(1, sum(event[0] == "fit" for event in self.driver.events))

    def test_restoration_failure_checkpoint_remains_false(self):
        self.args.limit = 1
        self.driver.fail_restore = True
        with self.assertRaises(RuntimeError):
            S.candidates(self.args, self.state, self.driver)
        saved = S.read(self.output / "state.json")
        self.assertFalse(saved["restoration_verified"])
        self.assertEqual("restore failed", saved["restoration_failure"]["message"])

    def test_objective_pair_must_reuse_exact_inventory(self):
        self.args.limit = 1
        S.candidates(self.args, self.state, self.driver)
        response = self.driver.train(self.state["planned_attempts"][1])
        response["partition_inventory"]["train"]["texts_sha256"] = "different"
        with self.assertRaises(ValueError):
            S.verify_pair(self.state, self.state["planned_attempts"][1], response)
        # This synthetic direct train call is not a controller request; explicitly restore it.
        self.driver.install_raw("balanced", Path(self.state["catalog_backups"]["privoke-balanced"]["path"]).read_bytes())
        self.assert_restored()

    def test_report_count_and_runtime_errors_are_rejected(self):
        counts, reports = self.driver.measure(None, "validation", self.validation, "audit")
        wrong = copy.deepcopy(counts)
        wrong["pipeline"]["tp"] += 1
        with self.assertRaises(ValueError):
            S.verify_measurement(wrong, reports, self.validation, artifact())
        path = Path(reports["pipeline"]["path"])
        report = S.read(path)
        report["metrics"]["runtime_errors"] = 1
        S.write(path, report)
        reports["pipeline"]["sha256"] = S.sha(path)
        with self.assertRaises(ValueError):
            S.verify_measurement(counts, reports, self.validation, artifact())

    def test_ordered_target_and_weight_commitment_is_required_and_paired(self):
        self.args.limit = 1
        S.candidates(self.args, self.state, self.driver)
        record = self.state["planned_attempts"][1]
        for partition in ("train", "heldout"):
            for replacement in (None, "f" * 64):
                response = {"partition_inventory": inventory(record["seed"])}
                if replacement is None:
                    del response["partition_inventory"][partition]["ordered_samples_sha256"]
                else:
                    response["partition_inventory"][partition]["ordered_samples_sha256"] = replacement
                with self.assertRaises(ValueError):
                    S.verify_pair(self.state, record, response)


class ProtocolChecks(unittest.TestCase):
    def test_grid_has_24_unique_paired_requests(self):
        records = list(S.attempts())
        self.assertEqual(24, len({record["request_id"] for record in records}))
        for index in range(0, 24, 2):
            self.assertEqual(S.inventory_pair(records[index]), S.inventory_pair(records[index + 1]))
            self.assertEqual(S.OBJECTIVES, (records[index]["objective"], records[index + 1]["objective"]))

    def test_unknown_objective_fails_before_preparation_import(self):
        with self.assertRaises(ValueError):
            S.prepare_base(artifact(), {"objective": "unknown", "strategy": "heads"})

    def test_receipt_must_bind_exact_published_version(self):
        record = next(S.attempts())
        response = {"accepted": True, "request": record, "receipt": {"found": False}}
        with self.assertRaises(S.C.UnknownUpdateOutcome):
            S.validate_response(response, record, artifact())

    def test_objective_audits_preserve_control_and_equal_mass(self):
        uniform, weighted = list(S.attempts())[:2]
        response = {"accepted": True, "metadata": audit_metadata(weighted), "partition_inventory": inventory()}
        self.assertEqual(.5, S.objective_audit(weighted, response)["sensitive_objective_mass"])
        mismatched = copy.deepcopy(response)
        mismatched["partition_inventory"]["train"]["sensitivity_counts"] = {"S0": 250, "S3": 6}
        with self.assertRaises(ValueError):
            S.objective_audit(weighted, mismatched)
        response["metadata"]["effective_sensitive_weight"] = "129"
        with self.assertRaises(ValueError):
            S.objective_audit(weighted, response)
        with self.assertRaises(ValueError):
            S.objective_audit(uniform, response)
        response = {"accepted": True, "metadata": {}, "partition_inventory": inventory()}
        self.assertTrue(S.objective_audit(uniform, response)["original_example_weights_preserved"])
        with self.assertRaises((KeyError, ValueError)):
            S.objective_audit(weighted, response)

    def test_parity_checks_each_case_and_frozen_encoder_delta(self):
        row = {"example_id": "one", "expected_has_pii": True, "detected_sensitive": True, "action": "WARN"}
        self.assertEqual(0, S.parity([row], [copy.deepcopy(row)])["classification_action_presence_mismatches"])
        changed = {**row, "action": "ALLOW"}
        with self.assertRaises(ValueError):
            S.parity([row], [changed])
        base, candidate = artifact(), artifact()
        candidate["parameters"]["encoder"]["values"] = [.001]
        with self.assertRaises(ValueError):
            S.parameter_changes(base, candidate)


if __name__ == "__main__":
    unittest.main()
