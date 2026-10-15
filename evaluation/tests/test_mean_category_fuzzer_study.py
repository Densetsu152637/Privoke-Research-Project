"""Phase03 synthetic protocol/lifecycle checks; no fitting, RPC or Docker."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIRECTORY = Path(__file__).parent
M = load("mean_category_study", DIRECTORY.parent / "run-mean-category-fuzzer-study.py")
F = load("phase02_fake_fixtures", DIRECTORY / "test_class_balanced_fuzzer_study.py")


def artifact():
    result = F.artifact()
    result["config"] = {"category_labels": ["IDENTITY", "HEALTH"]}
    return result


def inventory(seed=42):
    result = F.inventory(seed)
    for name in ("train", "heldout"):
        result[name]["ordered_samples_sha256"] = result[name]["texts_sha256"]
    return result


def loss_metadata():
    return {"supervised_sensitivity_ce_loss": "1.0", "supervised_visibility_ce_loss": ".5", "supervised_category_bce_loss": ".25", "supervised_objective_loss": "1.75", "category_count": "2", "category_normalization": "mean_per_label", "diagnostic_loss": "weighted_classification_distance"}


class FakeDriver(F.FakeDriver):
    def __init__(self, args, state):
        super().__init__(args, state)
        self.eligible = True

    def train(self, record):
        # Inspect the generated inventory before the synthetic fit event.
        M.verify_pair(self.state, record, {"partition_inventory": inventory(record["seed"])})
        try:
            response = super().train(record)
        except F.S.C.UnknownUpdateOutcome as error:
            raise M.C.UnknownUpdateOutcome(str(error)) from error
        response["metadata"].update(loss_metadata())
        response["metadata"]["total_weight"] = "256"
        response["partition_inventory"] = inventory(record["seed"])
        return response

    def measure(self, *args):
        counts, reports = super().measure(*args)
        if not self.eligible and len(args[2]) == 968:
            for layer, binding in reports.items():
                report = M.read(binding["path"])
                row = next(row for row in report["metadata"]["predictions"] if row["expected_has_pii"] and row["detected_sensitive"])
                row["detected_sensitive"] = False
                M.write(binding["path"], report)
                binding["sha256"] = M.sha(binding["path"])
                counts[layer] = F.verified(report, args[2], None)
        return counts, reports


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.args = SimpleNamespace(output=self.output, limit=12)
        self.validation = [{"id": str(i), "expected_has_pii": i < 475, "group_id": "piimb:synthetic:" + str(i)} for i in range(968)]
        self.development = [{"id": "dev-" + str(i), "expected_has_pii": i < 264, "group_id": "piimb:synthetic:" + str(i)} for i in range(502)]
        self.cases = [{"case_id": str(i), "required_sensitive": i < 17, "minimum_action": "WARN" if i < 17 else "ALLOW", "ambiguous": i >= 41} for i in range(48)]
        self.state = {"prefix": M.PREFIX, "phase": "mean-category-objective-representation", "planned_attempts": list(M.attempts()), "records": [], "baseline_complete": True, "restoration_verified": True, "images": {key: key + "-original" for key in M.SERVICES}, "catalog_backups": {}, "validation": "validation", "development": "development", "fixture": "fixture", "baselines": {"balanced": {"validation": {"pipeline": {"tp": 427, "tn": 143, "fp": 350, "fn": 48}}}}}
        for key in M.MODEL_IDS:
            path = self.output / (key + ".json")
            M.write(path, artifact())
            self.state["catalog_backups"][key] = {"path": str(path), "sha256": M.sha(path)}
        for target, replacement in (("load_artifact", M.read), ("bound_inputs", lambda state: self.validation), ("bound_rows", lambda path, *args: self.development if path == "development" else self.cases), ("verified_report", F.verified), ("verify_guarded_publication", lambda *args: None)):
            guard = patch.object(M.C, target, replacement)
            guard.start()
            self.addCleanup(guard.stop)
        for module, target, replacement in ((M, "prepare_base", F.prepare), (M.P, "prepare_base", F.prepare), (M, "LIVE_BASE_SHA", self.state["catalog_backups"]["privoke-balanced"]["sha256"])):
            guard = patch.object(module, target, replacement)
            guard.start()
            self.addCleanup(guard.stop)
        self.prior_path = self.output / "historical"
        self.prior_path.mkdir()
        prior = {"phase": "class-balanced-objective-representation", "planned_attempts": list(M.P.attempts()), "records": [], "restoration_verified": True, "finalized": {"retained": False}, "catalog_backups": self.state["catalog_backups"], "images": self.state["images"], "preparation_manifest_sha256": "prepared", "project_name": "project", "runtime_target": "runtime", "base_overrides": [], "base_override_sha256": {}, "source_revision": "commit"}
        for record in prior["planned_attempts"]:
            target = self.prior_path / str(record["index"])
            target.mkdir()
            base_path, response_path = target / "base.json", target / "response.json"
            M.write(base_path, F.prepare(artifact(), record))
            response = {"request": record, "accepted": False, "error_code": "FAILED_PRECONDITION", "receipt": {"found": False}, "metadata": {}, "partition_inventory": inventory(record["seed"])}
            M.write(response_path, response)
            prior["records"].append({**record, "accepted": False, "response_path": str(response_path), "response_sha256": M.sha(response_path), "base_artifact": str(base_path), "base_artifact_sha256": M.sha(base_path), "partition_inventory": response["partition_inventory"]})
        selection_path = self.prior_path / "selection.json"
        M.write(selection_path, {"candidate_count": 24, "winner": None})
        prior["selection"] = {"path": str(selection_path), "sha256": M.sha(selection_path)}
        M.write(self.prior_path / "state.json", prior)
        self.state["prior_study"] = M.bind_prior_study(self.prior_path)
        self.driver = FakeDriver(self.args, self.state)
        counts, reports = self.driver.measure(None, "validation", self.validation, "baseline-validation")
        for layer, binding in reports.items():
            report = M.read(binding["path"])
            for truth, before, after in ((True, True, False), (False, False, True)):
                row = next(row for row in report["metadata"]["predictions"] if row["expected_has_pii"] == truth and row["detected_sensitive"] == before)
                row["detected_sensitive"] = after
            M.write(binding["path"], report)
            binding["sha256"] = M.sha(binding["path"])
            counts[layer] = F.verified(report, self.validation, None)
        original = self.state["catalog_backups"]["privoke-balanced"]
        self.state["baselines"]["balanced"] = {"artifact": original["path"], "sha256": original["sha256"], "validation": counts, "reports": reports}
        self.driver.events.clear()

    def assert_restored(self):
        M.assert_originals(self.driver, self.state, M.backup_bytes(self.state))
        self.assertTrue(self.state["restoration_verified"])
        self.assertTrue(all(event[1] == "privoke-balanced" for event in self.driver.events if event[0] == "restore-model"))

    def test_twelve_terminal_attempts_before_once_only_endpoint(self):
        M.candidates(self.args, self.state, self.driver)
        self.assertEqual(list(range(12)), [event[1] for event in self.driver.events if event[0] == "fit"])
        self.assertTrue(all(event[1] == 968 for event in self.driver.events if event[0] == "measure"))
        self.assertFalse(any(event[0] == "fixture" for event in self.driver.events))
        self.assert_restored()
        M.freeze(self.args, self.state)
        selection = M.read(self.state["selection"]["path"])
        self.assertEqual(12, selection["candidate_count"])
        self.assertEqual(0, selection["winner"]["index"])
        self.assertFalse(selection["historical_controls_select"])
        counts, reports = self.driver.measure(None, "development", self.development, "reference-development")
        fixture_path = self.output / "fixture-live.json"
        self.driver.fixture(None, self.cases, fixture_path)
        self.state["reference_endpoint"] = {"counts": counts, "reports": reports, "fixture": {"path": str(fixture_path), "sha256": M.sha(fixture_path)}}
        self.driver.events.clear()
        M.finalize(self.args, self.state, self.driver)
        self.assertEqual([502], [event[1] for event in self.driver.events if event[0] == "measure"])
        self.assertEqual([48], [event[1] for event in self.driver.events if event[0] == "fixture"])
        self.assertFalse(self.state["finalized"]["retained"])
        self.assert_restored()
        with self.assertRaises(ValueError):
            M.finalize(self.args, self.state, self.driver)

    def test_no_eligible_candidate_has_no_endpoint_access(self):
        self.driver.eligible = False
        M.candidates(self.args, self.state, self.driver)
        M.freeze(self.args, self.state)
        self.driver.events.clear()
        M.finalize(self.args, self.state, self.driver)
        self.assertFalse(any(event[0] in ("measure", "fixture") for event in self.driver.events))
        self.assertFalse(self.state["finalized"]["retained"])
        self.assert_restored()

    def test_incomplete_grid_cannot_freeze(self):
        self.args.limit = 1
        M.candidates(self.args, self.state, self.driver)
        with self.assertRaises(ValueError):
            M.freeze(self.args, self.state)

    def test_unknown_receipt_stops_and_cannot_retry(self):
        self.driver.unknown = True
        with self.assertRaises(M.C.UnknownUpdateOutcome):
            M.candidates(self.args, self.state, self.driver)
        self.assertEqual(1, sum(event[0] == "fit" for event in self.driver.events))
        self.assertTrue(self.state["unknown_outcome"]["request_reuse_forbidden"])
        self.assert_restored()
        with self.assertRaises(ValueError):
            M.candidates(self.args, self.state, self.driver)

    def test_reserved_failed_fit_is_not_repeated(self):
        self.driver.fail_measure = True
        with self.assertRaises(RuntimeError):
            M.candidates(self.args, self.state, self.driver)
        self.assert_restored()
        self.driver.fail_measure = False
        with self.assertRaises(FileExistsError):
            M.candidates(self.args, self.state, self.driver)
        self.assertEqual(1, sum(event[0] == "fit" for event in self.driver.events))

    def test_historical_inventory_mismatch_prevents_fit(self):
        control = self.state["prior_study"]["controls"][0]
        response = M.read(control["response_path"])
        response["partition_inventory"]["train"]["ordered_samples_sha256"] = "f" * 64
        M.write(control["response_path"], response)
        control["response_sha256"] = M.sha(control["response_path"])
        with self.assertRaises(ValueError):
            M.candidates(self.args, self.state, self.driver)
        self.assertFalse(any(event[0] == "fit" for event in self.driver.events))
        self.assert_restored()

    def test_actual_driver_hook_blocks_rpc_before_historical_inventory_match(self):
        driver = M.Driver.__new__(M.Driver)
        driver.state = self.state
        driver._active_record = next(M.attempts())
        driver._inventory_verified = False
        generator = ["exec", "python", "-c", "from prompt_generation.generator import generate_training_partition"]
        rpc = ["exec", "python", "-c", "response=stub.RunTrainingCycle(req,timeout=300)"]
        changed = inventory()
        changed["heldout"]["ordered_samples_sha256"] = "a" * 64
        with patch.object(M.C.Driver, "call", return_value=json.dumps(changed).encode()) as command:
            with self.assertRaises(ValueError):
                driver.call(generator)
            with self.assertRaises(ValueError):
                driver.call(rpc)
            self.assertEqual(1, command.call_count)
        with patch.object(M.C.Driver, "call", return_value=json.dumps(inventory()).encode()) as command:
            driver.call(generator)
            self.assertTrue(driver._inventory_verified)
            driver.call(rpc)
            self.assertEqual(2, command.call_count)

    def test_historical_state_and_response_hash_scope(self):
        M.validate_prior_binding(self.state["prior_study"])
        prior = M.read(self.prior_path / "state.json")
        prior["runtime_target"] = "different"
        M.write(self.prior_path / "state.json", prior)
        with self.assertRaises(ValueError):
            M.validate_prior_binding(self.state["prior_study"])

    def test_current_source_scope_cannot_drift(self):
        source, frozen = self.output / "controller.py", self.output / "frozen-controller.py"
        source.write_text("original", encoding="utf-8")
        frozen.write_bytes(source.read_bytes())
        self.state.update(project_name="project", runtime_target="runtime", base_overrides=[], base_override_sha256={}, source_revision="commit", computation_source_sha256={"controller.py": M.sha(source)}, source_freeze={"controller.py": {"path": str(frozen), "sha256": M.sha(frozen)}})
        args = SimpleNamespace(project_name="project", runtime_target="runtime", base_override=[], prior_study=None)
        with patch.object(M, "ROOT", self.output), patch.object(M, "sources", return_value=[source]), patch.object(M.C.subprocess, "check_output", return_value="commit"):
            M.validate_scope(args, self.state)
            source.write_text("changed", encoding="utf-8")
            with self.assertRaises(ValueError):
                M.validate_scope(args, self.state)

    def test_historical_accepted_validation_bytes_are_bound(self):
        prior = M.read(self.prior_path / "state.json")
        prior["prefix"] = M.P.PREFIX
        record = prior["records"][1]
        record["accepted"] = True
        base = M.read(record["base_artifact"])
        candidate = copy.deepcopy(base)
        candidate.update(version="v0.3.0+train.3", checksum="candidate")
        artifact_path = Path(record["base_artifact"]).parent / "candidate.json"
        M.write(artifact_path, candidate)
        response = M.read(record["response_path"])
        response.update(accepted=True, model_id=base["model_id"], base_version=base["version"], applied_version=candidate["version"], prompts_generated=256, metadata=F.audit_metadata(record))
        response["receipt"] = {"found": True, "accepted": True, **{key: response[key] for key in ("model_id", "base_version", "applied_version", "prompts_generated")}}
        M.write(record["response_path"], response)
        record.update(response_sha256=M.sha(record["response_path"]), artifact=str(artifact_path), artifact_sha256=M.sha(artifact_path), identity={}, validation={}, reports={})
        directory = self.output / (M.P.PREFIX + "-v-01")
        directory.mkdir()
        for layer in ("semantic", "pipeline"):
            path = directory / (layer + ".json")
            M.write(path, {"synthetic_validation_evidence": True})
            record["reports"][layer] = {"path": str(path), "sha256": M.sha(path)}
        M.write(self.prior_path / "state.json", prior)
        bound = M.bind_prior_study(self.prior_path)
        self.assertIn("control-01/validation-pipeline.json", bound["bindings"])
        report_path = record["reports"]["pipeline"]["path"]
        M.write(report_path, {"changed": True})
        with self.assertRaises(ValueError):
            M.validate_prior_binding(bound)

    def test_prior_must_be_terminal_unretained_restored(self):
        for change in ({"finalized": None}, {"restoration_verified": False}, {"unknown_outcome": {"request_id": "unknown"}}, {"records": []}):
            prior = M.read(self.prior_path / "state.json")
            M.write(self.prior_path / "state.json", {**prior, **change})
            with self.assertRaises(ValueError):
                M.bind_prior_study(self.prior_path)
            M.write(self.prior_path / "state.json", prior)

    def test_new_loss_components_and_category_count_are_checked(self):
        response = {"accepted": True, "metadata": loss_metadata()}
        self.assertEqual(1.75, M.loss_audit(response, artifact())["supervised_objective_loss"])
        for field, value in (("supervised_objective_loss", "9"), ("category_count", "10"), ("supervised_category_bce_loss", "nan"), ("category_normalization", "sum")):
            changed = copy.deepcopy(response)
            changed["metadata"][field] = value
            with self.assertRaises(ValueError):
                M.loss_audit(changed, artifact())

    def test_optimization_denominator_matches_original_total_weight(self):
        record = next(M.attempts())
        response = {"accepted": True, "metadata": F.audit_metadata(record),
                    "partition_inventory": inventory(record["seed"])}
        response["metadata"]["total_weight"] = "256"
        M.objective_audit(record, response)
        for value in (None, "512", "nan", "inf"):
            changed = copy.deepcopy(response)
            if value is None:
                del changed["metadata"]["total_weight"]
            else:
                changed["metadata"]["total_weight"] = value
            with self.assertRaises((KeyError, ValueError)):
                M.objective_audit(record, changed)


class SourceScopeChecks(unittest.TestCase):
    def test_source_freeze_binds_all_controllers_reporters_and_protocol(self):
        with patch.object(M.C, "computation_sources", return_value=[]):
            names = {path.name for path in M.sources()}
        for name in ("run-contextual-fuzzer-study.py", "run-class-balanced-fuzzer-study.py", "run-mean-category-fuzzer-study.py", "report-contextual-fuzzer-study.py", "report-class-balanced-fuzzer-study.py", "report-mean-category-fuzzer-study.py", "mean-category-fuzzer-study-20261006.md", "test_mean_category_fuzzer_study.py"):
            self.assertIn(name, names)

    def test_fixed_new_grid_has_twelve_unique_requests(self):
        records = list(M.attempts())
        self.assertEqual(12, len(records))
        self.assertEqual(12, len({record["request_id"] for record in records}))
        self.assertEqual({M.OBJECTIVE}, {record["objective"] for record in records})


if __name__ == "__main__":
    unittest.main()
