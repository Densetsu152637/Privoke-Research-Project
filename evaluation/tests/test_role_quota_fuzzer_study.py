"""Synthetic phase04 checks; all Docker/RPC/model interfaces are fake or mocked."""
import ast
import copy
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


DIRECTORY = Path(__file__).parent
M = load("role_quota_study", DIRECTORY.parent / "run-role-quota-fuzzer-study.py")
R = load("role_quota_report", DIRECTORY.parent / "report-role-quota-fuzzer-study.py")
F = load("phase03_fake_helpers", DIRECTORY / "test_mean_category_fuzzer_study.py")


def inventory(record):
    value = F.inventory(record["seed"])
    if record["sampling_strategy"] == "uniform":
        return value
    value["train"].update(sensitivity_counts={"S0": 224, "S3": 32}, contextual_class_counts={"clean": 224, "sensitive": 32}, role_counts={"authored_contrastive_context": 64, "public_annotation_negative": 192}, groups=200,
        opaque_group_labels={**{f"author-{record['seed']}-{i}": ["S0", "S3"] for i in range(8)}, **{f"public-{record['seed']}-{i}": ["S0"] for i in range(192)}},
        texts_sha256=f"{record['seed'] + 100000:064x}", ordered_samples_sha256=f"{record['seed'] + 200000:064x}")
    numbers = (256, 256, 32, 32, 192, 0, 32, 224, 8, 8, 8)
    value["sampling_audit"] = {"contextual_sampling_strategy": M.SAMPLERS[1], **{key: str(number) for key, number in zip(M.SAMPLING_AUDITS, numbers)}}
    return value


class FakeDriver(F.F.FakeDriver):
    def __init__(self, args, state):
        super().__init__(args, state)
        self.eligible, self.bad_heldout = True, False

    def start_inventory_services(self):
        self.events.append(("inventory-start",))

    def sampling_inventory(self, record):
        self.events.append(("inventory", record["index"]))
        value = inventory(record)
        if self.bad_heldout and record["sampling_strategy"] != "uniform":
            value["heldout"]["ordered_samples_sha256"] = "a" * 64
        return value

    def train(self, record):
        M.verify_pair(self.state, record, {"partition_inventory": inventory(record)})
        try:
            response = super().train(record)
        except F.F.S.C.UnknownUpdateOutcome as error:
            raise M.C.UnknownUpdateOutcome(str(error)) from error
        response["request_fingerprint"] = M.request_fingerprint(record)
        response["partition_inventory"] = inventory(record)
        response["metadata"].update(F.loss_metadata(), total_weight="256", examples="256", exact_match_rate=".5", average_loss="1.0", heldout_examples="16", candidate_heldout_examples="16", heldout_sensitive_examples="8", candidate_heldout_sensitive_examples="8", heldout_clean_examples="8", candidate_heldout_clean_examples="8", heldout_exact_match_rate=".5", candidate_heldout_exact_match_rate=".5", heldout_sensitive_recall=".5", candidate_heldout_sensitive_recall=".5", heldout_clean_specificity=".5", candidate_heldout_clean_specificity=".5", candidate_heldout_safety_regression_rate="0")
        clean = response["partition_inventory"]["train"]["sensitivity_counts"]["S0"]
        sensitive = 256 - clean
        response["metadata"].update({key: str(value) for key, value in zip(M.OBJECTIVE_AUDITS, (clean, sensitive, clean, sensitive, 256, 128, 128, .5, .5))})
        if record["sampling_strategy"] != "uniform":
            response["metadata"].update(response["partition_inventory"]["sampling_audit"])
        return response

    def measure(self, *args):
        counts, reports = super().measure(*args)
        if not self.eligible and len(args[2]) == 968:
            for layer, binding in reports.items():
                report = M.read(binding["path"])
                next(row for row in report["metadata"]["predictions"] if row["expected_has_pii"] and row["detected_sensitive"])["detected_sensitive"] = False
                M.write(binding["path"], report)
                binding["sha256"] = M.sha(binding["path"])
                counts[layer] = F.F.verified(report, args[2], None)
        return counts, reports


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        (self.output / "source-freeze").mkdir()
        self.args = SimpleNamespace(output=self.output, limit=12)
        self.validation = [{"id": str(i), "expected_has_pii": i < 475, "group_id": "piimb:synthetic:" + str(i)} for i in range(968)]
        self.development = [{"id": "dev-" + str(i), "expected_has_pii": i < 264, "group_id": "piimb:synthetic:" + str(i)} for i in range(502)]
        self.cases = [{"case_id": str(i), "required_sensitive": i < 17, "minimum_action": "WARN" if i < 17 else "ALLOW", "ambiguous": i >= 41} for i in range(48)]
        self.state = {"prefix": M.PREFIX, "phase": "role-quota-exposure-representation", "planned_attempts": list(M.attempts()), "records": [], "baseline_complete": True, "restoration_verified": True, "images": {key: key + "-original" for key in M.SERVICES}, "catalog_backups": {}, "validation": "validation", "development": "development", "fixture": "fixture", "source_freeze": {}, "computation_source_sha256": {}, "source_revision": "commit", "preparation_manifest_sha256": "prepared"}
        for key in M.MODEL_IDS:
            path = self.output / (key + ".json")
            M.write(path, F.artifact())
            self.state["catalog_backups"][key] = {"path": str(path), "sha256": M.sha(path)}
        for target, replacement in (("load_artifact", M.read), ("bound_inputs", lambda state: self.validation), ("bound_rows", lambda path, *args: self.development if path == "development" else self.cases), ("verified_report", F.F.verified), ("verify_guarded_publication", lambda *args: None)):
            self.start_patch(M.C, target, replacement)
        self.start_patch(M, "prepare_base", F.F.prepare)
        self.start_patch(M, "LIVE_BASE_SHA", self.state["catalog_backups"]["privoke-balanced"]["sha256"])
        self.start_patch(M, "request_fingerprint", lambda record: M.C.hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest())
        self.prior_path = self.output / "phase03"
        self.prior_path.mkdir()
        prior = {"phase": "mean-category-objective-representation", "planned_attempts": list(M.P.attempts()), "records": [], "restoration_verified": True, "finalized": {"retained": False}, "catalog_backups": self.state["catalog_backups"], "images": self.state["images"], "preparation_manifest_sha256": "prepared", "project_name": "project", "runtime_target": "runtime", "base_overrides": [], "base_override_sha256": {}, "source_revision": "commit"}
        for record in prior["planned_attempts"]:
            path = self.prior_path / f"response-{record['index']}.json"
            value = F.inventory(record["seed"])
            response = {"request": record, "accepted": False, "partition_inventory": value, "error_code": "FAILED_PRECONDITION", "receipt": {"found": False}}
            M.write(path, response)
            prior["records"].append({**record, "accepted": False, "response_path": str(path), "response_sha256": M.sha(path), "partition_inventory": value})
        selection = self.prior_path / "selection.json"
        M.write(selection, {"candidate_count": 12, "winner": None})
        prior["selection"] = {"path": str(selection), "sha256": M.sha(selection)}
        M.write(self.prior_path / "state.json", prior)
        self.state["prior_study"] = M.bind_prior_study(self.prior_path)
        self.driver = FakeDriver(self.args, self.state)
        counts, reports = self.driver.measure(None, "validation", self.validation, "base")
        for layer, binding in reports.items():
            report = M.read(binding["path"])
            for truth, before, after in ((True, True, False), (False, False, True)):
                next(row for row in report["metadata"]["predictions"] if row["expected_has_pii"] == truth and row["detected_sensitive"] == before)["detected_sensitive"] = after
            M.write(binding["path"], report)
            binding["sha256"] = M.sha(binding["path"])
            counts[layer] = F.F.verified(report, self.validation, None)
        original = self.state["catalog_backups"]["privoke-balanced"]
        self.state["baselines"] = {"balanced": {"artifact": original["path"], "sha256": original["sha256"], "validation": counts, "reports": reports}}
        self.driver.events.clear()

    def start_patch(self, obj, name, value):
        guard = patch.object(obj, name, value)
        guard.start()
        self.addCleanup(guard.stop)

    def run_preflight(self):
        M.preflight(self.args, self.state, self.driver)

    def assert_restored(self):
        M.assert_originals(self.driver, self.state, M.backup_bytes(self.state))
        self.assertTrue(self.state["restoration_verified"])

    def test_preflight_is_inventory_only_complete_and_restored(self):
        self.run_preflight()
        self.assertEqual(list(range(12)), [event[1] for event in self.driver.events if event[0] == "inventory"])
        self.assertFalse(any(event[0] in ("fit", "measure", "fixture") for event in self.driver.events))
        self.assertEqual(12, len(M.frozen_preflight(self.state)["inventories"]))
        self.assert_restored()
        with self.assertRaises(ValueError):
            self.run_preflight()

    def test_fits_require_frozen_preflight_and_all_twelve_before_selection(self):
        with self.assertRaises((ValueError, KeyError)):
            M.candidates(self.args, self.state, self.driver)
        self.run_preflight()
        M.candidates(self.args, self.state, self.driver)
        self.assertEqual(list(range(12)), [event[1] for event in self.driver.events if event[0] == "fit"])
        self.assertTrue(all(event[1] == 968 for event in self.driver.events if event[0] == "measure"))
        self.assertFalse(any(event[0] == "fixture" for event in self.driver.events))
        M.freeze(self.args, self.state)
        self.assertEqual(0, M.read(self.state["selection"]["path"])["winner"]["index"])
        self.assert_restored()

    def test_frozen_winner_only_once_and_no_alternate(self):
        self.run_preflight()
        M.candidates(self.args, self.state, self.driver)
        M.freeze(self.args, self.state)
        counts, reports = self.driver.measure(None, "development", self.development, "reference-development")
        path = self.output / "fixture-live.json"
        self.driver.fixture(None, self.cases, path)
        self.state["reference_endpoint"] = {"counts": counts, "reports": reports, "fixture": {"path": str(path), "sha256": M.sha(path)}}
        self.driver.events.clear()
        M.finalize(self.args, self.state, self.driver)
        self.assertEqual([502], [event[1] for event in self.driver.events if event[0] == "measure"])
        self.assertEqual([48], [event[1] for event in self.driver.events if event[0] == "fixture"])
        self.assertFalse(self.state["finalized"]["retained"])
        self.assert_restored()
        with self.assertRaises(ValueError):
            M.finalize(self.args, self.state, self.driver)

    def test_no_eligible_candidate_never_scores_endpoint(self):
        self.run_preflight()
        self.driver.eligible = False
        M.candidates(self.args, self.state, self.driver)
        M.freeze(self.args, self.state)
        self.driver.events.clear()
        M.finalize(self.args, self.state, self.driver)
        self.assertFalse(any(event[0] in ("measure", "fixture") for event in self.driver.events))

    def test_unknown_receipt_no_retry_and_reserved_failed_fit_no_repeat(self):
        self.run_preflight()
        self.driver.unknown = True
        with self.assertRaises(M.C.UnknownUpdateOutcome):
            M.candidates(self.args, self.state, self.driver)
        self.assert_restored()
        with self.assertRaises(ValueError):
            M.candidates(self.args, self.state, self.driver)
        self.assertEqual(1, sum(event[0] == "fit" for event in self.driver.events))

    def test_scoring_failure_restores_and_reserved_request_cannot_repeat(self):
        self.run_preflight()
        self.driver.fail_measure = True
        with self.assertRaises(RuntimeError):
            M.candidates(self.args, self.state, self.driver)
        self.assert_restored()
        self.driver.fail_measure = False
        with self.assertRaises(FileExistsError):
            M.candidates(self.args, self.state, self.driver)
        self.assertEqual(1, sum(event[0] == "fit" for event in self.driver.events))

    def test_changed_heldout_preflight_fails_before_any_fit(self):
        self.driver.bad_heldout = True
        with self.assertRaises(ValueError):
            self.run_preflight()
        self.assertFalse(any(event[0] == "fit" for event in self.driver.events))
        self.assert_restored()

    def test_restoration_failure_cannot_be_reported_as_verified_or_retried(self):
        self.driver.fail_restore = True
        with self.assertRaises(RuntimeError): self.run_preflight()
        self.assertFalse(self.state["restoration_verified"])
        self.assertEqual("RuntimeError", self.state["restoration_failure"]["type"])
        self.assertNotIn("preflight_complete", self.state)
        with self.assertRaises(ValueError): self.run_preflight()

    def test_unknown_optional_policy_is_rejected_before_any_command(self):
        driver = M.C.Driver.__new__(M.C.Driver)
        with patch.object(driver, "call") as command:
            with self.assertRaises(ValueError): driver.train({"sampling_strategy": "unknown"})
            command.assert_not_called()

    def test_actual_hook_blocks_rpc_for_frozen_inventory_mixup(self):
        self.run_preflight()
        driver = M.Driver.__new__(M.Driver)
        driver.state = self.state
        driver._active_record, driver._inventory_verified = next(M.attempts()), False
        value = inventory(driver._active_record)
        value["train"]["ordered_samples_sha256"] = "f" * 64
        with patch.object(M.C.Driver, "call", return_value=json.dumps(value).encode()) as command:
            with self.assertRaises(ValueError):
                driver.call(["exec", "python", "-c", "from prompt_generation.generator import generate_training_partition"])
            with self.assertRaises(ValueError):
                driver.call(["exec", "python", "-c", "stub.RunTrainingCycle(req,timeout=300)"])
            self.assertEqual(1, command.call_count)

    def test_sampler_policy_fingerprint_receipt_and_audits_cannot_mix(self):
        self.run_preflight()
        record = list(M.attempts())[1]
        response = self.driver.train(record)
        M.validate_response(response, record, F.artifact())
        M.sampling_audit(record, response)
        altered = copy.deepcopy(response)
        altered["request_fingerprint"] = "0" * 64
        with self.assertRaises(ValueError):
            M.validate_response(altered, record, F.artifact())
        altered = copy.deepcopy(response)
        altered["metadata"]["sampling_authored_clean_rows"] = "31"
        with self.assertRaises(ValueError):
            M.sampling_audit(record, altered)
        altered = copy.deepcopy(response)
        altered["receipt"]["applied_version"] = "wrong"
        with self.assertRaises(M.C.UnknownUpdateOutcome):
            M.validate_response(altered, record, F.artifact())

    def test_s0_with_category_is_contextually_sensitive_in_quota_and_objective_audits(self):
        self.run_preflight()
        record = list(M.attempts())[1]
        response = self.driver.train(record)
        # One S0 bootstrap target has a category: severity coverage is unchanged,
        # while is_sensitive() puts that row in the sensitive objective stratum.
        selected = response["partition_inventory"]
        selected["train"]["contextual_class_counts"] = {"clean": 223, "sensitive": 33}
        selected["sampling_audit"].update(sampling_training_clean_rows="223", sampling_training_sensitive_rows="33")
        response["metadata"].update(selected["sampling_audit"], training_clean_examples="223", training_sensitive_examples="33", raw_clean_weight="223", raw_sensitive_weight="33")
        self.assertEqual(33, M.sampling_audit(record, response)["sampling_training_sensitive_rows"])
        self.assertEqual(33, M.objective_audit(record, response)["training_sensitive_examples"])
        response["metadata"]["training_sensitive_examples"] = "32"
        response["metadata"]["training_clean_examples"] = "224"
        with self.assertRaises(ValueError): M.objective_audit(record, response)
        selected["sampling_audit"].update(sampling_training_clean_rows="224", sampling_training_sensitive_rows="32")
        with self.assertRaises(ValueError): M.validate_sampling_inventory(record, selected)

    def test_preflight_source_image_and_prior_hash_scope_is_bound(self):
        self.run_preflight()
        self.state["study_images"]["privoke-fuzzer"] = "changed"
        with self.assertRaises(ValueError):
            M.frozen_preflight(self.state)
        self.state["study_images"]["privoke-fuzzer"] = "feature-privoke-fuzzer-original"
        prior = M.read(self.prior_path / "state.json")
        prior["restoration_verified"] = False
        M.write(self.prior_path / "state.json", prior)
        with self.assertRaises(ValueError):
            M.validate_prior_binding(self.state["prior_study"])

    def test_partial_report_reconciles_new_pair_without_certifying_completion(self):
        prepared = self.output / "prepared"
        prepared.mkdir()
        (prepared / "prompts.jsonl").write_text("synthetic\n", encoding="utf-8")
        M.write(prepared / "manifest.json", {"curriculum_sha256": M.sha(prepared / "prompts.jsonl")})
        self.state.update(prepared=str(prepared), preparation_manifest_sha256=M.sha(prepared / "manifest.json"))
        self.run_preflight()
        self.args.limit = 2
        M.candidates(self.args, self.state, self.driver)
        # Synthetic model summaries are mocked, but raw report reconciliation,
        # identities, guards, inventories, losses and file commitments are real.
        bindings = [self.state["baselines"]["balanced"], *self.state["records"]]
        for binding in bindings:
            identity = M.C.artifact_identity(M.read(binding["artifact"]))
            for layer, evidence in binding["reports"].items():
                value = M.read(evidence["path"])
                for row in value["metadata"]["predictions"]:
                    row.update(elapsed_ms=1.0, layers=[{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok", "results": [{"metadata": identity}]}])
                value["metrics"].update({name: binding["validation"][layer][key] for key, name in
                    (("tp", "true_positives"), ("tn", "true_negatives"), ("fp", "false_positives"), ("fn", "false_negatives"))})
                M.write(evidence["path"], value)
                evidence["sha256"] = M.sha(evidence["path"])
        M.write(self.output / "state.json", self.state)
        reference = {row["id"]: (row["expected_has_pii"], row["group_id"]) for row in self.validation}
        def model_summary(path, commitment):
            R.Q.read_bytes(path, commitment)
            return {"model_id": "synthetic"}, M.C.artifact_identity(M.read(path))
        with patch.object(R.P.C, "load_artifact", M.read), patch.object(R.P.C, "verify_guarded_publication", lambda *args: None), patch.object(R.P, "prepare_base", F.F.prepare), patch.object(R.P, "request_fingerprint", M.request_fingerprint), patch.object(R.P, "LIVE_BASE_SHA", M.LIVE_BASE_SHA), patch.object(R.Q, "endpoint", return_value=reference), patch.object(R.Q, "model_summary", side_effect=model_summary):
            before = M.sha(self.output / "state.json")
            report = R.quality_report(self.output, partial=True)
            self.assertEqual(before, M.sha(self.output / "state.json"))
            self.assertTrue(report["report_status"].startswith("PARTIAL"))
            self.assertEqual(12, len(report["attempts"]))
            self.assertEqual(2, sum(item.get("accepted") is True for item in report["attempts"]))
            self.assertEqual(32, report["attempts"][1]["sampling_audit"]["sampling_authored_sensitive_rows"])
            self.assertIsNotNone(report["sampling_pairs"][0]["prediction_changes"])
            self.assertIsNone(report["sampling_pairs"][1]["prediction_changes"])
            with self.assertRaises(ValueError): R.quality_report(self.output)
            self.state["records"][0]["validation"]["pipeline"]["tp"] -= 1
            M.write(self.output / "state.json", self.state)
            with self.assertRaises(ValueError): R.quality_report(self.output, partial=True)


class QualityTests(unittest.TestCase):
    def test_source_rates_remain_null_for_absent_classes(self):
        values = R.Q.source_strata([{"group_id": "piimb:clean-only:1", "expected_has_pii": False, "detected_sensitive": False}])
        row = next(iter(values.values()))
        self.assertIsNone(row["recall"])
        self.assertEqual(1, row["specificity"])

    def test_reporter_pairs_only_fresh_modes_and_preserves_partial_outcomes(self):
        items = [{**record, "status": "rejected; no quality score"} for record in M.attempts()]
        pairs = R.paired_comparisons(items, {}, None)
        self.assertEqual(6, len(pairs))
        self.assertTrue(all(pair["prediction_changes"] is None for pair in pairs))
        self.assertEqual((0, 1), (pairs[0]["uniform_index"], pairs[0]["quota_index"]))

    def test_controller_sources_bind_sampler_tests_and_task_dockerfile(self):
        with patch.object(M.C, "computation_sources", return_value=[]):
            names = {path.name for path in M.sources()}
        for name in ("Dockerfile.fuzzer-sampling", "run-role-quota-fuzzer-study.py", "report-role-quota-fuzzer-study.py", "test_role_quota_fuzzer_study.py", "role-quota-fuzzer-study-20261006.md"):
            self.assertIn(name, names)

    def test_legacy_inventory_and_rpc_metadata_defaults_are_unchanged(self):
        # Execute only the embedded pure inventory/pb construction, with fake inputs.
        class Target:
            def sensitivity(self): return SimpleNamespace(name="S0")
            def visibility(self): return SimpleNamespace(name="PU")
            def categories(self): return []
            def is_sensitive(self): raise AssertionError("Default inventory must not add contextual counting.")
        batch = [SimpleNamespace(text="synthetic", weight=1.0, expected_classification=Target(), metadata={"group_id": "group", "training_role": "public_annotation_negative"})]
        generator = types.ModuleType("prompt_generation.generator")
        calls = []
        def generate(*args, **kwargs):
            calls.append(kwargs)
            return batch, []
        generator.generate_training_partition = generate
        generator.contextual_sampling_audit = lambda _: {"unexpected": True}
        serialized = []
        for record in ({"seed": 42}, {"seed": 42, "sampling_strategy": "uniform"}):
            output = io.StringIO()
            with patch.dict(sys.modules, {"prompt_generation.generator": generator}), patch.object(sys, "stdin", io.StringIO(json.dumps(record))), patch.object(sys, "stdout", output):
                exec(M.inventory_code(), {})
            result = json.loads(output.getvalue())
            self.assertNotIn("sampling_audit", result)
            self.assertNotIn("contextual_class_counts", result["train"])
            serialized.append(output.getvalue())
        # Compare bytes against the original emitter, retaining field order,
        # whitespace and newline rather than only comparing parsed dictionaries.
        legacy = M.inventory_code().split("inventory={'train':", 1)[0] + "print(json.dumps({'train':summary(train),'heldout':summary(heldout),'group_overlap':len({x.metadata['group_id'] for x in train}&{x.metadata['group_id'] for x in heldout})}))"
        legacy_output = io.StringIO()
        with patch.dict(sys.modules, {"prompt_generation.generator": generator}), patch.object(sys, "stdin", io.StringIO('{"seed":42}')), patch.object(sys, "stdout", legacy_output):
            exec(legacy, {})
        self.assertEqual([legacy_output.getvalue()] * 2, serialized)
        self.assertEqual([{}, {}, {}], calls)
        self.assertEqual(["uniform", M.SAMPLERS[1]] * 6, [record["sampling_strategy"] for record in M.attempts()])
        # Stop before fingerprinting/channel creation: inspect the exact constructor
        # used by Driver.train, without importing generated clients or issuing RPCs.
        tree = ast.parse(Path(M.C.__file__).read_text(encoding="utf-8"))
        driver = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Driver")
        train = next(node for node in driver.body if isinstance(node, ast.FunctionDef) and node.name == "train")
        code = next(node.value.value for node in ast.walk(train) if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "code" for target in node.targets)
                    and isinstance(node.value, ast.Constant))
        prefix = code.split("fingerprint=", 1)[0]
        package = types.ModuleType("privoke")
        v1 = types.ModuleType("privoke.v1")
        v1.parameters_pb2 = SimpleNamespace(FuzzerTrainingRequest=lambda **kwargs: SimpleNamespace(**kwargs))
        v1.parameters_pb2_grpc = SimpleNamespace()
        results = []
        base = {"request_id": "request", "source_id": "source", "profile": "balanced", "seed": 42}
        for mode in (None, "uniform", M.SAMPLERS[1]):
            record = {**base, **({"sampling_strategy": mode} if mode is not None else {})}
            scope = {}
            with patch.dict(sys.modules, {"privoke": package, "privoke.v1": v1, "grpc": types.ModuleType("grpc")}), patch.object(sys, "stdin", io.StringIO(json.dumps(record))):
                exec(prefix, scope)
            results.append(vars(scope["req"]))
        self.assertEqual(results[0], results[1])
        self.assertEqual({"initiator": "contextual-study-controller"}, results[0]["metadata"])
        self.assertEqual(M.SAMPLERS[1], results[2]["metadata"]["contextual_sampling_strategy"])

    def test_quota_inventory_counts_s0_category_target_independently(self):
        class Target:
            def __init__(self, category): self.category = category
            def sensitivity(self): return SimpleNamespace(name="S0")
            def visibility(self): return SimpleNamespace(name="PU")
            def categories(self): return [SimpleNamespace(name="IDENTITY")] if self.category else []
            def is_sensitive(self): return self.category
        batch = [SimpleNamespace(text=str(category), weight=1.0, expected_classification=Target(category),
                 metadata={"group_id": str(category), "training_role": "existing_bootstrap_replay"}) for category in (True, False)]
        generator = types.ModuleType("prompt_generation.generator")
        generator.generate_training_partition = lambda *args, **kwargs: (batch, [])
        generator.contextual_sampling_audit = lambda _: {"sampling_training_sensitive_rows": "1", "sampling_training_clean_rows": "1"}
        output = io.StringIO()
        with patch.dict(sys.modules, {"prompt_generation.generator": generator}), patch.object(sys, "stdin", io.StringIO(json.dumps({"seed":42, "sampling_strategy": M.SAMPLERS[1]}))), patch.object(sys, "stdout", output):
            exec(M.inventory_code(), {})
        result = json.loads(output.getvalue())
        self.assertEqual({"S0": 2}, result["train"]["sensitivity_counts"])
        self.assertEqual({"sensitive": 1, "clean": 1}, result["train"]["contextual_class_counts"])

    def test_raw_quality_reconciles_counts_identity_errors_and_service_latency(self):
        identity = {"model_id": "synthetic", "parameter_fingerprint": "fingerprint"}
        rows = [{"example_id": str(i), "group_id": "source:" + str(i), "expected_has_pii": i == 0,
                 "detected_sensitive": i == 0, "status": "ok", "elapsed_ms": 2.0,
                 "layers": [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok", "results": [{"metadata": identity}]}]}
                for i in range(2)]
        reference = {row["example_id"]: (row["expected_has_pii"], row["group_id"]) for row in rows}
        counts = {"tp": 1, "tn": 1, "fp": 0, "fn": 0}
        report = {"errors": [], "metadata": {"predictions": rows}, "metrics": {
            "true_positives": 1, "true_negatives": 1, "false_positives": 0, "false_negatives": 0,
            "evaluated_samples": 2, "runtime_errors": 0}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.json"
            def evaluate():
                M.write(path, report)
                return R.Q.verify_report({"path": str(path), "sha256": M.sha(path)}, reference, identity, counts)
            summary, _ = evaluate()
            self.assertEqual(1, summary["metrics"]["recall"])
            self.assertEqual(2.0, summary["latency"]["median_ms"])
            report["metrics"]["true_positives"] = 0
            with self.assertRaises(ValueError): evaluate()
            report["metrics"]["true_positives"] = 1
            rows[0]["layers"][0]["results"][0]["metadata"] = {**identity, "parameter_fingerprint": "wrong"}
            with self.assertRaises(ValueError): evaluate()
            rows[0]["layers"][0]["results"][0]["metadata"] = identity
            rows[1]["layers"][0]["status"] = "error"
            with self.assertRaises(ValueError): evaluate()

    def test_semantic_misses_and_pipeline_clean_flags_are_paired_descriptions(self):
        before = {str(i): {"group_id": "source:" + str(i), "expected_has_pii": i == 0,
                           "detected_sensitive": False, "layers": []} for i in range(2)}
        after = copy.deepcopy(before)
        after["0"]["detected_sensitive"] = after["1"]["detected_sensitive"] = True
        after["1"]["layers"] = [{"layer": "DETECTION_LAYER_NER", "status": "ok", "results": [{"sensitivity": "S2"}]}]
        result = R.Q.pipeline_rescue(before, after)
        self.assertEqual(1, result["positive_semantic_misses_detected_by_pipeline"])
        self.assertEqual(1, result["clean_pipeline_only_flags"])
        self.assertEqual(1, result["clean_pipeline_only_with_returned_ner_signal"])
        after["1"]["group_id"] = "changed"
        with self.assertRaises(ValueError): R.Q.pipeline_rescue(before, after)


if __name__ == "__main__":
    unittest.main()
