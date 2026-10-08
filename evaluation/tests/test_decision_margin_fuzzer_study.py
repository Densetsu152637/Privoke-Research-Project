"""Synthetic phase06 checks; all Docker/RPC/model interfaces are fake or mocked."""
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
M = load("decision_margin_study", DIRECTORY.parent / "run-decision-margin-fuzzer-study.py")
R = load("decision_margin_report", DIRECTORY.parent / "report-decision-margin-fuzzer-study.py")
F = load("phase05_fake_helpers", DIRECTORY / "test_local_sgd_fuzzer_study.py")


H = F.H

def artifact():
    return F.artifact()

def prepare(artifact, record):
    result = H.prepare(artifact, record)
    result["metadata"][M.OPTIMIZER_KEY] = record["optimizer"]
    return result

def inventory(record):
    return F.inventory(record)


class FakeDriver(H.FakeDriver):
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
        original = json.loads(self.live("balanced"))
        try:
            response = super().train(record)
        except H.S.C.UnknownUpdateOutcome as error:
            raise M.C.UnknownUpdateOutcome(str(error)) from error
        response["request_fingerprint"] = M.request_fingerprint(record)
        response["partition_inventory"] = inventory(record)
        response["metadata"].update(F.F.F.loss_metadata(), total_weight="256", examples="256", exact_match_rate=".5", average_loss="1.0", heldout_examples="16", candidate_heldout_examples="16", heldout_sensitive_examples="8", candidate_heldout_sensitive_examples="8", heldout_clean_examples="8", candidate_heldout_clean_examples="8", heldout_exact_match_rate=".5", candidate_heldout_exact_match_rate=".5", heldout_sensitive_recall=".5", candidate_heldout_sensitive_recall=".5", heldout_clean_specificity=".5", candidate_heldout_clean_specificity=".5", candidate_heldout_safety_regression_rate="0")
        clean = response["partition_inventory"]["train"]["sensitivity_counts"]["S0"]
        sensitive = 256 - clean
        response["metadata"].update({key: str(value) for key, value in zip(M.OBJECTIVE_AUDITS, (clean, sensitive, clean, sensitive, 256, 128, 128, .5, .5))})
        if record["sampling_strategy"] != "uniform":
            response["metadata"].update(response["partition_inventory"]["sampling_audit"])
        cap = M.C.float32(record["max_gradient"])
        if cap > record["max_gradient"]:
            cap = M.struct.unpack("<f", M.struct.pack("<I", M.struct.unpack("<I", M.struct.pack("<f", cap))[0] - 1))[0]
        trace = {"optimizer":record["optimizer"], "steps":record["local_steps"], "objective":record["objective"], "rate":record["rate"], "max_gradient":record["max_gradient"], "transport_cap":cap,
                 "category_normalization":"mean_per_label", "category_count":2, "loss_columns":["sensitivity_ce","visibility_ce","category_bce","objective"], "loss":[[1.,.5,.25,1.75] for _ in range(record["local_steps"] + 1)],
                 "update_columns":["gradient_l2","raw_delta_max","clipped_coordinates","transport_delta_max"], "updates":[[.1,.001,0,.001] for _ in range(record["local_steps"])]}
        trace["state_parameter_fingerprints"] = [M.C.artifact_identity(original)["parameter_fingerprint"]] + [M.C.artifact_identity(json.loads(self.live("balanced")))["parameter_fingerprint"]] * record["local_steps"]
        if record["objective"] == M.DECISION_MARGIN_OBJECTIVE:
            trace.update(decision_margin_coefficient=1.0,decision_margin_rule="max_non_s0_or_category_logit_v1")
            trace["loss_columns"] = ["sensitivity_ce","visibility_ce","category_bce","decision_margin_bce","objective"]
            trace["loss"] = [[1.,.5,.25,.4,2.15] for _ in range(2)]
            response["metadata"]["supervised_objective_loss"] = "2.15"
        response["metadata"]["contextual_optimizer_trace"] = json.dumps(trace, separators=(",",":"), allow_nan=False)
        return response

    def measure(self, *args):
        counts, reports = super().measure(*args)
        if not self.eligible and len(args[2]) == 968:
            for layer, binding in reports.items():
                report = M.read(binding["path"])
                next(row for row in report["metadata"]["predictions"] if row["expected_has_pii"] and row["detected_sensitive"])["detected_sensitive"] = False
                M.write(binding["path"], report)
                binding["sha256"] = M.sha(binding["path"])
                counts[layer] = H.verified(report, args[2], None)
        return counts, reports


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        (self.output / "source-freeze").mkdir()
        self.args = SimpleNamespace(output=self.output, limit=6)
        self.validation = [{"id": str(i), "expected_has_pii": i < 475, "group_id": "piimb:synthetic:" + str(i)} for i in range(968)]
        self.development = [{"id": "dev-" + str(i), "expected_has_pii": i < 264, "group_id": "piimb:synthetic:" + str(i)} for i in range(502)]
        self.cases = [{"case_id": str(i), "required_sensitive": i < 17, "minimum_action": "WARN" if i < 17 else "ALLOW", "ambiguous": i >= 41} for i in range(48)]
        self.state = {"prefix": M.PREFIX, "phase": "decision-margin-objective", "planned_attempts": list(M.attempts()), "records": [], "baseline_complete": True, "restoration_verified": True, "images": {key: key + "-original" for key in M.SERVICES}, "catalog_backups": {}, "validation": "validation", "development": "development", "fixture": "fixture", "source_freeze": {}, "computation_source_sha256": {}, "source_revision": "commit", "preparation_manifest_sha256": "prepared"}
        for key in M.MODEL_IDS:
            path = self.output / (key + ".json")
            M.write(path, artifact())
            self.state["catalog_backups"][key] = {"path": str(path), "sha256": M.sha(path)}
        for target, replacement in (("load_artifact", M.read), ("bound_inputs", lambda state: self.validation), ("bound_rows", lambda path, *args: self.development if path == "development" else self.cases), ("verified_report", H.verified), ("verify_guarded_publication", lambda *args: None)):
            self.start_patch(M.C, target, replacement)
        self.start_patch(M, "prepare_base", prepare)
        self.start_patch(M, "LIVE_BASE_SHA", self.state["catalog_backups"]["privoke-balanced"]["sha256"])
        self.start_patch(M, "request_fingerprint", lambda record: M.C.hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest())
        self.prior_path = self.output / "phase05"
        self.prior_path.mkdir()
        prior = {"phase": "local-sgd-optimizer-representation", "planned_attempts": list(M.P.attempts()), "records": [], "restoration_verified": True, "finalized": {"retained": False}, "catalog_backups": self.state["catalog_backups"], "images": self.state["images"], "preparation_manifest_sha256": "prepared", "project_name": "project", "runtime_target": "runtime", "base_overrides": [], "base_override_sha256": {}, "source_revision": "commit"}
        for record in prior["planned_attempts"]:
            path = self.prior_path / f"response-{record['index']}.json"
            value = F.inventory(record)
            response = {"request": record, "accepted": False, "partition_inventory": value, "error_code": "FAILED_PRECONDITION", "receipt": {"found": False}}
            M.write(path, response)
            prior["records"].append({**record, "accepted": False, "response_path": str(path), "response_sha256": M.sha(path), "partition_inventory": value})
        selection = self.prior_path / "selection.json"
        M.write(selection, {"candidate_count": 18, "winner": None})
        prior["selection"] = {"path": str(selection), "sha256": M.sha(selection)}
        prior.update(preflight_complete=True, computation_source_sha256={}, study_images=self.state["images"], prior_study={"state_sha256":"earlier"})
        proof = {"planned_attempts": prior["planned_attempts"], "inventories": {str(record["index"]): F.inventory(record) for record in prior["planned_attempts"]}, "computation_source_sha256":{}, "study_images":prior["study_images"], "prior_state_sha256":"earlier", "preparation_manifest_sha256":"prepared", "training_rpc_executed":False,"model_inference_executed":False}
        proof_path = self.prior_path / "sampling-preflight.json"
        M.write(proof_path, proof)
        base_paths = {}
        for record in prior["planned_attempts"]:
            path = self.prior_path / f"prepared-{record['index']}.json"
            value = prepare(artifact(),record)
            M.write(path,value)
            base_paths[str(record["index"])] = {"path":str(path),"sha256":M.sha(path),"optimizer":record["optimizer"]}
        proof["prepared_bases"] = base_paths
        M.write(proof_path,proof)
        prior["sampling_preflight"] = {"path":str(proof_path),"sha256":M.sha(proof_path)}
        protocol = self.prior_path / "prior-protocol.md"
        protocol.write_text("synthetic declaration",encoding="utf-8")
        prior["source_freeze"] = {"docs/local-sgd-fuzzer-study-20261006.md":{"path":str(protocol),"sha256":M.sha(protocol)}}
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
            counts[layer] = H.verified(report, self.validation, None)
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
        self.assertEqual(list(range(6)), [event[1] for event in self.driver.events if event[0] == "inventory"])
        self.assertFalse(any(event[0] in ("fit", "measure", "fixture") for event in self.driver.events))
        self.assertEqual(6, len(M.frozen_preflight(self.state)["inventories"]))
        self.assert_restored()
        with self.assertRaises(ValueError):
            self.run_preflight()

    def test_fits_require_frozen_preflight_and_all_six_before_selection(self):
        with self.assertRaises((ValueError, KeyError)):
            M.candidates(self.args, self.state, self.driver)
        self.run_preflight()
        M.candidates(self.args, self.state, self.driver)
        self.assertEqual(list(range(6)), [event[1] for event in self.driver.events if event[0] == "fit"])
        self.assertTrue(all(event[1] == 968 for event in self.driver.events if event[0] == "measure"))
        self.assertFalse(any(event[0] == "fixture" for event in self.driver.events))
        M.freeze(self.args, self.state)
        self.assertEqual(0, M.read(self.state["selection"]["path"])["winner"]["index"])
        self.assert_restored()

    def test_six_plan_order_and_objective_base_commitments(self):
        records=list(M.attempts())
        self.assertEqual([42,42,1337,1337,2026,2026],[record["seed"] for record in records])
        self.assertEqual(list(M.OBJECTIVES)*3,[record["objective"] for record in records])
        self.assertEqual(6,len({record["request_id"] for record in records}))
        self.assertTrue(all(record["strategy"] == "heads" and record["local_steps"] == 1 and record["rate"] == .003 for record in records))
        self.run_preflight()
        bases=M.frozen_preflight(self.state)["prepared_bases"]
        before,after=(M.read(bases[str(index)]["path"]) for index in (0,1))
        self.assertEqual(before["parameters"],after["parameters"])
        self.assertNotEqual(bases["0"]["sha256"],bases["1"]["sha256"])
        self.assertEqual(bases["0"]["identity"]["parameter_fingerprint"],bases["1"]["identity"]["parameter_fingerprint"])
        self.assertEqual(3,len(self.state["prior_study"]["controls"]))
        self.assertEqual([0,3,6],[record["index"] for record in self.state["prior_study"]["controls"]])
        Path(bases["1"]["path"]).write_text("changed",encoding="utf-8")
        with self.assertRaises(ValueError): M.candidates(self.args,self.state,self.driver)

    def test_margin_five_columns_coefficient_rule_sum_and_fingerprints(self):
        self.run_preflight()
        record=list(M.attempts())[1]
        base=prepare(artifact(),record)
        self.driver.install_raw("balanced",json.dumps(base).encode())
        response=self.driver.train(record)
        audit=M.optimizer_audit(record,response,base)
        self.assertEqual(2,len(audit["trace"]["loss"]))
        self.assertEqual(["sensitivity_ce","visibility_ce","category_bce","decision_margin_bce","objective"],audit["trace"]["loss_columns"])
        self.assertEqual(2.15,audit["trace"]["loss"][0][-1])
        candidate=json.loads(self.driver.live("balanced"))
        M.bind_optimizer_publication(audit,M.parameter_changes(base,candidate),candidate)
        for change in ({"decision_margin_coefficient":.5},{"decision_margin_rule":"wrong"},{"steps":4},{"rate":.012},{"optimizer":"local_sgd_4_v1"},{"category_count":10},{"transport_cap":M.C.float32(.05)},{"extra":True}):
            altered=copy.deepcopy(response)
            trace=json.loads(altered["metadata"]["contextual_optimizer_trace"])
            trace.update(change)
            altered["metadata"]["contextual_optimizer_trace"]=json.dumps(trace)
            with self.assertRaises(ValueError): M.optimizer_audit(record,altered,base)
        for mutate in (lambda trace: trace.pop("decision_margin_coefficient"),lambda trace:trace["loss"][0].pop(3),lambda trace:trace["loss"][0].__setitem__(3,.8),lambda trace:trace["state_parameter_fingerprints"].__setitem__(0,"f"*64)):
            altered=copy.deepcopy(response)
            trace=json.loads(altered["metadata"]["contextual_optimizer_trace"])
            mutate(trace)
            altered["metadata"]["contextual_optimizer_trace"]=json.dumps(trace)
            with self.assertRaises(ValueError): M.optimizer_audit(record,altered,base)
        audit["trace"]["state_parameter_fingerprints"][-1]="f"*64
        with self.assertRaises(ValueError): M.bind_optimizer_publication(audit,M.parameter_changes(base,candidate),candidate)

    def test_mean_control_trace_preserves_phase05_four_column_contract(self):
        self.run_preflight()
        record=next(M.attempts())
        base=prepare(artifact(),record)
        self.driver.install_raw("balanced",json.dumps(base).encode())
        response=self.driver.train(record)
        actual=M.optimizer_audit(record,response,base)
        self.assertEqual(M.P.optimizer_audit(record,response,base),actual)
        self.assertNotIn("decision_margin_coefficient",actual["trace"])
        self.assertEqual(4,len(actual["trace"]["loss"][0]))
        altered=copy.deepcopy(response)
        trace=json.loads(altered["metadata"]["contextual_optimizer_trace"])
        trace["decision_margin_rule"]="max_non_s0_or_category_logit_v1"
        altered["metadata"]["contextual_optimizer_trace"]=json.dumps(trace)
        with self.assertRaises(ValueError): M.optimizer_audit(record,altered,base)

    def test_mean_control_wins_remaining_validation_tie(self):
        records=[{**record,"accepted":True,"validation":{"pipeline":{"tp":428,"tn":144}}} for record in M.attempts()]
        self.assertEqual(0,max(records,key=lambda record:M.candidate_key(record,{"tn":143}))["index"])

    def test_prior_reads_only_three_control_responses_and_checks_frozen_source_copies(self):
        prior=M.read(self.prior_path / "state.json")
        for record in prior["records"]:
            if record["index"] not in (0,3,6):
                record["response_path"]=str(self.prior_path / "forbidden-historical-response.json")
        frozen=self.prior_path / "source-freeze/tree/runtime.py"
        frozen.parent.mkdir(parents=True)
        frozen.write_text("immutable old runtime",encoding="utf-8")
        prior["computation_source_sha256"]={"runtime.py":M.sha(frozen)}
        proof=M.read(prior["sampling_preflight"]["path"])
        proof["computation_source_sha256"]=prior["computation_source_sha256"]
        M.write(prior["sampling_preflight"]["path"],proof)
        prior["sampling_preflight"]["sha256"]=M.sha(prior["sampling_preflight"]["path"])
        M.write(self.prior_path / "state.json",prior)
        previous=M.read
        with patch.object(M,"read",side_effect=previous) as reads:
            bound=M.bind_prior_study(self.prior_path)
        responses=[Path(call.args[0]).name for call in reads.call_args_list if Path(call.args[0]).name.startswith("response-")]
        self.assertEqual(["response-0.json","response-3.json","response-6.json"],responses)
        self.assertEqual(3,len(bound["controls"]))
        frozen.write_text("changed",encoding="utf-8")
        with self.assertRaises(ValueError): M.bind_prior_study(self.prior_path)

    def test_margin_trace_caps_nonfinite_duplicates_and_trace_only_auxiliary_metadata(self):
        self.run_preflight()
        record=list(M.attempts())[1]
        base=prepare(artifact(),record)
        self.driver.install_raw("balanced",json.dumps(base).encode())
        response=self.driver.train(record)
        trace=json.loads(response["metadata"]["contextual_optimizer_trace"])
        invalid=copy.deepcopy(trace)
        invalid["loss"][0][3]=float("nan")
        values=[json.dumps(invalid),'{"optimizer":"duplicate",'+response["metadata"]["contextual_optimizer_trace"][1:]," "*2049+response["metadata"]["contextual_optimizer_trace"]]
        for raw in values:
            altered=copy.deepcopy(response)
            altered["metadata"]["contextual_optimizer_trace"]=raw
            with self.assertRaises(ValueError): M.optimizer_audit(record,altered,base)
        altered=copy.deepcopy(response)
        altered["metadata"]["supervised_decision_margin_bce_loss"]=".4"
        with self.assertRaises(ValueError): M.optimizer_audit(record,altered,base)

    def test_reporter_distinguishes_full_objective_and_auxiliary_component(self):
        self.run_preflight()
        record=list(M.attempts())[1]
        base=prepare(artifact(),record)
        self.driver.install_raw("balanced",json.dumps(base).encode())
        response=self.driver.train(record)
        item={**record,"optimizer_audit":M.optimizer_audit(record,response,base)}
        with patch.object(R.R,"markdown",return_value="# Class-balanced fuzzer model quality\n"):
            rendered=R.markdown({"attempts":[item]})
        self.assertIn("2.15 / 2.15",rendered)
        self.assertIn("| 1 | 0.4 | 0.4 | 1.0 |",rendered)
        self.assertIn("full totals from different objectives are not directly comparable",rendered)
        altered=copy.deepcopy(response)
        for index in range(65): altered["metadata"][f"extra-{index}"]="0"
        with self.assertRaises(ValueError): M.optimizer_audit(record,altered,base)

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
        M.validate_response(response, record, artifact())
        M.sampling_audit(record, response)
        altered = copy.deepcopy(response)
        altered["request_fingerprint"] = "0" * 64
        with self.assertRaises(ValueError):
            M.validate_response(altered, record, artifact())
        altered = copy.deepcopy(response)
        altered["metadata"]["sampling_authored_clean_rows"] = "31"
        with self.assertRaises(ValueError):
            M.sampling_audit(record, altered)
        altered = copy.deepcopy(response)
        altered["receipt"]["applied_version"] = "wrong"
        with self.assertRaises(M.C.UnknownUpdateOutcome):
            M.validate_response(altered, record, artifact())

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
        with patch.object(R.P.C, "load_artifact", M.read), patch.object(R.P.C, "verify_guarded_publication", lambda *args: None), patch.object(R.P, "prepare_base", prepare), patch.object(R.P, "optimizer_audit", M.optimizer_audit), patch.object(R.P, "request_fingerprint", M.request_fingerprint), patch.object(R.P, "LIVE_BASE_SHA", M.LIVE_BASE_SHA), patch.object(R.Q, "endpoint", return_value=reference), patch.object(R.Q, "model_summary", side_effect=model_summary):
            before = M.sha(self.output / "state.json")
            report = R.quality_report(self.output, partial=True)
            self.assertEqual(before, M.sha(self.output / "state.json"))
            self.assertTrue(report["report_status"].startswith("PARTIAL"))
            self.assertEqual(6, len(report["attempts"]))
            self.assertEqual(2, sum(item.get("accepted") is True for item in report["attempts"]))
            self.assertEqual(32, report["attempts"][1]["sampling_audit"]["sampling_authored_sensitive_rows"])
            self.assertIsNotNone(report["objective_pairs"][0]["prediction_changes"])
            self.assertIsNone(report["objective_pairs"][1]["prediction_changes"])
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
        self.assertEqual(3, len(pairs))
        self.assertTrue(all(pair["prediction_changes"] is None for pair in pairs))
        self.assertEqual((0, 1), (pairs[0]["before_index"], pairs[0]["after_index"]))

    def test_controller_sources_bind_sampler_tests_and_task_dockerfile(self):
        with patch.object(M.C, "computation_sources", return_value=[]):
            names = {path.name for path in M.sources()}
        for name in ("Dockerfile.fuzzer-sampling", "Dockerfile.fuzzer-bases", "Dockerfile", "run-component-tests.py", "run-decision-margin-fuzzer-study.py", "report-decision-margin-fuzzer-study.py", "test_decision_margin_fuzzer_study.py", "decision-margin-fuzzer-study-20261006.md"):
            self.assertIn(name, names)
        self.assertIn("extension/client-runtime/test/test_local_sgd_training.py", M.FEATURE_TEST_PATHS)
        absent = "extension/client-runtime/test/test_not_yet_handed_off.py"
        with patch.object(M, "FEATURE_TEST_PATHS", (absent,)), patch.object(M.C, "computation_sources", return_value=[]):
            self.assertNotIn(M.ROOT / absent, M.sources())
            with self.assertRaises(ValueError): M.initialize(SimpleNamespace(), {})

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
