"""Behavior checks for the separate normal-batch protocol and final decisions."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from privoke_eval import accelerated_fuzzer_study as study
from privoke_eval import accelerated_fuzzer_report as report
from privoke_eval import continual_fuzzer_study as continual
from privoke_eval import curriculum_improvement_evidence as evidence
from privoke_eval import curriculum_improvement_report as prior_report
from privoke_eval import synthetic_curriculum as synthetic
from privoke.v1 import parameters_pb2 as PP

sys.path.insert(0, str(study.ROOT / "services/privoke-fuzzer/src"))
from prompt_generation.curriculum import Curriculum, reserve_batch
from fuzzer_service import FuzzerTrainingService, gate_diagnostics, write_gate_diagnostics, validate_training_update
from training.types import BatchTrainingUpdate
from types import SimpleNamespace
from privoke_model.fingerprint import parameter_fingerprint
import grpc


class AcceleratedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="accelerated-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def update(self):
        return BatchTrainingUpdate("privoke-balanced", "v0", {}, {},
            {"exact_match_rate": .5, "heldout_exact_match_rate": .5, "candidate_heldout_exact_match_rate": .5,
             "heldout_sensitive_recall": .75, "candidate_heldout_sensitive_recall": .75,
             "heldout_clean_specificity": .5, "candidate_heldout_clean_specificity": .5,
             "heldout_sensitive_examples": 8., "heldout_clean_examples": 8.,
             "candidate_heldout_safety_regression_rate": 0.},
            {"base_parameter_fingerprint": "a" * 64, "updated_parameter_fingerprint": "b" * 64})

    def test_matrix_uses_one_shared_control_and_three_realizations(self):
        cells = study.matrix("privoke-accelerated-test")
        self.assertEqual(len(cells), 12)
        self.assertEqual(sum(c["shared_control"] for c in cells), 3)
        self.assertEqual(len({c["project"] for c in cells}), 12)
        self.assertEqual(sum(study.BUDGET["attempts"] * study.BUDGET["prompt_count"] for c in cells), 64512)
        self.assertEqual(study.CHECKPOINTS, [0, 24, 72, 168])

    def test_gate_diagnostics_preserve_all_failed_predicates_and_guard(self):
        update = self.update()
        request = PP.FuzzerTrainingRequest(request_id="r", source_id="s", model_id=update.model_id)
        baseline = gate_diagnostics(request, update, 0.)
        self.assertTrue(baseline["gate_passed"])
        update.metrics.update(candidate_heldout_sensitive_recall=.5, candidate_heldout_clean_specificity=.25,
                              candidate_heldout_exact_match_rate=.25, candidate_heldout_safety_regression_rate=.125)
        with self.assertRaisesRegex(ValueError, "worse"):
            validate_training_update(update, minimum_exact_match_rate=0.)
        record = gate_diagnostics(request, update, 0.)
        self.assertEqual(report.gate_predicates(record), ["heldout_exact_no_decline", "heldout_recall_no_decline", "heldout_specificity_no_decline", "no_safety_regression"])
        self.assertFalse(record["gate_passed"])
        self.assertNotIn("gradients", record)
        self.assertNotIn("text", json.dumps(record))

    def test_gate_record_atomic_idempotent_and_conflict_fails_closed(self):
        request = PP.FuzzerTrainingRequest(request_id="same", source_id="s", model_id="privoke-balanced")
        config = SimpleNamespace(curriculum_state_path=str(self.root / "state.sqlite3"), minimum_exact_match_rate=0.)
        update = self.update()
        write_gate_diagnostics(request, update, config)
        write_gate_diagnostics(request, update, config)
        files = list((self.root / "gate-diagnostics").glob("*.json"))
        self.assertEqual(len(files), 1)
        update.metrics["candidate_heldout_sensitive_recall"] = .5
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            write_gate_diagnostics(request, update, config)
        self.assertTrue(json.loads(files[0].read_text())["gate_passed"])

    def test_missing_diagnostics_never_becomes_zero(self):
        with self.assertRaisesRegex(ValueError, "Exactly one"):
            report.audit_gate_diagnostics(self.root, [{"cycle": 1}], self.root, {})
        record = gate_diagnostics(PP.FuzzerTrainingRequest(), self.update(), 0.)
        del record["metrics"]["candidate_heldout_sensitive_recall"]
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            report.gate_predicates(record)

    def fixture(self, key, action="ALLOW"):
        return {"id": key, "group_id": key, "status": "ok", "quantitative": True,
                "target": {"sensitivity": "S0", "visibility": "PU", "categories": []},
                "classification": {"sensitivity": "S0", "visibility": "PU", "categories": []},
                "allowed_actions": ["ALLOW"], "action": action}

    def endpoint(self, joint=.5, recall=.75, disclosure=.5, action="ALLOW"):
        metrics = {key: disclosure for key in ("joint_accuracy", "sensitivity_accuracy", "visibility_accuracy", "category_exact_accuracy", "action_accuracy")}
        return {"contextual": {"semantic": {"metrics": {"joint_accuracy": joint}}},
                "development": {"semantic": {"metrics": {"recall": recall}}},
                "subgroups": {"disclosures": metrics}, "fixtures": {"semantic": {"predictions": [self.fixture("f", action)]}}}

    def test_final_promising_requires_both_references_and_no_harms(self):
        control = {"checkpoints": {"168": self.endpoint()}}
        record = {"checkpoints": {"0": self.endpoint(), "168": self.endpoint(joint=.6)}}
        self.assertTrue(report.promising_seed(record, control)["promising"])
        record["checkpoints"]["168"] = self.endpoint(joint=.6, disclosure=.4)
        self.assertFalse(report.promising_seed(record, control)["promising"])
        record["checkpoints"]["168"] = self.endpoint(joint=.6, action="BLOCK")
        self.assertFalse(report.promising_seed(record, control)["promising"])
        record["checkpoints"]["168"] = self.endpoint(joint=.5)
        self.assertFalse(report.promising_seed(record, control)["promising"])

    def test_changed_predictions_detect_canceling_aggregate_changes(self):
        before = [self.fixture("a"), self.fixture("b", "BLOCK")]
        after = [self.fixture("a", "BLOCK"), self.fixture("b")]
        self.assertEqual(report.prediction_changes(before, after)["changed_rows"], 2)
        self.assertFalse(evidence.restriction_harms(before, after)["passed"])
        a = {"id": "raw", "group_id": "raw", "status": "ok", "detected_sensitive": True,
             "raw": {"classification": {"sensitivity": "S2"}, "action": "WARN"}}
        b = copy.deepcopy(a)
        b["raw"]["classification"]["sensitivity"] = "S3"
        self.assertEqual(report.prediction_changes([a], [b])["changed_rows"], 1)

    def test_contextual_truth_and_subgroups_reconstructed_from_pinned_inputs(self):
        rows = continual.jsonl(study.ROOT / "evaluation/results/curriculum_improvement_20261009_v1/curricula/revised/assessment.jsonl")
        identity = {"model_id": "m", "model_version": "v0"}
        class Client:
            def snapshot(self, model_id):
                return {"identity": identity}
            def analyze(self, row, model_id, layer, request_id):
                return {"identities": [identity], "raw": {"classification": row["classification"], "action": row["allowed_actions"][0],
                    "layers": [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok"}]}}
        endpoint = study.prior.contextual_rows(Client(), rows, "m", identity, "synthetic")
        report.verify_endpoint_truth(endpoint, rows, identity)
        groups = report.context_subgroups(endpoint["semantic"]["predictions"])
        self.assertEqual([groups[k]["rows"] for k in ("controls", "disclosures", "hard_positives")], [32, 32, 4])
        endpoint["semantic"]["predictions"][0]["target"] = {"sensitivity": "S1", "visibility": "PU", "categories": []}
        with self.assertRaisesRegex(ValueError, "pinned truth"):
            report.verify_endpoint_truth(endpoint, rows, identity)

    def test_third_seed_fixture_harm_vetoes_two_promising_seeds(self):
        control = {"cell": {"id": "control"}, "checkpoints": {"168": self.endpoint()}}
        revised = [{"cell": {"id": str(seed)}, "checkpoints": {"0": self.endpoint(), "168": self.endpoint(joint=.6)}} for seed in (42, 43, 44)]
        self.assertTrue(report.profile_decision(revised, control)["promising_package"])
        revised[-1]["checkpoints"]["168"] = self.endpoint(joint=.6, action="BLOCK")
        decision = report.profile_decision(revised, control)
        self.assertEqual(decision["promising_seeds"], 2)
        self.assertTrue(decision["any_seed_fixture_harm_veto"])
        self.assertFalse(decision["promising_package"])

    def test_recall_only_gain_keeps_limited_two_metric_flag(self):
        baseline = {"development": {"metrics": {"recall": .5, "specificity": .75}},
                    "contextual": {"metrics": {"joint_accuracy": .25}},
                    "subgroups": {"disclosures": {key: .5 for key in ("joint_accuracy", "sensitivity_accuracy", "visibility_accuracy", "category_exact_accuracy", "action_accuracy")}},
                    "fixtures": {"casewise_harms": {"passed": True}}}
        final = copy.deepcopy(baseline)
        final["development"]["metrics"]["recall"] = .75
        flags = report.final_outcome_flags(baseline, final, 24)
        self.assertTrue(flags["no_specificity_or_context_joint_gain"])
        self.assertFalse(flags["tradeoff_only"])
        self.assertFalse(flags["continuing_rejections_final24"])
        self.assertNotIn("plateau_no_beneficial_final_change", flags)

    def controlled_endpoint(self, guesses, context_correct=0, fixture_action="ALLOW", disclosure=.5):
        development = [{"id": str(i), "group_id": "source-" + str(i // 2), "expected_has_pii": i < 2,
                        "detected_sensitive": guess, "status": "ok", "identities": [{"model_version": "v0"}]}
                       for i, guess in enumerate(guesses)]
        contextual = [self.fixture("c" + str(i)) for i in range(2)]
        for i, row in enumerate(contextual):
            row["identities"] = [{"model_version": "v0"}]
            if i >= context_correct:
                row["classification"] = {"sensitivity": "S3", "visibility": "P2", "categories": ["HEALTH"]}
        fixtures = [self.fixture("f", fixture_action)]
        fixtures[0]["identities"] = [{"model_version": "v0"}]
        return {"development": {"semantic": {"predictions": development, "metrics": continual.metrics(development)}},
                "contextual": {"semantic": {"predictions": contextual, "metrics": evidence.contextual_metrics(contextual)}},
                "fixtures": {"semantic": {"predictions": fixtures, "metrics": evidence.contextual_metrics(fixtures)}},
                "subgroups": {"disclosures": {key: disclosure for key in ("joint_accuracy", "sensitivity_accuracy", "visibility_accuracy", "category_exact_accuracy", "action_accuracy")}}}

    def test_controlled_effect_reports_shared_reference_and_difference_in_changes(self):
        baseline = self.controlled_endpoint([False, False, False, False])
        control = {"cell": {"id": "shared"}, "checkpoints": {"0": baseline,
                   "168": self.controlled_endpoint([True, False, False, False])}}
        revised = {"checkpoints": {"0": copy.deepcopy(baseline),
                   "168": self.controlled_endpoint([True, True, True, False], context_correct=1, fixture_action="BLOCK", disclosure=.75)}}
        effects = report.controlled_effect(revised, control, iterations=20)
        self.assertEqual(effects["shared_control_id"], "shared")
        self.assertTrue(effects["difference_in_changes_equivalent_to_final_contrast"])
        self.assertEqual(effects["development"]["recall"]["revised_final_minus_shared_control_final"], .5)
        self.assertEqual(effects["development"]["specificity"]["difference_in_changes"], -.5)
        self.assertEqual(effects["contextual"]["joint_accuracy"]["difference_in_changes"], .5)
        self.assertEqual(effects["disclosures"]["category_exact_accuracy"]["difference_in_changes"], .25)
        self.assertEqual(effects["fixture_harms_vs_shared_control"]["new_over_restrictions"], 1)
        self.assertEqual(effects["exact_prediction_changes_vs_shared_control"]["development"]["changed_rows"], 2)
        paired = effects["paired_development_vs_shared_control"]["semantic"]["paired"]
        self.assertEqual((paired["groups"], paired["iterations"], paired["seed"]), (2, 20, 10102026))
        revised["checkpoints"]["0"]["development"]["semantic"]["predictions"][0]["detected_sensitive"] = True
        with self.assertRaisesRegex(ValueError, "identical baseline"):
            report.controlled_effect(revised, control, iterations=20)

    def test_prepare_validates_retained_static_inputs_without_live_rpc(self):
        args = SimpleNamespace(output=self.root / "draft", study_id="privoke-accelerated-test",
            images=self.root / "images.json",
            current=study.ROOT / "evaluation/results/curriculum_improvement_20261009_v1/curricula/current/manifest.json",
            revised=study.ROOT / "evaluation/results/curriculum_improvement_20261009_v1/curricula/revised/manifest.json",
            dataset=study.ROOT / "evaluation/results/locked-public/development.jsonl",
            fixture=study.ROOT / "evaluation/results/contextual_fixtures_20261004_v1/support/fixture.jsonl",
            exclusion_index=study.ROOT / "evaluation/results/external_pii_20261004_prepared_v3/exclusion-index.json")
        continual.write_json(args.images, {service: "sha256:" + "a" * 64 for service in study.prior.SERVICES})
        with patch.object(study.prior, "require_committed_sources", return_value="test-revision"), patch.object(study.prior, "attest_image_sources", return_value={}), patch.object(study.prior, "command", side_effect=lambda command: json.dumps([{"Id": command[-1]}])):
            protocol = study.prepare(args)
        self.assertEqual(len(protocol["cells"]), 12)
        self.assertEqual(protocol["evaluation_layers"], ["semantic"])
        self.assertEqual(protocol["inputs"]["current"]["files"]["replay.jsonl"], protocol["inputs"]["revised"]["files"]["replay.jsonl"])

    def test_normal_batch_audit_crosses_epochs_and_legacy_default_rejects(self):
        pools = synthetic.build_curriculum(continual.read_json(study.ROOT / "evaluation/datasets/synthetic-teacher-templates-v2.json"))
        curriculum = Curriculum("test", "a" * 64, {key: tuple(rows) for key, rows in pools.items()})
        database = self.root / "curriculum.sqlite3"
        rounds = []
        for cycle in range(1, 169):
            request = PP.FuzzerTrainingRequest(request_id=f"r{cycle}", source_id="s", model_id="privoke-balanced", prompt_count=32,
                seed=1336 + cycle, metadata={"curriculum_sampler_policy": "seeded_family_v1", "curriculum_sampler_seed": "42"})
            reserve_batch(curriculum, str(database), request, 32, fingerprint="b" * 64, model_id=request.model_id)
            rounds.append({"request": {"source_id": "s", "model_id": request.model_id, "request_id": request.request_id}, "response": {"accepted": False}})
        lookup = {row["id"]: (split, row) for split, rows in pools.items() for row in rows}
        audited = evidence.audit_allocations(database, rounds, lookup, "seeded_family_v1", 42, .35, new_count=24, replay_count=8)
        self.assertEqual((audited["reservations"], audited["presentations"]), (168, 5376))
        with self.assertRaisesRegex(ValueError, "budget"):
            evidence.audit_allocations(database, rounds, lookup, "seeded_family_v1", 42, .35)

    def test_legacy_round_chain_default_does_not_accept_new_budget(self):
        continual.write_json(self.root / "snapshot-000.json", {"identity": {}, "parameters": {}})
        model = {"rounds": [{"response": {"accepted": False}}] * 168, "accepted_updates": 0}
        with self.assertRaisesRegex(ValueError, "budget"):
            prior_report.round_chain(self.root, "m", model)

    def test_new_round_chain_checks_all_168_seeds_and_32_row_requests(self):
        fingerprint = parameter_fingerprint({"head.bias": [0.]}, {"head.bias": [1]})
        identity = {"model_id": "m", "model_version": "v0", "artifact_checksum": "a", "parameter_fingerprint": fingerprint}
        snapshot = {"identity": identity, "parameters": {"head.bias": {"values": [0.], "shape": [1]}}}
        continual.write_json(self.root / "snapshot-000.json", snapshot)
        rounds = []
        for cycle in range(1, 169):
            request = {"request_id": str(cycle), "source_id": "s", "model_id": "m", "prompt_count": 32, "seed": 1336 + cycle}
            response = {"accepted": False, "metadata": {}}
            response_path = self.root / f"response-{cycle:03d}.json"
            continual.write_json(response_path, response)
            row = {"cycle": cycle, "request": request, "response": response, "identity": identity,
                   "request_fingerprint": hashlib.sha256(PP.FuzzerTrainingRequest(**request).SerializeToString(deterministic=True)).hexdigest(),
                   "response_path": response_path.name, "response_sha256": continual.sha(response_path)}
            continual.write_json(self.root / f"round-{cycle:03d}.json", row)
            continual.write_json(self.root / f"snapshot-{cycle:03d}.json", snapshot)
            rounds.append(row)
        model = {"rounds": rounds, "accepted_updates": 0}
        self.assertEqual(len(prior_report.round_chain(self.root, "m", model, attempts=168, prompt_count=32)), 168)
        rounds[-1]["request"]["seed"] = 1
        with self.assertRaisesRegex(ValueError, "budget/identity"):
            prior_report.round_chain(self.root, "m", model, attempts=168, prompt_count=32)

    def test_checkpoint_callback_never_remeasures_changed_resume_identity(self):
        identity = {"model_version": "v1"}
        client = SimpleNamespace(snapshot=lambda model_id: {"identity": identity})
        model = {"current_identity": {"model_version": "v0"}, "checkpoints": {}}
        callback = unittest.mock.Mock()
        with self.assertRaisesRegex(ValueError, "before checkpoint callback"):
            continual.save_checkpoint(client, [], "m", model, self.root, 0, {}, None, callback)
        callback.assert_not_called()
        checkpoint = self.root / "checkpoint-000.json"
        continual.write_json(checkpoint, {})
        model = {"current_identity": identity, "checkpoints": {"0": {"path": checkpoint.name, "sha256": continual.sha(checkpoint)}}}
        continual.save_checkpoint(client, [], "m", model, self.root, 0, {}, None, callback)
        callback.assert_called_once_with(client, "m", {"identity": identity}, 0)

    def test_service_optin_records_before_rejection_and_normal_branch_unchanged(self):
        config = SimpleNamespace(model_id="privoke-balanced", max_concurrent_cycles=1,
                                 max_prompt_count=256, seed=1337, heldout_prompt_count=16,
                                 prompt_dataset_path=None, minimum_exact_match_rate=0.)
        service = FuzzerTrainingService(config)
        update = self.update()
        update.metrics["candidate_heldout_sensitive_recall"] = .5
        class Rejected(Exception):
            pass
        class Context:
            def abort(self, code, message):
                self.code = code
                raise Rejected(message)
        for optin in (False, True):
            request = PP.FuzzerTrainingRequest(prompt_count=8, metadata={"study_gate_diagnostics": "v1"} if optin else {})
            context = Context()
            with patch.object(service, "_previous_update", return_value=PP.ParameterUpdateStatus()), patch.object(service, "_train", return_value=update), patch.object(service, "_submit_update") as submit, patch("fuzzer_service.write_gate_diagnostics") as write:
                with self.assertRaisesRegex(Rejected, "worse"):
                    service._run_training_cycle(request, context)
                self.assertEqual(write.call_count, int(optin))
                self.assertEqual(context.code, grpc.StatusCode.FAILED_PRECONDITION)
                submit.assert_not_called()

    def test_service_replayed_receipt_reuses_existing_diagnostic(self):
        service = FuzzerTrainingService(SimpleNamespace(model_id="m", max_concurrent_cycles=1, max_prompt_count=256, seed=1337))
        previous = PP.ParameterUpdateStatus(found=True, ack=PP.ParameterUpdateAck(accepted=True, model_id="m", applied_version="v1"))
        request = PP.FuzzerTrainingRequest(prompt_count=32, metadata={"study_gate_diagnostics": "v1"})
        with patch.object(service, "_previous_update", return_value=previous), patch("fuzzer_service.write_gate_diagnostics") as write:
            response = service._run_training_cycle(request, None)
        self.assertTrue(response.accepted)
        write.assert_not_called()

    def test_service_optin_success_keeps_publication_response(self):
        config = SimpleNamespace(model_id="privoke-balanced", max_concurrent_cycles=1, max_prompt_count=256,
                                 seed=1337, heldout_prompt_count=16, prompt_dataset_path=None, minimum_exact_match_rate=0.)
        service = FuzzerTrainingService(config)
        request = PP.FuzzerTrainingRequest(prompt_count=8, metadata={"study_gate_diagnostics": "v1"})
        context = SimpleNamespace(is_active=lambda: True)
        ack = PP.ParameterUpdateAck(accepted=True, model_id="privoke-balanced", applied_version="v1", message="ok")
        with patch.object(service, "_previous_update", return_value=PP.ParameterUpdateStatus()), patch.object(service, "_train", return_value=self.update()), patch.object(service, "_submit_update", return_value=ack) as submit, patch("fuzzer_service.write_gate_diagnostics") as write:
            response = service._run_training_cycle(request, context)
        self.assertTrue(response.accepted)
        self.assertEqual(response.applied_version, "v1")
        self.assertEqual(response.metadata["updated_parameter_fingerprint"], "b" * 64)
        submit.assert_called_once()
        write.assert_called_once()


if __name__ == "__main__":
    unittest.main()
