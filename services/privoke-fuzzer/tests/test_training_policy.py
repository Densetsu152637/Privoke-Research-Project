"""Durable policy admission and bounded actual publication contracts."""
import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_dual_runtime_contract import contract, ROOT
from test_taxonomy_coverage import Context, Aborted
from config import FuzzerConfig
from fuzzer_service import FuzzerTrainingService
from runtime_client import PrivokeRuntimeClient, RuntimeAnalysisError
from privoke.v1 import parameters_pb2
from privoke_contracts.classification import initialise_unpacked, Sensitivity, Visibility, Category
from privoke_model.contextual_training import (CLASS_BALANCED_OBJECTIVE, LEGACY_OBJECTIVE, TRAIN_DIAGNOSTICS_POLICY,
    DIAGNOSTICS_KEY, DIAGNOSTICS_POLICY_KEY, EXECUTED_OBJECTIVE_KEY, DIAGNOSTIC_LOSS_COLUMNS,
    DIAGNOSTIC_ACCURACY_COLUMNS, DIAGNOSTIC_UPDATE_COLUMNS)
from training.types import BatchTrainingExample, BatchTrainingUpdate
from training.evidence import persist_cycle_evidence
from training.parameter_updates import emit_training_update


class TrainingPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.environment = patch.dict(os.environ, {"PRIVOKE_FUZZER_DUMP_DIR": self.directory.name})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.clean = initialise_unpacked(Sensitivity.S0, Visibility.PU, [])
        self.sensitive = initialise_unpacked(Sensitivity.S3, Visibility.P4, [Category.HEALTH])
        self.rows = [BatchTrainingExample("synthetic train clean", self.clean), BatchTrainingExample("synthetic train private", self.sensitive)]

    def response(self, scope):
        _, response = contract(scope)
        response.executions[0].examples = 2
        response.metrics["examples"] = 2
        if scope == "full_encoder":
            response.gradients[0].values[0] = .0001
        record = {"schema": 1, "objective": CLASS_BALANCED_OBJECTIVE, "fingerprints": ["b" * 64, "c" * 64],
            "phases": [["base_training", "semantic", "ok", 2], ["candidate_training", "semantic", "ok", 2]],
            "counts": [2, 1, 1], "loss_columns": list(DIAGNOSTIC_LOSS_COLUMNS), "loss": [[1, 1, 1, 3]] * 2,
            "accuracy_columns": list(DIAGNOSTIC_ACCURACY_COLUMNS), "accuracy": [[1] * 6] * 2,
            "update_columns": list(DIAGNOSTIC_UPDATE_COLUMNS), "update": [sum(len(p.values) for p in response.gradients), 0, .0001, .0001]}
        response.metadata.update({EXECUTED_OBJECTIVE_KEY: CLASS_BALANCED_OBJECTIVE,
            DIAGNOSTICS_POLICY_KEY: TRAIN_DIAGNOSTICS_POLICY, DIAGNOSTICS_KEY: json.dumps(record, separators=(",", ":"))})
        return response

    def compute(self, response, scope="heads", objective=CLASS_BALANCED_OBJECTIVE):
        with patch("runtime_client.grpc.insecure_channel"), patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
            rpc = stub.return_value.ComputeUnderlyingModelGradients if scope == "full_encoder" else stub.return_value.ComputeSemanticGradients
            rpc.return_value = response
            return PrivokeRuntimeClient("unused").compute_semantic_gradients(self.rows, heldout_examples=[BatchTrainingExample("guard", self.clean)],
                model_id="privoke-balanced", learning_rate=.03, max_gradient=.05, request_id="req", training_scope=scope,
                expected_objective=objective, expected_diagnostics_policy=TRAIN_DIAGNOSTICS_POLICY)

    def test_postcompute_policy_and_diagnostic_failures_retain_immutable_actual_wire(self):
        response = self.response("heads")
        for failure in ("policy", "malformed", "overflow", "integer_overflow"):
            changed = copy.deepcopy(response)
            if failure == "malformed":
                changed.metadata[DIAGNOSTICS_KEY] = "malformed"
            if failure == "overflow":
                diagnostic = json.loads(changed.metadata[DIAGNOSTICS_KEY])
                diagnostic["loss"] = [[1e308] * 4] * 2
                changed.metadata[DIAGNOSTICS_KEY] = json.dumps(diagnostic, separators=(",", ":"))
            if failure == "integer_overflow":
                diagnostic = json.loads(changed.metadata[DIAGNOSTICS_KEY])
                diagnostic["loss"][0][0] = 10 ** 400
                changed.metadata[DIAGNOSTICS_KEY] = json.dumps(diagnostic, separators=(",", ":"))
            with self.assertRaises(RuntimeAnalysisError), patch("training.parameter_updates.emit_parameter_update") as submit:
                self.compute(changed, objective=LEGACY_OBJECTIVE if failure == "policy" else CLASS_BALANCED_OBJECTIVE)
            submit.assert_not_called()
        records = list(Path(self.directory.name).glob("policy-attempts/*/attempts/*.json"))
        self.assertEqual(len(records), 4)
        for path in records:
            record = json.loads(path.read_text())
            self.assertEqual(record["compute_status"], "response_received_unadmitted")
            self.assertEqual(record["admission_status"], "rejected")
            self.assertEqual(record["declared_executions"][0]["examples"], 2)
            self.assertTrue(base64.b64decode(record["response_protobuf_base64"]))

    def test_transport_failure_is_unknown_and_retained(self):
        import grpc
        with patch("runtime_client.grpc.insecure_channel"), patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
            stub.return_value.ComputeSemanticGradients.side_effect = grpc.RpcError()
            with self.assertRaises(grpc.RpcError):
                PrivokeRuntimeClient("unused").compute_semantic_gradients(self.rows, heldout_examples=[self.rows[0]],
                    model_id="privoke-balanced", learning_rate=.03, max_gradient=.05, expected_objective=LEGACY_OBJECTIVE)
        record = json.loads(next(Path(self.directory.name).glob("policy-attempts/*/attempts/*.json")).read_text())
        self.assertEqual(record["compute_status"], "transport_outcome_unknown")
        self.assertNotIn("declared_executions", record)

    def test_optin_head_reserves_before_lookup_and_identical_terminal_retry_does_no_work(self):
        with patch.dict(os.environ, {"FUZZ_CONTEXTUAL_SAMPLING_STRATEGY": "legacy_random_v1"}, clear=True):
            config = FuzzerConfig.from_env()
        request = parameters_pb2.FuzzerTrainingRequest(request_id="same", source_id="test", prompt_count=32,
            metadata={"expected_contextual_training_objective": LEGACY_OBJECTIVE})
        previous = parameters_pb2.ParameterUpdateStatus(found=True, base_version="v1", prompts_generated=32,
            ack=parameters_pb2.ParameterUpdateAck(accepted=True, model_id=config.model_id, applied_version="v2"))
        service = FuzzerTrainingService(config)
        for _ in range(2):
            with patch.object(service, "_previous_update_for_fingerprint", return_value=previous), \
                 patch("fuzzer_service.generate_training_partition") as sample, patch.object(service, "_train") as train:
                self.assertTrue(service.RunTrainingCycle(request, Context()).accepted)
            sample.assert_not_called()
            train.assert_not_called()
        changed = copy.deepcopy(request)
        changed.metadata["expected_contextual_training_objective"] = CLASS_BALANCED_OBJECTIVE
        with patch.object(service, "_previous_update_for_fingerprint") as lookup, self.assertRaisesRegex(Aborted, "different effective"):
            service.RunTrainingCycle(changed, Context())
        lookup.assert_not_called()
        with patch.dict(os.environ, {"PRIVOKE_FUZZER_DUMP_DIR": ""}), self.assertRaisesRegex(Aborted, "durable"):
            service.RunTrainingCycle(request, Context())

    def test_actual_head_and_full_publication_compacts_only_with_complete_durable_evidence(self):
        for scope in ("heads", "full_encoder"):
            batch = self.compute(self.response(scope), scope)
            metadata = batch["metadata"]
            # Match the existing taxonomy and class-weight audit union, then add runtime/gate fields.
            for index in range(16):
                metadata[f"sampling_test_{index}"] = "audit"
            for name in ("training_clean_examples", "training_sensitive_examples", "raw_clean_weight", "raw_sensitive_weight",
                         "raw_total_weight", "effective_clean_weight", "effective_sensitive_weight", "clean_objective_mass",
                         "sensitive_objective_mass", "objective_strata"):
                metadata[name] = "1"
            for index in range(20):
                batch["metrics"][f"retained_metric_{index}"] = 1.
            update = BatchTrainingUpdate(batch["model_id"], batch["base_version"], batch["gradients"], batch["shapes"],
                                         batch["metrics"], metadata, batch["execution_evidence"])
            request = parameters_pb2.FuzzerTrainingRequest(source_id="test", request_id="req")
            extra = {"request_source_id": "test", "request_id": "req", "training_request_fingerprint": "d" * 64,
                     "requested_prompt_count": "2", "generated_prompt_count": "2", "training_pipeline": "semantic"}
            with self.assertRaises(FileNotFoundError):
                emit_training_update("unused", "source", update, extra)
            persist_cycle_evidence(request, update, scope, gate_passed=True)
            with patch("training.parameter_updates.emit_parameter_update") as emit:
                emit_training_update("unused", "source", update, extra)
            payload = emit.call_args.args[1]
            self.assertLessEqual(len(payload.metadata), 64)
            self.assertTrue(all(len(v.encode()) <= 2048 for v in payload.metadata.values()))
            compact = json.loads(payload.metadata["training_audit_v1"])["fields"]
            self.assertEqual(compact["sampling_test_0"], "audit")
            self.assertEqual(payload.metadata[DIAGNOSTICS_KEY], metadata[DIAGNOSTICS_KEY])
            # Exercise the real protobuf submission conversion and updater's unchanged metadata boundary.
            from training.parameter_updates import emit_parameter_update
            with patch("grpc.insecure_channel"), patch("privoke.v1.parameters_pb2_grpc.ParamUpdateServiceStub") as stub:
                emit_parameter_update("unused", payload)
            wire = stub.return_value.SubmitParameterUpdate.call_args.args[0]
            self.assertEqual(dict(wire.metadata), dict(payload.metadata))
            import importlib.util
            spec = importlib.util.spec_from_file_location("policy_updater_validation", ROOT / "services/param-update-service/app/validation.py")
            validation = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(validation)
            validation._validate_metadata(wire.metadata)


class BacktrackingAdmissionTests(unittest.TestCase):
    setUp = TrainingPolicyTests.setUp
    # Inherit the established OP02 admission checks; add only the FULL policy boundary.
    def response(self, scope="full_encoder", rejected=False):
        from privoke_model.contextual_training import (BACKTRACKING_KEY, BACKTRACKING_POLICY, BACKTRACKING_PREPARATION_KEY,
            BACKTRACKING_TRACE_KEY, BACKTRACKING_TRIALS_KEY, BACKTRACKING_REJECTION, BACKTRACKING_SCALES)
        from privoke_model.fingerprint import parameter_fingerprint
        response = TrainingPolicyTests.response(self, scope)
        shapes = {p.name: tuple(p.shape) for p in response.gradients}
        delta = {p.name: tuple(p.values) for p in response.gradients}
        response.metadata.update({BACKTRACKING_KEY: BACKTRACKING_POLICY, BACKTRACKING_PREPARATION_KEY: "a"*64, "learning_rate": str(.03)})
        base = [1., 1., 1., 3.]
        losses = base if rejected else [.9, 1., 1., 2.9]
        trials = [[.03*scale, losses, 0, .0001, .0001, parameter_fingerprint(delta, shapes), "c"*64, "ok", 2, True, 2]
                  for scale in (BACKTRACKING_SCALES if rejected else BACKTRACKING_SCALES[:1])]
        header = {"schema": 1, "policy": BACKTRACKING_POLICY, "objective": CLASS_BALANCED_OBJECTIVE,
            "base": ["b"*64, base], "raw": ["d"*64, response.metadata["trained_parameter_inventory_fingerprint"],
            sum(len(p.values) for p in response.gradients), 1., 1.], "selected": None if rejected else 0, "gradient_fits": 1}
        response.metadata[BACKTRACKING_TRACE_KEY] = json.dumps(header, separators=(",", ":"))
        response.metadata[BACKTRACKING_TRIALS_KEY] = json.dumps(trials, separators=(",", ":"))
        response.metrics.update(gradient_fits=1, backtracking_trials=len(trials), backtracking_semantic_examples=2*len(trials), backtracking_forward_attempts=len(trials),backtracking_attempted_semantic_examples=2*len(trials))
        if rejected:
            response.error = BACKTRACKING_REJECTION
            del response.gradients[:]; del response.executions[1:]
            del response.metadata["updated_parameter_fingerprint"]; del response.metadata[DIAGNOSTICS_KEY]
            for key in list(response.metrics):
                if key.startswith("heldout_"): del response.metrics[key]
        else:
            response.metadata["effective_learning_rate"] = str(.03)
            diagnostic = json.loads(response.metadata[DIAGNOSTICS_KEY]); diagnostic["loss"] = [base, losses]
            response.metadata[DIAGNOSTICS_KEY] = json.dumps(diagnostic, separators=(",", ":"))
        return response

    def bs_compute(self, response):
        from privoke_model.contextual_training import BACKTRACKING_POLICY
        with patch("runtime_client.grpc.insecure_channel"), patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
            rpc = stub.return_value.ComputeUnderlyingModelGradients
            rpc.return_value = response
            result = PrivokeRuntimeClient("unused").compute_underlying_gradients(self.rows, heldout_examples=[self.rows[0]],
                model_id="privoke-balanced", learning_rate=.03, max_gradient=.05, request_id="req",
                expected_objective=CLASS_BALANCED_OBJECTIVE, expected_diagnostics_policy=TRAIN_DIAGNOSTICS_POLICY,
                expected_backtracking_policy=BACKTRACKING_POLICY, expected_backtracking_preparation_sha256="a"*64)
            self.assertEqual(list(rpc.call_args.args[0].layers), [4])
            self.assertEqual(len(rpc.call_args.kwargs["metadata"]), 1)
            return result

    def test_bs_raw_before_admission_huge_float_integer_malformed_and_policy(self):
        from privoke_model.contextual_training import BACKTRACKING_TRIALS_KEY, BACKTRACKING_KEY
        from runtime_client import validate_backtracking_response
        for mutation in ("huge_float", "huge_int", "malformed", "policy"):
            response = self.response()
            if mutation == "policy": response.metadata[BACKTRACKING_KEY] = "unknown"
            else:
                trials = json.loads(response.metadata[BACKTRACKING_TRIALS_KEY])
                if mutation == "huge_float": trials[0][1] = [1e308]*4
                if mutation == "huge_int": trials[0][1][0] = 10**309
                response.metadata[BACKTRACKING_TRIALS_KEY] = "bad" if mutation == "malformed" else json.dumps(trials, separators=(",", ":"))
            def admit(*args, **kwargs):
                paths = list(Path(self.directory.name).glob("backtracking-attempts/*/attempts/*.json"))
                self.assertTrue(paths)
                self.assertTrue(any(base64.b64decode(json.loads(p.read_text())["response_protobuf_base64"]) == response.SerializeToString(deterministic=True) for p in paths))
                return validate_backtracking_response(*args, **kwargs)
            with patch("runtime_client.validate_backtracking_response", side_effect=admit), self.assertRaises(RuntimeAnalysisError), patch("training.parameter_updates.emit_parameter_update") as submit:
                self.bs_compute(response)
            submit.assert_not_called()
        attempts = list(Path(self.directory.name).glob("backtracking-attempts/*/attempts/*.json"))
        verdicts = list(Path(self.directory.name).glob("backtracking-attempts/*/admission/attempts/*.json"))
        self.assertEqual((len(attempts), len(verdicts)), (4, 4))
        for p in verdicts: self.assertIsNone(json.loads(p.read_text())["gradient_fits"])

    def test_bs_known_rejection_retained_one_fit_no_guard_and_selected_acceptance(self):
        from runtime_client import TrainingStepRejected
        with self.assertRaises(TrainingStepRejected), patch("training.parameter_updates.emit_parameter_update") as submit:
            self.bs_compute(self.response(rejected=True))
        submit.assert_not_called()
        verdict = json.loads(next(Path(self.directory.name).glob("backtracking-attempts/*/admission/attempts/*.json")).read_text())
        self.assertEqual((verdict["status"], verdict["gradient_fits"]), ("known_train_rejection", 1))
        self.assertTrue(verdict["raw_gradient_shapes"])
        batch = self.bs_compute(self.response())
        self.assertEqual(batch["metrics"]["gradient_fits"], 1)
        self.assertTrue(batch["execution_evidence"]["invocation_metadata"])

    def test_bs_malformed_typed_rejection_is_unadmitted_with_raw_before_admission(self):
        from privoke_model.contextual_training import BACKTRACKING_TRIALS_KEY
        from runtime_client import validate_backtracking_response,TrainingStepRejected
        for mutation in ("extra_guard_execution","guard_metric","invalid_candidate_fingerprint"):
            response=self.response(rejected=True)
            if mutation=="extra_guard_execution":response.executions.add(phase="base_heldout",layer=4,status="ok",examples=1)
            elif mutation=="guard_metric":response.metrics["heldout_examples"]=1
            else:
                rows=json.loads(response.metadata[BACKTRACKING_TRIALS_KEY]);rows[0][6]="invalid"
                response.metadata[BACKTRACKING_TRIALS_KEY]=json.dumps(rows,separators=(",",":"))
            before=len(list(Path(self.directory.name).glob("backtracking-attempts/*/attempts/*.json")))
            def validate(*args,**kwargs):
                files=list(Path(self.directory.name).glob("backtracking-attempts/*/attempts/*.json"))
                self.assertEqual(len(files),before+1)
                self.assertTrue(any(base64.b64decode(json.loads(p.read_text())["response_protobuf_base64"])==response.SerializeToString(deterministic=True) for p in files))
                return validate_backtracking_response(*args,**kwargs)
            with patch("runtime_client.validate_backtracking_response",side_effect=validate),self.assertRaises(RuntimeAnalysisError),patch("training.parameter_updates.emit_parameter_update") as submit:
                self.bs_compute(response)
            submit.assert_not_called()
        verdicts=[json.loads(p.read_text()) for p in Path(self.directory.name).glob("backtracking-attempts/*/admission/attempts/*.json")]
        self.assertEqual(len(verdicts),3)
        self.assertTrue(all(v["status"]=="unadmitted" and v["gradient_fits"] is None for v in verdicts))

    def test_bs_transport_unknown_and_persistence_failure_do_not_submit(self):
        import grpc
        from privoke_model.contextual_training import BACKTRACKING_POLICY
        with patch("runtime_client.grpc.insecure_channel"), patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
            stub.return_value.ComputeUnderlyingModelGradients.side_effect = grpc.RpcError()
            with self.assertRaises(grpc.RpcError), patch("training.parameter_updates.emit_parameter_update") as submit:
                PrivokeRuntimeClient("unused").compute_underlying_gradients(self.rows, heldout_examples=[self.rows[0]], model_id="privoke-balanced",
                    learning_rate=.03, max_gradient=.05, expected_objective=CLASS_BALANCED_OBJECTIVE, expected_diagnostics_policy=TRAIN_DIAGNOSTICS_POLICY,
                    expected_backtracking_policy=BACKTRACKING_POLICY, expected_backtracking_preparation_sha256="a"*64)
            submit.assert_not_called()
        attempt = json.loads(next(Path(self.directory.name).glob("backtracking-attempts/*/attempts/*.json")).read_text())
        self.assertEqual(attempt["compute_status"], "transport_outcome_unknown")
        self.assertIsNone(attempt["gradient_fits"])
        self.assertNotIn("response_protobuf_base64", attempt)
        with patch("training.evidence.persist_backtracking_attempt", side_effect=OSError("fixture disk full")), self.assertRaises(OSError), patch("training.parameter_updates.emit_parameter_update") as submit:
            self.bs_compute(self.response())
        submit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
