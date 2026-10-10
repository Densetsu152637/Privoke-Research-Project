import base64
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))
import grpc
from fuzzer_service import FuzzerTrainingService
from privoke.v1 import parameters_pb2 as pb
from training.types import BatchTrainingExample, BatchTrainingUpdate, BatchTrainingConfig


class Aborted(Exception):
    pass


class Context:
    def __init__(self, active=True): self.active=active
    def abort(self, code, message):
        self.code=code
        raise Aborted(message)
    def is_active(self): return self.active


class UnderlyingCycleTests(unittest.TestCase):
    def test_definitive_updater_rejections_reach_scheduler_without_transient_relabeling(self):
        class RejectedUpdate(grpc.RpcError):
            def __init__(self, status): self.status=status
            def code(self): return self.status
        self.config.param_update_target="unused"
        self.config.fuzzer_id="test-fuzzer"
        for status in (grpc.StatusCode.INVALID_ARGUMENT, grpc.StatusCode.FAILED_PRECONDITION,
                       grpc.StatusCode.ALREADY_EXISTS, grpc.StatusCode.UNAVAILABLE):
            context=Context()
            with self.subTest(status=status),patch("fuzzer_service.emit_training_update",side_effect=RejectedUpdate(status)):
                with self.assertRaises(Aborted):
                    self.service._submit_update(self.request,SimpleNamespace(requested_prompt_count=8),
                                                self.update,8,context)
            self.assertEqual(context.code,status)

    def test_durable_reservation_rejects_changed_effective_settings_before_lookup_or_training(self):
        from training.evidence import reserve_training_request
        reserve_training_request(self.request,"heads","old-settings")
        with patch.object(self.service,"_previous_update_for_fingerprint") as lookup,patch.object(self.service,"_train") as train:
            with self.assertRaisesRegex(Aborted,"different effective training settings"):
                self.service.RunTrainingCycle(self.request,Context())
        lookup.assert_not_called();train.assert_not_called()

    def test_lost_ack_evidence_is_recovered_from_actual_committed_receipt(self):
        from training.evidence import persist_cycle_evidence,recover_cycle_evidence_ack
        persist_cycle_evidence(self.request,self.update,"full_encoder",gate_passed=True)
        status=pb.ParameterUpdateStatus(found=True,base_version="S1",ack=self.ack,prompts_generated=8)
        recover_cycle_evidence_ack(self.request,"full_encoder",status)
        evidence=json.loads(next(Path(self.temporary.name).glob("training-cycles/*/*.json")).read_text())
        self.assertEqual(evidence["ack_source"],"updater_receipt")
        self.assertEqual(evidence["ack"]["applied_version"],"S2")
        self.assertEqual(evidence["execution_evidence"],self.update.execution_evidence)

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        environment=patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":self.temporary.name})
        environment.start()
        self.addCleanup(environment.stop)
        self.config=SimpleNamespace(model_id="privoke-balanced", max_concurrent_cycles=1, seed=42,
            max_prompt_count=256,heldout_prompt_count=16,prompt_dataset_path=None,minimum_exact_match_rate=0.0)
        self.config.batch_training_config=lambda seed: BatchTrainingConfig(seed=seed)
        self.config.privoke_runtime_target="unused"
        self.config.timeout_seconds=10
        self.service=FuzzerTrainingService(self.config)
        self.request=pb.FuzzerTrainingRequest(request_id="same-id",source_id="same-source",model_id="privoke-balanced",
            prompt_count=8,metadata={"require_full_capability":"true"})
        metrics={key:.5 for key in ("exact_match_rate","heldout_exact_match_rate","candidate_heldout_exact_match_rate",
            "heldout_sensitive_recall","candidate_heldout_sensitive_recall","heldout_clean_specificity","candidate_heldout_clean_specificity")}
        metrics.update(heldout_sensitive_examples=8,heldout_clean_examples=8,candidate_heldout_safety_regression_rate=0.)
        self.update=BatchTrainingUpdate(model_id="privoke-balanced",base_version="S1",gradients={},parameter_shapes={},
            metrics=metrics,metadata={"base_parameter_fingerprint":"a"*64,"training_scope":"full_encoder"},
            execution_evidence={"rpc":"ComputeUnderlyingModelGradients","request_layers":[4],"executions":[]})
        self.ack=pb.ParameterUpdateAck(accepted=True,model_id="privoke-balanced",applied_version="S2")

    def run_cycle(self, context=None):
        return self.service.RunUnderlyingTrainingCycle(self.request,context or Context())

    def test_full_dispatch_namespaces_receipts_and_persists_actual_evidence_before_submission(self):
        def submit(request,cycle,update,count,context,**kwargs):
            evidence=list(Path(self.temporary.name).glob("training-cycles/*/*.json"))
            self.assertEqual(len(evidence),1)
            self.assertNotIn("ack",json.loads(evidence[0].read_text()))
            return self.ack
        with patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":self.temporary.name}), \
             patch.object(self.service,"_previous_update_for_fingerprint",return_value=pb.ParameterUpdateStatus()) as lookup, \
             patch("fuzzer_service.generate_training_partition",return_value=([BatchTrainingExample("synthetic")]*8,[])), \
             patch.object(self.service,"_train",return_value=self.update) as train, \
             patch.object(self.service,"_submit_update",side_effect=submit):
            response=self.run_cycle()
        self.assertTrue(response.accepted)
        self.assertEqual(train.call_args.kwargs["training_scope"],"full_encoder")
        self.assertNotEqual(lookup.call_args.args[0].source_id,self.request.source_id)
        self.assertEqual(lookup.call_args.args[0].metadata["original_request_source_id"],self.request.source_id)
        evidence=json.loads(next(Path(self.temporary.name).glob("training-cycles/*/*.json")).read_text())
        self.assertEqual(evidence["execution_evidence"],self.update.execution_evidence)
        self.assertEqual(evidence["ack"]["applied_version"],"S2")

    def test_replay_uses_receipt_without_sampling_or_training(self):
        status=pb.ParameterUpdateStatus(found=True,base_version="S1",ack=self.ack,prompts_generated=8)
        with patch.object(self.service,"_previous_update_for_fingerprint",return_value=status), \
             patch("fuzzer_service.generate_training_partition") as sample,patch.object(self.service,"_train") as train:
            self.assertTrue(self.run_cycle().accepted)
        sample.assert_not_called();train.assert_not_called()

    def test_cancel_guard_veto_and_stale_sequential_base_prevent_publication(self):
        for failure in ("cancel","guard","stale"):
            self.request.request_id=failure
            context=Context(active=failure!="cancel")
            if failure=="guard": self.update.metrics["candidate_heldout_safety_regression_rate"]=.125
            if failure=="stale": self.request.metadata["expected_base_version"]="different-S1"
            with patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":self.temporary.name}), \
                 patch.object(self.service,"_previous_update_for_fingerprint",return_value=pb.ParameterUpdateStatus()), \
                 patch("fuzzer_service.generate_training_partition",return_value=([BatchTrainingExample("synthetic")]*8,[])), \
                 patch.object(self.service,"_train",return_value=self.update),patch.object(self.service,"_submit_update") as submit:
                with self.subTest(failure=failure),self.assertRaises(Aborted): self.run_cycle(context)
            submit.assert_not_called()
            self.update.metrics["candidate_heldout_safety_regression_rate"]=0.

    def test_unusable_runtime_preflight_cannot_publish_automatic_head(self):
        from runtime_client import RuntimeAnalysisError
        with patch.object(self.service,"_previous_update_for_fingerprint",return_value=pb.ParameterUpdateStatus()), \
             patch("fuzzer_service.generate_training_partition",return_value=([BatchTrainingExample("synthetic")]*8,[])), \
             patch("fuzzer_service.train_parameter_batch",side_effect=RuntimeAnalysisError("CPU autograd unavailable")), \
             patch.object(self.service,"_submit_update") as submit:
            with self.assertRaises(Aborted): self.service.RunTrainingCycle(self.request,Context())
        submit.assert_not_called()
