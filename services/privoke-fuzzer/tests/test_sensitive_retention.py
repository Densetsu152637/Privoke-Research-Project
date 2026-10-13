"""Manufactured reference authentication at real fuzzer/trainer boundaries; no RPC."""
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from config import FuzzerConfig
from fuzzer_service import FuzzerTrainingService
from prompt_generation import benign_coverage as benign
import test_benign_coverage
from test_taxonomy_coverage import Context, Aborted
from training.trainer import train_parameter_batch, iter_training_examples
from training.types import BatchTrainingUpdate
from training.parameter_updates import emit_training_update
from training.evidence import persist_cycle_evidence
from training.full_adam_evidence import publication_metadata, WEIGHT_FIELDS, BENIGN_KEY, WEIGHT_KEY, GATE_KEY
from privoke_model import sensitive_retention as retention
from privoke_model.full_adam import CONFIG, canonical
from privoke.v1 import parameters_pb2 as pb, runtime_pb2

ROOT = Path(__file__).resolve().parents[3]
BANK = ROOT / "evaluation/results/iterative_fuzzer_20261011/train-sensitive-retention/approved-train-bank.json"


def manufactured_release():
    bank = BANK.read_bytes()
    teacher = {"profile": "balanced", "model_id": "privoke-balanced", "version": "manufactured-original",
        "file_sha256": retention.TEACHER_SHA256["balanced"], "checksum": "a" * 64,
        "parameter_fingerprint": "b" * 64, "inventory_fingerprint": "c" * 64, "config": {}}
    references = retention.canonical_bytes({"schema": 1, "teacher": teacher,
        "bank_sha256": retention.BANK_SHA256, "boundary": retention.BOUNDARY,
        "rows": [{"id": r["id"], "packed": r["packed_classification"], "confidence": .9,
            "margin": 2., "sensitivity_gap": 1., "eligible": True} for r in retention.validate_bank(bank)]})
    manifest = retention.canonical_bytes(retention.manifest_value(bank, references, teacher))
    return retention.RetentionRelease(bank, references, manifest, "manufactured-original.json"), teacher


def admission(release):
    return {"expected_contextual_training_optimizer": retention.GATE_POLICY,
        "expected_contextual_training_objective": retention.GATE_OBJECTIVE,
        "expected_contextual_candidate_eligibility": retention.ELIGIBILITY,
        "expected_full_projected_adam_config_v1": canonical(CONFIG),
        "expected_contextual_training_scope": "full_encoder",
        "expected_" + retention.MANIFEST_KEY: release.sha256}


class RetentionBoundaryTests(unittest.TestCase):
    setUp = test_benign_coverage.BenignCoverageTests.setUp

    def test_both_policy_publishers_project_losslessly_before_emit(self):
        expanded = list(iter_training_examples(self.originals, (), self.config))
        audit = benign.audit_expanded(self.dataset, self.release, self.originals, expanded, self.guard, self.config)
        import base64
        wire = runtime_pb2.ComputeSemanticGradientsRequest(request_id="req", model_id="privoke-balanced", layers=[4],
            examples=benign.training_wire_rows(expanded), heldout_examples=benign.guard_wire_rows(self.guard))
        request = pb.FuzzerTrainingRequest(request_id="req", source_id="test")
        gate = {"minimum_exact_match_rate": 0}
        metrics = {key: .000000123 for key in WEIGHT_FIELDS}
        extra = {"request_id": "req", "request_source_id": "test", "training_request_fingerprint": "d" * 64}
        for policy in retention.POLICIES:
            meta = {**audit, "contextual_training_optimizer": policy, "training_scope": "full_encoder",
                "base_parameter_fingerprint": "b" * 64, retention.TRACE_KEY: "manufactured retained raw trace",
                retention.SUMMARY_KEY: canonical({"fixture": "bounded summary"}), retention.MANIFEST_KEY: "c" * 64,
                GATE_KEY: canonical(gate)}
            evidence = {"request_protobuf_base64": base64.b64encode(wire.SerializeToString(deterministic=True)).decode()}
            update = BatchTrainingUpdate("privoke-balanced", "v1", {}, {}, metrics, meta, evidence)
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"PRIVOKE_FUZZER_DUMP_DIR": directory}), \
                 patch("training.full_adam_evidence.validate_candidate_route", return_value=True), \
                 patch("training.full_adam_evidence.gate_summary", return_value=gate), \
                 patch("fuzzer_service.validate_training_update"), \
                 patch("training.full_adam_evidence.publication_metadata", wraps=publication_metadata) as projection, \
                 patch("training.parameter_updates.emit_parameter_update") as emit:
                # This focused fixture isolates dispatch/projection; the constructor witness validates the complete raw route.
                evidence["benign_audit"] = benign.persist_audit(self.release, audit)
                persist_cycle_evidence(request, update, "full_encoder", gate_passed=True)
                emit_training_update("unused", "source", update, extra)
                projection.assert_called_once(); emit.assert_called_once()
                incoming = projection.call_args.args[1]
                outgoing = dict(emit.call_args.args[1].metadata)
                self.assertNotIn(retention.TRACE_KEY, outgoing)
                self.assertEqual(outgoing[retention.SUMMARY_KEY], meta[retention.SUMMARY_KEY])
                self.assertEqual(outgoing[retention.MANIFEST_KEY], meta[retention.MANIFEST_KEY])
                self.assertLessEqual(len(outgoing), 64)
                self.assertLessEqual(max(len(v.encode()) for v in outgoing.values()), 2048)
                restored = {k: v for k, v in outgoing.items() if k not in (BENIGN_KEY, WEIGHT_KEY, "training_evidence_sha256")}
                restored.update(json.loads(outgoing[BENIGN_KEY])["fields"])
                restored.update(json.loads(outgoing[WEIGHT_KEY])["fields"])
                self.assertEqual(restored, {k: v for k, v in incoming.items() if k != retention.TRACE_KEY})

    def test_both_policy_publishers_reject_missing_raw_evidence_before_emit(self):
        for policy in retention.POLICIES:
            update = BatchTrainingUpdate("privoke-balanced", "v1", {}, {}, {},
                {"contextual_training_optimizer": policy, retention.TRACE_KEY: "manufactured"}, {})
            with patch("training.parameter_updates.emit_parameter_update") as emit, \
                 patch("training.full_adam_evidence.publication_metadata", wraps=publication_metadata) as projection, \
                 self.assertRaises((ValueError, KeyError)):
                emit_training_update("unused", "source", update)
            projection.assert_called_once(); emit.assert_not_called()

    def test_forged_manifest_rejects_before_reservation_and_recovered_receipt(self):
        release, teacher = manufactured_release()
        refs = json.loads(release.reference_payload)
        refs["rows"][0]["margin"] = 1.5
        payload = retention.canonical_bytes(refs)
        forged = replace(release, reference_payload=payload,
            manifest_payload=retention.canonical_bytes(retention.manifest_value(release.bank_payload, payload, teacher)))
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"PRIVOKE_FUZZER_DUMP_DIR": directory}), \
             patch.object(retention, "teacher_identity", return_value=teacher):
            root = Path(directory)
            for name, value in (("dataset", self.dataset_payload), ("pool", self.pool.payload),
                    ("proof", self.proof), ("manifest", self.release.payload)):
                (root / name).write_bytes(value)
            config = replace(FuzzerConfig.from_env(), model_id="privoke-balanced",
                prompt_dataset_path=str(root / "dataset"), benign_pool_path=str(root / "pool"),
                benign_manifest_path=str(root / "manifest"), benign_exclusion_proof_path=str(root / "proof"),
                underlying_training_learning_rate=.003, retention_manifest_sha256=release.sha256)
            metadata = {**admission(forged), "contextual_sampling_strategy": benign.STRATEGY,
                "taxonomy_dataset_sha256": self.dataset.sha256, benign.POOL_KEY: self.pool.sha256,
                benign.MANIFEST_KEY: self.release.sha256, benign.PROOF_KEY: self.release.proof_sha256}
            request = pb.FuzzerTrainingRequest(request_id="forged-replay", source_id="manufactured",
                model_id="privoke-balanced", prompt_count=32, seed=42, metadata=metadata)
            service = FuzzerTrainingService(config)
            with patch.object(retention, "load_release", return_value=forged), \
                 patch("fuzzer_service.reserve_training_request") as reserve, \
                 patch.object(service, "_previous_update_for_fingerprint") as lookup, \
                 patch.object(service, "_train") as train, self.assertRaises(Aborted):
                service.RunUnderlyingTrainingCycle(request, Context())
            reserve.assert_not_called(); lookup.assert_not_called(); train.assert_not_called()
            request.metadata.update(admission(release))
            previous = pb.ParameterUpdateStatus(found=True, base_version="v1", prompts_generated=32,
                ack=pb.ParameterUpdateAck(accepted=True, model_id="privoke-balanced", applied_version="v2"))
            with patch.object(retention, "load_release", return_value=release), \
                 patch.object(service, "_previous_update_for_fingerprint", return_value=previous) as lookup:
                self.assertTrue(service.RunUnderlyingTrainingCycle(request, Context()).accepted)
                lookup.assert_called_once()

    def test_direct_trainer_requires_independent_pin_before_runtime(self):
        release, teacher = manufactured_release()
        runtime = Mock()
        args = dict(model_id="privoke-balanced", new_examples=self.originals, heldout_examples=self.guard,
            config=self.config, runtime_client=runtime, taxonomy_dataset=self.dataset, benign_release=self.release,
            retention_release=release, expected_retention_manifest_sha256=release.sha256,
            training_scope="full_encoder", expected_objective=retention.GATE_OBJECTIVE,
            expected_optimizer=retention.GATE_POLICY, expected_candidate_eligibility=retention.ELIGIBILITY,
            expected_optimizer_config=canonical(CONFIG), expected_training_scope="full_encoder")
        with patch.object(retention, "teacher_identity", return_value=teacher):
            for pin in ("", "f" * 64):
                with patch.dict(os.environ, {"FUZZ_RETENTION_MANIFEST_SHA256": pin}), self.assertRaises(ValueError):
                    train_parameter_batch(**args)
            runtime.compute_underlying_gradients.assert_not_called()


if __name__ == "__main__":
    unittest.main()
