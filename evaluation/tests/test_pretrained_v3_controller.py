"""Synthetic controller/scorer mechanics; never dispatch physical fits or score fixtures."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "services/pretrained-v3/src")]
from privoke_eval import pretrained_v3_study as study
from privoke_eval import pretrained_v3_plan as plan
from privoke_eval import pretrained_v3_scoring as scoring
from privoke_model.v3_contract import parse

INITIAL = ROOT / "models/experiments/pretrained_v3_20261012/initials/efficient"


class PlanTests(unittest.TestCase):
    def test_exact_matrix_and_fixed_exports(self):
        cells = plan.matrix()
        self.assertEqual(len(cells), 18)
        self.assertEqual(len({c["id"] for c in cells}), 18)
        for tier in ("efficient", "balanced", "quality"):
            for seed in (42, 43, 44):
                self.assertEqual({c["scope"] for c in cells if c["tier"] == tier and c["seed"] == seed}, {"heads", "full_encoder"})

    def pilots(self):
        return [{"tier": tier, "scope": scope, "seed": seed, "seconds": 10., "cuda_peak_bytes": 1000,
                 "work": {"optimizer_steps": 2, "train_rows": 128, "microbatch_forward": 32, "microbatch_backward": 32}}
                for tier, scope, seed in plan.PILOTS]

    def test_resource_selection_ignores_guard_quality_and_fails_without_budget(self):
        pilots = self.pilots()
        choice = plan.resource_budget(pilots, max_total_seconds=14400, vram_capacity_bytes=10000)
        self.assertEqual(choice["steps"], 64)
        for row in pilots: row.update(initial_guard_joint=0, candidate_guard_joint=16, publication_status="applied")
        self.assertEqual(plan.resource_budget(pilots, max_total_seconds=14400, vram_capacity_bytes=10000), choice)
        with self.assertRaises(ValueError): plan.resource_budget(pilots[:2], max_total_seconds=14400, vram_capacity_bytes=10000)
        with self.assertRaises(ValueError): plan.resource_budget(pilots, max_total_seconds=1, vram_capacity_bytes=10000)
        pilots[0]["cuda_peak_bytes"] = 9500
        with self.assertRaises(ValueError): plan.resource_budget(pilots, max_total_seconds=14400, vram_capacity_bytes=10000)

    def test_reserved_fit_never_dispatches_again(self):
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            study.init_cell(cell, "efficient", "heads", 42)
            study.exclusive(cell / "host-dispatch.pb", b"reserved")
            with patch.object(study, "check_binding", return_value={}), patch.object(study, "channel") as channel:
                with self.assertRaisesRegex(ValueError, "reserved physical attempt"):
                    study.cycle(cell)
                channel.assert_not_called()

    def test_source_binding_detects_dirty_helper_and_equal_evidence_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            study.init_cell(cell, "efficient", "heads", 42)
            with patch.object(study, "source_identity", return_value="1" * 64), patch.object(study, "source_inventory", return_value={"dirty_helper.py": "2" * 64}):
                binding = study.bind_cell(cell, "sha256:" + "3" * 64)
                self.assertEqual(study.check_binding(cell), binding)
                with patch.object(study, "source_inventory", return_value={"dirty_helper.py": "4" * 64}):
                    with self.assertRaisesRegex(ValueError, "source bytes changed"): study.check_binding(cell)
            path = cell / "immutable.json"
            study.retain(path, b"same"); study.retain(path, b"same")
            with self.assertRaises(ValueError): study.retain(path, b"different")

    def test_unknown_outcome_only_queries_status_and_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            cell = Path(temporary)
            study.init_cell(cell, "efficient", "heads", 42)
            study.exclusive(cell / "host-dispatch.pb", study.parameters_pb2.FuzzerTrainingRequest(request_id="reserved").SerializeToString())
            checkpoint, runtime = Mock(), Mock()
            checkpoint.GetCommitStatus.return_value = study.pb.Receipt(status="unknown", request_id="reserved")
            runtime.GetFitStatus.return_value = study.pb.Receipt(status="started", request_id="reserved")
            connection = Mock(); connection.__enter__ = Mock(return_value=connection); connection.__exit__ = Mock(return_value=False)
            with patch.object(study, "check_binding", return_value={}), patch.object(study, "channel", return_value=connection), patch.object(study.rpc, "CheckpointServiceStub", return_value=checkpoint), patch.object(study.rpc, "TrainingServiceStub", return_value=runtime):
                with self.assertRaisesRegex(RuntimeError, "without replay"): study.reconcile(cell)
            runtime.FitCandidate.assert_not_called()
            checkpoint.CommitCandidate.assert_not_called()
            self.assertTrue((cell / "unknown-receipt.pb").exists())


class ScoringTests(unittest.TestCase):
    def manifest(self):
        return parse((INITIAL / "manifest.json").read_bytes())

    def response(self, *, error=False):
        manifest = self.manifest(); snapshot = "1" * 64
        metadata = {"model_id": manifest["model_id"], "model_version": snapshot, "artifact_checksum": snapshot,
                    "parameter_fingerprint": manifest["blob"], "parameter_count": str(manifest["parameter_count"]),
                    "backbone_sha256": manifest["source"]["weights_sha256"], "tokenizer_sha256": manifest["vocab"], "architecture": manifest["architecture"]}
        return study.runtime_pb2.AnalyzePromptResponse(action="BLOCK" if error else "ALLOW", error="overlength" if error else "",
            metadata={"privoke.semantic." + k: v for k, v in metadata.items()},
            classification=study.runtime_pb2.RuntimeClassification(sensitivity="S0", visibility="P0", packed=4),
            layers=[study.runtime_pb2.RuntimeLayerExecution(layer=4, status="error" if error else "ok", error="overlength" if error else "")])

    def test_identity_and_actual_layer_are_mandatory_including_errors(self):
        manifest = self.manifest()
        response = self.response(error=True)
        study.assert_semantic(response, manifest["model_id"], "1" * 64, manifest, allow_error=True)
        with self.assertRaises(ValueError): study.assert_semantic(response, manifest["model_id"], "1" * 64, manifest)
        response.metadata["privoke.semantic.tokenizer_sha256"] = "0" * 64
        with self.assertRaises(ValueError): study.assert_semantic(response, manifest["model_id"], "1" * 64, manifest, allow_error=True)
        response = self.response(); response.layers.add(layer=1, status="ok")
        with self.assertRaises(ValueError): study.assert_semantic(response, manifest["model_id"], "1" * 64, manifest)

    def test_allowed_sets_and_error_block_keep_requested_denominator(self):
        target = {"sensitivity": "S3", "visibility": "P0", "categories": ["IDENTITY"]}
        good = {"id": "1", "group_id": "g", "eligible": True, "status": "ok", "target": target,
                "classification": target, "allowed_actions": ["WARN", "BLOCK"], "action": "WARN"}
        failed = dict(good, id="2", status="error", action="BLOCK", classification=None)
        counts = scoring.summarize_records([good, failed], "context64")
        self.assertEqual(counts["action"], {"correct": 1, "denominator": 2})
        self.assertEqual(counts["joint"], {"correct": 1, "denominator": 2})
        self.assertEqual(counts["errors"], 1)
        paired = scoring.paired_difference([failed], [dict(failed, status="ok", classification=target)], "context64")
        self.assertEqual(paired["joint"]["improved"], 1)

    def test_scoring_records_actual_error_and_transport_without_dropping_rows(self):
        rows = [{"id": str(i), "group_id": "g", "text": "synthetic " + str(i), "classification": {"sensitivity": "S0", "visibility": "P0", "categories": []}, "allowed_actions": ["ALLOW"]} for i in range(3)]
        stub = Mock()
        def respond(request, **kwargs):
            if request.text.endswith("2"): raise RuntimeError("transport")
            response = self.response(error=request.text.endswith("1")); response.request_id = request.request_id
            return response
        stub.AnalyzePrompt.side_effect = respond
        with tempfile.TemporaryDirectory() as temporary, patch.object(scoring, "endpoint_rows", return_value=rows):
            output = Path(temporary)
            counts = scoring.score_endpoint(stub, self.manifest(), "1" * 64, "context64", {}, output)
            self.assertEqual(counts["requested"], 3); self.assertEqual(counts["errors"], 2)
            self.assertEqual(counts["joint"], {"correct": 1, "denominator": 3})
            records = scoring.audit_endpoint_records(self.manifest(), "1" * 64, "context64", {}, output)
            self.assertEqual([r["status"] for r in records], ["ok", "error", "transport_error"])
            scoring.score_endpoint(stub, self.manifest(), "1" * 64, "context64", {}, output)
            self.assertEqual(stub.AnalyzePrompt.call_count, 3)
            for call in stub.AnalyzePrompt.call_args_list:
                self.assertEqual(list(call.args[0].layers), [4])


if __name__ == "__main__": unittest.main()
