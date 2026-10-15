"""Synthetic controller/scorer mechanics; never dispatch physical fits or score fixtures."""
from __future__ import annotations

import copy
from contextlib import ExitStack, redirect_stderr
import io
import json
from pathlib import Path
import sys
import runpy
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
            self.assertEqual(len(list((cell / "status-observations/publication").glob("*.pb"))), 1)

    def test_unknown_publication_preserves_fit_progress_without_redispatch(self):
        for terminal_status in ("completed", "failed"):
            with self.subTest(terminal_status=terminal_status), tempfile.TemporaryDirectory() as temporary:
                cell = Path(temporary)
                study.init_cell(cell, "efficient", "heads", 42)
                study.exclusive(cell / "host-dispatch.pb", study.parameters_pb2.FuzzerTrainingRequest(request_id="reserved").SerializeToString())
                checkpoint, runtime = Mock(), Mock()
                receipts = [study.pb.Receipt(status="unknown", request_id="reserved", reason=reason) for reason in ("pending", "still pending")]
                statuses = [study.pb.Receipt(status=status, request_id="reserved") for status in ("started", terminal_status)]
                checkpoint.GetCommitStatus.side_effect = receipts
                runtime.GetFitStatus.side_effect = statuses
                connection = Mock(); connection.__enter__ = Mock(return_value=connection); connection.__exit__ = Mock(return_value=False)
                with patch.object(study, "check_binding", return_value={}), patch.object(study, "channel", return_value=connection), patch.object(study.rpc, "CheckpointServiceStub", return_value=checkpoint), patch.object(study.rpc, "TrainingServiceStub", return_value=runtime):
                    for status in ("started", terminal_status):
                        with self.assertRaisesRegex(RuntimeError, "Fit status=" + status): study.reconcile(cell)
                for kind, observations in (("publication", receipts), ("fit", statuses)):
                    paths = list((cell / "status-observations" / kind).glob("*.pb"))
                    self.assertEqual({path.read_bytes() for path in paths}, {value.SerializeToString(deterministic=True) for value in observations})
                runtime.FitCandidate.assert_not_called()
                checkpoint.CommitCandidate.assert_not_called()


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

    def test_nullable_visibility_hint_matches_wire_without_accepting_wrong_hint(self):
        for hint in (None, "absent", "P0"):
            with self.subTest(hint=hint), tempfile.TemporaryDirectory() as temporary:
                row = {"case_id": "synthetic", "family_id": "family", "text": "synthetic hazard",
                       "eligible": True, "allowed_actions": ["ALLOW"],
                       "classification": {"sensitivity": "S0", "visibility": "P0", "categories": []}}
                # Use the actual hazard fixture schema, without accessing real fixtures.
                row.update(target=row.pop("classification"), ambiguous=False)
                if hint != "absent": row["visibility_hint"] = hint
                stub = Mock()
                def respond(request, **kwargs):
                    response = self.response(); response.request_id = request.request_id; return response
                stub.AnalyzePrompt.side_effect = respond
                with patch.object(scoring, "endpoint_rows", return_value=[row]):
                    output = Path(temporary)
                    scoring.score_endpoint(stub, self.manifest(), "1" * 64, "hazard48", {}, output)
                    scoring.audit_endpoint_records(self.manifest(), "1" * 64, "hazard48", {}, output)
                    request_path = output / "rows/0000/request.pb"
                    request = study.runtime_pb2.AnalyzePromptRequest.FromString(request_path.read_bytes())
                    request.visibility_hint = "P1"
                    payload = request.SerializeToString(deterministic=True); request_path.write_bytes(payload)
                    record_path = output / "rows/0000/record.json"; record = json.loads(record_path.read_bytes())
                    record["request_sha256"] = study.digest(payload); record_path.write_bytes(study.canonical(record))
                    with self.assertRaisesRegex(ValueError, "stimulus/identity"):
                        scoring.audit_endpoint_records(self.manifest(), "1" * 64, "hazard48", {}, output)


class AmendmentTests(unittest.TestCase):
    """Small synthetic filesystem; no real study mutation, server or model RPC."""
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.directory = self.root / "study"; self.run = self.root / "run"
        self.old_sources = {}
        for name in (*plan.AUDIT_AMENDMENT_PATHS, "unchanged-server.py"):
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            old = ("old " + name).encode(); self.old_sources[name] = study.digest(old)
            study.exclusive(self.directory / "source-bytes" / study.digest(old), old)
            path.write_bytes(("new " + name).encode() if name in plan.AUDIT_AMENDMENT_PATHS else old)
        self.sources = lambda: {name: study.digest((self.root / name).read_bytes()) for name in self.old_sources}
        self.stack.enter_context(patch.object(plan, "source_closure", side_effect=self.sources))
        self.stack.enter_context(patch.object(plan, "RUN", self.run))
        self.stack.enter_context(patch.object(study, "host_environment", return_value={"python": "synthetic"}))
        manifest = (INITIAL / "manifest.json").read_bytes()
        originals = {}
        for tier in ("efficient", "balanced", "quality"):
            study.exclusive(self.run / "initials" / tier / "manifest.json", manifest)
            study.exclusive(self.run / "initials" / tier / "model.safetensors", b"synthetic original")
            originals[tier] = {"manifest": study.digest(manifest), "blob": study.digest(b"synthetic original")}
        endpoints = {"hazard48": {"rows": 1, "eligible": 1, "role": "synthetic"}}
        self.stack.enter_context(patch.object(plan, "ENDPOINTS", endpoints))
        self.protocol = {"study_id": plan.STUDY_ID, "cells": plan.matrix(), "policy": {"steps": 256},
                         "source_files": self.old_sources, "source_closure": study.digest(study.canonical(self.old_sources)),
                         "host_environment": {"python": "synthetic"}, "endpoints": endpoints, "originals": originals,
                         "server_source_closure": "s" * 64, "image_id": "sha256:" + "i" * 64,
                         "schedules": {str(seed): {"source_commitment": str(seed)} for seed in plan.SEEDS}}
        executions = {}
        for cell in self.protocol["cells"]:
            path = self.run / "cells" / cell["id"]; cell["directory"] = str(path)
            binding = {**cell, "original_manifest": originals[cell["tier"]]["manifest"]}
            study.exclusive(path / "cell.json", study.canonical(binding))
            study.exclusive(path / "policy.json", study.canonical(self.protocol["policy"]))
            executions[str(path)] = {"image_id": self.protocol["image_id"], "source_commitment": str(cell["seed"])}
            for name in ("terminal-evidence.json", "terminal-candidate.safetensors", "host-dispatch.pb", "host-receipt.pb", "summary.json"):
                study.exclusive(path / name, b"synthetic " + name.encode())
            study.exclusive(path / "terminal-manifest.json", manifest)
        self.stack.enter_context(patch.object(study, "check_binding", side_effect=lambda p: executions[str(p)]))
        study.exclusive(self.directory / "protocol.json", study.canonical(self.protocol))
        self.protocol_sha = study.digest((self.directory / "protocol.json").read_bytes())
        study.exclusive(self.directory / "fit-completion.json", study.canonical({"completed": [c["id"] for c in self.protocol["cells"]], "physical_attempts": 18}))
        self.candidates = [{"name": c["id"], "directory": c["directory"], "snapshot": study.digest(manifest)} for c in self.protocol["cells"]]
        self.candidates += [{"name": "original-" + tier, "snapshot": study.digest(manifest)} for tier in originals]
        self.stack.enter_context(patch.object(plan, "candidates_for_scoring", return_value=self.candidates))
        self.stack.enter_context(patch.object(plan, "audit_endpoint_records", return_value=[]))
        study.exclusive(self.directory / "endpoint-candidates.json", study.canonical(self.candidates))
        for name in plan.AMENDMENT_PRIOR_NAMES: self.complete(name)
        self.amendment = self.directory / "amendment.json"
        inventory = plan._endpoint_inventory(self.directory, self.protocol, plan.AMENDMENT_PRIOR_NAMES)
        bindings = plan._fit_amendment_bindings(self.directory, self.protocol)
        self.prior_evidence = self.directory / "pre-amendment-evidence.json"
        study.exclusive(self.prior_evidence, study.canonical(dict(protocol_sha256=self.protocol_sha,
            source_closure=self.protocol["source_closure"], fit_completion_sha256=bindings["fit_completion_sha256"],
            terminal_artifacts={str(Path(c["directory"]) / name): sha for c in self.protocol["cells"]
                                for name, sha in bindings["terminal_artifacts"][c["id"]].items() if name != "summary.json"},
            endpoint_files=inventory["files"], endpoint_inventory_sha256=study.digest(study.canonical(inventory["files"])))))
        self.record = plan.create_audit_amendment(self.directory, self.amendment, expected_protocol_sha256=self.protocol_sha, prior_evidence=self.prior_evidence)

    def complete(self, name):
        output = self.directory / "endpoints" / name
        target = {"sensitivity": "S0", "visibility": "P0", "categories": []}
        row = {"id": "synthetic", "group_id": "group", "eligible": True, "status": "ok",
               "target": target, "classification": target, "allowed_actions": ["ALLOW"], "action": "ALLOW"}
        for filename, payload in (("record.json", study.canonical(row)), ("request.pb", b"request"), ("response.pb", b"response")):
            study.exclusive(output / "hazard48/rows/0000" / filename, payload)
        summary = scoring.summarize_records([row], "hazard48")
        study.exclusive(output / "hazard48/summary.json", study.canonical(summary))
        study.exclusive(output / "complete.json", study.canonical({"snapshot": self.candidates[0]["snapshot"], "summaries": {"hazard48": summary}}))

    def test_default_strict_and_amended_scoring_only_changes_readiness(self):
        with self.assertRaisesRegex(ValueError, "Frozen source"):
            plan.validate_plan(self.directory)
        self.assertEqual(plan._postfit_plan(self.directory, self.amendment), self.protocol)
        with patch.object(study, "start", side_effect=RuntimeError("synthetic startup boundary")) as start, patch.object(plan, "stop"), patch.object(study, "channel") as channel, patch.object(study, "cycle") as cycle:
            with self.assertRaisesRegex(RuntimeError, "synthetic startup boundary"):
                plan.score_plan(self.directory, audit_amendment=self.amendment)
            self.assertEqual(start.call_args.kwargs["readiness_timeout"], 180)
            self.assertEqual(Path(start.call_args.args[0]).name, "quality-full_encoder-42")
            channel.assert_not_called(); cycle.assert_not_called()
        for phase in ("run-plan", "freeze-plan", "validate-plan", "cycle"):
            with self.subTest(phase=phase), patch.object(sys, "argv", ["cli", phase, "--audit-amendment", str(self.amendment)]), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error: runpy.run_path(str(ROOT / "evaluation/run-pretrained-v3-study.py"), run_name="__main__")
                self.assertEqual(error.exception.code, 2)

    def test_amendment_rejects_paths_hashes_and_captured_original_source_changes(self):
        mutations = [lambda r: r["changes"].update({"unknown.py": {"old": "0", "new": "1"}}),
                     lambda r: r["changes"][plan.AUDIT_AMENDMENT_PATHS[0]].update(old="0" * 64),
                     lambda r: r["changes"][plan.AUDIT_AMENDMENT_PATHS[0]].update(new="0" * 64)]
        for change in mutations:
            changed = copy.deepcopy(self.record); change(changed); self.amendment.write_bytes(study.canonical(changed))
            with self.assertRaises(ValueError): plan._postfit_plan(self.directory, self.amendment)
        self.amendment.write_bytes(study.canonical(self.record))
        (self.root / "unchanged-server.py").write_bytes(b"changed server")
        with self.assertRaisesRegex(ValueError, "Frozen source"): plan._postfit_plan(self.directory, self.amendment)
        (self.root / "unchanged-server.py").write_bytes(b"old unchanged-server.py")
        (self.directory / "source-bytes" / next(iter(self.old_sources.values()))).write_bytes(b"forged captured source")
        with self.assertRaisesRegex(ValueError, "Captured original"): plan._postfit_plan(self.directory, self.amendment)

    def test_amendment_rejects_environment_policy_and_terminal_mutation(self):
        with patch.object(study, "host_environment", return_value={"python": "changed"}):
            with self.assertRaisesRegex(ValueError, "Frozen source/environment"): plan._postfit_plan(self.directory, self.amendment)
        path = Path(self.protocol["cells"][0]["directory"]) / "policy.json"; original = path.read_bytes(); path.write_bytes(study.canonical({"steps": 128}))
        with self.assertRaisesRegex(ValueError, "Frozen cell binding"): plan._postfit_plan(self.directory, self.amendment)
        path.write_bytes(original)
        path = path.parent / "terminal-candidate.safetensors"; path.write_bytes(b"tampered candidate")
        with self.assertRaisesRegex(ValueError, "terminal/source bindings"): plan._postfit_plan(self.directory, self.amendment)

    def test_prior_case_evidence_is_exact_and_immutable(self):
        path = self.directory / "endpoints" / plan.AMENDMENT_PRIOR_NAMES[0] / "hazard48/rows/0000/response.pb"
        original = path.read_bytes(); path.unlink()
        with self.assertRaisesRegex(ValueError, "Missing/extraneous"): plan._postfit_plan(self.directory, self.amendment)
        path.write_bytes(original); path.write_bytes(b"changed response")
        with self.assertRaisesRegex(ValueError, "Prior scoring evidence"): plan._postfit_plan(self.directory, self.amendment)
        path.write_bytes(original)
        extra = path.parent.parent / "0001/request.pb"; study.exclusive(extra, b"incomplete reserved request")
        with self.assertRaisesRegex(ValueError, "Missing/extraneous"): plan._postfit_plan(self.directory, self.amendment)

    def test_creator_rejects_new_reserved_case_and_wrong_protocol(self):
        with self.assertRaisesRegex(ValueError, "accepted original protocol"):
            plan.create_audit_amendment(self.directory, self.directory / "other.json", expected_protocol_sha256="0" * 64, prior_evidence=self.prior_evidence)
        output = self.directory / "endpoints/quality-full_encoder-42/hazard48/rows/0000/request.pb"
        study.exclusive(output, b"reserved")
        with self.assertRaisesRegex(ValueError, "Unexpected prior endpoint"):
            plan.create_audit_amendment(self.directory, self.directory / "other.json", expected_protocol_sha256=self.protocol_sha, prior_evidence=self.prior_evidence)

    def test_export_requires_complete_matching_analysis_provenance(self):
        study.exclusive(self.directory / "analysis.json", b'{}')
        with self.assertRaises(FileNotFoundError): plan.export_fixed_models(self.directory, audit_amendment=self.amendment)
        for candidate in self.candidates:
            if candidate["name"] not in plan.AMENDMENT_PRIOR_NAMES: self.complete(candidate["name"])
        provenance = plan._analysis_provenance(self.directory, self.protocol, self.amendment)
        self.assertEqual(provenance["complete_models"], 21)
        wrong = dict(provenance, audit_amendment_sha256="0" * 64)
        study.exclusive(self.directory / "postfit-analysis-provenance.json", study.canonical(wrong))
        with self.assertRaisesRegex(ValueError, "matching complete amended analysis provenance"):
            plan.export_fixed_models(self.directory, audit_amendment=self.amendment)

    def test_start_default_and_explicit_readiness_timeout_reach_health(self):
        cell = Path(self.protocol["cells"][0]["directory"])
        def compose(path, *args):
            return Mock(returncode=0, stdout="checkpoint runtime fuzzer" if args == ("config", "--services") else "", stderr="")
        for timeout in (60, 180):
            with patch.object(study, "compose", side_effect=compose), patch.object(study, "health", side_effect=RuntimeError("health boundary")) as health:
                with self.assertRaisesRegex(RuntimeError, "health boundary"):
                    if timeout == 60: study.start(cell, output=self.root / "startup60", roles=("runtime",))
                    else: study.start(cell, output=self.root / "startup180", roles=("runtime",), readiness_timeout=180)
                health.assert_called_once_with("runtime", timeout=timeout)


if __name__ == "__main__": unittest.main()
