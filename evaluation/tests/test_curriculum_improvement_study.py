"""Synthetic contract checks for matrix isolation, audit and paired inference."""
import copy
from contextlib import closing
import importlib.util
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from privoke_eval import curriculum_improvement_evidence as evidence
from privoke_eval import curriculum_improvement_study as study
from privoke_eval import synthetic_curriculum as synthetic
from privoke.v1 import parameters_pb2 as PP
from privoke.v1 import runtime_pb2 as RP
from privoke_eval import curriculum_improvement_report as report

FUZZER = study.ROOT / "services/privoke-fuzzer/src"
sys.path.insert(0, str(FUZZER))
from prompt_generation.curriculum import Curriculum, reserve_batch


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="improvement-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def row(self, key="a", action="ALLOW", target="ALLOW"):
        return {"id": key, "group_id": "family-" + key, "status": "ok", "quantitative": True,
                "target": {"sensitivity": "S0", "visibility": "PU", "categories": []},
                "allowed_actions": [target], "action": action,
                "classification": {"sensitivity": "S0", "visibility": "PU", "categories": []}}

    def test_complete_matrix_has_unique_storage_and_stable_sampler_seeds(self):
        cells = study.matrix("privoke-improve-test")
        self.assertEqual((len(cells), len({c["project"] for c in cells}), sum(c["kind"] == "live" for c in cells)), (63, 63, 45))
        self.assertTrue(all(c["sampler_seed"] == 0 for c in cells if c.get("policy") == "deterministic_v1"))
        self.assertEqual({c["sampler_seed"] for c in cells if c.get("policy") == "seeded_family_v1"}, {42, 43, 44})

    def test_contextual_targets_are_not_binary_annotation_presence(self):
        before, after = self.row(), self.row()
        after["classification"] = {"sensitivity": "S3", "visibility": "P2", "categories": ["HEALTH"]}
        metric = evidence.contextual_metrics([after])
        self.assertEqual(metric["joint_accuracy"], 0)
        self.assertEqual(metric["action_accuracy"], 1)
        change = evidence.contextual_changes([before], [after], iterations=10)
        self.assertEqual(change["changes"]["joint_accuracy"]["estimate"], -1)

    def test_casewise_harms_cannot_cancel_and_worsened_existing_failure_counts(self):
        before = [self.row("a", "ALLOW"), self.row("b", "BLOCK", "ALLOW"), self.row("c", "WARN", "BLOCK")]
        after = [self.row("a", "WARN"), self.row("b", "ALLOW", "ALLOW"), self.row("c", "ALLOW", "BLOCK")]
        harm = evidence.restriction_harms(before, after)
        self.assertEqual((harm["newly_incorrect_actions"], harm["new_over_restrictions"], harm["new_under_restrictions"]), (1, 1, 1))
        self.assertFalse(harm["passed"])

    def test_ambiguous_cases_remain_descriptive(self):
        a, b = self.row(), self.row(action="BLOCK")
        a["quantitative"] = b["quantitative"] = False
        self.assertTrue(evidence.restriction_harms([a], [b])["passed"])

    def test_pairing_rejects_different_truth_groups_duplicate_ids_or_errors(self):
        before = [self.row()]
        for change in ("group_id", "target", "allowed_actions", "status"):
            after = copy.deepcopy(before)
            after[0][change] = "changed"
            with self.subTest(change=change), self.assertRaises(ValueError):
                evidence.matched(before, after)
        with self.assertRaises(ValueError):
            evidence.matched(before + before, before + before)

    def test_fixture_explicit_allow_only_is_authoritative(self):
        identity = {"model_id": "privoke-efficient"}
        class Client:
            def analyze(self, *args):
                return {"identities": [identity], "raw": {"layers": [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok"}], "classification": {"sensitivity": "S1", "visibility": "P0", "categories": ["IDENTITY"]}, "action": "WARN"}}
            def snapshot(self, *args):
                return {"identity": identity}
        fixture = {"case_id": "clean", "family_id": "public_bio", "text": "Synthetic public biography", "ambiguous": False,
                   "expected_sensitivity": "S1", "expected_visibility": "P0", "expected_categories": ["IDENTITY"],
                   "minimum_action": "ALLOW", "expected_action": "ALLOW", "allowed_actions": ["ALLOW"]}
        report = study.contextual_rows(Client(), [fixture], "privoke-efficient", identity, "test", True)
        row = report["semantic"]["predictions"][0]
        self.assertEqual(row["allowed_actions"], ["ALLOW"])
        self.assertEqual(row["group_id"], "public_bio")
        self.assertEqual(report["semantic"]["metrics"]["over_restriction_rate"], 1)

    def test_rpc_forwards_visibility_hint_and_omits_legacy_hint(self):
        requests = []
        def analyze(request, **kwargs):
            requests.append(request)
            return RP.AnalyzePromptResponse(request_id=request.request_id, action="ALLOW",
                classification=RP.RuntimeClassification(sensitivity="S0", visibility="PU"))
        client = study.continual.RpcClient.__new__(study.continual.RpcClient)
        client.runtime = SimpleNamespace(AnalyzePrompt=analyze)
        client.analyze({"text": "synthetic", "visibility_hint": "P2"}, "privoke-efficient", "pipeline", "a")
        client.analyze({"text": "synthetic"}, "privoke-efficient", "pipeline", "b")
        self.assertEqual(requests[0].visibility_hint, "P2")
        self.assertNotIn("visibility_hint", dict((d.name, v) for d, v in requests[1].ListFields()))

    def test_effective_settings_poisoning_fails_before_first_rpc(self):
        cell = {"project": "test", "profile": "efficient", "replay_weight": .35}
        values = {"fuzzer": {"MODEL_ID": "privoke-efficient", "FUZZ_TRAINING_LEARNING_RATE": "0.003", "FUZZ_TRAINING_MAX_GRADIENT": "0.05",
                            "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE": "0", "FUZZ_HELDOUT_PROMPT_COUNT": "16", "FUZZ_CURRICULUM_REPLAY_FRACTION": "0.25",
                            "FUZZ_TRAINING_REPLAY_WEIGHT": "0.35", "FUZZ_CURRICULUM_MANIFEST_PATH": "/curriculum/manifest.json", "FUZZ_MAX_CONCURRENT_CYCLES": "1"},
                  "updater": {"MODEL_ID": "privoke-efficient", "FUZZER_PROMPT_COUNT": "0"},
                  "runtime": {"PRIVOKE_MODEL_DEVICE": "cpu", "MODEL_STREAMING_CACHE_TTL_SECONDS": "1", "OMP_NUM_THREADS": "1", "MKL_NUM_THREADS": "1", "TELEMETRY_ENABLED": "false"}}
        protocol = {"images": {service: "synthetic-image" for service in study.SERVICES}}
        operations = {"containers": {"test-" + suffix: {"image_id": "synthetic-image", "environment": values.get(suffix, {})} for suffix in study.SUFFIXES}}
        study.validate_operations(operations, cell, protocol)
        for key in values["fuzzer"]:
            changed = copy.deepcopy(operations)
            changed["containers"]["test-fuzzer"]["environment"][key] = "poison"
            with self.subTest(key=key), self.assertRaises(ValueError):
                study.validate_operations(changed, cell, protocol)

    def test_offline_encoder_change_recomputed_from_artifact_values(self):
        a = {"parameters": {"token_embedding": {"shape": [1], "values": [0.]}, "head.bias": {"shape": [1], "values": [0.]}}}
        b = copy.deepcopy(a)
        b["parameters"]["token_embedding"]["values"] = [.25]
        self.assertEqual(report.offline_tensor_changes(a, b)["token_embedding"], {"changed_values": 1, "maximum_absolute_delta": .25})

    def test_durable_publication_payload_and_rejected_receipt_audit(self):
        directory = self.root / "parameter-update-data"
        directory.mkdir()
        metadata = {"request_id": "r1", "request_source_id": "controller", "training_request_fingerprint": "f" * 64}
        update = PP.ParameterUpdateRequest(source_id="server-fuzzer", model_id="privoke-efficient", base_version="v0",
                    gradients=[{"name": "head.bias", "shape": [1], "values": [.1]}], metadata=metadata)
        # JSON audit tensors are the exact float32 protobuf transport values.
        row = {"source_id": update.source_id, "model_id": update.model_id, "base_version": "v0", "applied_version": "v1", "artifact_checksum": "c",
               "gradients": [{"name": p.name, "shape": list(p.shape), "values": list(p.values)} for p in update.gradients], "metadata": metadata}
        key = evidence.digest(["server-fuzzer", "controller", "r1"])
        receipt = {"key": key, "payload_digest": hashlib.sha256(update.SerializeToString(deterministic=True)).hexdigest(), "request_fingerprint": "f" * 64,
                   "model_id": "privoke-efficient", "base_version": "v0", "applied_version": "v1", "prompts_generated": 256}
        audit_path = directory / "updates.jsonl"
        audit_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        db_path = directory / "updates.jsonl.receipts.sqlite3"
        with closing(sqlite3.connect(db_path)) as db:
            db.execute("CREATE TABLE update_receipts (key TEXT PRIMARY KEY, receipt TEXT)")
            db.execute("INSERT INTO update_receipts VALUES (?, ?)", (key, json.dumps(receipt)))
            db.commit()
        attempt = {"request": {"source_id": "controller", "request_id": "r1", "model_id": "privoke-efficient"},
                   "response": {"accepted": True, "base_version": "v0", "applied_version": "v1", "metadata": {"replayed": "true"}}, "identity": {"artifact_checksum": "c"}}
        published = {"metadata": {"last_update_receipt": json.dumps(receipt)}}
        result = report.durable_publications(self.root, [attempt], published, "server-fuzzer")
        self.assertEqual(result["replayed_acknowledgments_reconciled_from_durable_metadata"], 1)
        row["gradients"][0]["values"][0] += .1
        audit_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            report.durable_publications(self.root, [attempt], published, "server-fuzzer")
        audit_path.write_text(json.dumps({**row, "gradients": [{"name": p.name, "shape": list(p.shape), "values": list(p.values)} for p in update.gradients]}) + "\n", encoding="utf-8")
        with closing(sqlite3.connect(db_path)) as db:
            db.execute("INSERT INTO update_receipts VALUES (?, ?)", ("rejected-extra", json.dumps(receipt)))
            db.commit()
        with self.assertRaises(ValueError):
            report.durable_publications(self.root, [attempt], published, "server-fuzzer")

    def test_exact_baseline_rejects_changed_values_or_checksum(self):
        artifact = {"model_id": "privoke-efficient", "version": "base", "checksum": "checked",
                    "parameters": {"head": {"shape": [1], "values": [.123456789]}}}
        snapshot = {"identity": study.artifact_identity(artifact), "parameters": {"head": {"shape": [1], "values": [study.float32(.123456789)]}}}
        study.assert_baseline(snapshot, artifact)
        changed = copy.deepcopy(snapshot)
        changed["parameters"]["head"]["values"][0] += .01
        with self.assertRaises(ValueError):
            study.assert_baseline(changed, artifact)
        snapshot["identity"]["artifact_checksum"] = "wrong"
        with self.assertRaises(ValueError):
            study.assert_baseline(snapshot, artifact)

    def test_source_and_protocol_drift_rejected_before_execution(self):
        protocol = {"schema_version": 2, "evaluation_layers": ["semantic"], "imports": {}, "import_manifest_sha256": "synthetic", "source_files": {"fixture.py": "old"}}
        study.continual.write_json(self.root / "protocol.json", protocol)
        study.continual.write_json(self.root / "supervisor.json", {"protocol_sha256": study.continual.sha(self.root / "protocol.json")})
        with patch.object(study, "verify_import_manifest"), patch.object(study.continual, "sha", return_value="synthetic"), patch.object(study, "source_inventory", return_value={"fixture.py": "new"}), self.assertRaisesRegex(ValueError, "source"):
            study.verify_freeze(self.root)
        with patch.object(study, "command", side_effect=["commit\n", " M fixture.py\n"]), self.assertRaisesRegex(ValueError, "Commit"):
            study.require_committed_sources({"fixture.py": "old"})

    def test_unknown_request_resumes_exact_controller_pending_manifest(self):
        directory = self.root / "cell"
        destination = directory / "controller"
        destination.mkdir(parents=True)
        pending = {"request_id": "exact-unknown", "seed": 1337}
        study.continual.write_json(destination / "run-manifest.json", {"status": "interrupted", "models": {"privoke-efficient": {"pending": pending}}})
        cell = {"id": "efficient-c-42", "profile": "efficient", "policy": "seeded_family_v1", "sampler_seed": 42, "curriculum": "current"}
        protocol = {"inputs": {"dataset": {"path": "development.jsonl"}, "current": {"manifest": "manifest.json"}}}
        class Client:
            def snapshot(self, *args):
                return {"identity": {}}
        with patch.object(study, "load_artifact", return_value={}), patch.object(study, "artifact_identity", return_value={}), \
             patch.object(study, "command") as command, patch.object(study, "verify_baseline_endpoints"), patch.object(study, "endpoints"):
            study.run_live(self.root, protocol, {}, cell, {"status": "training"}, directory, {}, Client(), directory / "operations.json", directory / "log")
        self.assertIn("--resume", command.call_args.args[0])
        self.assertEqual(study.continual.read_json(destination / "run-manifest.json")["models"]["privoke-efficient"]["pending"], pending)

    def test_archive_detects_changed_evidence(self):
        (self.root / "evidence.json").write_text("original", encoding="utf-8")
        commitment = study.archive_cell(self.root)
        study.verify_archive(self.root, commitment)
        (self.root / "evidence.json").write_text("changed", encoding="utf-8")
        with self.assertRaises(ValueError):
            study.verify_archive(self.root, commitment)

    def allocations(self):
        resource = study.continual.read_json(study.ROOT / "evaluation/datasets/synthetic-teacher-templates.json")
        pools = synthetic.build_curriculum(resource)
        curriculum = Curriculum("synthetic", "f" * 64, {role: tuple(rows) for role, rows in pools.items()})
        lookup = {r["id"]: (role, r) for role, rows in pools.items() for r in rows}
        path = self.root / "allocation.sqlite3"
        rounds = []
        for index in range(3):
            request = {"source_id": "synthetic", "model_id": "privoke-efficient", "request_id": f"test-{index}", "prompt_count": 256,
                       "metadata": {"curriculum_sampler_policy": "seeded_family_v1", "curriculum_sampler_seed": "42"}}
            batch = reserve_batch(curriculum, str(path), PP.FuzzerTrainingRequest(**request), 256)
            rounds.append({"request": request, "response": {"accepted": index != 1, "metadata": {**batch.audit, "curriculum_replay_weight": "0.35"}}})
        return path, rounds, lookup

    def test_multi_round_allocation_audit_including_rejected_and_epochs(self):
        path, rounds, lookup = self.allocations()
        result = evidence.audit_allocations(path, rounds, lookup, "seeded_family_v1", 42, .35)
        self.assertEqual((result["reservations"], result["presentations"]), (3, 768))
        self.assertGreater(result["unique_families"], 32)

    def test_replay_only_ack_uses_exact_durable_metadata_without_changing_raw(self):
        path, rounds, lookup = self.allocations()
        record = rounds[0]
        original = copy.deepcopy(record["response"]["metadata"])
        record["response"]["metadata"] = {"replayed": "true"}
        request = record["request"]
        durable = {(request["source_id"], request["request_id"]): original}
        result = evidence.audit_allocations(path, rounds, lookup, "seeded_family_v1", 42, .35, durable)
        self.assertEqual(result["reservations"], 3)
        self.assertEqual(record["response"]["metadata"], {"replayed": "true"})
        with self.assertRaises(ValueError):
            evidence.audit_allocations(path, rounds, lookup, "seeded_family_v1", 42, .35)

    def test_poisoned_rejected_allocation_order_or_cursor_fails(self):
        path, rounds, lookup = self.allocations()
        with closing(sqlite3.connect(path)) as db:
            identity, raw = db.execute("SELECT identity, allocation FROM batches ORDER BY identity LIMIT 1 OFFSET 1").fetchone()
            original = json.loads(raw)
            for poison in ("order", "cursor"):
                allocation = copy.deepcopy(original)
                if poison == "order":
                    allocation["train"][0], allocation["train"][1] = allocation["train"][1], allocation["train"][0]
                else:
                    allocation["positions"]["grammar:False"]["stop"] += 1
                db.execute("UPDATE batches SET allocation=? WHERE identity=?", (json.dumps(allocation), identity))
                db.commit()
                with self.subTest(poison=poison), self.assertRaises(ValueError):
                    evidence.audit_allocations(path, rounds, lookup, "seeded_family_v1", 42, .35)
            db.execute("UPDATE batches SET allocation=? WHERE identity=?", (raw, identity))


if __name__ == "__main__":
    unittest.main()
