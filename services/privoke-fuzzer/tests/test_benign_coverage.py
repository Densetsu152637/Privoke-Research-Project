"""Nonmodel ordinary-benign selection, replay and actual wire publication contracts."""
import base64
import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_taxonomy_coverage import fixture, Context, Aborted
from test_anchor_rehearsal import admission
from config import FuzzerConfig
from fuzzer_service import FuzzerTrainingService
from prompt_generation import benign_coverage as benign, taxonomy_coverage as legacy
from prompt_generation.generator import generate_training_partition
from training.trainer import iter_training_examples, train_parameter_batch
from training.types import BatchTrainingConfig, BatchTrainingUpdate
from training.evidence import persist_cycle_evidence
from training.parameter_updates import emit_training_update
from training.full_adam_evidence import BENIGN_KEY, BENIGN_FIELDS, WEIGHT_FIELDS, GATE_KEY, project_benign_audit
from privoke_model.full_adam import POLICY, ELIGIBILITY, OBJECTIVE, CONFIG, canonical, TRACE_KEY
from privoke.v1 import parameters_pb2 as pb, runtime_pb2


def pool_fixture():
    rows = []
    for _, visibility in benign.SLOTS:
        for i in range(8):
            group = f"ordinary-benign-train-synthetic/{visibility}-{i}"
            target = {"sensitivity": "S0", "visibility": visibility, "categories": []}
            rows.append({"id": group + "/00", "text": f"Synthetic impersonal task {visibility} distinct word {i}",
                "weight": 1.0, "classification": target, "packed_classification": int(legacy._target(target).pack()),
                "metadata": {"group_id": group, "split": "train", "partition": "train", "source": benign.SOURCE,
                    "control": "ordinary_benign", "label_status": "assistant_provisional", "sensitivity_rationale": "Synthetic rationale",
                    "visibility_rationale": "Synthetic explicit audience", "category_rationale": "No personal facts"}})
    return {"schema": 1, "source": benign.SOURCE, "authorship": "Synthetic test fixture, not measured source data",
        "label_status": "assistant_provisional", "permanent_partition": "train", "fit_release": False, "rows": rows}


def proof_fixture(pool, dataset):
    # Manufactured admission fixture; this is never a real exclusion proof.
    return legacy.canonical_bytes({"schema": 1, "strategy": benign.STRATEGY, "status": "passed",
        "pool_sha256": pool.sha256, "dataset_sha256": dataset.sha256, "label_review_sha256": "a" * 64,
        "all_transform_variants": True, "transform_commitment_sha256": benign.transform_commitment(pool),
        "source_overlap_counts": {"ids": 0, "groups": 0, "texts": 0},
        "exclusion_validation": dataset.exclusion_validation, "fit_release": False})


class BenignCoverageTests(unittest.TestCase):
    def setUp(self):
        self.dataset_payload = legacy.canonical_bytes(fixture())
        self.dataset = legacy.load_snapshot(self.dataset_payload)
        pin = patch.object(benign, "DATASET_SHA256", self.dataset.sha256)
        pin.start(); self.addCleanup(pin.stop)
        content_pin = patch.object(benign, "LEGACY_SNAPSHOT_SHA256", benign.legacy_snapshot_commitment(self.dataset))
        content_pin.start(); self.addCleanup(content_pin.stop)
        self.pool = benign.load_pool_snapshot(legacy.canonical_bytes(pool_fixture()))
        self.proof = proof_fixture(self.pool, self.dataset)
        self.release = benign.load_snapshot(benign.prepare_manifest(self.pool, self.dataset, self.proof), self.pool, self.dataset, self.proof)
        self.config = BatchTrainingConfig(seed=42, learning_rate=.003)
        self.originals, self.guard = benign.generate_partition(self.dataset, self.release, 42)

    def test_four_in_place_substitutions_preserve_sensitive_targets_and_ordered_guard_bytes(self):
        identities = set()
        for seed in (0, 1, 42, 1337, 2026):
            old, old_guard = legacy.generate_partition(self.dataset, seed)
            rows, guard = benign.generate_partition(self.dataset, self.release, seed)
            self.assertEqual((rows, guard), benign.generate_partition(self.dataset, self.release, seed))
            self.assertEqual(guard, old_guard)
            self.assertEqual([r.SerializeToString(deterministic=True) for r in benign.guard_wire_rows(guard)],
                             [r.SerializeToString(deterministic=True) for r in benign.guard_wire_rows(old_guard)])
            changed = 0
            for index, (before, after) in enumerate(zip(old, rows)):
                self.assertEqual(before.expected_packed_classification, after.expected_packed_classification)
                self.assertEqual(after.weight, 1.0)
                self.assertEqual(after.metadata["generation_index"], str(index))
                self.assertEqual(after.metadata["taxonomy_strategy"], benign.STRATEGY)
                if before.text != after.text:
                    changed += 1
                    self.assertEqual(before.metadata["control"], "fiction")
                    self.assertIn((before.metadata["primary_category"], before.expected_classification.visibility().name), benign.SLOTS)
                    self.assertEqual(after.metadata["control"], "ordinary_benign")
                    self.assertNotIn("taxonomy_row_id", after.metadata)
                    self.assertNotIn("primary_category", after.metadata)
                    identities.add(after.metadata["benign_row_id"])
                else:
                    self.assertEqual({k: v for k, v in after.metadata.items() if k != "taxonomy_strategy"},
                                     {k: v for k, v in before.metadata.items() if k != "taxonomy_strategy"})
            self.assertEqual(changed, 4)
            self.assertEqual(legacy._counts(rows), legacy._counts(old))
            self.assertEqual(len({r.metadata["group_id"] for r in rows}), 14)
        self.assertGreater(len(identities), 4)
        expanded = list(iter_training_examples(self.originals, (), self.config))
        audit = benign.audit_expanded(self.dataset, self.release, self.originals, expanded, self.guard, self.config)
        self.assertEqual(audit["sampling_expanded_rows"], "64")
        self.assertEqual(audit["sampling_ordinary_benign_rows"], "4")
        self.assertEqual(audit["sampling_fiction_rows"], "4")

    def test_pool_provenance_targets_uniqueness_and_transform_collisions_fail_closed(self):
        for mutate in (lambda v: v.update(fit_release=True), lambda v: v.update(permanent_partition="guard"),
                lambda v: v["rows"][0]["metadata"].update(split="assessment"),
                lambda v: v["rows"][0].update(weight=2), lambda v: v["rows"][0].update(packed_classification=0),
                lambda v: v["rows"][0]["classification"].update(categories=["HEALTH"]),
                lambda v: v["rows"][0]["metadata"].update(sensitivity_rationale=""),
                lambda v: v["rows"][0].update(id="borrowed-old-id"), lambda v: v["rows"].pop()):
            value = pool_fixture(); mutate(value)
            with self.assertRaises((ValueError, KeyError, TypeError)):
                benign.load_pool_snapshot(legacy.canonical_bytes(value))
        value = pool_fixture(); value["rows"][1]["text"] = "Please review this prompt: " + value["rows"][0]["text"]
        with self.assertRaisesRegex(ValueError, "collision"):
            benign.load_pool_snapshot(legacy.canonical_bytes(value))
        with self.assertRaises(ValueError): benign.load_pool_snapshot(self.pool.payload + b" ")

    def test_snapshot_proof_target_guard_and_expansion_tampering_cannot_bypass_audits(self):
        with self.assertRaises(ValueError): benign.load_snapshot(self.release.payload + b" ", self.pool, self.dataset, self.proof)
        for mutate in (lambda p: p.update(all_transform_variants=False), lambda p: p.update(pool_sha256="b"*64),
                       lambda p: p.update(source_overlap_counts={"ids": 0,"groups":0,"texts":1}),
                       lambda p: p.update(label_review_sha256="not-a-hash")):
            proof = json.loads(self.proof); mutate(proof)
            with self.assertRaises(ValueError): benign.prepare_manifest(self.pool, self.dataset, legacy.canonical_bytes(proof))
        with self.assertRaises(ValueError): benign.validate_pool(replace(self.pool, rows=self.pool.rows[:-1]))
        for originals, guard in ((list(reversed(self.originals)), self.guard), (self.originals, list(reversed(self.guard))),
                ([replace(self.originals[0], weight=2), *self.originals[1:]], self.guard)):
            with self.assertRaises(ValueError): benign.audit_originals(self.dataset, self.release, originals, guard, 42)
        runtime = type("Runtime", (), {"compute_underlying_gradients": lambda *a, **kw: self.fail("no RPC")})()
        kwargs = dict(model_id="privoke-balanced", new_examples=self.originals, heldout_examples=self.guard,
            config=self.config, runtime_client=runtime, taxonomy_dataset=self.dataset, benign_release=self.release,
            training_scope="full_encoder", expected_objective=OBJECTIVE, expected_optimizer=POLICY,
            expected_candidate_eligibility=ELIGIBILITY, expected_optimizer_config=canonical(CONFIG), expected_training_scope="full_encoder")
        for changes in ({"training_scope":"heads"},{"benign_release":None},{"golden_examples":self.originals[:1]},
                        {"expected_optimizer":None},{"config":replace(self.config,new_example_weight=.5)},
                        {"config":replace(self.config,transformations_per_example=0)}):
            with self.assertRaises(ValueError): train_parameter_batch(**{**kwargs, **changes})
        with patch("training.trainer.random_pii_transform",return_value="outside approved transforms"), self.assertRaises(ValueError):
            train_parameter_batch(**kwargs)
        with self.assertRaises(ValueError): generate_training_partition(32,16,42,sampling_strategy=benign.STRATEGY,taxonomy_dataset=self.dataset)

    def test_same_sha_legacy_snapshot_tampering_rejects_before_selection_and_direct_runtime(self):
        train_index = next(i for i, r in enumerate(self.dataset.rows) if r.metadata["taxonomy_partition"] == "train")
        guard_index = next(i for i, r in enumerate(self.dataset.rows) if r.metadata["taxonomy_partition"] == "guard")
        def changed_row(index, **changes):
            return replace(self.dataset, rows=tuple(replace(r, **changes) if i == index else r
                                                    for i, r in enumerate(self.dataset.rows)))
        row = self.dataset.rows[train_index]
        variants = {
            "train_text": changed_row(train_index, text=row.text + " altered source"),
            "guard_text": changed_row(guard_index, text=self.dataset.rows[guard_index].text + " altered guard"),
            "target": changed_row(train_index, expected_classification=legacy._target(
                {"sensitivity": "S0", "visibility": "P0", "categories": []})),
            "weight": changed_row(train_index, weight=2.0),
            "metadata": changed_row(train_index, metadata={**row.metadata, "new_unpinned_field": "changed"}),
            "partitions": replace(self.dataset, partitions={**self.dataset.partitions, "new_group": "train"}),
            "exclusion_validation": replace(self.dataset, exclusion_validation={**self.dataset.exclusion_validation, "new": True}),
            "row_order": replace(self.dataset, rows=tuple(reversed(self.dataset.rows))),
        }
        from unittest.mock import Mock
        runtime = Mock()
        kwargs = dict(model_id="privoke-balanced", new_examples=self.originals, heldout_examples=self.guard,
            config=self.config, runtime_client=runtime, benign_release=self.release,
            training_scope="full_encoder", expected_objective=OBJECTIVE, expected_optimizer=POLICY,
            expected_candidate_eligibility=ELIGIBILITY, expected_optimizer_config=canonical(CONFIG), expected_training_scope="full_encoder")
        for name, altered in variants.items():
            with self.subTest(name=name):
                self.assertEqual(altered.sha256, self.dataset.sha256)
                with self.assertRaisesRegex(ValueError, "independently pinned"):
                    benign.generate_partition(altered, self.release, 42)
                with self.assertRaisesRegex(ValueError, "independently pinned"):
                    benign.prepare_manifest(self.pool, altered, self.proof)
                with self.assertRaisesRegex(ValueError, "independently pinned"):
                    benign.audit_originals(altered, self.release, self.originals, self.guard, 42)
                with self.assertRaisesRegex(ValueError, "independently pinned"):
                    train_parameter_batch(taxonomy_dataset=altered, **kwargs)
        runtime.compute_underlying_gradients.assert_not_called()
        benign.validate_release(self.release, self.dataset)
        self.assertEqual(json.loads(self.release.payload)["legacy_snapshot_commitment_sha256"], benign.LEGACY_SNAPSHOT_SHA256)

    def test_actual_publication_restores_exact_strings_and_binds_train_and_guard_wire(self):
        expanded = list(iter_training_examples(self.originals, (), self.config))
        audit = benign.audit_expanded(self.dataset,self.release,self.originals,expanded,self.guard,self.config)
        wire = runtime_pb2.ComputeSemanticGradientsRequest(request_id="req",model_id="privoke-balanced",
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC],examples=benign.training_wire_rows(expanded),
            heldout_examples=benign.guard_wire_rows(self.guard))
        gate = {"minimum_exact_match_rate":0}
        meta = {**audit,"contextual_training_optimizer":POLICY,"training_scope":"full_encoder",
            "base_parameter_fingerprint":"b"*64,TRACE_KEY:"immutable synthetic trace",GATE_KEY:canonical(gate)}
        metrics = {k:.000000123 for k in WEIGHT_FIELDS}
        evidence = {"request_protobuf_base64":base64.b64encode(wire.SerializeToString(deterministic=True)).decode()}
        update = BatchTrainingUpdate("privoke-balanced","v1",{}, {},metrics,meta,evidence)
        request = pb.FuzzerTrainingRequest(request_id="req",source_id="test")
        extra = {"request_source_id":"test","request_id":"req","training_request_fingerprint":"d"*64}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":directory}), \
             patch("training.full_adam_evidence.validate_candidate_route",return_value=True), \
             patch("training.full_adam_evidence.gate_summary",return_value=gate), \
             patch("fuzzer_service.validate_training_update"),patch("training.parameter_updates.emit_parameter_update") as emit:
            evidence["benign_audit"] = benign.persist_audit(self.release,audit)
            persist_cycle_evidence(request,update,"full_encoder",gate_passed=True)
            emit_training_update("mock","fuzzer",update,extra)
            actual = emit.call_args.args[1].metadata
            self.assertLessEqual(len(actual),64)
            self.assertLessEqual(max(len(v.encode()) for v in actual.values()),2048)
            self.assertEqual(json.loads(actual[BENIGN_KEY])["fields"],{k:audit[k] for k in BENIGN_FIELDS})
            self.assertEqual(actual[benign.POOL_KEY],self.pool.sha256)
            self.assertEqual(actual[benign.PROOF_KEY],self.release.proof_sha256)
            self.assertEqual(actual["contextual_sampling_strategy"],benign.STRATEGY)
            self.assertIn(TRACE_KEY,update.metadata)
            for kind in ("train","guard"):
                altered = runtime_pb2.ComputeSemanticGradientsRequest(); altered.CopyFrom(wire)
                (altered.examples if kind=="train" else altered.heldout_examples)[0].weight=2
                with self.assertRaises(ValueError): project_benign_audit(meta,altered)
            with self.assertRaises(ValueError): project_benign_audit({**meta,"sampling_unknown":"bad"},wire)


class BenignReplayTests(unittest.TestCase):
    setUp = BenignCoverageTests.setUp
    def test_pre_reservation_receipt_snapshot_and_fingerprint_contracts(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{"PRIVOKE_FUZZER_DUMP_DIR":directory}):
            root = Path(directory)
            for name,payload in (("dataset",self.dataset_payload),("pool",self.pool.payload),("proof",self.proof),("manifest",self.release.payload)):
                (root/name).write_bytes(payload)
            config = replace(FuzzerConfig.from_env(),model_id="privoke-balanced",prompt_dataset_path=str(root/"dataset"),
                benign_pool_path=str(root/"pool"),benign_manifest_path=str(root/"manifest"),
                benign_exclusion_proof_path=str(root/"proof"),underlying_training_learning_rate=.003)
            request = pb.FuzzerTrainingRequest(request_id="same",source_id="test",prompt_count=32,seed=42,model_id="privoke-balanced",
                metadata={**admission(),"contextual_sampling_strategy":benign.STRATEGY,"taxonomy_dataset_sha256":self.dataset.sha256,
                    benign.POOL_KEY:self.pool.sha256,benign.MANIFEST_KEY:self.release.sha256,benign.PROOF_KEY:self.release.proof_sha256})
            previous = pb.ParameterUpdateStatus(found=True,base_version="v1",prompts_generated=32,
                ack=pb.ParameterUpdateAck(accepted=True,model_id="privoke-balanced",applied_version="v2"))
            service=FuzzerTrainingService(config)
            with patch.object(service,"_previous_update_for_fingerprint",return_value=previous) as lookup,patch.object(service,"_train") as train:
                self.assertTrue(service.RunUnderlyingTrainingCycle(request,Context()).accepted)
                fingerprint=lookup.call_args.args[3]
                self.assertTrue(service.RunUnderlyingTrainingCycle(request,Context()).accepted)
                self.assertEqual(fingerprint,lookup.call_args.args[3]); train.assert_not_called()
            service=FuzzerTrainingService(replace(config,minimum_exact_match_rate=.1))
            with patch.object(service,"_previous_update_for_fingerprint") as lookup,self.assertRaisesRegex(Aborted,"different effective"):
                service.RunUnderlyingTrainingCycle(request,Context())
            lookup.assert_not_called()
            for mode in ("head","orphan","curriculum","missing_path",*benign.PIN_KEYS):
                bad=pb.FuzzerTrainingRequest(); bad.CopyFrom(request); changed=config
                if mode=="orphan": bad.metadata["contextual_sampling_strategy"]=legacy.STRATEGY
                elif mode=="curriculum": changed=replace(config,curriculum_manifest_path="forbidden")
                elif mode=="missing_path": changed=replace(config,benign_pool_path=None)
                elif mode in benign.PIN_KEYS: del bad.metadata[mode]
                service=FuzzerTrainingService(changed)
                with patch("fuzzer_service.reserve_training_request") as reserve,patch.object(service,"_previous_update_for_fingerprint") as lookup,self.assertRaises(Aborted):
                    (service.RunTrainingCycle if mode=="head" else service.RunUnderlyingTrainingCycle)(bad,Context())
                reserve.assert_not_called(); lookup.assert_not_called()
            (root/"manifest").write_bytes(self.release.payload+b" ")
            with patch("fuzzer_service.reserve_training_request") as reserve,patch.object(service,"_previous_update_for_fingerprint") as lookup,self.assertRaises(Aborted):
                service.RunUnderlyingTrainingCycle(request,Context())
            reserve.assert_not_called(); lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
