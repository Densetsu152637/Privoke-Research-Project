"""Taxonomy exposure, immutable replay and actual semantic execution boundaries."""
import copy
import grpc
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SERVICE = Path(__file__).resolve().parents[1]
for path in (SERVICE / "src", SERVICE / "generated", SERVICE.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))

from config import FuzzerConfig
from fuzzer_service import FuzzerTrainingService, _training_request_fingerprint
from privoke.v1 import parameters_pb2, runtime_pb2
from privoke_contracts.classification import Category
from prompt_generation.generator import generate_training_partition, CONTEXTUAL_SAMPLING_STRATEGY_KEY
from prompt_generation import taxonomy_coverage as taxonomy
from runtime_client import RuntimeAnalysisError
from test_dual_runtime_contract import contract
from training.trainer import train_parameter_batch, iter_training_examples
from training.types import BatchTrainingConfig, BatchTrainingExample


def fixture():
    rows = []
    for category in taxonomy.AUDIENCES:
        for family in range(4):
            group = f"synthetic-{category}-{family}"
            categories = [category]
            if category == "CHILD" or category == "SEXUAL" and family == 1:
                categories.append("THIRD_PARTY")
            if category == "THIRD_PARTY":
                categories = ["FINANCIAL", "THIRD_PARTY"]
            categories = [c for c in Category.__members__ if c in categories]
            for slot in range(16):
                control = "actual" if slot < 6 else "fiction" if slot < 12 else "mixed" if slot == 12 else "hypothetical_real_premise" if slot == 13 else "mild"
                audience = ("P0", "P1", "P2", "P3", "P4", "PU")[slot % 6] if slot < 12 else "P4" if slot == 13 else "P1" if slot == 15 else "PU"
                severity = "S2" if category in ("FINANCIAL", "LOCATION", "THIRD_PARTY") else "S3"
                target = {"sensitivity": "S0" if control == "fiction" else "S1" if control == "mild" else severity,
                          "visibility": audience, "categories": [] if control in ("fiction", "mild") else categories}
                rows.append({"id": f"{group}/{slot}", "text": f"Synthetic John Doe {group} independent slot {slot}",
                    "classification": target, "packed_classification": int(taxonomy._target(target).pack()),
                    "metadata": {"group_id": group, "family_id": group, "primary_category": category,
                        "split": "train", "taxonomy_partition": "train" if family < 2 else "guard",
                        "label_status": "assistant_provisional", "target_convention": "asserted_personal_disclosure_v1",
                        "control": control, "annotations": {"categories": {c: {} for c in target["categories"]}}}})
    return {"schema_version": 1, "strategy": taxonomy.STRATEGY,
        "policy": json.loads(taxonomy.canonical_bytes(taxonomy.policy_contract())), "rows": rows,
        "provenance": {"source_sha256": taxonomy.SOURCE_SHA256, "renderer_sha256": taxonomy.RENDERER_SHA256,
            "source_split": "historical_train", "label_status": "assistant_provisional",
            "partition_recipe": taxonomy.PARTITION_RECIPE,
            "exclusion_validation": {"status": "passed", "all_transform_variants": True}}}


class Aborted(Exception):
    pass


class Context:
    def abort(self, code, message):
        raise Aborted(f"{code.name}: {message}")

    def is_active(self):
        return True


class TaxonomyCoverageTests(unittest.TestCase):
    def setUp(self):
        self.release = fixture()
        self.dataset = taxonomy.load_snapshot(taxonomy.canonical_bytes(self.release))

    def test_exact_slots_determinism_permanent_partitions_and_both_sexual_families(self):
        selected_sexual = set()
        third_party = set()
        for seed in (0, 1, 2, 42, 43, 44, 1337, 2026):
            training, guard = taxonomy.generate_partition(self.dataset, seed)
            self.assertEqual((training, guard), taxonomy.generate_partition(self.dataset, seed))
            audit = taxonomy.audit_originals(self.dataset, training, guard)
            self.assertEqual(json.loads(audit["sampling_sensitivity_counts"]), taxonomy.SENSITIVITY_COUNTS)
            self.assertEqual(set(json.loads(audit["sampling_sensitive_visibility_counts"]).values()), {4})
            self.assertEqual(len({r.metadata["group_id"] for r in guard}), 16)
            for row in training:
                self.assertEqual(self.dataset.partitions[row.metadata["group_id"]], "train")
                if row.metadata["primary_category"] == "SEXUAL":
                    selected_sexual.add(row.metadata["group_id"])
            third_party.add(json.loads(audit["sampling_category_counts"])["THIRD_PARTY"])
            expanded = list(iter_training_examples(training, (), BatchTrainingConfig(seed=seed)))
            expanded_audit = taxonomy.audit_expanded(self.dataset, training, expanded, guard, BatchTrainingConfig(seed=seed))
            self.assertEqual(expanded_audit["sampling_expanded_rows"], "64")
            self.assertGreaterEqual(int(expanded_audit["sampling_expanded_unique_texts"]), 32)
        self.assertEqual(len(selected_sexual), 2)
        self.assertEqual(third_party, {4, 6})

    def test_invalid_release_boundaries_fail_closed(self):
        for mutation in ("enum", "unknown_category", "packed", "duplicate", "group", "partition", "slot", "evidence", "policy"):
            value = copy.deepcopy(self.release)
            row = value["rows"][0]
            if mutation == "enum": row["classification"]["sensitivity"] = "S9"
            elif mutation == "unknown_category": row["classification"]["categories"].append("OTHER")
            elif mutation == "packed": row["packed_classification"] += 1
            elif mutation == "duplicate": value["rows"][1]["text"] = row["text"].upper()
            elif mutation == "group": row["metadata"].pop("group_id")
            elif mutation == "partition": row["metadata"]["taxonomy_partition"] = "guard"
            elif mutation == "slot": row["metadata"]["control"] = "mild"
            elif mutation == "evidence": row["metadata"]["annotations"]["categories"] = {}
            else: value["policy"]["originals"] = 33
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                taxonomy.load_snapshot(taxonomy.canonical_bytes(value))

    def test_actual_batch_target_weight_and_augmentation_cannot_bypass_audit(self):
        training, guard = taxonomy.generate_partition(self.dataset, 42)
        config = BatchTrainingConfig(seed=42)
        runtime = type("Runtime", (), {"compute_semantic_gradients": lambda *a, **kw: self.fail("RPC must not run")})()
        for mutation in ("target", "weight", "provenance", "text", "extra_replay", "missing_snapshot"):
            changed = list(training)
            if mutation == "target": changed[0] = replace(changed[0], expected_classification=guard[0].expected_classification)
            elif mutation == "weight": changed[0] = replace(changed[0], weight=2.)
            elif mutation == "provenance": changed[0] = replace(changed[0], metadata={**changed[0].metadata, "group_id": "invented"})
            elif mutation == "text": changed[0] = replace(changed[0], text="changed source fact")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                train_parameter_batch("privoke-balanced", changed, heldout_examples=guard, config=config,
                    runtime_client=runtime, taxonomy_dataset=None if mutation == "missing_snapshot" else self.dataset,
                    golden_examples=[training[0]] if mutation == "extra_replay" else ())
        with patch("training.trainer.random_pii_transform", return_value=guard[0].text), self.assertRaisesRegex(ValueError, "overlap"):
            train_parameter_batch("privoke-balanced", training, heldout_examples=guard, config=config,
                                  runtime_client=runtime, taxonomy_dataset=self.dataset)

    def test_actual_64_row_rpc_is_semantic_only_and_returned_execution_is_checked(self):
        training, guard = taxonomy.generate_partition(self.dataset, 42)
        for scope, rpc in (("heads", "ComputeSemanticGradients"), ("full_encoder", "ComputeUnderlyingModelGradients")):
            _, response = contract(scope)
            for execution in response.executions:
                execution.examples = 64 if execution.phase == "training" else 16
            response.metrics.update(examples=64, heldout_examples=16)
            for bad_layer in (False, True):
                response.executions[0].layer = runtime_pb2.DETECTION_LAYER_REGEX if bad_layer else runtime_pb2.DETECTION_LAYER_SEMANTIC
                with self.subTest(scope=scope, bad_layer=bad_layer), patch("runtime_client.grpc.insecure_channel"), \
                     patch("runtime_client.runtime_pb2_grpc.PrivokeRuntimeServiceStub") as stub:
                    getattr(stub.return_value, rpc).return_value = response
                    arguments = dict(model_id="privoke-balanced", new_examples=training, heldout_examples=guard,
                        config=BatchTrainingConfig(seed=42), taxonomy_dataset=self.dataset, training_scope=scope, request_id="req")
                    if bad_layer:
                        with self.assertRaises(RuntimeAnalysisError): train_parameter_batch(**arguments)
                    else:
                        result = train_parameter_batch(**arguments)
                        sent = getattr(stub.return_value, rpc).call_args.args[0]
                        self.assertEqual(list(sent.layers), [runtime_pb2.DETECTION_LAYER_SEMANTIC])
                        self.assertEqual(len(sent.examples), 64)
                        self.assertEqual(len(sent.heldout_examples), 16)
                        self.assertEqual(result.metadata["sampling_expanded_rows"], "64")

    def test_dispatch_budgets_and_default_compatibility(self):
        for count, heldout in ((31, 16), (32, 8)):
            with self.assertRaises(ValueError):
                generate_training_partition(count, heldout, 42, sampling_strategy=taxonomy.STRATEGY, taxonomy_dataset=self.dataset)
        def signature(partition):
            return [[(r.text, r.expected_packed_classification, r.weight, r.metadata) for r in rows] for rows in partition]
        self.assertEqual(signature(generate_training_partition(32, 16, 42)),
                         signature(generate_training_partition(32, 16, 42, sampling_strategy=None)))
        request = parameters_pb2.FuzzerTrainingRequest(request_id="legacy", source_id="test", prompt_count=32)
        self.assertEqual(_training_request_fingerprint(request), hashlib.sha256(request.SerializeToString(deterministic=True)).hexdigest())

    def test_preparation_checks_opaque_memberships_and_requires_pinned_inputs(self):
        root = SERVICE.parents[1]
        sys.path.insert(0, str(root / "evaluation"))
        spec = importlib.util.spec_from_file_location("taxonomy_preparation", root / "evaluation/prepare-taxonomy-coverage.py")
        preparation = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparation)
        row = self.release["rows"][0]
        counts = {"ids": 1, "groups": 1, "texts": 1}
        unrelated = {kind: ["a" * 64] for kind in counts}
        self.assertEqual(preparation.opaque_overlap([row], unrelated, counts), {kind: 0 for kind in counts})
        for kind, domain, value in (("ids", "id", row["id"]), ("groups", "group", row["metadata"]["group_id"]),
                                    ("texts", "text_key", preparation.training_text_key(row["text"]))):
            keys = copy.deepcopy(unrelated)
            keys[kind] = [preparation.opaque_key(domain, value)]
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "overlaps"):
                preparation.opaque_overlap([row], keys, counts)
        with self.assertRaisesRegex(ValueError, "pinned historical TRAIN"):
            taxonomy.prepare_release(b"not authorized TRAIN", b"renderer", {})


class TaxonomyReplayTests(unittest.TestCase):
    def setUp(self):
        TaxonomyCoverageTests.setUp(self)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "release.json"
        self.path.write_bytes(taxonomy.canonical_bytes(self.release))
        with patch.dict(os.environ, {}, clear=True):
            self.config = replace(FuzzerConfig.from_env(), model_id="privoke-balanced", prompt_dataset_path=str(self.path))
        self.environment = patch.dict(os.environ, {"PRIVOKE_FUZZER_DUMP_DIR": str(Path(self.directory.name) / "durable")})
        self.environment.start(); self.addCleanup(self.environment.stop)
        self.request = parameters_pb2.FuzzerTrainingRequest(request_id="same", source_id="test", prompt_count=32, seed=42,
            model_id="privoke-balanced", metadata={CONTEXTUAL_SAMPLING_STRATEGY_KEY: taxonomy.STRATEGY})
        self.previous = parameters_pb2.ParameterUpdateStatus(found=True, base_version="v1", prompts_generated=32,
            ack=parameters_pb2.ParameterUpdateAck(accepted=True, model_id="privoke-balanced", applied_version="v2"))

    def replay(self, config=None, request=None):
        service = FuzzerTrainingService(config or self.config)
        with patch.object(service, "_previous_update_for_fingerprint", return_value=self.previous) as lookup, \
             patch("fuzzer_service.generate_training_partition") as sample, patch.object(service, "_train") as train, \
             patch.object(service, "_submit_update") as submit:
            result = service.RunTrainingCycle(request or self.request, Context())
        sample.assert_not_called(); train.assert_not_called(); submit.assert_not_called()
        return result, lookup.call_args.args[3]

    def test_identical_replay_skips_selection_training_publication_and_reservation_binds_changes(self):
        _, fingerprint = self.replay()
        self.assertEqual(self.replay()[1], fingerprint)
        for change in (replace(self.config, training_learning_rate=.02), replace(self.config, training_max_gradient=.04),
                       replace(self.config, minimum_exact_match_rate=.1)):
            service = FuzzerTrainingService(change)
            with patch.object(service, "_previous_update_for_fingerprint") as lookup, self.assertRaisesRegex(Aborted, "different effective"):
                service.RunTrainingCycle(self.request, Context())
            lookup.assert_not_called()
        changed = copy.deepcopy(self.release); changed["rows"][0]["text"] += " safe extra wording"
        self.path.write_bytes(taxonomy.canonical_bytes(changed))
        service = FuzzerTrainingService(self.config)
        with patch.object(service, "_previous_update_for_fingerprint") as lookup, self.assertRaisesRegex(Aborted, "different effective"):
            service.RunTrainingCycle(self.request, Context())
        lookup.assert_not_called()

    def test_policy_config_and_dataset_are_bound_before_lookup_even_for_head(self):
        self.replay()
        changed_plan = {**taxonomy.policy_contract(), "semantic_execution_contract": "changed"}
        service = FuzzerTrainingService(self.config)
        with patch("fuzzer_service.taxonomy_policy_contract", return_value=changed_plan), \
             patch.object(service, "_previous_update_for_fingerprint") as lookup, self.assertRaisesRegex(Aborted, "different effective"):
            service.RunTrainingCycle(self.request, Context())
        lookup.assert_not_called()
        with patch.dict(os.environ, {"PRIVOKE_FUZZER_DUMP_DIR": ""}), \
             patch.object(service, "_previous_update_for_fingerprint") as lookup, self.assertRaisesRegex(Aborted, "durable"):
            service.RunTrainingCycle(self.request, Context())
        lookup.assert_not_called()

    def test_rejected_candidate_reservation_survives_and_snapshot_is_not_reread(self):
        service = FuzzerTrainingService(self.config)
        def sample(**kwargs):
            # Changing the path after reservation cannot change this call's loaded rows.
            self.path.write_bytes(b"invalid later bytes")
            return taxonomy.generate_partition(kwargs["taxonomy_dataset"], kwargs["seed"])
        with patch.object(service, "_previous_update_for_fingerprint", return_value=parameters_pb2.ParameterUpdateStatus(found=False)), \
             patch("fuzzer_service.generate_training_partition", side_effect=sample), \
             patch.object(service, "_train", side_effect=Aborted("candidate rejected")) as train:
            with self.assertRaisesRegex(Aborted, "candidate rejected"):
                service.RunTrainingCycle(self.request, Context())
        self.assertEqual(len(train.call_args.args[1]), 32)
        self.path.write_bytes(taxonomy.canonical_bytes(self.release))
        changed = FuzzerTrainingService(replace(self.config, training_learning_rate=.02))
        with patch.object(changed, "_previous_update_for_fingerprint") as lookup, self.assertRaisesRegex(Aborted, "different effective"):
            changed.RunTrainingCycle(self.request, Context())
        lookup.assert_not_called()

    def test_legacy_request_only_receipt_cannot_masquerade_as_new_mode_replay(self):
        class Conflict(grpc.RpcError):
            def code(self): return grpc.StatusCode.ALREADY_EXISTS
        service = FuzzerTrainingService(self.config)
        with patch("fuzzer_service.grpc.insecure_channel"), \
             patch("fuzzer_service.parameters_pb2_grpc.ParamUpdateServiceStub") as stub, \
             patch.object(service, "_train") as train, self.assertRaisesRegex(Aborted, "different training request"):
            stub.return_value.GetParameterUpdateStatus.side_effect = Conflict()
            service.RunTrainingCycle(self.request, Context())
        sent = stub.return_value.GetParameterUpdateStatus.call_args.args[0]
        self.assertNotEqual(sent.request_fingerprint, _training_request_fingerprint(self.request))
        train.assert_not_called()

    def test_full_effective_learning_rate_is_bound_and_head_ignores_full_only_override(self):
        head_fingerprint = self.replay()[1]
        self.assertEqual(self.replay(replace(self.config, underlying_training_learning_rate=.003))[1], head_fingerprint)
        service = FuzzerTrainingService(self.config)
        with patch.object(service, "_previous_update_for_fingerprint", return_value=self.previous) as lookup, \
             patch.object(service, "_train") as train:
            self.assertTrue(service.RunUnderlyingTrainingCycle(self.request, Context()).accepted)
        self.assertNotEqual(lookup.call_args.args[3], head_fingerprint)
        train.assert_not_called()
        changed = FuzzerTrainingService(replace(self.config, underlying_training_learning_rate=.003))
        with patch.object(changed, "_previous_update_for_fingerprint") as lookup, self.assertRaisesRegex(Aborted, "different effective"):
            changed.RunUnderlyingTrainingCycle(self.request, Context())
        lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
