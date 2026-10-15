import sys
import json
import tempfile
import unittest

import grpc
from collections import Counter
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))

from privoke_model.training_data import training_text_key
from prompt_generation.generator import (generate_training_partition, generate_training_prompts,
    contextual_sampling_audit, CONTEXTUAL_SAMPLING_STRATEGY_KEY, CONTEXTUAL_ROLE_QUOTA_STRATEGY)
from training.trainer import iter_training_examples
from training.types import BatchTrainingConfig, BatchTrainingUpdate
from fuzzer_service import FuzzerTrainingService, _resolve_cycle, _training_request_fingerprint
from privoke.v1 import parameters_pb2


class TrainingPartitionTests(unittest.TestCase):
    def test_reserved_evaluation_remains_disjoint_at_maximum_training_count(self):
        for seed in (0, 1337, 2026):
            training, heldout = generate_training_partition(256, 16, seed)
            expanded = list(iter_training_examples(training, (), BatchTrainingConfig(seed=seed)))
            train_keys = {training_text_key(item.text) for item in expanded}
            heldout_keys = {training_text_key(item.text) for item in heldout}
            self.assertEqual(len(training), 256)
            self.assertEqual(len(heldout_keys), 16)
            self.assertFalse(train_keys & heldout_keys)
            self.assertEqual({item.expected_classification.is_sensitive() for item in heldout}, {True, False})

    def test_replay_returns_committed_result_without_training_or_publication(self):
        service = FuzzerTrainingService(type("Config", (), {"max_concurrent_cycles": 1})())
        service.config = type("Config", (), {"model_id": "privoke-balanced", "max_prompt_count": 256, "seed": 1337})()
        previous = parameters_pb2.ParameterUpdateStatus(
            found=True,
            ack=parameters_pb2.ParameterUpdateAck(accepted=True, model_id="privoke-balanced", applied_version="v1+train.1"),
            base_version="v1", prompts_generated=8,
        )
        request = parameters_pb2.FuzzerTrainingRequest(request_id="retry-1", source_id="test", prompt_count=8)
        with patch.object(service, "_previous_update", return_value=previous), patch.object(service, "_train") as train, patch.object(service, "_submit_update") as submit:
            response = service._run_training_cycle(request, None)
        self.assertTrue(response.accepted)
        self.assertEqual(response.applied_version, "v1+train.1")
        self.assertEqual(response.metadata["replayed"], "true")
        train.assert_not_called()
        submit.assert_not_called()


class FixedDatasetPartitionTests(unittest.TestCase):
    def test_source_group_siblings_are_excluded_and_provenance_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "groups.json"
            path.write_text(json.dumps([
                {"text": f"{'Sensitive' if sensitive else 'Clean'} document {group} sentence {sentence}",
                 "packed_classification": 63 if sensitive else 28,
                 "metadata": {"group_id": f"doc-{sensitive}-{group}", "source": "fixture"}}
                for sensitive in (False, True) for group in range(6) for sentence in range(3)
            ]), encoding="utf-8")
            for seed in (42, 1337):
                training, heldout = generate_training_partition(256, 8, seed, path)
                train_groups = {item.metadata["group_id"] for item in training}
                heldout_groups = {item.metadata["group_id"] for item in heldout}
                self.assertEqual(len(heldout_groups), 8)
                self.assertFalse(train_groups & heldout_groups)
                self.assertTrue(all(item.metadata["source"] == "fixture" for item in heldout))
                repeated = generate_training_partition(256, 8, seed, path)
                self.assertEqual([[item.text for item in part] for part in (training, heldout)],
                                 [[item.text for item in part] for part in repeated])

    def test_too_few_groups_cannot_pass_by_using_sibling_sentences(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "groups.json"
            path.write_text(json.dumps([
                {"text": f"{'Sensitive' if sensitive else 'Clean'} sentence {index}",
                 "packed_classification": 63 if sensitive else 28,
                 "metadata": {"group_id": f"single-document-{sensitive}"}}
                for sensitive in (False, True) for index in range(12)
            ]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source groups"):
                generate_training_partition(8, 4, 42, path)
            with self.assertRaisesRegex(ValueError, "training texts separate"):
                generate_training_partition(8, 2, 42, path)

    def dataset(self, directory, each_count):
        path = Path(directory) / "fixed.json"
        path.write_text(json.dumps([
            {"text": f"Fixed {'sensitive' if sensitive else 'clean'} sample {index}",
             "packed_classification": 63 if sensitive else 28}
            for sensitive in (False, True) for index in range(each_count)
        ]), encoding="utf-8")
        return path

    def test_nearly_exhausted_fixed_dataset_still_supplies_training(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = self.dataset(directory, 129)
            for count in (1, 256):
                training, heldout = generate_training_partition(count, 256, 0, dataset)
                self.assertEqual(len(training), count)
                self.assertEqual(len({item.text for item in heldout}), 256)
                self.assertFalse({item.text for item in training} & {item.text for item in heldout})
                self.assertEqual([item.metadata["generation_index"] for item in training], [str(index) for index in range(count)])

    def test_fixed_dataset_is_reproducible_and_real_exhaustion_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            dataset = self.dataset(directory, 9)
            first = generate_training_partition(8, 16, 1337, dataset)
            second = generate_training_partition(8, 16, 1337, dataset)
            self.assertEqual([[item.text for item in part] for part in first], [[item.text for item in part] for part in second])
            with self.assertRaisesRegex(ValueError, "training texts separate"):
                generate_training_partition(1, 18, 1337, dataset)
            with self.assertRaisesRegex(ValueError, "distinct held-out"):
                generate_training_partition(1, 20, 1337, dataset)


    def test_empty_dataset_and_invalid_templates_have_safe_domain_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "at least one seed"):
                generate_training_prompts(1, 0, path)
            with self.assertRaises(ValueError):
                generate_training_partition(1, 2, 0, path)
            for template in ("Private {unknown_field}", "Private {", "Private {}", "Private {name.missing}"):
                path.write_text(json.dumps([
                    {"text": template, "packed_classification": 28},
                    {"text": "sensitive sample", "packed_classification": 63},
                ]), encoding="utf-8")
                with self.subTest(template=template):
                    with self.assertRaisesRegex(ValueError, "invalid template"):
                        generate_training_prompts(8, 0, path)
                    with self.assertRaisesRegex(ValueError, "invalid template"):
                        generate_training_partition(1, 2, 0, path)


class ContextualRoleQuotaPartitionTests(unittest.TestCase):
    def inventory(self, batch):
        return [(item.text, item.expected_classification.sensitivity().name,
                 item.expected_classification.visibility().name,
                 tuple(sorted(category.name for category in item.expected_classification.categories())),
                 item.weight, item.metadata) for item in batch]

    def partition_inventory(self, partition):
        return [self.inventory(batch) for batch in partition]

    def rows(self):
        rows = []
        for family in range(24):
            for sensitive in (False, True):
                for variant in range(4):
                    # Include category-only positives to exercise is_sensitive,
                    # rather than an incorrect sensitivity != S0 surrogate.
                    rows.append({"text": f"Authored {sensitive} family {family} variant {variant}",
                        "classification": {"sensitivity": "S3" if sensitive and family % 2 else "S0",
                                           "visibility": "PU", "categories": ["HEALTH"] if sensitive else []},
                        "metadata": {"training_role": "authored_contrastive_context", "group_id": f"auth-{family}"}})
        for role, number in (("public_annotation_negative", 320), ("existing_bootstrap_replay", 40)):
            for index in range(number):
                sensitive = role == "existing_bootstrap_replay" and index % 2 == 0
                rows.append({"text": f"Background {role} row {index}",
                    "classification": {"sensitivity": "S3" if sensitive else "S0", "visibility": "PU",
                                       "categories": ["HEALTH"] if sensitive else []},
                    "metadata": {"training_role": role, "group_id": f"background-{role}-{index}"}})
        return rows

    def dataset(self, directory, rows=None):
        path = Path(directory) / "quota.json"
        path.write_text(json.dumps(self.rows() if rows is None else rows), encoding="utf-8")
        return path

    def quota(self, path, seed=42, **kwargs):
        return generate_training_partition(256, 16, seed, path,
            sampling_strategy=CONTEXTUAL_ROLE_QUOTA_STRATEGY, **kwargs)

    def test_quota_determinism_group_first_coverage_and_identical_heldout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.dataset(directory)
            for seed in (42, 1337, 2026):
                legacy = generate_training_partition(256, 16, seed, path)
                self.assertEqual(self.partition_inventory(legacy), self.partition_inventory(
                    generate_training_partition(256, 16, seed, path, sampling_strategy=None)))
                training, heldout = self.quota(path, seed)
                self.assertEqual(self.inventory(heldout), self.inventory(legacy[1]))
                self.assertEqual(self.partition_inventory((training, heldout)), self.partition_inventory(self.quota(path, seed)))
                self.assertEqual(len(training), 256)
                keys = {training_text_key(item.text) for item in training}
                self.assertEqual(len(keys), 256)
                self.assertFalse(keys & {training_text_key(item.text) for item in heldout})
                reserved = {item.metadata["group_id"] for item in heldout}
                self.assertFalse(reserved & {item.metadata["group_id"] for item in training})
                self.assertEqual([item.metadata["generation_index"] for item in training], [str(i) for i in range(256)])
                self.assertTrue(all(item.weight == 1. for item in training))
                audit = contextual_sampling_audit(training)
                self.assertEqual(audit["sampling_authored_sensitive_rows"], "32")
                self.assertEqual(audit["sampling_authored_clean_rows"], "32")
                self.assertEqual(int(audit["sampling_public_negative_rows"]) + int(audit["sampling_bootstrap_replay_rows"]), 192)
                self.assertEqual(int(audit["sampling_training_sensitive_rows"]), sum(item.expected_classification.is_sensitive() for item in training))
                available_families = {f"auth-{i}" for i in range(24)} - reserved
                for sensitive in (False, True):
                    group_counts = Counter(item.metadata["group_id"] for item in training
                        if item.metadata["training_role"] == "authored_contrastive_context"
                        and item.expected_classification.is_sensitive() == sensitive)
                    self.assertEqual(set(group_counts), available_families)
                    self.assertLessEqual(max(group_counts.values()) - min(group_counts.values()), 1)
                self.assertEqual(int(audit["sampling_authored_groups"]), len(available_families))

    def test_unknown_policy_count_and_heldout_budget_fail_closed(self):
        for strategy in ("", "unknown", True, 1):
            with self.assertRaisesRegex(ValueError, "sampling strategy"):
                generate_training_partition(256, 16, 42, sampling_strategy=strategy)
        for count in (0, 8, 255, 257):
            with self.assertRaisesRegex(ValueError, "256"):
                generate_training_partition(count, 16, 42, sampling_strategy=CONTEXTUAL_ROLE_QUOTA_STRATEGY)
        with self.assertRaisesRegex(ValueError, "16 held-out"):
            generate_training_partition(256, 8, 42, sampling_strategy=CONTEXTUAL_ROLE_QUOTA_STRATEGY)

    def test_unknown_roles_groups_and_insufficient_unique_rows_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            for mutation, message in (("unknown", "unknown training role"), ("group", "source groups"),
                                      ("insufficient", "without replacement"), ("duplicates", "without replacement")):
                rows = self.rows()
                if mutation == "unknown": rows[0]["metadata"]["training_role"] = "other"
                elif mutation == "group": rows[0]["metadata"].pop("group_id")
                elif mutation == "insufficient": rows = [r for r in rows if r["metadata"]["training_role"] != "authored_contrastive_context"]
                else:
                    for row in rows:
                        if row["metadata"]["training_role"] == "authored_contrastive_context" and row["classification"]["categories"]:
                            row["text"] = "Identical private disclosure"
                path = self.dataset(directory, rows)
                with self.assertRaisesRegex(ValueError, message): self.quota(path)

    def test_audit_rejects_duplicates_and_reports_actual_background_mix(self):
        with tempfile.TemporaryDirectory() as directory:
            training, _ = self.quota(self.dataset(directory))
            audit = contextual_sampling_audit(training)
            self.assertEqual(audit["sampling_training_rows"], "256")
            self.assertEqual(audit["sampling_training_unique_texts"], "256")
            counts = Counter(item.metadata["training_role"] for item in training)
            self.assertEqual(audit["sampling_public_negative_rows"], str(counts["public_annotation_negative"]))
            self.assertEqual(audit["sampling_bootstrap_replay_rows"], str(counts["existing_bootstrap_replay"]))
            with self.assertRaisesRegex(ValueError, "distinct"):
                contextual_sampling_audit(training[:-1] + [training[0]])

    def service(self, path):
        config = type("Config", (), {"max_concurrent_cycles": 1, "model_id": "privoke-balanced", "max_prompt_count": 256,
            "seed": 42, "heldout_prompt_count": 16, "prompt_dataset_path": path, "minimum_exact_match_rate": 0.,
            "param_update_target": "unused:1", "fuzzer_id": "test-fuzzer", "timeout_seconds": 1.})()
        return FuzzerTrainingService(config)

    def request(self):
        return parameters_pb2.FuzzerTrainingRequest(request_id="quota-1", source_id="study", model_id="privoke-balanced",
            prompt_count=256, seed=42, metadata={CONTEXTUAL_SAMPLING_STRATEGY_KEY: CONTEXTUAL_ROLE_QUOTA_STRATEGY})

    def test_service_passes_policy_and_carries_actual_audit_through_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.dataset(directory)
            service = self.service(path)
            metrics = {"exact_match_rate": 1., "heldout_exact_match_rate": 1., "candidate_heldout_exact_match_rate": 1.,
                "heldout_sensitive_recall": 1., "candidate_heldout_sensitive_recall": 1., "heldout_clean_specificity": 1.,
                "candidate_heldout_clean_specificity": 1., "candidate_heldout_safety_regression_rate": 0.,
                "heldout_sensitive_examples": 8., "heldout_clean_examples": 8.}
            update = BatchTrainingUpdate("privoke-balanced", "v1", {}, {}, metrics, {"existing": "preserved"})
            ack = parameters_pb2.ParameterUpdateAck(accepted=True, model_id="privoke-balanced", applied_version="v1+train.1")
            context = type("Context", (), {"is_active": lambda self: True})()
            with patch.object(service, "_previous_update", return_value=parameters_pb2.ParameterUpdateStatus(found=False)), \
                 patch("fuzzer_service.generate_training_partition", wraps=generate_training_partition) as sampler, \
                 patch.object(service, "_train", return_value=update) as train, \
                 patch.object(service, "_submit_update", return_value=ack) as submit:
                response = service._run_training_cycle(self.request(), context)
            self.assertEqual(sampler.call_count, 1)
            self.assertEqual(sampler.call_args.kwargs["sampling_strategy"], CONTEXTUAL_ROLE_QUOTA_STRATEGY)
            selected = train.call_args.args[1]
            self.assertEqual(len(selected), len({training_text_key(item.text) for item in selected}))
            audit = contextual_sampling_audit(selected)
            emitted = submit.call_args.args[2]
            self.assertIsNot(emitted, update)
            self.assertEqual(update.metadata, {"existing": "preserved"})
            self.assertEqual(emitted.metadata, {"existing": "preserved", **audit})
            for key,value in audit.items(): self.assertEqual(response.metadata[key], value)

    def test_quota_replay_never_samples_trains_or_fabricates_audits(self):
        service = self.service(None)
        previous = parameters_pb2.ParameterUpdateStatus(found=True, base_version="v1", prompts_generated=256,
            ack=parameters_pb2.ParameterUpdateAck(accepted=True, model_id="privoke-balanced", applied_version="v1+train.1"))
        with patch.object(service, "_previous_update", return_value=previous), \
             patch("fuzzer_service.generate_training_partition") as sampler, \
             patch.object(service, "_train") as train, patch.object(service, "_submit_update") as submit:
            response = service._run_training_cycle(self.request(), None)
        self.assertEqual(dict(response.metadata), {"replayed": "true"})
        sampler.assert_not_called(); train.assert_not_called(); submit.assert_not_called()

    def test_policy_fingerprint_conflict_aborts_before_sampling_or_training(self):
        class Conflict(grpc.RpcError):
            def code(self): return grpc.StatusCode.ALREADY_EXISTS

        class Context:
            def abort(self, code, message):
                raise RuntimeError(f"{code.name}: {message}")

        service = self.service(None)
        request = self.request()
        with patch("fuzzer_service.grpc.insecure_channel"), \
             patch("fuzzer_service.parameters_pb2_grpc.ParamUpdateServiceStub") as stub, \
             patch("fuzzer_service.generate_training_partition") as sampler, \
             patch.object(service, "_train") as train, patch.object(service, "_submit_update") as submit:
            status = stub.return_value.GetParameterUpdateStatus
            status.side_effect = Conflict()
            with self.assertRaisesRegex(RuntimeError, "ALREADY_EXISTS.*different training request"):
                service._run_training_cycle(request, Context())
            self.assertEqual(status.call_args.args[0].request_fingerprint, _training_request_fingerprint(request))
        sampler.assert_not_called(); train.assert_not_called(); submit.assert_not_called()

    def test_submitted_metadata_includes_complete_audit_within_entry_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            training, _ = self.quota(self.dataset(directory))
            audit = contextual_sampling_audit(training)
            # The current runtime response has 45 metadata/metric entries. Exercise
            # the actual emitter merge plus all six service publication fields.
            metrics = {f"runtime_metric_{i}": float(i) for i in range(20)}
            metadata = {f"runtime_metadata_{i}": str(i) for i in range(25)}
            update = BatchTrainingUpdate("privoke-balanced", "v1", {}, {}, metrics, {**metadata, **audit})
            service = self.service(None)
            request = self.request()
            ack = parameters_pb2.ParameterUpdateAck(accepted=True)
            with patch("training.parameter_updates.emit_parameter_update", return_value=ack) as emit:
                service._submit_update(request, _resolve_cycle(request, service.config), update, 256, None)
            payload = emit.call_args.args[1]
            self.assertEqual(len(payload.metadata), 63)
            self.assertLessEqual(len(payload.metadata), 64)
            for key, value in audit.items(): self.assertEqual(payload.metadata[key], value)
            self.assertEqual(payload.metadata["training_request_fingerprint"], _training_request_fingerprint(request))
            self.assertEqual(payload.metadata["generated_prompt_count"], "256")
