import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))

from privoke_model.training_data import training_text_key
from prompt_generation.generator import generate_training_partition, generate_training_prompts
from training.trainer import iter_training_examples
from training.types import BatchTrainingConfig
from fuzzer_service import FuzzerTrainingService
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
