import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "generated", ROOT.parents[1] / "shared/python"):
    sys.path.insert(0, str(path))

from privoke_model.training_data import training_text_key
from prompt_generation import generate_training_partition
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
