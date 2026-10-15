"""Shared synthetic v2 artifact contract and explicit preparation."""
import copy
from pathlib import Path
import unittest

from privoke_model.artifact import load_artifact, validate_artifact, apply_parameter_update
from privoke_model.contextual_training import (prepare_task_query_artifact, prepare_contextual_training_artifact,
    prepare_full_encoder_artifact, FULL_ENCODER_STRATEGY, LAST_BLOCK_STRATEGY, contextual_trainable_names)
from privoke_model.readout import QUERY_NAMES

FIXTURES = Path(__file__).parent / "fixtures"


class TaskQueryContractTests(unittest.TestCase):
    def test_shared_fixture_and_full_preparation_chaining(self):
        artifact = load_artifact(FIXTURES / "contextual-task-query.json")
        for strategy in (None, LAST_BLOCK_STRATEGY, FULL_ENCODER_STRATEGY):
            prepared = prepare_contextual_training_artifact(artifact, strategy)
            validate_artifact(prepared)
            self.assertTrue(QUERY_NAMES.issubset(contextual_trainable_names(prepared["config"], strategy)))
        full = prepare_full_encoder_artifact(artifact, version="v3", generated_at_unix=3, source_revision="b" * 40)
        self.assertEqual(contextual_trainable_names(full["config"], FULL_ENCODER_STRATEGY), set(full["parameters"]))

    def test_migration_refuses_implicit_identity_or_repeat(self):
        source = load_artifact(FIXTURES / "contextual-last-block.json")
        original = copy.deepcopy(source)
        artifact = prepare_task_query_artifact(source, version="v2", generated_at_unix=2, source_revision="a" * 40)
        self.assertEqual(source, original)
        with self.assertRaises(ValueError):
            prepare_task_query_artifact(artifact, version="v3", generated_at_unix=3, source_revision="b" * 40)
        for revision in ("main", "", "g" * 40):
            with self.assertRaises(ValueError):
                prepare_task_query_artifact(source, version="v2", generated_at_unix=2, source_revision=revision)
        with self.assertRaises(ValueError):
            apply_parameter_update(artifact, base_version="stale", deltas={"readout.category.query": [0., 0.]}, source_id="test")
        with self.assertRaises(ValueError):
            apply_parameter_update(artifact, base_version=artifact["version"], deltas={"readout.extra.query": [0., 0.]}, source_id="test")


if __name__ == "__main__":
    unittest.main()
