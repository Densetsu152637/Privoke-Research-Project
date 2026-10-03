import unittest

from prepare_public_splits import partition_examples
from privoke_eval.types import EvaluationExample


class PublicPartitionTests(unittest.TestCase):
    def test_document_lineage_stays_together_and_splits_are_reproducible(self):
        examples = [EvaluationExample(f"text {group} {label}", label, metadata={
            "example_id": f"{group}-{label}", "group_id": group,
        }) for group in range(8) for label in (True, False)]
        development, final = partition_examples(examples, 42)
        self.assertEqual((development, final), partition_examples(examples, 42))
        self.assertFalse({x.metadata["group_id"] for x in development} & {x.metadata["group_id"] for x in final})
        self.assertEqual(len(development) + len(final), len(examples))

    def test_missing_class_cannot_silently_create_invalid_final_set(self):
        with self.assertRaises(ValueError):
            partition_examples([EvaluationExample("clean", False, metadata={"example_id": "1"})], 42)
