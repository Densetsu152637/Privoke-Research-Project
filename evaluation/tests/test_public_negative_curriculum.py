import importlib.util
from pathlib import Path
import unittest

from privoke_eval.types import EvaluationExample
from privoke_model.training_data import training_text_key

SPEC = importlib.util.spec_from_file_location("public_negatives", Path(__file__).parents[1] / "prepare-public-negatives.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
STUDY_SPEC = importlib.util.spec_from_file_location("negative_study", Path(__file__).parents[1] / "run-public-negative-study.py")
STUDY = importlib.util.module_from_spec(STUDY_SPEC)
STUDY_SPEC.loader.exec_module(STUDY)


def example(identifier, text, positive=False, group=None):
    return EvaluationExample(text, positive, metadata={"example_id": identifier, "group_id": group or identifier})


class PublicNegativeCurriculumTests(unittest.TestCase):
    def test_selection_uses_exact_pipeline_floor_and_declared_ties(self):
        def metrics(tp, tn):
            return {"pipeline": {"true_positives": tp, "true_negatives": tn}}
        self.assertIsNone(STUDY.candidate_key(metrics(237, 230), 1, .03, 42))
        self.assertIsNone(STUDY.candidate_key(metrics(264, 53), 1, .03, 42))
        self.assertIsNotNone(STUDY.candidate_key(metrics(238, 54), 1, .03, 42))
        self.assertGreater(STUDY.candidate_key(metrics(238, 80), 1, .03, 42),
                           STUDY.candidate_key(metrics(264, 79), 1, .03, 42))
        first = STUDY.candidate_key(metrics(247, 80), 1, .03, 42)
        self.assertGreater(first, STUDY.candidate_key(metrics(247, 80), 2, .03, 42))
        self.assertGreater(first, STUDY.candidate_key(metrics(247, 80), 1, .1, 42))
        self.assertGreater(first, STUDY.candidate_key(metrics(247, 80), 1, .03, 1337))

    def test_locked_siblings_ids_and_normalized_variants_are_excluded(self):
        protected = [{"id": "reserved", "group_id": "document", "text": "Locked ＴＥＸＴ 1 2"}]
        rows = [example("sibling", "Other sentence", group="document"),
                example("reserved", "Different identifier content"),
                example("duplicate", "locked text 12"),
                example("valid", "Usable clean sentence")]
        selected, counts = MODULE.select_clean_pool(rows, protected, [], 1, 42)
        self.assertEqual([x.metadata["example_id"] for x in selected], ["valid"])
        self.assertEqual(counts["exclusions"]["locked_group_id_or_text_or_anchor"], 3)

    def test_normalized_label_conflicts_and_anchor_duplicates_are_excluded(self):
        rows = [example("first", "Case Difference"), example("second", "CASE DIFFERENCE", True),
                example("third", "case difference"), example("anchor", "Original sample"),
                example("valid", "Clean alternative")]
        anchors = [("original SAMPLE", "S3", "PU", ("HEALTH",))]
        selected, counts = MODULE.select_clean_pool(rows, [], anchors, 1, 42)
        self.assertEqual([x.metadata["example_id"] for x in selected], ["valid"])
        self.assertEqual(counts["exclusions"]["normalized_conflicting_key"], 1)

    def test_selection_is_reproducible_and_never_fills_an_undersized_pool(self):
        rows = [example(str(i), f"Clean sentence {i}") for i in range(12)]
        first, _ = MODULE.select_clean_pool(rows, [], [], 8, 42)
        second, _ = MODULE.select_clean_pool(list(reversed(rows)), [], [], 8, 42)
        self.assertEqual([x.metadata["example_id"] for x in first], [x.metadata["example_id"] for x in second])
        with self.assertRaisesRegex(ValueError, "eligible clean"):
            MODULE.select_clean_pool(rows, [], [], 13, 42)
        self.assertEqual(len({training_text_key(x.text) for x in first}), 8)

    def test_braces_render_as_literal_data_without_changing_the_sentence(self):
        text = 'A generic example: {"items": []}; placeholder {name}.'
        self.assertEqual(MODULE.escape_template(text).format(name="replacement"), text)


if __name__ == "__main__":
    unittest.main()
