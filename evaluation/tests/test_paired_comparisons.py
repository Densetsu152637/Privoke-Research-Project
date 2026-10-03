"""Validate comparison integrity independently of detector scores."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("paired_comparisons", Path(__file__).parents[1] / "compare-paired-runs.py")
paired = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paired)


def report(*rows):
    return {"metadata": {"predictions": [
        {"example_id": name, "group_id": group, "expected_has_pii": truth,
         "detected_sensitive": prediction, "status": "ok"}
        for name, group, truth, prediction in rows]}}


class PairedComparisonTests(unittest.TestCase):
    def test_reordered_ids_align_before_scoring(self):
        baseline = report(("a", "doc1", True, False), ("b", "doc2", False, True))
        updated = report(("b", "doc2", False, False), ("a", "doc1", True, True))
        self.assertEqual(paired.rate_changes(paired.align(baseline, updated), [0, 1]), (1.0, 1.0, 1.0))

    def test_different_examples_cannot_be_compared(self):
        with self.assertRaisesRegex(ValueError, "different example IDs"):
            paired.align(report(("a", "doc1", True, True)), report(("b", "doc1", True, True)))

    def test_changed_labels_or_groups_cannot_be_compared(self):
        baseline = report(("a", "doc1", True, True))
        for changed in (report(("a", "doc1", False, True)), report(("a", "doc2", True, True))):
            with self.assertRaisesRegex(ValueError, "Labels or source groups"):
                paired.align(baseline, changed)

    def test_duplicate_ids_and_errors_are_rejected(self):
        row = ("a", "doc1", True, True)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            paired.align(report(row, row), report(row))
        erroneous = report(row)
        erroneous["metadata"]["predictions"][0]["status"] = "error"
        with self.assertRaisesRegex(ValueError, "runtime errors"):
            paired.align(erroneous, report(row))

    def test_single_class_resample_is_not_reported_as_two_class_change(self):
        same = report(("a", "doc1", True, True))
        self.assertIsNone(paired.rate_changes(paired.align(same, same), [0]))
