"""Fail-closed checks for the offline frozen-representation diagnostic."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    if name == "prepare-representation-study":
        # The preparation module's hosted-dataset loader is unused by these pure tests.
        stub = types.ModuleType("privoke_eval.datasets")
        stub.load_examples = None
        sys.modules["privoke_eval.datasets"] = stub
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prep = load_script("prepare-representation-study")
fit = load_script("fit-representation-probe")


class Example:
    def __init__(self, identifier, group, text, label):
        self.text = text
        self.expected_has_pii = label
        self.metadata = {"example_id": identifier, "group_id": group, "source_dataset": "x"}


class RepresentationProbeTests(unittest.TestCase):
    def test_selection_keeps_groups_disjoint_and_balanced(self):
        rows = [Example(f"i{label}{i}", f"g{i // 5}", f"text {label} {i}", bool(label))
                for label in (0, 1) for i in range(250)]
        selected, train, validation, _ = prep.select_rows(rows, [], [], count=250)
        self.assertEqual(500, len(selected))
        self.assertFalse({r.metadata["group_id"] for r in train} &
                         {r.metadata["group_id"] for r in validation})
        self.assertEqual(250, sum(r.expected_has_pii for r in selected))

    def test_protected_text_and_conflicting_normalized_labels_are_excluded(self):
        rows = [Example("a", "ga", "same [at] text", True), Example("b", "gb", "same @ text", False)]
        with self.assertRaisesRegex(ValueError, "eligible positive"):
            prep.select_rows(rows, [], [], count=1)

    def test_feature_validation_rejects_alignment_dimension_and_nonfinite(self):
        source = [{"id": "a", "group_id": "g", "expected_has_pii": True}]
        good = [{"id": "a", "group_id": "g", "expected_has_pii": True,
                 "pooled": [0.0] * 32, "original_binary": False}]
        self.assertEqual(good, fit.validate_feature_rows(good, source))
        with self.assertRaisesRegex(ValueError, "dimensions"):
            fit.validate_feature_rows([{**good[0], "pooled": [0.0]}], source)
        with self.assertRaisesRegex(ValueError, "non-finite"):
            fit.validate_feature_rows([{**good[0], "pooled": [float("nan")] + [0.0] * 31}], source)
        with self.assertRaisesRegex(ValueError, "row count"):
            fit.validate_feature_rows([], source)

    def test_threshold_obeys_floor_and_tie_order(self):
        threshold, metrics = fit.select_threshold(np.array([1, 1, 1, 0, 0]),
                                                   np.array([0.2, 0.8, 0.9, 0.1, 0.8]))
        self.assertGreaterEqual(metrics["recall"], 0.9)
        self.assertEqual(0.2, threshold)
        self.assertEqual(0.5, metrics["specificity"])


if __name__ == "__main__":
    unittest.main()
