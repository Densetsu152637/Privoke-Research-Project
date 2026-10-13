"""Regression for export values; no data, weights, fitting or evaluation."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
from privoke_eval import privacy_heads_v3 as core
core.configure_repository(ROOT)
import torch
from privoke_contracts.classification import Classification

SPEC = importlib.util.spec_from_file_location("ph3_export_finalize", ROOT / "evaluation/finalize-privacy-heads-v3-exports.py")
FINALIZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FINALIZER)


class ExportValueParityTests(unittest.TestCase):
    def values(self):
        first = [(Classification(30), .8), (Classification(28), .7)]
        second = [(Classification(30), .8), (Classification(28), .7)]
        self.assertNotEqual(first, second)  # Identity comparison was the original bug.
        return (FINALIZER.prediction_values(first, ["first", "second"]),
                FINALIZER.prediction_values(second, ["first", "second"]))

    def logits(self):
        return {task: torch.zeros(2, len(labels)) for task, labels in core.LABELS.items()}

    def test_equal_separately_constructed_classifications_accepted(self):
        before, after = self.values()
        report = FINALIZER.assert_values_and_logits(before, after, self.logits(), self.logits(), 2)
        self.assertEqual(report["rows"], 2)
        self.assertTrue(report["finite_logits_exact"])

    def test_changed_packed_value_rejected(self):
        before, after = self.values()
        after[0]["packed"] += 1
        with self.assertRaisesRegex(ValueError, "values differ"):
            FINALIZER.assert_values_and_logits(before, after, self.logits(), self.logits(), 2)

    def test_changed_named_value_rejected(self):
        before, after = self.values()
        after[0]["named"]["sensitivity"] = "S3"
        with self.assertRaisesRegex(ValueError, "values differ"):
            FINALIZER.assert_values_and_logits(before, after, self.logits(), self.logits(), 2)

    def test_changed_confidence_rejected(self):
        before, after = self.values()
        after[0]["confidence"] = .799
        with self.assertRaisesRegex(ValueError, "values differ"):
            FINALIZER.assert_values_and_logits(before, after, self.logits(), self.logits(), 2)

    def test_changed_action_rejected(self):
        before, after = self.values()
        after[0]["action"] = "BLOCK"
        with self.assertRaisesRegex(ValueError, "values differ"):
            FINALIZER.assert_values_and_logits(before, after, self.logits(), self.logits(), 2)

    def test_changed_finite_logit_rejected(self):
        before, after = self.values()
        logits = self.logits()
        logits["category"][0, 0] = 1e-7
        with self.assertRaisesRegex(ValueError, "logits differ"):
            FINALIZER.assert_values_and_logits(before, after, self.logits(), logits, 2)

    def test_nonfinite_logit_rejected(self):
        before, after = self.values()
        for value in (float("nan"), float("inf")):
            logits = self.logits()
            logits["sensitivity"][0, 0] = value
            with self.assertRaisesRegex(ValueError, "nonfinite"):
                FINALIZER.assert_values_and_logits(before, after, self.logits(), logits, 2)

    def test_row_count_and_task_shape_rejected(self):
        before, after = self.values()
        with self.assertRaisesRegex(ValueError, "row count"):
            FINALIZER.assert_values_and_logits(before, after, self.logits(), self.logits(), 1)
        logits = self.logits()
        logits["visibility"] = torch.zeros(2, 5)
        with self.assertRaisesRegex(ValueError, "shape"):
            FINALIZER.assert_values_and_logits(before, after, self.logits(), logits, 2)


if __name__ == "__main__":
    unittest.main()
