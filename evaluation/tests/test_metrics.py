from __future__ import annotations

import unittest

from privoke_eval.metrics import compute_metrics


class MetricsTests(unittest.TestCase):
    def test_binary_metrics_use_expected_confusion_matrix(self) -> None:
        metrics = compute_metrics(
            [1, 1, 0, 0],
            [1, 0, 1, 0],
            bootstrap_iterations=100,
            seed=7,
        )

        self.assertEqual(metrics["true_positives"], 1)
        self.assertEqual(metrics["true_negatives"], 1)
        self.assertEqual(metrics["false_positives"], 1)
        self.assertEqual(metrics["false_negatives"], 1)
        self.assertEqual(metrics["precision"], 0.5)
        self.assertEqual(metrics["recall"], 0.5)
        self.assertEqual(metrics["specificity"], 0.5)
        self.assertEqual(metrics["balanced_accuracy"], 0.5)
        self.assertEqual(metrics["f1"], 0.5)
        self.assertEqual(metrics["f2"], 0.5)
        self.assertEqual(metrics["accuracy"], 0.5)
        self.assertEqual(metrics["false_negative_rate"], 0.5)
        self.assertEqual(metrics["false_positive_rate"], 0.5)
        self.assertEqual(metrics["negative_predictive_value"], 0.5)
        self.assertIsNotNone(metrics["confidence_intervals_95"]["balanced_accuracy"])

    def test_missing_class_is_reported_as_undefined(self) -> None:
        metrics = compute_metrics(
            [1, 1],
            [1, 0],
            bootstrap_iterations=10,
        )

        self.assertIsNone(metrics["specificity"])
        self.assertIsNone(metrics["balanced_accuracy"])

    def test_no_predicted_positive_has_undefined_precision(self) -> None:
        metrics = compute_metrics(
            [1, 0],
            [0, 0],
            bootstrap_iterations=10,
        )

        self.assertIsNone(metrics["precision"])
        self.assertEqual(metrics["f1"], 0.0)

    def test_runtime_errors_reduce_coverage_and_invalidate_paper_run(self) -> None:
        metrics = compute_metrics(
            [1],
            [1],
            errors=1,
            loaded_samples=2,
            error_truths=[0],
            bootstrap_iterations=0,
        )

        self.assertEqual(metrics["coverage"], 0.5)
        self.assertEqual(metrics["non_sensitive_runtime_errors"], 1)
        self.assertEqual(metrics["sensitive_runtime_errors"], 0)
        self.assertFalse(metrics["paper_result_valid"])

    def test_grouped_bootstrap_is_reproducible(self) -> None:
        first = compute_metrics(
            [1, 1, 0, 0],
            [1, 0, 0, 1],
            group_ids=["document-a", "document-a", "document-b", "document-b"],
            bootstrap_iterations=50,
            seed=9,
        )
        second = compute_metrics(
            [1, 1, 0, 0],
            [1, 0, 0, 1],
            group_ids=["document-a", "document-a", "document-b", "document-b"],
            bootstrap_iterations=50,
            seed=9,
        )
        self.assertEqual(first["confidence_intervals_95"], second["confidence_intervals_95"])

    def test_perfect_recall_has_non_degenerate_wilson_interval(self) -> None:
        metrics = compute_metrics(
            [1] * 500,
            [1] * 500,
            bootstrap_iterations=100,
            seed=42,
        )
        interval = metrics["confidence_intervals_95"]["recall"]

        self.assertLess(interval["low"], 1.0)
        self.assertEqual(interval["high"], 1.0)
        self.assertAlmostEqual(interval["low"], 0.9924, places=4)


if __name__ == "__main__":
    unittest.main()
