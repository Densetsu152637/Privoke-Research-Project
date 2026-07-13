from __future__ import annotations

import json
from contextlib import redirect_stdout
from io import StringIO
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from privoke_eval.cli import build_parser, evaluate_run, main
from privoke_eval.reporting import print_summary
from privoke_eval.types import (
    DatasetLoadResult,
    DatasetSpec,
    DetectionOutcome,
    EvaluationExample,
)


class CliTests(unittest.TestCase):
    def test_parser_accepts_english_only(self) -> None:
        args = build_parser().parse_args(
            ["--dataset", "piimb", "--english-only"]
        )
        self.assertTrue(args.english_only)

    def test_positive_only_dataset_rejects_balanced_sampling(self) -> None:
        argv = [
            "evaluate.py",
            "--dataset",
            "gretel-finance",
            "--samples",
            "50",
            "--sampling",
            "balanced",
            "--backend",
            "streamed",
        ]
        with patch("sys.argv", argv), self.assertRaises(SystemExit) as raised:
            main()

        self.assertIn("positive-only recall benchmark", str(raised.exception))
        self.assertIn("--sampling random", str(raised.exception))

    def test_end_to_end_report_keeps_research_metadata(self) -> None:
        examples = [
            EvaluationExample("pii one", True, ("IDENTITY",), {"example_id": "one"}),
            EvaluationExample("pii two", True, ("EMAIL",), {"example_id": "two"}),
            EvaluationExample("clean one", False, metadata={"example_id": "three"}),
            EvaluationExample("clean two", False, metadata={"example_id": "four"}),
        ]
        outcomes = iter(
            (
                DetectionOutcome("BLOCK", ("IDENTITY",), None, 10.0, sensitivity="S2"),
                DetectionOutcome("ALLOW", (), None, 10.0),
                DetectionOutcome("WARN", ("IDENTITY",), None, 10.0, sensitivity="S1"),
                DetectionOutcome("ALLOW", (), None, 10.0),
            )
        )

        def fake_run_pipeline(_text: str, _backend: str | None) -> DetectionOutcome:
            return next(outcomes)

        load_result = DatasetLoadResult(
            examples=examples,
            rows_seen=4,
            eligible_rows=4,
            duplicate_rows=0,
            population_label_counts={"pii": 2, "clean": 2},
            selected_label_counts={"pii": 2, "clean": 2},
            sampling_strategy="balanced",
            sampling_seed=42,
            population_scan_complete=True,
        )
        spec = DatasetSpec(
            "test",
            "test gold data",
            loader=lambda *_: load_result,
            research_role="primary",
            ground_truth="audited test labels",
        )

        with tempfile.TemporaryDirectory() as directory, patch(
            "privoke_eval.cli.run_pipeline", side_effect=fake_run_pipeline
        ):
            summary = evaluate_run(
                "test",
                None,
                4,
                examples,
                spec,
                load_result,
                "pipeline",
                "streamed",
                Path(directory),
                quiet=True,
                bootstrap_iterations=20,
                seed=42,
                run_name="balanced seed 42",
            )
            payload = json.loads(summary.output_path.read_text(encoding="utf-8"))

        self.assertTrue(summary.output_path.name.endswith("_balanced-seed-42_results.json"))
        self.assertEqual(payload["metrics"]["balanced_accuracy"], 0.5)
        self.assertEqual(payload["metadata"]["sampling"]["selected_label_counts"], {"pii": 2, "clean": 2})
        self.assertEqual(len(payload["metadata"]["sampling"]["selected_example_ids"]), 4)
        self.assertEqual(payload["metadata"]["language_filter"], "all")
        self.assertEqual(
            payload["metadata"]["prediction_diagnostics"]["sensitivity_counts"],
            {"S0": 2, "S1": 1, "S2": 1},
        )
        category_recall = payload["metrics"]["prompt_detection_recall_by_source_category"]
        self.assertEqual(category_recall["IDENTITY"]["recall"], 1.0)
        self.assertEqual(category_recall["EMAIL"]["recall"], 0.0)

        output = StringIO()
        with redirect_stdout(output):
            print_summary(summary)
        rendered = output.getvalue()
        self.assertIn("Balanced accuracy (main score)", rendered)
        self.assertIn("Sensitive prompts caught: 1/2", rendered)
        self.assertNotIn("Bootstrap Iterations", rendered)

    def test_positive_only_dataset_reports_recall_without_binary_scores(self) -> None:
        examples = [
            EvaluationExample("pii one", True, metadata={"example_id": "one"}),
            EvaluationExample("pii two", True, metadata={"example_id": "two"}),
        ]
        outcomes = iter(
            (
                DetectionOutcome("BLOCK", ("IDENTITY",), None, 10.0, sensitivity="S2"),
                DetectionOutcome("ALLOW", (), None, 10.0),
            )
        )

        def fake_run_pipeline(_text: str, _backend: str | None) -> DetectionOutcome:
            return next(outcomes)

        load_result = DatasetLoadResult(
            examples=examples,
            rows_seen=2,
            eligible_rows=2,
            duplicate_rows=0,
            population_label_counts={"pii": 2, "clean": 0},
            selected_label_counts={"pii": 2, "clean": 0},
            sampling_strategy="random",
            sampling_seed=42,
            population_scan_complete=True,
        )
        spec = DatasetSpec(
            "positive-test",
            "positive-only data",
            loader=lambda *_: load_result,
            research_role="secondary",
            ground_truth="explicit PII spans",
            evaluation_mode="positive-only",
        )

        with tempfile.TemporaryDirectory() as directory, patch(
            "privoke_eval.cli.run_pipeline", side_effect=fake_run_pipeline
        ):
            summary = evaluate_run(
                "positive-test",
                None,
                2,
                examples,
                spec,
                load_result,
                "pipeline",
                "streamed",
                Path(directory),
                quiet=True,
                bootstrap_iterations=20,
                seed=42,
            )

        self.assertEqual(summary.metrics["recall"], 0.5)
        self.assertIsNone(summary.metrics["balanced_accuracy"])
        self.assertIsNone(summary.metrics["specificity"])
        self.assertIsNone(summary.metrics["precision"])
        self.assertIsNone(summary.metrics["f1"])
        self.assertIsNone(summary.metrics["f2"])
        self.assertEqual(summary.metrics["false_negative_rate"], 0.5)

        output = StringIO()
        with redirect_stdout(output):
            print_summary(summary)
        rendered = output.getvalue()
        self.assertIn("Sensitive recall (main score)", rendered)
        self.assertIn("no verified clean class", rendered)
        self.assertNotIn("Balanced accuracy (main score)", rendered)

    def test_detection_is_independent_of_enforcement_action(self) -> None:
        detected_but_allowed = DetectionOutcome(
            "ALLOW",
            ("IDENTITY",),
            None,
            10.0,
            sensitivity="S1",
        )
        blocked_without_detection = DetectionOutcome("BLOCK", (), None, 10.0)

        self.assertTrue(detected_but_allowed.detected_sensitive)
        self.assertFalse(detected_but_allowed.intervened)
        self.assertFalse(blocked_without_detection.detected_sensitive)
        self.assertTrue(blocked_without_detection.intervened)


if __name__ == "__main__":
    unittest.main()
