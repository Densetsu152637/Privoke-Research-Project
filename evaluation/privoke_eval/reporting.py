from __future__ import annotations

import json
import re
from dataclasses import asdict, replace
from pathlib import Path
from typing import Iterable

from tabulate import tabulate

from .types import EvaluationSummary


def _serialisable_summary(summary: EvaluationSummary) -> dict:
    payload = asdict(summary)
    payload["output_path"] = str(summary.output_path) if summary.output_path is not None else None
    return payload


def _percent(value: object) -> str:
    return "not defined" if value is None else f"{float(value) * 100:.1f}%"


def _score_with_interval(summary: EvaluationSummary, name: str) -> str:
    value = summary.metrics.get(name)
    rendered = _percent(value)
    intervals = summary.metrics.get("confidence_intervals_95", {})
    interval = intervals.get(name) if isinstance(intervals, dict) else None
    if isinstance(interval, dict) and interval.get("low") is not None and interval.get("high") is not None:
        rendered += f" (95% CI {_percent(interval['low'])}–{_percent(interval['high'])})"
    return rendered


def print_summary(summary: EvaluationSummary) -> None:
    title = summary.dataset
    if summary.backend:
        title = f"{title} / {summary.backend}"

    print()
    print(f"=== PriVoke Evaluation: {title} ({summary.layer}) ===")
    print()
    print("Scoring signal: PriVoke's returned privacy classification; ALLOW/WARN/BLOCK is not scored.")
    print()

    positive_only = summary.metadata.get("evaluation_mode") == "positive-only"
    if positive_only:
        metric_rows = [
            ["Sensitive recall (main score)", _score_with_interval(summary, "recall")],
            ["Miss rate", _score_with_interval(summary, "false_negative_rate")],
        ]
    else:
        metric_rows = [
            ["Balanced accuracy (main score)", _score_with_interval(summary, "balanced_accuracy")],
            ["Sensitive recall", _score_with_interval(summary, "recall")],
            ["Miss rate", _score_with_interval(summary, "false_negative_rate")],
            ["Non-sensitive specificity", _score_with_interval(summary, "specificity")],
            ["False-positive rate", _score_with_interval(summary, "false_positive_rate")],
            ["Precision", _score_with_interval(summary, "precision")],
            ["F1", _score_with_interval(summary, "f1")],
            ["F2 (recall-weighted)", _score_with_interval(summary, "f2")],
        ]
    print(tabulate(metric_rows, headers=["Research metric", "Result"], tablefmt="github"))

    tp = int(summary.metrics.get("true_positives", 0))
    tn = int(summary.metrics.get("true_negatives", 0))
    fp = int(summary.metrics.get("false_positives", 0))
    fn = int(summary.metrics.get("false_negatives", 0))
    sensitive_total = tp + fn
    clean_total = tn + fp

    print()
    print("Plain-language counts:")
    print(f"  Sensitive prompts caught: {tp}/{sensitive_total}")
    print(f"  Sensitive prompts not detected: {fn}/{sensitive_total}")
    if positive_only:
        print("  Non-sensitive performance: not measured (no verified clean class)")
    else:
        print(f"  Non-sensitive prompts correctly not detected: {tn}/{clean_total}")
        print(f"  Non-sensitive prompts incorrectly detected: {fp}/{clean_total}")
    print(f"  Runtime errors: {summary.errors}")
    print(f"  Successful-analysis coverage: {_percent(summary.metrics.get('coverage'))}")

    if summary.errors:
        print()
        print("Paper-result warning: runtime errors occurred. Fix them and rerun before reporting these scores.")

    role = summary.metadata.get("research_role")
    if role != "primary":
        print()
        print(f"Dataset note: this is a {role} benchmark.")
        print(f"  {summary.metadata.get('ground_truth', summary.dataset_description)}")
    if int(summary.metrics.get("evaluated_samples", 0)) < 100:
        print()
        print("Sample-size caution: fewer than 100 prompts were evaluated. Treat this as a test run, not a paper result.")
    if summary.failures:
        print(f"Detailed prediction disagreements are saved in the JSON report ({len(summary.failures)} records).")


def save_summary(summary: EvaluationSummary, output_dir: Path, run_name: str | None = None) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    backend_suffix = f"_{summary.backend}" if summary.backend else ""
    run_suffix = ""
    if run_name:
        safe_run_name = re.sub(r"[^A-Za-z0-9._-]+", "-", run_name).strip("-._")
        if not safe_run_name:
            raise ValueError("--run-name must contain at least one letter or number.")
        run_suffix = f"_{safe_run_name}"
    output_path = output_dir / f"{summary.dataset}_{summary.layer}{backend_suffix}{run_suffix}_results.json"
    payload = _serialisable_summary(replace(summary, output_path=output_path))
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return output_path


def save_batch_report(summaries: Iterable[EvaluationSummary], output_dir: Path, filename: str = "batch_results.json") -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / filename
    payload = [_serialisable_summary(summary) for summary in summaries]
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return output_path
