from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Iterable

from tabulate import tabulate

from .types import EvaluationSummary


def _serialisable_summary(summary: EvaluationSummary) -> dict:
    payload = asdict(summary)
    payload["output_path"] = str(summary.output_path) if summary.output_path is not None else None
    return payload


def print_summary(summary: EvaluationSummary) -> None:
    title = summary.dataset
    if summary.backend:
        title = f"{title} / {summary.backend}"

    print()
    print(f"=== PriVoke Evaluation: {title} ({summary.layer}) ===")
    print()

    metric_rows = [
        ["Requested samples", summary.requested_samples],
        ["Loaded samples", summary.loaded_samples],
        ["Errors", summary.errors],
    ]
    metric_rows.extend([[name.replace("_", " ").title(), value] for name, value in summary.metrics.items()])
    print(tabulate(metric_rows, headers=["Metric", "Value"], tablefmt="github"))

    false_negatives = [failure for failure in summary.failures if failure.failure_type == "false_negative"]
    false_positives = [failure for failure in summary.failures if failure.failure_type == "false_positive"]

    print()
    print(f"False negatives (missed PII): {len(false_negatives)}")
    print(f"False positives (over-flagged): {len(false_positives)}")

    if summary.failures:
        print()
        print("Sample failures (first 5):")
        for failure in summary.failures[:5]:
            print(
                f"  [{failure.failure_type}] action={failure.detected_action} "
                f"categories={list(failure.detected_categories)}"
            )
            print(f"    text: {failure.text}")


def save_summary(summary: EvaluationSummary, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    backend_suffix = f"_{summary.backend}" if summary.backend else ""
    output_path = output_dir / f"{summary.dataset}_{summary.layer}{backend_suffix}_results.json"
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
