from __future__ import annotations

import argparse
import hashlib
import os
import platform
from collections import Counter
from dataclasses import replace
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from tqdm import tqdm

from .datasets import (
    DATASET_SPECS,
    SAMPLING_STRATEGIES,
    DatasetValidationError,
    load_examples,
)
from .metrics import compute_metrics
from .reporting import print_summary, save_batch_report, save_summary
from .runners import check_runtime_available, run_pipeline, runtime_url
from .types import EvaluationFailure, EvaluationSummary


DEFAULT_BACKENDS = ("streamed", "openai")


def _software_versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for package in ("datasets", "numpy", "scikit-learn"):
        try:
            versions[package] = version(package)
        except PackageNotFoundError:
            versions[package] = "not-installed"
    return versions


def _resolve_backends(args) -> list[str | None]:
    if args.layer != "pipeline":
        return [None]
    if args.all_backends:
        return list(DEFAULT_BACKENDS)
    if args.backend:
        return [args.backend]
    return [None]


def _resolve_layers(args) -> list[str]:
    return ["pipeline"]


def evaluate_run(
    dataset_name: str,
    dataset_file: Path | None,
    samples: int,
    examples,
    spec,
    load_result,
    layer: str,
    backend: str | None,
    output_dir: Path,
    quiet: bool = False,
    bootstrap_iterations: int = 2000,
    seed: int = 42,
    run_name: str | None = None,
    english_only: bool = False,
) -> EvaluationSummary:
    active_backend = backend if layer == "pipeline" else None
    if layer == "pipeline" and active_backend is None:
        active_backend = os.getenv("PRIVOKE_LLM_CHOICE", "streamed")

    y_true: list[int] = []
    y_pred: list[int] = []
    failures: list[EvaluationFailure] = []
    errors = 0
    error_truths: list[int] = []
    evaluated_group_ids: list[str] = []
    category_totals: Counter[str] = Counter()
    category_detected: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    sensitivity_counts: Counter[str] = Counter()
    returned_category_counts: Counter[str] = Counter()

    iterator = tqdm(examples, desc=f"Evaluating {dataset_name} / {layer}") if not quiet else examples
    for index, example in enumerate(iterator):
        try:
            outcome = run_pipeline(example.text, active_backend)
        except Exception as exc:  # noqa: BLE001
            errors += 1
            error_truths.append(int(example.expected_has_pii))
            failures.append(
                EvaluationFailure(
                    index=index,
                    text=example.text[:240],
                    expected_has_pii=example.expected_has_pii,
                    detected_action="ERROR",
                    detected_categories=(),
                    failure_type="error",
                    expected_categories=example.expected_categories,
                    error=str(exc),
                    example_id=str(example.metadata.get("example_id", index)),
                    text_truncated=len(example.text) > 240,
                )
            )
            continue

        detected_sensitive = outcome.detected_sensitive
        action_counts[outcome.action] += 1
        sensitivity_counts[outcome.sensitivity] += 1
        for category in set(outcome.categories):
            returned_category_counts[category] += 1
        y_true.append(int(example.expected_has_pii))
        y_pred.append(int(detected_sensitive))
        evaluated_group_ids.append(
            str(example.metadata.get("group_id") or example.metadata.get("example_id", index))
        )
        if example.expected_has_pii:
            for category in set(example.expected_categories):
                category_totals[category] += 1
                if detected_sensitive:
                    category_detected[category] += 1
        if example.expected_has_pii != detected_sensitive:
            failures.append(
                EvaluationFailure(
                    index=index,
                    text=example.text[:240],
                    expected_has_pii=example.expected_has_pii,
                    detected_action=outcome.action,
                    detected_categories=outcome.categories,
                    failure_type="false_negative" if example.expected_has_pii else "false_positive",
                    expected_categories=example.expected_categories,
                    example_id=str(example.metadata.get("example_id", index)),
                    text_truncated=len(example.text) > 240,
                )
            )

    metrics = compute_metrics(
        y_true,
        y_pred,
        errors=errors,
        loaded_samples=len(examples),
        bootstrap_iterations=bootstrap_iterations,
        seed=seed,
        group_ids=evaluated_group_ids,
        error_truths=error_truths,
    )
    metrics["prompt_detection_recall_by_source_category"] = {
        category: {
            "support": category_totals[category],
            "detected": category_detected[category],
            "recall": round(category_detected[category] / category_totals[category], 4),
        }
        for category in sorted(category_totals)
    }
    if spec.evaluation_mode == "positive-only":
        intervals = dict(metrics.get("confidence_intervals_95", {}))
        for unsupported in (
            "accuracy",
            "balanced_accuracy",
            "specificity",
            "false_positive_rate",
            "precision",
            "negative_predictive_value",
            "f1",
            "f2",
        ):
            metrics[unsupported] = None
            intervals[unsupported] = None
        metrics["confidence_intervals_95"] = intervals
    selected_ids = [str(example.metadata.get("example_id", index)) for index, example in enumerate(examples)]
    selection_digest = hashlib.sha256("\n".join(sorted(selected_ids)).encode("utf-8")).hexdigest()
    summary = EvaluationSummary(
        dataset=dataset_name,
        layer=layer,
        backend=active_backend,
        requested_samples=samples,
        loaded_samples=len(examples),
        errors=errors,
        metrics=metrics,
        failures=failures,
        dataset_description=spec.description,
        metadata={
            "dataset_file": str(dataset_file) if dataset_file else None,
            "backend_requested": backend,
            "run_name": run_name,
            "streaming_dataset": spec.is_streaming,
            "runtime_url": runtime_url(),
            "research_role": spec.research_role,
            "ground_truth": spec.ground_truth,
            "dataset_revision": spec.revision,
            "language_filter": "english" if english_only else "all",
            "software_versions": _software_versions(),
            "prediction_diagnostics": {
                "action_counts": dict(sorted(action_counts.items())),
                "sensitivity_counts": dict(sorted(sensitivity_counts.items())),
                "returned_category_prompt_counts": dict(
                    sorted(returned_category_counts.items())
                ),
            },
            "independence_group": spec.independence_group,
            "evaluation_mode": spec.evaluation_mode,
            "sampling": {
                "strategy": load_result.sampling_strategy,
                "seed": load_result.sampling_seed,
                "rows_seen": load_result.rows_seen,
                "eligible_rows": load_result.eligible_rows,
                "duplicate_rows_removed": load_result.duplicate_rows,
                "population_scan_complete": load_result.population_scan_complete,
                "population_label_counts": load_result.population_label_counts,
                "selected_label_counts": load_result.selected_label_counts,
                "exclusions": load_result.exclusions,
                "selected_ids_sha256": selection_digest,
                "selected_example_ids": selected_ids if len(selected_ids) <= 5000 else None,
                "selected_group_count": len(
                    {
                        str(example.metadata.get("group_id") or example.metadata.get("example_id", index))
                        for index, example in enumerate(examples)
                    }
                ),
            },
            "metric_configuration": {
                "implementation": "scikit-learn",
                "bootstrap_iterations": bootstrap_iterations,
                "bootstrap_seed": seed,
                "confidence_level": 0.95,
                "interval_methods": (
                    "Wilson score intervals for simple rates when prompts are independent; "
                    "cluster bootstrap for repeated source-document groups; percentile bootstrap for composite scores"
                ),
                "bootstrap_method": (
                    "cluster bootstrap by source document when repeated group IDs are present; otherwise "
                    "class-stratified bootstrap"
                ),
            },
            "metric_scope": (
                "Only rows with explicit PII annotations are eligible. Sensitive recall measures whether PriVoke "
                "returned a non-default privacy classification; this dataset does not provide verified clean ground "
                "truth, so negative-class and two-class metrics such as balanced accuracy, specificity, precision, "
                "F-scores and NPV are intentionally undefined."
                if spec.evaluation_mode == "positive-only"
                else
                "Dataset PII labels are used as binary sensitivity labels. A returned S1, S2, or S3 sensitivity, "
                "or at least one returned privacy category, is a positive prediction. S0 with no categories is a "
                "negative prediction. ALLOW, WARN, and BLOCK are recorded but do not determine the score. Metrics "
                "measure prompt-level detection, not exact span, category, masking, or action accuracy."
            ),
            "error_handling": "Runtime errors are reported separately and excluded from the confusion matrix.",
        },
    )

    output_path = save_summary(summary, output_dir, run_name=run_name)
    return replace(summary, output_path=output_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate the PriVoke client runtime against dedicated PII datasets.",
    )
    parser.add_argument(
        "--dataset",
        choices=[*sorted(DATASET_SPECS.keys()), "local-jsonl"],
        required=True,
        help="Dataset to evaluate against.",
    )
    parser.add_argument(
        "--dataset-file",
        type=Path,
        help="Local JSON or JSONL file for --dataset local-jsonl.",
    )
    parser.add_argument(
        "--layer",
        choices=("pipeline",),
        default="pipeline",
        help="Detector layer to evaluate.",
    )
    parser.add_argument(
        "--backend",
        choices=DEFAULT_BACKENDS,
        help="Semantic backend for --layer pipeline. Defaults to the runtime environment.",
    )
    parser.add_argument(
        "--all-backends",
        action="store_true",
        help="Run pipeline evaluations for streamed and OpenAI backends.",
    )
    parser.add_argument(
        "--samples",
        default="300",
        help="Number of examples to evaluate, or 'all' for the full dataset.",
    )
    parser.add_argument(
        "--sampling",
        choices=SAMPLING_STRATEGIES,
        default="balanced",
        help=(
            "Finite-sample selection method. 'balanced' draws equal sensitive/clean classes for binary datasets; "
            "--samples all always evaluates the full eligible split."
        ),
    )
    parser.add_argument(
        "--english-only",
        action="store_true",
        help="Keep English prompts only before duplicate removal and sampling.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed used for sampling and confidence intervals (default: 42).",
    )
    parser.add_argument(
        "--bootstrap-iterations",
        type=int,
        default=2000,
        help="Bootstrap resamples for 95%% confidence intervals (default: 2000).",
    )
    parser.add_argument(
        "--run-name",
        help="Optional reproducible run label added to the result filename (for example balanced_seed42).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./results"),
        help="Directory where JSON reports are written.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress bars.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    samples: int | None
    if args.samples == "all":
        samples = None
    else:
        samples = int(args.samples)
        if samples <= 0:
            raise SystemExit("--samples must be a positive integer or 'all'.")

    if args.bootstrap_iterations < 0:
        raise SystemExit("--bootstrap-iterations must be zero or greater.")

    public_spec = DATASET_SPECS.get(args.dataset)
    if (
        samples is not None
        and public_spec is not None
        and public_spec.evaluation_mode == "positive-only"
        and args.sampling in {"balanced", "stratified"}
    ):
        raise SystemExit(
            f"--sampling {args.sampling} requires a verified clean class, but {args.dataset} is a "
            "positive-only recall benchmark. Use --sampling random (recommended) or sequential."
        )

    try:
        spec, load_result = load_examples(
            args.dataset,
            samples,
            args.dataset_file,
            seed=args.seed,
            strategy=args.sampling,
            english_only=args.english_only,
        )
    except (DatasetValidationError, FileNotFoundError, ValueError) as exc:
        raise SystemExit(f"Dataset validation failed: {exc}") from exc
    examples = load_result.examples
    if not examples:
        raise SystemExit("No eligible examples remained after validation and duplicate removal.")

    try:
        check_runtime_available()
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

    print(
        "Evaluation calls the client-runtime /analyze API and therefore measures "
        "the complete regex + NER + semantic pipeline."
    )
    print(
        f"Dataset role={spec.research_role}; mode={spec.evaluation_mode}; "
        f"sampling={load_result.sampling_strategy}; "
        f"language={'english' if args.english_only else 'all'}; "
        f"selected={load_result.selected_label_counts}."
    )
    if spec.evaluation_mode == "positive-only":
        print(
            "This source does not guarantee clean negative documents. Only explicitly PII-labelled rows "
            "are evaluated, and sensitive recall is the supported score."
        )
    if load_result.exclusions:
        print(f"Excluded ambiguous dataset rows: {load_result.exclusions}.")

    backends = _resolve_backends(args)
    layers = _resolve_layers(args)
    summaries: list[EvaluationSummary] = []

    for layer in layers:
        layer_backends = backends if layer == "pipeline" else [None]
        for backend in layer_backends:
            summary = evaluate_run(
                dataset_name=args.dataset,
                dataset_file=args.dataset_file,
                samples=samples if samples is not None else len(examples),
                examples=examples,
                spec=spec,
                load_result=load_result,
                layer=layer,
                backend=backend,
                output_dir=args.output_dir,
                quiet=args.quiet,
                bootstrap_iterations=args.bootstrap_iterations,
                seed=args.seed,
                run_name=args.run_name,
                english_only=args.english_only,
            )
            summaries.append(summary)
            print_summary(summary)
            if summary.output_path is not None:
                print(f"\nResults saved to: {summary.output_path}")

    if len(summaries) > 1:
        batch_path = save_batch_report(summaries, args.output_dir)
        print(f"\nBatch summary saved to: {batch_path}")


if __name__ == "__main__":
    main()
