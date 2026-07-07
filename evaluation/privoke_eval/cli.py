from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

from tqdm import tqdm

from .datasets import DATASET_SPECS, load_examples
from .metrics import compute_metrics
from .reporting import print_summary, save_batch_report, save_summary
from .runners import run_ner, run_pipeline, run_regex
from .types import EvaluationFailure, EvaluationSummary


DEFAULT_BACKENDS = ("streamed", "local", "openai")


def check_client_runtime_importable() -> None:
    try:
        import privoke_client_runtime  # noqa: F401
    except ImportError:
        print(
            "ERROR: privoke_client_runtime is not installed.\n"
            "Install the client runtime first, for example:\n"
            "    pip install -r evaluation/requirements.txt\n"
            "or run the evaluation container defined in evaluation/Dockerfile.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _resolve_backends(args) -> list[str | None]:
    if args.layer != "pipeline":
        return [None]
    if args.all_backends:
        return list(DEFAULT_BACKENDS)
    if args.backend:
        return [args.backend]
    return [None]


def _resolve_layers(args) -> list[str]:
    if args.all_layers:
        return ["regex", "ner", "pipeline"]
    return [args.layer]


def evaluate_run(
    dataset_name: str,
    dataset_file: Path | None,
    samples: int,
    examples,
    spec,
    layer: str,
    backend: str | None,
    output_dir: Path,
    quiet: bool = False,
) -> EvaluationSummary:
    active_backend = backend if layer == "pipeline" else None
    if layer == "pipeline" and active_backend is None:
        active_backend = os.getenv("PRIVOKE_LLM_CHOICE", "streamed")

    y_true: list[int] = []
    y_pred: list[int] = []
    latencies_ms: list[float] = []
    failures: list[EvaluationFailure] = []
    errors = 0

    iterator = tqdm(examples, desc=f"Evaluating {dataset_name} / {layer}") if not quiet else examples
    for index, example in enumerate(iterator):
        try:
            if layer == "pipeline":
                outcome = run_pipeline(example.text, active_backend)
            elif layer == "regex":
                outcome = run_regex(example.text)
            else:
                outcome = run_ner(example.text)
        except Exception as exc:  # noqa: BLE001
            errors += 1
            y_true.append(int(example.expected_has_pii))
            y_pred.append(0)
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
                )
            )
            continue

        y_true.append(int(example.expected_has_pii))
        y_pred.append(int(outcome.detected_has_pii))
        latencies_ms.append(outcome.elapsed_ms)

        if example.expected_has_pii != outcome.detected_has_pii:
            failures.append(
                EvaluationFailure(
                    index=index,
                    text=example.text[:240],
                    expected_has_pii=example.expected_has_pii,
                    detected_action=outcome.action,
                    detected_categories=outcome.categories,
                    failure_type="false_negative" if example.expected_has_pii else "false_positive",
                    expected_categories=example.expected_categories,
                )
            )

    metrics = compute_metrics(y_true, y_pred, latencies_ms)
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
            "streaming_dataset": spec.is_streaming,
        },
    )

    output_path = save_summary(summary, output_dir)
    return replace(summary, output_path=output_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate the PriVoke client runtime against privacy and NER datasets.",
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
        help="Local JSON or JSONL dataset file for --dataset local-jsonl.",
    )
    parser.add_argument(
        "--layer",
        choices=("pipeline", "regex", "ner"),
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
        help="Run pipeline evaluations for streamed, local, and OpenAI backends.",
    )
    parser.add_argument(
        "--all-layers",
        action="store_true",
        help="Run regex, ner, and pipeline evaluations.",
    )
    parser.add_argument(
        "--samples",
        default="300",
        help="Number of examples to evaluate, or 'all' for the full dataset.",
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

    check_client_runtime_importable()

    samples: int | None
    if args.samples == "all":
        samples = None
    else:
        samples = int(args.samples)
        if samples <= 0:
            raise SystemExit("--samples must be a positive integer or 'all'.")

    spec, examples = load_examples(args.dataset, samples, args.dataset_file)

    if args.layer == "pipeline" or args.all_layers:
        print(
            "Pipeline evaluations use the active semantic backend. "
            "Streamed mode needs the model-streaming service, local mode needs LM Studio-compatible configuration, and OpenAI mode needs OPENAI_API_KEY."
        )

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
                layer=layer,
                backend=backend,
                output_dir=args.output_dir,
                quiet=args.quiet,
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
