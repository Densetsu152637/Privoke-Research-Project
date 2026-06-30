"""
Evaluate the PriVoke client-runtime detector against the AI4Privacy PII
masking dataset (or CoNLL-2003 NER dataset).

Usage
-----
    python evaluate.py --dataset ai4privacy --samples 500
    python evaluate.py --dataset conll2003 --samples 500
    python evaluate.py --dataset ai4privacy --samples 200 --layer regex

--layer can be: pipeline (default, full detector), regex, ner
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

os.environ.setdefault("PRIVOKE_LLM_CHOICE", "local")

from datasets import load_dataset
from sklearn.metrics import precision_score, recall_score, f1_score
from tabulate import tabulate
from tqdm import tqdm


def check_client_runtime_importable() -> None:
    """
    """
    try:
        import privoke_client_runtime  
    except ImportError:
        print(
            "ERROR: privoke_client_runtime is not installed.\n"
            "Run this first:\n"
            "    pip install -e ../services/client-runtime\n"
            "(adjust the path if your repo layout differs)",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Dataset loaders — each returns a list of (text, expected_has_pii) tuples
# ---------------------------------------------------------------------------

def load_ai4privacy(num_samples: int) -> List[Tuple[str, bool]]:
    """
    AI4Privacy PII masking dataset (300k version). Confirmed working schema:
    'source_text' (raw text) and 'privacy_mask' (list of PII span dicts,
    empty list when the sample has no PII).
    """
    ds = load_dataset("ai4privacy/pii-masking-300k", split="train", streaming=True)
    samples = []
    for row in ds:
        text = row.get("source_text")
        if not text:
            continue
        mask = row.get("privacy_mask") or []
        has_pii = len(mask) > 0
        samples.append((text, has_pii))
        if len(samples) >= num_samples:
            break
    return samples


def load_conll2003(num_samples: int) -> List[Tuple[str, bool]]:
    """
    CoNLL-2003 NER dataset. A sentence is treated as containing PII if it
    has at least one PERSON, ORG, or LOC entity tag (non-"O").
    """
    ds = load_dataset(
        "eriktks/conll2003",
        revision="refs/convert/parquet",
        split="test",
    )
    tag_names = ds.features["ner_tags"].feature.names

    samples = []
    for row in ds:
        tokens = row["tokens"]
        tags = [tag_names[t] for t in row["ner_tags"]]
        text = " ".join(tokens)
        has_entity = any(tag != "O" for tag in tags)
        samples.append((text, has_entity))
        if len(samples) >= num_samples:
            break
    return samples


DATASET_LOADERS = {
    "ai4privacy": load_ai4privacy,
    "conll2003": load_conll2003,
}


# ---------------------------------------------------------------------------
# Detector runners — each calls into the privoke_client_runtime package
# ---------------------------------------------------------------------------

def run_pipeline(text: str) -> Dict[str, Any]:
    """Run the full client-runtime pipeline (regex + NER + semantic)."""
    from privoke_client_runtime.pipeline import pipeline_analyse_text

    started = time.perf_counter()
    result, action = pipeline_analyse_text(text)
    elapsed_ms = (time.perf_counter() - started) * 1000

    return {
        "action": action.name,
        "categories": [c.name for c in result.classification.categories()] if result else [],
        "confidence": result.confidence if result else None,
        "elapsed_ms": elapsed_ms,
    }


def run_regex_only(text: str) -> Dict[str, Any]:
    """Run only the regex rule detector layer."""
    from privoke_client_runtime.detection import normalize_text
    from privoke_client_runtime.regex.rule_detector import RuleDetector
    from privoke_client_runtime.pipeline import strongest_result

    started = time.perf_counter()
    results = RuleDetector().analyze(normalize_text(text))
    result, action = strongest_result(results)
    elapsed_ms = (time.perf_counter() - started) * 1000

    return {
        "action": action.name,
        "categories": [c.name for c in result.classification.categories()] if result else [],
        "confidence": result.confidence if result else None,
        "elapsed_ms": elapsed_ms,
    }


def run_ner_only(text: str) -> Dict[str, Any]:
    """Run only the spaCy NER detector layer."""
    from privoke_client_runtime.detection import normalize_text
    from privoke_client_runtime.NER import EntityNERDetector
    from privoke_client_runtime.pipeline import strongest_result

    started = time.perf_counter()
    results = EntityNERDetector().extract_entities(normalize_text(text))
    result, action = strongest_result(results)
    elapsed_ms = (time.perf_counter() - started) * 1000

    return {
        "action": action.name,
        "categories": [c.name for c in result.classification.categories()] if result else [],
        "confidence": result.confidence if result else None,
        "elapsed_ms": elapsed_ms,
    }


LAYER_RUNNERS = {
    "pipeline": run_pipeline,
    "regex": run_regex_only,
    "ner": run_ner_only,
}


# ---------------------------------------------------------------------------
# Evaluation loop
# ---------------------------------------------------------------------------

def evaluate(samples: List[Tuple[str, bool]], layer: str) -> Dict[str, Any]:
    runner = LAYER_RUNNERS[layer]

    y_true: List[int] = []
    y_pred: List[int] = []
    elapsed_times: List[float] = []
    errors = 0
    failures: List[Dict[str, Any]] = []   # false negatives / false positives

    for text, expected_has_pii in tqdm(samples, desc=f"Evaluating ({layer})"):
        try:
            response = runner(text)
        except Exception as exc:
            if errors < 3:
                import traceback
                print(f"\n--- ERROR on sample (errors={errors}) ---")
                traceback.print_exc()
            errors += 1
            y_true.append(int(expected_has_pii))
            y_pred.append(0)
            continue

        detected_has_pii = response["action"] in ("WARN", "BLOCK")
        elapsed_times.append(response["elapsed_ms"])

        y_true.append(int(expected_has_pii))
        y_pred.append(int(detected_has_pii))

        if expected_has_pii != detected_has_pii:
            failures.append({
                "text": text[:150],
                "expected_has_pii": expected_has_pii,
                "detected_action": response["action"],
                "detected_categories": response["categories"],
                "type": "false_negative" if expected_has_pii else "false_positive",
            })

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    accuracy = sum(t == p for t, p in zip(y_true, y_pred)) / len(y_true)

    avg_latency = sum(elapsed_times) / len(elapsed_times) if elapsed_times else 0.0

    return {
        "layer": layer,
        "total_samples": len(samples),
        "errors": errors,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "avg_latency_ms": round(avg_latency, 3),
        "failures": failures,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(dataset_name: str, results: Dict[str, Any]) -> None:
    print()
    print(f"=== PriVoke Detector Evaluation: {dataset_name} ({results['layer']} layer) ===")
    print()

    table = [
        ["Total samples", results["total_samples"]],
        ["Errors", results["errors"]],
        ["Precision", results["precision"]],
        ["Recall", results["recall"]],
        ["F1 Score", results["f1"]],
        ["Accuracy", results["accuracy"]],
        ["Avg latency (ms)", results["avg_latency_ms"]],
    ]
    print(tabulate(table, headers=["Metric", "Value"], tablefmt="github"))

    fn_count = sum(1 for f in results["failures"] if f["type"] == "false_negative")
    fp_count = sum(1 for f in results["failures"] if f["type"] == "false_positive")
    print()
    print(f"False negatives (missed PII): {fn_count}")
    print(f"False positives (over-flagged): {fp_count}")

    if results["failures"]:
        print()
        print("Sample failures (first 5):")
        for failure in results["failures"][:5]:
            print(f"  [{failure['type']}] action={failure['detected_action']} "
                  f"categories={failure['detected_categories']}")
            print(f"    text: {failure['text']}")


def save_report(dataset_name: str, results: Dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{dataset_name}_{results['layer']}_results.json"
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return output_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate PriVoke detector against public datasets.")
    parser.add_argument(
        "--dataset",
        choices=list(DATASET_LOADERS.keys()),
        required=True,
        help="Public dataset to evaluate against.",
    )
    parser.add_argument(
        "--layer",
        choices=list(LAYER_RUNNERS.keys()),
        default="pipeline",
        help="Detector layer to test (default: pipeline = full detector).",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=300,
        help="Number of dataset samples to evaluate (default: 300).",
    )
    parser.add_argument(
        "--output-dir",
        default="./results",
        help="Directory to write JSON results to.",
    )
    args = parser.parse_args()

    check_client_runtime_importable()

    if args.layer == "pipeline":
        backend = os.environ.get("PRIVOKE_LLM_CHOICE", "local")
        print(
            f"NOTE: --layer pipeline runs the full detector including the "
            f"semantic classifier (backend={backend}).\n"
            f"  - backend=streamed needs model-streaming-service running + "
            f"generated gRPC stubs\n"
            f"  - backend=local needs LM Studio (or compatible) running at "
            f"LM_STUDIO_BASE_URL\n"
            f"  - backend=openai needs OPENAI_API_KEY set\n"
            f"If none of these are available, use --layer regex or --layer ner "
            f"instead, which have no external dependencies.\n"
        )

    print(f"Loading dataset '{args.dataset}' ({args.samples} samples)...")
    samples = DATASET_LOADERS[args.dataset](args.samples)
    print(f"Loaded {len(samples)} samples.")

    results = evaluate(samples, args.layer)
    print_report(args.dataset, results)

    output_path = save_report(args.dataset, results, Path(args.output_dir))
    print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()