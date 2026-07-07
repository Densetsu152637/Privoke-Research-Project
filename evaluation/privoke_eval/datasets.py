from __future__ import annotations

import json
import ast
from pathlib import Path
from typing import Any, Iterable

from datasets import load_dataset

from .types import DatasetSpec, EvaluationExample


def _first_present(mapping: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", [], {}, ()):
            return value
    return None


def _normalise_expected_categories(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item) for item in value if str(item))
    return (str(value),)


def _extract_mask_categories(mask: Any) -> tuple[str, ...]:
    categories: list[str] = []
    if not isinstance(mask, list):
        return ()

    for item in mask:
        if not isinstance(item, dict):
            continue
        category = _first_present(
            item,
            ("category", "label", "entity_type", "entity", "type", "tag"),
        )
        if category is not None:
            category_name = str(category)
            if category_name and category_name not in categories:
                categories.append(category_name)

    return tuple(categories)


def load_ai4privacy(num_samples: int | None) -> list[EvaluationExample]:
    dataset = load_dataset("ai4privacy/pii-masking-300k", split="train", streaming=True)
    examples: list[EvaluationExample] = []

    for row in dataset:
        if not isinstance(row, dict):
            continue

        text = _first_present(row, ("source_text", "text", "prompt"))
        if not isinstance(text, str) or not text.strip():
            continue

        mask = _first_present(row, ("privacy_mask", "pii_mask", "mask")) or []
        categories = _extract_mask_categories(mask)
        expected_has_pii = bool(mask)

        examples.append(
            EvaluationExample(
                text=text,
                expected_has_pii=expected_has_pii,
                expected_categories=categories,
                metadata={"source": "ai4privacy/pii-masking-300k"},
            )
        )

        if num_samples is not None and len(examples) >= num_samples:
            break

    return examples


def load_conll2003(num_samples: int | None) -> list[EvaluationExample]:
    dataset = load_dataset(
        "eriktks/conll2003",
        revision="refs/convert/parquet",
        split="test",
    )
    tag_names = dataset.features["ner_tags"].feature.names
    examples: list[EvaluationExample] = []

    for row in dataset:
        tokens = row["tokens"]
        tags = [tag_names[tag] for tag in row["ner_tags"]]
        text = " ".join(tokens)
        expected_categories = tuple(tag for tag in tags if tag != "O")
        examples.append(
            EvaluationExample(
                text=text,
                expected_has_pii=bool(expected_categories),
                expected_categories=expected_categories,
                metadata={"source": "eriktks/conll2003", "split": "test"},
            )
        )

        if num_samples is not None and len(examples) >= num_samples:
            break

    return examples


def load_piibench(num_samples: int | None) -> list[EvaluationExample]:
    dataset = load_dataset(
        "Pritesh-2711/pii-bench",
        split="train",
        streaming=True
    )

    examples: list[EvaluationExample] = []

    for row in dataset:
        text = row["text"]
        labels = row["labels"]

        expected_has_pii = any(label != "O" for label in labels)

        expected_categories = tuple(
            sorted({
                label.split("-", 1)[1]
                for label in labels
                if label != "O"
            })
        )

        examples.append(
            EvaluationExample(
                text=text,
                expected_has_pii=expected_has_pii,
                expected_categories=expected_categories,
                metadata={
                    "source": row["source"],
                },
            )
        )

        if num_samples is not None and len(examples) >= num_samples:
            break

    return examples

def load_nemotron_pii(num_samples: int | None) -> list[EvaluationExample]:
    dataset = load_dataset(
        "nvidia/Nemotron-PII",
        split="test",
        streaming=True,
    )

    examples: list[EvaluationExample] = []

    for row in dataset:
        text = row["text"]
        raw_spans = row["spans"]

        spans = []
        if isinstance(raw_spans, str) and raw_spans.strip():
            try:
                spans = json.loads(raw_spans)
            except json.JSONDecodeError:
                try:
                    spans = ast.literal_eval(raw_spans)
                except Exception:
                    spans = []
        elif isinstance(raw_spans, list):
            spans = raw_spans

        expected_has_pii = bool(spans)

        categories_set = set()
        for span in spans:
            if isinstance(span, dict) and "label" in span:
                categories_set.add(span["label"])
            elif isinstance(span, str):
                categories_set.add(span)

        expected_categories = tuple(sorted(categories_set))

        examples.append(
            EvaluationExample(
                text=text,
                expected_has_pii=expected_has_pii,
                expected_categories=expected_categories,
                metadata={
                    "source": "nvidia/Nemotron-PII",
                    "domain": row.get("domain"),
                    "document_type": row.get("document_type"),
                    "document_format": row.get("document_format"),
                    "locale": row.get("locale"),
                },
            )
        )

        if num_samples is not None and len(examples) >= num_samples:
            break

    return examples

def load_gretel_finance(num_samples: int | None) -> list[EvaluationExample]:
    dataset = load_dataset(
        "gretelai/synthetic_pii_finance_multilingual",
        split="test",
        streaming=True,
    )

    examples: list[EvaluationExample] = []

    for row in dataset:
        text = row["generated_text"]
        raw_spans = row["pii_spans"]

        spans = []
        if isinstance(raw_spans, str) and raw_spans.strip():
            try:
                spans = json.loads(raw_spans)
            except json.JSONDecodeError:
                try:
                    spans = ast.literal_eval(raw_spans)
                except Exception:
                    spans = []
        elif isinstance(raw_spans, list):
            spans = raw_spans

        expected_has_pii = bool(spans)

        expected_categories = tuple(
            sorted({
                span["label"]
                for span in spans
                if isinstance(span, dict) and "label" in span
            })
        )

        examples.append(
            EvaluationExample(
                text=text,
                expected_has_pii=expected_has_pii,
                expected_categories=expected_categories,
                metadata={
                    "source": "gretelai/synthetic_pii_finance_multilingual",
                    "domain": row.get("domain"),
                    "language": row.get("language"),
                    "document_type": row.get("document_type"),
                    "expanded_type": row.get("expanded_type"),
                    "quality_score": row.get("quality_score"),
                },
            )
        )

        if num_samples is not None and len(examples) >= num_samples:
            break

    return examples

def load_pii_shield(num_samples: int | None) -> list[EvaluationExample]:
    dataset = load_dataset(
        "auren-research/pii-shield",
        split="train",
        streaming=True,
    )

    examples: list[EvaluationExample] = []

    for row in dataset:
        text = row["text"]

        raw_spans = row.get("spans", "[]")

        spans = []
        if isinstance(raw_spans, str) and raw_spans.strip():
            try:
                spans = json.loads(raw_spans)
            except json.JSONDecodeError:
                try:
                    spans = ast.literal_eval(raw_spans)
                except Exception:
                    spans = []
        elif isinstance(raw_spans, list):
            spans = raw_spans

        expected_has_pii = bool(row.get("has_pii", bool(spans)))

        expected_categories = tuple(
            sorted({
                span["label"]
                for span in spans
                if isinstance(span, dict) and "label" in span
            })
        )

        examples.append(
            EvaluationExample(
                text=text,
                expected_has_pii=expected_has_pii,
                expected_categories=expected_categories,
                metadata={
                    "source": "auren-research/pii-shield",
                    "pii_count": row.get("pii_count"),
                },
            )
        )

        if num_samples is not None and len(examples) >= num_samples:
            break

    return examples

def load_meddies_pii(num_samples: int |None) -> list[EvaluationExample]:
    dataset = load_dataset(
        "Meddies/meddies-pii",
        "english",
        split="train",
        streaming=True,
    )

    examples: list[EvaluationExample] = []

    for row in dataset:
        text = row["raw"]

        raw_labels = row.get("label", "{}")

        labels = {}

        if isinstance(raw_labels, str) and raw_labels.strip():
            try:
                labels = json.loads(raw_labels)
            except json.JSONDecodeError:
                try:
                    labels = ast.literal_eval(raw_labels)
                except Exception:
                    labels = {}
        elif isinstance(raw_labels, dict):
            labels = raw_labels

        expected_categories = tuple(sorted(labels.keys()))
        expected_has_pii = bool(expected_categories)

        examples.append(
            EvaluationExample(
                text=text,
                expected_has_pii=expected_has_pii,
                expected_categories=expected_categories,
                metadata={
                    "source": "Meddies/meddies-pii",
                    "language": row.get("language"),
                    "document_type": row.get("document_type"),
                    "document_label": row.get("document_label"),
                    "document_length": row.get("document_length"),
                    "text_format": row.get("text_format"),
                    "edge_case": row.get("edge_case"),
                },
            )
        )

        if num_samples is not None and len(examples) >= num_samples:
            break

    return examples

def load_local_json_dataset(path: Path, num_samples: int | None) -> list[EvaluationExample]:
    payload = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(payload, dict):
        records = (
            payload.get("examples")
            or payload.get("prompts")
            or payload.get("data")
            or payload.get("items")
            or []
        )
    elif isinstance(payload, list):
        records = payload
    else:
        raise ValueError(
            f"Unsupported JSON dataset format in {path}. Use an array or an object with examples/prompts/data/items."
        )

    examples: list[EvaluationExample] = []
    for item in records:
        if isinstance(item, str):
            examples.append(
                EvaluationExample(
                    text=item,
                    expected_has_pii=False,
                    metadata={"source": str(path), "inferred": True},
                )
            )
        elif isinstance(item, dict):
            text = _first_present(item, ("text", "prompt", "source_text", "input"))
            if not isinstance(text, str) or not text.strip():
                continue
            label = _first_present(item, ("expected_has_pii", "has_pii", "label", "pii"))
            if isinstance(label, str):
                expected_has_pii = label.strip().lower() in {"1", "true", "yes", "y", "pii"}
            else:
                expected_has_pii = bool(label)
            categories = _normalise_expected_categories(
                _first_present(item, ("expected_categories", "categories", "labels"))
            )
            examples.append(
                EvaluationExample(
                    text=text,
                    expected_has_pii=expected_has_pii,
                    expected_categories=categories,
                    metadata={
                        k: v
                        for k, v in item.items()
                        if k not in {"text", "prompt", "source_text", "input"}
                    },
                )
            )

        if num_samples is not None and len(examples) >= num_samples:
            break

    return examples


DATASET_SPECS: dict[str, DatasetSpec] = {
    "ai4privacy": DatasetSpec(
        name="ai4privacy",
        description="AI4Privacy pii-masking-300k streaming dataset",
        loader=load_ai4privacy,
        is_streaming=True,
    ),
    "conll2003": DatasetSpec(
        name="conll2003",
        description="CoNLL-2003 test split",
        loader=load_conll2003,
    ),
    "piibench": DatasetSpec(              
        name="piibench",
        description="Pritesh-2711/pii-bench streaming dataset",
        loader=load_piibench,
        is_streaming=True,
    ),
    "nemotron-pii": DatasetSpec(
    name="nemotron-pii",
    description="nvidia/Nemotron-PII streaming dataset",
    loader=load_nemotron_pii,
    is_streaming=True,
    ),
    "gretel-finance": DatasetSpec(
    name="gretel-finance",
    description="Gretel Synthetic PII Finance Multilingual dataset",
    loader=load_gretel_finance,
    is_streaming=True,
    ),
    "pii-shield": DatasetSpec(
    name="pii-shield",
    description="Auren Research PII Shield dataset",
    loader=load_pii_shield,
    is_streaming=True,
    ),
    "meddies-pii": DatasetSpec(
    name="meddies-pii",
    description="Meddies English healthcare PII dataset",
    loader=load_meddies_pii,
    is_streaming=True,
    ),
}


def load_examples(dataset_name: str, num_samples: int | None, dataset_file: Path | None = None) -> tuple[DatasetSpec, list[EvaluationExample]]:
    if dataset_name == "local-jsonl":
        if dataset_file is None:
            raise ValueError("--dataset-file is required when --dataset local-jsonl is used.")
        if not dataset_file.exists():
            raise FileNotFoundError(f"Dataset file not found: {dataset_file}")
        if dataset_file.suffix.lower() == ".jsonl":
            examples = _load_jsonl_examples(dataset_file, num_samples)
        else:
            examples = load_local_json_dataset(dataset_file, num_samples)
        spec = DatasetSpec(
            name="local-jsonl",
            description=f"Local dataset file {dataset_file}",
            loader=lambda _: examples,
        )
        return spec, examples

    try:
        spec = DATASET_SPECS[dataset_name]
    except KeyError as exc:
        available = ", ".join(sorted([*DATASET_SPECS.keys(), "local-jsonl"]))
        raise ValueError(f"Unsupported dataset '{dataset_name}'. Available datasets: {available}") from exc

    examples = spec.loader(num_samples)
    return spec, examples


def _load_jsonl_examples(path: Path, num_samples: int | None) -> list[EvaluationExample]:
    examples: list[EvaluationExample] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if isinstance(item, str):
                examples.append(
                    EvaluationExample(
                        text=item,
                        expected_has_pii=False,
                        metadata={"source": str(path), "inferred": True},
                    )
                )
            elif isinstance(item, dict):
                text = _first_present(item, ("text", "prompt", "source_text", "input"))
                if not isinstance(text, str) or not text.strip():
                    continue
                label = _first_present(item, ("expected_has_pii", "has_pii", "label", "pii"))
                if isinstance(label, str):
                    expected_has_pii = label.strip().lower() in {"1", "true", "yes", "y", "pii"}
                else:
                    expected_has_pii = bool(label)
                categories = _normalise_expected_categories(
                    _first_present(item, ("expected_categories", "categories", "labels"))
                )
                examples.append(
                    EvaluationExample(
                        text=text,
                        expected_has_pii=expected_has_pii,
                        expected_categories=categories,
                        metadata={
                            k: v
                            for k, v in item.items()
                            if k not in {"text", "prompt", "source_text", "input"}
                        },
                    )
                )

            if num_samples is not None and len(examples) >= num_samples:
                break

    return examples

