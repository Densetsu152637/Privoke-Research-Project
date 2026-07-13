from __future__ import annotations

import ast
import hashlib
import json
import random
import unicodedata
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable, Iterator

from datasets import load_dataset

from .types import DatasetLoadResult, DatasetSpec, EvaluationExample


SAMPLING_STRATEGIES = ("balanced", "stratified", "random", "sequential")

# Fixed Hub commits make a paper run reproducible even if a dataset is updated later.
DATASET_REVISIONS = {
    "piimb": "4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133",
    "ai4privacy": "c8c77895a005822682b66ab547fc0422579bc1d3",
    "nemotron-pii": "b70ffaf5ff39e079776134c5bf4381f00a9fd1ed",
    "gretel-finance": "7b844d16738527a04264f50214cb426a4cea0897",
    "meddies-pii": "6a5c8f5441e3b421d983c9741770262365acdd77",
}


class DatasetValidationError(ValueError):
    """Raised when source ground truth cannot be parsed without guessing."""


def _first_present(mapping: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", [], {}, ()):
            return value
    return None


def _is_english_language(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower().replace("_", "-")
    return normalized in {"en", "eng", "english", "en-us", "en-gb", "en-ca"}


def _normalise_expected_categories(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(item) for item in value if str(item))
    return (str(value),)


def _parse_required_pii_label(value: Any, source: str) -> bool:
    if value is None:
        raise DatasetValidationError(
            f"Dataset entry from {source} is missing an expected_has_pii/has_pii label."
        )
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalised = value.strip().lower().replace("_", "-")
        if normalised in {"1", "true", "yes", "y", "pii", "sensitive"}:
            return True
        if normalised in {
            "0", "false", "no", "n", "clean", "non-pii", "not-sensitive",
            "non-sensitive", "nonsensitive",
        }:
            return False
    raise DatasetValidationError(
        f"Dataset entry from {source} has ambiguous PII label {value!r}. "
        "Use true/false, 1/0, pii/clean, or sensitive/non-sensitive."
    )


def _parse_spans(value: Any, source: str) -> list[Any]:
    if value in (None, "", []):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            try:
                parsed = ast.literal_eval(value)
            except (ValueError, SyntaxError) as exc:
                raise DatasetValidationError(
                    f"Could not parse PII spans for {source}; the row was not relabeled as clean."
                ) from exc
        if not isinstance(parsed, list):
            raise DatasetValidationError(f"PII spans for {source} must decode to a list.")
        return parsed
    raise DatasetValidationError(f"PII spans for {source} have unsupported type {type(value).__name__}.")


def _parse_label_mapping(value: Any, source: str) -> dict[str, Any]:
    if value in (None, "", {}):
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            try:
                parsed = ast.literal_eval(value)
            except (ValueError, SyntaxError) as exc:
                raise DatasetValidationError(
                    f"Could not parse PII labels for {source}; the row was not relabeled as clean."
                ) from exc
        if not isinstance(parsed, dict):
            raise DatasetValidationError(f"PII labels for {source} must decode to an object.")
        return parsed
    raise DatasetValidationError(f"PII labels for {source} have unsupported type {type(value).__name__}.")


def _span_categories(spans: list[Any]) -> tuple[str, ...]:
    categories: set[str] = set()
    for span in spans:
        if isinstance(span, dict):
            label = _first_present(span, ("label", "category", "entity_type", "entity", "type", "tag"))
            if label is not None:
                categories.add(str(label))
        elif isinstance(span, str):
            categories.add(span)
    return tuple(sorted(categories))


def _span_ground_truth(
    value: Any,
    source: str,
    text: str | None = None,
) -> tuple[bool, tuple[str, ...]]:
    spans = _parse_spans(value, source)
    categories = _span_categories(spans)
    if spans and not categories:
        raise DatasetValidationError(
            f"{source} contains PII span entries without a category/type label."
        )
    for span in spans:
        if not isinstance(span, dict):
            raise DatasetValidationError(f"{source} contains a non-object PII span.")
        start = span.get("start")
        end = span.get("end")
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 0
            or end <= start
        ):
            raise DatasetValidationError(f"{source} contains invalid PII span offsets.")
        if text is not None and not isinstance(text, str):
            raise DatasetValidationError(f"{source} has PII spans but no valid source text.")
        if isinstance(text, str) and end > len(text):
            raise DatasetValidationError(
                f"{source} contains a PII span outside the source text."
            )
    return bool(spans), categories


def _label_mapping_ground_truth(
    labels: dict[str, Any],
    source: str,
) -> tuple[bool, tuple[str, ...]]:
    categories: list[str] = []
    for category, values in labels.items():
        if not isinstance(category, str) or not category.strip():
            raise DatasetValidationError(f"{source} contains an invalid PII category name.")
        if isinstance(values, str):
            has_values = bool(values.strip())
        elif isinstance(values, (list, tuple, set)):
            has_values = any(str(value).strip() for value in values)
        elif values is None:
            has_values = False
        else:
            raise DatasetValidationError(
                f"{source} contains unsupported values for PII category {category!r}."
            )
        if has_values:
            categories.append(category)
    return bool(categories), tuple(sorted(categories))


def _example_id(dataset_name: str, text: str, source_id: Any = None) -> str:
    if source_id not in (None, ""):
        return f"{dataset_name}:{source_id}"
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:20]
    return f"{dataset_name}:sha256:{digest}"


def _example(
    dataset_name: str,
    text: Any,
    expected_has_pii: bool,
    categories: tuple[str, ...],
    metadata: dict[str, Any],
    source_id: Any = None,
) -> EvaluationExample:
    if not isinstance(text, str) or not text.strip():
        raise DatasetValidationError(f"{dataset_name} contains an empty or non-text sample.")
    # The hosted API strips surrounding whitespace before analysis. Store exactly
    # that effective prompt so duplicate checks match what PriVoke receives.
    text = unicodedata.normalize("NFC", text.strip())
    return EvaluationExample(
        text=text,
        expected_has_pii=expected_has_pii,
        expected_categories=categories,
        metadata={"example_id": _example_id(dataset_name, text, source_id), **metadata},
    )


def _reservoir_add(
    reservoir: list[EvaluationExample],
    item: EvaluationExample,
    seen_for_reservoir: int,
    capacity: int,
    rng: random.Random,
) -> None:
    if len(reservoir) < capacity:
        reservoir.append(item)
        return
    replacement = rng.randrange(seen_for_reservoir)
    if replacement < capacity:
        reservoir[replacement] = item


def _select_examples(
    rows: Iterable[EvaluationExample],
    num_samples: int | None,
    seed: int,
    strategy: str,
    *,
    strict_conflicts: bool = True,
) -> DatasetLoadResult:
    if strategy not in SAMPLING_STRATEGIES:
        raise ValueError(f"Unsupported sampling strategy: {strategy}")

    rng = random.Random(seed)
    selected: list[EvaluationExample] = []
    reservoirs: dict[bool, list[EvaluationExample]] = {False: [], True: []}
    random_reservoir: list[EvaluationExample] = []
    population = Counter({"pii": 0, "clean": 0})
    seen_text_labels: dict[bytes, bool | None] = {}
    exclusions: Counter[str] = Counter()
    rows_seen = 0
    eligible_rows = 0
    duplicate_rows = 0
    scan_complete = True

    for row in rows:
        rows_seen += 1
        digest = hashlib.blake2b(row.text.encode("utf-8"), digest_size=16).digest()
        if digest in seen_text_labels:
            previous_label = seen_text_labels[digest]
            if previous_label is None:
                duplicate_rows += 1
                exclusions["conflicting_duplicate_label_rows"] += 1
                continue
            if previous_label == row.expected_has_pii:
                duplicate_rows += 1
                continue
            if strict_conflicts:
                raise DatasetValidationError(
                    "Identical prompt text has conflicting sensitive/clean ground-truth labels."
                )

            # Neither contradictory label is reliable. Remove the previously accepted
            # row and exclude this row plus any later copies of the same text.
            seen_text_labels[digest] = None
            previous_name = "pii" if previous_label else "clean"
            population[previous_name] -= 1
            eligible_rows -= 1
            duplicate_rows += 2
            exclusions["conflicting_duplicate_label_rows"] += 2

            def different_text(candidate: EvaluationExample) -> bool:
                candidate_digest = hashlib.blake2b(
                    candidate.text.encode("utf-8"), digest_size=16
                ).digest()
                return candidate_digest != digest

            selected = [candidate for candidate in selected if different_text(candidate)]
            random_reservoir = [
                candidate for candidate in random_reservoir if different_text(candidate)
            ]
            reservoirs[False] = [
                candidate for candidate in reservoirs[False] if different_text(candidate)
            ]
            reservoirs[True] = [
                candidate for candidate in reservoirs[True] if different_text(candidate)
            ]
            continue
        seen_text_labels[digest] = row.expected_has_pii

        eligible_rows += 1
        label_name = "pii" if row.expected_has_pii else "clean"
        population[label_name] += 1

        if num_samples is None:
            selected.append(row)
            continue

        if strategy == "sequential":
            selected.append(row)
            if len(selected) >= num_samples:
                scan_complete = False
                break
            continue

        if strategy == "random":
            _reservoir_add(random_reservoir, row, eligible_rows, num_samples, rng)
            continue

        class_seen = population[label_name]
        _reservoir_add(reservoirs[row.expected_has_pii], row, class_seen, num_samples, rng)

    if num_samples is not None and strategy == "random":
        selected = random_reservoir
    elif num_samples is not None and strategy in {"balanced", "stratified"}:
        positive_count = population["pii"]
        negative_count = population["clean"]
        total_available = positive_count + negative_count
        target_total = min(num_samples, total_available)

        if strategy == "balanced":
            target_positive = (target_total + 1) // 2
        else:
            target_positive = round(target_total * positive_count / total_available) if total_available else 0
            if positive_count and negative_count and target_total >= 2:
                target_positive = min(max(target_positive, 1), target_total - 1)
        target_negative = target_total - target_positive

        target_positive = min(target_positive, positive_count)
        target_negative = min(target_negative, negative_count)
        remaining = target_total - target_positive - target_negative
        if remaining:
            positive_room = positive_count - target_positive
            add_positive = min(remaining, positive_room)
            target_positive += add_positive
            target_negative += min(remaining - add_positive, negative_count - target_negative)

        selected = rng.sample(reservoirs[True], target_positive) + rng.sample(
            reservoirs[False], target_negative
        )

    rng.shuffle(selected)
    selected_counts = Counter("pii" if row.expected_has_pii else "clean" for row in selected)
    return DatasetLoadResult(
        examples=selected,
        rows_seen=rows_seen,
        eligible_rows=eligible_rows,
        duplicate_rows=duplicate_rows,
        population_label_counts={"pii": population["pii"], "clean": population["clean"]},
        selected_label_counts={"pii": selected_counts["pii"], "clean": selected_counts["clean"]},
        sampling_strategy="all" if num_samples is None else strategy,
        sampling_seed=seed,
        population_scan_complete=scan_complete,
        exclusions=dict(sorted(exclusions.items())),
    )


def _finish(
    rows: Iterable[EvaluationExample],
    num_samples: int | None,
    seed: int,
    strategy: str,
    *,
    strict_conflicts: bool = False,
) -> DatasetLoadResult:
    return _select_examples(
        rows,
        num_samples,
        seed,
        strategy,
        strict_conflicts=strict_conflicts,
    )


def _finish_positive_only(
    rows: Iterable[EvaluationExample],
    num_samples: int | None,
    seed: int,
    strategy: str,
) -> DatasetLoadResult:
    excluded_without_spans = 0

    def positives() -> Iterator[EvaluationExample]:
        nonlocal excluded_without_spans
        for row in rows:
            if row.expected_has_pii:
                yield row
            else:
                excluded_without_spans += 1

    result = _finish(positives(), num_samples, seed, strategy)
    exclusions = Counter(result.exclusions)
    if excluded_without_spans:
        exclusions["rows_without_verified_negative_ground_truth"] += excluded_without_spans
    return replace(
        result,
        rows_seen=result.rows_seen + excluded_without_spans,
        exclusions=dict(sorted(exclusions.items())),
    )


def _add_public_row_exclusions(
    result: DatasetLoadResult,
    **exclusion_counts: int,
) -> DatasetLoadResult:
    added_rows = sum(count for count in exclusion_counts.values() if count > 0)
    if not added_rows:
        return result
    exclusions = Counter(result.exclusions)
    for name, count in exclusion_counts.items():
        if count > 0:
            exclusions[name] += count
    return replace(
        result,
        rows_seen=result.rows_seen + added_rows,
        exclusions=dict(sorted(exclusions.items())),
    )


def load_ai4privacy(
    num_samples: int | None,
    seed: int,
    strategy: str,
    english_only: bool = False,
) -> DatasetLoadResult:
    dataset = load_dataset(
        "ai4privacy/pii-masking-300k",
        split="validation",
        streaming=True,
        revision=DATASET_REVISIONS["ai4privacy"],
    )

    malformed_rows = 0
    non_english_rows = 0

    def rows() -> Iterator[EvaluationExample]:
        nonlocal malformed_rows, non_english_rows
        for index, row in enumerate(dataset):
            if english_only and not _is_english_language(row.get("language")):
                non_english_rows += 1
                continue
            try:
                text = _first_present(row, ("source_text", "text", "prompt"))
                expected, categories = _span_ground_truth(
                    _first_present(row, ("privacy_mask", "pii_mask", "mask")),
                    f"ai4privacy row {index}",
                    text,
                )
                yield _example(
                    "ai4privacy", text, expected, categories,
                    {
                        "source": "ai4privacy/pii-masking-300k",
                        "split": "validation",
                        "group_id": row.get("id") or index,
                    },
                    row.get("id", index),
                )
            except DatasetValidationError:
                malformed_rows += 1

    result = _finish_positive_only(rows(), num_samples, seed, strategy)
    return _add_public_row_exclusions(
        result,
        malformed_source_annotation_rows=malformed_rows,
        non_english_language_rows=non_english_rows,
    )


def load_nemotron_pii(
    num_samples: int | None,
    seed: int,
    strategy: str,
    english_only: bool = False,
) -> DatasetLoadResult:
    dataset = load_dataset(
        "nvidia/Nemotron-PII",
        split="test",
        streaming=True,
        revision=DATASET_REVISIONS["nemotron-pii"],
    )

    malformed_rows = 0

    def rows() -> Iterator[EvaluationExample]:
        nonlocal malformed_rows
        for index, row in enumerate(dataset):
            try:
                expected, categories = _span_ground_truth(
                    row.get("spans"), f"Nemotron-PII row {index}", row.get("text")
                )
                yield _example(
                    "nemotron-pii", row["text"], expected, categories,
                    {
                        "source": "nvidia/Nemotron-PII", "split": "test", "domain": row.get("domain"),
                        "document_type": row.get("document_type"), "document_format": row.get("document_format"),
                        "locale": row.get("locale"), "group_id": row.get("uid") or index,
                    },
                    row.get("uid", index),
                )
            except (DatasetValidationError, KeyError):
                malformed_rows += 1

    result = _finish_positive_only(rows(), num_samples, seed, strategy)
    return _add_public_row_exclusions(
        result,
        malformed_source_annotation_rows=malformed_rows,
    )


def load_gretel_finance(
    num_samples: int | None,
    seed: int,
    strategy: str,
    english_only: bool = False,
) -> DatasetLoadResult:
    dataset = load_dataset(
        "gretelai/synthetic_pii_finance_multilingual",
        split="test",
        streaming=True,
        revision=DATASET_REVISIONS["gretel-finance"],
    )

    malformed_rows = 0
    non_english_rows = 0

    def rows() -> Iterator[EvaluationExample]:
        nonlocal malformed_rows, non_english_rows
        for index, row in enumerate(dataset):
            if english_only and not _is_english_language(row.get("language")):
                non_english_rows += 1
                continue
            try:
                expected, categories = _span_ground_truth(
                    row.get("pii_spans"), f"Gretel finance row {index}", row.get("generated_text")
                )
                yield _example(
                    "gretel-finance", row["generated_text"], expected, categories,
                    {
                        "source": "gretelai/synthetic_pii_finance_multilingual", "split": "test",
                        "domain": row.get("domain"), "language": row.get("language"),
                        "document_type": row.get("document_type"), "expanded_type": row.get("expanded_type"),
                        "quality_score": row.get("quality_score"),
                        "group_id": row.get("index") if row.get("index") is not None else index,
                    },
                    row.get("index", index),
                )
            except (DatasetValidationError, KeyError):
                malformed_rows += 1

    result = _finish_positive_only(rows(), num_samples, seed, strategy)
    return _add_public_row_exclusions(
        result,
        malformed_source_annotation_rows=malformed_rows,
        non_english_language_rows=non_english_rows,
    )


def load_meddies_pii(
    num_samples: int | None,
    seed: int,
    strategy: str,
    english_only: bool = False,
) -> DatasetLoadResult:
    dataset = load_dataset(
        "Meddies/meddies-pii",
        "english",
        split="train",
        streaming=True,
        revision=DATASET_REVISIONS["meddies-pii"],
    )

    malformed_rows = 0

    def rows() -> Iterator[EvaluationExample]:
        nonlocal malformed_rows
        for index, row in enumerate(dataset):
            try:
                labels = _parse_label_mapping(row.get("label"), f"Meddies row {index}")
                expected, categories = _label_mapping_ground_truth(labels, f"Meddies row {index}")
                yield _example(
                    "meddies-pii", row["raw"], expected, categories,
                    {
                        "source": "Meddies/meddies-pii", "split": "train", "language": row.get("language"),
                        "document_type": row.get("document_type"), "document_label": row.get("document_label"),
                        "document_length": row.get("document_length"), "text_format": row.get("text_format"),
                        "edge_case": row.get("edge_case"), "group_id": row.get("id") or index,
                    },
                    row.get("id", index),
                )
            except (DatasetValidationError, KeyError):
                malformed_rows += 1

    result = _finish_positive_only(rows(), num_samples, seed, strategy)
    return _add_public_row_exclusions(
        result,
        malformed_source_annotation_rows=malformed_rows,
    )


def load_piimb(
    num_samples: int | None,
    seed: int,
    strategy: str,
    english_only: bool = False,
) -> DatasetLoadResult:
    dataset = load_dataset(
        "piimb/pii-masking-benchmark",
        "sentences",
        split="test",
        streaming=True,
        revision=DATASET_REVISIONS["piimb"],
    )

    malformed_rows = 0
    non_english_rows = 0

    def rows() -> Iterator[EvaluationExample]:
        nonlocal malformed_rows, non_english_rows
        for index, row in enumerate(dataset):
            if english_only and not _is_english_language(row.get("language")):
                non_english_rows += 1
                continue
            try:
                expected, categories = _span_ground_truth(
                    row.get("entities"), f"PIIMB row {index}", row.get("text")
                )
                yield _example(
                    "piimb", row["text"], expected, categories,
                    {
                        "source": "piimb/pii-masking-benchmark", "split": "test",
                        "task_name": row.get("task_name"), "source_dataset": row.get("source_dataset"),
                        "language": row.get("language"), "parent_id": row.get("parent_id"),
                        "group_id": row.get("parent_id") or row.get("source_uid") or row.get("uid", index),
                    },
                    row.get("uid", index),
                )
            except (DatasetValidationError, KeyError):
                malformed_rows += 1

    result = _finish(rows(), num_samples, seed, strategy)
    return _add_public_row_exclusions(
        result,
        malformed_source_annotation_rows=malformed_rows,
        non_english_language_rows=non_english_rows,
    )


def _iter_local_json(path: Path) -> Iterator[EvaluationExample]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        records = payload.get("examples") or payload.get("prompts") or payload.get("data") or payload.get("items") or []
    elif isinstance(payload, list):
        records = payload
    else:
        raise DatasetValidationError(
            f"Unsupported JSON dataset format in {path}. Use an array or an object with examples/prompts/data/items."
        )
    yield from _iter_local_records(records, path)


def _iter_local_jsonl(path: Path) -> Iterator[EvaluationExample]:
    with path.open("r", encoding="utf-8") as handle:
        records = (json.loads(line) for line in handle if line.strip())
        yield from _iter_local_records(records, path)


def _iter_local_records(records: Iterable[Any], path: Path) -> Iterator[EvaluationExample]:
    for index, item in enumerate(records):
        if not isinstance(item, dict):
            raise DatasetValidationError(
                f"Unlabeled or non-object entry {index} in {path}; every sample needs text and expected_has_pii."
            )
        text = _first_present(item, ("text", "prompt", "source_text", "input"))
        label = _first_present(item, ("expected_has_pii", "has_pii", "label", "pii"))
        expected = _parse_required_pii_label(label, f"{path} row {index}")
        categories = _normalise_expected_categories(
            _first_present(item, ("expected_categories", "categories", "labels"))
        )
        metadata = {key: value for key, value in item.items() if key not in {"text", "prompt", "source_text", "input"}}
        yield _example("local-jsonl", text, expected, categories, metadata, item.get("id", index))


DATASET_SPECS: dict[str, DatasetSpec] = {
    "piimb": DatasetSpec(
        name="piimb", description="PIIMB locked multi-source PII masking test benchmark", loader=load_piimb,
        is_streaming=True, research_role="primary", ground_truth="curated span annotations from dedicated test tasks",
        independence_group="shared-public-pii-source-corpora",
        revision=DATASET_REVISIONS["piimb"],
    ),
    "ai4privacy": DatasetSpec(
        name="ai4privacy", description="AI4Privacy PII Masking validation split", loader=load_ai4privacy,
        is_streaming=True, research_role="secondary", ground_truth="synthetic spans with documented human-in-the-loop QA",
        independence_group="shared-public-pii-source-corpora",
        evaluation_mode="positive-only",
        revision=DATASET_REVISIONS["ai4privacy"],
    ),
    "nemotron-pii": DatasetSpec(
        name="nemotron-pii", description="NVIDIA Nemotron-PII test split", loader=load_nemotron_pii,
        is_streaming=True, research_role="secondary", ground_truth="synthetically generated span annotations",
        independence_group="shared-public-pii-source-corpora",
        evaluation_mode="positive-only",
        revision=DATASET_REVISIONS["nemotron-pii"],
    ),
    "gretel-finance": DatasetSpec(
        name="gretel-finance", description="Gretel synthetic multilingual finance PII test split", loader=load_gretel_finance,
        is_streaming=True, research_role="secondary", ground_truth="synthetically generated finance PII spans",
        independence_group="shared-public-pii-source-corpora",
        evaluation_mode="positive-only",
        revision=DATASET_REVISIONS["gretel-finance"],
    ),
    "meddies-pii": DatasetSpec(
        name="meddies-pii", description="Meddies synthetic English healthcare PII data", loader=load_meddies_pii,
        is_streaming=True, research_role="secondary", ground_truth="synthetic healthcare extraction labels",
        independence_group="meddies",
        evaluation_mode="positive-only",
        revision=DATASET_REVISIONS["meddies-pii"],
    ),
}


def load_examples(
    dataset_name: str,
    num_samples: int | None,
    dataset_file: Path | None = None,
    *,
    seed: int = 42,
    strategy: str = "balanced",
    english_only: bool = False,
) -> tuple[DatasetSpec, DatasetLoadResult]:
    if dataset_name == "local-jsonl":
        if dataset_file is None:
            raise ValueError("--dataset-file is required when --dataset local-jsonl is used.")
        if not dataset_file.exists():
            raise FileNotFoundError(f"Dataset file not found: {dataset_file}")
        rows = _iter_local_jsonl(dataset_file) if dataset_file.suffix.lower() == ".jsonl" else _iter_local_json(dataset_file)
        non_english_rows = 0
        if english_only:
            source_rows = rows

            def english_rows() -> Iterator[EvaluationExample]:
                nonlocal non_english_rows
                for row in source_rows:
                    if _is_english_language(row.metadata.get("language")):
                        yield row
                    else:
                        non_english_rows += 1

            rows = english_rows()
        result = _finish(rows, num_samples, seed, strategy, strict_conflicts=True)
        result = _add_public_row_exclusions(
            result,
            non_english_language_rows=non_english_rows,
        )
        spec = DatasetSpec(
            name="local-jsonl", description=f"Local gold dataset {dataset_file}", loader=lambda *_: result,
            research_role="primary", ground_truth="user-supplied explicit binary annotations",
            independence_group="local-gold",
        )
        return spec, result

    try:
        spec = DATASET_SPECS[dataset_name]
    except KeyError as exc:
        available = ", ".join(sorted([*DATASET_SPECS, "local-jsonl"]))
        raise ValueError(f"Unsupported dataset '{dataset_name}'. Available datasets: {available}") from exc
    return spec, spec.loader(num_samples, seed, strategy, english_only)
