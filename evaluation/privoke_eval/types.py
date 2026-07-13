from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class EvaluationExample:
    text: str
    expected_has_pii: bool
    expected_categories: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DatasetSpec:
    name: str
    description: str
    loader: Callable[[int | None, int, str, bool], "DatasetLoadResult"]
    is_streaming: bool = False
    research_role: str = "primary"
    ground_truth: str = "dataset-provided PII annotations"
    independence_group: str | None = None
    evaluation_mode: str = "binary"
    revision: str | None = None


@dataclass(frozen=True)
class DatasetLoadResult:
    examples: list[EvaluationExample]
    rows_seen: int
    eligible_rows: int
    duplicate_rows: int
    population_label_counts: dict[str, int]
    selected_label_counts: dict[str, int]
    sampling_strategy: str
    sampling_seed: int
    population_scan_complete: bool
    exclusions: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionOutcome:
    action: str
    categories: tuple[str, ...]
    confidence: float | None
    elapsed_ms: float
    sensitivity: str = "S0"
    visibility: str = "PU"
    masked_text: str | None = None

    @property
    def detected_sensitive(self) -> bool:
        """Whether the runtime returned a non-default privacy classification."""
        return self.sensitivity != "S0" or bool(self.categories)

    @property
    def detected_has_pii(self) -> bool:
        """Backward-compatible alias for the prompt-level detection signal."""
        return self.detected_sensitive

    @property
    def intervened(self) -> bool:
        """Whether PriVoke selected an enforcement action other than ALLOW."""
        return self.action in {"WARN", "BLOCK"}


@dataclass(frozen=True)
class EvaluationFailure:
    index: int
    text: str
    expected_has_pii: bool
    detected_action: str
    detected_categories: tuple[str, ...]
    failure_type: str
    expected_categories: tuple[str, ...] = ()
    error: str | None = None
    example_id: str | None = None
    text_truncated: bool = False


@dataclass(frozen=True)
class EvaluationSummary:
    dataset: str
    layer: str
    backend: str | None
    requested_samples: int
    loaded_samples: int
    errors: int
    metrics: dict[str, Any]
    failures: list[EvaluationFailure]
    dataset_description: str
    output_path: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
