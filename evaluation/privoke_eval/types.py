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
    loader: Callable[[int], list[EvaluationExample]]
    is_streaming: bool = False


@dataclass(frozen=True)
class DetectionOutcome:
    action: str
    categories: tuple[str, ...]
    confidence: float | None
    elapsed_ms: float

    @property
    def detected_has_pii(self) -> bool:
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


@dataclass(frozen=True)
class EvaluationSummary:
    dataset: str
    layer: str
    backend: str | None
    requested_samples: int
    loaded_samples: int
    errors: int
    metrics: dict[str, float | int]
    failures: list[EvaluationFailure]
    dataset_description: str
    output_path: Path | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
