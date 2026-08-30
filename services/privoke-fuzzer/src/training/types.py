from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

from privoke_contracts.classification import Classification


ParameterDict = Dict[str, Tuple[float, ...]]
ShapeDict = Dict[str, Tuple[int, ...]]


@dataclass(frozen=True)
class BatchTrainingConfig:
    learning_rate: float = 0.03
    max_gradient: float = 0.05
    new_example_weight: float = 1.0
    golden_example_weight: float = 0.35
    transformations_per_example: int = 1
    seed: int = 42


@dataclass(frozen=True)
class BatchTrainingExample:
    text: str
    expected_classification: Classification | None = None
    weight: float = 1.0
    metadata: Dict[str, str] = field(default_factory=dict)

    @property
    def has_explicit_target(self) -> bool:
        return self.expected_classification is not None

    @property
    def expected_packed_classification(self) -> int | None:
        if self.expected_classification is None:
            return None
        return int(self.expected_classification.pack())

    def with_text_and_weight(self, text: str, weight: float) -> "BatchTrainingExample":
        return BatchTrainingExample(
            text=text,
            expected_classification=self.expected_classification,
            weight=weight,
            metadata=dict(self.metadata),
        )


@dataclass(frozen=True)
class BatchTrainingUpdate:
    model_id: str
    base_version: str
    gradients: ParameterDict
    updated_parameters: ParameterDict
    parameter_shapes: ShapeDict
    metrics: Dict[str, float]
    metadata: Dict[str, str]

    @property
    def updated_fingerprint(self) -> str:
        from .parameters import parameter_fingerprint

        return parameter_fingerprint(self.updated_parameters)
