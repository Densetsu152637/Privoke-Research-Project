from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol


class StreamedParameter(Protocol):
    name: str
    values: Sequence[float]
    shape: Sequence[int]


class StreamedParameterSnapshot(Protocol):
    model_id: str
    version: str
    generated_at_unix: int
    parameters: Mapping[str, Sequence[float]] | Sequence[StreamedParameter]
    shapes: Mapping[str, Sequence[int]]
    metadata: Mapping[str, str]
