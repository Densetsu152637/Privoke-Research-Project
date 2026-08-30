from __future__ import annotations

from typing import Mapping, Protocol, Sequence


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
