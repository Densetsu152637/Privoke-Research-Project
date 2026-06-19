from __future__ import annotations

from typing import Mapping, Protocol, Sequence


class StreamedParameter(Protocol):
    name: str
    values: Sequence[float]


class StreamedParameterSnapshot(Protocol):
    model_id: str
    version: str
    generated_at_unix: int
    parameters: Mapping[str, Sequence[float]] | Sequence[StreamedParameter]
    metadata: Mapping[str, str]
