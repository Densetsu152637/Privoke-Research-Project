from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from .protocols import StreamedParameter, StreamedParameterSnapshot
from .types import ParameterDict, ShapeDict


@dataclass(frozen=True)
class ParameterSnapshot:
    model_id: str
    version: str
    generated_at_unix: int
    parameters: ParameterDict
    shapes: ShapeDict
    metadata: dict[str, str]


def snapshot_with_trainable_parameters(
    snapshot: StreamedParameterSnapshot,
) -> ParameterSnapshot:
    client_snapshot = to_client_snapshot(snapshot)
    if not client_snapshot.parameters:
        raise ValueError("The streamed model snapshot has no parameters.")
    return client_snapshot


def to_client_snapshot(snapshot: StreamedParameterSnapshot) -> ParameterSnapshot:
    raw_parameters = snapshot.parameters

    if isinstance(raw_parameters, Mapping):
        parameters = {
            str(name): tuple(float(value) for value in values)
            for name, values in raw_parameters.items()
        }
        raw_shapes = getattr(snapshot, "shapes", {})
        shapes = {
            str(name): tuple(int(size) for size in shape)
            for name, shape in raw_shapes.items()
        }
    else:
        streamed_parameters = cast(Sequence[StreamedParameter], raw_parameters)
        parameters = {
            parameter.name: tuple(float(value) for value in parameter.values)
            for parameter in streamed_parameters
        }
        shapes = {
            parameter.name: tuple(int(size) for size in parameter.shape)
            for parameter in streamed_parameters
        }

    if set(parameters) != set(shapes):
        raise ValueError("Every streamed parameter must include a tensor shape.")
    for name, values in parameters.items():
        size = 1
        for dimension in shapes[name]:
            if dimension <= 0:
                raise ValueError(f"Parameter {name!r} has an invalid shape.")
            size *= dimension
        if size != len(values):
            raise ValueError(f"Parameter {name!r} shape does not match its values.")

    return ParameterSnapshot(
        model_id=snapshot.model_id,
        version=snapshot.version,
        generated_at_unix=int(snapshot.generated_at_unix),
        parameters=parameters,
        shapes=shapes,
        metadata=dict(snapshot.metadata),
    )


def add_parameter_delta(
    parameters: ParameterDict,
    delta: ParameterDict,
) -> ParameterDict:
    updated = {}
    for name, values in parameters.items():
        update_values = delta.get(name, tuple(0.0 for _ in values))
        if len(update_values) != len(values):
            raise ValueError(f"Parameter shape mismatch for {name}.")
        updated[name] = tuple(
            float(value) + float(update_values[index])
            for index, value in enumerate(values)
        )
    return updated


def parameter_fingerprint(parameters: ParameterDict) -> str:
    digest = hashlib.sha256()
    for name in sorted(parameters):
        digest.update(name.encode("utf-8"))
        for value in parameters[name]:
            digest.update(repr(float(value)).encode("utf-8"))
    return digest.hexdigest()[:16]


def clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))
