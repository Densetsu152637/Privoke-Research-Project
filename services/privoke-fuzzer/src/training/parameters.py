from __future__ import annotations

import hashlib
from typing import Mapping, Sequence, cast

from privoke_client_runtime.LLM.privoke.parameter_stream import ParameterSnapshot
from privoke_client_runtime.classification import Category

from .protocols import StreamedParameter, StreamedParameterSnapshot
from .types import ParameterDict


def snapshot_with_trainable_parameters(
    snapshot: StreamedParameterSnapshot,
) -> ParameterSnapshot:
    client_snapshot = to_client_snapshot(snapshot)
    if client_snapshot.parameters:
        return client_snapshot

    default_parameters = {
        "classifier.bias": (0.0,),
        "semantic.category_weights": tuple(0.0 for _ in Category),
    }
    return ParameterSnapshot(
        model_id=client_snapshot.model_id,
        version=client_snapshot.version,
        generated_at_unix=client_snapshot.generated_at_unix,
        parameters=default_parameters,
        metadata=dict(client_snapshot.metadata),
    )


def to_client_snapshot(snapshot: StreamedParameterSnapshot) -> ParameterSnapshot:
    raw_parameters = snapshot.parameters

    if isinstance(raw_parameters, Mapping):
        parameters = {
            str(name): tuple(float(value) for value in values)
            for name, values in raw_parameters.items()
        }
    else:
        streamed_parameters = cast(Sequence[StreamedParameter], raw_parameters)
        parameters = {
            parameter.name: tuple(float(value) for value in parameter.values)
            for parameter in streamed_parameters
        }

    return ParameterSnapshot(
        model_id=snapshot.model_id,
        version=snapshot.version,
        generated_at_unix=int(snapshot.generated_at_unix),
        parameters=parameters,
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


def diff_parameters(
    base_parameters: ParameterDict,
    updated_parameters: ParameterDict,
) -> ParameterDict:
    delta = {}
    for name, values in updated_parameters.items():
        base_values = base_parameters.get(name, ())
        if len(base_values) != len(values):
            raise ValueError(f"Parameter shape mismatch for {name}.")
        delta[name] = tuple(
            float(value) - float(base_values[index])
            for index, value in enumerate(values)
        )
    return delta


def parameter_fingerprint(parameters: ParameterDict) -> str:
    digest = hashlib.sha256()
    for name in sorted(parameters):
        digest.update(name.encode("utf-8"))
        for value in parameters[name]:
            digest.update(repr(float(value)).encode("utf-8"))
    return digest.hexdigest()[:16]


def clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))
