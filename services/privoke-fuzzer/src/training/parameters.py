from __future__ import annotations

import hashlib
from typing import Any, Mapping

from client_runtime_imports import import_client_module

from .types import ParameterDict


def snapshot_with_trainable_parameters(snapshot: Any):
    parameter_stream = import_client_module("LLM.privoke.parameter_stream")
    client_snapshot = to_client_snapshot(snapshot)
    if client_snapshot.parameters:
        return client_snapshot

    classification = import_client_module("classification")
    fallback_parameters = {
        "classifier.bias": (0.0,),
        "semantic.category_weights": tuple(0.0 for _ in classification.Category),
    }
    return parameter_stream.ParameterSnapshot(
        model_id=client_snapshot.model_id,
        version=client_snapshot.version,
        generated_at_unix=client_snapshot.generated_at_unix,
        parameters=fallback_parameters,
        metadata=dict(client_snapshot.metadata),
    )


def to_client_snapshot(snapshot: Any):
    parameter_stream = import_client_module("LLM.privoke.parameter_stream")
    raw_parameters = getattr(snapshot, "parameters", {})

    if isinstance(raw_parameters, Mapping):
        parameters = {
            str(name): tuple(float(value) for value in values)
            for name, values in raw_parameters.items()
        }
    else:
        parameters = {
            parameter.name: tuple(float(value) for value in parameter.values)
            for parameter in raw_parameters
        }

    return parameter_stream.ParameterSnapshot(
        model_id=str(getattr(snapshot, "model_id", "privoke-baseline")),
        version=str(getattr(snapshot, "version", "unknown")),
        generated_at_unix=int(getattr(snapshot, "generated_at_unix", 0)),
        parameters=parameters,
        metadata=dict(getattr(snapshot, "metadata", {})),
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
