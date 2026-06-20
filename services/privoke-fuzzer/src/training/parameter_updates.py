from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Mapping, Tuple

from .types import BatchTrainingUpdate, ParameterDict


GeneratedModules = Tuple[ModuleType, ModuleType]


def emit_training_update(
    target: str,
    source_id: str,
    update: BatchTrainingUpdate,
    extra_metadata: Mapping[str, str] | None = None,
    timeout_seconds: float = 10.0,
):
    metadata = dict(update.metadata)
    metadata.update({key: str(value) for key, value in update.metrics.items()})
    metadata.update(
        {str(key): str(value) for key, value in (extra_metadata or {}).items()}
    )
    return emit_parameter_update(
        target=target,
        source_id=source_id,
        model_id=update.model_id,
        base_version=update.base_version,
        parameter_updates=update.gradients,
        metadata=metadata,
        timeout_seconds=timeout_seconds,
    )


def emit_parameter_update(
    target: str,
    source_id: str,
    model_id: str,
    base_version: str,
    parameter_updates: ParameterDict,
    metadata: Mapping[str, str] | None = None,
    timeout_seconds: float = 10.0,
):
    import grpc

    parameters_pb2, parameters_pb2_grpc = load_generated_grpc_modules()

    gradients = [
        parameters_pb2.Parameter(
            name=name,
            values=[float(value) for value in values],
        )
        for name, values in parameter_updates.items()
    ]

    with grpc.insecure_channel(target) as channel:
        client = parameters_pb2_grpc.ParamUpdateServiceStub(channel)
        return client.SubmitParameterUpdate(
            parameters_pb2.ParameterUpdateRequest(
                source_id=source_id,
                model_id=model_id,
                base_version=base_version,
                gradients=gradients,
                metadata={
                    str(key): str(value)
                    for key, value in (metadata or {}).items()
                },
            ),
            timeout=timeout_seconds,
        )


def load_generated_grpc_modules(
    generated_dir: str | Path | None = None,
) -> GeneratedModules:
    resolved_dir = Path(generated_dir) if generated_dir else _default_generated_dir()
    if str(resolved_dir) not in sys.path:
        sys.path.insert(0, str(resolved_dir))

    from privoke.v1 import parameters_pb2, parameters_pb2_grpc

    return parameters_pb2, parameters_pb2_grpc


def _default_generated_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "generated"
