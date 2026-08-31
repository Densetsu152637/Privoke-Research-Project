from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from .types import BatchTrainingUpdate, ParameterDict, ShapeDict

GeneratedModules = tuple[ModuleType, ModuleType]


@dataclass(frozen=True)
class ParameterUpdatePayload:
    source_id: str
    model_id: str
    base_version: str
    parameters: ParameterDict
    shapes: ShapeDict
    metadata: Mapping[str, str]


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
        target,
        ParameterUpdatePayload(
            source_id=source_id,
            model_id=update.model_id,
            base_version=update.base_version,
            parameters=update.gradients,
            shapes=update.parameter_shapes,
            metadata=metadata,
        ),
        timeout_seconds=timeout_seconds,
    )


def emit_parameter_update(
    target: str,
    update: ParameterUpdatePayload,
    timeout_seconds: float = 10.0,
):
    import grpc

    parameters_pb2, parameters_pb2_grpc = load_generated_grpc_modules()

    gradients = [
        parameters_pb2.Parameter(
            name=name,
            values=[float(value) for value in values],
            shape=list(update.shapes.get(name, (len(values),))),
        )
        for name, values in update.parameters.items()
    ]

    with grpc.insecure_channel(target) as channel:
        client = parameters_pb2_grpc.ParamUpdateServiceStub(channel)
        return client.SubmitParameterUpdate(
            parameters_pb2.ParameterUpdateRequest(
                source_id=update.source_id,
                model_id=update.model_id,
                base_version=update.base_version,
                gradients=gradients,
                metadata={
                    str(key): str(value) for key, value in update.metadata.items()
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
