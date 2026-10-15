from __future__ import annotations

import sys
import hashlib
import json
import os
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
    from privoke_model import window_training as window
    if update.metadata.get("contextual_training_optimizer") == window.POLICY:
        from .window_evidence import publication_metadata
        metadata = publication_metadata(update,metadata,extra_metadata or {},os.getenv("PRIVOKE_FUZZER_DUMP_DIR"))
    from privoke_model.sensitive_retention import POLICIES as RETENTION_POLICIES
    if update.metadata.get("contextual_training_optimizer") in ({"full_projected_adam64_v1"} | RETENTION_POLICIES):
        from .full_adam_evidence import publication_metadata
        metadata = publication_metadata(update, metadata, extra_metadata or {}, os.getenv("PRIVOKE_FUZZER_DUMP_DIR"))
    if len(metadata) > 64 and update.metadata.get("contextual_training_diagnostics_policy") == "train_before_candidate_v1":
        # The physical RPC and complete unprojected cycle must exist before compact publication.
        extra = extra_metadata or {}
        identity = hashlib.sha256(json.dumps([update.metadata["training_scope"], extra["request_source_id"], extra["request_id"]],
                                             separators=(",", ":")).encode()).hexdigest()
        directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
        if not directory:
            raise ValueError("Compact training publication requires durable complete evidence.")
        path = Path(directory) / "training-cycles" / identity / (update.metadata["base_parameter_fingerprint"] + ".json")
        retained = json.loads(path.read_text(encoding="utf-8"))
        if (retained.get("metadata") != dict(update.metadata) or retained.get("metrics") != dict(update.metrics)
                or retained.get("execution_evidence") != update.execution_evidence or not retained.get("gate_passed")):
            raise ValueError("Compact publication differs from retained complete evidence.")
        weight_keys = {"training_clean_examples", "training_sensitive_examples", "raw_clean_weight", "raw_sensitive_weight",
                       "raw_total_weight", "effective_clean_weight", "effective_sensitive_weight", "clean_objective_mass",
                       "sensitive_objective_mass", "objective_strata"}
        audit = {key: metadata[key] for key in sorted(metadata) if key.startswith("sampling_") or key in weight_keys}
        compact = json.dumps({"schema": 1, "fields": audit}, separators=(",", ":"), allow_nan=False)
        if len(compact.encode("utf-8")) > 2048:
            raise ValueError("Compact training audit exceeds publication byte budget.")
        metadata = {key: value for key, value in metadata.items() if key not in audit}
        metadata["training_audit_v1"] = compact
        bound_evidence = {key: retained[key] for key in ("metadata", "metrics", "execution_evidence")}
        metadata["training_evidence_sha256"] = hashlib.sha256(json.dumps(bound_evidence, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    if update.metadata.get("contextual_training_diagnostics_policy") == "train_before_candidate_v1":
        if len(metadata) > 64 or any(len(value.encode("utf-8")) > 2048 for value in metadata.values()):
            raise ValueError("Opt-in training publication metadata exceeds its unchanged limits.")
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
