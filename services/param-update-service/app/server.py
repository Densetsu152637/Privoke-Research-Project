import json
import logging
import math
import os
import sys
import threading
from concurrent import futures
from pathlib import Path

SHARED_DIR = Path(__file__).resolve().parents[3] / "shared/python"
if SHARED_DIR.exists() and str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

import grpc
from privoke_model import (
    ModelArtifactError,
    apply_parameter_update,
    load_artifact,
    write_artifact_atomic,
)

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import parameters_pb2, parameters_pb2_grpc
from fuzzer_requests import FuzzerRequestConfig, start_fuzzer_requester

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    force=True,
)


class ParamUpdateService(parameters_pb2_grpc.ParamUpdateServiceServicer):
    def __init__(
        self,
        storage_path: Path,
        expected_model_id: str,
        max_abs_gradient: float = 1.0,
        model_artifact_path: Path | None = None,
    ):
        self.storage_path = storage_path
        self.expected_model_id = expected_model_id
        self.max_abs_gradient = max_abs_gradient
        self.model_artifact_path = model_artifact_path
        self._write_lock = threading.Lock()
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    def SubmitParameterUpdate(self, request, context):
        try:
            validate_parameter_update(
                request,
                expected_model_id=self.expected_model_id,
                max_abs_gradient=self.max_abs_gradient,
            )
        except ValueError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))

        if self.model_artifact_path is None:
            context.abort(
                grpc.StatusCode.FAILED_PRECONDITION,
                "MODEL_ARTIFACT_PATH is not configured.",
            )
        try:
            with self._write_lock:
                artifact = load_artifact(self.model_artifact_path)
                if artifact["model_id"] != request.model_id:
                    raise ModelArtifactError(
                        f"Artifact model_id is {artifact['model_id']!r}, not {request.model_id!r}."
                    )
                validate_gradient_shapes_against_artifact(request, artifact)
                updated_artifact = apply_parameter_update(
                    artifact,
                    base_version=request.base_version,
                    deltas={
                        gradient.name: tuple(float(value) for value in gradient.values)
                        for gradient in request.gradients
                    },
                    source_id=request.source_id,
                )
                write_artifact_atomic(self.model_artifact_path, updated_artifact)
                try:
                    persist_update_audit(
                        self.storage_path,
                        request,
                        applied_version=updated_artifact["version"],
                        artifact_checksum=updated_artifact["checksum"],
                    )
                except OSError:
                    # The authoritative model is already atomically committed;
                    # do not make a retry double-apply the same update.
                    logging.exception("parameter update audit persistence failed")
        except ModelArtifactError as exc:
            code = (
                grpc.StatusCode.FAILED_PRECONDITION
                if str(exc).startswith("Stale base_version")
                else grpc.StatusCode.INVALID_ARGUMENT
            )
            context.abort(code, str(exc))
        except OSError:
            logging.exception("model artifact persistence failed")
            context.abort(
                grpc.StatusCode.INTERNAL,
                "Model artifact persistence failed.",
            )

        logging.info(
            "accepted parameter update source=%r model=%r gradients=%d",
            request.source_id,
            request.model_id,
            len(request.gradients),
        )

        return parameters_pb2.ParameterUpdateAck(
            accepted=True,
            model_id=request.model_id,
            applied_version=updated_artifact["version"],
            message="Parameter update applied to the persistent model artifact.",
        )

    def Health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="param-update-service",
            status=(
                "SERVING"
                if storage_is_writable(self.storage_path)
                and artifact_is_usable(self.model_artifact_path)
                else "NOT_SERVING"
            ),
        )


def serve() -> None:
    port = int(os.getenv("PARAM_UPDATE_PORT", "50052"))
    storage_path = Path(os.getenv("PARAM_UPDATE_STORAGE_PATH", "/data/updates.jsonl"))
    model_artifact_path = Path(
        os.getenv("MODEL_ARTIFACT_PATH", "/models/privoke-baseline.json")
    )
    expected_model_id = os.getenv("MODEL_ID", "privoke-baseline").strip()
    max_abs_gradient = float(os.getenv("PARAM_UPDATE_MAX_ABS_GRADIENT", "1.0"))
    max_message_bytes = int(
        os.getenv("PARAM_UPDATE_MAX_MESSAGE_BYTES", "1048576")
    )
    if not expected_model_id:
        raise ValueError("MODEL_ID must not be empty.")
    if not math.isfinite(max_abs_gradient) or max_abs_gradient <= 0:
        raise ValueError("PARAM_UPDATE_MAX_ABS_GRADIENT must be finite and positive.")
    if max_message_bytes <= 0:
        raise ValueError("PARAM_UPDATE_MAX_MESSAGE_BYTES must be positive.")
    fuzzer_config = FuzzerRequestConfig.from_env()

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=(
            ("grpc.max_receive_message_length", max_message_bytes),
            ("grpc.max_send_message_length", 262_144),
        ),
    )
    parameters_pb2_grpc.add_ParamUpdateServiceServicer_to_server(
        ParamUpdateService(
            storage_path,
            expected_model_id=expected_model_id,
            max_abs_gradient=max_abs_gradient,
            model_artifact_path=model_artifact_path,
        ),
        server,
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logging.info("param-update-service listening on %s", port)
    start_fuzzer_requester(fuzzer_config)
    server.wait_for_termination()


def validate_parameter_update(
    request,
    *,
    expected_model_id: str,
    max_abs_gradient: float,
) -> None:
    _validate_identifier(request.source_id, "source_id", required=True)
    _validate_identifier(request.model_id, "model_id", required=True)
    _validate_identifier(request.base_version, "base_version", required=True)
    if request.model_id != expected_model_id:
        raise ValueError(f"model_id must be {expected_model_id!r}.")
    if not request.gradients:
        raise ValueError("At least one gradient is required.")
    if len(request.gradients) > 256:
        raise ValueError("A parameter update may contain at most 256 gradients.")

    names: set[str] = set()
    total_values = 0
    for gradient in request.gradients:
        _validate_identifier(gradient.name, "gradient name", required=True, limit=256)
        if gradient.name in names:
            raise ValueError(f"Duplicate gradient name: {gradient.name!r}.")
        names.add(gradient.name)
        if not gradient.values:
            raise ValueError(f"Gradient {gradient.name!r} has no values.")
        if len(gradient.values) > 4_096:
            raise ValueError(
                f"Gradient {gradient.name!r} exceeds 4096 values."
            )
        if not gradient.shape:
            raise ValueError(f"Gradient {gradient.name!r} has no shape.")
        expected_values = 1
        for dimension in gradient.shape:
            if dimension <= 0:
                raise ValueError(
                    f"Gradient {gradient.name!r} has an invalid shape."
                )
            expected_values *= int(dimension)
        if expected_values != len(gradient.values):
            raise ValueError(
                f"Gradient {gradient.name!r} shape does not match its values."
            )
        total_values += len(gradient.values)
        for value in gradient.values:
            if not math.isfinite(value) or abs(value) > max_abs_gradient:
                raise ValueError(
                    f"Gradient {gradient.name!r} contains a non-finite or "
                    "out-of-range value."
                )
    if total_values > 65_536:
        raise ValueError("A parameter update may contain at most 65536 values.")

    if len(request.metadata) > 64:
        raise ValueError("metadata may contain at most 64 entries.")
    for key, value in request.metadata.items():
        _validate_identifier(key, "metadata key", required=True, limit=128)
        _validate_identifier(value, "metadata value", required=False, limit=2_048)


def validate_gradient_shapes_against_artifact(request, artifact) -> None:
    parameters = artifact["parameters"]
    for gradient in request.gradients:
        tensor = parameters.get(gradient.name)
        if tensor is None:
            continue
        if tuple(int(size) for size in gradient.shape) != tuple(tensor["shape"]):
            raise ModelArtifactError(
                f"Parameter shape mismatch for {gradient.name!r}."
            )


def open_storage_file(storage_path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(storage_path, flags, 0o600)


def persist_update_audit(
    storage_path: Path,
    request,
    *,
    applied_version: str,
    artifact_checksum: str,
) -> None:
    payload = {
        "source_id": request.source_id,
        "model_id": request.model_id,
        "base_version": request.base_version,
        "applied_version": applied_version,
        "artifact_checksum": artifact_checksum,
        "gradients": [
            {
                "name": gradient.name,
                "shape": list(gradient.shape),
                "values": list(gradient.values),
            }
            for gradient in request.gradients
        ],
        "metadata": dict(request.metadata),
    }
    descriptor = open_storage_file(storage_path)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, separators=(",", ":")) + "\n")


def storage_is_writable(storage_path: Path) -> bool:
    try:
        descriptor = open_storage_file(storage_path)
    except OSError:
        return False
    os.close(descriptor)
    return True


def artifact_is_usable(model_artifact_path: Path | None) -> bool:
    if model_artifact_path is None:
        return True
    try:
        load_artifact(model_artifact_path)
    except (ModelArtifactError, OSError):
        return False
    return os.access(model_artifact_path.parent, os.W_OK)


def _validate_identifier(
    value: str,
    field_name: str,
    *,
    required: bool,
    limit: int = 128,
) -> None:
    if required and not value:
        raise ValueError(f"{field_name} is required.")
    if len(value) > limit:
        raise ValueError(f"{field_name} exceeds {limit} characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} must not contain control characters.")


if __name__ == "__main__":
    serve()
