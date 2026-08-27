import json
import logging
import math
import os
import sys
import threading
from concurrent import futures
from pathlib import Path

import grpc

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
    ):
        self.storage_path = storage_path
        self.expected_model_id = expected_model_id
        self.max_abs_gradient = max_abs_gradient
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

        payload = {
            "source_id": request.source_id,
            "model_id": request.model_id,
            "base_version": request.base_version,
            "gradients": [
                {"name": gradient.name, "values": list(gradient.values)}
                for gradient in request.gradients
            ],
            "metadata": dict(request.metadata),
        }

        try:
            with self._write_lock:
                descriptor = open_storage_file(self.storage_path)
                with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
                    handle.write(
                        json.dumps(payload, separators=(",", ":")) + "\n"
                    )
        except OSError:
            logging.exception("parameter update persistence failed")
            context.abort(
                grpc.StatusCode.INTERNAL,
                "Parameter update persistence failed.",
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
            applied_version=f"{request.base_version}-updated",
            message="Parameter update persisted for downstream training.",
        )

    def Health(self, request, context):
        return parameters_pb2.HealthResponse(
            service="param-update-service",
            status=(
                "SERVING"
                if storage_is_writable(self.storage_path)
                else "NOT_SERVING"
            ),
        )


def serve() -> None:
    port = int(os.getenv("PARAM_UPDATE_PORT", "50052"))
    storage_path = Path(os.getenv("PARAM_UPDATE_STORAGE_PATH", "/data/updates.jsonl"))
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


def open_storage_file(storage_path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(storage_path, flags, 0o600)


def storage_is_writable(storage_path: Path) -> bool:
    try:
        descriptor = open_storage_file(storage_path)
    except OSError:
        return False
    os.close(descriptor)
    return True


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
