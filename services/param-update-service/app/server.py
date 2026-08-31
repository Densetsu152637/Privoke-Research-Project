"""gRPC entry point for validating and applying parameter updates."""

from __future__ import annotations

import logging
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
from privoke_service import configure_logging

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from audit import artifact_is_usable, persist_update_audit, storage_is_writable
from config import ParamUpdateConfig
from fuzzer_requests import FuzzerRequestConfig, start_fuzzer_requester
from privoke.v1 import parameters_pb2, parameters_pb2_grpc
from validation import (
    validate_gradient_shapes_against_artifact,
    validate_parameter_update,
)

SERVICE_NAME = "param-update-service"
MAX_RESPONSE_BYTES = 262_144
LOGGER = logging.getLogger(__name__)


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
            updated_artifact = self._apply_update(request)
        except ModelArtifactError as exc:
            context.abort(_artifact_error_status(exc), str(exc))
        except OSError:
            LOGGER.exception("model artifact persistence failed")
            context.abort(
                grpc.StatusCode.INTERNAL,
                "Model artifact persistence failed.",
            )

        LOGGER.info(
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

    def _apply_update(self, request):
        with self._write_lock:
            artifact = load_artifact(self.model_artifact_path)
            if artifact["model_id"] != request.model_id:
                raise ModelArtifactError(
                    f"Artifact model_id is {artifact['model_id']!r}, "
                    f"not {request.model_id!r}."
                )
            validate_gradient_shapes_against_artifact(request, artifact)
            updated_artifact = apply_parameter_update(
                artifact,
                base_version=request.base_version,
                deltas=_gradient_deltas(request),
                source_id=request.source_id,
            )
            write_artifact_atomic(self.model_artifact_path, updated_artifact)
            self._persist_audit(request, updated_artifact)
            return updated_artifact

    def _persist_audit(self, request, updated_artifact) -> None:
        try:
            persist_update_audit(
                self.storage_path,
                request,
                applied_version=updated_artifact["version"],
                artifact_checksum=updated_artifact["checksum"],
            )
        except OSError:
            # The model is already committed atomically. Failing the RPC here
            # could make a retry apply the same gradient twice.
            LOGGER.exception("parameter update audit persistence failed")

    def Health(self, request, context):
        healthy = storage_is_writable(self.storage_path) and artifact_is_usable(
            self.model_artifact_path
        )
        return parameters_pb2.HealthResponse(
            service=SERVICE_NAME,
            status="SERVING" if healthy else "NOT_SERVING",
        )


def _gradient_deltas(request) -> dict[str, tuple[float, ...]]:
    return {
        gradient.name: tuple(float(value) for value in gradient.values)
        for gradient in request.gradients
    }


def _artifact_error_status(exc: ModelArtifactError):
    if str(exc).startswith("Stale base_version"):
        return grpc.StatusCode.FAILED_PRECONDITION
    return grpc.StatusCode.INVALID_ARGUMENT


def create_server(config: ParamUpdateConfig):
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=(
            ("grpc.max_receive_message_length", config.max_message_bytes),
            ("grpc.max_send_message_length", MAX_RESPONSE_BYTES),
        ),
    )
    parameters_pb2_grpc.add_ParamUpdateServiceServicer_to_server(
        ParamUpdateService(
            config.storage_path,
            expected_model_id=config.model_id,
            max_abs_gradient=config.max_abs_gradient,
            model_artifact_path=config.model_artifact_path,
        ),
        server,
    )
    server.add_insecure_port(f"[::]:{config.port}")
    return server


def serve() -> None:
    configure_logging()
    config = ParamUpdateConfig.from_env()
    server = create_server(config)
    server.start()
    LOGGER.info("%s listening on %s", SERVICE_NAME, config.port)
    start_fuzzer_requester(FuzzerRequestConfig.from_env())
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
