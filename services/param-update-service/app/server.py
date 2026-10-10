"""gRPC entry point for validating and applying parameter updates."""

from __future__ import annotations

import logging
import hashlib
import json
import sqlite3
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
from privoke_model.artifact import artifact_checksum
from privoke_service import configure_logging

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from audit import artifact_is_usable, persist_update_audit, storage_is_writable
from config import ParamUpdateConfig
from receipts import RECEIPT_METADATA_KEY, UpdateReceipts, receipt_key, request_receipt
from privoke_service import validate_text
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
                artifact=load_artifact(self.model_artifact_path) if self.model_artifact_path is not None else None,
            )
        except (ValueError, OSError) as exc:
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
        except (OSError, sqlite3.Error):
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
        with self._write_lock, UpdateReceipts(self.storage_path) as receipts:
            artifact = load_artifact(self.model_artifact_path)
            while receipts.recover(artifact):
                receipts.checkpoint()
                artifact = load_artifact(self.model_artifact_path)
            if artifact["model_id"] != request.model_id:
                raise ModelArtifactError(
                    f"Artifact model_id is {artifact['model_id']!r}, "
                    f"not {request.model_id!r}."
                )
            # Revalidate under the writer lock against the exact current artifact,
            # including its strategy-specific tensor bound; metadata is not authority.
            validate_parameter_update(request, expected_model_id=self.expected_model_id,
                                      max_abs_gradient=self.max_abs_gradient, artifact=artifact)
            request_id = request.metadata.get("request_id", "")
            if request_id:
                key = receipt_key(request.source_id, request_id, request.metadata.get("request_source_id", ""))
                existing = receipts.get(key)
                if existing:
                    digest = hashlib.sha256(request.SerializeToString(deterministic=True)).hexdigest()
                    if existing["payload_digest"] != digest:
                        raise ModelArtifactError("request_id was already used for a different parameter update.")
                    return {"version": existing["applied_version"]}
            validate_gradient_shapes_against_artifact(request, artifact)
            updated_artifact = apply_parameter_update(
                artifact,
                base_version=request.base_version,
                deltas=_gradient_deltas(request),
                source_id=request.source_id,
            )
            receipt = request_receipt(request, updated_artifact["version"])
            updated_artifact["metadata"].pop(RECEIPT_METADATA_KEY, None)
            if receipt:
                updated_artifact["metadata"][RECEIPT_METADATA_KEY] = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
            updated_artifact["checksum"] = artifact_checksum({key: value for key, value in updated_artifact.items() if key != "checksum"})
            write_artifact_atomic(self.model_artifact_path, updated_artifact)
            if receipt:
                receipts.put(receipt)
            self._persist_audit(request, updated_artifact)
            return updated_artifact

    def GetParameterUpdateStatus(self, request, context):
        try:
            for name in ("source_id", "request_id", "model_id"):
                validate_text(getattr(request, name), name, required=True)
            validate_text(request.request_source_id, "request_source_id", required=False)
            validate_text(request.request_fingerprint, "request_fingerprint", required=False)
            if request.model_id != self.expected_model_id:
                raise ValueError("Unexpected model_id.")
        except ValueError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        try:
            with self._write_lock, UpdateReceipts(self.storage_path) as receipts:
                artifact = load_artifact(self.model_artifact_path)
                receipts.recover(artifact)
                receipt = receipts.get(receipt_key(request.source_id, request.request_id, request.request_source_id))
            if receipt is None:
                return parameters_pb2.ParameterUpdateStatus(found=False)
            if receipt["request_fingerprint"] != request.request_fingerprint:
                context.abort(grpc.StatusCode.ALREADY_EXISTS, "request_id belongs to a different training request.")
            return parameters_pb2.ParameterUpdateStatus(
                found=True,
                ack=parameters_pb2.ParameterUpdateAck(
                    accepted=True, model_id=receipt["model_id"], applied_version=receipt["applied_version"],
                    message="Previously committed parameter update.",
                ),
                base_version=receipt["base_version"], prompts_generated=receipt["prompts_generated"],
            )
        except (ModelArtifactError, OSError, sqlite3.Error):
            LOGGER.exception("update receipt lookup failed")
            context.abort(grpc.StatusCode.INTERNAL, "Update receipt lookup failed.")

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
