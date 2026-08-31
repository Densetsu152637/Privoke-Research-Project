"""gRPC entry point for privacy-minimal telemetry collection."""

from __future__ import annotations

import logging
import sqlite3
import sys
from concurrent import futures
from pathlib import Path

SHARED_DIR = Path(__file__).resolve().parents[3] / "shared/python"
if SHARED_DIR.exists() and str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

import grpc
from privoke_service import configure_logging

GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from config import TelemetryConfig
from privoke.v1 import telemetry_pb2, telemetry_pb2_grpc
from serialization import stored_packet_from_row
from storage import TelemetryStore
from validation import validate_telemetry_packet

SERVICE_NAME = "telemetry-service"
MAX_RESPONSE_BYTES = 4_194_304
DEFAULT_QUERY_LIMIT = 100
LOGGER = logging.getLogger(__name__)


class TelemetryCollector(telemetry_pb2_grpc.TelemetryServiceServicer):
    def __init__(self, store: TelemetryStore, max_query_limit: int = 1_000):
        self.store = store
        self.max_query_limit = max(1, max_query_limit)

    def RecordTelemetry(self, request, context):
        try:
            validate_telemetry_packet(request)
        except ValueError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))

        try:
            sequence = self.store.record(request)
        except sqlite3.IntegrityError:
            return _record_response(request.event_id, duplicate=True)
        except sqlite3.Error:
            LOGGER.exception("telemetry persistence failed")
            context.abort(grpc.StatusCode.INTERNAL, "Telemetry persistence failed.")

        LOGGER.info(
            "recorded telemetry sequence=%s event=%r action=%r",
            sequence,
            request.event_id,
            request.action,
        )
        return _record_response(request.event_id, sequence=sequence)

    def ListTelemetry(self, request, context):
        if request.before_sequence < 0:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "before_sequence must not be negative.",
            )
        limit = min(
            max(1, int(request.limit or DEFAULT_QUERY_LIMIT)),
            self.max_query_limit,
        )
        try:
            rows = self.store.list(limit, int(request.before_sequence))
        except sqlite3.Error:
            LOGGER.exception("telemetry query failed")
            context.abort(grpc.StatusCode.INTERNAL, "Telemetry query failed.")
        return telemetry_pb2.ListTelemetryResponse(
            packets=[stored_packet_from_row(row) for row in rows]
        )

    def Health(self, request, context):
        try:
            self.store.check_writable()
        except sqlite3.Error:
            status = "NOT_SERVING"
        else:
            status = "SERVING"
        return telemetry_pb2.TelemetryHealthResponse(
            service=SERVICE_NAME,
            status=status,
        )


def _record_response(
    event_id: str,
    *,
    sequence: int = 0,
    duplicate: bool = False,
):
    message = (
        "Telemetry event was already recorded."
        if duplicate
        else "Telemetry event persisted."
    )
    return telemetry_pb2.RecordTelemetryResponse(
        accepted=True,
        event_id=event_id,
        sequence=sequence,
        message=message,
    )


def create_server(config: TelemetryConfig):
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=(
            ("grpc.max_receive_message_length", config.max_message_bytes),
            ("grpc.max_send_message_length", MAX_RESPONSE_BYTES),
        ),
    )
    telemetry_pb2_grpc.add_TelemetryServiceServicer_to_server(
        TelemetryCollector(
            TelemetryStore(config.database_path),
            max_query_limit=config.max_query_limit,
        ),
        server,
    )
    server.add_insecure_port(f"[::]:{config.port}")
    return server


def serve() -> None:
    configure_logging()
    config = TelemetryConfig.from_env()
    server = create_server(config)
    server.start()
    LOGGER.info("%s listening on %s", SERVICE_NAME, config.port)
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
