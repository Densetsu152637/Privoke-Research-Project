"""gRPC entry point for strict locally private telemetry collection."""

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
from storage import TelemetryStore
from validation import validate_telemetry_packet

SERVICE_NAME = "telemetry-service"
MAX_RESPONSE_BYTES = 4_194_304
LOGGER = logging.getLogger(__name__)


class TelemetryCollector(telemetry_pb2_grpc.TelemetryServiceServicer):
    def __init__(self, store: TelemetryStore):
        self.store = store

    def RecordTelemetry(self, request, context):
        try:
            validate_telemetry_packet(request)
        except ValueError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))

        try:
            self.store.record(request)
        except sqlite3.Error:
            LOGGER.exception("telemetry persistence failed")
            context.abort(grpc.StatusCode.INTERNAL, "Telemetry persistence failed.")

        LOGGER.info("recorded locally-private telemetry report")
        return _record_response()

    def GetTelemetrySummary(self, request, context):
        try:
            sample_count, dimensions = self.store.summary()
        except sqlite3.Error:
            LOGGER.exception("telemetry aggregation failed")
            context.abort(grpc.StatusCode.INTERNAL, "Telemetry aggregation failed.")
        return telemetry_pb2.GetTelemetrySummaryResponse(
            sample_count=sample_count,
            dimensions=[
                telemetry_pb2.TelemetryDimensionEstimate(
                    dimension=dimension["dimension"],
                    values=[
                        telemetry_pb2.TelemetryCategoryEstimate(
                            value=item["value"],
                            estimated_count=item["estimated_count"],
                            observed_noisy_count=item["observed_noisy_count"],
                        )
                        for item in dimension["values"]
                    ],
                )
                for dimension in dimensions
            ],
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


def _record_response():
    return telemetry_pb2.RecordTelemetryResponse(
        accepted=True,
        message="Protected report added to aggregates.",
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
        TelemetryCollector(TelemetryStore(config.database_path)),
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
