from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import sys
from concurrent import futures
from pathlib import Path

import grpc


GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import telemetry_pb2, telemetry_pb2_grpc
from storage import TelemetryStore


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    force=True,
)


class TelemetryCollector(telemetry_pb2_grpc.TelemetryServiceServicer):
    def __init__(self, store: TelemetryStore, max_query_limit: int = 1000):
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
            return telemetry_pb2.RecordTelemetryResponse(
                accepted=True,
                event_id=request.event_id,
                message="Telemetry event was already recorded.",
            )
        except sqlite3.Error as exc:
            logging.exception("telemetry persistence failed")
            context.abort(grpc.StatusCode.INTERNAL, "Telemetry persistence failed.")

        logging.info(
            "recorded telemetry sequence=%s event=%r action=%r",
            sequence,
            request.event_id,
            request.action,
        )
        return telemetry_pb2.RecordTelemetryResponse(
            accepted=True,
            event_id=request.event_id,
            sequence=sequence,
            message="Telemetry event persisted.",
        )

    def ListTelemetry(self, request, context):
        if request.before_sequence < 0:
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                "before_sequence must not be negative.",
            )
        limit = min(max(1, int(request.limit or 100)), self.max_query_limit)
        try:
            rows = self.store.list(limit, int(request.before_sequence))
        except sqlite3.Error:
            logging.exception("telemetry query failed")
            context.abort(grpc.StatusCode.INTERNAL, "Telemetry query failed.")
        return telemetry_pb2.ListTelemetryResponse(
            packets=[_stored_packet(row) for row in rows]
        )

    def Health(self, request, context):
        try:
            self.store.check_writable()
        except sqlite3.Error:
            status = "NOT_SERVING"
        else:
            status = "SERVING"
        return telemetry_pb2.TelemetryHealthResponse(
            service="telemetry-service",
            status=status,
        )


def serve() -> None:
    port = int(os.getenv("TELEMETRY_PORT", "50055"))
    store = TelemetryStore(
        os.getenv("TELEMETRY_DB_PATH", "/data/telemetry.db")
    )
    max_message_bytes = int(os.getenv("TELEMETRY_MAX_MESSAGE_BYTES", "131072"))
    if max_message_bytes <= 0:
        raise ValueError("TELEMETRY_MAX_MESSAGE_BYTES must be positive.")
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=(
            ("grpc.max_receive_message_length", max_message_bytes),
            ("grpc.max_send_message_length", 4_194_304),
        ),
    )
    telemetry_pb2_grpc.add_TelemetryServiceServicer_to_server(
        TelemetryCollector(store),
        server,
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logging.info("telemetry-service listening on %s", port)
    server.wait_for_termination()


def validate_telemetry_packet(packet) -> None:
    _validate_text(packet.event_id, "event_id", required=True, limit=128)
    _validate_text(packet.time_bucket, "time_bucket", required=True, limit=32)
    _validate_text(packet.source_id, "source_id", required=True, limit=128)
    _validate_text(packet.request_id, "request_id", required=False, limit=256)
    _validate_text(packet.target_app, "target_app", required=False, limit=256)
    _validate_choice(packet.action, "action", {"ALLOW", "WARN", "BLOCK"})
    _validate_choice(packet.sensitivity, "sensitivity", {"S0", "S1", "S2", "S3"})
    _validate_choice(
        packet.visibility,
        "visibility",
        {"P0", "P1", "P2", "P3", "P4", "PU"},
    )
    if packet.occurred_at_unix_ms <= 0 or packet.occurred_at_unix_ms > 4_102_444_800_000:
        raise ValueError("occurred_at_unix_ms is outside the supported range.")
    if packet.text_length > 100_000:
        raise ValueError("text_length exceeds 100000 characters.")
    if not math.isfinite(packet.elapsed_ms) or not 0 <= packet.elapsed_ms <= 3_600_000:
        raise ValueError("elapsed_ms must be finite and between 0 and 3600000.")
    if not math.isfinite(packet.risk_score) or not 0 <= packet.risk_score <= 1:
        raise ValueError("risk_score must be finite and between 0 and 1.")
    _validate_choice(
        packet.risk_bucket,
        "risk_bucket",
        {"0.0-0.2", "0.2-0.5", "0.5-0.8", "0.8-1.0"},
    )
    _validate_text(
        packet.detector_version,
        "detector_version",
        required=True,
        limit=64,
    )

    allowed_categories = {
        "HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL",
        "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY",
    }
    if len(packet.categories) > len(allowed_categories):
        raise ValueError("Too many telemetry categories.")
    if len(set(packet.categories)) != len(packet.categories):
        raise ValueError("Telemetry categories must not contain duplicates.")
    for category in packet.categories:
        _validate_choice(category, "category", allowed_categories)

    if len(packet.layers) > 16:
        raise ValueError("Telemetry may contain at most 16 layer results.")
    for layer in packet.layers:
        _validate_choice(layer.layer, "layer", {"regex", "ner", "semantic"})
        _validate_choice(layer.status, "layer status", {"ok", "error", "skipped"})
        _validate_text(layer.error, "layer error", required=False, limit=64)
        if layer.error not in {"", "detector_error", "short_circuited"}:
            raise ValueError("layer error must use a supported generic code.")
        if layer.result_count > 10_000:
            raise ValueError("layer result_count exceeds 10000.")


def _validate_choice(value: str, field_name: str, allowed: set[str]) -> None:
    if value not in allowed:
        raise ValueError(f"{field_name} has an unsupported value.")


def _validate_text(
    value: str,
    field_name: str,
    *,
    required: bool,
    limit: int,
) -> None:
    if required and not value:
        raise ValueError(f"{field_name} is required.")
    if len(value) > limit:
        raise ValueError(f"{field_name} exceeds {limit} characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} must not contain control characters.")


def _stored_packet(row):
    categories = json.loads(row["categories_json"])
    layers = json.loads(row["layers_json"])
    return telemetry_pb2.StoredTelemetryPacket(
        sequence=row["sequence"],
        packet=telemetry_pb2.TelemetryPacket(
            event_id=row["event_id"],
            occurred_at_unix_ms=row["occurred_at_unix_ms"],
            time_bucket=row["time_bucket"],
            source_id=row["source_id"],
            request_id=row["request_id"],
            target_app=row["target_app"],
            action=row["action"],
            sensitivity=row["sensitivity"],
            visibility=row["visibility"],
            categories=categories,
            text_length=row["text_length"],
            elapsed_ms=row["elapsed_ms"],
            risk_score=row["risk_score"],
            risk_bucket=row["risk_bucket"],
            detector_version=row["detector_version"],
            layers=[telemetry_pb2.LayerTelemetry(**layer) for layer in layers],
        ),
    )


if __name__ == "__main__":
    serve()
