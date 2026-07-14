from __future__ import annotations

import json
import logging
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
        if not request.event_id:
            return telemetry_pb2.RecordTelemetryResponse(
                accepted=False,
                message="event_id is required.",
            )
        try:
            sequence = self.store.record(request)
        except sqlite3.IntegrityError:
            return telemetry_pb2.RecordTelemetryResponse(
                accepted=True,
                event_id=request.event_id,
                message="Telemetry event was already recorded.",
            )
        except sqlite3.Error as exc:
            context.abort(grpc.StatusCode.INTERNAL, f"Telemetry persistence failed: {exc}")

        logging.info(
            "recorded telemetry sequence=%s event=%s action=%s",
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
        limit = min(max(1, int(request.limit or 100)), self.max_query_limit)
        rows = self.store.list(limit, int(request.before_sequence))
        return telemetry_pb2.ListTelemetryResponse(
            packets=[_stored_packet(row) for row in rows]
        )

    def Health(self, request, context):
        return telemetry_pb2.TelemetryHealthResponse(
            service="telemetry-service",
            status="SERVING",
        )


def serve() -> None:
    port = int(os.getenv("TELEMETRY_PORT", "50055"))
    store = TelemetryStore(
        os.getenv("TELEMETRY_DB_PATH", "/data/telemetry.db")
    )
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    telemetry_pb2_grpc.add_TelemetryServiceServicer_to_server(
        TelemetryCollector(store),
        server,
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logging.info("telemetry-service listening on %s", port)
    server.wait_for_termination()


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
