"""Conversions between persisted telemetry rows and protobuf messages."""

from __future__ import annotations

import json

from privoke.v1 import telemetry_pb2


def stored_packet_from_row(row):
    categories = json.loads(row["categories_json"])
    layers = json.loads(row["layers_json"])
    packet = telemetry_pb2.TelemetryPacket(
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
    )
    return telemetry_pb2.StoredTelemetryPacket(
        sequence=row["sequence"],
        packet=packet,
    )
