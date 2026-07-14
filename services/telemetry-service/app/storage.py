from __future__ import annotations

import json
import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetry_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    occurred_at_unix_ms INTEGER NOT NULL,
    time_bucket TEXT NOT NULL,
    source_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    target_app TEXT NOT NULL,
    action TEXT NOT NULL,
    sensitivity TEXT NOT NULL,
    visibility TEXT NOT NULL,
    categories_json TEXT NOT NULL,
    text_length INTEGER NOT NULL,
    elapsed_ms REAL NOT NULL,
    risk_score REAL NOT NULL,
    risk_bucket TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    layers_json TEXT NOT NULL,
    stored_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS telemetry_events_time_idx
    ON telemetry_events(occurred_at_unix_ms DESC);
"""


class TelemetryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(SCHEMA)

    def record(self, packet) -> int:
        values = (
            packet.event_id,
            int(packet.occurred_at_unix_ms),
            packet.time_bucket,
            packet.source_id,
            packet.request_id,
            packet.target_app,
            packet.action,
            packet.sensitivity,
            packet.visibility,
            json.dumps(list(packet.categories), separators=(",", ":")),
            int(packet.text_length),
            float(packet.elapsed_ms),
            float(packet.risk_score),
            packet.risk_bucket,
            packet.detector_version,
            json.dumps(
                [
                    {
                        "layer": layer.layer,
                        "status": layer.status,
                        "result_count": int(layer.result_count),
                        "error": layer.error,
                    }
                    for layer in packet.layers
                ],
                separators=(",", ":"),
            ),
        )
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO telemetry_events (
                    event_id, occurred_at_unix_ms, time_bucket, source_id,
                    request_id, target_app, action, sensitivity, visibility,
                    categories_json, text_length, elapsed_ms, risk_score,
                    risk_bucket, detector_version, layers_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            return int(cursor.lastrowid)

    def list(self, limit: int, before_sequence: int = 0) -> list[sqlite3.Row]:
        where = "WHERE sequence < ?" if before_sequence > 0 else ""
        parameters = (before_sequence, limit) if before_sequence > 0 else (limit,)
        with self._connect() as connection:
            return list(
                connection.execute(
                    f"""
                    SELECT * FROM telemetry_events
                    {where}
                    ORDER BY sequence DESC
                    LIMIT ?
                    """,
                    parameters,
                )
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection
