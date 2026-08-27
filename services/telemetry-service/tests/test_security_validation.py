from __future__ import annotations

import math
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
for path in (SERVICE_ROOT / "app", SERVICE_ROOT / "generated"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from privoke.v1 import telemetry_pb2
from server import TelemetryCollector, validate_telemetry_packet
from storage import TelemetryStore


def valid_packet():
    return telemetry_pb2.TelemetryPacket(
        event_id="4fa3f1b7-test",
        occurred_at_unix_ms=1_750_000_000_000,
        time_bucket="2025-06-15T12:00:00Z",
        source_id="client-runtime",
        request_id="request-1",
        target_app="chatgpt",
        action="WARN",
        sensitivity="S2",
        visibility="P1",
        categories=["IDENTITY"],
        text_length=120,
        elapsed_ms=10.5,
        risk_score=0.65,
        risk_bucket="0.5-0.8",
        detector_version="v2",
        layers=[
            telemetry_pb2.LayerTelemetry(
                layer="regex",
                status="ok",
                result_count=1,
            )
        ],
    )


class TelemetryValidationTests(unittest.TestCase):
    def test_health_is_not_serving_when_storage_is_unwritable(self) -> None:
        class UnwritableStore:
            def check_writable(self) -> None:
                raise sqlite3.OperationalError("read-only")

        response = TelemetryCollector(UnwritableStore()).Health(None, None)
        self.assertEqual(response.status, "NOT_SERVING")

    def test_storage_health_opens_a_write_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "telemetry.db")
            store.check_writable()

    def test_accepts_privacy_minimal_packet(self) -> None:
        validate_telemetry_packet(valid_packet())

    def test_rejects_non_finite_risk(self) -> None:
        packet = valid_packet()
        packet.risk_score = math.nan
        with self.assertRaisesRegex(ValueError, "risk_score"):
            validate_telemetry_packet(packet)

    def test_rejects_unknown_category(self) -> None:
        packet = valid_packet()
        packet.categories.append("RAW_PROMPT")
        with self.assertRaisesRegex(ValueError, "category"):
            validate_telemetry_packet(packet)

    def test_rejects_detailed_layer_error(self) -> None:
        packet = valid_packet()
        packet.layers[0].status = "error"
        packet.layers[0].error = "secret stack trace"
        with self.assertRaisesRegex(ValueError, "generic code"):
            validate_telemetry_packet(packet)


if __name__ == "__main__":
    unittest.main()
