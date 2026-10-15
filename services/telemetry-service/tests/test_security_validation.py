from __future__ import annotations

import math
import sqlite3
import sys
import tempfile
import unittest
from concurrent import futures
from pathlib import Path

import grpc

SERVICE_ROOT = Path(__file__).resolve().parents[1]
for path in (SERVICE_ROOT / "app", SERVICE_ROOT / "generated"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from privoke.v1 import telemetry_pb2
from privoke.v1 import telemetry_pb2_grpc
from server import TelemetryCollector, validate_telemetry_packet
from storage import TelemetryStore
from validation import ALLOWED_VALUES


def valid_packet(**overrides):
    values = {
        "time_bucket": "12-16_UTC",
        "action": "WARN",
        "primary_category": "HEALTH",
        "risk_bucket": "0.5-0.8",
        "model_version": "v0.3.0",
        "privacy_mechanism": "grr_rr_v1",
        "privacy_epsilon": 1.0,
    }
    values.update(overrides)
    return telemetry_pb2.TelemetryPacket(**values)


class TelemetryValidationTests(unittest.TestCase):
    def test_health_is_not_serving_when_storage_is_unwritable(self) -> None:
        class UnwritableStore:
            def check_writable(self) -> None:
                raise sqlite3.OperationalError("read-only")

        response = TelemetryCollector(UnwritableStore()).Health(None, None)
        self.assertEqual(response.status, "NOT_SERVING")

    def test_storage_keeps_only_epsilon_stratified_aggregate_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "telemetry.db")
            packet = valid_packet()
            store.record(packet)
            store.record(valid_packet(action="BLOCK", privacy_epsilon=0.5))
            connection = store._connect()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            stored_rows = connection.execute("SELECT COUNT(*) FROM telemetry_counts").fetchone()[0]
            strata = connection.execute(
                "SELECT epsilon_micros, sample_count FROM telemetry_strata ORDER BY epsilon_micros"
            ).fetchall()
            connection.close()

        self.assertEqual(tables, {"telemetry_strata", "telemetry_counts"})
        self.assertEqual(stored_rows, 10)  # five marginals per epsilon stratum
        self.assertEqual([tuple(row) for row in strata], [(500_000, 1), (1_000_000, 1)])

    def test_summary_debiases_each_epsilon_stratum_separately(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "telemetry.db")
            store.record(valid_packet(action="ALLOW", privacy_epsilon=1.0))
            store.record(valid_packet(action="BLOCK", privacy_epsilon=0.5))
            sample_count, dimensions = store.summary()

        self.assertEqual(sample_count, 2)
        action = next(item for item in dimensions if item["dimension"] == "action")
        estimates = {item["value"]: item for item in action["values"]}

        def contribution(observed: int, sample_n: int, epsilon: float, domain_size: int) -> float:
            exp_epsilon = math.exp(epsilon / 5)
            q = 1 / (exp_epsilon + domain_size - 1)
            p = exp_epsilon / (exp_epsilon + domain_size - 1)
            return (observed - sample_n * q) / (p - q)

        expected_allow = min(
            2.0,
            max(0.0, contribution(1, 1, 1.0, 3) + contribution(0, 1, 0.5, 3)),
        )
        self.assertAlmostEqual(estimates["ALLOW"]["estimated_count"], expected_allow)
        self.assertEqual(estimates["ALLOW"]["observed_noisy_count"], 1)

    def test_live_record_and_summary_grpc_flow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "telemetry.db")
            server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
            telemetry_pb2_grpc.add_TelemetryServiceServicer_to_server(
                TelemetryCollector(store), server
            )
            port = server.add_insecure_port("127.0.0.1:0")
            server.start()
            try:
                with grpc.insecure_channel(f"127.0.0.1:{port}") as channel:
                    client = telemetry_pb2_grpc.TelemetryServiceStub(channel)
                    accepted = client.RecordTelemetry(valid_packet())
                    summary = client.GetTelemetrySummary(
                        telemetry_pb2.GetTelemetrySummaryRequest()
                    )
            finally:
                server.stop(grace=None).wait()

        self.assertTrue(accepted.accepted)
        self.assertEqual(summary.sample_count, 1)
        self.assertEqual({row.dimension for row in summary.dimensions}, {
            "action", "risk_bucket", "primary_category", "model_version", "time_bucket"
        })

    def test_accepts_protected_packet(self) -> None:
        validate_telemetry_packet(valid_packet())

    def test_rejects_missing_or_untrusted_mechanism(self) -> None:
        for mechanism in ("", "none", "central_dp"):
            with self.subTest(mechanism=mechanism):
                with self.assertRaisesRegex(ValueError, "mechanism"):
                    validate_telemetry_packet(
                        valid_packet(privacy_mechanism=mechanism)
                    )

    def test_rejects_invalid_epsilon_boundaries_and_non_finite_values(self) -> None:
        for epsilon in (0.0, 0.4999, 2.0001, math.inf, math.nan):
            with self.subTest(epsilon=epsilon):
                with self.assertRaisesRegex(ValueError, "privacy_epsilon"):
                    validate_telemetry_packet(valid_packet(privacy_epsilon=epsilon))
        validate_telemetry_packet(valid_packet(privacy_epsilon=0.5))
        validate_telemetry_packet(valid_packet(privacy_epsilon=2.0))

    def test_rejects_values_outside_fixed_domains(self) -> None:
        for field in ALLOWED_VALUES:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    validate_telemetry_packet(valid_packet(**{field: "unbounded-input"}))

    def test_legacy_wire_packet_fails_closed(self) -> None:
        # A pre-LDP packet has fields 1-16. The new protocol reserves those tags
        # and requires the GRR marker at tag 25, which legacy senders cannot set.
        legacy_wire = b"\x3a\x04WARN"  # old action field at tag 7
        legacy = telemetry_pb2.TelemetryPacket.FromString(legacy_wire)
        with self.assertRaisesRegex(ValueError, "mechanism"):
            validate_telemetry_packet(legacy)

    def test_explicit_legacy_database_path_fails_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE telemetry_events (event_id TEXT, source_id TEXT, risk_score REAL)"
            )
            connection.execute("INSERT INTO telemetry_events VALUES ('old', 'client', 0.7)")
            connection.commit()
            connection.close()

            with self.assertRaisesRegex(RuntimeError, "legacy unprotected"):
                TelemetryStore(path)
            connection = sqlite3.connect(path)
            rows = connection.execute("SELECT * FROM telemetry_events").fetchall()
            connection.close()
        self.assertEqual(rows, [("old", "client", 0.7)])

    def test_summary_inverts_rr_and_clips_impossible_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(Path(directory) / "telemetry.db")
            store.record(valid_packet(action="ALLOW", privacy_epsilon=1.0))
            sample_count, dimensions = store.summary()

        self.assertEqual(sample_count, 1)
        action = next(item for item in dimensions if item["dimension"] == "action")
        estimates = {item["value"]: item for item in action["values"]}
        epsilon_i = 1.0 / 5
        exp_epsilon = math.exp(epsilon_i)
        q = 1 / (exp_epsilon + 3 - 1)
        p = exp_epsilon / (exp_epsilon + 3 - 1)
        expected_allow = min(1.0, max(0.0, (1.0 - q) / (p - q)))
        self.assertAlmostEqual(estimates["ALLOW"]["estimated_count"], expected_allow)
        self.assertEqual(estimates["ALLOW"]["observed_noisy_count"], 1)
        self.assertTrue(all(0.0 <= row["estimated_count"] <= 1.0 for row in action["values"]))


if __name__ == "__main__":
    unittest.main()
