from __future__ import annotations

import math
import sqlite3
from contextlib import closing
from pathlib import Path

from validation import ALLOWED_VALUES, MIN_EPSILON, MAX_EPSILON

DIMENSIONS = ("action", "risk_bucket", "primary_category", "model_version", "time_bucket")
DIMENSION_EPSILON = len(DIMENSIONS)
SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetry_strata (
    epsilon_micros INTEGER PRIMARY KEY,
    sample_count INTEGER NOT NULL CHECK(sample_count >= 0)
);
CREATE TABLE IF NOT EXISTS telemetry_counts (
    epsilon_micros INTEGER NOT NULL,
    dimension TEXT NOT NULL,
    value TEXT NOT NULL,
    observed_count INTEGER NOT NULL CHECK(observed_count >= 0),
    PRIMARY KEY (epsilon_micros, dimension, value),
    FOREIGN KEY (epsilon_micros) REFERENCES telemetry_strata(epsilon_micros)
);
"""
STRATUM_COLUMNS = frozenset({"epsilon_micros", "sample_count"})
COUNT_COLUMNS = frozenset({"epsilon_micros", "dimension", "value", "observed_count"})


class TelemetryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            legacy = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'telemetry_events'"
            ).fetchone()
            if legacy:
                raise RuntimeError(
                    "legacy unprotected telemetry database schema detected; "
                    "use the new telemetry-ldp-v1.sqlite3 database path. "
                    "Historical data was not imported or deleted."
                )
            for table, expected in (
                ("telemetry_strata", STRATUM_COLUMNS),
                ("telemetry_counts", COUNT_COLUMNS),
            ):
                existing = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                    (table,),
                ).fetchone()
                if existing:
                    columns = frozenset(
                        row[1] for row in connection.execute(f"PRAGMA table_info({table})")
                    )
                    if columns != expected:
                        raise RuntimeError(
                            "incompatible telemetry aggregate schema; "
                            "use a fresh telemetry-ldp-v1.sqlite3 database."
                        )
            connection.executescript(SCHEMA)

    def record(self, packet) -> None:
        epsilon_micros = int(round(float(packet.privacy_epsilon) * 1_000_000))
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO telemetry_strata(epsilon_micros, sample_count) VALUES (?, 0) "
                "ON CONFLICT(epsilon_micros) DO NOTHING",
                (epsilon_micros,),
            )
            connection.execute(
                "UPDATE telemetry_strata SET sample_count = sample_count + 1 "
                "WHERE epsilon_micros = ?",
                (epsilon_micros,),
            )
            for dimension in DIMENSIONS:
                value = getattr(packet, dimension)
                connection.execute(
                    "INSERT INTO telemetry_counts(epsilon_micros, dimension, value, observed_count) "
                    "VALUES (?, ?, ?, 1) ON CONFLICT(epsilon_micros, dimension, value) "
                    "DO UPDATE SET observed_count = observed_count + 1",
                    (epsilon_micros, dimension, value),
                )
            connection.commit()

    def summary(self) -> tuple[int, list[dict[str, object]]]:
        with closing(self._connect()) as connection:
            strata = list(
                connection.execute(
                    "SELECT epsilon_micros, sample_count FROM telemetry_strata ORDER BY epsilon_micros"
                )
            )
            counts = list(
                connection.execute(
                    "SELECT epsilon_micros, dimension, value, observed_count FROM telemetry_counts"
                )
            )
        sample_count = sum(int(row["sample_count"]) for row in strata)
        observed = {
            (int(row["epsilon_micros"]), row["dimension"], row["value"]): int(row["observed_count"])
            for row in counts
        }
        dimensions: list[dict[str, object]] = []
        for dimension in DIMENSIONS:
            values = []
            for value in sorted(ALLOWED_VALUES[dimension]):
                estimate = 0.0
                observed_count = 0
                domain_size = len(ALLOWED_VALUES[dimension])
                for stratum in strata:
                    epsilon_micros = int(stratum["epsilon_micros"])
                    n = int(stratum["sample_count"])
                    epsilon = epsilon_micros / 1_000_000
                    if not math.isfinite(epsilon) or not MIN_EPSILON <= epsilon <= MAX_EPSILON:
                        raise sqlite3.DatabaseError("stored privacy epsilon is invalid")
                    epsilon_per_dimension = epsilon / DIMENSION_EPSILON
                    exp_epsilon = math.exp(epsilon_per_dimension)
                    denominator = exp_epsilon + domain_size - 1
                    truthful_probability = exp_epsilon / denominator
                    other_probability = 1.0 / denominator
                    gap = truthful_probability - other_probability
                    count = observed.get((epsilon_micros, dimension, value), 0)
                    observed_count += count
                    estimate += (count - n * other_probability) / gap
                # Truncation is post-processing, though it introduces estimator bias.
                estimate = min(float(sample_count), max(0.0, estimate))
                values.append(
                    {
                        "value": value,
                        "estimated_count": estimate,
                        "observed_noisy_count": observed_count,
                    }
                )
            dimensions.append({"dimension": dimension, "values": values})
        return sample_count, dimensions

    def check_writable(self) -> None:
        connection = sqlite3.connect(self.path, timeout=0.5)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.rollback()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection
