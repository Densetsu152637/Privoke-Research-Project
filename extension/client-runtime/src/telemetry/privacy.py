"""Local randomized response and durable telemetry privacy-budget accounting."""

from __future__ import annotations

import math
import os
import random
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

MECHANISM = "grr_rr_v1"
EVENT_EPSILON_DEFAULT = 1.0
EVENT_EPSILON_MIN = 0.5
EVENT_EPSILON_MAX = 2.0
DAILY_EPSILON_DEFAULT = 8.0
DAILY_EPSILON_MAX = 8.0
DIMENSIONS = ("action", "risk_bucket", "primary_category", "model_version", "time_bucket")
DOMAINS: Mapping[str, tuple[str, ...]] = {
    "action": ("ALLOW", "WARN", "BLOCK"),
    "risk_bucket": ("0.0-0.2", "0.2-0.5", "0.5-0.8", "0.8-1.0"),
    "primary_category": (
        "NONE", "CHILD", "HEALTH", "CRIMINAL", "SEXUAL", "FINANCIAL",
        "IDENTITY", "LOCATION", "RELIGION", "POLITICS", "THIRD_PARTY",
    ),
    "model_version": ("v0.3.0", "OTHER"),
    "time_bucket": ("00-04_UTC", "04-08_UTC", "08-12_UTC", "12-16_UTC", "16-20_UTC", "20-24_UTC"),
}


def validate_privacy_config(event_epsilon: float, daily_epsilon: float) -> None:
    if not math.isfinite(event_epsilon) or not EVENT_EPSILON_MIN <= event_epsilon <= EVENT_EPSILON_MAX:
        raise ValueError(
            f"TELEMETRY_LDP_EPSILON must be between {EVENT_EPSILON_MIN:g} and {EVENT_EPSILON_MAX:g}."
        )
    if not math.isfinite(daily_epsilon) or not event_epsilon <= daily_epsilon <= DAILY_EPSILON_MAX:
        raise ValueError(
            "TELEMETRY_LDP_DAILY_EPSILON must be at least the per-event epsilon "
            f"and at most {DAILY_EPSILON_MAX:g}."
        )
    if not math.isclose(event_epsilon * 1_000_000, round(event_epsilon * 1_000_000), abs_tol=1e-7):
        raise ValueError("TELEMETRY_LDP_EPSILON must have at most six decimal places.")
    if not math.isclose(daily_epsilon * 1_000_000, round(daily_epsilon * 1_000_000), abs_tol=1e-7):
        raise ValueError("TELEMETRY_LDP_DAILY_EPSILON must have at most six decimal places.")


def default_ledger_path() -> Path:
    configured = os.getenv("TELEMETRY_PRIVACY_LEDGER_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        state_root = os.getenv("LOCALAPPDATA", "").strip()
        if state_root:
            return Path(state_root) / "PriVoke" / "telemetry-budget.sqlite3"
    state_root = os.getenv("XDG_STATE_HOME", "").strip()
    if state_root:
        return Path(state_root) / "privoke" / "telemetry-budget.sqlite3"
    return Path.home() / ".local" / "state" / "privoke" / "telemetry-budget.sqlite3"


def generalized_randomized_response(
    value: str,
    domain: Sequence[str],
    epsilon: float,
    *,
    rng=None,
) -> str:
    """Return k-ary GRR output with a pure epsilon-LDP guarantee."""
    choices = tuple(domain)
    if len(choices) < 2 or len(set(choices)) != len(choices):
        raise ValueError("GRR domain must contain at least two unique values.")
    if value not in choices:
        raise ValueError("GRR input must be in the declared finite domain.")
    if not math.isfinite(epsilon) or epsilon <= 0:
        raise ValueError("GRR epsilon must be finite and positive.")
    source = rng or random.SystemRandom()
    probabilities = grr_probabilities(value, choices, epsilon)
    truthful_probability = probabilities[value]
    if source.random() < truthful_probability:
        return value
    alternatives = tuple(candidate for candidate in choices if candidate != value)
    return source.choice(alternatives)


def grr_probabilities(
    value: str,
    domain: Sequence[str],
    epsilon: float,
) -> dict[str, float]:
    """Return the exact output distribution for one input under k-ary GRR."""
    choices = tuple(domain)
    if len(choices) < 2 or len(set(choices)) != len(choices):
        raise ValueError("GRR domain must contain at least two unique values.")
    if not math.isfinite(epsilon) or epsilon <= 0:
        raise ValueError("GRR epsilon must be finite and positive.")
    if value not in choices:
        raise ValueError("GRR input must be in the declared finite domain.")
    exp_epsilon = math.exp(epsilon)
    denominator = exp_epsilon + len(choices) - 1
    truthful_probability = exp_epsilon / denominator
    other_probability = 1.0 / denominator
    return {
        output: truthful_probability if output == value else other_probability
        for output in choices
    }


def randomize_report(values: Mapping[str, str], epsilon: float, *, rng=None) -> dict[str, str]:
    if set(values) != set(DIMENSIONS):
        raise ValueError("Telemetry report must contain exactly the protected dimensions.")
    validate_privacy_config(epsilon, DAILY_EPSILON_MAX)
    source = rng or random.SystemRandom()
    per_dimension_epsilon = epsilon / len(DIMENSIONS)
    return {
        dimension: generalized_randomized_response(
            values[dimension], DOMAINS[dimension], per_dimension_epsilon, rng=source
        )
        for dimension in DIMENSIONS
    }


class DailyPrivacyBudget:
    """Atomic installation-local UTC-day epsilon ledger; reservations never refund."""

    def __init__(self, path: str | Path, daily_epsilon: float = DAILY_EPSILON_DEFAULT):
        self.path = Path(path)
        self.daily_epsilon = float(daily_epsilon)
        validate_privacy_config(EVENT_EPSILON_MIN, self.daily_epsilon)

    def reserve(self, epsilon: float, *, now: datetime | None = None) -> bool:
        if not math.isfinite(epsilon) or not EVENT_EPSILON_MIN <= epsilon <= EVENT_EPSILON_MAX:
            raise ValueError("Reservation epsilon is outside the supported range.")
        if not math.isclose(epsilon * 1_000_000, round(epsilon * 1_000_000), abs_tol=1e-7):
            raise ValueError("Reservation epsilon must have at most six decimal places.")
        if epsilon > self.daily_epsilon:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            created = not self.path.exists()
            connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            try:
                if created and os.name != "nt":
                    self.path.chmod(0o600)
                connection.execute("PRAGMA busy_timeout=5000")
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                if not integrity or integrity[0] != "ok":
                    raise sqlite3.DatabaseError("privacy budget ledger integrity check failed")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS daily_budget ("
                    "singleton INTEGER PRIMARY KEY CHECK(singleton = 1), "
                    "utc_day TEXT NOT NULL, epsilon_spent REAL NOT NULL)"
                )
                day = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).date().isoformat()
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT OR IGNORE INTO daily_budget (singleton, utc_day, epsilon_spent) "
                    "VALUES (1, ?, 0)",
                    (day,),
                )
                row = connection.execute(
                    "SELECT utc_day, epsilon_spent FROM daily_budget WHERE singleton = 1"
                ).fetchone()
                previous_day = row[0] if row else ""
                spent = float(row[1]) if row else math.nan
                rows = connection.execute("SELECT COUNT(*) FROM daily_budget").fetchone()
                if not rows or rows[0] > 1:
                    raise sqlite3.DatabaseError("privacy budget ledger has invalid rows")
                if not math.isfinite(spent) or spent < 0 or spent > self.daily_epsilon:
                    raise sqlite3.DatabaseError("privacy budget ledger contains invalid accounting data")
                try:
                    if date.fromisoformat(previous_day).isoformat() != previous_day:
                        raise ValueError
                except ValueError as exc:
                    raise sqlite3.DatabaseError("privacy budget ledger contains an invalid UTC day") from exc
                if day < previous_day:
                    raise sqlite3.DatabaseError("system date moved backwards; budget ledger fails closed")
                if day > previous_day:
                    spent = 0.0
                if spent + epsilon > self.daily_epsilon + 1e-12:
                    connection.execute("ROLLBACK")
                    return False
                connection.execute(
                    "UPDATE daily_budget SET utc_day = ?, epsilon_spent = ? WHERE singleton = 1",
                    (day, spent + epsilon),
                )
                connection.execute("COMMIT")
                return True
            finally:
                connection.close()
        except (OSError, sqlite3.Error) as exc:
            raise RuntimeError("telemetry privacy budget unavailable; report suppressed") from exc
