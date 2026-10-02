"""Strict ingestion validation for locally privatized telemetry reports."""

from __future__ import annotations

import math

from privoke_service import validate_choice

MECHANISM = "grr_rr_v1"
MIN_EPSILON = 0.5
MAX_EPSILON = 2.0
ALLOWED_VALUES = {
    "time_bucket": frozenset(
        {"00-04_UTC", "04-08_UTC", "08-12_UTC", "12-16_UTC", "16-20_UTC", "20-24_UTC"}
    ),
    "action": frozenset({"ALLOW", "WARN", "BLOCK"}),
    "primary_category": frozenset(
        {"NONE", "CHILD", "HEALTH", "CRIMINAL", "SEXUAL", "FINANCIAL", "IDENTITY", "LOCATION", "RELIGION", "POLITICS", "THIRD_PARTY"}
    ),
    "risk_bucket": frozenset({"0.0-0.2", "0.2-0.5", "0.5-0.8", "0.8-1.0"}),
    "model_version": frozenset({"v0.3.0", "OTHER"}),
}


def validate_telemetry_packet(packet) -> None:
    if packet.privacy_mechanism != MECHANISM:
        raise ValueError("Unsupported or missing local privacy mechanism.")
    if (
        not math.isfinite(packet.privacy_epsilon)
        or not MIN_EPSILON <= packet.privacy_epsilon <= MAX_EPSILON
    ):
        raise ValueError(
            f"privacy_epsilon must be finite and between {MIN_EPSILON:g} and {MAX_EPSILON:g}."
        )
    if not math.isclose(packet.privacy_epsilon * 1_000_000, round(packet.privacy_epsilon * 1_000_000), abs_tol=1e-7):
        raise ValueError("privacy_epsilon must have at most six decimal places.")
    for field, allowed in ALLOWED_VALUES.items():
        validate_choice(getattr(packet, field), field, allowed)
