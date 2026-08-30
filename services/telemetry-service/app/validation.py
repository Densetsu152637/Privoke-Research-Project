"""Privacy and bounds validation for telemetry packets."""

from __future__ import annotations

import math

from privoke_contracts import Category, PriVokeAction, Sensitivity, Visibility
from privoke_service import validate_choice, validate_text

ALLOWED_ACTIONS = frozenset(value.name for value in PriVokeAction)
ALLOWED_CATEGORIES = frozenset(value.name for value in Category)
ALLOWED_SENSITIVITIES = frozenset(value.name for value in Sensitivity)
ALLOWED_VISIBILITIES = frozenset(value.name for value in Visibility)
ALLOWED_LAYERS = frozenset({"regex", "ner", "semantic"})
ALLOWED_LAYER_STATUSES = frozenset({"ok", "error", "skipped"})
ALLOWED_LAYER_ERRORS = frozenset({"", "detector_error", "short_circuited"})
ALLOWED_RISK_BUCKETS = frozenset({"0.0-0.2", "0.2-0.5", "0.5-0.8", "0.8-1.0"})

MAX_OCCURRED_AT_UNIX_MS = 4_102_444_800_000
MAX_TEXT_LENGTH = 100_000
MAX_ELAPSED_MS = 3_600_000
MAX_LAYER_RESULTS = 10_000
MAX_LAYERS = 16


def validate_telemetry_packet(packet) -> None:
    _validate_identity(packet)
    _validate_measurements(packet)
    _validate_categories(packet.categories)
    _validate_layers(packet.layers)


def _validate_identity(packet) -> None:
    validate_text(packet.event_id, "event_id", required=True, limit=128)
    validate_text(packet.time_bucket, "time_bucket", required=True, limit=32)
    validate_text(packet.source_id, "source_id", required=True, limit=128)
    validate_text(packet.request_id, "request_id", required=False, limit=256)
    validate_text(packet.target_app, "target_app", required=False, limit=256)
    validate_choice(packet.action, "action", ALLOWED_ACTIONS)
    validate_choice(packet.sensitivity, "sensitivity", ALLOWED_SENSITIVITIES)
    validate_choice(packet.visibility, "visibility", ALLOWED_VISIBILITIES)
    validate_text(
        packet.detector_version,
        "detector_version",
        required=True,
        limit=64,
    )


def _validate_measurements(packet) -> None:
    if not 0 < packet.occurred_at_unix_ms <= MAX_OCCURRED_AT_UNIX_MS:
        raise ValueError("occurred_at_unix_ms is outside the supported range.")
    if packet.text_length > MAX_TEXT_LENGTH:
        raise ValueError(f"text_length exceeds {MAX_TEXT_LENGTH} characters.")
    _validate_finite_range(packet.elapsed_ms, "elapsed_ms", 0, MAX_ELAPSED_MS)
    _validate_finite_range(packet.risk_score, "risk_score", 0, 1)
    validate_choice(packet.risk_bucket, "risk_bucket", ALLOWED_RISK_BUCKETS)


def _validate_categories(categories) -> None:
    if len(categories) > len(ALLOWED_CATEGORIES):
        raise ValueError("Too many telemetry categories.")
    if len(set(categories)) != len(categories):
        raise ValueError("Telemetry categories must not contain duplicates.")
    for category in categories:
        validate_choice(category, "category", ALLOWED_CATEGORIES)


def _validate_layers(layers) -> None:
    if len(layers) > MAX_LAYERS:
        raise ValueError(f"Telemetry may contain at most {MAX_LAYERS} layer results.")
    for layer in layers:
        validate_choice(layer.layer, "layer", ALLOWED_LAYERS)
        validate_choice(layer.status, "layer status", ALLOWED_LAYER_STATUSES)
        validate_text(layer.error, "layer error", required=False, limit=64)
        if layer.error not in ALLOWED_LAYER_ERRORS:
            raise ValueError("layer error must use a supported generic code.")
        if layer.result_count > MAX_LAYER_RESULTS:
            raise ValueError(f"layer result_count exceeds {MAX_LAYER_RESULTS}.")


def _validate_finite_range(
    value: float,
    field_name: str,
    lower: float,
    upper: float,
) -> None:
    if not math.isfinite(value) or not lower <= value <= upper:
        raise ValueError(
            f"{field_name} must be finite and between {lower:g} and {upper:g}."
        )
