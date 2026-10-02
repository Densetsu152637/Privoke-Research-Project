"""Reusable validation for values that cross a service boundary."""

from __future__ import annotations

from collections.abc import Collection


def validate_text(
    value: str,
    field_name: str,
    *,
    required: bool,
    limit: int = 128,
) -> None:
    """Validate bounded text before storage or interpolation into logs."""
    if required and not value:
        raise ValueError(f"{field_name} is required.")
    if len(value) > limit:
        raise ValueError(f"{field_name} exceeds {limit} characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} must not contain control characters.")


def validate_choice(
    value: str,
    field_name: str,
    allowed: Collection[str],
) -> None:
    if value not in allowed:
        raise ValueError(f"{field_name} has an unsupported value.")
