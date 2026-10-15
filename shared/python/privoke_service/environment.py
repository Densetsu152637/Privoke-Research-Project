"""Consistent environment-variable parsing for service configuration."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import TypeVar

ParsedValue = TypeVar("ParsedValue")


def env_string(name: str, default: str, *, strip: bool = False) -> str:
    """Read a string, using the default only when the variable is absent."""
    value = os.getenv(name, default)
    return value.strip() if strip else value


def env_int(name: str, default: int) -> int:
    return _parse_env(name, default, int, "an integer")


def env_float(name: str, default: float) -> float:
    return _parse_env(name, default, float, "a number")


def _parse_env(
    name: str,
    default: ParsedValue,
    parser: Callable[[str], ParsedValue],
    expected_type: str,
) -> ParsedValue:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return parser(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be {expected_type}.") from exc
