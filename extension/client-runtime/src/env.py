from __future__ import annotations

import os
from pathlib import Path

from privoke_service.stack_connection import load_runtime_environment

load_runtime_environment(Path(__file__).resolve().parents[1])


def env_optional_str(name: str) -> str | None:
    raw_value = os.getenv(name)
    if raw_value is None:
        return None

    stripped = raw_value.strip()
    return stripped or None


def env_bool(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.lower() in {"1", "true", "yes", "on"}


def env_float(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        return float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number.") from exc


def env_positive_float(name: str, default: float) -> float:
    value = env_float(name, default)
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return value


def env_non_negative_float(name: str, default: float) -> float:
    value = env_float(name, default)
    if value < 0:
        raise ValueError(f"{name} must be zero or greater.")
    return value


def env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        return int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc


def env_positive_int(name: str, default: int) -> int:
    value = env_int(name, default)
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return value
