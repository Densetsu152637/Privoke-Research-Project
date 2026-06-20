from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict

from ..config import (
    GLOBAL_CONFIG,
    LLMChoice,
    LLMRuntimeConfig,
    LocalEndpointConfig,
    OpenAIEndpointConfig,
    StreamedEndpointConfig,
)
from .models import RequestValidationError


def current_llm_config_response() -> Dict[str, Any]:
    return {
        "llm": serialize_llm_config(GLOBAL_CONFIG.get_llm_config()),
    }


def update_llm_config_from_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise RequestValidationError("Request body must be a JSON object.")

    previous = GLOBAL_CONFIG.get_llm_config()
    choice = _parse_choice(payload, previous.choice)

    streamed = _updated_streamed_config(previous.streamed, payload)
    local = _updated_local_config(previous.local, payload)
    openai = _updated_openai_config(previous.openai, payload)

    updated = LLMRuntimeConfig(
        choice=choice,
        streamed=streamed,
        local=local,
        openai=openai,
    )
    GLOBAL_CONFIG.set_llm_config(updated)

    return {
        "previous": serialize_llm_config(previous),
        "current": serialize_llm_config(updated),
    }


def serialize_llm_config(config: LLMRuntimeConfig) -> Dict[str, Any]:
    return {
        "choice": config.choice.api_name,
        "streamed": {
            "target": config.streamed.target,
            "model_id": config.streamed.model_id,
            "consumer_id": config.streamed.consumer_id,
            "timeout_seconds": config.streamed.timeout_seconds,
        },
        "local": {
            "base_url": config.local.base_url,
            "model": config.local.model,
            "api_key": _redact_secret(config.local.api_key),
            "api_key_configured": bool(config.local.api_key),
            "timeout_seconds": config.local.timeout_seconds,
            "temperature": config.local.temperature,
            "max_tokens": config.local.max_tokens,
            "response_format": config.local.response_format,
        },
        "openai": {
            "model": config.openai.model,
            "base_url": config.openai.base_url,
            "api_key": _redact_secret(config.openai.api_key),
            "api_key_configured": bool(config.openai.api_key),
            "timeout_seconds": config.openai.timeout_seconds,
            "temperature": config.openai.temperature,
            "max_tokens": config.openai.max_tokens,
        },
    }


def _parse_choice(payload: Dict[str, Any], current: LLMChoice) -> LLMChoice:
    raw_choice = payload.get("choice")
    if raw_choice is None:
        return current

    try:
        return LLMChoice.parse(raw_choice)
    except ValueError as exc:
        raise RequestValidationError(str(exc)) from exc


def _updated_streamed_config(
    current: StreamedEndpointConfig,
    payload: Dict[str, Any],
) -> StreamedEndpointConfig:
    section = _section(payload, "streamed")
    if not section:
        return current

    return replace(
        current,
        target=_optional_non_empty_string(section, "target", current.target),
        model_id=_optional_non_empty_string(section, "model_id", current.model_id),
        consumer_id=_optional_non_empty_string(
            section,
            "consumer_id",
            current.consumer_id,
        ),
        timeout_seconds=_optional_positive_float(
            section,
            "timeout_seconds",
            current.timeout_seconds,
        ),
    )


def _updated_local_config(
    current: LocalEndpointConfig,
    payload: Dict[str, Any],
) -> LocalEndpointConfig:
    section = _section(payload, "local")
    if not section:
        return current

    return replace(
        current,
        base_url=_optional_non_empty_string(section, "base_url", current.base_url),
        model=_optional_string(section, "model", current.model),
        api_key=_optional_string(section, "api_key", current.api_key),
        timeout_seconds=_optional_positive_float(
            section,
            "timeout_seconds",
            current.timeout_seconds,
        ),
        temperature=_optional_non_negative_float(
            section,
            "temperature",
            current.temperature,
        ),
        max_tokens=_optional_positive_int(section, "max_tokens", current.max_tokens),
        response_format=_optional_choice(
            section,
            "response_format",
            current.response_format,
            {"json_schema", "json_object", "none", "off"},
        ),
    )


def _updated_openai_config(
    current: OpenAIEndpointConfig,
    payload: Dict[str, Any],
) -> OpenAIEndpointConfig:
    section = _section(payload, "openai")
    if not section:
        return current

    return replace(
        current,
        api_key=_optional_string(section, "api_key", current.api_key),
        model=_optional_non_empty_string(section, "model", current.model),
        base_url=_optional_string(section, "base_url", current.base_url),
        timeout_seconds=_optional_positive_float(
            section,
            "timeout_seconds",
            current.timeout_seconds,
        ),
        temperature=_optional_non_negative_float(
            section,
            "temperature",
            current.temperature,
        ),
        max_tokens=_optional_positive_int(section, "max_tokens", current.max_tokens),
    )


def _section(payload: Dict[str, Any], *names: str) -> Dict[str, Any]:
    for name in names:
        if name not in payload:
            continue
        raw_section = payload[name]
        if raw_section is None:
            return {}
        if not isinstance(raw_section, dict):
            raise RequestValidationError(f"'{name}' must be an object when provided.")
        return raw_section

    return {}


def _optional_string(
    payload: Dict[str, Any],
    key: str,
    current: str | None,
) -> str | None:
    if key not in payload:
        return current

    raw_value = payload[key]
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        raise RequestValidationError(f"'{key}' must be a string or null.")

    stripped = raw_value.strip()
    return stripped or None


def _optional_non_empty_string(
    payload: Dict[str, Any],
    key: str,
    current: str,
) -> str:
    if key not in payload:
        return current

    raw_value = payload[key]
    if not isinstance(raw_value, str) or not raw_value.strip():
        raise RequestValidationError(f"'{key}' must be a non-empty string.")

    return raw_value.strip()


def _optional_positive_float(
    payload: Dict[str, Any],
    key: str,
    current: float,
) -> float:
    if key not in payload:
        return current

    raw_value = payload[key]
    if not isinstance(raw_value, (int, float)) or isinstance(raw_value, bool):
        raise RequestValidationError(f"'{key}' must be a number.")

    value = float(raw_value)
    if value <= 0:
        raise RequestValidationError(f"'{key}' must be greater than zero.")
    return value


def _optional_non_negative_float(
    payload: Dict[str, Any],
    key: str,
    current: float,
) -> float:
    if key not in payload:
        return current

    raw_value = payload[key]
    if not isinstance(raw_value, (int, float)) or isinstance(raw_value, bool):
        raise RequestValidationError(f"'{key}' must be a number.")

    value = float(raw_value)
    if value < 0:
        raise RequestValidationError(f"'{key}' must be zero or greater.")
    return value


def _optional_positive_int(
    payload: Dict[str, Any],
    key: str,
    current: int,
) -> int:
    if key not in payload:
        return current

    raw_value = payload[key]
    if not isinstance(raw_value, int) or isinstance(raw_value, bool):
        raise RequestValidationError(f"'{key}' must be an integer.")

    if raw_value <= 0:
        raise RequestValidationError(f"'{key}' must be greater than zero.")
    return raw_value


def _optional_choice(
    payload: Dict[str, Any],
    key: str,
    current: str,
    allowed: set[str],
) -> str:
    if key not in payload:
        return current

    raw_value = payload[key]
    if not isinstance(raw_value, str):
        raise RequestValidationError(f"'{key}' must be a string.")

    value = raw_value.strip().lower()
    if value not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise RequestValidationError(f"'{key}' must be one of: {allowed_values}.")
    return value


def _redact_secret(secret: str | None) -> str | None:
    if not secret:
        return None
    return "********"
