from __future__ import annotations

from typing import Any, Dict

from ..classification import (
    Classification,
    ClassificationResult,
    PriVokeAction,
    Sensitivity,
    Visibility,
    initialise_unpacked,
)
from .models import PromptInspectionRequest, RequestValidationError


DEFAULT_MAX_TEXT_CHARS = 20_000


def parse_prompt_request(
    payload: Any,
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
) -> PromptInspectionRequest:
    if not isinstance(payload, dict):
        raise RequestValidationError("Request body must be a JSON object.")

    raw_text = payload.get("text", payload.get("prompt"))
    if not isinstance(raw_text, str):
        raise RequestValidationError("Request body must include string field 'text'.")

    text = raw_text.strip()
    if not text:
        raise RequestValidationError("Prompt text must not be empty.")
    if len(text) > max_text_chars:
        raise RequestValidationError(
            f"Prompt text exceeds {max_text_chars} characters.",
            status_code=413,
        )

    metadata = payload.get("metadata", {})
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise RequestValidationError("'metadata' must be an object when provided.")

    return PromptInspectionRequest(
        text=text,
        source=_optional_string(payload.get("source"), "source"),
        visibility_hint=_parse_visibility_hint(payload.get("visibility_hint")),
        target_app=_optional_string(payload.get("target_app"), "target_app"),
        request_id=_optional_string(payload.get("request_id"), "request_id"),
        metadata=metadata,
    )


def serialize_analysis_response(
    request: PromptInspectionRequest,
    result: ClassificationResult | None,
    action: PriVokeAction,
    elapsed_ms: float,
) -> Dict[str, Any]:
    classification = (
        result.classification
        if result is not None
        else _default_classification(request.visibility_hint)
    )

    return {
        "request_id": request.request_id,
        "action": action.name,
        "allowed": action != PriVokeAction.BLOCK,
        "masked_text": _masked_text(request.text, result, action),
        "classification": serialize_classification(classification),
        "reason": result.reasoning if result is not None else "No privacy risk detected.",
        "evidence": _serialize_evidence(result),
        "metadata": {
            "source": request.source,
            "target_app": request.target_app,
            "visibility_hint": (
                request.visibility_hint.name if request.visibility_hint else None
            ),
            "text_length": len(request.text),
            "elapsed_ms": round(elapsed_ms, 3),
            "detector": "client-runtime.pipeline",
        },
    }


def serialize_classification(classification: Classification) -> Dict[str, Any]:
    return classification.to_dict()


def error_response(message: str, status_code: int) -> Dict[str, Any]:
    return {
        "error": {
            "message": message,
            "status_code": status_code,
        }
    }


def _parse_visibility_hint(raw_value: Any) -> Visibility | None:
    if raw_value is None or raw_value == "":
        return None
    if isinstance(raw_value, Visibility):
        return raw_value
    if not isinstance(raw_value, str):
        raise RequestValidationError("'visibility_hint' must be a string.")

    try:
        return Visibility[raw_value.upper()]
    except KeyError as exc:
        allowed = ", ".join(item.name for item in Visibility)
        raise RequestValidationError(
            f"'visibility_hint' must be one of: {allowed}."
        ) from exc


def _optional_string(raw_value: Any, field_name: str) -> str | None:
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        raise RequestValidationError(f"'{field_name}' must be a string when provided.")
    return raw_value


def _default_classification(visibility: Visibility | None) -> Classification:
    return initialise_unpacked(
        Sensitivity.S0,
        visibility or Visibility.PU,
        [],
    )


def _serialize_evidence(result: ClassificationResult | None) -> Dict[str, Any] | None:
    if result is None:
        return None

    return {
        "section_of_text": result.section_of_text,
        "span": list(result.span) if result.span is not None else None,
        "reasoning": result.reasoning,
        "confidence": result.confidence,
        "action": result.action().name,
        "metadata": result.metadata,
    }


def _masked_text(
    text: str,
    result: ClassificationResult | None,
    action: PriVokeAction,
) -> str | None:
    if action != PriVokeAction.WARN or result is None or result.span is None:
        return None

    start, end = result.span
    if not (0 <= start < end <= len(text)):
        return None

    return f"{text[:start]}[PRIVOKE_MASKED]{text[end:]}"
