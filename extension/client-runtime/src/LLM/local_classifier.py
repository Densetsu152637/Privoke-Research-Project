import json
import os
from typing import Any, Dict, List
from urllib import error, request
from urllib.parse import urlsplit

from .abs_classifier import AbstractClassifier
from .prompt import system_prompt, user_prompt
from ..classification import (
    Category,
    ClassificationResult,
    Sensitivity,
    Visibility,
    build_results,
)
from ..env import env_float, env_positive_int


MAX_LLM_RESPONSE_BYTES = 1_048_576

class LocalClassifier(AbstractClassifier):
    """
    Semantic privacy risk classifier backed by LM Studio's local
    OpenAI-compatible API.

    Environment configuration:
    - LM_STUDIO_BASE_URL: defaults to http://localhost:1234/v1
    - LM_STUDIO_MODEL: model id to use; if omitted, the first model returned by
      /v1/models is used.
    - LM_STUDIO_TIMEOUT_SECONDS: request timeout, defaults to 60 seconds.
    - LM_STUDIO_TEMPERATURE: defaults to 0.25.
    - LM_STUDIO_MAX_TOKENS: defaults to 512.
    - LM_STUDIO_RESPONSE_FORMAT: json_schema, json_object, or none.
    - LM_STUDIO_API_KEY: optional bearer token if LM Studio auth is enabled.
    """

    DEFAULT_BASE_URL = "http://localhost:1234/v1"
    DEFAULT_TIMEOUT_SECONDS = 60.0
    DEFAULT_TEMPERATURE = 0.25
    DEFAULT_MAX_TOKENS = 512

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: str | None = None,
        use_environment: bool = True,
    ):
        default_base_url = (
            os.getenv("LM_STUDIO_BASE_URL", self.DEFAULT_BASE_URL)
            if use_environment
            else self.DEFAULT_BASE_URL
        )
        self.base_url = _normalise_base_url(base_url or default_base_url)
        self.model = (
            model
            if not use_environment
            else model or os.getenv("LM_STUDIO_MODEL")
        )
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else (
                env_float("LM_STUDIO_TIMEOUT_SECONDS", self.DEFAULT_TIMEOUT_SECONDS)
                if use_environment
                else self.DEFAULT_TIMEOUT_SECONDS
            )
        )
        self.temperature = (
            temperature
            if temperature is not None
            else (
                env_float("LM_STUDIO_TEMPERATURE", self.DEFAULT_TEMPERATURE)
                if use_environment
                else self.DEFAULT_TEMPERATURE
            )
        )
        self.max_tokens = (
            max_tokens
            if max_tokens is not None
            else (
                env_positive_int("LM_STUDIO_MAX_TOKENS", self.DEFAULT_MAX_TOKENS)
                if use_environment
                else self.DEFAULT_MAX_TOKENS
            )
        )
        self.response_format = _response_format(
            response_format
            if response_format is not None
            else (
                os.getenv("LM_STUDIO_RESPONSE_FORMAT", "json_schema")
                if use_environment
                else "json_schema"
            )
        )
        if use_environment:
            self.api_key = (
                api_key if api_key is not None else os.getenv("LM_STUDIO_API_KEY")
            )
        else:
            self.api_key = api_key
        if self.timeout_seconds <= 0:
            raise ValueError("LM_STUDIO_TIMEOUT_SECONDS must be greater than zero.")

    def classify(self, text: str) -> List[ClassificationResult]:
        model = self._model_id()
        payload: Dict[str, Any] = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt(text),
                },
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
        }

        if self.response_format is not None:
            payload["response_format"] = self.response_format

        response_payload = self._post_chat_completion(payload)
        content = _response_content(response_payload)
        parsed = _parse_json_content(content)
        if parsed is None:
            return []

        results = build_results(parsed)
        for result in results:
            result.metadata.setdefault("classifier", "local_lm_studio")
            result.metadata.setdefault("model", model)
        return results

    def _post_chat_completion(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return _request_json(
            "POST",
            self._endpoint("chat/completions"),
            self._headers(),
            payload,
            self.timeout_seconds,
            "LM Studio chat completion",
        )

    def _model_id(self) -> str:
        if self.model:
            return self.model

        self.model = self._discover_first_model()
        return self.model

    def _discover_first_model(self) -> str:
        try:
            payload = _request_json(
                "GET",
                self._endpoint("models"),
                self._headers(),
                None,
                min(self.timeout_seconds, 10.0),
                "LM Studio model discovery",
            )
        except RuntimeError as exc:
            raise RuntimeError(
                "LM_STUDIO_MODEL is not set and model discovery from LM Studio "
                "failed."
            ) from exc

        for model in payload.get("data", []):
            if isinstance(model, dict):
                model_id = model.get("id")
                if isinstance(model_id, str) and model_id:
                    return model_id

        raise RuntimeError(
            "LM_STUDIO_MODEL is not set and LM Studio returned no available "
            "models. Load a model in LM Studio or set LM_STUDIO_MODEL."
        )

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _endpoint(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"


def _normalise_base_url(base_url: str) -> str:
    normalised = base_url.strip().rstrip("/")
    parsed = urlsplit(normalised)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("LM Studio base URL must be an http(s) URL with a host.")
    if parsed.username or parsed.password:
        raise ValueError("LM Studio base URL must not contain credentials.")
    if parsed.query or parsed.fragment:
        raise ValueError("LM Studio base URL must not contain a query or fragment.")
    if normalised.endswith("/chat/completions"):
        normalised = normalised[: -len("/chat/completions")]
    if not normalised.endswith("/v1"):
        normalised = f"{normalised}/v1"
    return normalised


def _request_json(
    method: str,
    url: str,
    headers: Dict[str, str],
    payload: Dict[str, Any] | None,
    timeout_seconds: float,
    operation: str,
) -> Dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request_obj = request.Request(
        url,
        data=body,
        headers=headers,
        method=method,
    )

    try:
        # The URL is constrained to HTTP(S) by _normalise_base_url.
        with request.urlopen(  # nosec B310
            request_obj,
            timeout=timeout_seconds,
        ) as response:
            response_body = _read_response_body(response, operation)
    except error.HTTPError as exc:
        response_body = _read_response_body(exc, operation, errors="replace")
        raise RuntimeError(
            f"{operation} failed ({exc.code}): {response_body}"
        ) from exc
    except error.URLError as exc:
        raise RuntimeError(f"{operation} failed: {exc.reason}") from exc

    try:
        parsed = json.loads(response_body)
    except ValueError as exc:
        raise RuntimeError(f"{operation} returned a non-JSON response.") from exc

    if not isinstance(parsed, dict):
        raise RuntimeError(f"{operation} returned malformed JSON.")

    return parsed


def _read_response_body(response, operation: str, errors: str = "strict") -> str:
    body = response.read(MAX_LLM_RESPONSE_BYTES + 1)
    if len(body) > MAX_LLM_RESPONSE_BYTES:
        raise RuntimeError(
            f"{operation} response exceeds {MAX_LLM_RESPONSE_BYTES} bytes."
        )
    return body.decode("utf-8", errors=errors)


def _response_format(mode: str) -> Dict[str, Any] | None:
    mode = mode.strip().lower()

    if mode == "json_schema":
        return {
            "type": "json_schema",
            "json_schema": {
                "name": "privoke_semantic_classification",
                "strict": True,
                "schema": _classification_schema(),
            },
        }

    if mode == "json_object":
        return {"type": "json_object"}

    if mode in {"", "none", "off"}:
        return None

    raise ValueError(
        "LM_STUDIO_RESPONSE_FORMAT must be json_schema, json_object, or none."
    )


def _classification_schema() -> Dict[str, Any]:
    result_schema: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "sensitivity": {
                "type": "string",
                "enum": [item.name for item in Sensitivity],
            },
            "visibility": {
                "type": "string",
                "enum": [item.name for item in Visibility],
            },
            "categories": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [item.name for item in Category],
                },
            },
            "section_of_text": {"type": "string"},
            "reasoning": {"type": "string"},
            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
            },
            "span": {
                "type": "array",
                "items": {"type": "integer"},
                "minItems": 2,
                "maxItems": 2,
            },
            "metadata": {
                "type": "object",
                "additionalProperties": True,
            },
        },
        "required": [
            "sensitivity",
            "visibility",
            "categories",
            "section_of_text",
            "reasoning",
        ],
        "additionalProperties": True,
    }

    return {
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": result_schema,
            },
        },
        "required": ["results"],
        "additionalProperties": False,
    }


def _response_content(response_payload: Dict[str, Any]) -> str:
    choices = response_payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("LM Studio response did not contain choices.")

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise RuntimeError("LM Studio response choice was malformed.")

    message = first_choice.get("message")
    if not isinstance(message, dict):
        raise RuntimeError("LM Studio response did not contain a message.")

    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, dict):
        return json.dumps(content)
    if isinstance(content, list):
        return "".join(
            item.get("text", "")
            for item in content
            if isinstance(item, dict)
        ).strip()

    raise RuntimeError("LM Studio response message content was malformed.")


def _parse_json_content(content: str) -> Dict[str, Any] | List[Dict[str, Any]] | None:
    if not content:
        return None

    candidates = [content, _strip_markdown_fence(content)]
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, (dict, list)):
                return parsed
        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(content):
        if char not in "{[":
            continue

        try:
            parsed, _ = decoder.raw_decode(content[index:])
        except json.JSONDecodeError:
            continue

        if isinstance(parsed, (dict, list)):
            return parsed

    return None


def _strip_markdown_fence(content: str) -> str:
    stripped = content.strip()
    if not stripped.startswith("```"):
        return stripped

    lines = stripped.splitlines()
    if len(lines) >= 3 and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()

    return stripped
