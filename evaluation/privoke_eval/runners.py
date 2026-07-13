from __future__ import annotations

import os
import json
from time import perf_counter
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .types import DetectionOutcome


DEFAULT_RUNTIME_URL = "http://127.0.0.1:8765"
_configured_backend: str | None = None


def runtime_url() -> str:
    return os.getenv("PRIVOKE_RUNTIME_URL", DEFAULT_RUNTIME_URL).rstrip("/")


def check_runtime_available() -> None:
    url = f"{runtime_url()}/health"
    try:
        _request_json(url, timeout=5)
    except (HTTPError, URLError, ValueError) as exc:
        raise RuntimeError(
            f"PriVoke client runtime is unavailable at {url}. "
            "Start the client-runtime container before running evaluation."
        ) from exc


def configure_backend(backend: str) -> None:
    global _configured_backend
    if _configured_backend == backend:
        return

    url = f"{runtime_url()}/config/llm"
    try:
        _request_json(url, payload={"choice": backend}, timeout=10)
    except (HTTPError, URLError, ValueError) as exc:
        detail = _response_detail(exc)
        raise RuntimeError(
            f"Could not configure client runtime backend '{backend}' at {url}{detail}"
        ) from exc
    _configured_backend = backend


def run_pipeline(text: str, backend: str) -> DetectionOutcome:
    configure_backend(backend)
    url = f"{runtime_url()}/analyze"
    started = perf_counter()
    try:
        payload = _request_json(
            url,
            payload={"text": text, "source": "privoke-evaluation"},
            timeout=float(os.getenv("PRIVOKE_RUNTIME_TIMEOUT_SECONDS", "120")),
        )
    except (HTTPError, URLError, ValueError) as exc:
        detail = _response_detail(exc)
        raise RuntimeError(f"Client runtime analysis failed at {url}{detail}") from exc

    classification = payload.get("classification")
    if not isinstance(classification, dict):
        raise RuntimeError("Client runtime returned a missing or invalid classification object.")

    sensitivity = classification.get("sensitivity")
    if sensitivity not in {"S0", "S1", "S2", "S3"}:
        raise RuntimeError(
            f"Client runtime returned an invalid classification sensitivity: {sensitivity!r}"
        )

    categories = classification.get("categories")
    if not isinstance(categories, list) or not all(isinstance(item, str) for item in categories):
        raise RuntimeError("Client runtime returned invalid classification categories.")

    evidence = payload.get("evidence") or {}
    metadata = payload.get("metadata") or {}
    elapsed_ms = metadata.get("elapsed_ms")
    if not isinstance(elapsed_ms, (int, float)):
        elapsed_ms = (perf_counter() - started) * 1000

    action = str(payload.get("action", ""))
    if action not in {"ALLOW", "WARN", "BLOCK"}:
        raise RuntimeError(f"Client runtime returned an invalid action: {action!r}")

    return DetectionOutcome(
        action=action,
        categories=tuple(categories),
        confidence=(
            float(evidence["confidence"])
            if isinstance(evidence.get("confidence"), (int, float))
            else None
        ),
        elapsed_ms=float(elapsed_ms),
        sensitivity=sensitivity,
        visibility=str(classification.get("visibility", "PU")),
        masked_text=(
            str(payload["masked_text"])
            if isinstance(payload.get("masked_text"), str)
            else None
        ),
    )


def _response_detail(exc: Exception) -> str:
    if isinstance(exc, HTTPError):
        body = exc.read().decode("utf-8", errors="replace")
        return f" (HTTP {exc.code}): {body}"
    return f": {exc}"


def _request_json(
    url: str,
    payload: dict | None = None,
    timeout: float = 10,
) -> dict:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=headers, method="POST" if data else "GET")
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - configured local runtime
        decoded = json.loads(response.read().decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError(f"Expected a JSON object from {url}.")
    return decoded
