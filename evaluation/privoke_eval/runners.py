from __future__ import annotations

import atexit
import os

from .types import DetectionOutcome


DEFAULT_RUNTIME_TARGET = "127.0.0.1:50054"
_client = None


def runtime_url() -> str:
    """Backward-compatible report field for the runtime endpoint."""
    return f"grpc://{os.getenv('PRIVOKE_RUNTIME_TARGET', DEFAULT_RUNTIME_TARGET)}"


def check_runtime_available() -> None:
    payload = _request_grpc({"operation": "health"})
    if payload.get("status") != "SERVING":
        raise RuntimeError(
            f"PriVoke client runtime is not serving: {payload.get('status')!r}"
        )


def configure_backend(backend: str) -> None:
    configured = os.getenv("PRIVOKE_LLM_CHOICE", "streamed")
    if backend != configured:
        raise RuntimeError(
            f"The running client-runtime uses backend {configured!r}; "
            f"restart it with PRIVOKE_LLM_CHOICE={backend} to evaluate that backend."
        )


def run_pipeline(text: str, backend: str | None, layer: str = "semantic") -> DetectionOutcome:
    if layer not in {"semantic", "pipeline", "runtime", "regex", "ner", "regex-ner"}:
        raise ValueError(f"Unsupported evaluation layer: {layer}")
    if layer in {"semantic", "pipeline", "runtime"}:
        configure_backend(backend or os.getenv("PRIVOKE_LLM_CHOICE", "streamed"))
    payload = _request_grpc(
        {
            "operation": "analyze",
            "text": text,
            "layer": layer,
            "model_id": os.getenv("MODEL_ID", "privoke-baseline"),
        }
    )

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

    action = str(payload.get("action", ""))
    if action not in {"ALLOW", "WARN", "BLOCK"}:
        raise RuntimeError(f"Client runtime returned an invalid action: {action!r}")
    if layer == "semantic":
        executions = payload.get("layers", [])
        if (len(executions) != 1 or executions[0].get("layer") != "DETECTION_LAYER_SEMANTIC"
                or executions[0].get("status") != "ok" or executions[0].get("error")):
            raise RuntimeError("Semantic-only evaluation requires exactly one successful semantic layer execution.")

    confidence = payload.get("confidence")
    elapsed_ms = payload.get("elapsed_ms")
    return DetectionOutcome(
        action=action,
        categories=tuple(categories),
        confidence=float(confidence) if isinstance(confidence, (int, float)) else None,
        elapsed_ms=float(elapsed_ms) if isinstance(elapsed_ms, (int, float)) else 0.0,
        layer_records=tuple(payload.get("layers", [])),
        sensitivity=sensitivity,
        visibility=str(classification.get("visibility", "PU")),
        masked_text=str(payload["masked_text"]) if payload.get("masked_text") else None,
    )


def _request_grpc(request: dict) -> dict:
    try:
        from grpc_runtime_client import grpc, handle, runtime_pb2_grpc
    except ImportError as exc:
        raise RuntimeError(
            "Install evaluation/requirements-host.txt and run python evaluation/setup-host.py "
            "with the same Python interpreter before evaluating."
        ) from exc

    global _client
    target = os.getenv("PRIVOKE_RUNTIME_TARGET", DEFAULT_RUNTIME_TARGET)
    if _client is None or _client[0] != target:
        _close_client()
        channel = grpc.insecure_channel(target)
        _client = (target, channel, runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel))
    try:
        return handle(_client[2], request)
    except grpc.RpcError as exc:
        raise RuntimeError(f"Runtime RPC to {target} failed ({exc.code().name}): {exc.details()}") from exc


def _close_client() -> None:
    global _client
    if _client is not None:
        _client[1].close()
        _client = None


atexit.register(_close_client)
