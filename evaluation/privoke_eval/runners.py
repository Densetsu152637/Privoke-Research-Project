from __future__ import annotations

import atexit
import json
import os
import subprocess
from pathlib import Path

from .types import DetectionOutcome


DEFAULT_RUNTIME_TARGET = "client-runtime:50054"
_bridge: subprocess.Popen[str] | None = None


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
            f"The running Docker client-runtime uses backend {configured!r}; "
            f"restart it with PRIVOKE_LLM_CHOICE={backend} to evaluate that backend."
        )


def run_pipeline(text: str, backend: str) -> DetectionOutcome:
    configure_backend(backend)
    payload = _request_grpc(
        {
            "operation": "analyze",
            "text": text,
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

    confidence = payload.get("confidence")
    elapsed_ms = payload.get("elapsed_ms")
    return DetectionOutcome(
        action=action,
        categories=tuple(categories),
        confidence=float(confidence) if isinstance(confidence, (int, float)) else None,
        elapsed_ms=float(elapsed_ms) if isinstance(elapsed_ms, (int, float)) else 0.0,
        sensitivity=sensitivity,
        visibility=str(classification.get("visibility", "PU")),
        masked_text=str(payload["masked_text"]) if payload.get("masked_text") else None,
    )


def _request_grpc(request: dict) -> dict:
    process = _bridge_process()
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(json.dumps(request, ensure_ascii=False) + "\n")
    process.stdin.flush()
    line = process.stdout.readline()
    if not line:
        detail = process.stderr.read().strip() if process.stderr is not None else ""
        _close_bridge()
        raise RuntimeError(
            "The Docker gRPC evaluation client stopped unexpectedly"
            + (f": {detail}" if detail else ".")
        )
    response = json.loads(line)
    if response.get("error"):
        raise RuntimeError(f"Client runtime analysis failed: {response['error']}")
    return response


def _bridge_process() -> subprocess.Popen[str]:
    global _bridge
    if _bridge is not None and _bridge.poll() is None:
        return _bridge

    repository_root = Path(__file__).resolve().parents[2]
    bridge_source = (repository_root / "evaluation" / "grpc_runtime_client.py").read_text()
    compose_file = repository_root / "docker-compose.yml"
    try:
        _bridge = subprocess.Popen(
            [
                "docker",
                "compose",
                "-f",
                str(compose_file),
                "exec",
                "-T",
                "client-runtime",
                "/opt/venv/bin/python",
                "-u",
                "-c",
                bridge_source,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        raise RuntimeError(
            "Could not start the Docker gRPC evaluation client. Ensure Docker Compose is running."
        ) from exc
    return _bridge


def _close_bridge() -> None:
    global _bridge
    if _bridge is not None:
        if _bridge.stdin is not None:
            _bridge.stdin.close()
        try:
            _bridge.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _bridge.terminate()
        _bridge = None


atexit.register(_close_bridge)
