"""Convert the additive presence RPC response to strict JSON-safe records."""
from __future__ import annotations

import argparse
import json
import os
import sys

from host_environment import configure_imports, RUNTIME_TARGET

configure_imports()

import grpc

from privoke.v1 import runtime_pb2, runtime_pb2_grpc  # noqa: E402


def handle(stub, request: dict) -> dict:
    if not isinstance(request, dict) or request.get("operation") != "presence":
        raise ValueError("Unsupported presence bridge operation.")
    request_id = request.get("request_id")
    text = request.get("text")
    model_id = request.get("model_id")
    if not all(isinstance(value, str) and value for value in (request_id, model_id)) or not isinstance(text, str):
        raise ValueError("Presence request ID/model ID/text is invalid.")
    response = stub.DetectAnnotationPresence(
        runtime_pb2.DetectAnnotationPresenceRequest(request_id=request_id, text=text, model_id=model_id),
        timeout=120)
    return {"request_id": response.request_id, "model_id": response.model_id,
            "model_version": response.model_version, "probability": response.probability,
            "threshold": response.threshold, "predicted_label": int(response.predicted_label),
            "artifact_checksum": response.artifact_checksum,
            "parameter_fingerprint": response.parameter_fingerprint,
            "elapsed_ms": response.elapsed_ms, "error": response.error}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=os.getenv("PRIVOKE_RUNTIME_TARGET", RUNTIME_TARGET))
    args = parser.parse_args()
    with grpc.insecure_channel(args.target) as channel:
        stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
        for line in sys.stdin:
            try:
                response = handle(stub, json.loads(line))
            except Exception as exc:
                response = {"error": str(exc) or exc.__class__.__name__}
            print(json.dumps(response, ensure_ascii=False, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
