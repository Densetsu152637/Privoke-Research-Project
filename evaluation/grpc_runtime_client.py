"""JSON-lines bridge to the running client-runtime gRPC service.

This file is executed inside the existing client-runtime container by the
evaluation runner. It imports only generated protobuf client stubs, never
PriVoke detector implementation modules.
"""

from __future__ import annotations

import json
import sys

import grpc


sys.path.insert(0, "/workspace/extension/client-runtime/generated")

from privoke.v1 import runtime_pb2, runtime_pb2_grpc  # noqa: E402


TARGET = "127.0.0.1:50054"


def main() -> None:
    with grpc.insecure_channel(TARGET) as channel:
        stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
        for line in sys.stdin:
            try:
                request = json.loads(line)
                response = handle(stub, request)
            except Exception as exc:  # returned to the host evaluator as a runtime error
                response = {"error": str(exc) or exc.__class__.__name__}
            print(json.dumps(response, ensure_ascii=False), flush=True)


def handle(stub, request: dict) -> dict:
    if request.get("operation") == "health":
        response = stub.Health(runtime_pb2.RuntimeHealthRequest(), timeout=5)
        return {"service": response.service, "status": response.status}

    if request.get("operation") != "analyze":
        raise ValueError("Unsupported evaluation bridge operation")

    response = stub.AnalyzePrompt(
        runtime_pb2.AnalyzePromptRequest(
            text=request["text"],
            source="privoke-evaluation",
            layers=[runtime_pb2.DETECTION_LAYER_RUNTIME],
            semantic_model_id=request.get("model_id", "privoke-baseline"),
        ),
        timeout=120,
    )
    if response.error:
        raise RuntimeError(response.error)
    evidence = response.evidence
    return {
        "action": response.action,
        "masked_text": response.masked_text or None,
        "classification": {
            "sensitivity": response.classification.sensitivity,
            "visibility": response.classification.visibility,
            "categories": list(response.classification.categories),
        },
        "confidence": evidence.confidence if evidence.has_confidence else None,
        "elapsed_ms": response.elapsed_ms,
        "layers": [
            {
                "layer": runtime_pb2.DetectionLayer.Name(layer.layer),
                "status": layer.status,
                "error": layer.error or None,
            }
            for layer in response.layers
        ],
    }


if __name__ == "__main__":
    main()
