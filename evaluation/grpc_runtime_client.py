"""JSON-lines bridge to the running client-runtime gRPC service.

Run on the host against localhost, or pass an explicit service target when
running in a container. Only generated protobuf clients are imported.
"""

from __future__ import annotations

import json
import os
import sys

from host_environment import configure_imports, RUNTIME_TARGET

configure_imports()

import grpc


from privoke.v1 import runtime_pb2, runtime_pb2_grpc  # noqa: E402


TARGET = os.getenv("PRIVOKE_RUNTIME_TARGET", RUNTIME_TARGET)

LAYER_NAMES = {
    "pipeline": runtime_pb2.DETECTION_LAYER_RUNTIME,
    "runtime": runtime_pb2.DETECTION_LAYER_RUNTIME,
    "regex": runtime_pb2.DETECTION_LAYER_REGEX,
    "ner": runtime_pb2.DETECTION_LAYER_NER,
    "semantic": runtime_pb2.DETECTION_LAYER_SEMANTIC,
}


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
            layers=(
                [runtime_pb2.DETECTION_LAYER_REGEX, runtime_pb2.DETECTION_LAYER_NER]
                if request.get("layer") == "regex-ner"
                else [_layer_value(request.get("layer", "pipeline"))]
            ),
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
                "results": [{
                    "sensitivity": result.classification.sensitivity,
                    "categories": list(result.classification.categories),
                    "action": result.action,
                    "metadata": dict(result.metadata),
                } for result in layer.results],
            }
            for layer in response.layers
        ],
    }


def _layer_value(layer: str) -> int:
    try:
        return LAYER_NAMES[layer]
    except KeyError as exc:
        raise ValueError(f"Unsupported evaluation layer: {layer}") from exc


if __name__ == "__main__":
    main()
