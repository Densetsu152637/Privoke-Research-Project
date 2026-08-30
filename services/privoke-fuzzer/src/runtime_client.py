from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping

import grpc

from privoke_contracts.classification import (
    Category,
    Classification,
    Sensitivity,
    Visibility,
    initialise_unpacked,
    merge_classifications,
)


GENERATED_DIR = Path(__file__).resolve().parents[1] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import runtime_pb2, runtime_pb2_grpc


LAYER_VALUES = {
    "runtime": runtime_pb2.DETECTION_LAYER_RUNTIME,
    "regex": runtime_pb2.DETECTION_LAYER_REGEX,
    "ner": runtime_pb2.DETECTION_LAYER_NER,
    "semantic": runtime_pb2.DETECTION_LAYER_SEMANTIC,
}
LAYER_NAMES = {value: key for key, value in LAYER_VALUES.items()}


class RuntimeAnalysisError(RuntimeError):
    pass


class PrivokeRuntimeClient:
    def __init__(
        self,
        target: str,
        timeout_seconds: float = 10.0,
        max_in_flight: int = 8,
    ):
        self.target = target
        self.timeout_seconds = timeout_seconds
        self.max_in_flight = max_in_flight
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")
        if self.max_in_flight <= 0:
            raise ValueError("max_in_flight must be positive.")

    def analyze(
        self,
        payload: Mapping[str, Any],
        layers: list[str] | tuple[str, ...] | None = None,
        regex_first: bool | None = None,
    ) -> dict[str, Any]:
        return response_to_dict(
            self._analyze(payload, layers=layers, regex_first=regex_first)
        )

    def _analyze(
        self,
        payload: Mapping[str, Any],
        layers: list[str] | tuple[str, ...] | None = None,
        regex_first: bool | None = None,
    ):
        request = self._request(payload, layers=layers, regex_first=regex_first)
        with grpc.insecure_channel(self.target) as channel:
            response = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel).AnalyzePrompt(
                request,
                timeout=self.timeout_seconds,
            )
        return response

    def _request(
        self,
        payload: Mapping[str, Any],
        layers: list[str] | tuple[str, ...] | None = None,
        regex_first: bool | None = None,
    ):
        metadata = payload.get("metadata") or {}
        requested_layers = list(layers or ["runtime"])
        unknown_layers = [layer for layer in requested_layers if layer not in LAYER_VALUES]
        if unknown_layers:
            raise ValueError(f"Unsupported runtime layer: {unknown_layers[0]}")
        return runtime_pb2.AnalyzePromptRequest(
            text=str(payload.get("text") or payload.get("prompt") or ""),
            source=str(payload.get("source") or ""),
            target_app=str(payload.get("target_app") or ""),
            visibility_hint=str(payload.get("visibility_hint") or ""),
            request_id=str(payload.get("request_id") or ""),
            metadata={str(key): _string_value(value) for key, value in metadata.items()},
            layers=[LAYER_VALUES[layer] for layer in requested_layers],
            regex_execution_order=_regex_execution_order(regex_first),
            semantic_model_id=str(payload.get("semantic_model_id") or ""),
        )

    def classify(
        self,
        text: str,
        layer: str = "semantic",
        model_id: str | None = None,
    ) -> Classification:
        return self.classify_many((text,), layer=layer, model_id=model_id)[0]

    def classify_many(
        self,
        texts: list[str] | tuple[str, ...],
        layer: str = "semantic",
        model_id: str | None = None,
    ) -> list[Classification]:
        """Classify prompts concurrently over one shared, thread-safe gRPC channel."""
        if not texts:
            return []
        requests = [
            self._request(
                {
                    "text": text,
                    "source": "privoke-fuzzer-training",
                    "semantic_model_id": model_id,
                },
                layers=[layer],
            )
            for text in texts
        ]
        responses = []
        with grpc.insecure_channel(self.target) as channel:
            method = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel).AnalyzePrompt
            for start in range(0, len(requests), self.max_in_flight):
                pending = [
                    method.future(request, timeout=self.timeout_seconds)
                    for request in requests[start : start + self.max_in_flight]
                ]
                responses.extend(future.result() for future in pending)
        return [_classification_from_response(response) for response in responses]


def response_to_dict(response) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "request_id": response.request_id or None,
        "action": response.action or None,
        "allowed": response.allowed,
        "masked_text": response.masked_text or None,
        "classification": _classification_to_dict(response.classification),
        "reason": response.reason or None,
        "metadata": dict(response.metadata),
        "layers": [_layer_to_dict(layer) for layer in response.layers],
        "elapsed_ms": response.elapsed_ms,
        "error": response.error or None,
    }
    if response.HasField("evidence"):
        payload["evidence"] = _result_to_dict(response.evidence)
    else:
        payload["evidence"] = None
    return payload


def _classification_from_response(response) -> Classification:
    if response.error:
        raise RuntimeAnalysisError(response.error)
    results = [
        result
        for execution in response.layers
        for result in execution.results
    ]
    if results:
        return merge_classifications(
            _classification_from_proto(result.classification)
            for result in results
        )
    return _classification_from_proto(response.classification)


def _classification_from_proto(value) -> Classification:
    if value.packed:
        return Classification(int(value.packed))
    sensitivity = Sensitivity.__members__.get(value.sensitivity, Sensitivity.S0)
    visibility = Visibility.__members__.get(value.visibility, Visibility.PU)
    categories = [
        Category.__members__[category]
        for category in value.categories
        if category in Category.__members__
    ]
    return initialise_unpacked(sensitivity, visibility, categories)


def _classification_to_dict(value) -> dict[str, Any]:
    return {
        "sensitivity": value.sensitivity or "S0",
        "visibility": value.visibility or "PU",
        "categories": list(value.categories),
        "packed": int(value.packed),
    }


def _result_to_dict(result) -> dict[str, Any]:
    return {
        "classification": _classification_to_dict(result.classification),
        "action": result.action or None,
        "section_of_text": result.section_of_text,
        "span": [result.span_start, result.span_end] if result.has_span else None,
        "confidence": result.confidence if result.has_confidence else None,
        "reasoning": result.reasoning,
        "metadata": dict(result.metadata),
    }


def _layer_to_dict(layer) -> dict[str, Any]:
    return {
        "layer": LAYER_NAMES.get(layer.layer, str(layer.layer)),
        "status": layer.status,
        "results": [_result_to_dict(result) for result in layer.results],
        "error": layer.error or None,
    }


def _regex_execution_order(regex_first: bool | None) -> int:
    if regex_first is None:
        return runtime_pb2.REGEX_EXECUTION_ORDER_DEFAULT
    if regex_first:
        return runtime_pb2.REGEX_EXECUTION_ORDER_FIRST
    return runtime_pb2.REGEX_EXECUTION_ORDER_PARALLEL


def _string_value(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)
