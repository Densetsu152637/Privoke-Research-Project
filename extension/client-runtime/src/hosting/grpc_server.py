from __future__ import annotations

import json
from concurrent import futures
from typing import Any, Mapping

import grpc

from ..classification import Classification, ClassificationResult
from ..pipeline import DETECTION_LAYERS, LayerExecution
from ..telemetry import TelemetryReporter
from .analyzer import PromptAnalysis, analyse_prompt
from .serialization import (
    DEFAULT_MAX_TEXT_CHARS,
    classification_for_response,
    parse_prompt_request,
)

from privoke.v1 import runtime_pb2, runtime_pb2_grpc


PROTO_TO_LAYER = {
    runtime_pb2.DETECTION_LAYER_REGEX: "regex",
    runtime_pb2.DETECTION_LAYER_NER: "ner",
    runtime_pb2.DETECTION_LAYER_SEMANTIC: "semantic",
}
LAYER_TO_PROTO = {value: key for key, value in PROTO_TO_LAYER.items()}


class PrivokeRuntimeService(runtime_pb2_grpc.PrivokeRuntimeServiceServicer):
    def __init__(
        self,
        max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
        telemetry_reporter: TelemetryReporter | None = None,
    ):
        self.max_text_chars = max_text_chars
        self.telemetry_reporter = telemetry_reporter

    def AnalyzePrompt(self, request, context):
        try:
            prompt_request = parse_prompt_request(
                {
                    "text": request.text,
                    "source": request.source or None,
                    "target_app": request.target_app or None,
                    "visibility_hint": request.visibility_hint or None,
                    "request_id": request.request_id or None,
                    "metadata": dict(request.metadata),
                },
                max_text_chars=self.max_text_chars,
            )
            layers = _requested_layers(request.layers)
            regex_first = _regex_first(request.regex_execution_order)
            analysis = analyse_prompt(
                prompt_request,
                layers=layers,
                regex_first=regex_first,
                semantic_model_id=request.semantic_model_id or None,
            )
            response = _analysis_response(analysis)
            if self.telemetry_reporter is not None:
                self.telemetry_reporter.report(analysis)
            return response
        except Exception as exc:
            return runtime_pb2.AnalyzePromptResponse(
                request_id=request.request_id,
                error=_error_message(exc),
            )

    def Health(self, request, context):
        return runtime_pb2.RuntimeHealthResponse(
            service="privoke-runtime",
            status="SERVING",
        )


def create_grpc_server(
    max_workers: int = 8,
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
    telemetry_reporter: TelemetryReporter | None = None,
):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(
        PrivokeRuntimeService(
            max_text_chars=max_text_chars,
            telemetry_reporter=telemetry_reporter,
        ),
        server,
    )
    return server


def _requested_layers(values) -> tuple[str, ...]:
    if not values or runtime_pb2.DETECTION_LAYER_RUNTIME in values:
        return DETECTION_LAYERS
    layers = []
    for value in values:
        layer = PROTO_TO_LAYER.get(value)
        if layer is None:
            raise ValueError(f"Unsupported detection layer value: {value}")
        if layer not in layers:
            layers.append(layer)
    return tuple(layers)


def _regex_first(value: int) -> bool | None:
    if value == runtime_pb2.REGEX_EXECUTION_ORDER_DEFAULT:
        return None
    if value == runtime_pb2.REGEX_EXECUTION_ORDER_FIRST:
        return True
    if value == runtime_pb2.REGEX_EXECUTION_ORDER_PARALLEL:
        return False
    raise ValueError(f"Unsupported regex execution order: {value}")


def _analysis_response(analysis: PromptAnalysis):
    payload = analysis.response()
    metadata = payload.get("metadata") or {}
    errors = [
        f"{execution.layer}: {execution.error}"
        for execution in analysis.execution.layers
        if execution.status == "error"
    ]
    classification = (
        analysis.result.classification
        if analysis.result is not None
        else classification_for_response(analysis.request.visibility_hint)
    )
    return runtime_pb2.AnalyzePromptResponse(
        request_id=payload.get("request_id") or "",
        action=payload.get("action") or "",
        allowed=bool(payload.get("allowed")),
        masked_text=payload.get("masked_text") or "",
        classification=_classification(classification),
        reason=payload.get("reason") or "",
        evidence=(
            _detection_result(analysis.result)
            if analysis.result is not None
            else None
        ),
        metadata=_string_map(metadata),
        layers=[
            _layer_execution(execution)
            for execution in analysis.execution.layers
        ],
        elapsed_ms=analysis.elapsed_ms,
        error="; ".join(errors),
    )


def _layer_execution(execution: LayerExecution):
    return runtime_pb2.RuntimeLayerExecution(
        layer=LAYER_TO_PROTO[execution.layer],
        status=execution.status,
        results=[_detection_result(result) for result in execution.results],
        error=execution.error or "",
    )


def _classification(classification: Classification):
    return runtime_pb2.RuntimeClassification(
        sensitivity=classification.sensitivity().name,
        visibility=classification.visibility().name,
        categories=[category.name for category in classification.categories()],
        packed=classification.pack(),
    )


def _detection_result(result: ClassificationResult):
    span = result.span or (0, 0)
    return runtime_pb2.RuntimeDetectionResult(
        classification=_classification(result.classification),
        action=result.action().name,
        section_of_text=result.section_of_text,
        span_start=span[0],
        span_end=span[1],
        has_span=result.span is not None,
        confidence=float(result.confidence or 0.0),
        has_confidence=result.confidence is not None,
        reasoning=result.reasoning,
        metadata=_string_map(result.metadata),
    )


def _string_map(values: Mapping[str, Any]) -> dict[str, str]:
    return {
        str(key): value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        for key, value in values.items()
        if value is not None
    }


def _error_message(exc: Exception) -> str:
    message = str(exc).strip()
    return message or exc.__class__.__name__
