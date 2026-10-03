from __future__ import annotations

import json
import time
from concurrent import futures
from typing import Any, Mapping

import grpc

from ..classification import Classification, ClassificationResult
from ..LLM.privoke.parameter_stream import ModelParameterStreamer
from ..LLM.privoke.presence_training import (
    PresenceTrainingExample,
    compute_presence_gradients,
)
from ..LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE
from ..LLM.privoke.training import SemanticTrainingExample, compute_semantic_gradients
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
DEFAULT_MAX_GRPC_MESSAGE_BYTES = 262_144
DEFAULT_MAX_GRPC_RESPONSE_BYTES = 1_048_576
DEFAULT_MAX_TRAINING_EXAMPLES = 1_024
DEFAULT_MAX_TRAINING_TEXT_CHARS = 200_000
PRESENCE_MODEL_ID_PREFIX = "privoke-presence-"


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

    def ComputeSemanticGradients(self, request, context):
        try:
            if not request.model_id.strip():
                raise ValueError("model_id is required.")
            if not request.examples:
                raise ValueError("At least one training example is required.")
            all_examples = tuple(request.examples) + tuple(request.heldout_examples)
            if len(all_examples) > DEFAULT_MAX_TRAINING_EXAMPLES:
                raise ValueError(
                    "Training batches may contain at most "
                    f"{DEFAULT_MAX_TRAINING_EXAMPLES} examples."
                )
            if (
                sum(len(item.text) for item in all_examples)
                > DEFAULT_MAX_TRAINING_TEXT_CHARS
            ):
                raise ValueError(
                    "Training batch text may contain at most "
                    f"{DEFAULT_MAX_TRAINING_TEXT_CHARS} characters."
                )
            converted = []
            for item in all_examples:
                if not item.text or len(item.text) > self.max_text_chars:
                    raise ValueError(
                        f"Training example text must contain 1 to {self.max_text_chars} characters."
                    )
                converted.append(
                    SemanticTrainingExample(
                        text=item.text,
                        target=(
                            Classification(int(item.target.packed))
                            if item.has_target
                            else None
                        ),
                        weight=float(item.weight),
                    )
                )
            batch = compute_semantic_gradients(
                converted[:len(request.examples)],
                model_id=request.model_id,
                learning_rate=float(request.learning_rate),
                max_gradient=float(request.max_gradient),
                heldout_examples=converted[len(request.examples):],
            )
            return runtime_pb2.ComputeSemanticGradientsResponse(
                request_id=request.request_id,
                model_id=batch.model_id,
                base_version=batch.base_version,
                gradients=[
                    runtime_pb2.RuntimeParameterDelta(
                        name=name,
                        values=values,
                        shape=batch.shapes[name],
                    )
                    for name, values in batch.gradients.items()
                ],
                metrics=batch.metrics,
                metadata=batch.metadata,
            )
        except Exception as exc:
            return runtime_pb2.ComputeSemanticGradientsResponse(
                request_id=request.request_id,
                error=_error_message(exc),
            )

    def DetectAnnotationPresence(self, request, context):
        # Includes request validation, remote snapshot fetch/cache lookup, and local inference.
        # The RPC duration excludes the caller's network/browser round trip.
        started = time.perf_counter()
        try:
            _validate_presence_model_id(request.model_id)
            if not request.request_id.strip():
                raise ValueError("request_id is required.")
            if not isinstance(request.text, str) or not request.text.strip():
                raise ValueError("text is required.")
            if len(request.text) > self.max_text_chars:
                raise ValueError(f"text may contain at most {self.max_text_chars} characters.")
            model = GLOBAL_STREAMED_MODEL_CACHE.presence_model_for_streamer(
                ModelParameterStreamer(model_id=request.model_id)
            )
            probability = model.predict_probability(request.text)
            predicted = (
                runtime_pb2.ANNOTATION_PRESENCE_PRESENT
                if probability >= model.threshold
                else runtime_pb2.ANNOTATION_PRESENCE_ABSENT
            )
            return runtime_pb2.DetectAnnotationPresenceResponse(
                request_id=request.request_id,
                model_id=model.model_id,
                model_version=model.version,
                probability=probability,
                threshold=model.threshold,
                predicted_label=predicted,
                artifact_checksum=model.snapshot.metadata.get("artifact_checksum", ""),
                parameter_fingerprint=model.snapshot.fingerprint,
                elapsed_ms=(time.perf_counter() - started) * 1000.0,
            )
        except Exception as exc:
            return runtime_pb2.DetectAnnotationPresenceResponse(
                request_id=request.request_id,
                error=_error_message(exc),
            )

    def ComputePresenceGradients(self, request, context):
        try:
            _validate_presence_model_id(request.model_id)
            if not request.request_id.strip():
                raise ValueError("request_id is required.")
            if not request.examples:
                raise ValueError("At least one training example is required.")
            all_examples = tuple(request.examples) + tuple(request.heldout_examples)
            if len(all_examples) > DEFAULT_MAX_TRAINING_EXAMPLES:
                raise ValueError(
                    "Training batches may contain at most "
                    f"{DEFAULT_MAX_TRAINING_EXAMPLES} examples."
                )
            if sum(len(item.text) for item in all_examples) > DEFAULT_MAX_TRAINING_TEXT_CHARS:
                raise ValueError(
                    "Training batch text may contain at most "
                    f"{DEFAULT_MAX_TRAINING_TEXT_CHARS} characters."
                )
            converted = []
            for item in all_examples:
                if not item.text or len(item.text) > self.max_text_chars:
                    raise ValueError(
                        f"Training example text must contain 1 to {self.max_text_chars} characters."
                    )
                if item.target == runtime_pb2.ANNOTATION_PRESENCE_PRESENT:
                    target = True
                elif item.target == runtime_pb2.ANNOTATION_PRESENCE_ABSENT:
                    target = False
                else:
                    raise ValueError("Presence targets must be explicitly PRESENT or ABSENT.")
                converted.append(
                    PresenceTrainingExample(
                        text=item.text,
                        target=target,
                        weight=float(item.weight),
                        group_id=item.group_id,
                    )
                )
            batch = compute_presence_gradients(
                converted[:len(request.examples)],
                model_id=request.model_id,
                learning_rate=float(request.learning_rate),
                max_gradient=float(request.max_gradient),
                heldout_examples=converted[len(request.examples):],
            )
            return runtime_pb2.ComputePresenceGradientsResponse(
                request_id=request.request_id,
                model_id=batch.model_id,
                base_version=batch.base_version,
                gradients=[
                    runtime_pb2.RuntimeParameterDelta(
                        name=name,
                        values=values,
                        shape=batch.shapes[name],
                    )
                    for name, values in batch.gradients.items()
                ],
                metrics=batch.metrics,
                metadata=batch.metadata,
            )
        except Exception as exc:
            return runtime_pb2.ComputePresenceGradientsResponse(
                request_id=request.request_id,
                error=_error_message(exc),
            )

    def Health(self, request, context):
        return runtime_pb2.RuntimeHealthResponse(
            service="client-runtime",
            status="SERVING",
        )


def create_grpc_server(
    max_workers: int = 8,
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
    max_message_bytes: int = DEFAULT_MAX_GRPC_MESSAGE_BYTES,
    max_response_bytes: int = DEFAULT_MAX_GRPC_RESPONSE_BYTES,
    telemetry_reporter: TelemetryReporter | None = None,
):
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        options=(
            ("grpc.max_receive_message_length", max_message_bytes),
            ("grpc.max_send_message_length", max_response_bytes),
        ),
    )
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


def _validate_presence_model_id(model_id: str) -> None:
    if (
        not isinstance(model_id, str)
        or not model_id.startswith(PRESENCE_MODEL_ID_PREFIX)
        or model_id != model_id.strip()
        or len(model_id) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in model_id)
    ):
        raise ValueError("model_id must explicitly name a privoke-presence model.")
