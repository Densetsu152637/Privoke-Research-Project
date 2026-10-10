from __future__ import annotations

import json
import base64
import math
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

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


def _validate_requested_execution(request, response):
    if list(request.layers) == [runtime_pb2.DETECTION_LAYER_SEMANTIC]:
        if (response.error or len(response.layers) != 1
                or response.layers[0].layer != runtime_pb2.DETECTION_LAYER_SEMANTIC
                or response.layers[0].status != "ok" or response.layers[0].error):
            raise RuntimeAnalysisError("Semantic-only testing requires exactly one successful semantic layer execution.")


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
            response = runtime_pb2_grpc.PrivokeRuntimeServiceStub(
                channel
            ).AnalyzePrompt(
                request,
                timeout=self.timeout_seconds,
            )
        _validate_requested_execution(request, response)
        return response

    def _request(
        self,
        payload: Mapping[str, Any],
        layers: list[str] | tuple[str, ...] | None = None,
        regex_first: bool | None = None,
    ):
        metadata = payload.get("metadata") or {}
        if layers is not None and (not isinstance(layers, (list, tuple)) or not layers):
            raise ValueError("Detection layers must be a nonempty list or tuple.")
        requested_layers = list(layers) if layers is not None else ["semantic"]
        unknown_layers = [
            layer for layer in requested_layers if layer not in LAYER_VALUES
        ]
        if unknown_layers:
            raise ValueError(f"Unsupported runtime layer: {unknown_layers[0]}")
        return runtime_pb2.AnalyzePromptRequest(
            text=str(payload.get("text") or payload.get("prompt") or ""),
            source=str(payload.get("source") or ""),
            target_app=str(payload.get("target_app") or ""),
            visibility_hint=str(payload.get("visibility_hint") or ""),
            request_id=str(payload.get("request_id") or ""),
            metadata={
                str(key): _string_value(value) for key, value in metadata.items()
            },
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
        for request, response in zip(requests, responses):
            _validate_requested_execution(request, response)
        return [_classification_from_response(response) for response in responses]

    def compute_semantic_gradients(
        self,
        examples,
        *,
        heldout_examples=(),
        model_id: str,
        learning_rate: float,
        max_gradient: float,
        request_id: str = "",
        training_scope: str = "heads",
        require_full_capability: bool = False,
    ) -> dict[str, Any]:
        if training_scope not in ("heads", "full_encoder") or not examples or not heldout_examples:
            raise ValueError("Semantic training requires a known scope and nonempty training and held-out batches.")
        request = runtime_pb2.ComputeSemanticGradientsRequest(
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC],
            request_id=request_id,
            model_id=model_id,
            examples=[
                runtime_pb2.RuntimeTrainingExample(
                    text=example.text,
                    target=(
                        runtime_pb2.RuntimeClassification(
                            sensitivity=example.expected_classification.sensitivity().name,
                            visibility=example.expected_classification.visibility().name,
                            categories=[
                                category.name
                                for category in example.expected_classification.categories()
                            ],
                            packed=example.expected_classification.pack(),
                        )
                        if example.expected_classification is not None
                        else None
                    ),
                    has_target=example.expected_classification is not None,
                    weight=example.weight,
                )
                for example in examples
            ],
            heldout_examples=[
                runtime_pb2.RuntimeTrainingExample(
                    text=example.text,
                    target=runtime_pb2.RuntimeClassification(
                        packed=example.expected_classification.pack()
                    ) if example.expected_classification is not None else None,
                    has_target=example.expected_classification is not None,
                    weight=example.weight,
                )
                for example in heldout_examples
            ],
            learning_rate=learning_rate,
            max_gradient=max_gradient,
        )
        with grpc.insecure_channel(self.target) as channel:
            stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
            method = stub.ComputeUnderlyingModelGradients if training_scope == "full_encoder" else stub.ComputeSemanticGradients
            response = method(request, timeout=self.timeout_seconds)
        if response.error:
            raise RuntimeAnalysisError(response.error)
        validate_training_response(request, response, training_scope, max_gradient,
                                   require_full_capability=require_full_capability)
        gradients = {}
        shapes = {}
        for parameter in response.gradients:
            if parameter.name in gradients:
                raise RuntimeAnalysisError(
                    f"Client runtime returned duplicate gradient {parameter.name!r}."
                )
            gradients[parameter.name] = tuple(float(value) for value in parameter.values)
            shapes[parameter.name] = tuple(int(size) for size in parameter.shape)
        if not response.model_id or not response.base_version or not gradients:
            raise RuntimeAnalysisError(
                "Client runtime returned an incomplete semantic gradient batch."
            )
        return {
            "model_id": response.model_id,
            "base_version": response.base_version,
            "gradients": gradients,
            "shapes": shapes,
            "metrics": dict(response.metrics),
            "metadata": dict(response.metadata),
            "execution_evidence": {
                "rpc": "ComputeUnderlyingModelGradients" if training_scope == "full_encoder" else "ComputeSemanticGradients",
                "request_layers": list(request.layers),
                "request_protobuf_base64": base64.b64encode(request.SerializeToString(deterministic=True)).decode("ascii"),
                "response_protobuf_base64": base64.b64encode(response.SerializeToString(deterministic=True)).decode("ascii"),
                "executions": [{"phase": e.phase, "layer": e.layer, "status": e.status,
                                "examples": e.examples, "error": e.error} for e in response.executions],
            },
        }

    def compute_underlying_gradients(self, examples, **kwargs):
        return self.compute_semantic_gradients(examples, training_scope="full_encoder", **kwargs)

    def compute_presence_gradients(
        self, examples, *, heldout_examples=(), model_id: str,
        learning_rate: float, max_gradient: float, request_id: str = "",
    ) -> dict[str, Any]:
        """Ask client-runtime to train only its frozen-representation presence head."""
        for example in (*examples, *heldout_examples):
            if type(example.sensitive) is not bool:
                raise ValueError("Presence runtime targets must be strict booleans.")
        labels = {
            False: runtime_pb2.ANNOTATION_PRESENCE_ABSENT,
            True: runtime_pb2.ANNOTATION_PRESENCE_PRESENT,
        }
        request = runtime_pb2.ComputePresenceGradientsRequest(
            request_id=request_id,
            model_id=model_id,
            examples=[runtime_pb2.PresenceTrainingExample(
                text=example.text,
                target=labels[example.sensitive],
                weight=example.weight,
                group_id=example.group_id,
            ) for example in examples],
            heldout_examples=[runtime_pb2.PresenceTrainingExample(
                text=example.text,
                target=labels[example.sensitive],
                weight=example.weight,
                group_id=example.group_id,
            ) for example in heldout_examples],
            learning_rate=learning_rate,
            max_gradient=max_gradient,
        )
        with grpc.insecure_channel(self.target) as channel:
            response = runtime_pb2_grpc.PrivokeRuntimeServiceStub(
                channel
            ).ComputePresenceGradients(request, timeout=self.timeout_seconds)
        if response.error:
            raise RuntimeAnalysisError(response.error)
        gradients, shapes = {}, {}
        for parameter in response.gradients:
            if parameter.name in gradients:
                raise RuntimeAnalysisError(
                    f"Client runtime returned duplicate gradient {parameter.name!r}."
                )
            gradients[parameter.name] = tuple(float(value) for value in parameter.values)
            shapes[parameter.name] = tuple(int(size) for size in parameter.shape)
        if response.model_id != model_id or not response.base_version or not gradients:
            raise RuntimeAnalysisError(
                "Client runtime returned an incomplete or mismatched presence gradient batch."
            )
        if any(not name.startswith("head.presence.") for name in gradients):
            raise RuntimeAnalysisError("Client runtime returned a non-presence parameter gradient.")
        return {
            "model_id": response.model_id,
            "base_version": response.base_version,
            "gradients": gradients,
            "shapes": shapes,
            "metrics": dict(response.metrics),
            "metadata": dict(response.metadata),
        }


def validate_training_response(request, response, scope, max_gradient, *, require_full_capability=False):
    """Admit actual semantic execution and independently derived Tiny tensor shapes."""
    from privoke_model.contextual_training import HEAD_NAMES, FULL_ENCODER_STRATEGY, LAST_BLOCK_STRATEGY, full_encoder_tensor_shapes, contextual_trainable_names
    from privoke_model.fingerprint import parameter_fingerprint
    def reject(message):
        raise RuntimeAnalysisError(message)
    if list(request.layers) != [runtime_pb2.DETECTION_LAYER_SEMANTIC]:
        reject("Training requires an explicit semantic-only request.")
    if (response.request_id != request.request_id or response.model_id != request.model_id
            or not response.base_version or response.error):
        reject("Runtime training response identity is incomplete or mismatched.")
    phases = [("training", len(request.examples)), ("base_heldout", len(request.heldout_examples)),
              ("candidate_heldout", len(request.heldout_examples))]
    if len(response.executions) != len(phases):
        reject("Runtime training requires all three actual semantic executions.")
    for execution, (phase, count) in zip(response.executions, phases):
        if (execution.phase != phase or execution.examples != count or execution.status != "ok"
                or execution.error or execution.layer != runtime_pb2.DETECTION_LAYER_SEMANTIC):
            reject("Runtime training execution phase, layer, count or status is invalid.")
    metadata = response.metadata
    full = scope == "full_encoder"
    legacy_last = (not full and not require_full_capability and metadata.get("artifact_training_strategy") == LAST_BLOCK_STRATEGY)
    if metadata.get("training_scope") != ("last_block" if legacy_last else scope):
        reject("Runtime returned the wrong training scope.")
    expected_strategy = FULL_ENCODER_STRATEGY if full else (LAST_BLOCK_STRATEGY if legacy_last else "transformer_classification_head_finetune")
    if metadata.get("strategy") != expected_strategy:
        reject("Runtime executed the wrong training strategy.")
    if (full or require_full_capability) and metadata.get("artifact_training_strategy") != FULL_ENCODER_STRATEGY:
        reject("Automatic dual training requires a full-capable Tiny artifact before head publication.")
    if (full or require_full_capability) and metadata.get("underlying_training_available") != "true":
        reject("Automatic dual training requires usable CPU autograd before head publication.")
    for key in ("artifact_checksum", "base_parameter_fingerprint", "updated_parameter_fingerprint"):
        if not re.fullmatch("[0-9a-f]{64}", metadata.get(key, "")):
            reject("Runtime training lacks an exact artifact identity.")
    try:
        config = json.loads(metadata["model_config"])
        for task, enum in (("sensitivity", Sensitivity), ("visibility", Visibility), ("category", Category)):
            labels = config.get(task + "_labels")
            if (not isinstance(labels, list) or len(labels) != len(enum)
                    or set(labels) != set(enum.__members__)):
                raise ValueError("Invalid classification label inventory")
        expected_names = contextual_trainable_names(config, FULL_ENCODER_STRATEGY if full else (LAST_BLOCK_STRATEGY if legacy_last else None))
        all_shapes = full_encoder_tensor_shapes(config)
        shapes = {name: all_shapes[name] for name in expected_names}
        from privoke_model.artifact import float32
        # Legacy trainers clipped in float32, which may round a double request
        # bound outward. Full-capable artifacts enforce the exact double bound.
        strict_bound = metadata.get("artifact_training_strategy") == FULL_ENCODER_STRATEGY
        admitted_bound = max_gradient if strict_bound else max(max_gradient, float32(max_gradient))
        names = [p.name for p in response.gradients]
        if len(names) != len(set(names)) or set(names) != set(shapes):
            raise ValueError("Incomplete or unexpected tensor inventory")
        if json.loads(metadata["trained_parameter_names"]) != sorted(shapes):
            raise ValueError("Incorrect declared inventory")
        expected_fingerprint = parameter_fingerprint({name: () for name in shapes}, shapes)
        if metadata["trained_parameter_inventory_fingerprint"] != expected_fingerprint:
            raise ValueError("Incorrect inventory fingerprint")
        if sum(math.prod(shape) for shape in shapes.values()) > 65536:
            raise ValueError("Excessive total tensor size")
        for parameter in response.gradients:
            if (tuple(parameter.shape) != shapes[parameter.name] or len(parameter.values) != math.prod(parameter.shape)
                    or len(parameter.values) > (24576 if full else 4096)
                    or any(not math.isfinite(v) or abs(v) > admitted_bound for v in parameter.values)):
                raise ValueError("Invalid tensor shape, size or delta")
        if response.metrics.get("examples") != len(request.examples) or response.metrics.get("heldout_examples") != len(request.heldout_examples):
            raise ValueError("Incorrect metric counts")
    except (ValueError, KeyError, TypeError) as exc:
        reject(f"Runtime training contract failed: {exc}")


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
    results = [result for execution in response.layers for result in execution.results]
    if results:
        return merge_classifications(
            _classification_from_proto(result.classification) for result in results
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
