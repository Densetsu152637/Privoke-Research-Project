from __future__ import annotations

from dataclasses import dataclass, field, replace
import math
from typing import Callable, Iterable, List, Sequence, Tuple

from .classification import ClassificationResult, PriVokeAction
from .classification.classification_types import merge_classifications
from .config import GLOBAL_CONFIG, LLMChoice
from .detection.preprocessing import NormalizedText, normalize_with_offsets
from privoke_model.scratch_presence import SCRATCH_PRESENCE_MODEL_IDS
from privoke_model.pretrained_context import PRETRAINED_CONTEXT_MODEL_ID


REGEX_LAYER = "regex"
NER_LAYER = "ner"
SEMANTIC_LAYER = "semantic"
DETECTION_LAYERS = (REGEX_LAYER, NER_LAYER, SEMANTIC_LAYER)
SEMANTIC_PRESENCE_MODEL_IDS = SCRATCH_PRESENCE_MODEL_IDS | frozenset({
    "privoke-presence-efficient",
    "privoke-presence-balanced",
    "privoke-presence-quality",
})


@dataclass(frozen=True)
class SemanticPresenceGateRequest:
    model_id: str
    threshold: float | None = None

    def __post_init__(self) -> None:
        if self.model_id not in SEMANTIC_PRESENCE_MODEL_IDS:
            raise ValueError("Gate model_id must explicitly name a supported presence model.")
        if self.threshold is not None and (
            isinstance(self.threshold, bool)
            or not isinstance(self.threshold, (int, float))
            or not math.isfinite(self.threshold)
            or not 0 <= self.threshold <= 1
        ):
            raise ValueError("Gate threshold must be finite and in [0, 1].")


@dataclass(frozen=True)
class SemanticPresenceGateTrace:
    status: str
    model_id: str
    decision_threshold: float | None = None
    model_version: str = ""
    artifact_checksum: str = ""
    parameter_fingerprint: str = ""
    probability: float | None = None
    model_threshold: float | None = None
    predicted_label: str = ""
    semantic_results: tuple[ClassificationResult, ...] = ()
    error: str | None = None
    contextual_model_id: str = ""
    contextual_model_version: str = ""
    contextual_artifact_checksum: str = ""
    contextual_parameter_fingerprint: str = ""


@dataclass(frozen=True)
class LayerExecution:
    layer: str
    status: str
    results: tuple[ClassificationResult, ...] = ()
    error: str | None = None
    semantic_presence_gate: SemanticPresenceGateTrace | None = None
    pretrained_context_identity: dict[str, str] | None = None
    semantic_model_identity: dict[str, str] | None = None


@dataclass(frozen=True)
class PipelineAnalysis:
    layers: tuple[LayerExecution, ...]
    result: ClassificationResult | None = field(init=False)
    action: PriVokeAction = field(init=False)

    def __post_init__(self) -> None:
        result, action = strongest_result(
            result
            for layer in self.layers
            for result in layer.results
        )
        if self.errors and action == PriVokeAction.ALLOW:
            action = PriVokeAction.BLOCK
        object.__setattr__(self, "result", result)
        object.__setattr__(self, "action", action)

    @property
    def results(self) -> tuple[ClassificationResult, ...]:
        return tuple(
            result
            for layer in self.layers
            for result in layer.results
        )

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(
            f"{layer.layer}: {layer.error}"
            for layer in self.layers
            if layer.status == "error" and layer.error
        )


def get_llm_choice(model_id: str | None = None):
    llm_config = GLOBAL_CONFIG.get_llm_config()

    match llm_config.choice:
        case LLMChoice.Open:
            from .LLM.open_classifier import OpenClassifier

            openai = llm_config.openai
            return OpenClassifier(
                api_key=openai.api_key,
                model=openai.model,
                base_url=openai.base_url,
                timeout_seconds=openai.timeout_seconds,
                temperature=openai.temperature,
                max_tokens=openai.max_tokens,
                use_environment=False,
            )
        case LLMChoice.Local:
            from .LLM.local_classifier import LocalClassifier

            local = llm_config.local
            return LocalClassifier(
                base_url=local.base_url,
                model=local.model,
                api_key=local.api_key,
                timeout_seconds=local.timeout_seconds,
                temperature=local.temperature,
                max_tokens=local.max_tokens,
                response_format=local.response_format,
                use_environment=False,
            )
        case _:
            from .LLM.privoke_classifier import PriVokeClassifier

            streamed = llm_config.streamed
            return PriVokeClassifier(
                target=streamed.target,
                model_id=model_id or streamed.model_id,
                consumer_id=streamed.consumer_id,
                timeout_seconds=streamed.timeout_seconds,
            )


def analyse_text(
    text: str,
    layers: Sequence[str] | None = None,
    regex_first: bool | None = None,
    semantic_model_id: str | None = None,
    semantic_presence_gate: SemanticPresenceGateRequest | None = None,
) -> PipelineAnalysis:
    requested_layers = _normalise_layers(layers)
    if semantic_presence_gate is not None:
        if SEMANTIC_LAYER not in requested_layers:
            raise ValueError("Semantic presence gate requires the semantic layer.")
        if semantic_model_id != "privoke-balanced":
            raise ValueError("Semantic presence gate requires explicit semantic_model_id='privoke-balanced'.")
    run_regex_first = (
        GLOBAL_CONFIG.wait_for_regex if regex_first is None else regex_first
    )

    try:
        normalised = normalize_with_offsets(text)
        normalised_text = normalised.text
    except Exception as exc:
        return PipelineAnalysis(
            tuple(
                LayerExecution(
                    layer,
                    "error",
                    error=_error_message(exc),
                    semantic_presence_gate=(
                        SemanticPresenceGateTrace(
                            status="NOT_RUN",
                            model_id=semantic_presence_gate.model_id,
                            decision_threshold=semantic_presence_gate.threshold,
                            error=_error_message(exc),
                        )
                        if layer == SEMANTIC_LAYER and semantic_presence_gate is not None
                        else None
                    ),
                )
                for layer in requested_layers
            )
        )

    completed: dict[str, LayerExecution] = {}
    if REGEX_LAYER in requested_layers and run_regex_first:
        regex_execution = _remap_execution(
            _execute_layer(REGEX_LAYER, normalised_text), normalised
        )
        completed[REGEX_LAYER] = regex_execution
        _, regex_action = strongest_result(regex_execution.results)
        if regex_action == PriVokeAction.BLOCK:
            for layer in requested_layers:
                if layer != REGEX_LAYER:
                    completed[layer] = LayerExecution(
                        layer,
                        "skipped",
                        error="Skipped after regex returned BLOCK.",
                        semantic_presence_gate=(
                            SemanticPresenceGateTrace(
                                status="NOT_RUN",
                                model_id=semantic_presence_gate.model_id,
                                decision_threshold=semantic_presence_gate.threshold,
                                error="Skipped after regex returned BLOCK.",
                            )
                            if layer == SEMANTIC_LAYER and semantic_presence_gate is not None
                            else None
                        ),
                    )
            return PipelineAnalysis(
                tuple(completed[layer] for layer in requested_layers)
            )

    pending_layers = [
        layer for layer in requested_layers if layer not in completed
    ]
    executions = GLOBAL_CONFIG.threadpool.map(
        lambda layer: _execute_layer(
            layer,
            normalised_text,
            semantic_model_id=semantic_model_id,
            semantic_presence_gate=(
                semantic_presence_gate if layer == SEMANTIC_LAYER else None
            ),
        ),
        pending_layers,
    )
    completed.update({execution.layer: _remap_execution(execution, normalised)
                      for execution in executions})
    return PipelineAnalysis(tuple(completed[layer] for layer in requested_layers))


def _execute_layer(
    layer: str,
    text: str,
    semantic_model_id: str | None = None,
    semantic_presence_gate: SemanticPresenceGateRequest | None = None,
) -> LayerExecution:
    if layer == SEMANTIC_LAYER and semantic_presence_gate is not None:
        return _execute_semantic_with_presence_gate(
            text, semantic_model_id, semantic_presence_gate
        )
    if layer == SEMANTIC_LAYER and semantic_model_id == PRETRAINED_CONTEXT_MODEL_ID:
        return _execute_pretrained_context(text)
    try:
        detector = _detector_for(layer, semantic_model_id=semantic_model_id)
        identity = None
        if layer == SEMANTIC_LAYER:
            from .LLM.privoke_classifier import PriVokeClassifier

            owner = getattr(detector, "__self__", None)
            if isinstance(owner, PriVokeClassifier):
                model = _streamed_model_for_semantic_detector(owner)
                identity = _semantic_snapshot_identity(model)
                detector = model.classify
        results = detector(text)
        return LayerExecution(layer, "ok", tuple(results), semantic_model_identity=identity)
    except Exception as exc:
        return LayerExecution(layer, "error", error=_error_message(exc))


def _execute_pretrained_context(text: str) -> LayerExecution:
    # Capture the validated loaded snapshot before inference: clean results and
    # overlength errors still need an auditable model identity without a finding.
    identity = {}
    try:
        detector = get_llm_choice(model_id=PRETRAINED_CONTEXT_MODEL_ID)
        model = _streamed_model_for_semantic_detector(detector)
        from .LLM.privoke.pretrained_context_model import StreamedPretrainedContextModel
        if not isinstance(model, StreamedPretrainedContextModel):
            raise ValueError("Pretrained contextual request returned an unsupported architecture.")
        identity = {"privoke.pretrained_context." + key: value for key, value in {
            "model_id": model.snapshot.model_id, "model_version": model.snapshot.version,
            "artifact_checksum": model.snapshot.metadata["artifact_checksum"],
            "parameter_fingerprint": model.snapshot.fingerprint,
            "backbone_sha256": model.model.config["backbone_sha256"],
            "tokenizer_sha256": model.model.config["tokenizer_sha256"],
        }.items()}
        results = tuple(model.classify(text))
        return LayerExecution(SEMANTIC_LAYER, "ok", results, pretrained_context_identity=identity,
                              semantic_model_identity=_semantic_snapshot_identity(model))
    except Exception as exc:
        return LayerExecution(SEMANTIC_LAYER, "error", error=_error_message(exc),
                              pretrained_context_identity=identity)


def _execute_semantic_with_presence_gate(
    text: str,
    semantic_model_id: str | None,
    gate: SemanticPresenceGateRequest,
) -> LayerExecution:
    trace = SemanticPresenceGateTrace(
        status="NOT_RUN",
        model_id=gate.model_id,
        decision_threshold=gate.threshold,
    )
    try:
        semantic_detector = get_llm_choice(model_id=semantic_model_id)
        semantic_model = _streamed_model_for_semantic_detector(semantic_detector)
        semantic_results = tuple(semantic_model.classify(text))
    except Exception as exc:
        message = _error_message(exc)
        if "semantic_model" in locals():
            trace = replace(
                trace,
                contextual_model_id=semantic_model.snapshot.model_id,
                contextual_model_version=semantic_model.snapshot.version,
                contextual_artifact_checksum=semantic_model.snapshot.metadata.get("artifact_checksum", ""),
                contextual_parameter_fingerprint=semantic_model.snapshot.fingerprint,
            )
        return LayerExecution(
            SEMANTIC_LAYER,
            "error",
            error=message,
            semantic_presence_gate=replace(trace, error=message),
        )

    try:
        # Reuse the semantic classifier's configured streamed endpoint and identity;
        # only the explicit gate model ID differs. Prompt text stays local.
        presence_model = _presence_model_for_semantic_detector(
            semantic_detector, gate
        )
        probability = (
            presence_model.predict_normalized_probability(text)
            if gate.model_id in SCRATCH_PRESENCE_MODEL_IDS
            else presence_model.predict_probability(text)
        )
        model_threshold = presence_model.threshold
        decision_threshold = (
            model_threshold if gate.threshold is None else float(gate.threshold)
        )
        for name, value in (
            ("presence probability", probability),
            ("presence model threshold", model_threshold),
            ("presence decision threshold", decision_threshold),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or not 0 <= value <= 1
            ):
                raise ValueError(f"{name} must be finite and in [0, 1].")
        present = probability >= decision_threshold
        gate_trace = SemanticPresenceGateTrace(
            status="APPLIED",
            model_id=presence_model.model_id,
            model_version=presence_model.version,
            artifact_checksum=presence_model.snapshot.metadata["artifact_checksum"],
            parameter_fingerprint=presence_model.snapshot.fingerprint,
            probability=probability,
            model_threshold=model_threshold,
            decision_threshold=decision_threshold,
            predicted_label="PRESENT" if present else "ABSENT",
            semantic_results=semantic_results,
            contextual_model_id=semantic_model.snapshot.model_id,
            contextual_model_version=semantic_model.snapshot.version,
            contextual_artifact_checksum=semantic_model.snapshot.metadata.get("artifact_checksum", ""),
            contextual_parameter_fingerprint=semantic_model.snapshot.fingerprint,
        )
        return LayerExecution(
            SEMANTIC_LAYER,
            "ok",
            semantic_results if present else (),
            semantic_presence_gate=gate_trace,
        )
    except Exception as exc:
        message = _error_message(exc)
        return LayerExecution(
            SEMANTIC_LAYER,
            "error",
            semantic_results,
            message,
            replace(
                trace,
                status="ERROR",
                semantic_results=semantic_results,
                error=message,
                contextual_model_id=(semantic_model.snapshot.model_id if "semantic_model" in locals() else ""),
                contextual_model_version=(semantic_model.snapshot.version if "semantic_model" in locals() else ""),
                contextual_artifact_checksum=(semantic_model.snapshot.metadata.get("artifact_checksum", "") if "semantic_model" in locals() else ""),
                contextual_parameter_fingerprint=(semantic_model.snapshot.fingerprint if "semantic_model" in locals() else ""),
            ),
        )


def _semantic_snapshot_identity(model):
    snapshot = model.snapshot
    return {"model_id": snapshot.model_id, "model_version": snapshot.version,
            "artifact_checksum": snapshot.metadata["artifact_checksum"],
            "parameter_fingerprint": snapshot.fingerprint}


def _streamed_model_for_semantic_detector(semantic_detector):
    from .LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE

    return GLOBAL_STREAMED_MODEL_CACHE.semantic_model_for_streamer(semantic_detector.streamer)


def _presence_model_for_semantic_detector(
    semantic_detector,
    gate: SemanticPresenceGateRequest,
    *,
    streamer_factory=None,
    model_cache=None,
):
    if streamer_factory is None:
        from .LLM.privoke.parameter_stream import ModelParameterStreamer

        streamer_factory = ModelParameterStreamer
    if model_cache is None:
        from .LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE

        model_cache = GLOBAL_STREAMED_MODEL_CACHE
    semantic_streamer = semantic_detector.streamer
    presence_streamer = streamer_factory(
        target=semantic_streamer.target,
        model_id=gate.model_id,
        consumer_id=semantic_streamer.consumer_id,
        timeout_seconds=semantic_streamer.timeout_seconds,
    )
    return model_cache.annotation_presence_model_for_streamer(presence_streamer)


def _detector_for(
    layer: str,
    semantic_model_id: str | None = None,
) -> Callable[[str], List[ClassificationResult]]:
    if layer == REGEX_LAYER:
        from .regex.rule_detector import RuleDetector

        detector = RuleDetector()
        return detector.analyze
    if layer == NER_LAYER:
        from .NER import EntityNERDetector

        detector = EntityNERDetector()
        return detector.extract_entities
    if layer == SEMANTIC_LAYER:
        detector = get_llm_choice(model_id=semantic_model_id)
        return detector.classify
    raise ValueError(f"Unsupported detection layer: {layer}")


def _normalise_layers(layers: Sequence[str] | None) -> tuple[str, ...]:
    if not layers:
        return DETECTION_LAYERS
    unsupported = [layer for layer in layers if layer not in DETECTION_LAYERS]
    if unsupported:
        raise ValueError(f"Unsupported detection layer: {unsupported[0]}")
    requested = set(layers)
    return tuple(layer for layer in DETECTION_LAYERS if layer in requested)


def _error_message(exc: Exception) -> str:
    message = str(exc).strip()
    return message or exc.__class__.__name__


def _remap_execution(execution: LayerExecution, text: NormalizedText) -> LayerExecution:
    def remap(results):
        remapped = []
        for result in results:
            span = result.span
            if span is None and result.section_of_text:
                start = text.text.find(result.section_of_text)
                if start >= 0 and text.text.find(result.section_of_text, start + 1) < 0:
                    span = (start, start + len(result.section_of_text))
            original_span = None
            if span is not None:
                candidate = text.original_span(span)
                if candidate is not None and text.text[slice(*span)] == result.section_of_text:
                    original_span = candidate
            section = (text.original[slice(*original_span)]
                       if original_span is not None else result.section_of_text)
            remapped.append(replace(result, span=original_span, section_of_text=section))
        return tuple(remapped)

    gate_trace = execution.semantic_presence_gate
    if gate_trace is not None:
        gate_trace = replace(gate_trace, semantic_results=remap(gate_trace.semantic_results))
    return replace(execution, results=remap(execution.results), semantic_presence_gate=gate_trace)


def strongest_result(
    results: Iterable[ClassificationResult],
) -> Tuple[ClassificationResult | None, PriVokeAction]:
    """Combine evidence while retaining one deterministic primary evidence span.

    Confidence comes from the most sensitive contributors; a weaker but certain
    result must not turn a low-confidence S3 finding into a confident BLOCK.
    Individual enforcement decisions are never weakened by aggregation.
    """
    results = tuple(results)
    if not results:
        return None, PriVokeAction.ALLOW
    primary = max(results, key=lambda result: (
        result.action().value, result.classification.sensitivity().value,
        len(result.classification.categories()),
    ))
    classification = merge_classifications(result.classification for result in results)
    contributors = [result for result in results
                    if result.classification.sensitivity() == classification.sensitivity()]
    confidence = (None if any(result.confidence is None for result in contributors)
                  else max(result.confidence for result in contributors))
    combined = replace(primary, classification=classification, confidence=confidence)
    if len(results) > 1:
        combined.reasoning = f'{primary.reasoning} Combined {len(results)} detector findings.'
        combined.metadata = {**combined.metadata, 'combined_result_count': len(results)}
    action = max((combined.action(), *(result.action() for result in results)),
                 key=lambda value: value.value)
    return combined, action
