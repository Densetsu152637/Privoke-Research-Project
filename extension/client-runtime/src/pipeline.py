from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Sequence, Tuple

from .classification import ClassificationResult, PriVokeAction
from .config import GLOBAL_CONFIG, LLMChoice
from .detection import normalize_text


REGEX_LAYER = "regex"
NER_LAYER = "ner"
SEMANTIC_LAYER = "semantic"
DETECTION_LAYERS = (REGEX_LAYER, NER_LAYER, SEMANTIC_LAYER)


@dataclass(frozen=True)
class LayerExecution:
    layer: str
    status: str
    results: tuple[ClassificationResult, ...] = ()
    error: str | None = None


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
) -> PipelineAnalysis:
    requested_layers = _normalise_layers(layers)
    run_regex_first = (
        GLOBAL_CONFIG.wait_for_regex if regex_first is None else regex_first
    )

    try:
        normalised_text = normalize_text(text)
    except Exception as exc:
        return PipelineAnalysis(
            tuple(
                LayerExecution(layer, "error", error=_error_message(exc))
                for layer in requested_layers
            )
        )

    completed: dict[str, LayerExecution] = {}
    if REGEX_LAYER in requested_layers and run_regex_first:
        regex_execution = _execute_layer(REGEX_LAYER, normalised_text)
        completed[REGEX_LAYER] = regex_execution
        _, regex_action = strongest_result(regex_execution.results)
        if regex_action == PriVokeAction.BLOCK:
            for layer in requested_layers:
                if layer != REGEX_LAYER:
                    completed[layer] = LayerExecution(
                        layer,
                        "skipped",
                        error="Skipped after regex returned BLOCK.",
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
        ),
        pending_layers,
    )
    completed.update({execution.layer: execution for execution in executions})
    return PipelineAnalysis(tuple(completed[layer] for layer in requested_layers))


def _execute_layer(
    layer: str,
    text: str,
    semantic_model_id: str | None = None,
) -> LayerExecution:
    try:
        results = _detector_for(layer, semantic_model_id=semantic_model_id)(text)
        return LayerExecution(layer, "ok", tuple(results))
    except Exception as exc:
        return LayerExecution(layer, "error", error=_error_message(exc))


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


def strongest_result(
    results: Iterable[ClassificationResult],
) -> Tuple[ClassificationResult | None, PriVokeAction]:
    strongest = None
    strongest_action = PriVokeAction.ALLOW

    for result in results:
        action = result.action()
        if action.value > strongest_action.value:
            strongest = result
            strongest_action = action

    return strongest, strongest_action
