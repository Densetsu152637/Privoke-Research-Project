from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Dict, Sequence, Tuple

from ..classification import (
    ClassificationResult,
    PriVokeAction,
    Visibility,
    initialise_unpacked,
)
from ..classification.classification_policy import strongest_visibility
from ..pipeline import PipelineAnalysis, analyse_text
from .models import PromptInspectionRequest
from .serialization import serialize_analysis_response


@dataclass(frozen=True)
class PromptAnalysis:
    request: PromptInspectionRequest
    execution: PipelineAnalysis
    result: ClassificationResult | None
    action: PriVokeAction
    elapsed_ms: float

    def response(self) -> Dict:
        return serialize_analysis_response(
            self.request,
            self.result,
            self.action,
            self.elapsed_ms,
        )


def analyse_prompt_request(request: PromptInspectionRequest) -> Dict:
    analysis = analyse_prompt(request)
    response = analysis.response()
    response["errors"] = list(analysis.execution.errors)
    response["layers"] = [
        {
            "layer": execution.layer,
            "status": execution.status,
            "result_count": len(execution.results),
            "error": execution.error,
        }
        for execution in analysis.execution.layers
    ]
    return response


def analyse_prompt(
    request: PromptInspectionRequest,
    layers: Sequence[str] | None = None,
    regex_first: bool | None = None,
) -> PromptAnalysis:
    started = perf_counter()
    analysis = analyse_text(request.text, layers=layers, regex_first=regex_first)
    result, action = analysis.result, analysis.action
    result, action = _apply_visibility_hint(
        result,
        action,
        request.visibility_hint,
    )
    elapsed_ms = (perf_counter() - started) * 1000
    return PromptAnalysis(request, analysis, result, action, elapsed_ms)


def _apply_visibility_hint(
    result: ClassificationResult | None,
    action: PriVokeAction,
    visibility_hint: Visibility | None,
) -> Tuple[ClassificationResult | None, PriVokeAction]:
    if visibility_hint is None or result is None:
        return result, action

    current = result.classification
    visibility = strongest_visibility(
        [current.visibility(), visibility_hint]
    )
    if visibility == current.visibility():
        return result, action

    hinted_result = ClassificationResult(
        classification=initialise_unpacked(
            current.sensitivity(),
            visibility,
            current.categories(),
        ),
        section_of_text=result.section_of_text,
        reasoning=f"{result.reasoning} Visibility hint applied: {visibility_hint.name}.",
        span=result.span,
        confidence=result.confidence,
        metadata={
            **result.metadata,
            "visibility_hint": visibility_hint.name,
        },
    )
    return hinted_result, hinted_result.action()
