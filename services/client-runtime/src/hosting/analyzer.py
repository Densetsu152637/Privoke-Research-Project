from __future__ import annotations

from time import perf_counter
from typing import Dict, Tuple

from ..classification import (
    ClassificationResult,
    PriVokeAction,
    Visibility,
    initialise_unpacked,
)
from ..classification.classification_policy import strongest_visibility
from ..pipeline import pipeline_analyse_text
from .models import PromptInspectionRequest
from .serialization import serialize_analysis_response


def analyse_prompt_request(request: PromptInspectionRequest) -> Dict:
    started = perf_counter()
    result, action = pipeline_analyse_text(request.text)
    result, action = _apply_visibility_hint(
        result,
        action,
        request.visibility_hint,
    )
    elapsed_ms = (perf_counter() - started) * 1000
    return serialize_analysis_response(request, result, action, elapsed_ms)


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
