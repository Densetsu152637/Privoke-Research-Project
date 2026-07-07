from __future__ import annotations

from contextlib import contextmanager
from time import perf_counter

from .types import DetectionOutcome


@contextmanager
def temporary_llm_choice(choice: str | "LLMChoice"):
    from privoke_client_runtime.config import GLOBAL_CONFIG, LLMChoice

    previous_config = GLOBAL_CONFIG.get_llm_config()
    try:
        GLOBAL_CONFIG.update_llm_config(choice=LLMChoice.parse(choice))
        yield
    finally:
        GLOBAL_CONFIG.set_llm_config(previous_config)


def run_pipeline(text: str, backend: str) -> DetectionOutcome:
    from privoke_client_runtime.pipeline import pipeline_analyse_text

    started = perf_counter()
    with temporary_llm_choice(backend):
        result, action = pipeline_analyse_text(text)
    elapsed_ms = (perf_counter() - started) * 1000
    return DetectionOutcome(
        action=action.name,
        categories=tuple(c.name for c in result.classification.categories()) if result else (),
        confidence=result.confidence if result else None,
        elapsed_ms=elapsed_ms,
    )


def run_regex(text: str) -> DetectionOutcome:
    from privoke_client_runtime.detection import normalize_text
    from privoke_client_runtime.pipeline import strongest_result
    from privoke_client_runtime.regex.rule_detector import RuleDetector

    started = perf_counter()
    normalized = normalize_text(text)
    results = RuleDetector().analyze(normalized)
    elapsed_ms = (perf_counter() - started) * 1000
    result, action = strongest_result(results)
    return DetectionOutcome(
        action=action.name,
        categories=tuple(c.name for c in result.classification.categories()) if result else (),
        confidence=result.confidence if result else None,
        elapsed_ms=elapsed_ms,
    )


def run_ner(text: str) -> DetectionOutcome:
    from privoke_client_runtime.NER import EntityNERDetector
    from privoke_client_runtime.detection import normalize_text
    from privoke_client_runtime.pipeline import strongest_result

    started = perf_counter()
    normalized = normalize_text(text)
    results = EntityNERDetector().extract_entities(normalized)
    elapsed_ms = (perf_counter() - started) * 1000
    result, action = strongest_result(results)
    return DetectionOutcome(
        action=action.name,
        categories=tuple(c.name for c in result.classification.categories()) if result else (),
        confidence=result.confidence if result else None,
        elapsed_ms=elapsed_ms,
    )
