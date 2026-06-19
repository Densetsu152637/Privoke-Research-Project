from typing import Callable, Iterable, List, Tuple

from .classification import ClassificationResult, PriVokeAction
from .config import GLOBAL_CONFIG, LLMChoice
from .detection import normalize_text
from .LLM import LocalClassifier, OpenClassifier, PriVokeClassifier
from .regex.rule_detector import RuleDetector
from .NER import EntityNERDetector

DetectorJob = Callable[[], List[ClassificationResult]]

def get_llm_choice():
    llm_config = GLOBAL_CONFIG.get_llm_config()

    match llm_config.choice:
        case LLMChoice.Open:
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
            streamed = llm_config.streamed
            return PriVokeClassifier(
                target=streamed.target,
                model_id=streamed.model_id,
                consumer_id=streamed.consumer_id,
                timeout_seconds=streamed.timeout_seconds,
            )


def pipeline_analyse_text(text: str) -> Tuple[ClassificationResult | None, PriVokeAction]:
    normalised_text = normalize_text(text)

    results: List[ClassificationResult] = []
    rule_detector = RuleDetector()
    jobs = []

    if GLOBAL_CONFIG.wait_for_regex:
        rule_results = rule_detector.analyze(normalised_text)
        results.extend(rule_results)

        rule_result, rule_action = strongest_result(rule_results)
        if rule_action == PriVokeAction.BLOCK:
            return rule_result, rule_action

    else:
        jobs.append(lambda: rule_detector.analyze(normalised_text))

    ner = EntityNERDetector()
    chosen_llm = get_llm_choice()

    jobs.extend(
        [
            lambda: ner.extract_entities(normalised_text),
            lambda: chosen_llm.classify(normalised_text),
        ]
    )

    results.extend(run_detector_jobs(jobs))
    return strongest_result(results)

def run_detector_jobs(jobs: Iterable[DetectorJob]) -> List[ClassificationResult]:
    job_list = list(jobs)
    if not job_list:
        return []

    results: List[ClassificationResult] = []

    for detector_results in GLOBAL_CONFIG.threadpool.map(lambda job: job(), job_list):
        results.extend(detector_results)

    return results


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
