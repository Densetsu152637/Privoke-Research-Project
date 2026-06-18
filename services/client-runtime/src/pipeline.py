from typing import Callable, Iterable, List, Tuple

from .classification import ClassificationResult, PriVokeAction
from .config import GLOBAL_CONFIG, LLMChoice
from .detection import normalize_text
from .LLM import LocalClassifier, OpenClassifier, PriVokeClassifier
from .regex.rule_detector import RuleDetector
from .NER import EntityNERDetector

DetectorJob = Callable[[], List[ClassificationResult]]

def get_llm_choice():
    match GLOBAL_CONFIG.llm_choice:
        case LLMChoice.Open:
            return OpenClassifier()
        case LLMChoice.Local:
            return LocalClassifier()
        case _:
            return PriVokeClassifier()


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
