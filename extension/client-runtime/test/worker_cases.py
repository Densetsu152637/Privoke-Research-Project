"""Request cases shared by the worker parity tests and the worker-frames capture script.

Every case names an explicit non-empty layer selection. Nothing here sends an empty list.
LLM-only (semantic) cases and product-pipeline cases are labelled apart: the plain
``semantic`` selection is the LLM-only measurement; any selection that includes regex or
NER belongs to the product pipeline or to a detector ablation and is never reported as
LLM-only evidence.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from privoke.v1 import runtime_pb2 as pb
from src import worker_protocol as proto

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PROMPTS_FILE = REPOSITORY_ROOT / "tests" / "conformance" / "worker-frames" / "prompts.json"

REGEX, NER, SEMANTIC = pb.DETECTION_LAYER_REGEX, pb.DETECTION_LAYER_NER, pb.DETECTION_LAYER_SEMANTIC
# (label, layers, scope). Only "semantic" is LLM-only.
SELECTIONS = (
    ("semantic", (SEMANTIC,), "llm_only"),
    ("regex", (REGEX,), "detector_ablation"),
    ("ner", (NER,), "detector_ablation"),
    ("regex+ner", (REGEX, NER), "detector_ablation"),
    ("regex+semantic", (REGEX, SEMANTIC), "product_pipeline"),
    ("ner+semantic", (NER, SEMANTIC), "product_pipeline"),
    ("regex+ner+semantic", (REGEX, NER, SEMANTIC), "product_pipeline"),
)
TINY_MODEL = "privoke-balanced"
V3_MODEL = "privoke-v3-balanced"
ORDER_FIRST = pb.REGEX_EXECUTION_ORDER_FIRST
ORDER_PARALLEL = pb.REGEX_EXECUTION_ORDER_PARALLEL


@dataclass(frozen=True)
class Case:
    label: str
    method: proto.Method
    payload: bytes
    scope: str
    metadata: tuple = ()


CAPTURE_DIRECTORY = PROMPTS_FILE.parent


def load_capture(name: str) -> dict:
    return json.loads((CAPTURE_DIRECTORY / name).read_text(encoding="ascii"))


def capture_matches_environment() -> bool:
    """The committed digests are valid for the torch build that captured them."""
    import torch
    environment = load_capture("manifest.json")["environment"]
    return environment["torch"] == torch.__version__


def load_prompts():
    return json.loads(PROMPTS_FILE.read_text(encoding="ascii"))["prompts"]


def analyze_cases(include_v3: bool) -> list[Case]:
    cases = []
    prompts = load_prompts()
    for prompt in prompts:
        for name, layers, scope in SELECTIONS:
            cases.append(Case(f"analyze/{prompt['id']}/{name}/{TINY_MODEL}", proto.Method.ANALYZE_PROMPT,
                              pb.AnalyzePromptRequest(request_id=f"{prompt['id']}:{name}", text=prompt["text"],
                                                      layers=list(layers), semantic_model_id=TINY_MODEL
                                                      ).SerializeToString(), scope))
    if include_v3:
        for prompt in prompts:
            for name, layers, scope in SELECTIONS:
                if SEMANTIC in layers and name in ("semantic", "regex+ner+semantic"):
                    cases.append(Case(f"analyze/{prompt['id']}/{name}/{V3_MODEL}", proto.Method.ANALYZE_PROMPT,
                                      pb.AnalyzePromptRequest(request_id=f"{prompt['id']}:{name}:v3",
                                                              text=prompt["text"], layers=list(layers),
                                                              semantic_model_id=V3_MODEL).SerializeToString(), scope))
    by_id = {prompt["id"]: prompt["text"] for prompt in prompts}
    for order_name, order in (("first", ORDER_FIRST), ("parallel", ORDER_PARALLEL)):
        for prompt_id in ("email", "card", "secret-key", "benign-weather"):
            cases.append(Case(f"analyze/{prompt_id}/regex+ner+semantic/order-{order_name}", proto.Method.ANALYZE_PROMPT,
                              pb.AnalyzePromptRequest(request_id=f"{prompt_id}:{order_name}", text=by_id[prompt_id],
                                                      layers=[REGEX, NER, SEMANTIC], regex_execution_order=order,
                                                      semantic_model_id=TINY_MODEL).SerializeToString(),
                              "product_pipeline"))
    cases.append(Case("analyze/health/semantic/hint-and-metadata", proto.Method.ANALYZE_PROMPT,
                      pb.AnalyzePromptRequest(request_id="hinted", text=by_id["health"], layers=[SEMANTIC],
                                              semantic_model_id=TINY_MODEL, visibility_hint="P3",
                                              source="conformance", target_app="notes",
                                              metadata={"zeta": "1", "alpha": "2", "mid": "3"}).SerializeToString(),
                      "llm_only"))
    cases.append(Case("analyze/benign-weather/semantic/unknown-model", proto.Method.ANALYZE_PROMPT,
                      pb.AnalyzePromptRequest(request_id="unknown", text=by_id["benign-weather"], layers=[SEMANTIC],
                                              semantic_model_id="privoke-does-not-exist").SerializeToString(),
                      "llm_only"))
    return cases


def health_case() -> Case:
    return Case("health", proto.Method.HEALTH, pb.RuntimeHealthRequest().SerializeToString(), "llm_only")


# ---------------------------------------------------------------------------------------
# Training and presence models
# ---------------------------------------------------------------------------------------

def build_training_root(directory: Path) -> Path:
    """Write the prepared full-encoder Tiny release and a presence release into ``directory``."""
    from privoke_model.artifact import write_artifact_atomic
    from privoke_model.contextual_training import prepare_full_encoder_artifact
    from test_presence_runtime import _artifact as presence_artifact
    source = json.loads((REPOSITORY_ROOT / "models" / "privoke-balanced.json").read_text())
    prepared = prepare_full_encoder_artifact(source, version="v0.4.0+test", generated_at_unix=1,
                                             source_revision="a" * 40)
    write_artifact_atomic(directory / "privoke-balanced.json", prepared)
    presence = presence_artifact()
    write_artifact_atomic(directory / (presence["model_id"] + ".json"), presence)
    return directory


def _training_examples():
    from src.classification import Category, Sensitivity, Visibility, initialise_unpacked
    clean = initialise_unpacked(Sensitivity.S0, Visibility.PU, [])
    private = initialise_unpacked(Sensitivity.S3, Visibility.P4, [Category.HEALTH])

    def example(text, target, weight):
        return pb.RuntimeTrainingExample(text=text, target=pb.RuntimeClassification(packed=target.pack()),
                                         has_target=True, weight=weight)

    rows = [example("Synthetic public weather", clean, 1.0),
            example("My private diagnosis is cancer", private, 2.0)]
    heldout = [example("Anonymous public forecast", clean, 1.0),
               example("My doctor prescribed medication", private, 1.0)]
    return rows, heldout


def training_cases() -> list[Case]:
    rows, heldout = _training_examples()
    common = dict(request_id="train-1", model_id=TINY_MODEL, examples=rows, learning_rate=0.003,
                  max_gradient=0.0001, heldout_examples=heldout, layers=[SEMANTIC])
    semantic = pb.ComputeSemanticGradientsRequest(**common).SerializeToString()
    cases = [
        Case("gradients/semantic/heads", proto.Method.COMPUTE_SEMANTIC_GRADIENTS, semantic, "llm_only"),
        Case("gradients/underlying/full_encoder", proto.Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS, semantic, "llm_only"),
    ]
    wrong_layers = pb.ComputeSemanticGradientsRequest(**{**common, "layers": [SEMANTIC, NER]}).SerializeToString()
    cases.append(Case("gradients/semantic/wrong-layers-error-response", proto.Method.COMPUTE_SEMANTIC_GRADIENTS,
                      wrong_layers, "llm_only"))
    from privoke_model.contextual_training import BACKTRACKING_HEADER
    cases.append(Case("gradients/underlying/bad-admission-header", proto.Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS,
                      semantic, "llm_only", metadata=((BACKTRACKING_HEADER, "{not json"),)))
    cases.append(Case("gradients/underlying/duplicate-admission-header", proto.Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS,
                      semantic, "llm_only", metadata=((BACKTRACKING_HEADER, "{}"), (BACKTRACKING_HEADER, "{}"))))
    return cases


def presence_cases() -> list[Case]:
    model = "privoke-presence-efficient"
    cases = []
    for label, text in (("present", "please email me the diagnosis report"), ("absent", "a safe meeting agenda"),
                        ("mixed", "mail the safe diagnosis")):
        cases.append(Case(f"presence/detect/{label}", proto.Method.DETECT_ANNOTATION_PRESENCE,
                          pb.DetectAnnotationPresenceRequest(request_id=f"d-{label}", text=text, model_id=model,
                                                             layers=[SEMANTIC]).SerializeToString(), "llm_only"))
    cases.append(Case("presence/detect/not-a-presence-model", proto.Method.DETECT_ANNOTATION_PRESENCE,
                      pb.DetectAnnotationPresenceRequest(request_id="d-bad", text="x", model_id="privoke-balanced",
                                                         layers=[SEMANTIC]).SerializeToString(), "llm_only"))

    def example(text, label, group):
        return pb.PresenceTrainingExample(text=text, target=label, weight=1.0, group_id=group)

    present, absent = pb.ANNOTATION_PRESENCE_PRESENT, pb.ANNOTATION_PRESENCE_ABSENT
    request = pb.ComputePresenceGradientsRequest(
        request_id="p-train", model_id=model, learning_rate=0.05, max_gradient=0.05, layers=[SEMANTIC],
        examples=[example("please email the diagnosis", present, "g1"), example("a safe meeting agenda", absent, "g2"),
                  example("mail the safe diagnosis", present, "g3"), example("safe meeting notes", absent, "g4")],
        heldout_examples=[example("send mail about diagnosis", present, "h1"), example("safe meeting plan", absent, "h2")])
    cases.append(Case("gradients/presence", proto.Method.COMPUTE_PRESENCE_GRADIENTS, request.SerializeToString(),
                      "llm_only"))
    return cases
