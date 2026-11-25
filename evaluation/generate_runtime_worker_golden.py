"""Golden output for the Rust worker's presence and gradient RPCs, ``rust/services/runtime`` (RUST-S17A).

The Rust worker serves ``DetectAnnotationPresence``, the presence gate of ``AnalyzePrompt`` and the three gradient RPCs
for the request shapes stage 19 ported. This tool records what the unchanged Python worker (``worker_main.Dispatcher``,
the W1 reference) answers for the same W1 frames, so that the Rust test can replay them.

* Everything goes through the W1 frame protocol: each case is encoded with ``worker_protocol.encode_frame`` (a
  metadata block for the training admission header), read back with ``read_request`` and handled by the Python
  ``Dispatcher``, whose payload (or frame error code) is what is recorded.
* Models are read from read-only directories by the worker's own ``LocalModelProvider``, as the Python worker reads
  them: the committed synthetic artifacts under ``rust/services/runtime/tests/fixtures/worker_models/`` and the tracked
  legacy models in ``models/`` (the semantic model of the gate). Nothing from a recorded dataset is read.
* Every request that carries layers names them explicitly and non-empty: ``[semantic]`` for the presence and gradient
  RPCs (the LLM layer alone), and ``[semantic]`` or ``[regex, semantic]`` for the gated ``AnalyzePrompt`` rows. The
  regex rows are product-pipeline rows and are labelled apart; the NER layer is never requested.
* ``elapsed_ms`` (and its copy in the response metadata) is cleared; it is the only wall-clock field.

Usage (host Python with the client runtime requirements and Torch; the protobuf clients must exist)::

    python evaluation/generate_runtime_worker_golden.py write
    python evaluation/generate_runtime_worker_golden.py routes    # the local-SGD, diagnostics and backtracking routes (RUST-S19C)
"""

from __future__ import annotations

import argparse
import base64
import importlib
import io
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

REPO = Path(__file__).resolve().parents[1]
CRATE = REPO / "rust" / "services" / "runtime"
MODELS_OUT = CRATE / "tests" / "fixtures" / "worker_models"
DEFAULT_OUT = CRATE / "tests" / "fixtures" / "worker_golden.json"
ROUTES_OUT = CRATE / "tests" / "fixtures" / "worker_routes_golden.json"
TRACKED_MODELS = REPO / "models"
SEED = 20261120
FULL_STRATEGY = "contextual_full_encoder_sgd_v1"
LEGACY_OBJECTIVES = {
    "legacy": None,
    "mean": "class_balanced_contextual_mean_category_v1",
    "sum": "class_balanced_contextual_sum_category_decision_margin_v1",
}
ADMISSION_HEADER = "x-privoke-training-admission-v1"
SEMANTIC = 4
REGEX = 2

PRESENCE_TRAIN = [
    ("Call 555 0123 at HOME (at) example today", True), ("my passport number is on the form", True),
    ("patient diagnosis report attached", True), ("send the invoice to accounts payable", True),
    ("ＡＢＣ salary details for the team", True), ("what is the weather like tomorrow", False),
    ("write a poem about autumn leaves", False), ("summarise this article in two lines", False),
    ("translate hello world into french", False), ("lunch meeting moved to noon", False),
]
PRESENCE_HELDOUT = [
    ("the patient passport and salary", True), ("invoice for home address", True), ("random thoughts about autumn", False),
    ("weather poem tomorrow", False), ("diagnosis attached to the invoice", True), ("meeting at noon today", False),
]
PRESENCE_PROMPTS = [
    "The patient diagnosis report is attached to the invoice for the home address.",
    "My passport number is on the form and my salary is in the report.",
    "Call 555 0123 tomorrow about the lunch meeting at noon.",
    "What is the weather like tomorrow? Write a poem about autumn leaves.",
    "Translate hello world into french and summarise this article.",
    "Nothing in this sentence appears in the vocabulary of the model: zzqx yyvw.",
    "ＡＢＣ salary [at] example (at) home",
    "tabs\tand\nnewlines   and   many   spaces in the invoice",
    "1 2 3 4 5 6 7 8 9 0",
    "é ü ñ 我叫张伟 invoice 日本語",
    "x" * 500,
    "passport " * 60,
    "Hi",
]
GATE_PROMPTS = [
    "I was diagnosed with type 2 diabetes last March and take metformin daily.",
    "My passport number is on the form and my salary is in the report.",
    "The patient diagnosis report is attached to the invoice for the home address.",
    "What is the capital of France? Write a poem about the sea.",
    "Call me on 555-0100 or email john.smith@example.com tomorrow.",
    "My name is John Smith and I live at 12 Main Street in London.",
    "Weather poem tomorrow, lunch meeting moved to noon.",
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
    "She was arrested in 2019 and my son is only seven years old.",
]


def bootstrap():
    return importlib.import_module("generate_runtime_golden").bootstrap()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --- artifacts --------------------------------------------------------------------------------------------------
def finish(payload: dict) -> dict:
    from privoke_model.artifact import artifact_checksum, validate_artifact

    payload = {key: value for key, value in payload.items() if key != "checksum"}
    payload["checksum"] = artifact_checksum(payload)
    validate_artifact(payload)
    return payload


def tiny_artifact(model_id: str, readout, objective, seed: int, strategy=FULL_STRATEGY, metadata=None) -> dict:
    """A seeded synthetic Tiny artifact, full-capable by default, with Python's own validation applied."""
    from privoke_model.contextual_training import contextual_trainable_names

    training = importlib.import_module("generate_training_golden")
    artifact = training.make_artifact(readout, seed)
    names = contextual_trainable_names(artifact["config"], strategy)
    parameters = {name: {**tensor, "trainable": name in names} for name, tensor in artifact["parameters"].items()}
    meta = {"weight_format": "json-float32"}
    if strategy:
        meta["contextual_training_strategy"] = strategy
    if objective:
        meta["contextual_training_objective"] = objective
    meta.update(metadata or {})
    return finish({**artifact, "model_id": model_id, "version": f"synthetic-{seed}", "generated_at_unix": 1790000000,
                   "parameters": parameters, "metadata": meta})


def presence_artifact(profile: str, threshold: float, version: str, seed: int) -> dict:
    import re

    import numpy as np

    from privoke_model.presence import PROFILE_MAX_FEATURES
    from privoke_model.training_data import training_text_key

    token = re.compile(r"(?u)\b\w\w+\b")
    words, chars = [], []
    for text in [t for t, _ in PRESENCE_TRAIN + PRESENCE_HELDOUT] + PRESENCE_PROMPTS[:9]:
        key = training_text_key(text)
        tokens = token.findall(key)
        for feature in [*tokens, *(" ".join(tokens[i:i + 2]) for i in range(len(tokens) - 1))]:
            if feature not in words:
                words.append(feature)
        for size in (3, 4, 5):
            for i in range(len(key) - size + 1):
                if key[i:i + size] not in chars:
                    chars.append(key[i:i + size])
    chars = chars[::2 if profile == "efficient" else 3]
    rng = np.random.default_rng(seed)
    branch = {"ngram_range": [1, 2], "max_features": PROFILE_MAX_FEATURES[profile], "sublinear_tf": True, "use_idf": True,
              "smooth_idf": True, "norm": "l2", "lowercase": False}
    config = {"task": "annotation_presence", "profile": profile, "threshold": threshold, "normalization": "training_text_key_v1",
              "column_order": ["word", "char"], "coefficient_block_size": 4096,
              "branches": {"word": {**branch, "analyzer": "word", "token_pattern": r"(?u)\b\w\w+\b", "features": words},
                           "char": {**branch, "analyzer": "char", "ngram_range": [3, 5], "features": chars}}}
    total = len(words) + len(chars)
    tensors = {"features.word.idf": 1.0 + rng.random(len(words)), "features.char.idf": 1.0 + rng.random(len(chars)),
               "head.presence.weight.000": 0.8 * rng.standard_normal(total), "head.presence.bias": np.array([-0.1])}
    parameters = {name: {"shape": [len(values)], "values": values.astype(np.float32).tolist(),
                         "trainable": name.startswith("head.presence.")} for name, values in tensors.items()}
    return finish({"schema_version": 1, "architecture": "privoke_sparse_presence_v1", "model_id": f"privoke-presence-{profile}",
                   "version": version, "generated_at_unix": 1790000000, "config": config, "parameters": parameters,
                   "metadata": {"source_revision": "synthetic-r1", "train_sha256": "a" * 64}})


def write_models(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    for readout, tag, seed in ((None, "legacy", SEED + 1), ("residual_task_query_v1", "taskquery", SEED + 2)):
        for name, objective in LEGACY_OBJECTIVES.items():
            model_id = f"synthetic-{tag}-{name}"
            artifacts[model_id] = tiny_artifact(model_id, readout, objective, seed)
    # Artifacts the Rust worker declines: not full-capable, and a local-SGD optimizer.
    artifacts["synthetic-legacy-heads"] = tiny_artifact("synthetic-legacy-heads", None, None, SEED + 1, strategy=None)
    adam = importlib.import_module("privoke_model.full_adam")
    artifacts["synthetic-legacy-adam"] = tiny_artifact(
        "synthetic-legacy-adam", None, LEGACY_OBJECTIVES["sum"], SEED + 1,
        metadata={adam.OPTIMIZER_KEY: adam.POLICY, adam.ELIGIBILITY_KEY: adam.ELIGIBILITY, adam.CONFIG_KEY: adam.canonical(adam.CONFIG)})
    artifacts["synthetic-legacy-sgd"] = tiny_artifact(
        "synthetic-legacy-sgd", None, LEGACY_OBJECTIVES["mean"], SEED + 1, metadata={"contextual_training_optimizer": "local_sgd_1_v1"})
    artifacts["privoke-presence-efficient"] = presence_artifact("efficient", 0.45, "2.1.0+train.007", SEED + 5)
    artifacts["privoke-presence-balanced"] = presence_artifact("balanced", 0.3, "1.0.0", SEED + 6)
    for model_id, payload in artifacts.items():
        (out / f"{model_id}.json").write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                                              encoding="utf-8", newline="\n")
    return artifacts


# --- the Python worker over W1 frames -----------------------------------------------------------------------------
class Worker:
    def __init__(self, roots):
        bootstrap()
        os.environ["TELEMETRY_ENABLED"] = "false"
        from privoke.v1 import runtime_pb2
        from src import worker_main
        from src import worker_protocol as proto
        from src.config import GLOBAL_CONFIG, LLMChoice

        GLOBAL_CONFIG.llm_choice = LLMChoice.Streamed
        worker_main._install_offline_runtime(worker_main.LocalModelProvider(roots, None))
        self.pb, self.proto = runtime_pb2, proto
        self.dispatcher = worker_main.Dispatcher()
        self.next_id = 0

    def call(self, method: int, message, metadata=()) -> dict:
        proto = self.proto
        self.next_id += 1
        payload = message.SerializeToString(deterministic=True)
        body = (proto.encode_metadata(list(metadata)) if metadata else b"") + payload
        frame = proto.encode_frame(proto.Kind.REQUEST, method, self.next_id, body, flags=1 if metadata else 0)
        record = {"method": method, "metadata": [list(pair) for pair in metadata], "request": b64(payload)}
        try:
            request = proto.read_request(io.BytesIO(frame))
            response = self.dispatcher.handle(request)
        except proto.FrameError as exc:
            record["error_code"] = exc.code
            return record
        record["response"] = b64(self.normalise(method, response))
        return record

    def normalise(self, method: int, payload: bytes) -> bytes:
        pb = self.pb
        if method == 1:
            message = pb.AnalyzePromptResponse.FromString(payload)
            message.ClearField("elapsed_ms")
            if "elapsed_ms" in message.metadata:
                del message.metadata["elapsed_ms"]
            return message.SerializeToString(deterministic=True)
        if method == 2:
            message = pb.DetectAnnotationPresenceResponse.FromString(payload)
            message.ClearField("elapsed_ms")
            return message.SerializeToString(deterministic=True)
        return payload


def example(pb, text, sensitivity, visibility, categories, weight=1.0):
    from privoke_contracts.classification import Category, Sensitivity, Visibility, initialise_unpacked

    packed = initialise_unpacked(Sensitivity[sensitivity], Visibility[visibility], [Category[name] for name in categories]).pack()
    return pb.RuntimeTrainingExample(text=text, target=pb.RuntimeClassification(packed=packed), has_target=True, weight=weight)


# --- cases ----------------------------------------------------------------------------------------------------------
def presence_cases(worker: Worker) -> list[dict]:
    pb = worker.pb
    cases = []

    def add(case_id, note, request, scope="presence_inference"):
        record = worker.call(2, request)
        record.update({"id": case_id, "note": note, "scope": scope})
        cases.append(record)

    for model in ("privoke-presence-efficient", "privoke-presence-balanced"):
        for index, text in enumerate(PRESENCE_PROMPTS):
            add(f"{model}/{index}", "explicit semantic-only selection",
                pb.DetectAnnotationPresenceRequest(request_id=f"p{index}", text=text, model_id=model, layers=[SEMANTIC]))
    base = dict(request_id="v", text="my passport and invoice", model_id="privoke-presence-efficient", layers=[SEMANTIC])
    invalid = {
        "validation/layers-regex": ({**base, "layers": [REGEX]}, "a non-semantic selection"),
        "validation/layers-mixed": ({**base, "layers": [REGEX, SEMANTIC]}, "a mixed selection"),
        "validation/model-prefix": ({**base, "model_id": "privoke-balanced"}, "not a presence model id"),
        "validation/model-space": ({**base, "model_id": "privoke-presence-efficient "}, "padded model id"),
        "validation/model-long": ({**base, "model_id": "privoke-presence-" + "x" * 120}, "an over-long model id"),
        "validation/model-control": ({**base, "model_id": "privoke-presence-a\x07b"}, "a control character"),
        "validation/model-traversal": ({**base, "model_id": "privoke-presence-../x"}, "an invalid identifier"),
        "validation/model-unknown": ({**base, "model_id": "privoke-presence-quality"}, "a presence model that is not in the roots"),
        "validation/model-scratch": ({**base, "model_id": "privoke-scratch-presence-efficient-head-only"}, "a scratch id"),
        "validation/request-id": ({**base, "request_id": "  "}, "a blank request id"),
        "validation/text-blank": ({**base, "text": " \n\t "}, "blank text"),
        "validation/text-empty": ({**base, "text": ""}, "empty text"),
        "validation/text-long": ({**base, "text": "a" * 20001}, "text over the limit"),
        "validation/text-edge": ({**base, "text": "invoice " * 2500}, "text at the limit"),
    }
    for case_id, (fields, note) in invalid.items():
        # A text at the limit is a valid request: its answer carries a probability.
        scope = "presence_inference" if case_id.endswith("text-edge") else "validation"
        add(case_id, note, pb.DetectAnnotationPresenceRequest(**fields), scope=scope)
    return cases


def gate_cases(worker: Worker) -> list[dict]:
    pb = worker.pb
    cases = []

    def add(case_id, note, scope, **fields):
        record = worker.call(1, pb.AnalyzePromptRequest(**fields))
        record.update({"id": case_id, "note": note, "scope": scope})
        cases.append(record)

    thresholds = [None, 0.0, 0.3, 0.5, 0.9999, 1.0]
    for gate in ("privoke-presence-efficient", "privoke-presence-balanced"):
        for index, text in enumerate(GATE_PROMPTS):
            for threshold in thresholds[: (6 if index < 3 else 2)]:
                gate_message = pb.SemanticPresenceGate(model_id=gate) if threshold is None else \
                    pb.SemanticPresenceGate(model_id=gate, threshold=threshold)
                add(f"gate/{gate}/{index}/{threshold}", "semantic layer alone behind the presence gate", "llm_only",
                    text=text, layers=[SEMANTIC], request_id=f"g{index}", semantic_model_id="privoke-balanced",
                    semantic_presence_gate=gate_message)
    gate = pb.SemanticPresenceGate(model_id="privoke-presence-efficient")
    for index, text in enumerate(GATE_PROMPTS[:5]):
        add(f"gate-product/{index}", "regex first, semantic behind the gate", "product_pipeline",
            text=text, layers=[REGEX, SEMANTIC], request_id=f"gp{index}", semantic_model_id="privoke-balanced",
            semantic_presence_gate=gate)
        add(f"gate-product-parallel/{index}", "regex in parallel, semantic behind the gate", "product_pipeline",
            text=text, layers=[SEMANTIC, REGEX], request_id=f"gq{index}", semantic_model_id="privoke-balanced",
            regex_execution_order=pb.REGEX_EXECUTION_ORDER_PARALLEL, semantic_presence_gate=gate)
    add("gate-product/block", "regex returns BLOCK, the gated semantic layer is skipped", "product_pipeline",
        text="My card number is 4111 1111 1111 1111 and my email is a.b@example.com", layers=[REGEX, SEMANTIC],
        request_id="gb", semantic_model_id="privoke-balanced", semantic_presence_gate=gate)
    add("gate/hint", "visibility hint on a gated finding", "llm_only", text=GATE_PROMPTS[0], layers=[SEMANTIC],
        request_id="gh", semantic_model_id="privoke-balanced", visibility_hint="P3", semantic_presence_gate=gate)
    invalid = {
        "validation/gate-model": (dict(semantic_presence_gate=pb.SemanticPresenceGate(model_id="nope")), "an unknown gate model"),
        "validation/gate-balanced-id": (dict(semantic_presence_gate=pb.SemanticPresenceGate(model_id="privoke-balanced")), "a semantic id as the gate"),
        "validation/gate-no-semantic": (dict(layers=[REGEX], semantic_presence_gate=gate), "a gate without the semantic layer"),
        "validation/gate-model-id-missing": (dict(semantic_model_id="", semantic_presence_gate=gate), "no semantic_model_id"),
        "validation/gate-model-id-other": (dict(semantic_model_id="privoke-quality", semantic_presence_gate=gate), "another semantic model"),
        "validation/gate-threshold-high": (dict(semantic_presence_gate=pb.SemanticPresenceGate(model_id="privoke-presence-efficient", threshold=1.5)), "threshold above one"),
        "validation/gate-threshold-low": (dict(semantic_presence_gate=pb.SemanticPresenceGate(model_id="privoke-presence-efficient", threshold=-0.1)), "negative threshold"),
        "validation/gate-threshold-inf": (dict(semantic_presence_gate=pb.SemanticPresenceGate(model_id="privoke-presence-efficient", threshold=float("inf"))), "infinite threshold"),
        "validation/gate-threshold-nan": (dict(semantic_presence_gate=pb.SemanticPresenceGate(model_id="privoke-presence-efficient", threshold=float("nan"))), "NaN threshold"),
        "validation/gate-absent-model": (dict(semantic_presence_gate=pb.SemanticPresenceGate(model_id="privoke-presence-quality")), "a presence model that is not in the roots"),
    }
    for case_id, (fields, note) in invalid.items():
        base = dict(text=GATE_PROMPTS[1], layers=[SEMANTIC], request_id=case_id[-12:], semantic_model_id="privoke-balanced")
        base.update(fields)
        add(case_id, note, "validation", **base)
    return cases


def gradient_cases(worker: Worker) -> list[dict]:
    pb = worker.pb
    training = importlib.import_module("generate_training_golden")
    rows = training.make_examples()
    heldout_rows = training.make_heldout()
    cases = []

    def build(items):
        return [r if not isinstance(r, dict) else example(pb, r["text"], r["sensitivity"], r["visibility"], r["categories"], r["weight"])
                for r in items]

    def request(model_id, items=rows, held=heldout_rows, **fields):
        values = dict(request_id="t1", model_id=model_id, examples=build(items), heldout_examples=build(held),
                      learning_rate=0.5, max_gradient=0.05, layers=[SEMANTIC])
        values.update(fields)
        return pb.ComputeSemanticGradientsRequest(**values)

    def add(case_id, note, scope, method, message, metadata=()):
        record = worker.call(method, message, metadata)
        record.update({"id": case_id, "note": note, "scope": scope})
        cases.append(record)

    for tag in ("legacy", "taskquery"):
        for name, objective in LEGACY_OBJECTIVES.items():
            model_id = f"synthetic-{tag}-{name}"
            header = ()
            if objective == LEGACY_OBJECTIVES["sum"]:
                header = ((ADMISSION_HEADER, json.dumps({"schema": 2, "expected_objective": objective,
                                                          "expected_diagnostics_policy": None})),)
            for method, scope in ((4, "heads"), (5, "full_encoder")):
                add(f"{model_id}/{scope}", f"{scope} scope on a full-capable artifact", "single_update", method,
                    request(model_id), header)
    sum_id = "synthetic-legacy-sum"
    sum_objective = LEGACY_OBJECTIVES["sum"]
    schema2 = json.dumps({"schema": 2, "expected_objective": sum_objective, "expected_diagnostics_policy": None})
    add("admission/missing", "sum-margin training without its admission header", "validation", 5, request(sum_id))
    add("admission/differs", "an objective admission that differs from the artifact", "validation", 5,
        request("synthetic-legacy-mean"), ((ADMISSION_HEADER, schema2),))
    adam_id = "synthetic-legacy-adam"
    for method in (4, 5):
        add(f"admission/full-adam-missing/{method}", "a FULL Adam artifact without explicit pre-gradient admission", "validation",
            method, request(adam_id))
        add(f"admission/full-adam-objective-only/{method}", "a FULL Adam artifact with only the objective admission", "validation",
            method, request(adam_id), ((ADMISSION_HEADER, schema2),))
    base = "synthetic-legacy-mean"
    invalid = {
        "validation/model-blank": request(" "),
        "validation/model-unknown": request("synthetic-nope"),
        "validation/model-invalid-id": request("../x"),
        "validation/no-examples": request(base, items=[]),
        "validation/no-heldout": request(base, held=[]),
        "validation/layers-regex": request(base, layers=[REGEX]),
        "validation/layers-mixed": request(base, layers=[REGEX, SEMANTIC]),
        "validation/learning-rate": request(base, learning_rate=0.0),
        "validation/max-gradient": request(base, max_gradient=-1.0),
        "validation/text-empty": request(base, items=[example(pb, "", "S0", "P0", [])] + build(rows[1:])),
        "validation/overlap": request(base, held=heldout_rows[:1] + [rows[0]]),
        "validation/weight": request(base, items=[{**rows[0], "weight": 0.0}] + rows[1:]),
        "validation/one-class": request(base, items=[r for r in rows if r["sensitivity"] == "S0"]),
    }
    for case_id, message in invalid.items():
        for method in (4, 5):
            add(f"{case_id}/{method}", "request or contract violation", "validation", method, message)
    # The request limits.
    many = [{"text": f"row {i} invoice passport", "sensitivity": "S2" if i % 2 else "S0", "visibility": "P1",
             "categories": ["IDENTITY"] if i % 2 else [], "weight": 1.0} for i in range(1100)]
    add("validation/too-many", "more than 1,024 examples", "validation", 4, request(base, items=many[:1020], held=many[1020:1030]))
    add("validation/too-much-text", "more than 200,000 characters", "validation", 4,
        request(base, items=[{**r, "text": ("a b " * 3000) + str(i)} for i, r in enumerate(rows * 2)]))
    add("validation/overlength", "a training text over the 12-token context of a full-capable artifact", "validation", 4,
        request(base, items=[{**rows[0], "text": "one two three four five six seven eight nine ten eleven twelve thirteen"}] + rows[1:]))
    add("validation/overlength-edge", "a text of exactly 11 tokens plus the start token", "single_update", 4,
        request(base, items=[{**rows[0], "text": "one two three four five six seven eight nine ten eleven"}] + rows[1:]))
    add("validation/overlength-heldout", "an overlong held-out text", "validation", 4,
        request(base, held=[{**heldout_rows[0], "text": "one two three four five six seven eight nine ten eleven twelve thirteen"}] + heldout_rows[1:]))
    # Presence gradients.
    presence = []

    def presence_example(text, target, weight, group):
        return pb.PresenceTrainingExample(text=text, target=pb.ANNOTATION_PRESENCE_PRESENT if target else pb.ANNOTATION_PRESENCE_ABSENT,
                                          weight=weight, group_id=group)

    train = [presence_example(t, y, 1.0 + 0.25 * (i % 3), f"g{i}") for i, (t, y) in enumerate(PRESENCE_TRAIN)]
    held = [presence_example(t, y, 1.0, f"h{i}") for i, (t, y) in enumerate(PRESENCE_HELDOUT)]

    def presence_request(model_id="privoke-presence-efficient", examples=train, heldout=held, **fields):
        values = dict(request_id="pg", model_id=model_id, examples=examples, heldout_examples=heldout,
                      learning_rate=0.8, max_gradient=0.05, layers=[SEMANTIC])
        values.update(fields)
        return pb.ComputePresenceGradientsRequest(**values)

    for model in ("privoke-presence-efficient", "privoke-presence-balanced"):
        for rate, bound in ((0.8, 0.05), (0.2, 0.01), (2.0, 0.5)):
            add(f"presence-gradients/{model}/{rate}", "explicit semantic-only selection", "presence_training", 6,
                presence_request(model, learning_rate=rate, max_gradient=bound))
    bad_target = [pb.PresenceTrainingExample(text="no target here", weight=1.0, group_id="x")] + train[1:]
    cases_invalid = {
        "validation/presence-layers": presence_request(layers=[REGEX]),
        "validation/presence-heldout": presence_request(heldout=[]),
        "validation/presence-model": presence_request(model_id="privoke-balanced"),
        "validation/presence-model-space": presence_request(model_id="privoke-presence-efficient "),
        "validation/presence-request-id": presence_request(request_id=" "),
        "validation/presence-examples": presence_request(examples=[]),
        "validation/presence-target": presence_request(examples=bad_target),
        "validation/presence-unknown": presence_request(model_id="privoke-presence-quality"),
        "validation/presence-learning-rate": presence_request(learning_rate=0.0),
        "validation/presence-group": presence_request(heldout=[presence_example("fresh heldout text", False, 1.0, "g1")] + held[:2]),
        "validation/presence-overlap": presence_request(heldout=[presence_example(PRESENCE_TRAIN[0][0], True, 1.0, "z"),
                                                                presence_example("something else entirely", False, 1.0, "y")]),
        "validation/presence-weight": presence_request(examples=[presence_example("zero weight", True, 0.0, "w")] + train[1:]),
        "validation/presence-one-label": presence_request(examples=[e for e in train if e.target == pb.ANNOTATION_PRESENCE_PRESENT]),
    }
    for case_id, message in cases_invalid.items():
        add(case_id, "request or contract violation", "validation", 6, message)
    return cases


# --- the local-SGD, diagnostics and backtracking routes (RUST-S19C) ---------------------------------------------------
def route_models(out: Path) -> dict:
    """Synthetic artifacts whose metadata selects a route beyond the single update (and artifacts the checks refuse)."""
    training = importlib.import_module("generate_training_golden")
    from privoke_model import contextual_training as ct
    from privoke_model import full_adam, sensitive_retention, window_training

    margin, summed = training.OBJECTIVES["decision_margin"], training.OBJECTIVES["sum_margin"]
    diagnostics = {ct.DIAGNOSTICS_POLICY_KEY: ct.TRAIN_DIAGNOSTICS_POLICY}
    backtracking = {ct.BACKTRACKING_KEY: ct.BACKTRACKING_POLICY, ct.BACKTRACKING_PREPARATION_KEY: training.preparation_text(),
                    ct.DIAGNOSTICS_POLICY_KEY: ct.TRAIN_DIAGNOSTICS_POLICY}
    window = {ct.OPTIMIZER_KEY: window_training.POLICY, ct.OBJECTIVE_KEY: window_training.OBJECTIVE,
              "contextual_candidate_eligibility": window_training.ELIGIBILITY,
              window_training.CONFIG_KEY: window_training.canonical(window_training.CONFIG),
              window_training.WINDOW_KEY: "a" * 64, window_training.REFERENCE_KEY: "b" * 64}
    policy = sorted(sensitive_retention.POLICIES)[0]
    retention = {ct.OPTIMIZER_KEY: policy, ct.OBJECTIVE_KEY: sensitive_retention.OBJECTIVES[policy],
                 "contextual_candidate_eligibility": sensitive_retention.ELIGIBILITY,
                 full_adam.CONFIG_KEY: full_adam.canonical(full_adam.CONFIG), sensitive_retention.MANIFEST_KEY: "c" * 64}
    taskquery = "residual_task_query_v1"
    artifacts = {
        "synthetic-taskquery-sgd4": tiny_artifact("synthetic-taskquery-sgd4", taskquery, margin, SEED + 2,
                                                  metadata={ct.OPTIMIZER_KEY: "local_sgd_4_v1"}),
        "synthetic-legacy-diagsum": tiny_artifact("synthetic-legacy-diagsum", None, summed, SEED + 1, metadata=diagnostics),
        "synthetic-taskquery-diag": tiny_artifact("synthetic-taskquery-diag", taskquery, None, SEED + 2, metadata=diagnostics),
        "synthetic-legacy-bt": tiny_artifact("synthetic-legacy-bt", None, None, SEED + 1, metadata=backtracking),
        "synthetic-taskquery-btsum": tiny_artifact("synthetic-taskquery-btsum", taskquery, summed, SEED + 2, metadata=backtracking),
        "synthetic-legacy-window": tiny_artifact("synthetic-legacy-window", None, None, SEED + 1, metadata=window),
        "synthetic-legacy-retention": tiny_artifact("synthetic-legacy-retention", None, None, SEED + 1, metadata=retention),
    }
    out.mkdir(parents=True, exist_ok=True)
    for model_id, payload in artifacts.items():
        (out / f"{model_id}.json").write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                                              encoding="utf-8", newline="\n")
    return artifacts


def route_cases(worker: Worker) -> list[dict]:
    import hashlib

    pb = worker.pb
    training = importlib.import_module("generate_training_golden")
    from privoke_model import contextual_training as ct

    rows = training.make_examples()
    heldout_rows = training.make_heldout()
    cases = []

    def build(items):
        return [example(pb, r["text"], r["sensitivity"], r["visibility"], r["categories"], r["weight"]) for r in items]

    def request(model_id, **fields):
        values = dict(request_id="t1", model_id=model_id, examples=build(rows), heldout_examples=build(heldout_rows),
                      learning_rate=0.5, max_gradient=0.05, layers=[SEMANTIC])
        values.update(fields)
        return pb.ComputeSemanticGradientsRequest(**values)

    def add(case_id, note, scope, method, message, metadata=()):
        record = worker.call(method, message, metadata)
        record.update({"id": case_id, "note": note, "scope": scope})
        cases.append(record)

    sha = hashlib.sha256(training.preparation_text().encode()).hexdigest()
    summed = training.OBJECTIVES["sum_margin"]

    def objective_header(diagnostics=None):
        return ((ADMISSION_HEADER, json.dumps({"schema": 2, "expected_objective": summed, "expected_diagnostics_policy": diagnostics})),)

    def backtracking_header(objective):
        return ((ADMISSION_HEADER, json.dumps({
            "schema": 1, "expected_objective": objective, "expected_diagnostics_policy": ct.TRAIN_DIAGNOSTICS_POLICY,
            "expected_backtracking_policy": ct.BACKTRACKING_POLICY, "expected_backtracking_preparation_sha256": sha})),)

    for method, scope in ((4, "heads"), (5, "full_encoder")):
        add(f"local-sgd-1/mean/{scope}", "explicit local_sgd_1_v1, mean-category objective", "local_sgd", method,
            request("synthetic-legacy-sgd"))
        add(f"local-sgd-4/decision-margin/{scope}", "explicit local_sgd_4_v1, decision-margin objective, task-query readout",
            "local_sgd", method, request("synthetic-taskquery-sgd4", learning_rate=0.05))
        add(f"diagnostics/summed-margin/{scope}", "TRAIN diagnostics with the summed-margin objective and its header",
            "diagnostics", method, request("synthetic-legacy-diagsum"), objective_header(ct.TRAIN_DIAGNOSTICS_POLICY))
        add(f"diagnostics/legacy/{scope}", "TRAIN diagnostics on the legacy objective, no header", "diagnostics", method,
            request("synthetic-taskquery-diag", learning_rate=0.1))
    for tag, rate in (("first-scale", 0.5), ("rejected", 1e-9), ("second-scale", 1.7e308)):
        add(f"backtracking/legacy/{tag}", "FULL backtracking, legacy objective", "backtracking", 5,
            request("synthetic-legacy-bt", learning_rate=rate), backtracking_header(ct.LEGACY_OBJECTIVE))
    add("backtracking/summed-margin/first-scale", "FULL backtracking, summed-margin objective, task-query readout",
        "backtracking", 5, request("synthetic-taskquery-btsum"), backtracking_header(summed))
    # Refusals: the Python texts, as responses.
    add("refusal/backtracking-header-on-heads", "a backtracking header on the head scope", "validation", 4,
        request("synthetic-legacy-bt"), backtracking_header(ct.LEGACY_OBJECTIVE))
    add("refusal/backtracking-without-header", "a backtracking artifact without its header", "validation", 5,
        request("synthetic-legacy-bt"))
    add("refusal/diagnostics-header-differs", "a diagnostics artifact against an objective-only header without the policy",
        "validation", 5, request("synthetic-legacy-diagsum"), objective_header(None))
    add("refusal/window-without-header", "a window artifact without its header", "validation", 5,
        request("synthetic-legacy-window"))
    add("refusal/window-objective-header", "a window artifact with the objective-only header", "validation", 5,
        request("synthetic-legacy-window"), objective_header(None))
    add("refusal/retention-objective-header", "an ORIGINAL-retention artifact with the objective-only header", "validation", 5,
        request("synthetic-legacy-retention"), objective_header(None))
    return cases


# Historical (stage V3-R8b): the routes golden, its Rust test and the seven route-only worker models were deleted with the V1
# gradient dispatch; running `write_routes` recreates them as untracked files.
def write_routes(out: Path, models_out: Path = MODELS_OUT) -> dict:
    bootstrap()
    artifacts = route_models(models_out)
    worker = Worker([models_out, TRACKED_MODELS])
    document = {
        "schema": 1,
        "python": sys.version.split()[0],
        "scope_note": "local-SGD, TRAIN diagnostics and FULL backtracking gradient RPCs over W1 frames; every request names "
                      "exactly the semantic layer",
        "models": sorted(artifacts),
        "cases": route_cases(worker),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    return document


def write(out: Path, models_out: Path = MODELS_OUT) -> dict:
    bootstrap()
    artifacts = write_models(models_out)
    worker = Worker([models_out, TRACKED_MODELS])
    document = {
        "schema": 1,
        "python": sys.version.split()[0],
        "scope_note": "presence, presence-gated AnalyzePrompt and gradient RPCs over W1 frames; every request names its layers "
                      "explicitly and non-empty; rows of scope llm_only select exactly the semantic layer, product_pipeline rows add regex",
        "models": sorted(artifacts),
        "cases": presence_cases(worker) + gate_cases(worker) + gradient_cases(worker),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    return document


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    writer = sub.add_parser("write", help="write the models and the golden fixture")
    writer.add_argument("--out", default=str(DEFAULT_OUT))
    router = sub.add_parser("routes", help="write the route models and the route golden fixture")
    router.add_argument("--out", default=str(ROUTES_OUT))
    args = parser.parse_args(argv)
    document = write_routes(Path(args.out)) if args.command == "routes" else write(Path(args.out))
    counts: dict[str, int] = {}
    for case in document["cases"]:
        counts[case["scope"]] = counts.get(case["scope"], 0) + 1
    print(f"wrote {args.out}: {len(document['cases'])} cases {counts}")


if __name__ == "__main__":
    main()
