"""Golden generator for the privoke-training crate (RUST-S19, stage 19).

Runs the product's own Tiny training code on seeded synthetic models and records what the Rust port must reproduce:

* ``supervised_training.supervised_last_block_deltas`` (the gradient of every objective the Tiny paths use), and
* ``full_adam_training.fit`` (the FULL projected Adam fit, 64 fixed steps, float64 moments, one CPU thread).

Nothing here calls the runtime pipeline or a detector layer: the code under test is the semantic-layer training path
only, so no layer list is ever built (the project's LLM-layer isolation rule has nothing to select here).
Tensors are stored as float32 bit patterns (``uint32``), so the Rust side compares exactly what torch produced.

    python evaluation/generate_training_golden.py synthetic     # writes the committed fixture
    python evaluation/generate_training_golden.py routes        # writes the local-SGD, backtracking and diagnostics fixture

The ``routes`` command (RUST-S19C, stage 19 item 2c) runs the product's ``_compute_training_gradients`` on a fake streamed
snapshot whose metadata selects one of the routes beyond the single update: the explicit local-SGD optimizers
(``local_sgd_1_v1``, ``local_sgd_4_v1``), the TRAIN diagnostics policy and the FULL backtracking policy, in the head and
full-encoder scopes, plus the artifact-policy and admission refusals (window, ORIGINAL retention, FULL Adam orphans,
backtracking and objective admission). Every request is the semantic-only training path; nothing builds a layer list.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# FULL Adam requires startup OMP/MKL threads of one; set before torch is imported.
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

REPO = Path(__file__).resolve().parents[1]
CRATE = REPO / "rust" / "crates" / "privoke-training"
FIXTURE = CRATE / "tests" / "fixtures" / "tiny_training_golden.json"
ROUTES_FIXTURE = CRATE / "tests" / "fixtures" / "tiny_training_routes_golden.json"
SEED = 20261119
LABELS = {
    "sensitivity": ["S0", "S1", "S2", "S3"],
    "visibility": ["P0", "P1", "P2", "P3", "P4", "PU"],
    "category": ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"],
}
WORDS = ["alpha", "beta", "gamma", "delta", "invoice", "patient", "salary", "meeting", "report", "address", "passport", "lunch"]
OBJECTIVES = {
    "legacy": None,
    "class_balanced": "class_balanced_contextual_v1",
    "mean_category": "class_balanced_contextual_mean_category_v1",
    "decision_margin": "class_balanced_contextual_decision_margin_v1",
    "sum_margin": "class_balanced_contextual_sum_category_decision_margin_v1",
}


def bootstrap() -> None:
    import os as _os

    extra = [Path(_os.environ["PRIVOKE_GENERATED"])] if _os.environ.get("PRIVOKE_GENERATED") else []
    for path in (REPO / "extension" / "client-runtime", REPO / "shared" / "python", REPO / "evaluation",
                 REPO / "extension" / "client-runtime" / "generated", *extra):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def config_for(readout: str | None) -> dict:
    config = {
        "category_labels": LABELS["category"], "category_threshold": 0.42, "hidden_size": 8, "intermediate_size": 8,
        "max_tokens": 12, "num_attention_heads": 2, "num_layers": 2, "sensitivity_labels": LABELS["sensitivity"],
        "visibility_labels": LABELS["visibility"], "vocab_size": 24,
    }
    if readout is not None:
        config["readout"] = readout
    return config


def make_artifact(readout: str | None, seed: int) -> dict:
    import numpy as np

    config = config_for(readout)
    rng = np.random.default_rng(seed)
    hidden, inner = config["hidden_size"], config["intermediate_size"]
    shapes = {"token_embedding": (config["vocab_size"], hidden), "position_embedding": (config["max_tokens"], hidden)}
    for task, labels in LABELS.items():
        shapes[f"head.{task}.weight"] = (hidden, len(labels))
        shapes[f"head.{task}.bias"] = (len(labels),)
    for layer in range(config["num_layers"]):
        for name, shape in {
            "attention.query.weight": (hidden, hidden), "attention.key.weight": (hidden, hidden),
            "attention.value.weight": (hidden, hidden), "attention.output.weight": (hidden, hidden),
            "attention.output.bias": (hidden,), "ffn.input.weight": (hidden, inner), "ffn.input.bias": (inner,),
            "ffn.output.weight": (inner, hidden), "ffn.output.bias": (hidden,),
        }.items():
            shapes[f"layers.{layer}.{name}"] = shape
    if readout is not None:
        for task in LABELS:
            shapes[f"readout.{task}.query"] = (hidden,)
    parameters = {}
    for name in sorted(shapes):
        scale = 0.5 if "embedding" in name or name.startswith("readout") else 0.4
        values = (scale * rng.standard_normal(shapes[name])).astype(np.float32)
        parameters[name] = {"shape": list(shapes[name]), "values": values.ravel().tolist()}
    return {
        "architecture": "privoke_tiny_transformer_v2" if readout is not None else "privoke_tiny_transformer_v1",
        "config": config, "model_id": f"synthetic-train-{readout or 'legacy'}", "version": f"synthetic-{seed}",
        "parameters": parameters, "metadata": {"weight_format": "json-float32"}, "schema_version": 1,
    }


def make_examples(count: int = 12) -> list[dict]:
    import random

    rng = random.Random(SEED)
    rows = []
    for index in range(count):
        text = " ".join(rng.choice(WORDS) for _ in range(rng.randint(3, 8)))
        sensitive = index % 3 != 0
        rows.append({
            "text": text,
            "sensitivity": rng.choice(["S1", "S2", "S3"]) if sensitive else "S0",
            "visibility": rng.choice(LABELS["visibility"]),
            "categories": sorted(rng.sample(LABELS["category"], rng.randint(1, 3))) if sensitive else [],
            "weight": rng.choice([1.0, 1.0, 2.0, 0.5]),
        })
    return rows


def bits(values) -> list[int]:
    import numpy as np

    return np.asarray([float(v) for v in values], dtype=np.float32).view(np.uint32).tolist()


def build_examples(rows):
    from privoke_contracts.classification import Category, Sensitivity, Visibility, initialise_unpacked
    from src.LLM.privoke.training import SemanticTrainingExample

    return tuple(
        SemanticTrainingExample(
            text=row["text"], weight=row["weight"],
            target=initialise_unpacked(Sensitivity[row["sensitivity"]], Visibility[row["visibility"]],
                                       [Category[name] for name in row["categories"]]))
        for row in rows)


def tiny_model(artifact: dict, *, parameters=None):
    from src.model import ModelConfig, TinyTransformerModel

    shapes = {name: tuple(t["shape"]) for name, t in artifact["parameters"].items()}
    values = parameters if parameters is not None else {name: t["values"] for name, t in artifact["parameters"].items()}
    return TinyTransformerModel(ModelConfig.from_mapping(artifact["config"]), values, shapes, device="cpu"), shapes


def gradient_case(artifact: dict, name: str, objective, examples) -> dict:
    from src.LLM.privoke.supervised_training import supervised_last_block_deltas

    model, shapes = tiny_model(artifact)
    diagnostics = {}
    deltas, loss = supervised_last_block_deltas(model, examples, set(shapes), objective=objective,
                                                diagnostics=diagnostics if objective else None)
    return {"objective_name": name, "objective": objective, "loss": loss, "task_totals": diagnostics,
            "deltas": {n: bits(v) for n, v in sorted(deltas.items())}}


def adam_record(artifact: dict, rows: list[dict]) -> dict:
    import torch

    torch.set_num_threads(1)
    from privoke_model.fingerprint import parameter_fingerprint
    from privoke_model.full_adam import OBJECTIVE, TRACE_KEY
    from src.LLM.privoke import full_adam_training, supervised_training
    from src.LLM.privoke.training import _class_balanced_examples

    examples, audit = _class_balanced_examples(build_examples(rows))
    model, shapes = tiny_model(artifact)
    base = {name: tuple(float(v) for v in artifact["parameters"][name]["values"]) for name in sorted(shapes)}
    recorded: list[dict] = []
    original = supervised_training.supervised_last_block_deltas

    def recording(*args, **kwargs):
        direction, loss = original(*args, **kwargs)
        recorded.append({"loss": loss, "direction": {n: bits(v) for n, v in sorted(direction.items())}})
        return direction, loss

    supervised_training.supervised_last_block_deltas = recording
    try:
        cumulative, candidate, _, metadata = full_adam_training.fit(model, base, shapes, examples)
    finally:
        supervised_training.supervised_last_block_deltas = original
    trace = json.loads(metadata[TRACE_KEY])
    steps = []
    for step, row in zip(recorded, trace["steps"]):
        steps.append({**step, "before": row["before"], "after": row["after"], "delta": row["delta"],
                      "clipped": row["clipped"], "trace_loss": row["loss"]})
    return {
        "objective": OBJECTIVE, "weights": [e.weight for e in examples], "weight_audit": audit,
        "base_fingerprint": trace["base"], "final_fingerprint": trace["final"], "delta_fingerprint": trace["delta"],
        "counts": trace["counts"], "steps": steps,
        "candidate_bits": {n: bits(v) for n, v in sorted(candidate.items())},
        "cumulative_bits": {n: bits(v) for n, v in sorted(cumulative.items())},
        "fingerprint_check": parameter_fingerprint(candidate, shapes) == trace["final"],
    }


HELDOUT_WORDS = ["zeta", "omega", "ledger", "diagnosis", "visa", "ticket"]


def make_heldout(count: int = 8) -> list[dict]:
    import random

    rng = random.Random(SEED + 7)
    rows = []
    for index in range(count):
        text = f"heldout{index} " + " ".join(rng.choice(HELDOUT_WORDS) for _ in range(rng.randint(2, 5)))
        sensitive = index % 2 == 0
        rows.append({
            "text": text,
            "sensitivity": rng.choice(["S1", "S2", "S3"]) if sensitive else "S0",
            "visibility": rng.choice(LABELS["visibility"]),
            "categories": sorted(rng.sample(LABELS["category"], rng.randint(1, 3))) if sensitive else [],
            "weight": 1.0,
        })
    return rows


def rpc_case(artifact: dict, objective, full_encoder: bool, rows, heldout_rows, learning_rate: float, max_gradient: float) -> dict:
    """Run the product's `_compute_training_gradients` on a fake streamed snapshot."""
    import types

    from src.LLM.privoke import training
    from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel

    parameters = {name: tuple(t["values"]) for name, t in artifact["parameters"].items()}
    shapes = {name: tuple(t["shape"]) for name, t in artifact["parameters"].items()}
    metadata = {
        "model_config": json.dumps(artifact["config"]), "architecture": artifact["architecture"], "artifact_checksum": "0" * 64,
        "contextual_training_strategy": "contextual_full_encoder_sgd_v1",
        "trainable_parameters": ",".join(sorted(parameters)),
    }
    if objective is not None:
        metadata["contextual_training_objective"] = objective
    snapshot = types.SimpleNamespace(model_id=artifact["model_id"], version=artifact["version"], parameters=parameters,
                                     shapes=shapes, metadata=metadata, cache_key="golden", fingerprint="golden")
    runtime = StreamedTransformerPrivacyModel(snapshot)
    saved = training.ModelParameterStreamer, training.GLOBAL_STREAMED_MODEL_CACHE
    training.ModelParameterStreamer = lambda model_id: types.SimpleNamespace(model_id=model_id)
    training.GLOBAL_STREAMED_MODEL_CACHE = types.SimpleNamespace(model_for_training=lambda streamer: runtime)
    admission = None if objective is None else {"expected_objective": objective, "expected_diagnostics_policy": None}
    try:
        batch = training._compute_training_gradients(
            build_examples(rows), model_id=artifact["model_id"], learning_rate=learning_rate, max_gradient=max_gradient,
            heldout_examples=build_examples(heldout_rows), full_encoder=full_encoder, admission=admission)
    finally:
        training.ModelParameterStreamer, training.GLOBAL_STREAMED_MODEL_CACHE = saved
    return {
        "full_encoder": full_encoder, "objective": objective, "learning_rate": learning_rate, "max_gradient": max_gradient,
        "gradients": {n: bits(v) for n, v in sorted(batch.gradients.items())}, "metrics": batch.metrics,
        "executions": [list(item) for item in batch.executions], "error": batch.error,
        "scope": batch.metadata["training_scope"],
    }


def admission_cases() -> dict:
    """`full_adam.validate_admission` on active and inactive artifacts, with the exact Python outcomes."""
    from privoke_model import full_adam

    config = full_adam.canonical(full_adam.CONFIG)
    active = {full_adam.OPTIMIZER_KEY: full_adam.POLICY, "contextual_training_strategy": full_adam.STRATEGY,
              "contextual_training_objective": full_adam.OBJECTIVE, full_adam.ELIGIBILITY_KEY: full_adam.ELIGIBILITY,
              full_adam.CONFIG_KEY: config}
    header = {"expected_optimizer": full_adam.POLICY, "expected_candidate_eligibility": full_adam.ELIGIBILITY,
              "expected_optimizer_config": config}
    scenarios = {
        "active_matching": (active, header),
        "active_missing_header": (active, None),
        "active_wrong_config": ({**active, full_adam.CONFIG_KEY: config.replace("64", "65")}, header),
        "active_wrong_objective": ({**active, "contextual_training_objective": "class_balanced_contextual_v1"}, header),
        "active_backtracking_key": ({**active, "contextual_training_backtracking_policy": "x"}, header),
        "active_header_mismatch": (active, {**header, "expected_optimizer_config": "{}"}),
        "inactive_plain": ({"contextual_training_strategy": full_adam.STRATEGY}, None),
        "inactive_stray_eligibility": ({full_adam.ELIGIBILITY_KEY: full_adam.ELIGIBILITY}, None),
        "inactive_with_header": ({}, header),
    }
    cases = []
    for name, (metadata, admission) in scenarios.items():
        try:
            outcome = {"active": bool(full_adam.validate_admission(admission, metadata))}
        except ValueError as exc:
            outcome = {"error": str(exc)}
        cases.append({"name": name, "metadata": metadata, "admission": admission, **outcome})
    return {"config_canonical": config, "cases": cases}


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


def presence_artifact(seed: int) -> dict:
    import re

    import numpy as np

    from privoke_model.training_data import training_text_key

    token = re.compile(r"(?u)\b\w\w+\b")
    words, chars = [], []
    for text, _ in PRESENCE_TRAIN + PRESENCE_HELDOUT:
        key = training_text_key(text)
        tokens = token.findall(key)
        for feature in [*tokens, *(" ".join(tokens[i:i + 2]) for i in range(len(tokens) - 1))]:
            if feature not in words:
                words.append(feature)
        for size in (3, 4, 5):
            for i in range(len(key) - size + 1):
                if key[i:i + size] not in chars:
                    chars.append(key[i:i + size])
    chars = chars[::2]
    rng = np.random.default_rng(seed)
    branch = {"ngram_range": [1, 2], "max_features": 2000, "sublinear_tf": True, "use_idf": True, "smooth_idf": True,
              "norm": "l2", "lowercase": False}
    config = {"task": "annotation_presence", "profile": "efficient", "threshold": 0.45, "normalization": "training_text_key_v1",
              "column_order": ["word", "char"], "coefficient_block_size": 4096,
              "branches": {"word": {**branch, "analyzer": "word", "token_pattern": r"(?u)\b\w\w+\b", "features": words},
                           "char": {**branch, "analyzer": "char", "ngram_range": [3, 5], "features": chars}}}
    total = len(words) + len(chars)
    tensors = {"features.word.idf": 1.0 + rng.random(len(words)), "features.char.idf": 1.0 + rng.random(len(chars)),
               "head.presence.weight.000": 0.8 * rng.standard_normal(total), "head.presence.bias": np.array([-0.1])}
    parameters = {n: {"shape": [len(v)], "values": v.astype(np.float32).tolist()} for n, v in tensors.items()}
    return {"architecture": "privoke_sparse_presence_v1", "config": config, "parameters": parameters}


def presence_record() -> dict:
    import types

    from privoke_model.presence import SparsePresenceModel
    from src.LLM.privoke import presence_training as pt

    artifact = presence_artifact(SEED + 5)
    version = "2.1.0+train.007"
    parameters = {n: tuple(t["values"]) for n, t in artifact["parameters"].items()}
    shapes = {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()}
    metadata = {"trainable_parameters": "head.presence.bias,head.presence.weight.000", "artifact_checksum": "0" * 64}
    snapshot = types.SimpleNamespace(model_id="synthetic-presence", version=version, parameters=parameters, shapes=shapes,
                                     metadata=metadata, cache_key="golden")
    runtime = types.SimpleNamespace(snapshot=snapshot, model=SparsePresenceModel(artifact["config"], parameters, shapes))
    rows = [{"text": t, "target": y, "weight": 1.0 + 0.25 * (i % 3), "group_id": f"g{i}"} for i, (t, y) in enumerate(PRESENCE_TRAIN)]
    heldout = [{"text": t, "target": y, "weight": 1.0, "group_id": f"h{i}"} for i, (t, y) in enumerate(PRESENCE_HELDOUT)]
    build_rows = lambda items: tuple(pt.PresenceTrainingExample(**item) for item in items)
    saved = pt.ModelParameterStreamer, pt.GLOBAL_STREAMED_MODEL_CACHE
    pt.ModelParameterStreamer = lambda model_id: types.SimpleNamespace(model_id=model_id)
    pt.GLOBAL_STREAMED_MODEL_CACHE = types.SimpleNamespace(presence_model_for_training=lambda streamer: runtime)
    try:
        batch = pt.compute_presence_gradients(build_rows(rows), model_id="synthetic-presence", learning_rate=0.8,
                                              max_gradient=0.05, heldout_examples=build_rows(heldout))
    finally:
        pt.ModelParameterStreamer, pt.GLOBAL_STREAMED_MODEL_CACHE = saved
    probabilities = [runtime.model.predict_probability(item["text"]) for item in rows + heldout]
    return {"artifact": artifact, "version": version, "examples": rows, "heldout": heldout, "learning_rate": 0.8, "max_gradient": 0.05,
            "probabilities": probabilities, "gradients": {n: bits(v) for n, v in sorted(batch.gradients.items())},
            "metrics": batch.metrics, "executions": [list(e) for e in batch.executions],
            "metadata": {k: batch.metadata[k] for k in ("release_version", "training_revision", "profile",
                         "base_parameter_fingerprint", "updated_parameter_fingerprint", "candidate_parameter_fingerprint",
                         "publication_delta_fingerprint")}}


def build() -> dict:
    bootstrap()
    import numpy as np
    import torch

    torch.set_num_threads(1)
    from src.LLM.privoke.training import _class_balanced_examples

    rows = make_examples()
    raw = build_examples(rows)
    balanced, _ = _class_balanced_examples(raw)
    models = {"legacy": make_artifact(None, SEED + 1), "task_query": make_artifact("residual_task_query_v1", SEED + 2)}
    cases = []
    for model_name, artifact in models.items():
        for name, objective in OBJECTIVES.items():
            use = raw if objective is None else balanced
            case = gradient_case(artifact, name, objective, use)
            case["model"] = model_name
            case["weights"] = [e.weight for e in use]
            cases.append(case)
    adam = adam_record(models["task_query"], rows)
    heldout_rows = make_heldout()
    rpc = []
    for model_name, artifact in models.items():
        for objective in (None, OBJECTIVES["mean_category"], OBJECTIVES["sum_margin"]):
            for full_encoder in (False, True):
                case = rpc_case(artifact, objective, full_encoder, rows, heldout_rows, 0.5, 0.05)
                case["model"] = model_name
                rpc.append(case)
    return {
        "meta": {"python": sys.version.split()[0], "numpy": np.__version__, "torch": torch.__version__,
                 "threads": torch.get_num_threads(), "seed": SEED, "tensor_encoding": "float32 bit patterns (uint32)"},
        "models": models, "examples": rows, "heldout": heldout_rows, "gradient_cases": cases, "adam": adam, "rpc_cases": rpc, "admission": admission_cases(), "presence": presence_record(),
    }


# --- the local-SGD, backtracking and diagnostics routes (RUST-S19C) -------------------------------------------------
LOCAL_OPTIMIZERS = ("local_sgd_1_v1", "local_sgd_4_v1")
LOCAL_OBJECTIVES = (None, OBJECTIVES["mean_category"], OBJECTIVES["decision_margin"], OBJECTIVES["class_balanced"])
PROCESS_OBJECTIVES = (None, OBJECTIVES["class_balanced"], OBJECTIVES["sum_margin"])
BACKTRACKING_RATES = (0.5, 0.0004, 1e-9, 1.7e308)
PREPARATION = {"schema": 1, "baseline_checksum": "1" * 64, "baseline_fingerprint": "2" * 64, "protocol_sha256": "3" * 64,
               "source_sha256": "4" * 64}


def preparation_text() -> str:
    return json.dumps(PREPARATION, sort_keys=True, separators=(",", ":"))


def auto_admission(objective, diagnostics: bool, sha) -> dict | None:
    """The header the client sends (`training_admission_metadata`): schema 1 for backtracking, schema 2 for summed margin."""
    from privoke_model import contextual_training as ct

    name = objective or ct.LEGACY_OBJECTIVE
    if sha is not None:
        return {"expected_objective": name, "expected_diagnostics_policy": ct.TRAIN_DIAGNOSTICS_POLICY,
                "expected_backtracking_policy": ct.BACKTRACKING_POLICY, "expected_backtracking_preparation_sha256": sha}
    if objective == ct.CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE:
        return {"expected_objective": name, "expected_diagnostics_policy": ct.TRAIN_DIAGNOSTICS_POLICY if diagnostics else None}
    return None


def envelope_case(artifact: dict, label: str, *, objective=None, extra=None, full_encoder: bool, rows, heldout_rows,
                  learning_rate: float = 0.5, max_gradient: float = 0.05, admission="auto", backtracking: bool = False,
                  optimizer=None, diagnostics: bool = False) -> dict:
    """Run `_compute_training_gradients` on a fake streamed snapshot with route metadata; record the outcome or the refusal."""
    import hashlib
    import types

    from privoke_model import contextual_training as ct
    from src.LLM.privoke import training
    from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel

    parameters = {name: tuple(t["values"]) for name, t in artifact["parameters"].items()}
    shapes = {name: tuple(t["shape"]) for name, t in artifact["parameters"].items()}
    metadata = {
        "model_config": json.dumps(artifact["config"]), "architecture": artifact["architecture"], "artifact_checksum": "0" * 64,
        "contextual_training_strategy": "contextual_full_encoder_sgd_v1",
        "trainable_parameters": ",".join(sorted(parameters)),
    }
    if objective is not None:
        metadata["contextual_training_objective"] = objective
    if optimizer is not None:
        metadata[ct.OPTIMIZER_KEY] = optimizer
    if diagnostics:
        metadata[ct.DIAGNOSTICS_POLICY_KEY] = ct.TRAIN_DIAGNOSTICS_POLICY
    sha = None
    if backtracking:
        text = preparation_text()
        metadata[ct.BACKTRACKING_KEY] = ct.BACKTRACKING_POLICY
        metadata[ct.BACKTRACKING_PREPARATION_KEY] = text
        metadata[ct.DIAGNOSTICS_POLICY_KEY] = ct.TRAIN_DIAGNOSTICS_POLICY
        sha = hashlib.sha256(text.encode()).hexdigest()
    metadata.update(extra or {})
    if admission == "auto":
        admission = auto_admission(objective, diagnostics or backtracking, sha)
    snapshot = types.SimpleNamespace(model_id=artifact["model_id"], version=artifact["version"], parameters=parameters,
                                     shapes=shapes, metadata=metadata, cache_key="golden", fingerprint="golden")
    runtime = StreamedTransformerPrivacyModel(snapshot)
    saved = training.ModelParameterStreamer, training.GLOBAL_STREAMED_MODEL_CACHE
    training.ModelParameterStreamer = lambda model_id: types.SimpleNamespace(model_id=model_id)
    training.GLOBAL_STREAMED_MODEL_CACHE = types.SimpleNamespace(model_for_training=lambda streamer: runtime)
    record = {"label": label, "full_encoder": full_encoder, "learning_rate": learning_rate, "max_gradient": max_gradient,
              "objective": objective, "optimizer": optimizer, "diagnostics": diagnostics, "backtracking": backtracking,
              "metadata": metadata, "admission": admission, "rows": len(rows)}
    try:
        batch = training._compute_training_gradients(
            build_examples(rows), model_id=artifact["model_id"], learning_rate=learning_rate, max_gradient=max_gradient,
            heldout_examples=build_examples(heldout_rows), full_encoder=full_encoder,
            **({"admission": admission} if admission is not None else {}))
    except Exception as exc:  # noqa: BLE001 - the refusal text is the recorded outcome
        record["refusal"] = str(exc)
        return record
    finally:
        training.ModelParameterStreamer, training.GLOBAL_STREAMED_MODEL_CACHE = saved
    record.update({
        "gradients": {n: bits(v) for n, v in sorted(batch.gradients.items())}, "metrics": batch.metrics,
        "executions": [list(item) for item in batch.executions], "error": batch.error, "metadata_out": batch.metadata,
        "scope": batch.metadata["training_scope"],
    })
    return record


def routes_build() -> dict:
    bootstrap()
    import numpy as np
    import torch

    torch.set_num_threads(1)
    from privoke_model import full_adam, sensitive_retention, window_training

    rows = make_examples()
    heldout_rows = make_heldout()
    models = {"legacy": make_artifact(None, SEED + 1), "task_query": make_artifact("residual_task_query_v1", SEED + 2)}
    cases = []

    def add(model, label, **fields):
        used = fields.pop("rows", rows)
        case = envelope_case(models[model], f"{model}/{label}", rows=used, heldout_rows=heldout_rows, **fields)
        case["model"] = model
        case["example_indices"] = [i for i, row in enumerate(rows) if any(row is item for item in used)]
        cases.append(case)

    # Explicit local-SGD optimizers: every objective twice, both scopes, both step budgets, both models.
    index = 0
    for model in models:
        for optimizer in LOCAL_OPTIMIZERS:
            for full_encoder in (False, True):
                objective = LOCAL_OBJECTIVES[index % len(LOCAL_OBJECTIVES)]
                rate = (0.5, 0.05)[(index // 2) % 2]
                scope = "full" if full_encoder else "heads"
                add(model, f"local-sgd/{optimizer}/{scope}/{(objective or 'legacy')[-24:]}", objective=objective,
                    optimizer=optimizer, full_encoder=full_encoder, learning_rate=rate)
                index += 1
    # TRAIN diagnostics: the legacy, class-balanced and summed-margin objectives, both scopes.
    for model in models:
        for objective in PROCESS_OBJECTIVES:
            for full_encoder in (False, True):
                add(model, f"diagnostics/{'full' if full_encoder else 'heads'}/{(objective or 'legacy')[-24:]}",
                    objective=objective, diagnostics=True, full_encoder=full_encoder, learning_rate=0.5 if full_encoder else 0.1)
    # FULL backtracking: the first scale, a later scale and the no-improvement rejection are looked for across the rates.
    for model in models:
        for objective in PROCESS_OBJECTIVES:
            for rate in BACKTRACKING_RATES:
                add(model, f"backtracking/{(objective or 'legacy')[-24:]}/{rate}", objective=objective, backtracking=True,
                    full_encoder=True, learning_rate=rate)
    # Refusals of the envelope, with the exact Python texts.
    mean = OBJECTIVES["mean_category"]
    summed = OBJECTIVES["sum_margin"]
    sensitive_only = [row for row in rows if row["sensitivity"] != "S0"]
    from privoke_model import contextual_training as ct

    def window_metadata():
        return {ct.OPTIMIZER_KEY: window_training.POLICY, ct.OBJECTIVE_KEY: window_training.OBJECTIVE,
                "contextual_candidate_eligibility": window_training.ELIGIBILITY,
                window_training.CONFIG_KEY: window_training.canonical(window_training.CONFIG),
                window_training.WINDOW_KEY: "a" * 64, window_training.REFERENCE_KEY: "b" * 64}

    def retention_metadata(policy):
        return {ct.OPTIMIZER_KEY: policy, ct.OBJECTIVE_KEY: sensitive_retention.OBJECTIVES[policy],
                "contextual_candidate_eligibility": sensitive_retention.ELIGIBILITY,
                full_adam.CONFIG_KEY: full_adam.canonical(full_adam.CONFIG), sensitive_retention.MANIFEST_KEY: "c" * 64}

    import hashlib

    sha = hashlib.sha256(preparation_text().encode()).hexdigest()
    base_admission = auto_admission(None, True, sha)
    add("legacy", "refusal/backtracking-admission-on-heads", backtracking=True, full_encoder=False)
    add("legacy", "refusal/backtracking-without-admission", backtracking=True, full_encoder=True, admission=None)
    add("legacy", "refusal/backtracking-wrong-preparation", backtracking=True, full_encoder=True,
        admission={**base_admission, "expected_backtracking_preparation_sha256": "0" * 64})
    add("legacy", "refusal/backtracking-admission-on-plain-artifact", full_encoder=True,
        admission={**base_admission})
    add("legacy", "refusal/objective-admission-differs", objective=mean, full_encoder=True,
        admission={"expected_objective": summed, "expected_diagnostics_policy": None})
    add("legacy", "refusal/diagnostics-admission-differs", objective=summed, full_encoder=True,
        admission={"expected_objective": summed, "expected_diagnostics_policy": ct.TRAIN_DIAGNOSTICS_POLICY})
    add("legacy", "refusal/summed-margin-without-admission", objective=summed, full_encoder=True, admission=None)
    add("legacy", "refusal/diagnostics-with-mean-objective", objective=mean, diagnostics=True, full_encoder=True)
    add("legacy", "refusal/diagnostics-with-local-sgd", optimizer="local_sgd_1_v1", diagnostics=True, full_encoder=True)
    add("legacy", "refusal/diagnostics-one-class", diagnostics=True, full_encoder=True, rows=sensitive_only)
    add("legacy", "refusal/summed-margin-with-local-sgd", objective=summed, optimizer="local_sgd_1_v1", full_encoder=True)
    add("legacy", "refusal/unsupported-optimizer", optimizer="local_sgd_9_v1", full_encoder=True)
    add("legacy", "refusal/unsupported-diagnostics-policy", full_encoder=True, extra={ct.DIAGNOSTICS_POLICY_KEY: "other_v1"})
    add("legacy", "refusal/backtracking-preparation-orphan", full_encoder=True,
        extra={ct.BACKTRACKING_PREPARATION_KEY: preparation_text()})
    add("legacy", "refusal/backtracking-with-optimizer", backtracking=True, optimizer="local_sgd_1_v1", full_encoder=True)
    add("legacy", "refusal/backtracking-bad-preparation", backtracking=True, full_encoder=True,
        extra={ct.BACKTRACKING_PREPARATION_KEY: "{}"})
    add("legacy", "refusal/window-without-admission", full_encoder=True, extra=window_metadata(), admission=None)
    add("legacy", "refusal/window-objective-admission", full_encoder=True, extra=window_metadata(),
        admission={"expected_objective": summed, "expected_diagnostics_policy": None})
    add("legacy", "refusal/window-bad-config", full_encoder=True,
        extra={**window_metadata(), window_training.CONFIG_KEY: "{}"}, admission=None)
    add("legacy", "refusal/window-orphan-pin", full_encoder=True, extra={window_training.WINDOW_KEY: "a" * 64})
    for policy in sorted(sensitive_retention.POLICIES):
        add("legacy", f"refusal/retention-objective-admission/{policy[-5:]}", full_encoder=True,
            extra=retention_metadata(policy), admission={"expected_objective": summed, "expected_diagnostics_policy": None})
        add("legacy", f"refusal/retention-without-admission/{policy[-5:]}", full_encoder=True,
            extra=retention_metadata(policy), admission=None)
    add("legacy", "refusal/retention-orphan-pin", full_encoder=True, extra={sensitive_retention.MANIFEST_KEY: "c" * 64})
    add("legacy", "refusal/full-adam-orphan-config", full_encoder=True, extra={full_adam.CONFIG_KEY: full_adam.canonical(full_adam.CONFIG)})
    return {
        "meta": {"python": sys.version.split()[0], "numpy": np.__version__, "torch": torch.__version__,
                 "threads": torch.get_num_threads(), "seed": SEED, "tensor_encoding": "float32 bit patterns (uint32)",
                 "preparation_sha256": sha},
        "models": models, "examples": rows, "heldout": heldout_rows, "cases": cases,
    }


def cmd_routes(_args) -> None:
    data = routes_build()
    ROUTES_FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    ROUTES_FIXTURE.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    served = [c for c in data["cases"] if "refusal" not in c]
    print(f"wrote {ROUTES_FIXTURE} ({ROUTES_FIXTURE.stat().st_size} bytes), {len(served)} served cases, "
          f"{len(data['cases']) - len(served)} refusals")


def cmd_synthetic(_args) -> None:
    data = build()
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {FIXTURE} ({FIXTURE.stat().st_size} bytes), {len(data['gradient_cases'])} gradient cases, "
          f"{len(data['adam']['steps'])} Adam steps")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["synthetic", "routes"])
    args = parser.parse_args(argv)
    {"synthetic": cmd_synthetic, "routes": cmd_routes}[args.command](args)


if __name__ == "__main__":
    main()
