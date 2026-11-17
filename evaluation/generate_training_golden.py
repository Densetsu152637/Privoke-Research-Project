"""Golden generator for the privoke-training crate (RUST-S19, stage 19).

Runs the product's own Tiny training code on seeded synthetic models and records what the Rust port must reproduce:

* ``supervised_training.supervised_last_block_deltas`` (the gradient of every objective the Tiny paths use), and
* ``full_adam_training.fit`` (the FULL projected Adam fit, 64 fixed steps, float64 moments, one CPU thread).

Nothing here calls the runtime pipeline or a detector layer: the code under test is the semantic-layer training path
only, so no layer list is ever built (the project's LLM-layer isolation rule has nothing to select here).
Tensors are stored as float32 bit patterns (``uint32``), so the Rust side compares exactly what torch produced.

    python evaluation/generate_training_golden.py synthetic     # writes the committed fixture
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
        "models": models, "examples": rows, "heldout": heldout_rows, "gradient_cases": cases, "adam": adam, "rpc_cases": rpc,
    }


def cmd_synthetic(_args) -> None:
    data = build()
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {FIXTURE} ({FIXTURE.stat().st_size} bytes), {len(data['gradient_cases'])} gradient cases, "
          f"{len(data['adam']['steps'])} Adam steps")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["synthetic"])
    args = parser.parse_args(argv)
    cmd_synthetic(args)


if __name__ == "__main__":
    main()
