"""Local-only golden for the Rust window loop (RUST-S19D, stage 19 item 3).

Runs the unchanged Python ``window_training.compute`` (the cold local Adam with TRAIN-only exact checkpoint selection of
``LLM/privoke/window_training.py``) on a real, locally held window release and records what the Rust port must reproduce:

* the retained trace (``train_window_trace_v1``), the summary and the metrics,
* the selected transported update (float32 raw),
* every direction the loop used (64 steps, the main sum-margin direction then the component-hinge direction, float32 raw),
  so that the Rust Adam recurrence, the checkpoint scoring and the selection can be replayed from Python's own gradients.

The release is study data (it contains prompt text) and is read only from the local models directory; the golden is
written to an ignored directory (``evaluation/results/`` is git-ignored) and is never committed. Nothing here builds a
detector layer selection: the code under test is the semantic training path only.

    python evaluation/generate_window_golden.py write [--release DIR] [--out DIR]

The default release is ``models/experiments/task_query_window_20261012/releases/host-v2/v1/42`` of the main checkout
(``--release`` or ``PRIVOKE_WINDOW_RELEASE``), the default output ``evaluation/results/window-golden-20261122``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import types
from pathlib import Path

# FULL Adam requires startup OMP/MKL threads of one; set before torch is imported.
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO / "evaluation" / "results" / "window-golden-20261122"
DEFAULT_RELEASE = Path("D:/Git Repositories/Privoke-Research-Project/models/experiments/task_query_window_20261012/releases/host-v2/v1/42")
FILES = {"bank": "bank.json", "references": "references-v2.json", "manifest": "component-manifest-v2.json",
         "teacher": "original.json", "window": "window.json"}


def bootstrap() -> None:
    extra = [Path(os.environ["PRIVOKE_GENERATED"])] if os.environ.get("PRIVOKE_GENERATED") else []
    for path in (REPO / "extension" / "client-runtime", REPO / "shared" / "python", REPO / "evaluation",
                 REPO / "extension" / "client-runtime" / "generated", *extra):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def f32_bytes(values) -> bytes:
    import numpy as np

    return np.asarray([float(v) for v in values], dtype="<f4").tobytes()


def build(release: Path, out: Path) -> dict:
    bootstrap()
    import torch

    torch.set_num_threads(1)
    from privoke_contracts.classification import Classification
    from privoke_model import contextual_training as ct
    from privoke_model import full_adam
    from privoke_model import window_training as contract
    from src.LLM.privoke import streamed_model, parameter_stream, supervised_training, window_training
    from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel
    from src.LLM.privoke.training import SemanticTrainingExample

    paths = {key: release / name for key, name in FILES.items()}
    pins = {key: sha256_file(path) for key, path in paths.items()}
    os.environ.update({
        "PRIVOKE_WINDOW_PATH": str(paths["window"]), "PRIVOKE_WINDOW_MANIFEST_SHA256": pins["window"],
        "PRIVOKE_COMPONENT_BANK_PATH": str(paths["bank"]), "PRIVOKE_COMPONENT_REFERENCE_PATH": str(paths["references"]),
        "PRIVOKE_COMPONENT_MANIFEST_PATH": str(paths["manifest"]), "PRIVOKE_COMPONENT_TEACHER_PATH": str(paths["teacher"]),
        "PRIVOKE_COMPONENT_MANIFEST_SHA256": pins["manifest"], "PRIVOKE_COMPONENT_TEACHER_SHA256": pins["teacher"]})
    artifact = json.loads(paths["teacher"].read_text(encoding="utf-8"))
    window = json.loads(paths["window"].read_text(encoding="utf-8"))
    parameters = {n: tuple(t["values"]) for n, t in artifact["parameters"].items()}
    shapes = {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()}
    names = sorted(parameters)
    metadata = {
        "model_config": json.dumps(artifact["config"]), "architecture": artifact["architecture"], "artifact_checksum": "0" * 64,
        ct.STRATEGY_KEY: ct.FULL_ENCODER_STRATEGY, "trainable_parameters": ",".join(names),
        ct.OBJECTIVE_KEY: full_adam.OBJECTIVE, ct.OPTIMIZER_KEY: contract.POLICY,
        "contextual_candidate_eligibility": contract.ELIGIBILITY,
        contract.CONFIG_KEY: contract.canonical(contract.CONFIG), contract.WINDOW_KEY: pins["window"],
        contract.REFERENCE_KEY: pins["manifest"]}
    admission = contract.expectations({
        "expected_contextual_training_optimizer": contract.POLICY, "expected_contextual_training_objective": full_adam.OBJECTIVE,
        "expected_contextual_candidate_eligibility": contract.ELIGIBILITY, "expected_contextual_training_scope": "full_encoder",
        "expected_" + contract.CONFIG_KEY: contract.canonical(contract.CONFIG),
        "expected_" + contract.WINDOW_KEY: pins["window"], "expected_" + contract.REFERENCE_KEY: pins["manifest"]})
    snapshot = types.SimpleNamespace(model_id=artifact["model_id"], version=artifact["version"], parameters=parameters, shapes=shapes,
                                     metadata=metadata, cache_key="golden", fingerprint="golden")
    runtime = StreamedTransformerPrivacyModel(snapshot)
    rows = [row for block in window["blocks"] for row in block["rows"]]
    build_rows = lambda items: tuple(SemanticTrainingExample(r["text"], Classification(r["packed"]), r["weight"]) for r in items)

    recorded: list[tuple[str, bytes]] = []
    original = supervised_training.supervised_last_block_deltas

    def recording(*args, **kwargs):
        direction, loss = original(*args, **kwargs)
        kind = "auxiliary" if kwargs.get("retention_components") is not None else "main"
        recorded.append((kind, b"".join(f32_bytes(direction[n]) for n in names)))
        return direction, loss

    saved = (streamed_model.GLOBAL_STREAMED_MODEL_CACHE, parameter_stream.ModelParameterStreamer)
    streamed_model.GLOBAL_STREAMED_MODEL_CACHE = types.SimpleNamespace(model_for_training=lambda streamer: runtime)
    parameter_stream.ModelParameterStreamer = lambda model_id: types.SimpleNamespace(model_id=model_id)
    supervised_training.supervised_last_block_deltas = recording
    try:
        batch = window_training.compute(build_rows(rows), model_id=artifact["model_id"], learning_rate=.003, max_gradient=.05,
                                        heldout_examples=build_rows(window["guard"]), admission=admission)
    finally:
        supervised_training.supervised_last_block_deltas = original
        streamed_model.GLOBAL_STREAMED_MODEL_CACHE, parameter_stream.ModelParameterStreamer = saved
    kinds = [kind for kind, _ in recorded]
    if kinds != ["main", "auxiliary"] * 64:
        raise SystemExit(f"unexpected direction calls: {kinds[:6]}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "directions.f32").write_bytes(b"".join(blob for _, blob in recorded))
    gradient_bytes = b"".join(f32_bytes(batch.gradients[n]) for n in names if n in batch.gradients)
    (out / "gradients.f32").write_bytes(gradient_bytes)
    trace_text = batch.metadata[contract.TRACE_KEY]
    (out / "trace.json").write_text(trace_text, encoding="utf-8", newline="\n")
    meta = {
        "python": sys.version.split()[0], "torch": torch.__version__, "threads": torch.get_num_threads(), "pins": pins,
        "names": names, "sizes": [len(parameters[n]) for n in names], "gradient_names": [n for n in names if n in batch.gradients],
        "schedule": list(contract.schedule(window["seed"])), "status": json.loads(trace_text)["status"],
        "reason": json.loads(trace_text)["reason"], "selected_step": json.loads(trace_text)["selected_step"],
        "summary": batch.metadata[contract.SUMMARY_KEY], "metrics": batch.metrics,
        "executions": [list(item) for item in batch.executions], "update_fingerprint": batch.metadata["updated_parameter_fingerprint"],
        "references": len([1 for r in json.loads(paths["references"].read_text(encoding="utf-8"))["rows"] if r["components"]]),
    }
    (out / "meta.json").write_text(json.dumps(meta, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    return meta


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["write"])
    parser.add_argument("--release", default=os.environ.get("PRIVOKE_WINDOW_RELEASE", str(DEFAULT_RELEASE)))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)
    meta = build(Path(args.release), Path(args.out))
    print(f"wrote {args.out}: status {meta['status']}/{meta['reason']}, selected step {meta['selected_step']}, "
          f"{meta['references']} references")


if __name__ == "__main__":
    main()
