"""Local-only golden for the Rust ORIGINAL-retention loops (RUST-S19F, stage 19 item 3).

Runs the unchanged Python retention route of ``training._compute_training_gradients`` (``sensitive_retention_training``,
the retention hinge of ``supervised_training`` and the fixed FULL Adam) for both policies, gate and hinge, on the real
balanced release held locally, and records what the Rust port must reproduce:

* the retained trace (``original_train_retention_trace_v1``), the metadata, the metrics and the executions,
* the transported update (float32 raw),
* every direction the fit used (64 steps: the main sum-margin direction, then for the hinge policy the hinge direction,
  float32 raw), so the Rust recurrence, safety audit and trace can be replayed from Python's own gradients.

The release is study data (the bank holds prompt text); it is read only from the local results directory and the golden is
written to an ignored directory (``evaluation/results/`` is git-ignored). It is never committed. Nothing here builds a
detector layer selection: the code under test is the semantic training path only.

    python evaluation/generate_retention_golden.py write [--root DIR] [--out DIR]

The main 64 rows and the 16 guard rows are the first block and the guard of the window release of the main checkout (the
retention contract fixes 64 and 16 rows; the rows themselves are not part of the release).
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
MAIN = Path("D:/Git Repositories/Privoke-Research-Project")
DEFAULT_ROOT = MAIN / "evaluation" / "results" / "iterative_fuzzer_20261011"
DEFAULT_OUT = REPO / "evaluation" / "results" / "retention-golden-20261122"
WINDOW = MAIN / "models" / "experiments" / "task_query_window_20261012" / "releases" / "host-v2" / "v1" / "42" / "window.json"


def release_paths(root: Path) -> dict[str, Path]:
    references = root / "sensitive-retention-pilot" / "execution" / "references" / "balanced"
    return {"bank": root / "train-sensitive-retention" / "approved-train-bank.json",
            "references": references / "references.json", "manifest": references / "manifest.json",
            "teacher": root / "block01" / "balanced" / "catalog" / "privoke-balanced.json"}


def bootstrap() -> None:
    extra = [Path(os.environ["PRIVOKE_GENERATED"])] if os.environ.get("PRIVOKE_GENERATED") else []
    for path in (REPO / "extension" / "client-runtime", REPO / "shared" / "python", REPO / "evaluation",
                 REPO / "extension" / "client-runtime" / "generated", *extra):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def f32_bytes(values) -> bytes:
    import numpy as np

    return np.asarray([float(v) for v in values], dtype="<f4").tobytes()


def run_policy(policy: str, paths: dict[str, Path], out: Path) -> dict:
    import torch

    torch.set_num_threads(1)
    from privoke_contracts.classification import Classification
    from privoke_model import contextual_training as ct
    from privoke_model import full_adam
    from privoke_model import sensitive_retention as contract
    from privoke_model.artifact import float32
    from src.LLM.privoke import parameter_stream, streamed_model, supervised_training, training
    from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel
    from src.LLM.privoke.training import SemanticTrainingExample

    pin = hashlib.sha256(paths["manifest"].read_bytes()).hexdigest()
    os.environ.update({"PRIVOKE_RETENTION_MANIFEST_SHA256": pin, "PRIVOKE_RETENTION_BANK_PATH": str(paths["bank"]),
                       "PRIVOKE_RETENTION_REFERENCE_PATH": str(paths["references"]),
                       "PRIVOKE_RETENTION_MANIFEST_PATH": str(paths["manifest"]),
                       "PRIVOKE_RETENTION_TEACHER_PATH": str(paths["teacher"])})
    artifact = json.loads(paths["teacher"].read_text(encoding="utf-8"))
    window = json.loads(WINDOW.read_text(encoding="utf-8"))
    parameters = {n: tuple(float32(v) for v in t["values"]) for n, t in artifact["parameters"].items()}
    shapes = {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()}
    names = sorted(parameters)
    objective = contract.OBJECTIVES[policy]
    metadata = {
        "model_config": json.dumps(artifact["config"]), "architecture": artifact["architecture"],
        "artifact_checksum": artifact["checksum"], ct.STRATEGY_KEY: ct.FULL_ENCODER_STRATEGY,
        "trainable_parameters": ",".join(names), ct.OBJECTIVE_KEY: objective, ct.OPTIMIZER_KEY: policy,
        contract.ELIGIBILITY_KEY: contract.ELIGIBILITY, contract.CONFIG_KEY: contract.canonical(contract.CONFIG),
        contract.MANIFEST_KEY: pin}
    checked = contract.expectations({
        "expected_contextual_training_optimizer": policy, "expected_contextual_candidate_eligibility": contract.ELIGIBILITY,
        "expected_full_projected_adam_config_v1": contract.canonical(contract.CONFIG),
        "expected_contextual_training_scope": "full_encoder", "expected_contextual_training_objective": objective,
        "expected_original_train_retention_manifest_sha256": pin})
    admission = {"expected_objective": objective, "expected_diagnostics_policy": None, **checked}
    snapshot = types.SimpleNamespace(model_id=artifact["model_id"], version=artifact["version"], parameters=parameters,
                                     shapes=shapes, metadata=metadata, cache_key="golden", fingerprint="golden")
    runtime = StreamedTransformerPrivacyModel(snapshot)
    main_rows = window["blocks"][0]["rows"]
    guard_rows = window["guard"]
    build = lambda rows: tuple(SemanticTrainingExample(r["text"], Classification(r["packed"]), r["weight"]) for r in rows)

    recorded: list[tuple[str, bytes]] = []
    original = supervised_training.supervised_last_block_deltas

    def recording(*args, **kwargs):
        direction, loss = original(*args, **kwargs)
        kind = "auxiliary" if kwargs.get("retention_margins") is not None else "main"
        recorded.append((kind, b"".join(f32_bytes(direction[n]) for n in names)))
        return direction, loss

    saved = (training.ModelParameterStreamer, training.GLOBAL_STREAMED_MODEL_CACHE)
    training.ModelParameterStreamer = lambda model_id: types.SimpleNamespace(model_id=model_id)
    training.GLOBAL_STREAMED_MODEL_CACHE = types.SimpleNamespace(model_for_training=lambda streamer: runtime)
    supervised_training.supervised_last_block_deltas = recording
    try:
        batch = training._compute_training_gradients(
            build(main_rows), model_id=artifact["model_id"], learning_rate=full_adam.CONFIG["eta"],
            max_gradient=full_adam.CONFIG["delta_cap"], heldout_examples=build(guard_rows), full_encoder=True, admission=admission)
    finally:
        supervised_training.supervised_last_block_deltas = original
        training.ModelParameterStreamer, training.GLOBAL_STREAMED_MODEL_CACHE = saved
    expected = ["main", "auxiliary"] * 64 if policy == contract.HINGE_POLICY else ["main"] * 64
    if [kind for kind, _ in recorded] != expected:
        raise SystemExit(f"unexpected direction calls: {[k for k, _ in recorded][:6]}")
    out.mkdir(parents=True, exist_ok=True)
    wire = lambda rows: [{"text": r["text"], "packed": r["packed"], "weight": r["weight"]} for r in rows]
    (out / "rows.json").write_text(json.dumps({"main": wire(main_rows), "guard": wire(guard_rows)}, separators=(",", ":")) + "\n",
                                   encoding="utf-8", newline="\n")
    directory = out / ("hinge" if policy == contract.HINGE_POLICY else "gate")
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "directions.f32").write_bytes(b"".join(blob for _, blob in recorded))
    (directory / "gradients.f32").write_bytes(b"".join(f32_bytes(batch.gradients[n]) for n in names if n in batch.gradients))
    trace_text = batch.metadata[contract.TRACE_KEY]
    (directory / "trace.json").write_text(trace_text, encoding="utf-8", newline="\n")
    meta = {"policy": policy, "pin": pin, "names": names, "sizes": [len(parameters[n]) for n in names],
            "gradient_names": [n for n in names if n in batch.gradients], "metrics": batch.metrics,
            "metadata": {k: v for k, v in batch.metadata.items() if k != contract.TRACE_KEY},
            "executions": [list(item) for item in batch.executions], "error": batch.error,
            "python": sys.version.split()[0], "torch": torch.__version__, "main_rows": len(main_rows), "guard_rows": len(guard_rows)}
    (directory / "meta.json").write_text(json.dumps(meta, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    return meta


def build(root: Path, out: Path) -> dict:
    bootstrap()
    from privoke_model import sensitive_retention as contract

    paths = release_paths(root)
    return {policy: run_policy(policy, paths, out) for policy in (contract.GATE_POLICY, contract.HINGE_POLICY)}


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["write"])
    parser.add_argument("--root", default=str(DEFAULT_ROOT))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)
    result = build(Path(args.root), Path(args.out))
    for policy, meta in result.items():
        print(f"{policy}: {len(meta['executions'])} executions, error {meta['error']!r}, {len(meta['gradient_names'])} tensors")


if __name__ == "__main__":
    main()
