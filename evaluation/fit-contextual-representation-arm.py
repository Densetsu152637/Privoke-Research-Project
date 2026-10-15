"""Fit one offline contextual arm from explicit TRAIN and baseline inputs only."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import random
import sys

from host_environment import configure_imports
configure_imports()
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "extension/client-runtime"))
import numpy as np
import torch
from privoke_model.artifact import artifact_checksum, load_artifact, validate_artifact
from privoke_eval.in_house_transformer_training import ContextualTarget, InHouseTransformerTrainer, TrainingOptions
from src.detection.preprocessing import normalize_text
from src.model import ModelConfig, TinyTransformerModel


def permitted_path(value):
    path = Path(value).resolve()
    if any("final" in part.casefold() for part in path.parts):
        raise ValueError("Protected final paths are forbidden before file access.")
    return path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def fit(args):
    baseline_path, train_path = permitted_path(args.baseline), permitted_path(args.train)
    if train_path.name != "train.jsonl":
        raise ValueError("Offline fitter accepts the prepared contextual TRAIN file only.")
    baseline = load_artifact(baseline_path)
    rows = [json.loads(line) for line in train_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 672 or len({r["id"] for r in rows}) != 672 or any(r["metadata"]["label_status"] != "assistant_provisional" for r in rows):
        raise ValueError("Expected 672 unique assistant-provisional contextual TRAIN rows.")
    if not 0 <= args.seed < 2**32:
        raise ValueError("Seed requires uint32.")
    output = permitted_path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    torch.manual_seed(args.seed)
    arrays = {name: np.asarray(tensor["values"], dtype=np.float32).reshape(tensor["shape"]).copy() for name, tensor in baseline["parameters"].items()}
    trainer = InHouseTransformerTrainer(ModelConfig.from_mapping(baseline["config"]), arrays,
                                        TrainingOptions(mode=args.mode, learning_rate=.001, weight_decay=.0001, max_gradient_norm=1.0))
    order = list(range(len(rows)))
    random.Random(args.seed).shuffle(order)
    selected = [rows[index] for index in order[:640]]
    losses = []
    for step in range(20):
        batch = selected[step * 32:(step + 1) * 32]
        targets = [ContextualTarget(r["classification"]["sensitivity"], r["classification"]["visibility"], tuple(r["classification"]["categories"])) for r in batch]
        result = dict(trainer.step([r["text"] for r in batch], targets))
        record = {"step": step + 1, "row_ids": [r["id"] for r in batch], **result}
        write_json(output / f"step-{step+1:03d}.json", record)
        losses.append(result)
    exported = trainer.export_parameters()
    changed = {name: {"changed_values": int(np.count_nonzero(value != arrays[name])),
                      "maximum_absolute_delta": float(np.max(np.abs(value - arrays[name])))} for name, value in exported.items()}
    if args.mode == "head_only" and any(value["changed_values"] for name, value in changed.items() if not name.startswith("head.")):
        raise ValueError("Head-only fit changed encoder tensors.")
    if args.mode == "end_to_end" and not any(value["changed_values"] for name, value in changed.items() if not name.startswith("head.")):
        raise ValueError("End-to-end fit did not change encoder tensors.")
    candidate = copy.deepcopy(baseline)
    for name, value in exported.items():
        candidate["parameters"][name]["values"] = value.ravel().tolist()
    candidate["version"] = baseline["version"] + f"+offline.{args.mode}.{args.seed}"
    candidate.setdefault("metadata", {}).update({"offline_contextual_mode": args.mode, "offline_seed": str(args.seed),
                                                "label_status": "assistant_provisional", "publication_scope": "isolated research only"})
    candidate["checksum"] = artifact_checksum({k: v for k, v in candidate.items() if k != "checksum"})
    validate_artifact(candidate)
    # Compare autograd logits with independent NumPy serving inference, including
    # padding/truncation/normalization probes. No endpoint truth enters this check.
    runtime = TinyTransformerModel(trainer.config, {n: a.ravel() for n, a in exported.items()}, {n: a.shape for n, a in exported.items()}, device="cpu")
    probes = ["", "Synthetic fullwidth Ａｌｉｃｅ 🧪", "synthetic token " * 180, selected[0]["text"], selected[-1]["text"]]
    maximum_error = 0.0
    for text in probes:
        ids, mask = trainer.tensor_batch([text])
        logits = trainer.logits(ids, mask)
        prediction = runtime.predict(normalize_text(text))
        expected = (prediction.sensitivity_probabilities, prediction.visibility_probabilities, prediction.category_probabilities)
        actual = (torch.softmax(logits["sensitivity"], -1)[0], torch.softmax(logits["visibility"], -1)[0], torch.sigmoid(logits["category"])[0])
        for a, b in zip(actual, expected):
            error = float(np.max(np.abs(a.detach().numpy() - np.asarray(b))))
            maximum_error = max(maximum_error, error)
            if not np.allclose(a.detach().numpy(), b, atol=2e-5, rtol=2e-5):
                raise ValueError("Exported contextual model failed NumPy serving inference parity.")
    write_json(output / "artifact.json", candidate)
    torch.save(trainer.optimizer_state(), output / "optimizer-state.pt")
    receipt = {"mode": args.mode, "seed": args.seed, "baseline_sha256": sha(baseline_path), "train_sha256": sha(train_path),
               "artifact_sha256": sha(output / "artifact.json"), "optimizer_state_sha256": sha(output / "optimizer-state.pt"),
               "torch_version": torch.__version__, "numpy_version": np.__version__, "threads": 1, "deterministic_algorithms": True,
               "steps": 20, "batch_size": 32, "presentations": 640, "unique_rows": len({r["id"] for r in selected}),
               "unique_families": len({r["metadata"]["group_id"] for r in selected}),
               "schedule_sha256": hashlib.sha256(json.dumps([r["id"] for r in selected], separators=(",", ":")).encode()).hexdigest(),
               "changed_tensors": changed, "maximum_inference_parity_error": maximum_error,
               "label_status": "assistant_provisional", "partial_epoch": True, "optimizer": "Adam",
               "learning_rate": .001, "weight_decay": .0001, "max_gradient_norm": 1.0}
    write_json(output / "fit-receipt.json", receipt)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("head_only", "end_to_end"), required=True)
    parser.add_argument("--seed", type=int, required=True)
    fit(parser.parse_args())
