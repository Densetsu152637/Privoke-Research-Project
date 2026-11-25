"""Golden generator for the V3 fit of the privoke-training crate (RUST-S19H, V3 checkpoint 4).

Runs the product's own ``src.v3.training.fit`` (``extension/client-runtime/src/v3/training.py``: AdamW over microbatches, clip,
guard assessment, evidence) on a V3 package, once per scope (HEADS and FULL_ENCODER), with the pilot policy (two steps over one
block of 64 rows and a guard of 16 rows), and records the rows, the evidence and the candidate checkpoint.

    <python with torch and transformers> evaluation/generate_v3_fit_golden.py synthetic
        the committed synthetic package of the semantic crate (tests/fixtures/v3_synthetic): writes
        rust/crates/privoke-training/tests/fixtures/v3_fit/ (committed)
    <python ...> evaluation/generate_v3_fit_golden.py real PACKAGE_DIR VOCAB OUT_DIR
        a real local V3 package directory (config.json and model.safetensors; vocab.txt given): writes OUT_DIR (git-ignored)

Rows are deterministic synthetic prompts (no study data). The product's ``validate_execution`` pins the admitted tiers'
parameter counts, so the synthetic run replaces it by the identity (the real run keeps it). Nothing builds a detector layer list:
the request is the semantic-only fit (layers [4]).
"""
from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path
from types import SimpleNamespace

os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "shared/python"), str(REPO / "extension/client-runtime")]

import torch  # noqa: E402
from safetensors.torch import load_file  # noqa: E402

from privoke_contracts.classification import Category, Sensitivity, Visibility, initialise_unpacked  # noqa: E402
from privoke_model.v3_contract import POLICY  # noqa: E402
from src.v3 import training  # noqa: E402
from src.v3.model import PretrainedV3  # noqa: E402
from src.v3.training import assess, fit  # noqa: E402

SEED = 20261123
SYNTHETIC = REPO / "rust" / "crates" / "privoke-semantic" / "tests" / "fixtures" / "v3_synthetic"
OUTPUT = REPO / "rust" / "crates" / "privoke-training" / "tests" / "fixtures" / "v3_fit"
WORDS = ["account", "medical", "address", "salary", "password", "school", "family", "travel", "invoice", "weather", "recipe", "court"]
SENSITIVITIES = [Sensitivity.S0, Sensitivity.S1, Sensitivity.S2, Sensitivity.S3]
VISIBILITIES = [Visibility.P0, Visibility.P1, Visibility.P2, Visibility.P3, Visibility.P4, Visibility.PU]


def pilot_policy() -> dict:
    return dict(POLICY, steps=2, window_batches=1, epochs=2)


def make_rows(rng: random.Random, count: int, tag: str) -> list:
    rows = []
    for index in range(count):
        text = f"{rng.choice(WORDS)} {rng.choice(WORDS)} note {tag}{index} about {rng.choice(WORDS)}"
        categories = [category for category in Category if rng.random() < 0.2]
        value = initialise_unpacked(rng.choice(SENSITIVITIES), rng.choice(VISIBILITIES), categories)
        rows.append({"text": text, "packed": value.pack()})
    return rows


def wire(row: dict) -> SimpleNamespace:
    from privoke_contracts.classification import Classification
    value = Classification(row["packed"])
    target = SimpleNamespace(**value.to_dict(), packed=value.pack())
    message = SimpleNamespace(text=row["text"], has_target=True, weight=1.0, target=target)
    message.SerializeToString = lambda deterministic=True, _row=row: json.dumps(_row, sort_keys=True).encode()
    return message


def load_model(directory: Path, vocab: Path):
    config = json.loads((directory / "config.json").read_text())
    state = load_file(str(directory / "model.safetensors"), device="cpu")
    encoder = {k.removeprefix("encoder."): v for k, v in state.items() if k.startswith("encoder.")}
    heads = {k.removeprefix("heads."): v for k, v in state.items() if k.startswith("heads.")}
    return PretrainedV3(config, encoder, vocab, heads=heads)


def run(directory: Path, vocab: Path, out: Path, model_id: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    train, guard = make_rows(rng, 64, "t"), make_rows(rng, 16, "g")
    policy = pilot_policy()
    result = {"seed": SEED, "torch": torch.__version__, "model_id": model_id, "policy": policy, "train": train, "guard": guard, "scopes": {}}
    for scope, number in (("heads", 1), ("full_encoder", 2)):
        torch.manual_seed(SEED)
        model = load_model(directory, vocab)
        request = SimpleNamespace(
            request_id="golden-" + scope, model_id=model_id, base="1" * 64, scope=number, layers=[4], source_commitment="2" * 64,
            train=[wire(r) for r in train], guard=[wire(r) for r in guard])
        evidence = fit(model, request, policy)
        model.export(out / (scope + ".safetensors"))
        result["scopes"][scope] = evidence
    (out / "golden.json").write_text(json.dumps(result, separators=(",", ":")) + "\n", encoding="utf8", newline="\n")
    print("wrote", out)


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "synthetic":
        # The tier and parameter-count pins describe the admitted real tiers; the synthetic package is not one of them.
        training.validate_execution = lambda evidence, finalized=True: evidence
        run(SYNTHETIC, SYNTHETIC / "vocab.txt", OUTPUT, "privoke-v3-efficient")
        return 0
    if mode == "real" and len(sys.argv) == 5:
        run(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), "privoke-v3-efficient")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
