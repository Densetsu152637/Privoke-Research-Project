"""Golden generator for AdamW and clip_grad_norm_ of the privoke-training crate (RUST-S19H, V3 checkpoint 3).

Runs ``torch.nn.utils.clip_grad_norm_`` and ``torch.optim.AdamW`` (weight decay 0, two parameter groups with their own learning
rates, as ``extension/client-runtime/src/v3/training.py`` builds them) in float64 on seeded synthetic tensors and gradients.
No detector, pipeline or study data is involved.

    <python with torch> evaluation/generate_adamw_golden.py [--check]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "rust" / "crates" / "privoke-training" / "tests" / "fixtures" / "adamw_golden.json"
SEED = 20261123
STEPS = 8


def flat(tensor: torch.Tensor) -> list[float]:
    return [float(v) for v in tensor.detach().reshape(-1).tolist()]


def case(name: str, betas, eps, rates, clip_norm, scale) -> dict:
    torch.manual_seed(SEED)
    shapes = [(4, 3), (4,), (5, 3), (5,)]
    groups = [[0, 1], [2, 3]]
    params = [torch.nn.Parameter(torch.randn(shape, dtype=torch.float64)) for shape in shapes]
    initial = [flat(p) for p in params]
    optimizer = torch.optim.AdamW(
        [{"params": [params[i] for i in group], "lr": rate} for group, rate in zip(groups, rates)],
        betas=betas, eps=eps, weight_decay=0.0)
    steps = []
    for step in range(STEPS):
        grads = [torch.randn(shape, dtype=torch.float64) * scale * (1 + step) for shape in shapes]
        for p, g in zip(params, grads):
            p.grad = g.clone()
        norm = torch.nn.utils.clip_grad_norm_(params, clip_norm, error_if_nonfinite=True)
        clipped = [flat(p.grad) for p in params]
        optimizer.step()
        steps.append({"grads": [flat(g) for g in grads], "norm": float(norm), "clipped": clipped, "params": [flat(p) for p in params]})
    return {"name": name, "betas": list(betas), "eps": eps, "rates": rates, "groups": groups, "clip_norm": clip_norm,
            "shapes": [list(s) for s in shapes], "initial": initial, "steps": steps}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    cases = [
        case("clipping_every_step", (0.9, 0.999), 1e-8, [1e-2, 1e-3], 0.5, 0.2),
        case("clipping_some_steps", (0.8, 0.95), 1e-6, [3e-3, 3e-2], 6.0, 0.4),
    ]
    text = json.dumps({"seed": SEED, "torch": torch.__version__, "cases": cases}, separators=(",", ":")) + "\n"
    if args.check:
        same = FIXTURE.read_text(encoding="utf8") == text
        print("fixture is current" if same else "fixture differs")
        return 0 if same else 1
    FIXTURE.write_text(text, encoding="utf8", newline="\n")
    print(f"wrote {FIXTURE} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
