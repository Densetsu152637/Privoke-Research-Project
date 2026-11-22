"""Golden generator for the BERT encoder-layer backward of the privoke-training crate (RUST-S19G, stage 19 item 4b).

Runs ``transformers.BertModel``'s own encoder layers (the module the V3 model of ``extension/client-runtime/src/v3/model.py``
wraps) in float64 on seeded synthetic weights and records what the Rust kernels must reproduce: the layer outputs and the
gradient of the input and of every layer parameter for the loss ``sum(w * last_hidden_state)``. Nothing here touches a
detector, the runtime pipeline or study data; the code under test is the semantic encoder only.

    <python with torch and transformers> evaluation/generate_bert_layer_golden.py     # writes the committed fixture

The fixture is synthetic (seeded random weights), so it is committed. ``--check`` regenerates it and compares.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch
from transformers import BertConfig, BertModel

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "rust" / "crates" / "privoke-training" / "tests" / "fixtures" / "bert_layer_golden.json"
SEED = 20261122
CASES = [
    {"name": "two_layers_two_heads", "hidden": 8, "heads": 2, "inner": 16, "layers": 2, "rows": 5},
    {"name": "one_layer_three_heads", "hidden": 12, "heads": 3, "inner": 20, "layers": 1, "rows": 3},
]
PARTS = [
    ("query", "attention.self.query"),
    ("key", "attention.self.key"),
    ("value", "attention.self.value"),
    ("attention_output", "attention.output.dense"),
    ("intermediate", "intermediate.dense"),
    ("output", "output.dense"),
]
NORMS = [("attention_norm", "attention.output.LayerNorm"), ("output_norm", "output.LayerNorm")]


def flat(tensor: torch.Tensor) -> list[float]:
    return [float(value) for value in tensor.detach().reshape(-1).tolist()]


def named(layer: torch.nn.Module, path: str) -> torch.nn.Module:
    module = layer
    for part in path.split("."):
        module = getattr(module, part)
    return module


def case(spec: dict) -> dict:
    torch.manual_seed(SEED + spec["hidden"])
    config = BertConfig(
        hidden_size=spec["hidden"], num_hidden_layers=spec["layers"], num_attention_heads=spec["heads"],
        intermediate_size=spec["inner"], vocab_size=10, max_position_embeddings=16, type_vocab_size=2,
        hidden_dropout_prob=0.0, attention_probs_dropout_prob=0.0, layer_norm_eps=1e-12,
        attn_implementation="eager",
    )
    model = BertModel(config, add_pooling_layer=True).double().eval()
    with torch.no_grad():
        for parameter in model.parameters():
            parameter.copy_(torch.randn_like(parameter) * 0.6)
        for layer in model.encoder.layer:
            for _, path in NORMS:
                norm = named(layer, path)
                norm.weight.copy_(1.0 + 0.3 * torch.randn_like(norm.weight))
    x = (torch.randn(1, spec["rows"], spec["hidden"], dtype=torch.float64) * 1.5).requires_grad_(True)
    weights = torch.randn(1, spec["rows"], spec["hidden"], dtype=torch.float64)
    current = x
    for layer in model.encoder.layer:
        current = layer(current)[0]
    loss = (weights * current).sum()
    loss.backward()
    layers = []
    for layer in model.encoder.layer:
        record = {}
        for key, path in PARTS:
            module = named(layer, path)
            record[key] = {
                "weight": flat(module.weight), "bias": flat(module.bias),
                "weight_grad": flat(module.weight.grad), "bias_grad": flat(module.bias.grad),
            }
        for key, path in NORMS:
            module = named(layer, path)
            record[key] = {
                "gamma": flat(module.weight), "beta": flat(module.bias),
                "gamma_grad": flat(module.weight.grad), "beta_grad": flat(module.bias.grad),
            }
        layers.append(record)
    return {
        **spec, "eps": 1e-12, "x": flat(x), "loss_weights": flat(weights), "output": flat(current), "loss": float(loss.detach()),
        "x_grad": flat(x.grad), "layer_params": layers,
    }


def build() -> dict:
    return {"seed": SEED, "torch": torch.__version__, "cases": [case(spec) for spec in CASES]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="compare a regeneration with the committed fixture")
    args = parser.parse_args()
    text = json.dumps(build(), separators=(",", ":")) + "\n"
    if args.check:
        same = FIXTURE.read_text(encoding="utf8") == text
        print("fixture is current" if same else "fixture differs")
        return 0 if same else 1
    FIXTURE.write_text(text, encoding="utf8", newline="\n")
    print(f"wrote {FIXTURE} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
