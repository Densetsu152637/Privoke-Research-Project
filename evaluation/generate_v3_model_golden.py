"""Golden generator for the V3 model and microbatch loss gradient of the privoke-training crate (RUST-S19G, item 4b, checkpoint 2).

Runs the product's own forward and loss (``extension/client-runtime/src/v3/model.py`` ``PretrainedV3.forward`` and the loss of
``v3/training.py``) on seeded synthetic weights in float64: ``transformers.BertModel`` with its pooler over a PADDED batch with
an attention mask (as the product tokenizes), three affine heads on the pooled output, and
``(CE_sens_sum + CE_vis_sum + BCE_cat_sum / 10) / 64``. Records the pooled output, the logits, the loss and the gradient of
every parameter. The weights are float32 values (what a checkpoint holds) used in float64, so the Rust side builds the same
model from float32 tensors. Nothing touches a detector, the runtime pipeline or study data.

    <python with torch and transformers> evaluation/generate_v3_model_golden.py [--check]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import torch
from torch.nn import functional as F
from transformers import BertConfig, BertModel

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "rust" / "crates" / "privoke-training" / "tests" / "fixtures" / "v3_model_golden.json"
SEED = 20261123
WIDTHS = {"sensitivity": 4, "visibility": 6, "category": 10}
CASES = [
    {"name": "two_layers_two_heads", "hidden": 8, "heads": 2, "inner": 16, "layers": 2, "lengths": [4, 6, 3, 5]},
    {"name": "one_layer_three_heads", "hidden": 12, "heads": 3, "inner": 20, "layers": 1, "lengths": [2, 5]},
]
VOCAB, POSITIONS = 20, 16


def flat(tensor: torch.Tensor) -> list[float]:
    return [float(value) for value in tensor.detach().reshape(-1).tolist()]


def case(spec: dict) -> dict:
    torch.manual_seed(SEED + spec["hidden"])
    config = {
        "model_type": "bert", "hidden_act": "gelu", "hidden_size": spec["hidden"], "num_hidden_layers": spec["layers"],
        "num_attention_heads": spec["heads"], "intermediate_size": spec["inner"], "vocab_size": VOCAB,
        "max_position_embeddings": POSITIONS, "type_vocab_size": 2, "layer_norm_eps": 1e-12,
        "hidden_dropout_prob": 0.0, "attention_probs_dropout_prob": 0.0,
    }
    model = BertModel(BertConfig(**config, attn_implementation="eager"), add_pooling_layer=True).eval()
    heads = {}
    with torch.no_grad():
        for parameter in model.parameters():
            parameter.copy_(torch.randn_like(parameter) * 0.5)
        for name, parameter in model.named_parameters():
            if name.endswith("LayerNorm.weight"):
                parameter.copy_(1.0 + 0.3 * torch.randn_like(parameter))
        for task, width in WIDTHS.items():
            heads[task + "_weight"] = torch.randn(width, spec["hidden"]) * 0.6
            heads[task + "_bias"] = torch.randn(width) * 0.3
    # Checkpoint values are float32; the golden computes in float64 over exactly those values.
    model = model.double()
    heads = {name: value.float().double().requires_grad_(True) for name, value in heads.items()}
    lengths = spec["lengths"]
    longest = max(lengths)
    ids = torch.zeros(len(lengths), longest, dtype=torch.long)
    mask = torch.zeros(len(lengths), longest, dtype=torch.long)
    rows = []
    for index, length in enumerate(lengths):
        tokens = torch.randint(1, VOCAB, (length,))
        ids[index, :length] = tokens
        mask[index, :length] = 1
        categories = (torch.rand(10) < 0.3).double()
        rows.append({
            "ids": tokens.tolist(), "sensitivity": int(torch.randint(0, 4, ())), "visibility": int(torch.randint(0, 6, ())),
            "categories": flat(categories),
        })
    pooled = model(input_ids=ids, attention_mask=mask).pooler_output
    logits = {task: pooled @ heads[task + "_weight"].T + heads[task + "_bias"] for task in WIDTHS}
    s = torch.tensor([row["sensitivity"] for row in rows])
    v = torch.tensor([row["visibility"] for row in rows])
    c = torch.tensor([row["categories"] for row in rows], dtype=torch.float64)
    loss = (F.cross_entropy(logits["sensitivity"], s, reduction="sum") + F.cross_entropy(logits["visibility"], v, reduction="sum")
            + F.binary_cross_entropy_with_logits(logits["category"], c, reduction="sum") / WIDTHS["category"]) / 64
    loss.backward()
    tensors, grads = {}, {}
    for name, parameter in model.named_parameters():
        tensors["encoder." + name] = {"shape": list(parameter.shape), "data": flat(parameter)}
        grads["encoder." + name] = flat(parameter.grad)
    for name, value in heads.items():
        tensors["heads." + name] = {"shape": list(value.shape), "data": flat(value)}
        grads["heads." + name] = flat(value.grad)
    return {
        "name": spec["name"], "config": config, "tensors": tensors, "examples": rows, "scale": 64.0,
        "pooled": [flat(row) for row in pooled], "logits": {task: [flat(row) for row in value] for task, value in logits.items()},
        "loss": float(loss.detach()), "grads": grads,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = json.dumps({"seed": SEED, "torch": torch.__version__, "cases": [case(spec) for spec in CASES]}, separators=(",", ":")) + "\n"
    if args.check:
        same = FIXTURE.read_text(encoding="utf8") == text
        print("fixture is current" if same else "fixture differs")
        return 0 if same else 1
    FIXTURE.write_text(text, encoding="utf8", newline="\n")
    print(f"wrote {FIXTURE} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
