"""Prepare intact official encoder/pooler bytes plus explicit zero task heads."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "shared/python"), str(ROOT / "extension/client-runtime")]
from privoke_model.v3_contract import ARCHITECTURE, TIERS, canonical, digest, validate_manifest

WEIGHT_PINS = {"efficient": "2e37a60f99c30c244da3a2ada3653faf378689783c5b6500d7291acc2516e199", "balanced": "67b710645b099510dba08b7605a60859fff59714628e1d9d1ffa9e0956b51783", "quality": "1be1c8c6a57894a139fdf526fb8435f6acb6ea01600569a4ac3cfd405dc5f875"}
EXCLUDED = {"cls.predictions.bias", "cls.predictions.transform.dense.weight", "cls.predictions.transform.dense.bias", "cls.predictions.transform.LayerNorm.weight", "cls.predictions.transform.LayerNorm.bias", "cls.predictions.decoder.weight", "cls.predictions.decoder.bias", "cls.seq_relationship.weight", "cls.seq_relationship.bias"}

def prepare(upstream, output, tier):
    import torch
    from src.v3.model import PretrainedV3, tensor_hash
    spec = TIERS[tier]
    source = json.loads((upstream / "source.json").read_text())
    if any(source.get(k) != v for k, v in (("tier", tier), ("repository", spec["repository"]), ("revision", spec["revision"]), ("license", "apache-2.0"))):
        raise ValueError("Official source identity/license mismatch.")
    files = {f["file"]: f for f in source["files"]}
    for name, info in files.items():
        path = upstream / name
        if name != Path(name).name or path.is_symlink() or path.stat().st_size != info["bytes"] or digest(path.read_bytes()) != info["sha256"]:
            raise ValueError("Source inventory bytes/hash mismatch.")
        if info["url"] != f"https://huggingface.co/{spec['repository']}/resolve/{spec['revision']}/{name}":
            raise ValueError("Source URL is not the pinned official revision.")
    if files["pytorch_model.bin"]["sha256"] != WEIGHT_PINS[tier]:
        raise ValueError("Source weights differ from independently pinned official bytes.")
    raw = torch.load(upstream / "pytorch_model.bin", map_location="cpu", weights_only=True)
    encoder = {k.removeprefix("bert."): v for k, v in raw.items() if k.startswith("bert.")}
    if set(raw) - {"bert." + k for k in encoder} != EXCLUDED:
        raise ValueError("Only the nine explicitly excluded pretrained MLM/NSP entries may be omitted.")
    config = json.loads((upstream / "config.json").read_text())
    for key in ("hidden_size", "num_hidden_layers", "num_attention_heads"):
        if config[key] != spec[key]: raise ValueError("Native tier/config mismatch.")
    if config["vocab_size"] != 30522 or config["max_position_embeddings"] != 512:
        raise ValueError("Native vocabulary/context mismatch.")
    before_rng = torch.get_rng_state().clone()
    model = PretrainedV3(config, encoder, upstream / "vocab.txt")
    if not torch.equal(before_rng, torch.get_rng_state()):
        raise ValueError("Preparation unexpectedly consumed initialization randomness.")
    for name, tensor in model.encoder.state_dict().items():
        if not torch.equal(tensor, encoder[name]): raise ValueError("Pretrained tensor bytes changed during loading.")
    if any(torch.count_nonzero(p) for p in model.heads.values()):
        raise ValueError("New task heads must be exactly zero.")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()): raise ValueError("Refusing to overwrite an existing ORIGINAL directory.")
    checkpoint = output / "model.safetensors"
    tensors = model.export(checkpoint)
    for name in ("config.json", "vocab.txt"):
        (output / name).write_bytes((upstream / name).read_bytes())
    provenance = {"repository": spec["repository"], "revision": spec["revision"],
        "weights_sha256": files["pytorch_model.bin"]["sha256"], "config_sha256": files["config.json"]["sha256"],
        "vocab_sha256": files["vocab.txt"]["sha256"], "source_inventory_sha256": digest((upstream / "source.json").read_bytes()),
        "excluded_pretraining_head_keys": sorted(EXCLUDED), "initialization": "intact_native_encoder_pooler+explicit_zero_affine_heads"}
    manifest = {"schema": 1, "architecture": ARCHITECTURE, "model_id": "privoke-v3-" + tier, "tier": tier,
        "parent": "", "original": "", "blob": digest(checkpoint.read_bytes()), "config": provenance["config_sha256"],
        "vocab": provenance["vocab_sha256"], "source": provenance, "tensors": tensors,
        "parameter_count": sum(p.numel() for p in model.parameters()), "scope": "original", "evidence": ""}
    validate_manifest(manifest)
    (output / "manifest.json").write_bytes(canonical(manifest))
    proof = {"manifest_sha256": digest(canonical(manifest)), "rng_state_unchanged": True,
        "all_encoder_pooler_tensors_byte_equal": True, "all_new_heads_zero": True,
        "parameter_count": manifest["parameter_count"], "head_parameter_count": sum(p.numel() for p in model.heads.values()),
        "encoder_tensor_hashes": {k: tensor_hash(v) for k, v in model.encoder.state_dict().items()},
        "torch": torch.__version__}
    (output / "preparation-proof.json").write_bytes(canonical(proof))
    return proof

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tier", choices=TIERS, required=True)
    args = parser.parse_args()
    proof = prepare(args.upstream, args.output, args.tier)
    print(json.dumps({k: v for k, v in proof.items() if k != "encoder_tensor_hashes"}, sort_keys=True))
