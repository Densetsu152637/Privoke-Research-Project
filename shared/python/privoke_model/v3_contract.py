"""Independent experimental v3 contract; legacy artifact limits stay unchanged."""
from __future__ import annotations
import hashlib
import json
import math
import re

ARCHITECTURE = "privoke_pretrained_bert_v3"
SCHEMA = 1
CHUNK_BYTES = 1024 * 1024
MAX_BLOB_BYTES = 80 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
TIERS = {
    "efficient": {"repository": "google/bert_uncased_L-4_H-128_A-2", "revision": "c29bee83fc7f003ac8c5e6e135529da4ecddb7c3", "hidden_size": 128, "num_hidden_layers": 4, "num_attention_heads": 2, "parameters": 4785044},
    "balanced": {"repository": "google/bert_uncased_L-2_H-256_A-4", "revision": "4e937a8675e5afd9a4836735c186ec01695bc3ea", "hidden_size": 256, "num_hidden_layers": 2, "num_attention_heads": 4, "parameters": 9596180},
    "quality": {"repository": "google/bert_uncased_L-12_H-256_A-4", "revision": "2ab9a0f41435a4d23d4cbc11cc3e7c922545f13d", "hidden_size": 256, "num_hidden_layers": 12, "num_attention_heads": 4, "parameters": 17493780},
}
LABELS = {"sensitivity": ["S0", "S1", "S2", "S3"], "visibility": ["P0", "P1", "P2", "P3", "P4", "PU"], "category": ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"]}
SOURCE_PINS = {
 "efficient": ("2e37a60f99c30c244da3a2ada3653faf378689783c5b6500d7291acc2516e199", "191ec8105cc6eb8ce2d64c117f7c5830f6028c06da4d7a0d3672414f2c77ad98"),
 "balanced": ("67b710645b099510dba08b7605a60859fff59714628e1d9d1ffa9e0956b51783", "ba873b4875d069697fa5bab011ea9e3f63b7f8186701bdf5356b4d8622d8f5c1"),
 "quality": ("1be1c8c6a57894a139fdf526fb8435f6acb6ea01600569a4ac3cfd405dc5f875", "9efa18e50a359c542d79f9c00a23049c2d78aa07c1fd11827c6e2487b3333cd7")}
VOCAB_SHA256 = "07eced375cec144d27c900241f3e339478dec958f92fddbc551f295c992038a3"
POLICY = {"schema": 1, "optimizer": "adamw", "head_lr": .001, "encoder_lr": .00002,
          "betas": [.9, .999], "eps": 1e-8, "weight_decay": 0.0, "clip_norm": 1.0,
          "microbatch": 4, "steps": 64, "window_batches": 8, "batch_rows": 64,
          "epochs": 8, "guard_rows": 16, "dropout": False, "max_tokens": 512,
          "category_threshold": .5, "objective": "sensitivity_ce+visibility_ce+category_mean_bce",
          "checkpoint_selection": "final_only", "publication": "joint_improve_action_harm_zero_v1"}

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()

def digest(payload):
    return hashlib.sha256(payload).hexdigest()

def check_sha(value):
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("Expected a lowercase SHA-256 identity.")
    return value

def parse(payload, limit=MAX_MANIFEST_BYTES):
    if not isinstance(payload, bytes) or len(payload) > limit:
        raise ValueError("JSON exceeds its explicit byte bound.")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON field.")
            result[key] = value
        return result
    value = json.loads(payload, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON.")))
    if canonical(value) != payload:
        raise ValueError("Canonical JSON bytes required.")
    return value

def validate_policy(value, *, pilot=False):
    expected = dict(POLICY)
    if pilot:
        expected.update(steps=2, window_batches=1, epochs=2)
    else:
        steps = value.get("steps")
        if type(steps) is not int or steps not in (64, 256, 512):
            raise ValueError("Predeclared v3 work budget must be 64, 256 or 512 steps.")
        expected.update(steps=steps, epochs=steps // 8)
    if value != expected:
        raise ValueError("Policy differs from the frozen v3 contract.")
    return value

def validate_manifest(value):
    required = {"schema", "architecture", "model_id", "tier", "parent", "original", "blob", "config", "vocab", "source", "tensors", "parameter_count", "scope", "evidence"}
    if not isinstance(value, dict) or set(value) != required or value["schema"] != SCHEMA or value["architecture"] != ARCHITECTURE:
        raise ValueError("Unsupported v3 manifest schema.")
    tier = TIERS.get(value["tier"])
    if tier is None or value["model_id"] != "privoke-v3-" + value["tier"]:
        raise ValueError("Unadmitted v3 model/tier.")
    for key in ("blob", "config", "vocab"):
        check_sha(value[key])
    for key in ("parent", "original", "evidence"):
        if value[key]: check_sha(value[key])
    source = value["source"]
    if not isinstance(source, dict) or source.get("repository") != tier["repository"] or source.get("revision") != tier["revision"]:
        raise ValueError("Pretrained provenance differs from admitted official revision.")
    for key in ("weights_sha256", "config_sha256", "vocab_sha256"):
        check_sha(source[key])
    if (source["weights_sha256"], source["config_sha256"]) != SOURCE_PINS[value["tier"]] or source["vocab_sha256"] != VOCAB_SHA256:
        raise ValueError("Pretrained source asset hashes differ from admitted official bytes.")
    if value["config"] != source["config_sha256"] or value["vocab"] != source["vocab_sha256"]:
        raise ValueError("Runtime config/tokenizer differs from admitted pretrained source.")
    tensors = value["tensors"]
    if not isinstance(tensors, dict) or not tensors or len(tensors) > 256:
        raise ValueError("Invalid v3 tensor inventory.")
    count = 0
    for name, tensor in tensors.items():
        if not isinstance(name, str) or len(name) > 256 or set(tensor) != {"shape", "dtype", "sha256"} or tensor["dtype"] != "F32":
            raise ValueError("Invalid v3 tensor declaration.")
        shape = tensor["shape"]
        if not isinstance(shape, list) or not shape or any(type(n) is not int or n <= 0 for n in shape):
            raise ValueError("Invalid v3 tensor shape.")
        check_sha(tensor["sha256"]); count += math.prod(shape)
    if count != value["parameter_count"] or count != tier["parameters"]:
        raise ValueError("Complete model parameter count differs from admitted tier.")
    if value["scope"] not in ("original", "heads", "full_encoder"):
        raise ValueError("Invalid v3 training scope.")
    if value["scope"] == "original":
        if value["parent"] or value["original"] or value["evidence"]:
            raise ValueError("ORIGINAL has no parent/training evidence.")
    elif not all(value[k] for k in ("parent", "original", "evidence")):
        raise ValueError("Candidate requires immutable parent, ORIGINAL and evidence.")
    return value

def validate_execution(evidence):
    if evidence.get("layers") != [4] or evidence.get("scope") not in ("heads", "full_encoder"):
        raise ValueError("Actual explicit semantic-only training evidence required.")
    phases = evidence.get("phases", {})
    if set(phases) != {"training", "base_heldout", "candidate_heldout"}:
        raise ValueError("All three actual training phases required.")
    if any(p.get("layer") != 4 or p.get("status") != "ok" or p.get("examples", 0) <= 0 for p in phases.values()):
        raise ValueError("Successful nonempty semantic execution required.")
    changes = evidence.get("changes", {})
    if changes.get("heads", 0) <= 0:
        raise ValueError("Observed head changes required.")
    if evidence["scope"] == "heads" and changes.get("encoder", 0) != 0:
        raise ValueError("HEADS changed pretrained encoder.")
    if evidence["scope"] == "full_encoder" and any(changes.get(key, 0) <= 0 for key in ("encoder", "embeddings", "first_block", "last_block", "pooler")):
        raise ValueError("FULL requires observed embedding, early/late block and pooler changes.")
    return evidence

def publication_passes(evidence):
    validate_execution(evidence)
    before, after = evidence["base_guard"], evidence["candidate_guard"]
    return after["joint_correct"] > before["joint_correct"] and evidence["action_harms"] == 0
