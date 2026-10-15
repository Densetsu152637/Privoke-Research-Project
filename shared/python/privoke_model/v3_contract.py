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

def tensor_changes(before, after, layers):
    """Recompute changed tensor groups from verified serialized inventories."""
    changed = sorted(name for name in before if before[name]["sha256"] != after[name]["sha256"])
    groups = {"heads": "heads.", "encoder": "encoder.", "embeddings": "encoder.embeddings.",
              "first_block": "encoder.encoder.layer.0.", "last_block": f"encoder.encoder.layer.{layers - 1}.",
              "pooler": "encoder.pooler."}
    counts = {key: sum(name.startswith(prefix) for name in changed) for key, prefix in groups.items()}
    counts["blocks"] = [sum(name.startswith(f"encoder.encoder.layer.{i}.") for name in changed) for i in range(layers)]
    return changed, counts


def validate_guard(value, denominator):
    from privoke_contracts.classification import Classification, PriVokeAction
    rows = value.get("rows", [])
    if value.get("examples") != denominator or len(rows) != denominator:
        raise ValueError("Guard row denominator differs from policy.")
    for row in rows:
        for key in ("target", "prediction"):
            packed = row[key]
            if type(packed) is not int or Classification(packed).pack() != packed:
                raise ValueError("Invalid packed guard classification.")
            Classification(packed).to_dict()
        for key in ("action", "target_action"):
            if row[key] not in PriVokeAction.__members__ or row[key + "_value"] != PriVokeAction[row[key]].value:
                raise ValueError("Guard action name/value mismatch.")
        confidence = row.get("confidence")
        if type(confidence) not in (float, int) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("Actual guard confidence required.")
        # Reuse the same production moderation as inference and the training guard.
        from src.classification import ClassificationResult
        for packed, score, action in ((row["prediction"], confidence, row["action"]),
                                      (row["target"], .999, row["target_action"])):
            if ClassificationResult(Classification(packed), "guard", "guard validation", confidence=score).action().name != action:
                raise ValueError("Guard action differs from production classification policy.")
        joint = row["target"] == row["prediction"] and row["action"] == row["target_action"]
        if type(row["joint_correct"]) is not bool or row["joint_correct"] != joint:
            raise ValueError("Guard joint correctness differs from rows.")
    if value.get("joint_correct") != sum(row["joint_correct"] for row in rows):
        raise ValueError("Guard joint count differs from rows.")
    if value.get("action_correct") != sum(row["action"] == row["target_action"] for row in rows):
        raise ValueError("Guard action count differs from rows.")
    return rows


def validate_execution(evidence, *, finalized=True):
    """Reconcile actual semantic work, every block, and row-derived guard arithmetic."""
    if evidence.get("schema") != 1 or evidence.get("layers") != [4] or evidence.get("scope") not in ("heads", "full_encoder"):
        raise ValueError("Actual explicit semantic-only training evidence required.")
    policy = evidence.get("policy", {})
    validate_policy(policy, pilot=policy.get("steps") == 2)
    for key in ("base", "source_commitment", "train_wire_sha256", "guard_wire_sha256"):
        check_sha(evidence.get(key))
    if not evidence.get("request_id"):
        raise ValueError("Execution request identity required.")
    tier = TIERS.get(evidence.get("tier"))
    if tier is None or evidence.get("model_id") != "privoke-v3-" + evidence["tier"]:
        raise ValueError("Execution model/tier identity required.")
    if evidence.get("parameter_count") != tier["parameters"]:
        raise ValueError("Execution complete parameter count mismatch.")
    expected_trainable = tier["parameters"] if evidence["scope"] == "full_encoder" else 20 * (tier["hidden_size"] + 1)
    if evidence.get("trainable_count") != expected_trainable:
        raise ValueError("Execution trainable parameter count mismatch.")
    phases = evidence.get("phases", {})
    counts = evidence.get("counts", {})
    microbatches = policy["steps"] * policy["batch_rows"] // policy["microbatch"]
    full = evidence["scope"] == "full_encoder"
    expected_counts = {"optimizer_steps": policy["steps"], "train_rows": policy["steps"] * policy["batch_rows"],
        "microbatch_forward": microbatches, "microbatch_backward": microbatches,
        "encoder_block_forward": microbatches * tier["num_hidden_layers"],
        "encoder_block_backward": microbatches * tier["num_hidden_layers"] if full else 0}
    if counts != expected_counts:
        raise ValueError("Actual work counters differ from frozen policy.")
    block_counts = evidence.get("block_counts", {})
    if block_counts != {"forward": [microbatches] * tier["num_hidden_layers"],
                         "backward": [microbatches if full else 0] * tier["num_hidden_layers"]}:
        raise ValueError("Every encoder block must attest actual forward/backward work.")
    expected_phases = {"training": expected_counts["train_rows"], "base_heldout": policy["guard_rows"], "candidate_heldout": policy["guard_rows"]}
    if set(phases) != set(expected_phases) or any(phases[k] != {"layer": 4, "status": "ok", "examples": n} for k, n in expected_phases.items()):
        raise ValueError("Successful exact-denominator semantic phases required.")
    changes = evidence.get("changes", {})
    if changes.get("heads", 0) <= 0 or len(changes.get("blocks", [])) != tier["num_hidden_layers"]:
        raise ValueError("Observed head and complete block changes required.")
    if not full and (changes.get("encoder") != 0 or any(changes["blocks"])):
        raise ValueError("HEADS changed pretrained encoder.")
    if full and (any(changes.get(k, 0) <= 0 for k in ("encoder", "embeddings", "first_block", "last_block", "pooler")) or any(n <= 0 for n in changes["blocks"])):
        raise ValueError("FULL requires changes in embeddings, every encoder block, and pooler.")
    if len(evidence.get("losses", [])) != policy["steps"] or any(not math.isfinite(v) for v in evidence["losses"]):
        raise ValueError("Finite per-step loss trace required.")
    trace = evidence.get("gradient_trace", [])
    if len(trace) != policy["steps"] or any(row["step"] != i + 1 or not math.isfinite(row["norm_before_clip"]) for i, row in enumerate(trace)):
        raise ValueError("Complete finite per-step gradient trace required.")
    if full and not any(row["encoder_nonzero_gradients"] > 0 for row in trace[1:]):
        raise ValueError("FULL requires observed encoder gradients after the zero-head step.")
    before = validate_guard(evidence["base_guard"], policy["guard_rows"])
    after = validate_guard(evidence["candidate_guard"], policy["guard_rows"])
    if any(a["target"] != b["target"] or a["target_action"] != b["target_action"] for a, b in zip(before, after)):
        raise ValueError("Base/candidate guard targets differ.")
    harms = sum(any(max(0, d * (b["action_value"] - b["target_action_value"])) >
                    max(0, d * (a["action_value"] - a["target_action_value"])) for d in (-1, 1))
                for a, b in zip(before, after))
    if evidence.get("action_harms") != harms:
        raise ValueError("Action harm count differs from guard rows.")
    if finalized:
        check_sha(evidence.get("candidate_blob"))
        if evidence.get("serialized_guard_parity") is not True:
            raise ValueError("Serialized guard parity required.")
    return evidence


def publication_passes(evidence):
    validate_execution(evidence)
    return evidence["candidate_guard"]["joint_correct"] > evidence["base_guard"]["joint_correct"] and evidence["action_harms"] == 0
