"""Versioned AU3 source stream; BC01 remains a separate frozen schedule."""
from __future__ import annotations
import os
import random
from pathlib import Path
from common import ROOT, canonical, digest
from prompt_generation import audience_coverage as audience
from training.transforms import random_pii_transform, synthetic_common_name
from training.types import BatchTrainingExample

SAMPLER = "audience_common_frozen_stream_v1"


def trusted_release():
    path, sha = os.getenv("V3_AUDIENCE_MANIFEST_PATH"), os.getenv("V3_AUDIENCE_MANIFEST_SHA256")
    if bool(path) != bool(sha):
        raise ValueError("Custom v3 audience release requires both trusted path and pin.")
    return audience.load_release(path, sha)


def record(row, *, transform="original", original_text=None):
    return {"source_id": row.metadata["example_id"], "group_id": row.metadata["group_id"],
            "family": row.metadata["primary_category"], "partition": "train" if row.metadata["split"] == "train" else "guard",
            "metadata": row.metadata, "transform": transform, "original_text": original_text or row.text,
            "text": row.text, "weight": row.weight, "target": row.expected_classification.to_dict(),
            "packed_target": row.expected_classification.pack()}


def build(seed, policy, release=None):
    from fuzzer_training import wire
    release = release or trusted_release()
    training, records = [], []
    _, guard = audience.generate_partition(release, seed)
    for index in range(policy["window_batches"]):
        batch_seed = seed + index * 1009
        originals, _ = audience.generate_partition(release, batch_seed)
        rng = random.Random(batch_seed)
        for original in originals:
            text = random_pii_transform(original.text, rng)
            variants = (original.text, "Please review this prompt: " + original.text, synthetic_common_name(original.text))
            name = ("identity", "review_prefix", "synthetic_name")[variants.index(text)]
            transformed = BatchTrainingExample(text, original.expected_classification, original.weight, dict(original.metadata))
            training.extend((wire(original), wire(transformed)))
            records.extend((record(original), record(transformed, transform=name, original_text=original.text)))
    guards = [wire(row) for row in guard]
    train_groups = {r["group_id"] for r in records}; guard_groups = {r.metadata["group_id"] for r in guard}
    from privoke_model.training_data import training_text_key
    unique_sources = len({r["source_id"] for r in records})
    unique_texts = len({training_text_key(r.text) for r in training})
    guard_records = [record(row) for row in guard]
    source = {"schema": 1, "sampler": SAMPLER, "seed": seed, "inputs": {"audience_manifest": release.sha256},
              "train_rows": len(training), "guard_rows": len(guards), "ordered_original_count": len(training)//2,
              "train_sidecar": records, "guard_sidecar": guard_records,
              "train_wire_sha256": digest(b"".join(r.SerializeToString(deterministic=True) for r in training)),
              "guard_wire_sha256": digest(b"".join(r.SerializeToString(deterministic=True) for r in guards)),
              "source_hashes": {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in
                  (Path(__file__), ROOT / "services/privoke-fuzzer/src/prompt_generation/audience_coverage.py", ROOT / "services/privoke-fuzzer/src/training/transforms.py")},
              "train_occurrences": len(training), "original_occurrences": len(training)//2,
              "unique_source_ids": unique_sources, "repeated_source_occurrences": len(training)//2-unique_sources,
              "unique_normalized_texts": unique_texts, "repeated_text_occurrences": len(training)-unique_texts,
              "guard_occurrences": len(guards), "guard_unique_source_ids": len(guards),
              "train_groups": sorted(train_groups), "guard_groups": sorted(guard_groups)}
    source["sidecar_sha256"] = digest(canonical({"train": records, "guard": guard_records}))
    return training, guards, source


def validate(training, guard, source, policy):
    expected_train, expected_guard, expected_source = build(source["seed"], policy)
    if canonical(source) != canonical(expected_source) or training != expected_train or guard != expected_guard:
        raise ValueError("AU3 actual source wires/sidecars/quotas differ from trusted deterministic schedule.")
    return {k: expected_source[k] for k in ("train_occurrences", "original_occurrences", "unique_source_ids",
             "repeated_source_occurrences", "unique_normalized_texts", "repeated_text_occurrences", "guard_occurrences",
             "guard_unique_source_ids", "train_groups", "guard_groups")}
