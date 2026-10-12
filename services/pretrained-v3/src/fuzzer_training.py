"""Reuse the maintained TRAIN sampler and freeze one common ordered stream."""
from __future__ import annotations
import random
from pathlib import Path
from common import ROOT, runtime_pb2, canonical, digest
from privoke_model.v3_contract import validate_policy
from prompt_generation import taxonomy_coverage as taxonomy, benign_coverage as benign
from training.transforms import random_pii_transform
from training.types import BatchTrainingExample

INPUTS = {"taxonomy": ("evaluation/results/iterative_fuzzer_20261011/taxonomy-coverage/release/taxonomy-coverage-v1.json", "3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0"),
 "pool": ("evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/pool-authored.json", "7c6ed6f6d751d2568141f715abd7ee8235fec937d9d1c0f6c0e29d0f2b9b99d7"),
 "manifest": ("evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/r1/benign-manifest.json", "c817db3579b93f88ac2028d1f226884e3882ec9405b3bd2a868bdd5fa0a38ec9"),
 "proof": ("evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/r1/exclusion-proof.json", "77392a02fe414419ff909a639d42fbe2ee2fdec6b08ba52be6868ba43089d61a")}

def wire(row):
    target = row.expected_classification
    return runtime_pb2.RuntimeTrainingExample(text=row.text, has_target=True, weight=row.weight,
        target=runtime_pb2.RuntimeClassification(**target.to_dict(), packed=target.pack()))

def schedule(seed, policy, input_root=ROOT):
    validate_policy(policy, pilot=policy["steps"] == 2)
    paths = {}
    for key, (relative, sha) in INPUTS.items():
        path = Path(input_root) / relative
        if digest(path.read_bytes()) != sha: raise ValueError("Approved fuzzer TRAIN source bytes changed: " + key)
        paths[key] = path
    dataset = taxonomy.load_dataset(paths["taxonomy"])
    release = benign.load_release(paths["pool"], paths["manifest"], paths["proof"], dataset)
    training, groups, originals = [], set(), []
    _, guard = benign.generate_partition(dataset, release, seed)
    for index in range(policy["window_batches"]):
        batch_seed = seed + index * 1009
        rows, _ = benign.generate_partition(dataset, release, batch_seed)
        rng = random.Random(batch_seed)
        expanded = []
        for row in rows:
            expanded.extend((row, BatchTrainingExample(random_pii_transform(row.text, rng), row.expected_classification,
                row.weight, dict(row.metadata))))
        if len(expanded) != 64: raise ValueError("Fuzzer sampler must produce 32 originals plus32 transforms.")
        groups.update(row.metadata["group_id"] for row in rows)
        originals.extend(rows); training.extend(wire(row) for row in expanded)
    guard_groups = {row.metadata["group_id"] for row in guard}
    if groups & guard_groups: raise ValueError("TRAIN/guard declared groups overlap.")
    guard_wire = [wire(row) for row in guard]
    source = {"schema": 1, "sampler": "existing_taxonomy_benign_common_frozen_stream_v1", "seed": seed,
        "inputs": {k: sha for k, (_, sha) in INPUTS.items()}, "train_groups": sorted(groups), "guard_groups": sorted(guard_groups),
        "train_rows": len(training), "guard_rows": len(guard_wire), "ordered_original_count": len(originals),
        "train_wire_sha256": digest(b"".join(r.SerializeToString(deterministic=True) for r in training)),
        "guard_wire_sha256": digest(b"".join(r.SerializeToString(deterministic=True) for r in guard_wire)),
        "source_hashes": {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in (
            Path(__file__), ROOT / "services/privoke-fuzzer/src/prompt_generation/taxonomy_coverage.py",
            ROOT / "services/privoke-fuzzer/src/prompt_generation/benign_coverage.py", ROOT / "services/privoke-fuzzer/src/training/transforms.py")}}
    return training, guard_wire, source
