"""Reuse the maintained TRAIN sampler and freeze one common ordered stream."""
from __future__ import annotations
import random
from pathlib import Path
from common import ROOT, runtime_pb2, canonical, digest
from privoke_model.v3_contract import validate_policy
from prompt_generation import taxonomy_coverage as taxonomy, benign_coverage as benign
from training.transforms import random_pii_transform
from training.types import BatchTrainingExample
from privoke_model.training_data import training_text_key

INPUTS = {"taxonomy": ("evaluation/results/iterative_fuzzer_20261011/taxonomy-coverage/release/taxonomy-coverage-v1.json", "3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0"),
 "pool": ("evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/pool-authored.json", "7c6ed6f6d751d2568141f715abd7ee8235fec937d9d1c0f6c0e29d0f2b9b99d7"),
 "manifest": ("evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/r1/benign-manifest.json", "c817db3579b93f88ac2028d1f226884e3882ec9405b3bd2a868bdd5fa0a38ec9"),
 "proof": ("evaluation/results/iterative_fuzzer_20261011/train-benign-coverage/r1/exclusion-proof.json", "77392a02fe414419ff909a639d42fbe2ee2fdec6b08ba52be6868ba43089d61a")}

def wire(row):
    target = row.expected_classification
    return runtime_pb2.RuntimeTrainingExample(text=row.text, has_target=True, weight=row.weight,
        target=runtime_pb2.RuntimeClassification(**target.to_dict(), packed=target.pack()))

def load_sources(input_root=ROOT):
    paths = {}
    for key, (relative, sha) in INPUTS.items():
        path = Path(input_root) / relative
        if digest(path.read_bytes()) != sha:
            raise ValueError("Approved fuzzer TRAIN source bytes changed: " + key)
        paths[key] = path
    dataset = taxonomy.load_dataset(paths["taxonomy"])
    release = benign.load_release(paths["pool"], paths["manifest"], paths["proof"], dataset)
    # Validate all permanent families under every allowed transformation, not only
    # the sampled window. Repeated equal targets are exposures, never new labels.
    variants = {}
    for row in (*dataset.rows, *release.pool.rows):
        record = sidecar(row)
        for text in taxonomy.transform_variants(row.text):
            key = training_text_key(text)
            binding = (record["partition"], record["packed_target"])
            if key in variants and variants[key] != binding:
                raise ValueError("Permanent partitions/targets conflict under an invariant transform.")
            variants[key] = binding
    return dataset, release


def sidecar(row, *, transform="original", original_text=None):
    meta = dict(row.metadata)
    return {"source_id": meta.get("benign_row_id", meta.get("taxonomy_row_id")),
        "group_id": meta["group_id"], "family": meta.get("primary_category", meta["group_id"]),
        "partition": meta.get("partition", meta.get("taxonomy_partition")),
        "metadata": meta, "transform": transform,
        "original_text": row.text if original_text is None else original_text,
        "text": row.text, "weight": row.weight,
        "target": row.expected_classification.to_dict(), "packed_target": row.expected_classification.pack()}


def validate_schedule(training, guard, source, policy, input_root=ROOT):
    """Validate actual serialized rows against pinned source, permanent split and transforms."""
    validate_policy(policy, pilot=policy["steps"] == 2)
    dataset, release = load_sources(input_root)
    if source.get("schema") != 1 or source.get("sampler") != "existing_taxonomy_benign_common_frozen_stream_v1" or source.get("inputs") != {k: sha for k, (_, sha) in INPUTS.items()}:
        raise ValueError("Pinned source proof differs from admitted inputs.")
    train_meta, guard_meta = source["train_sidecar"], source["guard_sidecar"]
    if len(training) != policy["window_batches"] * 64 or len(guard) != 16 or len(train_meta) != len(training) or len(guard_meta) != len(guard):
        raise ValueError("Actual schedule/sidecar denominator mismatch.")
    source_rows = {r.metadata.get("benign_row_id", r.metadata.get("taxonomy_row_id")): r
                   for r in (*dataset.rows, *release.pool.rows)}
    seen_targets = {}
    for partition, rows, metadata in (("train", training, train_meta), ("guard", guard, guard_meta)):
        for row, record in zip(rows, metadata):
            original = source_rows.get(record["source_id"])
            if original is None:
                raise ValueError("Schedule source ID is not admitted.")
            expected = sidecar(original)
            for key in ("source_id", "group_id", "family", "partition", "original_text", "target", "packed_target", "weight"):
                if record[key] != expected[key]:
                    raise ValueError("Schedule sidecar differs from pinned source: " + key)
            if record["partition"] != partition or row.text != record["text"] or row.weight != 1 or not row.has_target:
                raise ValueError("Serialized row differs from sidecar/permanent partition.")
            if row.target.packed != record["packed_target"] or {"sensitivity": row.target.sensitivity,
                    "visibility": row.target.visibility, "categories": list(row.target.categories)} != record["target"]:
                raise ValueError("Serialized named/packed target differs from pinned source.")
            allowed = dict(zip(("identity", "review_prefix", "synthetic_name"), taxonomy.transform_variants(original.text)))
            if record["transform"] == "original":
                wanted = original.text
            else:
                if partition != "train" or record["transform"] not in allowed:
                    raise ValueError("Unadmitted transformation.")
                wanted = allowed[record["transform"]]
            if row.text != wanted:
                raise ValueError("Actual text differs from named invariant transformation.")
            key = training_text_key(row.text)
            if key in seen_targets and seen_targets[key] != row.target.packed:
                raise ValueError("Conflicting targets for a normalized schedule text.")
            seen_targets[key] = row.target.packed
    # Validate the selected original stream against the maintained sampler per batch.
    for batch in range(policy["window_batches"]):
        expected, _ = benign.generate_partition(dataset, release, source["seed"] + batch * 1009)
        rng = random.Random(source["seed"] + batch * 1009)
        records = train_meta[batch * 64:(batch + 1) * 64]
        for i, original in enumerate(expected):
            first, transformed = records[2 * i:2 * i + 2]
            if first["metadata"] != original.metadata or transformed["metadata"] != original.metadata:
                raise ValueError("Actual provenance metadata differs from the maintained sampler.")
            if first["source_id"] != sidecar(original)["source_id"] or first["transform"] != "original" or transformed["source_id"] != first["source_id"] or transformed["transform"] == "original":
                raise ValueError("Actual original/transform ordering differs from sampler.")
            if transformed["text"] != random_pii_transform(original.text, rng):
                raise ValueError("Actual transformed stream differs from the frozen seed.")
    _, expected_guard = benign.generate_partition(dataset, release, source["seed"])
    if [r["source_id"] for r in guard_meta] != [sidecar(r)["source_id"] for r in expected_guard]:
        raise ValueError("Actual guard differs from the common seed guard.")
    if [r["metadata"] for r in guard_meta] != [r.metadata for r in expected_guard]:
        raise ValueError("Actual guard metadata differs from pinned source.")
    train_groups = {r["group_id"] for r in train_meta}; guard_groups = {r["group_id"] for r in guard_meta}
    if train_groups & guard_groups or {training_text_key(r.text) for r in training} & {training_text_key(r.text) for r in guard}:
        raise ValueError("TRAIN/guard group or normalized-text overlap.")
    for key, rows in (("train", training), ("guard", guard)):
        if source[key + "_wire_sha256"] != digest(b"".join(r.SerializeToString(deterministic=True) for r in rows)):
            raise ValueError("Actual wire commitment mismatch.")
    unique_sources = len({r["source_id"] for r in train_meta})
    unique_texts = len({training_text_key(r.text) for r in training})
    return {"train_occurrences": len(training), "original_occurrences": len(training) // 2,
        "unique_source_ids": unique_sources, "repeated_source_occurrences": len(training) // 2 - unique_sources,
        "unique_normalized_texts": unique_texts, "repeated_text_occurrences": len(training) - unique_texts,
        "guard_occurrences": len(guard), "guard_unique_source_ids": len({r["source_id"] for r in guard_meta}),
        "train_groups": sorted(train_groups), "guard_groups": sorted(guard_groups)}


def validate_source_evidence(evidence):
    """Reconstruct committed wires and validate the full source at admission."""
    source = evidence["source"]
    if digest(canonical(source)) != evidence["source_commitment"]:
        raise ValueError("Execution source bytes differ from fit commitment.")
    def rows(key):
        return [runtime_pb2.RuntimeTrainingExample(text=r["text"], weight=r["weight"], has_target=True,
            target=runtime_pb2.RuntimeClassification(**r["target"], packed=r["packed_target"])) for r in source[key + "_sidecar"]]
    counts = validate_schedule(rows("train"), rows("guard"), source, evidence["policy"])
    if any(source.get(k) != v for k, v in counts.items()):
        raise ValueError("Source exposure counts differ from actual rows.")
    if source.get("sidecar_sha256") != digest(canonical({"train": source["train_sidecar"], "guard": source["guard_sidecar"]})):
        raise ValueError("Source sidecar commitment differs.")
    for key in ("train_wire_sha256", "guard_wire_sha256"):
        if source[key] != evidence[key]:
            raise ValueError("Evidence wire differs from actual source.")
    guard_targets = [r["packed_target"] for r in source["guard_sidecar"]]
    if any([r["target"] for r in evidence[key]["rows"]] != guard_targets for key in ("base_guard", "candidate_guard")):
        raise ValueError("Execution guard targets differ from dispatched pinned source.")
    return source


def schedule(seed, policy, input_root=ROOT):
    validate_policy(policy, pilot=policy["steps"] == 2)
    dataset, release = load_sources(input_root)
    training, records = [], []
    _, guard = benign.generate_partition(dataset, release, seed)
    for index in range(policy["window_batches"]):
        batch_seed = seed + index * 1009
        rows, _ = benign.generate_partition(dataset, release, batch_seed)
        rng = random.Random(batch_seed)
        for row in rows:
            transformed_text = random_pii_transform(row.text, rng)
            variant = taxonomy.transform_variants(row.text).index(transformed_text)
            transformed = BatchTrainingExample(transformed_text, row.expected_classification, row.weight, dict(row.metadata))
            training.extend((wire(row), wire(transformed)))
            records.extend((sidecar(row), sidecar(transformed, transform=("identity", "review_prefix", "synthetic_name")[variant], original_text=row.text)))
    guard_wire = [wire(row) for row in guard]
    source = {"schema": 1, "sampler": "existing_taxonomy_benign_common_frozen_stream_v1", "seed": seed,
        "inputs": {k: sha for k, (_, sha) in INPUTS.items()}, "train_rows": len(training), "guard_rows": len(guard_wire),
        "ordered_original_count": len(training) // 2, "train_sidecar": records, "guard_sidecar": [sidecar(row) for row in guard],
        "train_wire_sha256": digest(b"".join(r.SerializeToString(deterministic=True) for r in training)),
        "guard_wire_sha256": digest(b"".join(r.SerializeToString(deterministic=True) for r in guard_wire)),
        "source_hashes": {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in (
            Path(__file__), ROOT / "services/privoke-fuzzer/src/prompt_generation/taxonomy_coverage.py",
            ROOT / "services/privoke-fuzzer/src/prompt_generation/benign_coverage.py", ROOT / "services/privoke-fuzzer/src/training/transforms.py")}}
    counts = validate_schedule(training, guard_wire, source, policy, input_root)
    source.update(counts)
    source["sidecar_sha256"] = digest(canonical({"train": records, "guard": source["guard_sidecar"]}))
    return training, guard_wire, source
