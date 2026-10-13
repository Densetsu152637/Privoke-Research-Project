"""Opt-in ordinary-benign TRAIN exposure; no numerical or efficacy claim."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import random

from privoke_model.training_data import training_text_key
from training.types import BatchTrainingExample
from . import taxonomy_coverage as legacy
from .anchor_rehearsal import training_wire_rows, wire_commitment

STRATEGY = "taxonomy_benign_coverage_v1"
SOURCE = "independently_authored_ordinary_benign_v1"
DATASET_SHA256 = "3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0"
# Independently derived from the accepted immutable release bytes, not caller objects.
LEGACY_SNAPSHOT_SHA256 = "04db8a469aa5c430f9333829da015f01b4377eb5268c58c1451c63b0a51dcced"
POOL_KEY = "benign_pool_sha256"
MANIFEST_KEY = "benign_manifest_sha256"
PROOF_KEY = "benign_exclusion_proof_sha256"
PIN_KEYS = frozenset(("taxonomy_dataset_sha256", POOL_KEY, MANIFEST_KEY, PROOF_KEY))
SLOTS = (("HEALTH", "P0"), ("POLITICS", "P1"), ("RELIGION", "P2"), ("CRIMINAL", "P3"))


def digest(value):
    return hashlib.sha256(legacy.canonical_bytes(value)).hexdigest()


def legacy_snapshot_commitment(dataset):
    """Bind every ordered source/guard field, including mutable nested mappings."""
    return digest({"dataset_sha256": dataset.sha256,
        "rows": [{"text": r.text, "target": r.expected_classification.to_dict(),
                  "packed": r.expected_packed_classification, "weight": r.weight,
                  "metadata": dict(r.metadata)} for r in dataset.rows],
        "partitions": dataset.partitions, "exclusion_validation": dataset.exclusion_validation})


def validate_legacy_snapshot(dataset):
    if dataset.sha256 != DATASET_SHA256 or legacy_snapshot_commitment(dataset) != LEGACY_SNAPSHOT_SHA256:
        raise ValueError("Benign coverage legacy snapshot differs from independently pinned accepted content.")


def guard_wire_rows(rows):
    """Match runtime_client's unchanged packed-only guard constructor exactly."""
    from privoke.v1 import runtime_pb2
    return [runtime_pb2.RuntimeTrainingExample(text=r.text, has_target=True, weight=r.weight,
        target=runtime_pb2.RuntimeClassification(packed=r.expected_packed_classification)) for r in rows]


def policy_contract():
    return {"strategy": STRATEGY, "version": 1, "replacement_slots": SLOTS,
        "base": legacy.policy_contract(), "selection": "independent_seeded_choice_sorted_pool_per_visibility_v1",
        "replacement": "four_fiction_rows_in_place_after_complete_legacy_generation",
        "originals": 32, "expanded": 64, "ordinary_benign": 4, "fiction": 4,
        "unit_weights": True, "guard": "unchanged_ordered_same_seed_v1_guard",
        "transforms": "unchanged_legacy_seeded_one_invariance_transform_v1"}


@dataclass(frozen=True)
class BenignPool:
    sha256: str
    payload: bytes
    rows: tuple[BatchTrainingExample, ...]


@dataclass(frozen=True)
class BenignRelease:
    sha256: str
    proof_sha256: str
    payload: bytes
    proof_payload: bytes
    pool: BenignPool


def load_pool_snapshot(payload):
    value = json.loads(payload)
    if (payload != legacy.canonical_bytes(value) or set(value) != {
            "schema", "source", "authorship", "label_status", "permanent_partition", "fit_release", "rows"}
            or value.get("schema") != 1 or value.get("source") != SOURCE
            or value.get("label_status") != "assistant_provisional" or value.get("permanent_partition") != "train"
            or value.get("fit_release") is not False or not isinstance(value.get("authorship"), str) or not value["authorship"].strip()):
        raise ValueError("Benign pool requires canonical independent positive permanent TRAIN provenance.")
    rows, ids, groups, keys = [], set(), set(), set()
    for raw in value["rows"]:
        if set(raw) != {"id", "text", "weight", "classification", "packed_classification", "metadata"}:
            raise ValueError("Unsupported benign row schema.")
        target = legacy._target(raw["classification"])
        meta = raw["metadata"]
        identity, text = raw["id"], raw["text"]
        if (not isinstance(meta, dict) or set(meta) != {"group_id", "split", "partition", "source", "control",
                "label_status", "sensitivity_rationale", "category_rationale", "visibility_rationale"}
                or any(type(v) is not str or not v.strip() for v in meta.values())
                or meta["source"] != SOURCE or meta["split"] != "train" or meta["partition"] != "train"
                or meta["control"] != "ordinary_benign" or meta["label_status"] != "assistant_provisional"
                or not meta["group_id"].startswith("ordinary-benign-train-")
                or type(identity) is not str or identity != meta["group_id"] + "/00"
                or type(text) is not str or not training_text_key(text)
                or type(raw["weight"]) not in (int, float) or raw["weight"] != 1.0
                or type(raw["packed_classification"]) is not int or raw["packed_classification"] != int(target.pack())
                or target.sensitivity().name != "S0" or target.visibility().name not in {v for _, v in SLOTS}
                or target.categories()):
            raise ValueError("Benign rows require own TRAIN identities, unit weights and explicit S0/visibility/empty-category targets.")
        if identity in ids or meta["group_id"] in groups or training_text_key(text) in keys:
            raise ValueError("Benign pool must contain distinct originals and independent declared source groups.")
        ids.add(identity); groups.add(meta["group_id"]); keys.add(training_text_key(text))
        rows.append(BatchTrainingExample(text, target, 1.0, {**meta, "benign_row_id": identity}))
    counts = Counter(r.expected_classification.visibility().name for r in rows)
    if len(rows) < 32 or any(counts[v] < 8 for _, v in SLOTS):
        raise ValueError("Benign pool requires at least32 originals and eight per selected visibility.")
    seen = {}
    for row in rows:
        for text in legacy.transform_variants(row.text):
            key = training_text_key(text)
            if key in seen and seen[key] != row.metadata["benign_row_id"]:
                raise ValueError("Benign pool has a cross-original transform collision.")
            seen[key] = row.metadata["benign_row_id"]
    return BenignPool(hashlib.sha256(payload).hexdigest(), payload, tuple(rows))


def transform_commitment(pool):
    return digest([{"id": r.metadata["benign_row_id"], "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "target": r.expected_classification.to_dict(), "packed": r.expected_packed_classification, "weight": r.weight}
        for r in pool.rows for text in legacy.transform_variants(r.text)])


def validate_pool(pool):
    rebuilt = load_pool_snapshot(pool.payload)
    def values(rows):
        return [(r.text, r.expected_packed_classification, r.weight, dict(r.metadata)) for r in rows]
    if rebuilt.sha256 != pool.sha256 or values(rebuilt.rows) != values(pool.rows):
        raise ValueError("Benign pool snapshot differs from its frozen bytes.")


def prepare_manifest(pool, dataset, proof_payload):
    validate_pool(pool)
    validate_legacy_snapshot(dataset)
    proof = json.loads(proof_payload)
    expected_validation = dataset.exclusion_validation
    validation = proof.get("exclusion_validation", {})
    if (proof_payload != legacy.canonical_bytes(proof) or set(proof) != {"schema", "strategy", "status", "pool_sha256",
            "dataset_sha256", "label_review_sha256", "all_transform_variants", "transform_commitment_sha256",
            "source_overlap_counts", "exclusion_validation", "fit_release"}
            or proof.get("schema") != 1 or proof.get("strategy") != STRATEGY or proof.get("status") != "passed"
            or proof.get("pool_sha256") != pool.sha256 or proof.get("dataset_sha256") != dataset.sha256
            or proof.get("all_transform_variants") is not True or proof.get("fit_release") is not False
            or proof.get("transform_commitment_sha256") != transform_commitment(pool)
            or proof.get("source_overlap_counts") != {"ids": 0, "groups": 0, "texts": 0}
            or type(proof.get("label_review_sha256")) is not str or len(proof["label_review_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in proof["label_review_sha256"])
            or validation != expected_validation or validation.get("status") != "passed"
            or validation.get("all_transform_variants") is not True):
        raise ValueError("Benign coverage requires a fresh hash-bound reviewed all-transform exclusion proof.")
    # New source rows must also be disjoint from every legacy source/guard family.
    legacy_ids = {r.metadata["taxonomy_row_id"] for r in dataset.rows}
    legacy_keys = {training_text_key(text) for r in dataset.rows for text in legacy.transform_variants(r.text)}
    if any(r.metadata["benign_row_id"] in legacy_ids or r.metadata["group_id"] in dataset.partitions
           or any(training_text_key(t) in legacy_keys for t in legacy.transform_variants(r.text)) for r in pool.rows):
        raise ValueError("Benign pool collides with legacy source/guard identities or transformations.")
    return legacy.canonical_bytes({"schema": 1, "strategy": STRATEGY, "dataset_sha256": dataset.sha256,
        "legacy_snapshot_commitment_sha256": LEGACY_SNAPSHOT_SHA256,
        "pool_sha256": pool.sha256, "exclusion_proof_sha256": hashlib.sha256(proof_payload).hexdigest(),
        "label_review_sha256": proof["label_review_sha256"], "pool_transform_commitment_sha256": transform_commitment(pool),
        "policy": policy_contract(), "fit_release": False})


def load_snapshot(payload, pool, dataset, proof_payload):
    if payload != prepare_manifest(pool, dataset, proof_payload):
        raise ValueError("Benign canonical manifest/config/source/proof differs.")
    return BenignRelease(hashlib.sha256(payload).hexdigest(), hashlib.sha256(proof_payload).hexdigest(), payload, proof_payload, pool)


def load_release(pool_path, manifest_path, proof_path, dataset):
    if not pool_path or not manifest_path or not proof_path:
        raise ValueError("Benign coverage requires explicit pool, manifest and exclusion-proof paths.")
    return load_snapshot(Path(manifest_path).read_bytes(), load_pool_snapshot(Path(pool_path).read_bytes()),
                         dataset, Path(proof_path).read_bytes())


def validate_release(release, dataset):
    if load_snapshot(release.payload, release.pool, dataset, release.proof_payload) != release:
        raise ValueError("Benign release snapshot differs from its frozen bytes.")


def validate_pins(metadata, release, dataset):
    validate_release(release, dataset)
    expected = {"taxonomy_dataset_sha256": dataset.sha256, POOL_KEY: release.pool.sha256,
                MANIFEST_KEY: release.sha256, PROOF_KEY: release.proof_sha256}
    if metadata.get("contextual_sampling_strategy") != STRATEGY or any(metadata.get(k) != v for k, v in expected.items()):
        raise ValueError("Benign coverage requires explicit matching dataset/pool/manifest/proof pins.")


def _select(dataset, release, seed):
    # Complete legacy generation first, preserving every legacy RNG operation and guard byte.
    originals, guard = legacy.generate_partition(dataset, seed)
    rng = random.Random(seed)  # nosec B311 -- independent deterministic author-pool selection
    replacement = {slot: rng.choice(sorted((r for r in release.pool.rows
                    if r.expected_classification.visibility().name == slot[1]), key=lambda r: r.metadata["benign_row_id"]))
                   for slot in SLOTS}
    selected = []
    for index, row in enumerate(originals):
        slot = row.metadata["primary_category"], row.expected_classification.visibility().name
        if row.metadata["control"] == "fiction" and slot in replacement:
            row = replacement[slot]
            metadata = {**row.metadata, "generation_seed": str(seed), "generation_index": str(index)}
        else:
            metadata = dict(row.metadata)
        selected.append(BatchTrainingExample(row.text, row.expected_classification, row.weight,
                            {**metadata, "taxonomy_strategy": STRATEGY}))
    return selected, guard


def generate_partition(dataset, release, seed):
    validate_release(release, dataset)
    rows, guard = _select(dataset, release, seed)
    audit_originals(dataset, release, rows, guard, seed)
    return rows, guard


def audit_originals(dataset, release, originals, guard, seed):
    validate_release(release, dataset)
    expected, expected_guard = _select(dataset, release, seed)
    if originals != expected or guard != expected_guard:
        raise ValueError("Benign actual originals/order/targets/weights/provenance or unchanged ordered guard differ.")
    sensitivity, visibility, categories = legacy._counts(originals)
    control = Counter(r.metadata["control"] for r in originals)
    if (len(originals) != 32 or len({training_text_key(r.text) for r in originals}) != 32
            or sensitivity != legacy.SENSITIVITY_COUNTS or visibility != {v: 4 for v in legacy.Visibility.__members__}
            or control != {"actual": 20, "fiction": 4, "mild": 4, "ordinary_benign": 4}
            or any(categories[c] < n for c, n in legacy.CATEGORY_MINIMUMS.items())):
        raise ValueError("Benign actual selection violates unchanged quotas or declared four/four controls.")
    if {training_text_key(r.text) for r in guard} & {training_text_key(t) for r in originals for t in legacy.transform_variants(r.text)}:
        raise ValueError("Benign possible transformed inputs overlap the same-seed guard.")
    ids = [r.metadata.get("benign_row_id", r.metadata.get("taxonomy_row_id")) for r in originals]
    groups = {r.metadata["group_id"] for r in originals}
    return {"contextual_sampling_strategy": STRATEGY, "taxonomy_dataset_sha256": dataset.sha256,
        POOL_KEY: release.pool.sha256, MANIFEST_KEY: release.sha256, PROOF_KEY: release.proof_sha256,
        "sampling_training_rows": "32", "sampling_training_unique_texts": "32", "sampling_training_groups": str(len(groups)),
        "sampling_guard_rows": "16", "sampling_guard_groups": str(len({r.metadata["group_id"] for r in guard})),
        "sampling_sensitivity_counts": json.dumps(dict(sensitivity), sort_keys=True),
        "sampling_sensitive_visibility_counts": json.dumps(dict(visibility), sort_keys=True),
        "sampling_category_counts": json.dumps(dict(categories), sort_keys=True),
        "sampling_training_ids_sha256": legacy._digest(ids), "sampling_training_groups_sha256": legacy._digest(groups),
        "sampling_guard_groups_sha256": legacy._digest(r.metadata["group_id"] for r in guard),
        "sampling_ordinary_benign_rows": "4", "sampling_fiction_rows": "4", "sampling_seed": str(seed),
        "sampling_original_order_sha256": wire_commitment(training_wire_rows(originals)),
        "sampling_guard_wire_sha256": wire_commitment(guard_wire_rows(guard))}


def audit_expanded(dataset, release, originals, expanded, guard, config):
    from training.trainer import iter_training_examples
    audit = audit_originals(dataset, release, originals, guard, config.seed)
    if (config.transformations_per_example != 1 or config.new_example_weight != 1.0 or len(expanded) != 64
            or expanded != list(iter_training_examples(originals, (), config))
            or any(actual.text not in legacy.transform_variants(original.text)
                   for i, original in enumerate(originals) for actual in expanded[i * 2:i * 2 + 2])):
        raise ValueError("Benign actual expansion is outside reviewed source/target/unit-weight/legacy-transform membership.")
    ids = [r.metadata.get("benign_row_id", r.metadata.get("taxonomy_row_id")) for r in expanded]
    audit.update(sampling_expanded_rows="64", sampling_expanded_unique_texts=str(len({training_text_key(r.text) for r in expanded})),
                 sampling_expanded_ids_sha256=legacy._digest(ids), sampling_expanded_wire_sha256=wire_commitment(training_wire_rows(expanded)))
    return audit


def persist_audit(release, audit):
    directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
    if not directory:
        raise ValueError("Benign coverage requires durable complete source/audit evidence.")
    payload = legacy.canonical_bytes({"schema": 1, "manifest_utf8": release.payload.decode(),
        "pool_utf8": release.pool.payload.decode(), "proof_utf8": release.proof_payload.decode(), "audit": audit})
    sha = hashlib.sha256(payload).hexdigest()
    path = Path(directory) / "benign-audits" / (sha + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
    except FileExistsError:
        if path.read_bytes() != payload:
            raise ValueError("Benign immutable sampling evidence conflicts.")
    return {"path": str(path), "sha256": sha}


def validate_retained_audit(evidence, metadata):
    reference = evidence["benign_audit"]
    payload = Path(reference["path"]).read_bytes()
    if hashlib.sha256(payload).hexdigest() != reference["sha256"]:
        raise ValueError("Benign retained audit checksum differs.")
    record = json.loads(payload)
    if (record.get("schema") != 1 or record.get("audit") != {k: metadata[k] for k in record.get("audit", {})}
            or hashlib.sha256(record["manifest_utf8"].encode()).hexdigest() != metadata.get(MANIFEST_KEY)
            or hashlib.sha256(record["pool_utf8"].encode()).hexdigest() != metadata.get(POOL_KEY)
            or hashlib.sha256(record["proof_utf8"].encode()).hexdigest() != metadata.get(PROOF_KEY)):
        raise ValueError("Benign retained source/pin/audit evidence differs from publication.")
    return record
