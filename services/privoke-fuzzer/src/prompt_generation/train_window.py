"""Freeze bounded BC01 TRAIN families and their actual transformed wire rows."""
from __future__ import annotations

from privoke_model import window_training as contract
from privoke_model.training_data import training_text_key
from training.types import BatchTrainingConfig, BatchTrainingExample
from . import benign_coverage as benign


def _source(row):
    meta = row.metadata
    return {"text": row.text, "packed": row.expected_packed_classification, "weight": float(row.weight),
            "id": meta.get("benign_row_id", meta.get("taxonomy_row_id")), "group": meta["group_id"],
            "partition": meta.get("taxonomy_partition", meta.get("split")),
            "family_kind": "benign" if "benign_row_id" in meta else "taxonomy"}


def prepare_window(dataset, release, seed):
    """At most64 candidates; greedy new-family coverage, then earliest unused blocks."""
    from training.trainer import iter_training_examples
    benign.validate_legacy_snapshot(dataset)
    benign.validate_release(release, dataset)
    candidates = []
    for index in range(64):
        candidate_seed = contract.derived_seed(seed, "candidate", index)
        originals, _ = benign.generate_partition(dataset, release, candidate_seed)
        groups = {r.metadata["group_id"] for r in originals if "taxonomy_row_id" in r.metadata}
        candidates.append((index, candidate_seed, originals, groups))
    selected, covered = [], set()
    while len(selected) < 8:
        chosen = min(candidates, key=lambda row: (-len(row[3] - covered), row[0]))
        candidates.remove(chosen)
        selected.append(chosen); covered.update(chosen[3])
    expected = {group for group, partition in dataset.partitions.items() if partition == "train"}
    if covered != expected or len(expected) != 20:
        raise ValueError("Bounded64-candidate search cannot cover all20 permanent TRAIN families in8blocks.")
    _, guard = benign.generate_partition(dataset, release, seed)
    blocks = []
    for _, candidate_seed, originals, _ in selected:
        config = BatchTrainingConfig(learning_rate=.003, max_gradient=.05,
                                    transformations_per_example=1, seed=candidate_seed)
        expanded = list(iter_training_examples(originals, (), config))
        benign.audit_expanded(dataset, release, originals, expanded,
                             benign.generate_partition(dataset, release, candidate_seed)[1], config)
        blocks.append({"seed": candidate_seed, "rows": [_source(row) for row in expanded]})
    rows = [row for block in blocks for row in block["rows"]]
    result = {"schema": 1, "sampler": contract.SAMPLER, "seed": seed, "config": contract.CONFIG,
        "sources": {"taxonomy": dataset.sha256, "benign": release.sha256,
                    "pool": release.pool.sha256, "proof": release.proof_sha256},
        "blocks": blocks, "guard": [_source(row) for row in guard],
        "provenance": {"wire_rows": 512, "unique_source_ids": len({r["id"] for r in rows}),
            "unique_texts": len({training_text_key(r["text"]) for r in rows}), "taxonomy_families": 20,
            "repeated_source_presentations": 512 - len({r["id"] for r in rows}), "fit_release": False}}
    return contract.validate_window(result)


def validate_sources(window, dataset, release):
    if window != prepare_window(dataset, release, window["seed"]):
        raise ValueError("Frozen window differs from bounded deterministic authenticated source selection.")


def examples(window):
    from privoke_contracts.classification import Classification
    contract.validate_window(window)
    def convert(row):
        return BatchTrainingExample(row["text"], Classification(row["packed"]), row["weight"],
                                    {"source_id": row["id"], "group_id": row["group"]})
    return tuple(map(convert, contract.flat_rows(window))), tuple(map(convert, window["guard"]))
