"""Build a fixed protected-key union for the prospective clean-data study.

This is a pure boundary over already parsed, caller-verified artifacts. It
never opens files, loads the locked selection, infers labels, or returns raw
identifiers/text. The I/O caller must hash each source/partition file and bind
those bytes to the supplied commitments before calling this function.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import re

from privoke_model.training_data import training_text_key

from .clean_augmentation_grouping import ProtectedKeys, opaque_exclusion_key


_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_NEMOTRON_ID = re.compile(r"(?:piimb:)?nemotron-pii:([0-9a-fA-F]{32})(?:_s\d+)?\Z")
_NEMOTRON_GROUP = re.compile(r"(?:piimb:)?nemotron-pii:([0-9a-fA-F]{32})(?:_s\d+)?\Z")
_PIIMB_PIN = "4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133"
_LOADER_REVISION = "9998e8986c7924223ea4598cb1ba683e32ade0ba"
_LOADER_SHA256 = "016a25a56b6fa3a9b8c16fcf9fde8a350c205101b26000cedd1095f097e15733"
_PREPARED_MANIFEST_SHA256 = "2b8a63b168d72510ce4e61e03748bf5f7858bdc33b41d15f0095780164658e1c"
_EXCLUSION_INDEX_SHA256 = "c0700613a965e26b85a2511c8a721b2f808536f215b8fe6f18f0d3890634fc2d"
_REFERENCE_TRAIN_SHA256 = "da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d"
_REFERENCE_VALIDATION_SHA256 = "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"
_BOOTSTRAP_SOURCE_SHA256 = "75422c421d1a80d0cc3321979fb049f1045f02f334586d6fe62d8832f8a5a7dd"
_ROW_COUNTS = {
    "reference_train": 3832,
    "reference_validation": 968,
    "bootstrap_texts": 43,
    "external_train": 19993,
    "nemotron_heldout": 1000,
    "meddies_heldout": 999,
}
_EXTERNAL_TRAIN_SOURCE_COUNTS = {"nemotron-pii": 13168, "meddies-pii": 2993}
_AGGREGATE = {
    "selected": 1000,
    "rows_seen": 150022,
    "eligible_rows": 107488,
    "selected_label_counts": {"pii": 500, "clean": 500},
    "duplicate_rows": 15354,
    "population_label_counts": {"pii": 60418, "clean": 47070},
    "exclusions": {"conflicting_duplicate_label_rows": 598, "non_english_language_rows": 27180},
}
_INDEX_TOP_LEVEL_FIELDS = {
    "schema_version", "records", "key_sets", "algorithm", "loader_revision",
    "loader_canonical_lf_sha256", "dataset_revision", "seed", "aggregate",
    "sorted_records_sha256", "reproduced_twice", "all_exclusion_key_sets",
    "all_exclusion_key_sets_sha256",
}
_RECORD_FIELDS = {"id_sha256", "canonical_group_sha256", "normalized_text_sha256", "text_sha256"}
_COMMITMENT_FIELDS = {
    "prepared_manifest_sha256", "exclusion_index_sha256", "reference_train_sha256",
    "reference_validation_sha256", "bootstrap_source_sha256", "partition_sha256",
}
_PARTITION_COMMITMENT_FIELDS = {"train", "validation", "nemotron_heldout", "meddies_heldout"}
_KEY_KINDS = ("ids", "groups", "texts")


@dataclass(frozen=True)
class ProtectedKeyUnion:
    """Opaque protected sets plus aggregate coverage and a commitment digest."""

    keys: ProtectedKeys
    coverage_counts: tuple[tuple[str, int], ...]
    union_sha256: str


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _sha_text(value: str) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ValueError("Protected text is not valid UTF-8 content.") from None
    return hashlib.sha256(encoded).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _valid_sha(value: object) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _opaque_set(raw: object) -> set[str]:
    _require(isinstance(raw, list), "Protected key set is malformed.")
    _require(all(_valid_sha(value) for value in raw), "Protected key set contains an invalid digest.")
    _require(raw == sorted(set(raw)), "Protected key set is not sorted and unique.")
    return set(raw)


def _canonical_group(value: str) -> str:
    clean = value.strip()
    match = _NEMOTRON_GROUP.fullmatch(clean)
    if match:
        return "nemotron-pii:" + match.group(1).lower()
    return clean


def _identity_aliases(identifier: str, group: str) -> set[str]:
    aliases = {identifier}
    match = _NEMOTRON_ID.fullmatch(identifier)
    if match:
        aliases.add("nemotron-pii:" + match.group(1).lower())
    aliases.add(_canonical_group(group))
    return aliases


def _row_keys(row: Mapping[str, object]) -> tuple[set[str], set[str], str, str]:
    identifier, group, text, text_key = (row.get(field) for field in ("id", "group_id", "text", "text_key"))
    _require(isinstance(identifier, str) and bool(identifier.strip()), "Protected row identity is malformed.")
    _require(isinstance(group, str) and bool(group.strip()), "Protected row group is malformed.")
    _require(isinstance(text, str) and bool(text.strip()), "Protected row text is malformed.")
    try:
        normalized = training_text_key(text)
        id_keys = {opaque_exclusion_key("id", alias) for alias in _identity_aliases(identifier, group)}
        group_key = opaque_exclusion_key("group", _canonical_group(group))
        normalized_key = opaque_exclusion_key("text_key", normalized)
        exact_key = _sha_text(text)
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("Protected row key derivation failed.") from None
    _require(isinstance(text_key, str) and text_key == normalized and bool(normalized),
             "Protected row normalized-text key is not canonical.")
    return id_keys, {group_key}, normalized_key, exact_key


def _validate_rows(
    rows: object,
    expected_count: int,
    *,
    source_family: str | None = None,
) -> tuple[set[str], set[str], set[str], set[str], Counter[str]]:
    _require(isinstance(rows, (list, tuple)) and len(rows) == expected_count,
             "Protected partition row count is invalid.")
    ids: set[str] = set()
    groups: set[str] = set()
    normalized: set[str] = set()
    exact: set[str] = set()
    source_counts: Counter[str] = Counter()
    raw_ids: set[str] = set()
    for index, row in enumerate(rows):
        _require(isinstance(row, Mapping), "Protected partition row is malformed.")
        row_ids, row_groups, normalized_key, exact_key = _row_keys(row)
        raw_id = row["id"]
        # Parent/group aliases may intentionally repeat across sibling rows;
        # the source row ID itself must still be unique.
        _require(raw_id not in raw_ids, "Protected partition contains duplicate identities.")
        _require(normalized_key not in normalized and exact_key not in exact,
                 "Protected partition contains duplicate text.")
        raw_ids.add(raw_id)
        ids.update(row_ids)
        groups.update(row_groups)
        normalized.add(normalized_key)
        exact.add(exact_key)
        if source_family is not None:
            _require(row.get("source_family") == source_family, "Held-out source identity is invalid.")
        elif index >= _ROW_COUNTS["reference_train"]:
            family = row.get("source_family")
            _require(isinstance(family, str) and family in _EXTERNAL_TRAIN_SOURCE_COUNTS,
                     "External training source identity is invalid.")
            source_counts[family] += 1
    return ids, groups, normalized, exact, source_counts


def _validate_index(index: object) -> tuple[dict[str, set[str]], dict[str, set[str]], set[str]]:
    _require(isinstance(index, Mapping) and set(index) == _INDEX_TOP_LEVEL_FIELDS,
             "Saved protected selection schema is invalid.")
    _require(index.get("schema_version") == 1 and type(index.get("seed")) is int and index["seed"] == 3102026,
             "Saved protected selection version or seed is invalid.")
    _require(index.get("dataset_revision") == _PIIMB_PIN
             and index.get("loader_revision") == _LOADER_REVISION
             and index.get("loader_canonical_lf_sha256") == _LOADER_SHA256
             and index.get("reproduced_twice") is True,
             "Saved protected selection source binding is invalid.")
    _require(index.get("algorithm") == "pinned PIIMB balanced full-scan reservoir and sampler order",
             "Saved protected selection algorithm is invalid.")
    _require(index.get("aggregate") == _AGGREGATE, "Saved protected selection aggregate is invalid.")

    records = index.get("records")
    _require(isinstance(records, list) and len(records) == 1000 and records == sorted(records, key=_canonical),
             "Saved protected selection records are incomplete or unsorted.")
    _require(index.get("sorted_records_sha256") == _sha_text(_canonical(records)),
             "Saved protected selection record commitment is invalid.")
    record_ids: set[str] = set()
    record_groups: set[str] = set()
    record_texts: set[str] = set()
    record_exact: set[str] = set()
    for record in records:
        _require(isinstance(record, Mapping) and set(record) == _RECORD_FIELDS,
                 "Saved protected selection record schema is invalid.")
        values = [record[name] for name in sorted(_RECORD_FIELDS)]
        _require(all(_valid_sha(value) for value in values), "Saved protected selection record digest is invalid.")
        record_ids.add(record["id_sha256"])
        record_groups.add(record["canonical_group_sha256"])
        record_texts.add(record["normalized_text_sha256"])
        record_exact.add(record["text_sha256"])
    _require(len(record_ids) == 1000 and len(record_groups) == 929
             and len(record_texts) == 1000 and len(record_exact) == 1000,
             "Saved protected selection record coverage is invalid.")

    key_sets_raw = index.get("key_sets")
    _require(isinstance(key_sets_raw, Mapping) and set(key_sets_raw) == set(_KEY_KINDS),
             "Saved protected selection key-set schema is invalid.")
    key_sets = {kind: _opaque_set(key_sets_raw[kind]) for kind in _KEY_KINDS}
    _require(record_ids.issubset(key_sets["ids"])
             and record_groups == key_sets["groups"] and record_texts == key_sets["texts"],
             "Saved protected records and key sets disagree.")
    _require(len(key_sets["groups"]) == 929 and len(key_sets["texts"]) == 1000,
             "Saved protected group/text coverage is invalid.")

    all_sets_raw = index.get("all_exclusion_key_sets")
    _require(isinstance(all_sets_raw, Mapping) and set(all_sets_raw) == set(_KEY_KINDS),
             "Committed prior exclusion-set schema is invalid.")
    all_sets = {kind: _opaque_set(all_sets_raw[kind]) for kind in _KEY_KINDS}
    _require(index.get("all_exclusion_key_sets_sha256") == _sha_text(_canonical(all_sets_raw)),
             "Committed prior exclusion-set digest is invalid.")
    _require(all(key_sets[kind].issubset(all_sets[kind]) for kind in _KEY_KINDS),
             "Committed prior exclusion sets omit selection keys.")
    return key_sets, all_sets, record_exact


def _validate_commitments(commitments: object) -> dict[str, object]:
    _require(isinstance(commitments, Mapping) and set(commitments) == _COMMITMENT_FIELDS,
             "Prepared input commitments are incomplete.")
    expected = {
        "prepared_manifest_sha256": _PREPARED_MANIFEST_SHA256,
        "exclusion_index_sha256": _EXCLUSION_INDEX_SHA256,
        "reference_train_sha256": _REFERENCE_TRAIN_SHA256,
        "reference_validation_sha256": _REFERENCE_VALIDATION_SHA256,
        "bootstrap_source_sha256": _BOOTSTRAP_SOURCE_SHA256,
    }
    result: dict[str, object] = {}
    for name, value in expected.items():
        _require(value == commitments.get(name), "Prepared input commitment differs from the frozen source.")
        result[name] = value
    partitions = commitments.get("partition_sha256")
    _require(isinstance(partitions, Mapping) and set(partitions) == _PARTITION_COMMITMENT_FIELDS,
             "Prepared partition commitments are incomplete.")
    _require(all(_valid_sha(value) for value in partitions.values()),
             "Prepared partition commitment is malformed.")
    _require(partitions.get("validation") == _REFERENCE_VALIDATION_SHA256,
             "Prepared validation partition commitment is not the frozen reference.")
    result["partition_sha256"] = {name: partitions[name] for name in sorted(partitions)}
    return result


def build_full_protected_key_union(
    *,
    approved_index: Mapping[str, object],
    reference_train: Sequence[Mapping[str, object]],
    reference_validation: Sequence[Mapping[str, object]],
    bootstrap_texts: Sequence[str],
    external_train: Sequence[Mapping[str, object]],
    nemotron_heldout: Sequence[Mapping[str, object]],
    meddies_heldout: Sequence[Mapping[str, object]],
    verified_commitments: Mapping[str, object],
) -> ProtectedKeyUnion:
    """Return the fixed full protected union from already validated parsed inputs.

    The caller must verify raw partition bytes against ``verified_commitments``
    and the prepared manifest before parsing. This function checks the frozen
    commitment values, the original parsed training prefix, exact fixed counts,
    selection record/key-set commitments, and canonical text keys. It never
    reads labels or accesses the locked selection.
    """
    commitments = _validate_commitments(verified_commitments)
    index_keys, committed_all, selection_exact = _validate_index(approved_index)

    for name, rows in (("reference_train", reference_train), ("reference_validation", reference_validation)):
        _require(isinstance(rows, (list, tuple)) and len(rows) == _ROW_COUNTS[name],
                 f"{name} reference cardinality is invalid.")
    _require(isinstance(bootstrap_texts, (list, tuple)) and len(bootstrap_texts) == _ROW_COUNTS["bootstrap_texts"],
             "Bootstrap reference cardinality is invalid.")
    _require(all(isinstance(text, str) and bool(text.strip()) for text in bootstrap_texts),
             "Bootstrap reference text is malformed.")
    _require(isinstance(external_train, (list, tuple))
             and len(external_train) == _ROW_COUNTS["external_train"],
             "Prior external training cardinality is invalid.")

    ref_train_keys = _validate_rows(reference_train, _ROW_COUNTS["reference_train"])
    ref_validation_keys = _validate_rows(reference_validation, _ROW_COUNTS["reference_validation"])
    _require(list(external_train[:_ROW_COUNTS["reference_train"]]) == list(reference_train),
             "Original training rows are not the exact parsed prefix of external training.")
    _, _, _, _, external_source_counts = _validate_rows(external_train, _ROW_COUNTS["external_train"])
    _require(dict(external_source_counts) == _EXTERNAL_TRAIN_SOURCE_COUNTS,
             "Prior external training source coverage is invalid.")
    nemotron_keys = _validate_rows(nemotron_heldout, _ROW_COUNTS["nemotron_heldout"], source_family="nemotron-pii")
    meddies_keys = _validate_rows(meddies_heldout, _ROW_COUNTS["meddies_heldout"], source_family="meddies-pii")

    try:
        anchor_normalized = {opaque_exclusion_key("text_key", training_text_key(text)) for text in bootstrap_texts}
        anchor_exact = {_sha_text(text) for text in bootstrap_texts}
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("Bootstrap protected-key derivation failed.") from None
    expected_committed = {kind: set(index_keys[kind]) for kind in _KEY_KINDS}
    for row_keys in (ref_train_keys, ref_validation_keys):
        expected_committed["ids"].update(row_keys[0])
        expected_committed["groups"].update(row_keys[1])
        expected_committed["texts"].update(row_keys[2])
    expected_committed["texts"].update(anchor_normalized)
    _require(expected_committed == committed_all,
             "Saved base exclusion keys do not cover exactly the pinned references and bootstrap anchors.")

    ids = set(committed_all["ids"])
    groups = set(committed_all["groups"])
    normalized = set(committed_all["texts"])
    exact = set(selection_exact) | anchor_exact
    counts: dict[str, int] = {
        "saved_selection_records": 1000,
        "saved_selection_groups": 929,
        "saved_selection_id_keys_including_aliases": len(index_keys["ids"]),
        "reference_train_rows": _ROW_COUNTS["reference_train"],
        "reference_validation_rows": _ROW_COUNTS["reference_validation"],
        "bootstrap_text_rows": _ROW_COUNTS["bootstrap_texts"],
        "external_train_rows_including_original_prefix": _ROW_COUNTS["external_train"],
        "external_training_nemotron_rows": _EXTERNAL_TRAIN_SOURCE_COUNTS["nemotron-pii"],
        "external_training_meddies_rows": _EXTERNAL_TRAIN_SOURCE_COUNTS["meddies-pii"],
        "nemotron_heldout_rows": _ROW_COUNTS["nemotron_heldout"],
        "meddies_heldout_rows": _ROW_COUNTS["meddies_heldout"],
    }
    partition_key_sets = {
        "external_train": _validate_rows(external_train, _ROW_COUNTS["external_train"]),
        "reference_validation": ref_validation_keys,
        "nemotron_heldout": nemotron_keys,
        "meddies_heldout": meddies_keys,
    }
    seen_by_kind = {"ids": set(), "groups": set(), "normalized": set(), "exact": set()}
    for partition_name in ("external_train", "reference_validation", "nemotron_heldout", "meddies_heldout"):
        part_ids, part_groups, part_normalized, part_exact, _ = partition_key_sets[partition_name]
        for kind, values in (("ids", part_ids), ("groups", part_groups),
                             ("normalized", part_normalized), ("exact", part_exact)):
            _require(not (seen_by_kind[kind] & values), "Prior external partitions overlap by protected key.")
            seen_by_kind[kind].update(values)
        ids.update(part_ids)
        groups.update(part_groups)
        normalized.update(part_normalized)
        exact.update(part_exact)

    protected = ProtectedKeys(frozenset(ids), frozenset(groups), frozenset(exact), frozenset(normalized))
    counts.update({
        "union_id_keys": len(protected.ids),
        "union_group_keys": len(protected.groups),
        "union_exact_text_hashes": len(protected.exact_text_sha256),
        "union_normalized_text_keys": len(protected.normalized_texts),
    })
    digest_payload = {
        "schema_version": 1,
        "verified_commitments": commitments,
        "keys": {
            "ids": sorted(protected.ids),
            "groups": sorted(protected.groups),
            "exact_text_sha256": sorted(protected.exact_text_sha256),
            "normalized_texts": sorted(protected.normalized_texts),
        },
    }
    return ProtectedKeyUnion(protected, tuple(sorted(counts.items())), _sha_text(_canonical(digest_payload)))
