"""Synthetic-only fixed-cardinality tests for clean-augmentation protection."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval.clean_augmentation_grouping import opaque_exclusion_key  # noqa: E402
from privoke_eval.clean_augmentation_protection import (  # noqa: E402
    _AGGREGATE,
    _BOOTSTRAP_SOURCE_SHA256,
    _EXCLUSION_INDEX_SHA256,
    _LOADER_REVISION,
    _LOADER_SHA256,
    _PIIMB_PIN,
    _PREPARED_MANIFEST_SHA256,
    _REFERENCE_TRAIN_SHA256,
    _REFERENCE_VALIDATION_SHA256,
    build_full_protected_key_union,
)
from privoke_model.training_data import training_text_key  # noqa: E402


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _row(identifier: str, group: str, text: str, *, family: str | None = None) -> dict[str, object]:
    row: dict[str, object] = {
        "id": identifier,
        "group_id": group,
        "text": text,
        "text_key": training_text_key(text),
        # Labels are present to mirror parsed project rows; the helper must not use them.
        "expected_has_pii": True,
    }
    if family is not None:
        row["source_family"] = family
    return row


def _row_key_sets(row: dict[str, object]) -> dict[str, set[str]]:
    identifier = row["id"]
    group = row["group_id"]
    text = row["text"]
    assert isinstance(identifier, str) and isinstance(group, str) and isinstance(text, str)
    canonical_group = group.strip()
    aliases = {identifier, canonical_group}
    import re

    match = re.fullmatch(r"(?:piimb:)?nemotron-pii:([0-9a-fA-F]{32})(?:_s\d+)?", identifier)
    if match:
        aliases.add("nemotron-pii:" + match.group(1).lower())
    return {
        "ids": {opaque_exclusion_key("id", alias) for alias in aliases},
        "groups": {opaque_exclusion_key("group", canonical_group)},
        "texts": {opaque_exclusion_key("text_key", training_text_key(text))},
    }


def _fixture() -> dict[str, object]:
    reference_train = [_row(f"reference-train:{i}", f"reference-train-group:{i}", f"Original train fixture {i}")
                       for i in range(3832)]
    reference_validation = [_row(f"reference-validation:{i}", f"reference-validation-group:{i}",
                                 f"Original validation fixture {i}") for i in range(968)]
    bootstrap_texts = [reference_train[0]["text"].upper()] + [f"Bootstrap fixture {i}" for i in range(42)]

    records: list[dict[str, str]] = []
    key_sets = {kind: set() for kind in ("ids", "groups", "texts")}
    for index in range(1000):
        group = f"nemotron-pii:{index % 929:032x}"
        row = _row(f"piimb:{group}_s{index}", group, f"Opaque selected fixture {index}")
        for kind, values in _row_key_sets(row).items():
            key_sets[kind].update(values)
        identifier, group_id, text = row["id"], row["group_id"], row["text"]
        assert isinstance(identifier, str) and isinstance(group_id, str) and isinstance(text, str)
        records.append({
            "id_sha256": opaque_exclusion_key("id", identifier),
            "canonical_group_sha256": opaque_exclusion_key("group", group_id),
            "normalized_text_sha256": opaque_exclusion_key("text_key", training_text_key(text)),
            "text_sha256": _sha(text),
        })
    records.sort(key=_canonical)

    all_sets = {kind: set(values) for kind, values in key_sets.items()}
    for rows in (reference_train, reference_validation):
        for row in rows:
            for kind, values in _row_key_sets(row).items():
                all_sets[kind].update(values)
    all_sets["texts"].update(opaque_exclusion_key("text_key", training_text_key(text)) for text in bootstrap_texts)
    # A committed alias-like key exercises preservation of opaque extras.
    alias_extra = opaque_exclusion_key("id", "committed opaque group alias")
    key_sets["ids"].add(alias_extra)
    all_sets["ids"].add(alias_extra)
    serialized_keys = {kind: sorted(values) for kind, values in key_sets.items()}
    serialized_all = {kind: sorted(values) for kind, values in all_sets.items()}
    index = {
        "schema_version": 1,
        "records": records,
        "key_sets": serialized_keys,
        "algorithm": "pinned PIIMB balanced full-scan reservoir and sampler order",
        "loader_revision": _LOADER_REVISION,
        "loader_canonical_lf_sha256": _LOADER_SHA256,
        "dataset_revision": _PIIMB_PIN,
        "seed": 3102026,
        "aggregate": deepcopy(_AGGREGATE),
        "sorted_records_sha256": _sha(_canonical(records)),
        "reproduced_twice": True,
        "all_exclusion_key_sets": serialized_all,
        "all_exclusion_key_sets_sha256": _sha(_canonical(serialized_all)),
    }

    external_train = [dict(row) for row in reference_train]
    for i in range(13168):
        external_train.append(_row(f"nemotron-pii:train:{i}", f"nemotron-pii:train-group:{i // 2}",
                                   f"Nemotron training fixture {i}", family="nemotron-pii"))
    for i in range(2993):
        external_train.append(_row(f"meddies-pii:train:{i}", f"meddies-pii:train-family:{i}",
                                   f"Meddies training fixture {i}", family="meddies-pii"))
    nemotron_heldout = [_row(f"nemotron-pii:heldout:{i}", f"nemotron-pii:heldout-group:{i}",
                             f"Nemotron heldout fixture {i}", family="nemotron-pii") for i in range(1000)]
    meddies_heldout = [_row(f"meddies-pii:heldout:{i}", f"meddies-pii:heldout-family:{i}",
                            f"Meddies heldout fixture {i}", family="meddies-pii") for i in range(999)]
    commitments = {
        "prepared_manifest_sha256": _PREPARED_MANIFEST_SHA256,
        "exclusion_index_sha256": _EXCLUSION_INDEX_SHA256,
        "reference_train_sha256": _REFERENCE_TRAIN_SHA256,
        "reference_validation_sha256": _REFERENCE_VALIDATION_SHA256,
        "bootstrap_source_sha256": _BOOTSTRAP_SOURCE_SHA256,
        "partition_sha256": {
            "train": "a" * 64,
            "validation": _REFERENCE_VALIDATION_SHA256,
            "nemotron_heldout": "b" * 64,
            "meddies_heldout": "c" * 64,
        },
    }
    return {
        "approved_index": index,
        "reference_train": reference_train,
        "reference_validation": reference_validation,
        "bootstrap_texts": bootstrap_texts,
        "external_train": external_train,
        "nemotron_heldout": nemotron_heldout,
        "meddies_heldout": meddies_heldout,
        "verified_commitments": commitments,
        "alias_extra": alias_extra,
    }


class CleanAugmentationProtectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inputs = _fixture()

    def _build(self, **updates):
        inputs = dict(self.inputs)
        inputs.update(updates)
        inputs.pop("alias_extra", None)
        return build_full_protected_key_union(**inputs)

    def test_builds_fixed_union_and_preserves_committed_opaque_aliases(self):
        result = self._build()
        counts = dict(result.coverage_counts)
        self.assertEqual(counts["saved_selection_records"], 1000)
        self.assertEqual(counts["saved_selection_groups"], 929)
        self.assertEqual(counts["reference_train_rows"], 3832)
        self.assertEqual(counts["reference_validation_rows"], 968)
        self.assertEqual(counts["bootstrap_text_rows"], 43)
        self.assertEqual(counts["external_train_rows_including_original_prefix"], 19993)
        self.assertEqual(counts["nemotron_heldout_rows"], 1000)
        self.assertEqual(counts["meddies_heldout_rows"], 999)
        self.assertIn(self.inputs["alias_extra"], result.keys.ids)
        self.assertEqual(len(result.union_sha256), 64)

    def test_direct_exact_text_and_shared_normalized_text_keys_are_separate(self):
        result = self._build()
        original = self.inputs["reference_train"][0]["text"]
        anchor = self.inputs["bootstrap_texts"][0]
        self.assertNotEqual(original, anchor)
        self.assertIn(_sha(original), result.keys.exact_text_sha256)
        self.assertIn(_sha(anchor), result.keys.exact_text_sha256)
        normalized = opaque_exclusion_key("text_key", training_text_key(original))
        self.assertIn(normalized, result.keys.normalized_texts)
        self.assertEqual(len(result.keys.exact_text_sha256), len(result.keys.normalized_texts) + 1)

    def test_repeated_group_aliases_within_a_partition_are_preserved(self):
        result = self._build()
        first = self.inputs["external_train"][3832]
        sibling = self.inputs["external_train"][3833]
        self.assertEqual(first["group_id"], sibling["group_id"])
        group_key = opaque_exclusion_key("group", first["group_id"])
        self.assertIn(group_key, result.keys.groups)

    def test_fixed_cardinality_shortfalls_fail_closed(self):
        with self.assertRaises(ValueError):
            self._build(bootstrap_texts=self.inputs["bootstrap_texts"][:-1])
        with self.assertRaises(ValueError):
            self._build(external_train=self.inputs["external_train"][:-1])
        with self.assertRaises(ValueError):
            self._build(meddies_heldout=self.inputs["meddies_heldout"][:-1])

    def test_selection_pin_seed_and_aggregate_are_fixed(self):
        index = deepcopy(self.inputs["approved_index"])
        index["seed"] += 1
        with self.assertRaisesRegex(ValueError, "version or seed"):
            self._build(approved_index=index)
        index = deepcopy(self.inputs["approved_index"])
        index["aggregate"]["selected"] -= 1
        with self.assertRaisesRegex(ValueError, "aggregate"):
            self._build(approved_index=index)

    def test_original_training_prefix_must_match_parsed_reference_rows(self):
        external = list(self.inputs["external_train"])
        external[0] = dict(
            external[0],
            text="changed fixture text",
            text_key=training_text_key("changed fixture text"),
        )
        with self.assertRaisesRegex(ValueError, "exact parsed prefix"):
            self._build(external_train=external)

    def test_no_label_values_are_used_or_inferred(self):
        reference_train = list(self.inputs["reference_train"])
        reference_train[0] = dict(reference_train[0], expected_has_pii=False)
        external_train = list(self.inputs["external_train"])
        external_train[0] = dict(external_train[0], expected_has_pii=False)
        self._build(reference_train=reference_train, external_train=external_train)

    def test_record_commitment_and_exact_text_hash_are_required(self):
        index = deepcopy(self.inputs["approved_index"])
        index["records"][0]["text_sha256"] = "not-a-sha256"
        index["records"].sort(key=_canonical)
        index["sorted_records_sha256"] = _sha(_canonical(index["records"]))
        with self.assertRaisesRegex(ValueError, "record digest"):
            self._build(approved_index=index)
        index = deepcopy(self.inputs["approved_index"])
        del index["records"][0]["text_sha256"]
        index["sorted_records_sha256"] = _sha(_canonical(index["records"]))
        with self.assertRaisesRegex(ValueError, "record schema"):
            self._build(approved_index=index)

    def test_record_ids_must_be_contained_in_committed_key_sets(self):
        index = deepcopy(self.inputs["approved_index"])
        missing = index["records"][0]["id_sha256"]
        index["key_sets"]["ids"].remove(missing)
        index["all_exclusion_key_sets"]["ids"].remove(missing)
        index["all_exclusion_key_sets_sha256"] = _sha(_canonical(index["all_exclusion_key_sets"]))
        with self.assertRaisesRegex(ValueError, "records and key sets"):
            self._build(approved_index=index)

    def test_keyset_records_and_committed_alias_coverage_must_match(self):
        index = deepcopy(self.inputs["approved_index"])
        index["all_exclusion_key_sets"]["ids"].remove(self.inputs["alias_extra"])
        index["all_exclusion_key_sets_sha256"] = _sha(_canonical(index["all_exclusion_key_sets"]))
        with self.assertRaisesRegex(ValueError, "omit selection keys"):
            self._build(approved_index=index)
        index = deepcopy(self.inputs["approved_index"])
        index["key_sets"]["texts"].pop()
        with self.assertRaisesRegex(ValueError, "records and key sets"):
            self._build(approved_index=index)

    def test_all_exclusion_commitment_covers_reference_and_bootstrap_keys(self):
        index = deepcopy(self.inputs["approved_index"])
        anchor = self.inputs["bootstrap_texts"][-1]
        anchor_key = opaque_exclusion_key("text_key", training_text_key(anchor))
        index["all_exclusion_key_sets"]["texts"].remove(anchor_key)
        index["all_exclusion_key_sets_sha256"] = _sha(_canonical(index["all_exclusion_key_sets"]))
        with self.assertRaisesRegex(ValueError, "exactly the pinned references"):
            self._build(approved_index=index)

    def test_source_commitments_and_partition_commitments_are_mandatory(self):
        commitments = dict(self.inputs["verified_commitments"])
        commitments["exclusion_index_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "frozen source"):
            self._build(verified_commitments=commitments)
        commitments = dict(self.inputs["verified_commitments"])
        commitments["partition_sha256"] = dict(commitments["partition_sha256"])
        commitments["partition_sha256"].pop("nemotron_heldout")
        with self.assertRaisesRegex(ValueError, "partition commitments are incomplete"):
            self._build(verified_commitments=commitments)

    def test_external_partition_digest_must_be_well_formed(self):
        commitments = deepcopy(self.inputs["verified_commitments"])
        commitments["partition_sha256"]["train"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "partition commitment is malformed"):
            self._build(verified_commitments=commitments)

    def test_heldout_source_identity_and_partition_schema_are_checked(self):
        heldout = list(self.inputs["nemotron_heldout"])
        heldout[0] = dict(heldout[0], source_family="meddies-pii")
        with self.assertRaisesRegex(ValueError, "Held-out source identity"):
            self._build(nemotron_heldout=heldout)
        train = list(self.inputs["external_train"])
        train[3832] = dict(train[3832], text_key="not-a-canonical-key")
        with self.assertRaisesRegex(ValueError, "normalized-text key"):
            self._build(external_train=train)

    def test_prior_external_partitions_must_be_disjoint(self):
        heldout = list(self.inputs["meddies_heldout"])
        source_text = self.inputs["external_train"][4000]["text"]
        heldout[0] = dict(heldout[0], text=source_text, text_key=training_text_key(source_text))
        with self.assertRaisesRegex(ValueError, "partitions overlap"):
            self._build(meddies_heldout=heldout)

    def test_no_identifier_or_text_is_echoed_in_validation_errors(self):
        secret_marker = "synthetic-secret-marker-never-echo"
        train = list(self.inputs["external_train"])
        train[0] = dict(train[0], text=secret_marker, text_key="bad")
        with self.assertRaises(ValueError) as caught:
            self._build(external_train=train)
        self.assertNotIn(secret_marker, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
