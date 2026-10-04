"""Synthetic-only tests for aggregate AdvPIIBench structure handling."""

from __future__ import annotations

import builtins
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval.advpii_native import parse_native_row  # noqa: E402
from privoke_eval.advpii_structure import (  # noqa: E402
    _EXPECTED_COMMITMENTS,
    _EXPECTED_INPUT_SOURCE_HASHES,
    _FIXED_COVERAGE,
    _PROTECTION_HELPER_FIELDS,
    _PROPOSED_PARTITION_QUOTAS,
    _PROPOSED_SOURCE_QUOTAS,
    PARQUET_SIZE,
    aggregate_scan,
    canonical_json_bytes,
    open_verified_parquet,
    parse_unique_batches,
    require_frozen_text_inputs,
    validate_protected_union,
    validate_source_audit,
    validate_training_data_source,
)
from privoke_eval.clean_augmentation_grouping import ProtectedKeys, opaque_exclusion_key  # noqa: E402

_SCRIPT_PATH = ROOT / "evaluation/scan-advpii-structure.py"
_SPEC = importlib.util.spec_from_file_location("scan_advpii_structure", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CLI)


def _row(uid: int, input_id: int, category: str, text: str, *, value: str | None = None):
    spans = []
    attack = {"pii": [], "context": []}
    if value is not None:
        start = text.index(value)
        spans = [{
            "type": "email", "start": start, "end": start + len(value),
            "value": value, "value_fuzzy": None,
        }]
    return {
        "uid": uid,
        "input_id": input_id,
        "category": category,
        "attack_target": attack,
        "llm_input": text,
        "pii_spans": spans,
    }


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _write_union(directory: Path, *, bad_coverage: bool = False):
    keys = {
        "ids": [_sha("id")],
        "groups": [_sha("group")],
        "exact_text_sha256": [_sha("exact")],
        "normalized_texts": [_sha("normalized")],
    }
    coverage = dict(_FIXED_COVERAGE)
    coverage.update({
        "saved_selection_id_keys_including_aliases": 1000,
        "union_id_keys": len(keys["ids"]),
        "union_group_keys": len(keys["groups"]),
        "union_exact_text_hashes": len(keys["exact_text_sha256"]),
        "union_normalized_text_keys": len(keys["normalized_texts"]),
    })
    if bad_coverage:
        coverage["reference_train_rows"] -= 1
    payload = {
        "schema_version": 1,
        "verified_commitments": _EXPECTED_COMMITMENTS,
        "keys": keys,
    }
    union_sha = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    union = {
        "schema_version": 1,
        "kind": "privoke-clean-protected-union",
        "union_sha256": union_sha,
        "coverage_counts": coverage,
        "verified_commitments": _EXPECTED_COMMITMENTS,
        "keys": keys,
    }
    union_path = directory / "protected-union.json"
    union_bytes = canonical_json_bytes(union) + b"\n"
    union_path.write_bytes(union_bytes)
    receipt = {
        "schema_version": 1,
        "status": "protected_union_built",
        "source_revision": "a" * 40,
        "prepared_source_revision": "85c7f475fb8ebd1529254e4135b774d98505ddb1",
        "artifact_file": "protected-union.json",
        "artifact_sha256": hashlib.sha256(union_bytes).hexdigest(),
        "union_sha256": union_sha,
        "coverage_counts": coverage,
        "input_source_hashes": _EXPECTED_INPUT_SOURCE_HASHES,
        "helper_source_hashes": {
            name: _EXPECTED_INPUT_SOURCE_HASHES["training_data_source"]
            if name == "training_data_sha256" else _sha(name)
            for name in sorted(_PROTECTION_HELPER_FIELDS)
        },
        "packages": {"python": "3.13.0"},
        "limitations": ["Synthetic fixture; source labels remain unreviewed."],
    }
    receipt_path = directory / "receipt.json"
    receipt_bytes = canonical_json_bytes(receipt) + b"\n"
    receipt_path.write_bytes(receipt_bytes)
    return union_path, receipt_path, hashlib.sha256(receipt_bytes).hexdigest()


class AggregateStructureTests(unittest.TestCase):
    def test_quota_arithmetic_matches_frozen_three_partition_protocol(self):
        self.assertEqual(_PROPOSED_PARTITION_QUOTAS["train"], {
            "positive": 2000, "negative": 1600, "hard_negative": 400,
        })
        self.assertEqual(_PROPOSED_PARTITION_QUOTAS["validation"], {
            "positive": 1000, "negative": 750, "hard_negative": 250,
        })
        self.assertEqual(_PROPOSED_PARTITION_QUOTAS["test"], {
            "positive": 1000, "negative": 750, "hard_negative": 250,
        })
        self.assertEqual(_PROPOSED_SOURCE_QUOTAS, {
            "positive": 4000, "negative": 3100, "hard_negative": 900,
        })
        self.assertEqual(sum(_PROPOSED_SOURCE_QUOTAS.values()), 8000)

    def test_full_component_closure_precedes_protected_category_ceilings(self):
        rows = [
            parse_native_row(_row(1, 101, "positive", "Prompt Alice@example.test", value="Alice@example.test")),
            parse_native_row(_row(2, 202, "negative", "Bridge row")),
            parse_native_row(_row(3, 202, "hard_negative", "Sibling lookalike")),
            parse_native_row(_row(4, 404, "negative", "Other prompt")),
        ]
        protected = ProtectedKeys(ids=frozenset({opaque_exclusion_key("id", "advpiibench:uid:3")}))
        report, graph = aggregate_scan(rows, protected, expected_rows=4)
        self.assertEqual(graph.component_count, 3)
        self.assertEqual(report["row_count"], 4)
        self.assertEqual(report["uid_unique_count"], 4)
        self.assertEqual(report["protected_component_count"], 1)
        self.assertEqual(report["native_category_row_ceilings_after_structure_and_protection"], {
            "positive": 1, "negative": 1, "hard_negative": 0,
        })
        self.assertEqual(report["native_category_component_ceilings_after_structure_and_protection"], {
            "hard_negative": 0, "negative": 1, "positive": 1,
        })
        self.assertNotIn("Prompt Alice", repr(report))
        self.assertIn("broad reviewed labels", report["interpretation"])

    def test_count_scan_rejects_wrong_full_row_count(self):
        parsed = [parse_native_row(_row(1, 1, "negative", "Only row"))]
        with self.assertRaisesRegex(ValueError, "row count"):
            aggregate_scan(parsed, ProtectedKeys(), expected_rows=2)

    def test_protected_union_and_receipt_accept_exact_frozen_commitments(self):
        with tempfile.TemporaryDirectory() as temp:
            union_path, receipt_path, receipt_sha = _write_union(Path(temp))
            protected, metadata = validate_protected_union(union_path, receipt_path, receipt_sha)
        self.assertEqual(len(protected.ids), 1)
        self.assertEqual(len(protected.exact_text_sha256), 1)
        self.assertEqual(metadata["coverage_counts"]["reference_train_rows"], 3832)
        self.assertEqual(
            metadata["verified_commitments"]["partition_sha256"],
            _EXPECTED_COMMITMENTS["partition_sha256"],
        )

    def test_protected_union_rejects_bad_coverage_tamper_receipt_and_source_commitment(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            union_path, receipt_path, receipt_sha = _write_union(directory, bad_coverage=True)
            with self.assertRaisesRegex(ValueError, "coverage"):
                validate_protected_union(union_path, receipt_path, receipt_sha)
            union_path, receipt_path, receipt_sha = _write_union(directory)
            altered = receipt_path.read_bytes() + b" "
            receipt_path.write_bytes(altered)
            with self.assertRaisesRegex(ValueError, "receipt bytes"):
                validate_protected_union(union_path, receipt_path, receipt_sha)
            union_path, receipt_path, receipt_sha = _write_union(directory)
            union = json.loads(union_path.read_text())
            union["verified_commitments"]["prepared_manifest_sha256"] = "0" * 64
            digest_payload = {
                "schema_version": union["schema_version"],
                "verified_commitments": union["verified_commitments"],
                "keys": union["keys"],
            }
            union["union_sha256"] = hashlib.sha256(canonical_json_bytes(digest_payload)).hexdigest()
            union_bytes = canonical_json_bytes(union) + b"\n"
            union_path.write_bytes(union_bytes)
            receipt = json.loads(receipt_path.read_text())
            receipt["artifact_sha256"] = hashlib.sha256(union_bytes).hexdigest()
            receipt["union_sha256"] = union["union_sha256"]
            receipt["verified_commitments"] = union["verified_commitments"]
            receipt_bytes = canonical_json_bytes(receipt) + b"\n"
            receipt_path.write_bytes(receipt_bytes)
            with self.assertRaisesRegex(ValueError, "source commitments"):
                validate_protected_union(union_path, receipt_path, hashlib.sha256(receipt_bytes).hexdigest())

    def test_wrong_receipt_hash_fails_and_undercovered_union_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            union_path, receipt_path, receipt_sha = _write_union(Path(temp))
            with self.assertRaisesRegex(ValueError, "receipt bytes"):
                validate_protected_union(union_path, receipt_path, "0" * 64)
            union = json.loads(union_path.read_text())
            union["coverage_counts"]["union_id_keys"] = 0
            union_path.write_bytes(canonical_json_bytes(union) + b"\n")
            with self.assertRaisesRegex(ValueError, "key coverage"):
                validate_protected_union(union_path, receipt_path, receipt_sha)

    def test_bad_local_parquet_hash_fails_before_importing_pyarrow(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fake.parquet"
            path.write_bytes(b"x" * PARQUET_SIZE)
            original_import = builtins.__import__

            def guarded_import(name, *args, **kwargs):
                if name.startswith("pyarrow"):
                    raise AssertionError("Parquet reader was imported before byte verification")
                return original_import(name, *args, **kwargs)

            builtins.__import__ = guarded_import
            try:
                with self.assertRaisesRegex(ValueError, "bytes differ"):
                    open_verified_parquet(path)
            finally:
                builtins.__import__ = original_import

    def test_duplicate_uids_across_batch_boundaries_are_fatal(self):
        class Batch:
            def __init__(self, rows):
                self.rows = rows

            def to_pylist(self):
                return self.rows

        batches = [
            Batch([_row(51, 1, "negative", "First")]),
            Batch([_row(51, 2, "positive", "Second", value=None)]),
        ]
        with self.assertRaisesRegex(ValueError, "Duplicate UID"):
            tuple(parse_unique_batches(batches))

    def test_pinned_input_hashes_reject_changed_protocol_or_source_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "wrong.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Protocol or rubric"):
                require_frozen_text_inputs(path, path)
            with self.assertRaisesRegex(ValueError, "Source audit bytes"):
                validate_source_audit(path)
            with self.assertRaisesRegex(ValueError, "normalizer source"):
                validate_training_data_source(path)

    def test_receipt_input_source_hashes_are_checked_even_when_receipt_hash_is_recomputed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            union_path, receipt_path, _ = _write_union(directory)
            receipt = json.loads(receipt_path.read_text())
            receipt["input_source_hashes"]["reference_train"] = "0" * 64
            raw = canonical_json_bytes(receipt) + b"\n"
            receipt_path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "input-source commitments"):
                validate_protected_union(union_path, receipt_path, hashlib.sha256(raw).hexdigest())


class ScannerOutputTests(unittest.TestCase):
    def _args(self, output: Path):
        return type("Args", (), {
            "output": output,
            "source_revision": "bad-revision",
        })()

    def test_failed_provenance_attempt_writes_safe_failure_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "attempt"
            self.assertEqual(_CLI.scan(self._args(output)), 1)
            failure = json.loads((output / "failure.json").read_text())
            self.assertEqual(failure["status"], "failed")
            self.assertEqual(failure["stage"], "validate_bindings")
            self.assertNotIn("bad-revision", repr(failure))

    def test_existing_output_is_refused_without_modification(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "existing"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("preserve")
            with self.assertRaises(FileExistsError):
                _CLI.scan(self._args(output))
            self.assertEqual(sentinel.read_text(), "preserve")
            self.assertEqual(sorted(path.name for path in output.iterdir()), ["keep.txt"])


if __name__ == "__main__":
    unittest.main()
