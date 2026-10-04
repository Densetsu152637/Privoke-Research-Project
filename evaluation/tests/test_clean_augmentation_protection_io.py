"""Synthetic-only tests for frozen protected-union byte verification."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval.clean_augmentation_grouping import ProtectedKeys  # noqa: E402
from privoke_eval.clean_augmentation_protection import ProtectedKeyUnion  # noqa: E402
from privoke_eval.clean_augmentation_protection_io import (  # noqa: E402
    ProtectionInputError,
    _Contract,
    _FROZEN,
    _canonical_lf_sha256,
    _safe_training_samples,
    build_from_files,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _jsonl(rows: list[dict[str, object]]) -> bytes:
    return b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode() for row in rows)


def _bootstrap_source() -> bytes:
    additions = [(f"Extra {index}", "S1", "PU", ("X",)) for index in range(13)]
    additions_src = repr(additions)
    return (
        "def training_samples():\n"
        "    category_phrases = {'X': (" + ",".join(repr(f"Phrase {index}") for index in range(30)) + ",)}\n"
        "    samples = [(phrase, 'S1', 'PU', ('X',)) for category, phrases in category_phrases.items() for phrase in phrases]\n"
        f"    samples.extend({additions_src})\n"
        "    return samples\n"
    ).encode()


def _row(identifier: str, group: str, text: str, family: str | None = None) -> dict[str, object]:
    row: dict[str, object] = {"id": identifier, "group_id": group, "text": text, "text_key": text.lower()}
    if family:
        row["source_family"] = family
    return row


class CleanAugmentationProtectionIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.reference = self.root / "reference"
        self.expansion = self.root / "expansion"
        self.output = self.root / "out"
        self.reference.mkdir()
        self.expansion.mkdir()
        self.train_rows = [_row(f"ref:{i}", f"ref-group:{i}", f"ref text {i}") for i in range(2)]
        self.validation_rows = [_row(f"val:{i}", f"val-group:{i}", f"val text {i}") for i in range(2)]
        self.appended = [_row("nem:1", "nem:g1", "nem text", "nemotron-pii"),
                         _row("med:1", "med:g1", "med text", "meddies-pii")]
        self.external_rows = self.train_rows + self.appended
        self.nem_rows = [_row("nem-held:1", "nem-held:g1", "nem held text", "nemotron-pii")]
        self.med_rows = [_row("med-held:1", "med-held:g1", "med held text", "meddies-pii")]
        self.reference_train_raw = _jsonl(self.train_rows)
        self.reference_val_raw = _jsonl(self.validation_rows)
        self.index_raw = json.dumps({"sorted_records_sha256": "b" * 64}, sort_keys=True).encode()
        self.partition_raw = {
            "train": self.external_rows,
            "validation": self.validation_rows,
            "nemotron_heldout": self.nem_rows,
            "meddies_heldout": self.med_rows,
        }
        self.contract = _Contract(
            prepared_manifest_sha256="1" * 64,
            exclusion_index_sha256=_sha(self.index_raw),
            reference_train_sha256=_sha(self.reference_train_raw),
            reference_train_bytes=len(self.reference_train_raw),
            reference_validation_sha256=_sha(self.reference_val_raw),
            bootstrap_sha256=_sha(_bootstrap_source()),
            training_data_sha256=_sha((ROOT / "shared/python/privoke_model/training_data.py").read_bytes()),
            protocol_lf_sha256=_canonical_lf_sha256(b"protocol\r\n"),
            rubric_lf_sha256=_canonical_lf_sha256(b"rubric\r\n"),
            partition_sha256={name: _sha(_jsonl(rows)) for name, rows in self.partition_raw.items()},
            rows={name: len(rows) for name, rows in self.partition_raw.items()},
        )
        self.bootstrap = self.root / "bootstrap.py"
        self.bootstrap.write_bytes(_bootstrap_source())
        self.protocol = self.root / "protocol.md"
        self.protocol.write_bytes(b"protocol\r\n")
        self.rubric = self.root / "rubric.json"
        self.rubric.write_bytes(b"rubric\r\n")
        (self.reference / "train.jsonl").write_bytes(self.reference_train_raw)
        (self.reference / "validation.jsonl").write_bytes(self.reference_val_raw)
        for name, filename in (("train", "train.jsonl"), ("validation", "validation.jsonl"),
                               ("nemotron_heldout", "nemotron-heldout.jsonl"),
                               ("meddies_heldout", "meddies-heldout.jsonl")):
            (self.expansion / filename).write_bytes(_jsonl(self.partition_raw[name]))
        sources = {}
        from privoke_eval.clean_augmentation_protection_io import _SOURCE_PINS
        for source, pin in _SOURCE_PINS.items():
            sources[source] = {
                **{field: pin[field] for field in ("repo_id", "revision", "config", "split", "license")},
                "file": {"path": pin["path"], "row_count": pin["source_rows"], "lfs_sha256": "a" * 64},
            }
        self.manifest = {
            "schema_version": 1,
            "status": "prepared",
            "partition_files": {"train": "train.jsonl", "validation": "validation.jsonl",
                                "nemotron_heldout": "nemotron-heldout.jsonl", "meddies_heldout": "meddies-heldout.jsonl"},
            "partition_sha256": dict(self.contract.partition_sha256),
            "rows": dict(self.contract.rows),
            "source_revision": "a" * 40,
            "prepared_reference": {"train_sha256": self.contract.reference_train_sha256,
                                    "validation_sha256": self.contract.reference_validation_sha256,
                                    "train_bytes": self.contract.reference_train_bytes},
            "exclusion_index_file": "exclusion-index.json",
            "exclusion_index_sha256": self.contract.exclusion_index_sha256,
            "bootstrap_source_sha256": self.contract.bootstrap_sha256,
            "training_text_key_source_sha256": self.contract.training_data_sha256,
            "protocol_sha256": self.contract.protocol_lf_sha256,
            "protected_selection_sha256": "b" * 64,
            "sources": sources,
        }
        self.manifest_raw = json.dumps(self.manifest, sort_keys=True).encode()
        (self.expansion / "manifest.json").write_bytes(self.manifest_raw)
        (self.expansion / "exclusion-index.json").write_bytes(self.index_raw)
        self.contract = replace(self.contract, prepared_manifest_sha256=_sha(self.manifest_raw))

    def tearDown(self):
        self.temp.cleanup()

    def _builder(self, **kwargs):
        self.assertEqual(len(kwargs["bootstrap_texts"]), 43)
        self.assertEqual(kwargs["reference_train"], self.train_rows)
        self.assertEqual(kwargs["external_train"], self.external_rows)
        return ProtectedKeyUnion(
            ProtectedKeys(frozenset({"a" * 64}), frozenset({"b" * 64}),
                          frozenset({"c" * 64}), frozenset({"d" * 64})),
            (("synthetic_rows", 1),), "e" * 64,
        )

    def _run(self, **changes):
        values = {
            "reference_dir": self.reference,
            "expansion_dir": self.expansion,
            "bootstrap_source": self.bootstrap,
            "protocol_file": self.protocol,
            "rubric_file": self.rubric,
            "output_dir": self.output,
            "source_revision": "a" * 40,
            "_contract": self.contract,
            "_union_builder": self._builder,
            "_test_only_allow_output_outside_results": True,
        }
        values.update(changes)
        return build_from_files(**values)

    def test_build_writes_exact_artifact_shape_and_count_only_manifest(self):
        receipt = self._run()
        artifact = json.loads((self.output / "protected-union.json").read_text(encoding="utf-8"))
        self.assertEqual(set(artifact), {"schema_version", "kind", "union_sha256", "coverage_counts",
                                        "verified_commitments", "keys"})
        self.assertEqual(artifact["kind"], "privoke-clean-protected-union")
        self.assertEqual(receipt["status"], "protected_union_built")
        manifest = json.loads((self.output / "manifest.json").read_text(encoding="utf-8"))
        self.assertNotIn("keys", manifest)
        self.assertNotIn("phrase", json.dumps(manifest).lower())
        self.assertNotIn("ref text", json.dumps(manifest).lower())

    def test_tampered_bytes_fail_before_json_parse_and_preserve_failure_receipt(self):
        (self.expansion / "train.jsonl").write_bytes(b"not valid json")
        with self.assertRaises(ProtectionInputError):
            self._run()
        receipt = json.loads((self.output / "failure.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["status"], "failed")
        self.assertNotIn("not valid json", (self.output / "failure.json").read_text(encoding="utf-8"))

    def test_training_prefix_is_byte_exact_not_only_parsed(self):
        raw = (self.expansion / "train.jsonl").read_bytes()
        (self.expansion / "train.jsonl").write_bytes(raw.replace(b"ref text 0", b"ref text 0 ", 1))
        self.contract = replace(self.contract, partition_sha256={**self.contract.partition_sha256,
                                                                   "train": _sha((self.expansion / "train.jsonl").read_bytes())})
        self.manifest["partition_sha256"] = dict(self.contract.partition_sha256)
        manifest_raw = json.dumps(self.manifest, sort_keys=True).encode()
        (self.expansion / "manifest.json").write_bytes(manifest_raw)
        self.contract = replace(self.contract, prepared_manifest_sha256=_sha(manifest_raw))
        with self.assertRaisesRegex(ProtectionInputError, "prefix"):
            self._run()

    def test_manifest_partition_map_and_revision_are_bound(self):
        self.manifest["partition_files"]["development"] = "development.jsonl"
        raw = json.dumps(self.manifest, sort_keys=True).encode()
        (self.expansion / "manifest.json").write_bytes(raw)
        self.contract = replace(self.contract, prepared_manifest_sha256=_sha(raw))
        with self.assertRaises(ProtectionInputError):
            self._run()

    def test_refuses_existing_output_directory_and_symlinked_partition(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ProtectionInputError, "existing"):
            self._run()
        self.output.rmdir()
        target = self.expansion / "target.jsonl"
        target.write_bytes((self.expansion / "train.jsonl").read_bytes())
        train_path = self.expansion / "train.jsonl"
        original_is_symlink = Path.is_symlink
        with patch.object(Path, "is_symlink", autospec=True,
                          side_effect=lambda path: path == train_path or original_is_symlink(path)):
            with self.assertRaises(ProtectionInputError):
                self._run()

    def test_bootstrap_extractor_never_executes_source_and_requires_43_authored_texts(self):
        self.assertEqual(len(_safe_training_samples(_bootstrap_source())), 43)
        source = _bootstrap_source() + b"\nraise RuntimeError('must not execute')\n"
        self.assertEqual(len(_safe_training_samples(source)), 43)

    def test_rejects_invalid_normalizer_protocol_and_rubric_commitments(self):
        self.protocol.write_bytes(b"modified\n")
        with self.assertRaisesRegex(ProtectionInputError, "Protocol or rubric"):
            self._run()


if __name__ == "__main__":
    unittest.main()
