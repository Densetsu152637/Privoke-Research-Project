"""Synthetic-only tests for restricted AdvPIIBench review-package I/O."""

from __future__ import annotations

import hashlib
import importlib.util
import contextlib
import io as text_io
import json
from pathlib import Path
import secrets
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval import advpii_review as review  # noqa: E402
from privoke_eval import advpii_review_io as io  # noqa: E402
from privoke_eval.clean_augmentation_grouping import ProtectedKeys  # noqa: E402


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _source_row(uid: int, input_id: int, category: str, text: str, *, value: str | None = None):
    spans = []
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
        "attack_target": {"pii": [], "context": []},
        "llm_input": text,
        "pii_spans": spans,
    }


class _Batch:
    def __init__(self, rows):
        self.rows = rows
        self.schema = object()
        self.converted = False

    def to_pylist(self):
        self.converted = True
        return list(self.rows)


class _FakeParquet:
    schema_arrow = object()

    def __init__(self, batches, count):
        self._batches = batches
        self.metadata = type("Meta", (), {"num_rows": count})()

    def iter_batches(self, *, batch_size):
        assert batch_size == 256
        self.iterated = True
        return iter(self._batches)


class PinManifestTests(unittest.TestCase):
    def test_pin_manifest_binds_raw_and_canonical_source_bytes(self):
        revision = "1" * 40
        manifest = io.build_pin_manifest(ROOT, revision)
        self.assertEqual(set(manifest["files"]), set(io._PIN_FILES))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pins.json"
            raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            path.write_bytes(raw)
            actual, digest = io.validate_pin_manifest(path, _sha(raw), revision, ROOT)
            self.assertEqual(actual, manifest["files"])
            self.assertEqual(digest, _sha(raw))
            with self.assertRaisesRegex(ValueError, "host commitment"):
                io.validate_pin_manifest(path, "0" * 64, revision, ROOT)

    def test_pin_manifest_rejects_wrong_revision_and_inventory(self):
        revision = "2" * 40
        manifest = io.build_pin_manifest(ROOT, revision)
        manifest["source_revision"] = "3" * 40
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "pins.json"
            raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "identity or file inventory"):
                io.validate_pin_manifest(path, _sha(raw), revision, ROOT)


class ReviewIOTests(unittest.TestCase):
    def _cli(self):
        path = ROOT / "evaluation/prepare-advpii-review.py"
        spec = importlib.util.spec_from_file_location("prepare_advpii_review_runtime", path)
        self.assertIsNotNone(spec)
        cli = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cli)
        return cli

    def _cli_args(self, output: Path) -> list[str]:
        return [
            "--parquet", "UNUSED_PRIVATE_INPUT_MARKER.parquet",
            "--source-audit", "UNUSED_PRIVATE_INPUT_MARKER-audit.json",
            "--protocol", "UNUSED_PRIVATE_INPUT_MARKER-protocol.md",
            "--rubric", "UNUSED_PRIVATE_INPUT_MARKER-rubric.json",
            "--protected-union", "UNUSED_PRIVATE_INPUT_MARKER-protected-union.json",
            "--protection-receipt", "UNUSED_PRIVATE_INPUT_MARKER-receipt.json",
            "--protection-receipt-sha256", "a" * 64,
            "--pin-manifest", "UNUSED_PRIVATE_INPUT_MARKER-pins.json",
            "--pin-manifest-sha256", "b" * 64,
            "--source-revision", "c" * 40,
            "--output", str(output),
        ]

    def _paths(self, root: Path, output: Path) -> io.ReviewIOPaths:
        input_dir = root / "inputs"
        input_dir.mkdir(exist_ok=True)
        paths = {name: input_dir / name for name in (
            "source.parquet", "source-audit.json", "protocol.md", "rubric.json",
            "protected-union.json", "receipt.json",
        )}
        for name, path in paths.items():
            path.write_bytes((name + " placeholder").encode())
        # Keep these tests runnable in the evaluator image, which intentionally
        # does not copy paper/. Production hashes remain untouched; fixtures
        # bind to these synthetic bytes within _patch_inputs only.
        paths["protocol.md"].write_bytes(b"synthetic protocol fixture\n")
        paths["rubric.json"].write_bytes(b'{"synthetic": true}\n')
        revision = "4" * 40
        pin_payload = io.build_pin_manifest(ROOT, revision)
        pin_path = input_dir / "pin-manifest.json"
        pin_path.write_bytes(json.dumps(pin_payload, sort_keys=True, separators=(",", ":")).encode())
        return io.ReviewIOPaths(
            parquet=paths["source.parquet"],
            source_audit=paths["source-audit.json"],
            protocol=paths["protocol.md"],
            rubric=paths["rubric.json"],
            protected_union=paths["protected-union.json"],
            protection_receipt=paths["receipt.json"],
            pin_manifest=pin_path,
            output=output,
        )

    def _patch_inputs(self, paths: io.ReviewIOPaths, fake_parquet: _FakeParquet, protected: ProtectedKeys | None = None):
        pin_digest = _sha(paths.pin_manifest.read_bytes())
        parquet_digest = _sha(paths.parquet.read_bytes())
        protected = protected or ProtectedKeys()
        protected = ProtectedKeys(
            ids=protected.ids or frozenset({_sha(b"unused-protected-id")}),
            groups=protected.groups or frozenset({_sha(b"unused-protected-group")}),
            exact_text_sha256=protected.exact_text_sha256 or frozenset({_sha(b"unused-protected-exact-text")}),
            normalized_texts=protected.normalized_texts or frozenset({_sha(b"unused-protected-normalized-text")}),
        )
        code = io._code_digests(ROOT)
        protocol_digest = io.canonical_lf_sha256(paths.protocol)
        rubric_digest = io.canonical_lf_sha256(paths.rubric)
        keys = {
            "ids": sorted(protected.ids),
            "groups": sorted(protected.groups),
            "exact_text_sha256": sorted(protected.exact_text_sha256),
            "normalized_texts": sorted(protected.normalized_texts),
        }
        commitments = {"synthetic_fixture": "bound-by-test-only"}
        union_digest = _sha(io.canonical_json_bytes({
            "schema_version": 1, "verified_commitments": commitments, "keys": keys,
        }))
        artifact = {
            "schema_version": 1,
            "kind": "privoke-clean-protected-union",
            "union_sha256": union_digest,
            "coverage_counts": {},
            "verified_commitments": commitments,
            "keys": keys,
        }
        paths.protected_union.write_bytes(io.canonical_json_bytes(artifact))
        paths.protection_receipt.write_bytes(b"synthetic receipt")
        receipt_sha = _sha(paths.protection_receipt.read_bytes())
        artifact_sha = _sha(paths.protected_union.read_bytes())
        protection_metadata = {
            "union_sha256": union_digest,
            "receipt_sha256": receipt_sha,
            "artifact_sha256": artifact_sha,
            "coverage_counts": {},
            "verified_commitments": commitments,
            "protection_source_revision": "5" * 40,
            "prepared_source_revision": "6" * 40,
            "helper_source_hashes": {
                "protection_io_sha256": code["protection_io"]["raw_sha256"],
                "protection_core_sha256": code["protection_core"]["raw_sha256"],
                "grouping_core_sha256": code["grouping"]["raw_sha256"],
                "training_data_sha256": code["normalizer"]["raw_sha256"],
            },
        }
        def validate_captured_union(union_path, receipt_path, expected):
            self.assertNotEqual(Path(union_path), paths.protected_union)
            self.assertNotEqual(Path(receipt_path), paths.protection_receipt)
            self.assertEqual(Path(union_path).read_bytes(), paths.protected_union.read_bytes())
            self.assertEqual(Path(receipt_path).read_bytes(), paths.protection_receipt.read_bytes())
            return protected, protection_metadata

        patches = [
            patch.object(io, "validate_source_audit", side_effect=lambda path: {
                "source_audit_sha256": _sha(Path(path).read_bytes()), "dataset_revision": "7" * 40,
            }),
            patch.object(io, "require_frozen_text_inputs", return_value={
                "protocol_sha256": protocol_digest,
                "rubric_sha256": rubric_digest,
            }),
            patch.object(io, "validate_training_data_source", return_value="1bdeeff73310808a3468eb54f6d94a16a008b02e027ba3f9d749602636024f0b"),
            patch.object(io, "validate_protected_union", side_effect=validate_captured_union),
            patch.object(io, "verify_parquet_bytes", return_value=parquet_digest),
            patch.object(io, "validate_arrow_schema", return_value=None),
            patch.object(io, "PARQUET_ROWS", 3),
            patch.object(review, "SOURCE_SHA256", parquet_digest),
            patch.object(review, "PROTOCOL_SHA256", protocol_digest),
            patch.object(review, "RUBRIC_SHA256", rubric_digest),
        ]
        return patches, pin_digest, receipt_sha, protected, protection_metadata, parquet_digest

    def test_cli_exposes_only_preparation_inputs(self):
        cli = self._cli()
        args = cli.build_parser().parse_args([
            "--parquet", "p", "--source-audit", "a", "--protocol", "q", "--rubric", "r",
            "--protected-union", "u", "--protection-receipt", "m", "--protection-receipt-sha256", "a" * 64,
            "--pin-manifest", "pins", "--pin-manifest-sha256", "b" * 64,
            "--source-revision", "c" * 40, "--output", "out",
        ])
        self.assertEqual(args.source_revision, "c" * 40)
        self.assertFalse(any("fit" in action.dest or "score" in action.dest for action in cli.build_parser()._actions))

    def test_actual_cli_path_failures_are_sanitized_and_leave_evidence_untouched(self):
        cli = self._cli()
        with tempfile.TemporaryDirectory(prefix="advpii-cli-paths-") as temporary:
            results = Path(temporary) / "results"
            results.mkdir()
            missing = results / "PRIVATE_PATH_MARKER_MISSING" / "run"
            stdout, stderr = text_io.StringIO(), text_io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(cli.main(self._cli_args(missing), _results_root=results), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")

            existing = results / "PRIVATE_PATH_MARKER_EXISTING"
            existing.mkdir()
            sentinel = existing / "do-not-overwrite.txt"
            sentinel.write_text("preserve", encoding="utf-8")
            stdout, stderr = text_io.StringIO(), text_io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(cli.main(self._cli_args(existing), _results_root=results), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

    def test_actual_cli_symlink_refusal_is_sanitized(self):
        cli = self._cli()
        with tempfile.TemporaryDirectory(prefix="advpii-cli-link-") as temporary:
            results = Path(temporary) / "results"
            results.mkdir()
            target = results / "target"
            target.mkdir()
            link = results / f"PRIVATE_PATH_MARKER_LINK_{secrets.token_hex(6)}"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Directory symlinks are unavailable in this Windows test environment.")
            stdout, stderr = text_io.StringIO(), text_io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(cli.main(self._cli_args(link), _results_root=results), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")
            self.assertFalse((target / "failure.json").exists())
            link.unlink(missing_ok=True)

    def test_valid_synthetic_scan_keeps_excluded_bridge_out_of_packages(self):
        rows = [
            _source_row(1, 77, "positive", "Send to alice@example.test", value="alice@example.test"),
            {
                "uid": 2, "input_id": 77, "category": "unknown", "attack_target": None,
                "llm_input": "UNSELECTED_BRIDGE_MARKER", "pii_spans": [],
            },
            _source_row(3, 88, "negative", "This is a verified clean synthetic prompt."),
        ]
        parquet = _FakeParquet([_Batch(rows[:2]), _Batch(rows[2:])], 3)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            paths = self._paths(root, results / "run-1")
            protected = ProtectedKeys(exact_text_sha256=frozenset({_sha(b"UNSELECTED_BRIDGE_MARKER")}))
            patches, pin_digest, receipt_sha, protected, protection_metadata, _ = self._patch_inputs(paths, parquet, protected)
            pool_calls = []
            real_builder = io.build_review_pool

            def capture_pool(*args):
                pool_calls.append(args)
                return real_builder(*args)

            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patch.object(
                io, "sha256_file", side_effect=lambda p: _sha(Path(p).read_bytes())
            ), patch.object(io, "build_review_pool", side_effect=capture_pool):
                result = io.prepare_review_pool(
                    paths,
                    source_revision="4" * 40,
                    pin_manifest_sha256=pin_digest,
                    protection_receipt_sha256=receipt_sha,
                    repository_root=ROOT,
                    results_root=results,
                    parquet_opener=lambda _: parquet,
                )
            self.assertEqual(result, 0, (paths.output / "failure.json").read_text(encoding="utf-8") if result else "")
            manifest = json.loads((paths.output / "manifest.json").read_text(encoding="utf-8"))
            packages = [json.loads(line) for line in (paths.output / "review-packages.jsonl").read_text(encoding="utf-8").splitlines()]
            private_map = [json.loads(line) for line in (paths.output / "private-review-map.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(manifest["source_row_count"], 3)
            self.assertEqual(manifest["pool_size"], 1)
            graph = pool_calls[0][1]
            self.assertEqual(graph.row_count, 3)
            self.assertTrue(any({1, 2} <= set(component.member_uids) for component in graph.components))
            protected_component = next(component for component in graph.components if {1, 2} <= set(component.member_uids))
            self.assertIn("protected_exact_text_overlap", protected_component.exclusion_reasons)
            self.assertEqual({item["source_uid"] for item in private_map}, {3})
            self.assertNotIn("UNSELECTED_BRIDGE_MARKER", "".join(
                (paths.output / name).read_text(encoding="utf-8")
                for name in ("manifest.json", "private-review-map.jsonl", "review-packages.jsonl")
            ))
            self.assertEqual(set(packages[0]), {"review_id", "text", "text_sha256", "rubric_sha256", "native_spans"})
            self.assertTrue(manifest["not_authorized_for_fitting"])

    def test_bad_pin_fails_before_opening_parquet_and_writes_sanitized_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            paths = self._paths(root, results / "run-bad-pin")
            opened = []
            with patch.object(io, "validate_pin_manifest", side_effect=ValueError("PRIVATE_MARKER")):
                result = io.prepare_review_pool(
                    paths,
                    source_revision="4" * 40,
                    pin_manifest_sha256="d" * 64,
                    protection_receipt_sha256="e" * 64,
                    repository_root=ROOT,
                    results_root=results,
                    parquet_opener=lambda p: (opened.append(p), object())[1],
                )
            self.assertEqual(result, 1)
            self.assertEqual(opened, [])
            failure = (paths.output / "failure.json").read_text(encoding="utf-8")
            self.assertNotIn("PRIVATE_MARKER", failure)
            self.assertNotIn(str(paths.parquet), failure)
            self.assertEqual(json.loads(failure)["stage"], "verify_code_pins")

    def test_schema_rejection_precedes_row_iteration(self):
        rows = [_source_row(1, 1, "positive", "x a@b.test", value="a@b.test")]
        parquet = _FakeParquet([_Batch(rows)], 3)
        parquet.iterated = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            paths = self._paths(root, results / "run-bad-schema")
            patches, pin_digest, receipt_sha, _, _, _ = self._patch_inputs(paths, parquet)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patch.object(
                io, "validate_arrow_schema", side_effect=ValueError("SCHEMA_PRIVATE_MARKER")
            ), patches[6], patches[7], patches[8], patches[9], patch.object(
                io, "sha256_file", side_effect=lambda p: _sha(Path(p).read_bytes())
            ):
                result = io.prepare_review_pool(
                    paths,
                    source_revision="4" * 40,
                    pin_manifest_sha256=pin_digest,
                    protection_receipt_sha256=receipt_sha,
                    repository_root=ROOT,
                    results_root=results,
                    parquet_opener=lambda _: parquet,
                )
            self.assertEqual(result, 1)
            failure = json.loads((paths.output / "failure.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["stage"], "validate_parquet_schema")
            self.assertNotIn("SCHEMA_PRIVATE_MARKER", json.dumps(failure))
            self.assertFalse(parquet.iterated)

    def test_batch_schema_rejection_precedes_pylist_and_native_parser(self):
        batch = _Batch([_source_row(1, 1, "negative", "synthetic")])
        parquet = _FakeParquet([batch], 1)
        with patch.object(io, "validate_arrow_schema", side_effect=ValueError("bad batch schema")), patch.object(
            io, "parse_native_row", side_effect=AssertionError("parser must not run")
        ):
            with self.assertRaisesRegex(ValueError, "batch schema"):
                list(io._iter_rows(parquet))
        self.assertFalse(batch.converted)

    def test_real_pyarrow_schema_guard_when_available(self):
        try:
            import pyarrow as pa
        except ImportError:
            self.skipTest("PyArrow is unavailable on this host; the Docker evaluator must run this test.")
        span = pa.struct([
            pa.field("type", pa.string()), pa.field("start", pa.int32()), pa.field("end", pa.int32()),
            pa.field("value", pa.string()), pa.field("value_fuzzy", pa.string()),
        ])
        attack = pa.struct([
            pa.field("pii", pa.list_(pa.string())), pa.field("context", pa.list_(pa.string())),
        ])
        good = pa.schema([
            pa.field("uid", pa.int32()), pa.field("input_id", pa.int32()), pa.field("category", pa.string()),
            pa.field("attack_target", attack, nullable=True), pa.field("llm_input", pa.string()),
            pa.field("pii_spans", pa.list_(span)),
        ])
        io.validate_arrow_schema(good)
        bad = pa.schema([
            pa.field("uid", pa.int64()), pa.field("input_id", pa.int32()), pa.field("category", pa.string()),
            pa.field("attack_target", attack, nullable=True), pa.field("llm_input", pa.string()),
            pa.field("pii_spans", pa.list_(span)),
        ])
        with self.assertRaisesRegex(ValueError, "uid"):
            io.validate_arrow_schema(bad)

    def test_validator_mutation_of_original_artifact_fails_before_reader_open(self):
        parquet = _FakeParquet([], 3)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            paths = self._paths(root, results / "run-swap-before-open")
            patches, pin_digest, receipt_sha, protected, metadata, _ = self._patch_inputs(paths, parquet)
            opened = []

            def replace_original_after_validation(captured_union, captured_receipt, expected):
                self.assertNotEqual(Path(captured_union), paths.protected_union)
                paths.protected_union.write_bytes(b"REPLACED_ARTIFACT_MARKER")
                return protected, metadata

            with patches[0], patches[1], patches[2], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patch.object(
                io, "validate_protected_union", side_effect=replace_original_after_validation
            ), patch.object(
                io, "sha256_file", side_effect=lambda p: _sha(Path(p).read_bytes())
            ):
                result = io.prepare_review_pool(
                    paths,
                    source_revision="4" * 40,
                    pin_manifest_sha256=pin_digest,
                    protection_receipt_sha256=receipt_sha,
                    repository_root=ROOT,
                    results_root=results,
                    parquet_opener=lambda p: (opened.append(p), parquet)[1],
                )
            self.assertEqual(result, 1)
            self.assertEqual(opened, [])
            failure = (paths.output / "failure.json").read_text(encoding="utf-8")
            self.assertNotIn("REPLACED_ARTIFACT_MARKER", failure)
            self.assertEqual(json.loads(failure)["stage"], "verify_original_inputs_before_reader")

    def test_validator_keys_must_match_captured_artifact(self):
        parquet = _FakeParquet([], 3)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            paths = self._paths(root, results / "run-foreign-keys")
            patches, pin_digest, receipt_sha, _, metadata, _ = self._patch_inputs(paths, parquet)
            opener_calls = []
            foreign_keys = ProtectedKeys(ids=frozenset({_sha(b"foreign-validator-key")}))
            with patches[0], patches[1], patches[2], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patch.object(
                io, "validate_protected_union", return_value=(foreign_keys, metadata)
            ), patch.object(
                io, "sha256_file", side_effect=lambda p: _sha(Path(p).read_bytes())
            ):
                result = io.prepare_review_pool(
                    paths,
                    source_revision="4" * 40,
                    pin_manifest_sha256=pin_digest,
                    protection_receipt_sha256=receipt_sha,
                    repository_root=ROOT,
                    results_root=results,
                    parquet_opener=lambda p: (opener_calls.append(p), parquet)[1],
                )
            self.assertEqual(result, 1)
            self.assertEqual(opener_calls, [])
            failure = json.loads((paths.output / "failure.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["stage"], "bind_captured_protection_bytes")

    def test_source_replacement_after_open_fails_before_batch_conversion(self):
        rows = [_source_row(1, 1, "negative", "synthetic")]
        batch = _Batch(rows)
        parquet = _FakeParquet([batch], 3)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            paths = self._paths(root, results / "run-swap-after-open")
            patches, pin_digest, receipt_sha, _, _, _ = self._patch_inputs(paths, parquet)

            def open_then_replace(_captured_path):
                paths.protection_receipt.write_bytes(b"REPLACED_RECEIPT_MARKER")
                return parquet

            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patch.object(
                io, "sha256_file", side_effect=lambda p: _sha(Path(p).read_bytes())
            ):
                result = io.prepare_review_pool(
                    paths,
                    source_revision="4" * 40,
                    pin_manifest_sha256=pin_digest,
                    protection_receipt_sha256=receipt_sha,
                    repository_root=ROOT,
                    results_root=results,
                    parquet_opener=open_then_replace,
                )
            self.assertEqual(result, 1)
            self.assertFalse(batch.converted)
            failure = (paths.output / "failure.json").read_text(encoding="utf-8")
            self.assertNotIn("REPLACED_RECEIPT_MARKER", failure)

    def test_duplicate_uid_across_batches_rejected(self):
        rows = [_source_row(1, 1, "negative", "same"), _source_row(1, 2, "negative", "other")]
        parquet = _FakeParquet([_Batch(rows[:1]), _Batch(rows[1:])], 2)
        with patch.object(io, "validate_arrow_schema", return_value=None):
            with self.assertRaisesRegex(ValueError, "duplicate UID"):
                list(io._iter_rows(parquet))

    def test_unicode_fuzzy_literal_and_base_identifier_are_kept_distinct(self):
        text = "Keep decomposed e\u0301; route to a\u0301lice@example.test"
        literal = "a\u0301lice@example.test"
        row = {
            "uid": 91,
            "input_id": 91,
            "category": "positive",
            "attack_target": {"pii": [], "context": []},
            "llm_input": text,
            "pii_spans": [{
                "type": "email",
                "start": text.index(literal),
                "end": text.index(literal) + len(literal),
                "value": "alice@example.test",
                "value_fuzzy": literal,
            }],
        }
        parsed = io.parse_native_row(row)
        self.assertTrue(parsed.grouping_row.eligible)
        mapped = io._spans_for_eligible_rows([row], (parsed,))[91]
        self.assertEqual(mapped[0].literal, literal)
        self.assertEqual(mapped[0].base_value, "alice@example.test")
        self.assertEqual(text[mapped[0].start:mapped[0].end], literal)
        spans = review._validate_native_spans(parsed, mapped)
        self.assertEqual((spans[0].start, spans[0].end), (row["pii_spans"][0]["start"], row["pii_spans"][0]["end"]))

    def test_selected_positive_with_bad_span_fails_without_repair(self):
        row = _source_row(92, 92, "positive", "mail alice@example.test", value="alice@example.test")
        row["pii_spans"][0]["start"] -= 1
        parsed = io.parse_native_row(row)
        self.assertFalse(parsed.grouping_row.eligible)
        self.assertEqual(io._spans_for_eligible_rows([row], (parsed,)), {})
        with self.assertRaises(ValueError):
            review._validate_native_spans(parsed, (
                io.ValidatedNativeSpanInput("email", 5, 23, "alice@example.test", "alice@example.test"),
            ))

    def test_existing_output_is_never_modified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir()
            output = results / "existing"
            output.mkdir()
            sentinel = output / "prior-evidence"
            sentinel.write_text("preserve", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                io._safe_output_directory(output, results)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
