"""Synthetic-only tests for the private fixture add-on I/O boundary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "evaluation/tests"))
sys.path.insert(0, str(ROOT / "shared/python"))

from privoke_eval import contextual_fixture_protection_io as io_layer
from test_contextual_fixture_protection import synthetic_inputs


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ContextualFixtureProtectionIOPortableTests(unittest.TestCase):
    def test_crlf_canonicalization_preserves_utf8_content(self):
        data = "café\r\nsecond line\n".encode("utf-8")
        self.assertEqual(io_layer._canonical_lf(data), "café\nsecond line\n".encode("utf-8"))
        with self.assertRaises(io_layer.FixtureProtectionIOError):
            io_layer._canonical_lf(b"\xff")

    @unittest.skipUnless(os.name == "nt", "Windows gate behavior only")
    def test_windows_refuses_before_reading_sources(self):
        with patch.object(io_layer, "_capture_set", side_effect=AssertionError("read attempted")):
            with self.assertRaises(io_layer.FixtureProtectionIOError):
                io_layer._build_fixture_protection_addon_io(
                    Path("C:/synthetic"), Path("C:/synthetic/evaluation/results/out"),
                    source_revision="d" * 40,
                    expected_input_raw_sha256={key: "a" * 64 for key in io_layer._INPUT_PATHS},
                    expected_helper_source_sha256={key: "b" * 64 for key in ("grouping", "normalizer", "fixture_validator")},
                    expected_adapter_source_sha256="c" * 64,
                    policy=synthetic_inputs()[3],
                )

    def test_live_modules_match_trusted_sources_and_reject_shadow_checkout(self):
        helper_hashes = {
            name: sha((ROOT / relative).read_bytes())
            for name, relative in io_layer._HELPER_PATHS.items() if name != "adapter"
        }
        adapter_hash = sha((ROOT / io_layer._HELPER_PATHS["adapter"]).read_bytes())
        for name, relative in io_layer._HELPER_PATHS.items():
            source = (ROOT / relative).read_bytes()
            io_layer._verify_loaded_module(
                ROOT, name, io_layer._Captured(source, sha(source), (0, 0, len(source), 0, 0)),
            )
        with patch.object(io_layer, "build_fixture_addon", lambda *args, **kwargs: (b"", b"")):
            with self.assertRaises(io_layer.FixtureProtectionIOError):
                io_layer._verify_code(ROOT, helper_hashes, adapter_hash)
        with tempfile.TemporaryDirectory() as shadow_temp:
            shadow = Path(shadow_temp).absolute()
            for relative in io_layer._HELPER_PATHS.values():
                target = shadow / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            for name, relative in io_layer._HELPER_PATHS.items():
                source = (shadow / relative).read_bytes()
                with self.assertRaises(io_layer.FixtureProtectionIOError):
                    io_layer._verify_loaded_module(
                        shadow, name, io_layer._Captured(source, sha(source), (0, 0, len(source), 0, 0)),
                    )


@unittest.skipIf(os.name == "nt", "Windows ACL verification is an execution gate; no chmod substitute")
class ContextualFixtureProtectionIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).absolute()
        self.fixture_path = self.root / io_layer._INPUT_PATHS["fixture"]
        self.rubric_path = self.root / io_layer._INPUT_PATHS["rubric"]
        self.review_path = self.root / io_layer._INPUT_PATHS["review"]
        for path in (self.fixture_path, self.rubric_path, self.review_path):
            path.parent.mkdir(parents=True, exist_ok=True)
        (self.root / "evaluation/results").mkdir(parents=True)

        self.fixture, self.rubric, self.review, self.policy, self.pure_helpers = synthetic_inputs()
        # Exercise CRLF conversion without changing any decoded JSON or rubric content.
        self.fixture = self.fixture.replace(b"\n", b"\r\n")
        self.rubric = self.rubric.replace(b"\n", b"\r\n")
        self.fixture_path.write_bytes(self.fixture)
        self.rubric_path.write_bytes(self.rubric)
        self.review_path.write_bytes(self.review)

        self.expected_raw = {
            "fixture": sha(self.fixture), "rubric": sha(self.rubric), "review": sha(self.review),
        }
        self.expected_helpers = {
            name: sha((ROOT / relative).read_bytes())
            for name, relative in io_layer._HELPER_PATHS.items() if name != "adapter"
        }
        self.expected_adapter = sha((ROOT / io_layer._HELPER_PATHS["adapter"]).read_bytes())

    def tearDown(self):
        self.temp.cleanup()

    def build(self, name="result", **overrides):
        source_root = overrides.pop("source_root", ROOT)
        args = {
            "source_revision": "d" * 40,
            "expected_input_raw_sha256": self.expected_raw,
            "expected_helper_source_sha256": self.expected_helpers,
            "expected_adapter_source_sha256": self.expected_adapter,
            "policy": self.policy,
        }
        args.update(overrides)
        return io_layer._build_fixture_protection_addon_io(
            self.root, self.root / "evaluation/results" / name, source_root=source_root, **args,
        )

    def test_capture_canonicalization_and_private_outputs(self):
        result = self.build()
        out = result.output_directory
        artifact = (out / io_layer._OUTPUT_ARTIFACT).read_bytes()
        pure_receipt = (out / io_layer._OUTPUT_PURE_RECEIPT).read_bytes()
        manifest_bytes = (out / io_layer._OUTPUT_MANIFEST).read_bytes()
        manifest = json.loads(manifest_bytes)
        self.assertEqual(sha(artifact), result.artifact_sha256)
        self.assertEqual(sha(pure_receipt), result.pure_receipt_sha256)
        self.assertEqual(sha(manifest_bytes), result.io_receipt_sha256)
        self.assertEqual(manifest["input_files"]["fixture"]["raw_sha256"], sha(self.fixture))
        self.assertEqual(manifest["input_files"]["fixture"]["canonical_lf_sha256"],
                         sha(self.fixture.replace(b"\r\n", b"\n")))
        self.assertEqual(manifest["input_files"]["review"]["raw_sha256"], sha(self.review))
        self.assertEqual(result.coverage_counts["ids"], 48)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o700)
        for child in out.iterdir():
            self.assertEqual(os.stat(child).st_mode & 0o777, 0o600)
        self.assertNotIn(b"synthetic fictional prompt", artifact)
        self.assertNotIn(b"synthetic-case-", manifest_bytes)

    def test_all_raw_hashes_checked_before_pure_builder(self):
        wrong = dict(self.expected_raw, review="0" * 64)
        with patch.object(io_layer, "build_fixture_addon", side_effect=AssertionError("builder called")):
            with self.assertRaises(io_layer.FixtureProtectionIOError):
                self.build(expected_input_raw_sha256=wrong)

    def test_oversize_capture_stops_before_builder(self):
        self.fixture_path.write_bytes(b"x" * (io_layer._INPUT_LIMITS["fixture"] + 1))
        expected = dict(self.expected_raw, fixture=sha(self.fixture_path.read_bytes()))
        with patch.object(io_layer, "build_fixture_addon", side_effect=AssertionError("builder called")):
            with self.assertRaises(io_layer.FixtureProtectionIOError):
                self.build(expected_input_raw_sha256=expected)

    def test_source_mutation_during_build_fails_without_receipt(self):
        real_builder = io_layer.build_fixture_addon

        def mutate_after_capture(*args, **kwargs):
            value = real_builder(*args, **kwargs)
            self.rubric_path.write_bytes(self.rubric_path.read_bytes() + b"changed")
            return value

        with patch.object(io_layer, "build_fixture_addon", side_effect=mutate_after_capture):
            with self.assertRaises(io_layer.FixtureProtectionIOError):
                self.build()
        self.assertFalse((self.root / "evaluation/results/result").exists())

    def test_changed_helper_and_existing_output_fail_closed(self):
        stale = dict(self.expected_helpers, normalizer="f" * 64)
        with patch.object(io_layer, "_capture_set", side_effect=AssertionError("fixture decoded")):
            with self.assertRaises(io_layer.FixtureProtectionIOError):
                self.build(expected_helper_source_sha256=stale)
        existing = self.root / "evaluation/results/existing"
        existing.mkdir()
        marker = existing / "keep.bin"
        marker.write_bytes(b"preserve")
        with self.assertRaises(io_layer.FixtureProtectionIOError):
            self.build("existing")
        self.assertEqual(marker.read_bytes(), b"preserve")

    def test_actual_module_sources_are_bound_before_fixture_capture(self):
        io_layer._verify_code(ROOT, self.expected_helpers, self.expected_adapter)
        with tempfile.TemporaryDirectory() as shadow_temp:
            shadow = Path(shadow_temp).absolute()
            for relative in io_layer._HELPER_PATHS.values():
                target = shadow / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            with patch.object(io_layer, "_capture_set", side_effect=AssertionError("fixture decoded")):
                with self.assertRaises(io_layer.FixtureProtectionIOError):
                    self.build(source_root=shadow)

    def test_output_directory_substitution_never_redirects_write(self):
        real_create = io_layer._create_output_directory
        outside = self.root / "synthetic-outside"
        outside.mkdir(mode=0o700)
        saved = self.root / "evaluation/results/saved-output"

        def substitute(context):
            real_create(context)
            context.output_path.rename(saved)
            context.output_path.symlink_to(outside, target_is_directory=True)

        with patch.object(io_layer, "_create_output_directory", side_effect=substitute):
            with self.assertRaises(io_layer.FixtureProtectionIOError):
                self.build()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(list(saved.iterdir()), [])

    def test_substitution_after_first_file_stops_later_publication(self):
        real_write = io_layer._write_output_file
        outside = self.root / "synthetic-outside"
        outside.mkdir(mode=0o700)
        saved = self.root / "evaluation/results/saved-output"

        def write_then_substitute(context, filename, payload):
            digest = real_write(context, filename, payload)
            if filename == io_layer._OUTPUT_ARTIFACT:
                context.output_path.rename(saved)
                context.output_path.symlink_to(outside, target_is_directory=True)
            return digest

        with patch.object(io_layer, "_write_output_file", side_effect=write_then_substitute):
            with self.assertRaises(io_layer.FixtureProtectionIOError):
                self.build()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual([path.name for path in saved.iterdir()], [io_layer._OUTPUT_ARTIFACT])

    def test_approved_parent_substitution_never_redirects_write(self):
        real_create = io_layer._create_output_directory
        results = self.root / "evaluation/results"
        saved = self.root / "evaluation/saved-results"
        outside = self.root / "synthetic-outside"
        outside.mkdir(mode=0o700)

        def substitute(context):
            real_create(context)
            results.rename(saved)
            results.symlink_to(outside, target_is_directory=True)

        with patch.object(io_layer, "_create_output_directory", side_effect=substitute):
            with self.assertRaises(io_layer.FixtureProtectionIOError):
                self.build()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(list((saved / "result").iterdir()), [])

    def test_symlinked_input_is_rejected(self):
        original = self.fixture_path.with_suffix(".bak")
        self.fixture_path.rename(original)
        try:
            self.fixture_path.symlink_to(original)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable on this host")
        with self.assertRaises(io_layer.FixtureProtectionIOError):
            self.build()


if __name__ == "__main__":
    unittest.main()
