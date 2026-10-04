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
from privoke_eval.contextual_fixture_protection import FixtureProtectionError
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

        helper_dir = self.root / "test-helpers"
        helper_dir.mkdir()
        self.helper_map = {}
        for name in ("grouping", "normalizer", "fixture_validator"):
            path = helper_dir / f"{name}.py"
            content = f"# synthetic {name}\n".encode()
            path.write_bytes(content)
            self.helper_map[name] = path
        adapter = helper_dir / "adapter.py"
        adapter.write_bytes(b"# synthetic adapter source\n")
        self.adapter_path = adapter

        self.input_paths = dict(io_layer._INPUT_PATHS)
        self.helper_paths = {name: path.relative_to(self.root) for name, path in self.helper_map.items()}
        self.helper_paths["adapter"] = self.adapter_path.relative_to(self.root)
        self.expected_raw = {
            "fixture": sha(self.fixture), "rubric": sha(self.rubric), "review": sha(self.review),
        }
        self.expected_helpers = {
            name: sha(path.read_bytes()) for name, path in self.helper_map.items()
        }
        self.expected_adapter = sha(self.adapter_path.read_bytes())
        self.patches = [
            patch.dict(io_layer._INPUT_PATHS, self.input_paths, clear=True),
            patch.dict(io_layer._HELPER_PATHS, self.helper_paths, clear=True),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def build(self, name="result", **overrides):
        args = {
            "source_revision": "d" * 40,
            "expected_input_raw_sha256": self.expected_raw,
            "expected_helper_source_sha256": self.expected_helpers,
            "expected_adapter_source_sha256": self.expected_adapter,
            "policy": self.policy,
        }
        args.update(overrides)
        return io_layer._build_fixture_protection_addon_io(
            self.root, self.root / "evaluation/results" / name, **args,
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
        self.helper_map["normalizer"].write_bytes(b"changed helper")
        with self.assertRaises(io_layer.FixtureProtectionIOError):
            self.build()
        self.helper_map["normalizer"].write_bytes(b"# synthetic normalizer\n")
        existing = self.root / "evaluation/results/existing"
        existing.mkdir()
        marker = existing / "keep.bin"
        marker.write_bytes(b"preserve")
        with self.assertRaises(io_layer.FixtureProtectionIOError):
            self.build("existing")
        self.assertEqual(marker.read_bytes(), b"preserve")

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
