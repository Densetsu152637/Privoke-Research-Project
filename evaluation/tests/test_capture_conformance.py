"""Tests for the Rust-rewrite conformance capture (stage 0 of docs/plans/rust-server-rewrite.md).

The Go-service surface needs Docker and is exercised by running the capture itself; these tests
cover the deterministic helpers, agreement with the reference modules, two-run determinism of the
host-only surfaces, and the integrity of the committed corpus.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import capture_conformance as capture  # noqa: E402

CORPUS = capture.ROOT / "tests" / "conformance"
HOST_ONLY_SURFACES = ("canonical", "contracts", "update_sequence", "telemetry", "native_messaging", "grpc_web")


class SerialisationTests(unittest.TestCase):
    def test_corpus_files_are_ascii_sorted_lf(self):
        raw = capture.dump_json({"b": 1, "a": "é\U0001f600", "c": [1.5, 1e-08]})
        self.assertEqual(raw, b'{\n "a": "\\u00e9\\ud83d\\ude00",\n "b": 1,\n "c": [\n  1.5,\n  1e-08\n ]\n}\n')
        self.assertNotIn(b"\r", raw)

    def test_crlf_is_folded_only_for_hashing(self):
        self.assertEqual(capture.sha256_lf(b"a\r\nb\n"), capture.sha256(b"a\nb\n"))

    def test_non_finite_values_are_refused(self):
        with self.assertRaises(ValueError):
            capture.dump_json({"x": float("nan")})


class CanonicalVariantTests(unittest.TestCase):
    def test_variants_agree_with_the_reference_modules(self):
        sample = json.loads('{"b":[1,2.5,{"\\u00e9":"\\u2028\\u2029"}],"a":null,"z":1e-8,"\\ud83d\\ude00":"x"}')
        capture.cross_check_variants(sample)

    def test_variant_outputs_differ_exactly_where_python_does(self):
        value = json.loads('{"k":"\\u00e9\\u2028"}')
        self.assertEqual(capture.canonical_text(value, "ascii"), '{"k":"\\u00e9\\u2028"}')
        self.assertEqual(capture.canonical_text(value, "utf8"), '{"k":"é "}')
        self.assertEqual(capture.canonical_text(value, "utf8_go"), '{"k":"é\\u2028"}')
        self.assertEqual(capture.canonical_text(value, "utf8_lf"), '{"k":"é "}\n')

    def test_lone_surrogate_is_an_error_for_utf8_variants_only(self):
        value = json.loads('"\\ud800"')
        self.assertEqual(capture.canonical_text(value, "ascii"), '"\\ud800"')
        for variant in ("utf8", "utf8_go", "utf8_lf"):
            with self.assertRaises(UnicodeError):
                capture.canonical_text(value, variant)

    def test_float_repr_corpus_is_unique_and_round_trips(self):
        rows = capture.float_repr_cases()
        self.assertEqual(len({bits for bits, _ in rows}), len(rows))
        self.assertGreater(len(rows), 800)
        for bits, text in rows:
            self.assertEqual(capture.f64_bits(float(text)), bits)
        self.assertIn(["3ff0000000000000", "1.0"], rows)
        self.assertTrue(any(text == "1e-08" for _, text in rows))
        self.assertTrue(any(text == "1e+16" for _, text in rows))


class DeterminismTests(unittest.TestCase):
    def run_surfaces(self, out: Path) -> dict:
        for surface in HOST_ONLY_SURFACES:
            result = subprocess.run([sys.executable, str(Path(capture.__file__)), "--surface", surface, "--out", str(out)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    env={**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(result.returncode, 0, f"{surface}: {result.stderr[-600:]}")
        return {path.name: path.read_bytes() for path in sorted(out.glob("*.json"))}

    def test_host_surfaces_are_identical_across_two_runs(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one, two = self.run_surfaces(Path(first)), self.run_surfaces(Path(second))
        self.assertEqual(sorted(one), sorted(two))
        self.assertGreaterEqual(len(one), 9)
        for name in one:
            self.assertEqual(one[name], two[name], name)


class CommittedCorpusTests(unittest.TestCase):
    def test_manifest_hashes_every_surface_file(self):
        manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["reference"]["tag"], capture.REFERENCE_TAG)
        listed = set(manifest["files"])
        expected = {name for names in capture.SURFACE_FILES.values() for name in names}
        self.assertEqual(listed, expected)
        for name, entry in manifest["files"].items():
            data = (CORPUS / name).read_bytes()
            self.assertEqual(capture.sha256(data), entry["sha256"], name)
            self.assertEqual(len(data), entry["bytes"], name)
            self.assertNotIn(b"\r", data, name)

    def test_deferred_gaps_are_recorded(self):
        manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(manifest["deferred_gaps"])
        for gap in manifest["deferred_gaps"]:
            self.assertTrue(gap["reason"] and gap["covered_instead"])

    def test_no_binary_asset_bytes_are_stored(self):
        streaming = json.loads((CORPUS / "model_streaming.json").read_text(encoding="utf-8"))
        for package in streaming["v3"].values():
            for asset in package["stream_asset"].values():
                self.assertEqual(len(asset["sha256"]), 64)
                for chunk in asset["chunks"]:
                    self.assertNotIn("data", chunk)
        for path in CORPUS.iterdir():
            self.assertLess(path.stat().st_size, 1_000_000, path.name)

    def test_streaming_capture_records_every_catalog_model_and_pinned_v3_manifest(self):
        streaming = json.loads((CORPUS / "model_streaming.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(streaming["legacy"]), sorted(capture.LEGACY_MODELS))
        self.assertEqual(sorted(streaming["v3"]), sorted(capture.V3_MODELS))
        from privoke_model.standard_v3 import STANDARD_PINS

        for model, package in streaming["v3"].items():
            self.assertEqual(package["manifest_file_sha256"], STANDARD_PINS[model])
            self.assertEqual(package["get_model_package"]["manifest_sha256"], STANDARD_PINS[model])


if __name__ == "__main__":
    unittest.main()
