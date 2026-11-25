"""Mechanics of the privoke-rules golden generator (RUST-S12), without any recorded dataset."""

from __future__ import annotations

import base64
import importlib
import json
import sys
import unicodedata
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_rules_golden")

RUST_COMMON = REPO / "rust" / "crates" / "privoke-rules" / "tests" / "common" / "mod.rs"


def runtime_available() -> bool:
    try:
        golden.bootstrap()
        from src import pipeline  # noqa: F401
    except Exception:  # noqa: BLE001 - generated clients or heavy dependencies missing
        return False
    return True


class GeneratorMechanicsTest(unittest.TestCase):
    def test_origins_are_run_length_encoded(self) -> None:
        self.assertEqual(golden.encode_origins([(0, 1), (0, 1), (1, 3), (0, 1)]), [[0, 1, 2], [1, 3, 1], [0, 1, 1]])
        self.assertEqual(golden.encode_origins([]), [])

    def test_final_endpoint_is_never_opened(self) -> None:
        with self.assertRaises(SystemExit):
            golden.refuse_final(Path("evaluation/results/locked-public/final.jsonl"))
        golden.refuse_final(Path("evaluation/results/locked-public/development.jsonl"))
        for relative in golden.SET_FILES.values():
            self.assertNotIn("final", Path(relative).name.lower())

    def test_lone_surrogates_are_detected(self) -> None:
        self.assertTrue(golden.has_surrogate("a\ud800b"))
        self.assertFalse(golden.has_surrogate("a\U0001f600b"))

    def test_configurations_match_the_rust_harness(self) -> None:
        source = RUST_COMMON.read_text(encoding="utf-8")
        for name in (*golden.NORM_CONFIGS, *golden.LAYER_CONFIGS):
            self.assertIn(f'"{name}"', source, f"configuration {name} is missing from the Rust harness")
        # Both shipped defaults and the four robustness variants are exercised.
        self.assertEqual(golden.LAYER_CONFIGS["default"], (True, False, False, False, True, True))
        self.assertEqual(golden.LAYER_CONFIGS["lowercase"][0], False)
        flags = {name: golden.LAYER_CONFIGS[name][1:4] for name in ("format", "digits", "email", "all-flags")}
        self.assertEqual(flags, {"format": (True, False, False), "digits": (False, True, False),
                                 "email": (False, False, True), "all-flags": (True, True, True)})
        self.assertFalse(golden.LAYER_CONFIGS["no-presidio"][4])
        self.assertFalse(golden.LAYER_CONFIGS["no-gitleaks"][5])

    def test_synthetic_fixture_is_complete(self) -> None:
        inputs = golden.synthetic_inputs()
        rows = json.loads(base64.b64decode((golden.FIXTURES / "synthetic_golden.b64").read_text()).decode("utf-8"))["rows"]
        self.assertEqual([row["id"] for row in rows], [case["id"] for case in inputs])
        self.assertEqual([row["text"] for row in rows], [case["text"] for case in inputs])
        for row in rows:
            self.assertEqual(set(row["norm"]), set(golden.NORM_CONFIGS))
            self.assertEqual(set(row["layer"]), set(golden.LAYER_CONFIGS))

    def test_tables_are_deterministic_and_current(self) -> None:
        first = golden.generate_tables()
        self.assertEqual(first, golden.generate_tables())
        self.assertIn(f'UNICODE_VERSION: &str = "{unicodedata.unidata_version}"', first)
        committed = (golden.CRATE / "src" / "unicode_tables.rs").read_text(encoding="utf-8").replace("\r\n", "\n")
        if unicodedata.unidata_version == "14.0.0":
            self.assertEqual(first, committed, "run `generate_rules_golden.py tables` with the reference Python")

    @unittest.skipUnless(runtime_available(), "the regex layer needs the generated protobuf clients (evaluation/setup-host.py)")
    def test_regex_layer_is_selected_explicitly(self) -> None:
        runtime = golden.Runtime()
        requested = []
        original = runtime.pipeline.analyse_text

        def recording(text, layers=None, **kwargs):
            requested.append(layers)
            return original(text, layers=layers, **kwargs)

        runtime.pipeline.analyse_text = recording
        try:
            hits = runtime.layer("mail jane.doe@example.com now", "no-external")
        finally:
            runtime.pipeline.analyse_text = original
        self.assertEqual(requested, [["regex"]])
        self.assertTrue(any(hit["rule"] == "email" for hit in hits))
        self.assertNotEqual(requested[0], [])


if __name__ == "__main__":
    unittest.main()
