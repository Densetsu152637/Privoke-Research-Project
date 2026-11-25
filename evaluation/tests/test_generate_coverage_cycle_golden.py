"""Mechanics of the coverage cycle golden generator (RUST-S21G), without the generated protobuf clients or recorded studies."""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_coverage_cycle_golden")


class GeneratorMechanicsTest(unittest.TestCase):
    def test_every_sidecar_is_a_committed_fixture_with_a_repo_relative_path(self) -> None:
        self.assertEqual(sorted(golden.PATHS), [
            "FUZZ_BENIGN_EXCLUSION_PROOF_PATH", "FUZZ_BENIGN_MANIFEST_PATH", "FUZZ_BENIGN_POOL_PATH", "FUZZ_REHEARSAL_MANIFEST_PATH"])
        for name, path in golden.PATHS.items():
            relative = golden.relative(path)
            self.assertFalse(Path(relative).is_absolute(), name)
            self.assertTrue(relative.startswith("rust/"), name)
        for name, path in golden.PATHS.items():
            if name != "FUZZ_REHEARSAL_MANIFEST_PATH":
                self.assertTrue(path.exists(), name)

    def test_the_strategies_are_the_two_coverage_samplers(self) -> None:
        self.assertEqual((golden.REHEARSAL, golden.BENIGN), ("taxonomy_anchor_rehearsal_v1", "taxonomy_benign_coverage_v1"))

    def test_the_runtime_is_never_asked_for_a_detector_pipeline(self) -> None:
        source = (REPO / "evaluation" / "generate_coverage_cycle_golden.py").read_text(encoding="utf-8")
        for forbidden in ("analyse_text", "AnalyzePrompt", '"regex"', '"ner"'):
            self.assertNotIn(forbidden, source, forbidden)


if __name__ == "__main__":
    unittest.main()
