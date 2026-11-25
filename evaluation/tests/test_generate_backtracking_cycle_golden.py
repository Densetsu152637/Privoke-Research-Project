"""Mechanics of the backtracking, diagnostics and retention cycle golden generators (RUST-S21G), without the generated protobuf clients or studies."""

from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
backtracking = importlib.import_module("generate_backtracking_cycle_golden")
retention = importlib.import_module("generate_retention_cycle_golden")


class GeneratorMechanicsTest(unittest.TestCase):
    def test_the_backtracking_golden_is_a_committed_fixture_and_the_retention_golden_stays_local(self) -> None:
        self.assertEqual(backtracking.OUTPUT.relative_to(REPO).as_posix(), "rust/services/fuzzer/tests/fixtures/backtracking_cycles_golden.json")
        self.assertEqual(retention.OUTPUT.relative_to(REPO).as_posix(), "rust/services/fuzzer/tests/local/retention_cycles_golden.json")
        ignored = (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("/rust/services/fuzzer/tests/local/", ignored)

    def test_the_retention_sidecars_are_read_by_bare_file_name(self) -> None:
        self.assertEqual([bare for _, bare, _ in retention.SIDECARS], ["bank.json", "references.json", "manifest.json", "teacher.json"])
        self.assertEqual([variable for _, _, variable in retention.SIDECARS], [
            "FUZZ_RETENTION_BANK_PATH", "FUZZ_RETENTION_REFERENCE_PATH", "FUZZ_RETENTION_MANIFEST_PATH", "FUZZ_RETENTION_TEACHER_PATH"])

    def test_the_runtime_is_never_asked_for_a_detector_pipeline(self) -> None:
        for name in ("generate_backtracking_cycle_golden.py", "generate_retention_cycle_golden.py"):
            source = (REPO / "evaluation" / name).read_text(encoding="utf-8")
            for forbidden in ("analyse_text", "AnalyzePrompt", '"regex"', '"ner"'):
                self.assertNotIn(forbidden, source, f"{name}: {forbidden}")


if __name__ == "__main__":
    unittest.main()
