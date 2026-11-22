"""Mechanics of the ORIGINAL retention golden generator (RUST-S21F), without the generated protobuf clients or recorded studies."""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_retention_trace_golden")


class GeneratorMechanicsTest(unittest.TestCase):
    def test_a_mutated_trace_is_resummarised_so_that_only_the_mutation_is_wrong(self) -> None:
        trace = {"policy": "p", "adam": {"base": "a", "final": "b", "delta": "c"},
                 "safety": [{"violation": True}, {"violation": False}], "auxiliary": {"counts": {"x": 1}}}
        metadata = {golden.MANIFEST: "m" * 64}
        resummed = golden.resummed(metadata, trace)
        raw = golden.canonical(trace)
        self.assertEqual(resummed[golden.TRACE], raw)
        summary = json.loads(resummed[golden.SUMMARY])
        self.assertEqual(summary["trace_sha256"], hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual((summary["eligible"], summary["violations"], summary["auxiliary"]), (2, 1, {"x": 1}))

    def test_the_canonical_form_is_compact_and_sorted(self) -> None:
        self.assertEqual(golden.canonical({"b": 1, "a": [1.5, None]}), '{"a":[1.5,null],"b":1}')

    def test_the_runtime_is_never_asked_for_a_detector_pipeline(self) -> None:
        source = (REPO / "evaluation" / "generate_retention_trace_golden.py").read_text(encoding="utf-8")
        for forbidden in ("analyse_text", "AnalyzePrompt", '"regex"', '"ner"'):
            self.assertNotIn(forbidden, source, forbidden)


if __name__ == "__main__":
    unittest.main()
