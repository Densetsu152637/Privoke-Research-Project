"""Mechanics of the pretrained contextual golden generator (RUST-S17B): fixture structure and a regeneration check.

The structure checks run anywhere (standard library only). The regeneration check needs the client runtime's Python
environment (numpy, the pinned ``tokenizers`` wheel, the ``parameters`` protobuf client) and is skipped without it.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_pretrained_context_golden")

FIXTURE = REPO / "rust" / "crates" / "privoke-semantic" / "tests" / "fixtures" / "context_golden.json"


class FixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_the_recorded_digests_are_those_of_the_recorded_bytes(self) -> None:
        onnx = base64.b64decode(self.document["onnx_b64"])
        self.assertEqual(hashlib.sha256(onnx).hexdigest(), self.document["onnx_sha256"])
        self.assertEqual(hashlib.sha256(self.document["tokenizer_json"].encode()).hexdigest(), self.document["tokenizer_sha256"])

    def test_the_cases_cover_findings_clean_results_and_context_length_errors(self) -> None:
        cases = self.document["model_cases"]
        self.assertTrue(any(case["findings"] for case in cases))
        self.assertTrue(all(not case["findings"] for case in self.document["clean"]["cases"]))
        self.assertTrue(any("error" in case for case in self.document["encoder_cases"]))
        self.assertEqual([case["text"] for case in cases], golden.TEXTS)

    def test_no_decision_sits_within_float32_noise_of_a_boundary(self) -> None:
        for case in self.document["model_cases"]:
            self.assertTrue(golden.margins_ok(case, 0.5), case["text"])

    def test_the_tokenizer_file_carries_the_settings_the_encoder_must_switch_off(self) -> None:
        tokenizer = json.loads(self.document["tokenizer_json"])
        self.assertIsNotNone(tokenizer["truncation"])
        self.assertIsNotNone(tokenizer["padding"])
        self.assertTrue(any(case["tokens"] > tokenizer["truncation"]["max_length"] for case in self.document["encoder_cases"]))


class RegenerationTest(unittest.TestCase):
    def test_the_committed_fixture_is_what_the_generator_writes(self) -> None:
        try:
            golden.bootstrap()
            import numpy  # noqa: F401
            import tokenizers  # noqa: F401
            import privoke.v1.parameters_pb2  # noqa: F401
            import dotenv  # noqa: F401
        except ImportError as error:
            self.skipTest(f"the client runtime environment is not available: {error}")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "golden.json"
            golden.run(out)
            # numpy's float32 matrix products differ in the last digits between BLAS builds: the integers, strings and
            # structure must be identical, the floats equal to 1e-5.
            self.assertSameDocument(json.loads(FIXTURE.read_text(encoding="utf-8")), json.loads(out.read_text(encoding="utf-8")))

    def assertSameDocument(self, committed, fresh, path="") -> None:
        if isinstance(committed, dict):
            self.assertEqual(sorted(committed), sorted(fresh), path)
            for key in committed:
                self.assertSameDocument(committed[key], fresh[key], f"{path}/{key}")
        elif isinstance(committed, list):
            self.assertEqual(len(committed), len(fresh), path)
            for index, (left, right) in enumerate(zip(committed, fresh)):
                self.assertSameDocument(left, right, f"{path}[{index}]")
        elif isinstance(committed, float):
            self.assertAlmostEqual(committed, fresh, delta=1e-5, msg=path)
        else:
            self.assertEqual(committed, fresh, path)


if __name__ == "__main__":
    unittest.main()
