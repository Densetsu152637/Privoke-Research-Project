"""Mechanics of the privoke-training golden generator (RUST-S19), without a Torch requirement."""

from __future__ import annotations

import importlib
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_training_golden")


def runtime_available() -> bool:
    try:
        golden.bootstrap()
        import torch  # noqa: F401
        from src.LLM.privoke import full_adam_training  # noqa: F401
    except Exception:  # noqa: BLE001 - torch or the generated protobuf clients are missing
        return False
    return True


class GeneratorMechanicsTest(unittest.TestCase):
    def test_no_detector_layer_selection_is_built(self) -> None:
        source = (REPO / "evaluation" / "generate_training_golden.py").read_text(encoding="utf-8")
        for forbidden in ("layers=", "analyse_text", "import pipeline", '"regex"', '"ner"'):
            self.assertNotIn(forbidden, source, forbidden)

    def test_threads_are_pinned_before_torch(self) -> None:
        source = (REPO / "evaluation" / "generate_training_golden.py").read_text(encoding="utf-8")
        self.assertLess(source.index('os.environ["OMP_NUM_THREADS"] = "1"'), source.index("import torch"))
        self.assertIn("torch.set_num_threads(1)", source)

    def test_examples_and_artifacts_are_seeded(self) -> None:
        self.assertEqual(golden.make_examples(), golden.make_examples())
        first = golden.make_artifact("residual_task_query_v1", golden.SEED + 2)
        self.assertEqual(first, golden.make_artifact("residual_task_query_v1", golden.SEED + 2))
        self.assertIn("readout.category.query", first["parameters"])
        self.assertNotIn("readout.category.query", golden.make_artifact(None, golden.SEED + 1)["parameters"])

    def test_bits_round_trip_float32(self) -> None:
        import numpy as np

        values = [0.1, -2.5, 1e-9]
        decoded = np.asarray(golden.bits(values), dtype=np.uint32).view(np.float32)
        self.assertEqual(decoded.tolist(), np.asarray(values, dtype=np.float32).tolist())


class FixtureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(golden.FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_shape(self) -> None:
        self.assertEqual(len(self.data["gradient_cases"]), 10)
        self.assertEqual(len(self.data["adam"]["steps"]), 64)
        self.assertEqual(self.data["meta"]["threads"], 1)
        self.assertTrue(self.data["adam"]["fingerprint_check"])
        self.assertEqual(self.data["adam"]["objective"], golden.OBJECTIVES["sum_margin"])

    def test_every_tensor_has_a_direction(self) -> None:
        names = set(self.data["models"]["task_query"]["parameters"])
        for step in self.data["adam"]["steps"]:
            self.assertEqual(set(step["direction"]), names)

    @unittest.skipUnless(runtime_available(), "Torch or the generated protobuf clients are not available")
    def test_regeneration_matches_the_committed_fixture(self) -> None:
        # Gradients are compared as float32 bit patterns with a one-ulp allowance; the fingerprints are exact.
        fresh = golden.build()
        self.assertEqual(fresh["examples"], self.data["examples"])
        self.assertEqual(fresh["adam"]["base_fingerprint"], self.data["adam"]["base_fingerprint"])
        self.assertEqual(fresh["meta"]["torch"].split("+")[0], self.data["meta"]["torch"].split("+")[0])


if __name__ == "__main__":
    unittest.main()
