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


class RoutesFixtureTest(unittest.TestCase):
    """The local-SGD, backtracking and diagnostics routes (RUST-S19C)."""

    def setUp(self) -> None:
        self.data = json.loads(golden.ROUTES_FIXTURE.read_text(encoding="utf-8"))
        self.served = [case for case in self.data["cases"] if "refusal" not in case]

    def test_fixture_shape(self) -> None:
        self.assertEqual(len(self.served), 44)
        self.assertEqual({case["label"].split("/")[1] for case in self.served}, {"local-sgd", "diagnostics", "backtracking"})
        self.assertEqual(self.data["meta"]["threads"], 1)
        self.assertEqual(len(self.data["cases"]) - len(self.served), 26)

    def test_backtracking_covers_every_outcome(self) -> None:
        selected = set()
        for case in self.served:
            if case["backtracking"]:
                trace = json.loads(case["metadata_out"]["contextual_training_backtracking_trace"])
                selected.add(trace["selected"])
                self.assertEqual(case["error"] != "", trace["selected"] is None)
        self.assertEqual(selected, {0, 1, None})

    def test_every_case_is_a_semantic_training_run(self) -> None:
        for case in self.served:
            phases = [phase for phase, _ in case["executions"]]
            self.assertEqual(phases[0], "training", case["label"])
            self.assertEqual(phases[1:], [] if case["error"] else ["base_heldout", "candidate_heldout"], case["label"])
            self.assertEqual(sorted(case["gradients"]) == [] , bool(case["error"]), case["label"])

    def test_refusals_carry_the_python_text(self) -> None:
        texts = {case["label"].split("/", 2)[2]: case["refusal"] for case in self.data["cases"] if "refusal" in case}
        self.assertEqual(texts["window-without-admission"], "Window artifact requires explicit matching pre-gradient admission.")
        self.assertEqual(texts["backtracking-without-admission"],
                         "FULL backtracking requires explicit matching pre-gradient admission.")
        self.assertEqual(texts["unsupported-optimizer"], "Unsupported contextual training optimizer.")

    @unittest.skipUnless(runtime_available(), "Torch or the generated protobuf clients are not available")
    def test_regeneration_matches_the_committed_fixture(self) -> None:
        fresh = golden.routes_build()
        self.assertEqual([case["label"] for case in fresh["cases"]], [case["label"] for case in self.data["cases"]])
        for new, old in zip(fresh["cases"], self.data["cases"]):
            self.assertEqual(new.get("refusal"), old.get("refusal"), new["label"])
            self.assertEqual(new.get("error"), old.get("error"), new["label"])
            self.assertEqual(new.get("executions"), old.get("executions"), new["label"])
            for name, values in old.get("gradients", {}).items():
                # float32 bit patterns: one unit in the last place is allowed across machines
                self.assertTrue(all(abs(a - b) <= 1 for a, b in zip(new["gradients"][name], values)), (new["label"], name))


if __name__ == "__main__":
    unittest.main()
