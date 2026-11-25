"""Mechanics of the local-only retention golden generator (RUST-S19F), without study data or a Torch requirement."""

from __future__ import annotations

import hashlib
import importlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_retention_golden")
SOURCE = (REPO / "evaluation" / "generate_retention_golden.py").read_text(encoding="utf-8")


class GeneratorMechanicsTest(unittest.TestCase):
    def test_no_detector_layer_selection_is_built(self) -> None:
        for forbidden in ("layers=", "analyse_text", "import pipeline", '"regex"', '"ner"'):
            self.assertNotIn(forbidden, SOURCE, forbidden)

    def test_threads_are_pinned_before_torch(self) -> None:
        self.assertLess(SOURCE.index('os.environ["OMP_NUM_THREADS"] = "1"'), SOURCE.index("import torch"))
        self.assertIn("torch.set_num_threads(1)", SOURCE)

    def test_float32_bytes_round_trip(self) -> None:
        import numpy as np

        values = [0.1, -2.5, 1e-9]
        decoded = np.frombuffer(golden.f32_bytes(values), dtype="<f4").tolist()
        self.assertEqual(decoded, np.asarray(values, dtype=np.float32).tolist())

    def test_the_default_output_is_git_ignored(self) -> None:
        probe = golden.DEFAULT_OUT / "probe"
        try:
            result = subprocess.run(["git", "check-ignore", "-q", str(probe)], cwd=REPO, check=False)
        except FileNotFoundError:
            self.skipTest("git is not available")
        self.assertEqual(result.returncode, 0, "the retention golden holds study text and must stay ignored")

    def test_the_release_is_the_balanced_one(self) -> None:
        paths = golden.release_paths(Path("/results"))
        self.assertEqual(paths["references"].parent.name, "balanced")
        self.assertEqual(paths["teacher"].name, "privoke-balanced.json")
        self.assertEqual(paths["bank"].name, "approved-train-bank.json")


@unittest.skipUnless(os.environ.get("PRIVOKE_RETENTION_REGENERATE") == "1" and golden.DEFAULT_ROOT.exists(),
                     "set PRIVOKE_RETENTION_REGENERATE=1 with the real release to regenerate the golden twice")
class RegenerationTest(unittest.TestCase):
    def test_regeneration_is_deterministic(self) -> None:
        digests = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                golden.build(golden.DEFAULT_ROOT, Path(directory))
                digests.append({str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in sorted(Path(directory).rglob("*")) if p.is_file()})
        self.assertEqual(digests[0], digests[1])


if __name__ == "__main__":
    unittest.main()
