"""Mechanics of the local-only window golden generator (RUST-S19D), without study data or a Torch requirement."""

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
golden = importlib.import_module("generate_window_golden")
SOURCE = (REPO / "evaluation" / "generate_window_golden.py").read_text(encoding="utf-8")


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
        self.assertEqual(result.returncode, 0, "the window golden contains study text-derived data and must stay ignored")

    def test_the_release_files_are_the_five_sidecars(self) -> None:
        self.assertEqual(set(golden.FILES.values()),
                         {"bank.json", "references-v2.json", "component-manifest-v2.json", "original.json", "window.json"})


@unittest.skipUnless(os.environ.get("PRIVOKE_WINDOW_REGENERATE") == "1" and golden.DEFAULT_RELEASE.exists(),
                     "set PRIVOKE_WINDOW_REGENERATE=1 with the real release to regenerate the golden twice")
class RegenerationTest(unittest.TestCase):
    def test_regeneration_is_deterministic(self) -> None:
        digests = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                golden.build(golden.DEFAULT_RELEASE, Path(directory))
                digests.append({p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(directory).iterdir())})
        self.assertEqual(digests[0], digests[1])


if __name__ == "__main__":
    unittest.main()
