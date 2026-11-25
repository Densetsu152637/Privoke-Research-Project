"""Mechanics of the model fetch golden generator (RUST-S17B): structure of the fixture and a regeneration check.

The structure checks run anywhere (standard library only). The regeneration check needs the client runtime's Python
environment and the generated ``parameters`` protobuf client, and is skipped without them.
"""

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "evaluation"))
golden = importlib.import_module("generate_model_fetch_golden")

FIXTURE = REPO / "rust" / "services" / "runtime-supervisor" / "tests" / "fixtures" / "model_fetch_golden.json"


class FixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_every_v3_case_names_a_known_mutation_once(self) -> None:
        names = [case["name"] for case in self.document["v3"]["cases"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names, [mutation for mutation, _ in golden.V3_CASES])

    def test_a_rejection_never_leaves_a_manifest_or_a_temporary_file(self) -> None:
        for case in self.document["v3"]["cases"]:
            if case["outcome"] == "error" and not case["name"].startswith("cached_manifest"):
                self.assertNotIn("manifest.json", case["files"], case["name"])
            self.assertEqual(case["hidden"], [], case["name"])

    def test_the_legacy_path_writes_no_cache_and_the_four_tracked_models_are_recorded(self) -> None:
        self.assertTrue(self.document["legacy"]["python_disk_cache"].startswith("none"))
        self.assertEqual([m["model_id"] for m in self.document["legacy"]["tracked"]], list(golden.TRACKED_MODELS))

    def test_the_honest_cases_are_accepted_and_every_other_legacy_case_is_refused(self) -> None:
        for case in self.document["legacy"]["cases"]:
            self.assertEqual(case["accepted"], case["name"] == "legacy_honest", case["name"])


class RegenerationTest(unittest.TestCase):
    def test_the_committed_fixture_is_what_the_generator_writes(self) -> None:
        try:
            golden.bootstrap()
            import privoke.v1.parameters_pb2  # noqa: F401
            import dotenv  # noqa: F401
        except ImportError as error:
            self.skipTest(f"the client runtime environment is not available: {error}")
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "golden.json"
            golden.run(out)
            self.assertEqual(FIXTURE.read_bytes(), out.read_bytes())


if __name__ == "__main__":
    unittest.main()
