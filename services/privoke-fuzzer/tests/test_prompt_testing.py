from __future__ import annotations

import sys
import unittest
from pathlib import Path


SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from prompt_testing import _summary


class PromptTestingSummaryTests(unittest.TestCase):
    def test_skipped_layer_is_not_a_failed_run(self) -> None:
        summary = _summary(
            [
                {
                    "layers": {
                        "regex": {"status": "ok"},
                        "semantic": {"status": "skipped"},
                    }
                }
            ],
            Path("result.json"),
        )

        self.assertEqual(summary["failed_layer_runs"], 0)
        self.assertEqual(summary["layer_counts"]["semantic"]["skipped"], 1)

    def test_error_layer_is_a_failed_run(self) -> None:
        summary = _summary(
            [{"layers": {"semantic": {"status": "error"}}}],
            Path("result.json"),
        )

        self.assertEqual(summary["failed_layer_runs"], 1)
        self.assertEqual(summary["layer_counts"]["semantic"]["error"], 1)


if __name__ == "__main__":
    unittest.main()
