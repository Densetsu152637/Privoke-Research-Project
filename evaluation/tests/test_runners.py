from __future__ import annotations

import unittest
from unittest.mock import patch

from privoke_eval.runners import run_pipeline


class RunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch("privoke_eval.runners.configure_backend")
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_uses_returned_classification_even_when_action_is_allow(self) -> None:
        response = {
            "action": "ALLOW",
            "classification": {
                "sensitivity": "S1",
                "visibility": "PU",
                "categories": ["IDENTITY"],
            },
            "evidence": {"confidence": 0.8},
            "metadata": {"elapsed_ms": 1.0},
        }
        with patch("privoke_eval.runners._request_json", return_value=response):
            outcome = run_pipeline("example", "streamed")

        self.assertTrue(outcome.detected_sensitive)
        self.assertFalse(outcome.intervened)

    def test_rejects_invalid_classification_instead_of_scoring_it(self) -> None:
        response = {
            "action": "ALLOW",
            "classification": {"sensitivity": "unknown", "categories": []},
        }
        with patch("privoke_eval.runners._request_json", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "invalid classification sensitivity"):
                run_pipeline("example", "streamed")


if __name__ == "__main__":
    unittest.main()
