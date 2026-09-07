from __future__ import annotations

import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from src.classification import PriVokeAction
from src.hosting.analyzer import PromptAnalysis
from src.hosting.models import PromptInspectionRequest
from src.pipeline import LayerExecution, PipelineAnalysis


class PipelineSafetyTests(unittest.TestCase):
    def test_detector_error_does_not_fail_open(self) -> None:
        analysis = PipelineAnalysis(
            (LayerExecution("semantic", "error", error="classifier unavailable"),)
        )

        self.assertIsNone(analysis.result)
        self.assertEqual(analysis.action, PriVokeAction.BLOCK)

    def test_detector_error_keeps_existing_block_action(self) -> None:
        analysis = PipelineAnalysis(
            (LayerExecution("semantic", "error", error="classifier unavailable"),)
        )

        self.assertEqual(analysis.action, PriVokeAction.BLOCK)

    def test_detector_error_explains_blocked_analysis(self) -> None:
        execution = PipelineAnalysis(
            (LayerExecution("semantic", "error", error="classifier unavailable"),)
        )
        response = PromptAnalysis(
            request=PromptInspectionRequest(text="test prompt"),
            execution=execution,
            result=execution.result,
            action=execution.action,
            elapsed_ms=1.0,
        ).response()

        self.assertEqual(response["action"], "BLOCK")
        self.assertFalse(response["allowed"])
        self.assertEqual(
            response["reason"],
            "PriVoke could not complete analysis safely.",
        )
        self.assertEqual(response["errors"], ["semantic: classifier unavailable"])


if __name__ == "__main__":
    unittest.main()