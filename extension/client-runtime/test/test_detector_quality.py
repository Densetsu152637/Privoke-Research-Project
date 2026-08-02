from __future__ import annotations

import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SHARED_ROOT = PACKAGE_ROOT.parents[1] / "shared/python"
for path in (PACKAGE_ROOT, SHARED_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.regex.rule_detector import RuleDetector


class DetectorQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = RuleDetector()

    def test_clean_financial_definition_does_not_trigger_broad_rule(self) -> None:
        results = self.detector.analyze(
            "Can you explain what a bank account number is using placeholders only?"
        )

        self.assertFalse(
            any(result.metadata.get("rule_name") == "financial_keyword" for result in results)
        )

    def test_clean_health_definition_does_not_trigger_broad_rule(self) -> None:
        results = self.detector.analyze(
            "Can you explain what diabetes means without using real patient details?"
        )

        self.assertFalse(
            any(result.metadata.get("rule_name") == "health_keyword" for result in results)
        )

    def test_real_bank_account_still_triggers(self) -> None:
        results = self.detector.analyze("My bank account number is 1234567890.")

        self.assertTrue(
            any(result.metadata.get("rule_name") == "bank_account" for result in results)
        )

    def test_structured_secret_patterns_trigger(self) -> None:
        text = "Use https://portal.example.com/reset?token=tok_123456789012345678 and password: TempPass1234!"
        results = self.detector.analyze(text)
        rule_names = {result.metadata.get("rule_name") for result in results}

        self.assertIn("url_with_token", rule_names)
        self.assertIn("password_assignment", rule_names)


if __name__ == "__main__":
    unittest.main()
