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

    def test_generic_workplace_topics_do_not_imply_identity_disclosure(self):
        for text in (
            "Help draft a message to a manager about an international flight.",
            "Explain the remote work policy for next quarter.",
            "How should a company describe volunteer work in an application?",
        ):
            with self.subTest(text=text):
                self.assertFalse(any(result.metadata.get("rule_name") == "workplace_keyword"
                                     for result in self.detector.analyze(text)))

    def test_personal_employer_disclosures_still_trigger(self):
        for text in ("I work at ExampleCorp.", "My employer is ExampleCorp.",
                     "Employer: ExampleCorp", "We are employed by ExampleCorp."):
            with self.subTest(text=text):
                expected = "workplace_keyword"
                found = any(result.metadata.get("rule_name") == expected for result in self.detector.analyze(text))
                self.assertTrue(found)

    def test_clean_financial_definition_does_not_trigger_broad_rule(self) -> None:
        results = self.detector.analyze(
            "Can you explain what a bank account number is using placeholders only?"
        )

        self.assertFalse(
            any(result.metadata.get("rule_name") == "financial_keyword" for result in results)
        )

    def test_public_prices_do_not_imply_personal_financial_disclosure(self):
        for text in ("The public catalogue lists a price of $125.",
                     "Total: $27.50", "The annual infrastructure budget is 200000 USD."):
            with self.subTest(text=text):
                self.assertFalse(any(result.metadata.get("rule_name") == "money_amount"
                                     for result in self.detector.analyze(text)))

    def test_personal_amounts_and_structured_balances_still_trigger(self):
        for text in ("My monthly rent is $1500.", "I owe 2000 USD.",
                     "Balance: $250.50", "Their savings total $4100."):
            with self.subTest(text=text):
                self.assertTrue(any(result.metadata.get("rule_name") == "money_amount"
                                    for result in self.detector.analyze(text)))

    def test_generic_origin_and_location_topics_do_not_imply_residence(self):
        for text in ("Import the headings from the document.",
                     "The venue is located in Melbourne.", "Explain address formatting."):
            with self.subTest(text=text):
                self.assertFalse(any(result.metadata.get("rule_name") == "location_keyword"
                                     for result in self.detector.analyze(text)))

    def test_personal_locations_and_labeled_fields_still_trigger(self):
        for text in ("I live in Melbourne.", "She is staying near Sydney.",
                     "I'm currently living near Sydney.", "We're from Melbourne.",
                     "She comes from Adelaide.", "I am alone tonight in Wellington.",
                     "My hometown is Adelaide.", "Address: Wellington"):
            with self.subTest(text=text):
                self.assertTrue(any(result.metadata.get("rule_name") == "location_keyword"
                                    for result in self.detector.analyze(text)))

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
