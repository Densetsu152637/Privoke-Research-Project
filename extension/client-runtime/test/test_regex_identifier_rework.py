"""Labelled identifiers and validator downgrades in the regex layer (author-written sentences)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SHARED_ROOT = PACKAGE_ROOT.parents[1] / "shared/python"
for path in (PACKAGE_ROOT, SHARED_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.detection.preprocessing import normalize_text
from src.regex.rule_detector import RuleDetector


class RegexIdentifierReworkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = RuleDetector()

    def _hits(self, text: str) -> dict[str, str]:
        """Rule name -> sensitivity for canonical (lowercased) production input."""
        return {result.metadata.get("rule_name"): result.classification.sensitivity().name
                for result in self.detector.analyze(normalize_text(text))}

    def _assert_hit(self, rule: str, sensitivity: str, texts) -> None:
        for text in texts:
            with self.subTest(text=text):
                self.assertEqual(sensitivity, self._hits(text).get(rule))

    def _assert_no_hit(self, rules, texts) -> None:
        for text in texts:
            with self.subTest(text=text):
                found = self._hits(text)
                for rule in rules:
                    self.assertNotIn(rule, found)

    # -- labelled identifiers -------------------------------------------------------------

    def test_government_health_and_payment_identifiers_are_s3_when_labelled(self):
        self._assert_hit("labelled_identifier_sensitive", "S3", (
            "Her passport number is QK4417203.",
            "Please note the national ID number 8841-2207-5531 on the form.",
            "Tax file number 482 119 337 was provided.",
            "The patient number is PT-2210984.",
            "Health plan member number: HP7733-2210.",
            "His insurance id is 4417-ZK-882.",
            "Medical record number MRN-004418 is attached.",
            "ID card: XR2209481",
            "Passport: ZK9981234",
            "SSN 482119337 appears twice in the file.",
            "The licence number is DL-4417-2209.",
            "driver's license no. 7741-2209-88 expires soon",
            "My card number is 9912 4417 2209 8841.",
        ))

    def test_organisation_reference_identifiers_are_s2_when_labelled(self):
        self._assert_hit("labelled_identifier_generic", "S2", (
            "The customer ID is CU-208841.",
            "Employee number: E4417209",
            "Membership no. 99-2217-04 lapsed.",
            "client reference 8841-QX-22",
            "Her loyalty card number is LY44172209.",
            "User id: usr_44172",
            "Plate number KD-4417",
            "Policy number HX-2210-448 renewed.",
        ))

    def test_structured_key_value_forms_are_labelled_identifiers(self):
        self._assert_hit("labelled_identifier_generic", "S2", (
            '{"customer_id": "CU-208841", "plan": "basic"}',
            "customerId=CU208841",
            "member_no: 9921-7740",
        ))
        self._assert_hit("labelled_identifier_sensitive", "S3", (
            '{"passport_number": "QK4417203"}',
            "**Patient ID:** PT-2210984",
        ))

    def test_labelled_identifiers_accept_any_value_shape(self):
        # Not a valid IBAN, card or SSN: the label alone makes it an identifier.
        self._assert_hit("labelled_identifier_sensitive", "S3", (
            "The beneficiary number is 2FJ8-QW4-LA92.",
            "National id: Q8841220",
        ))
        # Both case-preserved and lowercased input work.
        found = {result.metadata.get("rule_name") for result in self.detector.analyze(
            "Her Passport Number is QK4417203.")}
        self.assertIn("labelled_identifier_sensitive", found)

    def test_label_without_a_value_or_with_a_prose_value_is_not_an_identifier(self):
        self._assert_no_hit(("labelled_identifier_sensitive", "labelled_identifier_generic"), (
            "Your passport number is required to book the flight.",
            "What is a customer ID used for?",
            "Enter your member number below.",
            "The tax file number is optional on this form.",
            "Describe the patient number format in the design note.",
            "The reference number is shown at the top of the page.",
            "Keep your account number private and never share it.",
        ))

    def test_values_that_cannot_be_identifiers_are_rejected(self):
        self._assert_no_hit(("labelled_identifier_sensitive", "labelled_identifier_generic"), (
            "The member number 42 is on page two.",
            "Her customer ID is A1.",
            "The policy reference 2024-05-12 is the issue date.",
            "License: Apache-2.0",
            "Licence: MIT",
        ))

    def test_unlabelled_or_unrelated_codes_are_not_labelled_identifiers(self):
        self._assert_no_hit(("labelled_identifier_sensitive", "labelled_identifier_generic"), (
            "The build number is 20481 and the port number is 8080.",
            "Your order number is 884213.",
            "Use the promo code SPRING2025 at checkout.",
            "The zip code is 90210.",
            "Ticket T-4417 was closed on Friday.",
            "Part number KB-4417 ships Monday.",
        ))

    # -- validator downgrades -------------------------------------------------------------

    def test_failed_luhn_card_with_a_card_label_stays_s3(self):
        self._assert_hit("credit_card_unverified", "S3", (
            "Charge the credit card 1234 5678 9012 3456 today.",
            "Payment: visa 4417 1234 5678 9011 expires 09/27",
        ))
        self._assert_no_hit(("credit_card",), ("Charge the credit card 1234 5678 9012 3456 today.",))

    def test_failed_luhn_digit_run_without_a_card_label_is_not_a_card(self):
        self._assert_no_hit(("credit_card_unverified",), (
            "Order 1234 5678 9012 3456 shipped.",
            "The tracking digits 4417123456789011 are on the label.",
        ))

    def test_valid_card_keeps_its_full_rule(self):
        self.assertEqual("S3", self._hits("Card 4111 1111 1111 1111 expires soon.").get("credit_card"))

    def test_failed_iban_with_a_banking_label_stays_s3(self):
        self._assert_hit("iban_unverified", "S3", ("Please wire it to the bank account GB83WEST12345698765432 today.",))
        self._assert_no_hit(("iban",), ("Please wire it to the bank account GB83WEST12345698765432 today.",))

    def test_failed_iban_shaped_long_token_is_a_number_like_identifier_at_s2(self):
        self._assert_hit("unverified_number_identifier", "S2", (
            "Her badge reads KT90412358 at the door.",
            "Hand over the file marked ZZ0965178 please.",
        ))
        # Short codes and mostly-letter tokens stay out (the precision repair).
        self._assert_no_hit(("unverified_number_identifier", "iban_unverified", "iban"), (
            "Use code ab12cd for the promotion.", "Lookup xy99zz7 later.",
            "The token cp87igfatv was rotated.",
        ))

    def test_failed_ssn_with_an_ssn_label_stays_s3(self):
        self._assert_hit("ssn_unverified", "S3", ("Her SSN is 912-34-5678.", "social security number 000-12-3456"))
        self._assert_no_hit(("ssn_unverified", "ssn_formatted"), ("Ref 000-12-3456 here.", "Ref 912-34-5678 here."))

    # -- precision repairs that must stay in place ---------------------------------------

    def test_earlier_false_positive_repairs_remain_negative(self):
        self._assert_no_hit(("child", "family_disclosure", "financial_keyword"), (
            "Every student must show their ID at the door.",
            "Can you reset my account settings?",
            "Write a story about a husband and wife who open a bakery.",
            "I have two kids and a dog.",
        ))
        self._assert_no_hit(("presidio_uslicenserecognizer_driver license - alphanumeric (weak)",), (
            "The biggest driver of churn is q1 pricing.", "Part code B12 ships Monday.",
        ))


if __name__ == "__main__":
    unittest.main()
