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

    def _rules(self, text: str) -> set[str]:
        # Production feeds the detector canonical (lowercased, collapsed) text.
        return {result.metadata.get("rule_name")
                for result in self.detector.analyze(normalize_text(text))}

    def _assert_not_fires(self, rule: str, texts) -> None:
        for text in texts:
            with self.subTest(text=text):
                self.assertNotIn(rule, self._rules(text))

    def _assert_fires(self, rule: str, texts) -> None:
        for text in texts:
            with self.subTest(text=text):
                self.assertIn(rule, self._rules(text))

    def test_text_length_alone_is_not_identity_evidence(self):
        text = " ".join(["Please summarise the quarterly maintenance schedule for the warehouse."] * 12)
        self.assertGreater(len(text.split()), 80)
        self.assertNotIn("personal_narrative", self._rules(text))

    def test_family_terms_require_a_possessive(self):
        self._assert_not_fires("family_disclosure", (
            "Write a story about a husband and wife who open a bakery.",
            "Explain how family law treats custody.", "What does a mother bird feed its chicks?"))
        self._assert_fires("family_disclosure", (
            "My wife is travelling this week.", "Our family moved last year.",
            "Her youngest son plays football.", "My ex-wife has the weekend schedule.",
            "My soon-to-be ex-husband moved out.", "Our step-daughter visits often."))
        # Non-possessive self-statements ("I have two kids") are intentionally not matched.
        self._assert_not_fires("family_disclosure", ("I have two kids and a dog.",))

    def test_financial_keyword_requires_a_personal_financial_state_noun(self):
        self._assert_not_fires("financial_keyword", (
            "Can you reset my account settings?", "Explain how credit scoring models work.",
            "Which bank offers the best savings rate?", "Please close my bank.", "Update my account."))
        self._assert_fires("financial_keyword", (
            "My mortgage payment went up.", "Their debt is growing.", "I should review my loan terms.",
            "My monthly salary changed.", "Please check my credit score.", "My savings are low.",
            "My bank balance dropped.", "My bank account balance is overdrawn.", "Her net worth is private."))

    def test_child_requires_a_possessive_or_a_minor_age(self):
        self._assert_not_fires("child", (
            "Every student must submit the form.", "A child seat is required on this ride.",
            "The minor league season starts soon."))
        self._assert_fires("child", (
            "My daughter starts school soon.", "Their 8-year-old son needs a checkup.",
            "The player is aged 12."))
        self._assert_fires("child", ("The 9-year-old girl joined the swim class.", "Our 6-year-old needs a ride."))
        self._assert_not_fires("child", (
            "This 5-year-old laptop keeps freezing.", "A 2-year-old codebase needs a rewrite.",
            "The 3 year old server is being retired."))

    def test_student_alone_is_not_child_but_an_identified_student_record_is_identity(self):
        # Bare student/minor wording is not CHILD (students are often adults); an
        # institutional identifier value tied to a student is an IDENTITY disclosure instead.
        self._assert_not_fires("child", (
            "Student Jordan Lee, ID ABC-123456, needs a form.",
            "Please update student ID 20481733 in the roster."))
        self._assert_fires("student_id", (
            "Please update student ID 20481733 in the roster.",
            "Student Jordan Lee, ID ABC-123456, needs a form.",
            "student number: 55501234", "Student Priya (ID 889012) enrolled."))
        self._assert_not_fires("student_id", (
            "Every student must show their ID at the door.",
            "Each student ID is printed on the card.",
            "The student, ID required, left.",
            "Students receive a user ID after registration.",
            "The student ID format should be documented."))
        # A student who is explicitly a minor is still CHILD through the age cues.
        self._assert_fires("child", ("The 15-year-old student needs a form.", "Student aged 9 joined the class."))

    def test_location_needs_a_place_name_after_the_connector(self):
        self._assert_not_fires("location_keyword", (
            "Keep my address or any other detail out of the summary.",
            "I live in the middle of a busy schedule.", "Is my address in or out of scope?"))
        self._assert_fires("location_keyword", (
            "My address is Brisbane.", "I live in Perth.", "my location in Hobart",
            "I live on Elm Street."))

    def test_structured_identity_value_is_one_short_line(self):
        self._assert_not_fires("structured_identity", (
            "Name:\nthe following paragraph explains the background in much more detail than needed here",
            "Phone: iPhone 14 is the model I am comparing"))
        self._assert_fires("structured_identity", ("Name: Alex Morgan", "username: alex_m", "Phone: 555 0101",
            "Phone: +61 400 000 000", "Phone: (555) 010 0101"))
        long_value = "name: one two three four five six seven eight nine"
        matched = [result.section_of_text for result in self.detector.analyze(long_value)
                   if result.metadata.get("rule_name") == "structured_identity"]
        self.assertEqual(["name: one two three four five"], matched)

    def test_driver_licence_alphanumeric_needs_digits_or_licence_context(self):
        rule = "presidio_uslicenserecognizer_driver license - alphanumeric (weak)"
        self._assert_not_fires(rule, (
            "The biggest driver of churn is q1 pricing.", "Part code B12 ships Monday."))
        self._assert_fires(rule, (
            "Licence number: D12 on file.", "Reference B1234567 was recorded."))

    def test_card_numbers_need_a_valid_luhn_checksum(self):
        self._assert_not_fires("credit_card", ("Order 1234 5678 9012 3456 shipped.",))
        self._assert_not_fires("presidio_creditcardrecognizer_all credit cards (weak)",
                               ("Order 1234 5678 9012 3456 shipped.",))
        self._assert_fires("credit_card", ("Card 4111 1111 1111 1111 expires soon.",))
        self._assert_fires("presidio_creditcardrecognizer_all credit cards (weak)",
                           ("Card 4111 1111 1111 1111 expires soon.",))

    def test_iban_needs_a_valid_mod97_checksum(self):
        self._assert_not_fires("iban", ("Use code ab12cd for the promotion.", "Lookup xy99zz7 later."))
        self._assert_fires("iban", ("Pay into GB82WEST12345698765432 please.",))
        self._assert_fires("presidio_ibanrecognizer_iban generic",
                           ("Pay into GB82 WEST 1234 5698 7654 32 please.",))
        self._assert_not_fires("presidio_ibanrecognizer_iban generic",
                               ("Pay into GB83 WEST 1234 5698 7654 32 please.",))

    def test_nhs_number_needs_a_valid_check_digit(self):
        nhs = "presidio_nhsrecognizer_nhs (medium)"
        self._assert_not_fires(nhs, ("Reference 943 476 5918 was logged.",))
        self._assert_fires(nhs, ("Reference 943 476 5919 was logged.",))

    def test_ssn_needs_an_issuable_area_group_and_serial(self):
        self._assert_not_fires("presidio_usssnrecognizer_ssn5 (medium)", ("Ref 000-12-3456 here.", "Ref 666-12-3456 here.",
                                                                          "Ref 912-34-5678 here."))
        self._assert_not_fires("ssn_formatted", ("Ref 000-12-3456 here.", "Ref 123-00-6789 here.",
                                                 "Ref 123-45-0000 here.", "Ref 666-12-3456 here."))
        self._assert_fires("ssn_formatted", ("Her SSN is 123-45-6789.",))

    def test_short_numeric_dates_need_date_context(self):
        rule = "presidio_daterecognizer_mm/yy or m/yy"
        self._assert_not_fires(rule, ("The film scored 7/10 for me.", "Rate this 8/10 for the year."))
        self._assert_fires(rule, ("The card expires 07/27.",))

    def test_password_placeholders_are_not_credentials(self):
        self._assert_not_fires("password_assignment", ("password: required", "Password = optional",
                                                       "passcode: none"))
        self._assert_fires("password_assignment", ("password: Hunter2xyz", "pwd=s3cr3tvalue"))

    def test_chat_mentions_are_not_social_handles(self):
        self._assert_not_fires("social_handle", ("@here please review", "ping @everyone", "cc @channel"))
        self._assert_fires("social_handle", ("Follow me at @alex_m on social media.",))

    def test_standards_identifiers_are_not_license_plates(self):
        self._assert_not_fires("license_plate", ("See rfc-7231 for details.", "Patched in cve-2024 release.",
                                                 "Follows iso-9001 guidance."))
        self._assert_fires("license_plate", ("The car is ABC-1234.", "License plate: XYZ 987"))


if __name__ == "__main__":
    unittest.main()
