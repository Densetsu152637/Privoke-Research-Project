from __future__ import annotations

import sys
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SHARED_ROOT = PACKAGE_ROOT.parents[1] / "shared/python"
for path in (PACKAGE_ROOT, SHARED_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from src.NER.pattern_entity_detector import PatternEntityDetector
from src.NER.use_cases import NER_LABEL_USE_CASES
from src.classification import ClassificationResult


def found(detector, text, label=None):
    return [(r.section_of_text, r.metadata["label"], r.metadata["mechanism"], r.metadata["cue"])
            for r in detector.extract_entities(text)
            if label is None or r.metadata["label"] == label]


def values(detector, text, label):
    return [value for value, *_ in found(detector, text, label)]


class PatternEntityDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = PatternEntityDetector()

    # -- contract -----------------------------------------------------------

    def test_results_follow_the_ner_contract_and_label_mapping(self):
        text = "My name is Evan Khan and I live in Austin, TX 78701."
        results = self.detector.extract_entities(text)
        self.assertTrue(results)
        for result in results:
            self.assertIsInstance(result, ClassificationResult)
            use_case = NER_LABEL_USE_CASES[result.metadata["label"]]
            self.assertEqual(result.classification, use_case.classification)
            self.assertEqual(result.confidence, use_case.confidence)
            self.assertEqual(result.metadata["entity_type"], use_case.entity_type)
            self.assertIn(result.metadata["mechanism"], {"cue", "shape", "gazetteer", "recurrence"})
            start, end = result.span
            self.assertEqual(text[start:end], result.section_of_text)

    def test_spans_index_the_given_text_for_varied_inputs(self):
        samples = [
            "Name: John Q. Public\nEmployer: Globex University\nAddress: 12 Main St",
            "Dear Priya,\nThanks.\nRegards,\nPriya Nair",
            "my manager sarah lee said sarah is away; ask lee.",
            "Draft a note for Sam Brooks's file. Sam Brooks lives at 4 Elm Street, Reno, NV 89501.",
        ]
        for text in samples:
            for result in self.detector.extract_entities(text):
                with self.subTest(text=text, value=result.section_of_text):
                    start, end = result.span
                    self.assertEqual(text[start:end], result.section_of_text)

    def test_empty_text_returns_nothing(self):
        self.assertEqual(self.detector.extract_entities(""), [])

    # -- cues ---------------------------------------------------------------

    def test_person_cues(self):
        cases = {
            "Full name: Maria Gonzalez": "field_name",
            "My name is Evan Khan.": "self_intro_my_name",
            "Please call me Riley Singh tomorrow.": "self_intro_call_me",
            "Hello, I am Maya Chen from accounting.": "self_intro_called",
            "Dear Priya, thank you for the update.": "salutation_dear",
            "Thanks for your help.\nRegards,\nPriya Nair": "signoff",
            "Please forward this to Dr. Patel.": "honorific_period",
            "My manager Sarah Lee approved it.": "relation_apposition",
            "my son named ethan is sick.": "relation_named",
        }
        for text, cue in cases.items():
            with self.subTest(text=text):
                hits = [h for h in found(self.detector, text, "PERSON") if h[3] == cue]
                self.assertTrue(hits, found(self.detector, text))
                self.assertEqual(hits[0][2], "cue")

    def test_location_cues_and_shapes(self):
        self.assertIn("Austin, TX 78701", values(self.detector, "I live in Austin, TX 78701 now.", "GPE"))
        self.assertIn("4323 Maple Street", values(self.detector, "Ship it to 4323 Maple Street today.", "FAC"))
        self.assertIn("Seattle, WA 98101", values(self.detector, "Billing: 9 Pine Road, Seattle, WA 98101.", "GPE"))
        self.assertIn("Denver", values(self.detector, "She is based in Denver and likes it.", "GPE"))
        self.assertIn("Elm Street", values(self.detector, "Turn left on Elm Street.", "FAC"))

    def test_organisation_cues_and_shapes(self):
        self.assertIn("Acme Corp", values(self.detector, "I work at Acme Corp in sales.", "ORG"))
        self.assertIn("Globex University", values(self.detector, "Employer: Globex University", "ORG"))
        self.assertIn("Initech Inc", values(self.detector, "The invoice came from Initech Inc yesterday.", "ORG"))

    def test_shape_finds_mid_sentence_capitalised_names_without_a_cue(self):
        hits = found(self.detector, "Write a bank support message for Evan Khan.", "PERSON")
        self.assertEqual([(h[0], h[2]) for h in hits], [("Evan Khan", "shape")])

    def test_form_record_at_sentence_start_is_recognised_by_shape(self):
        hits = found(self.detector, "Update the file: Maya Patel, 1995-12-10, renewal.", "PERSON")
        self.assertEqual([(h[0], h[3]) for h in hits], [("Maya Patel", "title_record")])

    # -- lowercase input (the deployed runtime lowercases text before NER) ----

    def test_cues_survive_lowercasing_but_capitalisation_shapes_do_not(self):
        text = "my name is evan khan and i live in austin, tx 78701. i work at acme corp."
        hits = {(v, label, mech) for v, label, mech, _ in found(self.detector, text)}
        self.assertIn(("evan khan", "PERSON", "cue"), hits)
        self.assertIn(("austin, tx 78701", "GPE", "cue"), hits)
        self.assertIn(("acme corp", "ORG", "cue"), hits)
        self.assertEqual(found(self.detector, "write a bank support message for evan khan."), [])

    def test_lowercase_street_address_shape_still_fires(self):
        self.assertIn("1565 hillcrest drive",
                      values(self.detector, "i am at 1565 hillcrest drive, springfield, il 62704", "FAC"))

    def test_gazetteer_is_off_by_default_and_recovers_lowercase_names_when_enabled(self):
        text = "write a bank support message for evan khan."
        self.assertEqual(found(self.detector, text, "PERSON"), [])
        enabled = PatternEntityDetector(use_gazetteer=True)
        self.assertEqual([(h[0], h[2]) for h in found(enabled, text, "PERSON")], [("evan khan", "gazetteer")])

    # -- recurrence -----------------------------------------------------------

    def test_recurrence_finds_repeats_and_name_parts_of_a_cue_value(self):
        text = "My name is Evan Khan. Later evan asked again, and Khan replied. Evan Khan left."
        hits = [(h[0], h[2]) for h in found(self.detector, text, "PERSON")]
        self.assertEqual(hits.count(("Evan Khan", "recurrence")), 1)
        self.assertIn(("evan", "recurrence"), hits)
        self.assertIn(("Khan", "recurrence"), hits)
        self.assertEqual(hits[0], ("Evan Khan", "cue"))

    def test_recurrence_promotes_sentence_initial_capitalised_pairs_seen_twice(self):
        text = "Alder Quill called today. Alder Quill left a voicemail."
        self.assertEqual(found(PatternEntityDetector(use_recurrence=False), text, "PERSON"), [])
        hits = [(h[0], h[2]) for h in found(self.detector, text, "PERSON")]
        self.assertEqual(hits, [("Alder Quill", "recurrence"), ("Alder Quill", "recurrence")])

    def test_recurrence_requires_a_prior_find_or_two_occurrences(self):
        self.assertEqual(found(self.detector, "Alder Quill called today."), [])
        self.assertEqual(found(self.detector, "We discussed Alder Quill briefly."), [("Alder Quill", "PERSON", "shape", "title_sequence")])

    def test_ablation_switches_isolate_mechanisms(self):
        text = "Write a note for Evan Khan. My manager Sarah Lee agreed. Sarah will send it."
        mechanisms = lambda d: {m for _, _, m, _ in found(d, text)}
        self.assertEqual(mechanisms(PatternEntityDetector(use_shape=False, use_recurrence=False)), {"cue"})
        self.assertEqual(mechanisms(PatternEntityDetector(use_recurrence=False)), {"cue", "shape"})
        self.assertEqual(mechanisms(self.detector), {"cue", "shape", "recurrence"})

    def test_augment_keeps_seed_entities_and_extends_them_by_recurrence(self):
        seed_text = "Quill Alder"
        text = f"Please email {seed_text} soon. Later quill replied."
        base = PatternEntityDetector(use_shape=False)
        seed = base._result(text, __import__("src.NER.pattern_entity_detector", fromlist=["_Candidate"])._Candidate(
            13, 24, "PERSON", "cue", "seed-stand-in"))
        seed.metadata["mechanism"] = "spacy"
        results = PatternEntityDetector(use_shape=False).augment_entities(text, [seed])
        self.assertIs(results[0], seed)
        self.assertIn(("quill", "recurrence"),
                      [(r.section_of_text, r.metadata["mechanism"]) for r in results])

    # -- negatives -------------------------------------------------------------

    def test_ordinary_prompts_produce_no_entities(self):
        for text in (
            "Can you help me draft a message to my landlord about repairs?",
            "Explain how Microsoft Word handles tables.",
            "Please Help Me With This Request",
            "Social Security Number and Medical Records are sensitive.",
            "Dear Hiring Manager, I am writing to apply.",
            "Hello team, the Human Resources policy changed on Monday.",
            "Monday Morning meeting notes for the Project Review.",
            "Make this tenant-rights consultation note clearer.",
            "Write a function that works at scale.",
        ):
            with self.subTest(text=text):
                self.assertEqual(found(self.detector, text), [])

    def test_sentence_initial_words_are_not_names(self):
        for text in ("Draft Message to the team.", "Compose Email for review.", "Thanks Again for everything."):
            with self.subTest(text=text):
                self.assertEqual(found(self.detector, text, "PERSON"), [])

    def test_ambiguous_state_abbreviations_need_a_zip(self):
        self.assertEqual(found(self.detector, "Call the Student Office, ID is required."), [])
        self.assertIn("Boise, ID 83702", values(self.detector, "Ship to Boise, ID 83702 please.", "GPE"))

    def test_common_words_after_cues_are_not_entities(self):
        for text in ("I work at home on weekends.", "I live in a small town.", "Name: unknown", "my name is not important"):
            with self.subTest(text=text):
                self.assertEqual(found(self.detector, text), [])


if __name__ == "__main__":
    unittest.main()
