"""Tests for the opt-in NER post-filter (author-written generic sentences)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

import spacy  # noqa: F401  (pre-import in the main thread)

from src.NER import EntityNERDetector, ner_postfilter
from src.config import GLOBAL_CONFIG


def _detector() -> EntityNERDetector:
    return EntityNERDetector()


class PostfilterTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.detector = _detector()
        except OSError as exc:  # model not installed
            raise unittest.SkipTest(f"spaCy model unavailable: {exc}")

    def kept(self, text: str, enabled: bool = True) -> dict[str, str]:
        """Entity text -> final sensitivity name."""
        with mock.patch.object(GLOBAL_CONFIG, "ner_postfilter", enabled):
            return {
                r.section_of_text: r.classification.sensitivity().name
                for r in self.detector.extract_entities(text)
            }

    def decisions(self, text: str, **kwargs) -> dict[str, ner_postfilter.Decision]:
        doc = self.detector.nlp(text)
        ents = [e for e in doc.ents if e.label_ in {"PERSON", "GPE", "LOC", "FAC", "ORG"}]
        out = ner_postfilter.postfilter(doc, ents, nlp=self.detector.nlp, **kwargs)
        return {d.candidate.text: d for d in out}


class FlagTests(PostfilterTestCase):
    def test_flag_defaults_off_and_passes_raw_entities_through(self) -> None:
        self.assertFalse(type(GLOBAL_CONFIG)().ner_postfilter)
        raw = self.kept("Show a sample like Xs instead of the real digits.", enabled=False)
        self.assertEqual(raw, {"Xs": "S2"})

    def test_filtered_results_record_the_deciding_rule(self) -> None:
        with mock.patch.object(GLOBAL_CONFIG, "ner_postfilter", True):
            results = self.detector.extract_entities("My name is Maria Lopez and I live in Madrid.")
        self.assertTrue(results)
        self.assertTrue(all("postfilter_rule" in r.metadata for r in results))


class SpanRuleTests(PostfilterTestCase):
    def test_placeholder_runs_are_suppressed(self) -> None:
        self.assertEqual(self.kept("Please replace the digits with XXXX XXXX in the example."), {})
        self.assertEqual(self.kept("Show a sample like Xs instead of the real digits."), {})
        self.assertEqual(self.decisions("Show a sample like Xs instead of the real digits.")["Xs"].rule, "placeholder")

    def test_identifier_like_tokens_are_not_named_entities(self) -> None:
        self.assertEqual(self.kept("His email is carla.diaz99@example.com"), {})
        self.assertEqual(self.kept("Account code TempPass5344 was reset."), {})

    def test_markdown_heading_is_structural(self) -> None:
        self.assertEqual(self.kept("# Quarterly Budget Overview"), {})
        self.assertEqual(self.decisions("# Quarterly Budget Overview")["# Quarterly Budget Overview"].rule, "structural")

    def test_title_case_heading_is_suppressed(self) -> None:
        self.assertEqual(self.kept("Voter Eligibility Requirements And Deadlines"), {})

    def test_heading_rule_is_inert_on_lowercase_text(self) -> None:
        # No capitalisation evidence: the structural title-case test must not fire.
        decisions = self.decisions("marcus webb and dana cole discussed budgets.")
        self.assertTrue(all(d.rule != "structural" for d in decisions.values()))

    def test_short_acronyms_need_locating_context(self) -> None:
        self.assertEqual(self.kept("Format a US phone number with the area code."), {})
        self.assertEqual(self.kept("Can you explain what an SSN is?"), {})
        self.assertEqual(self.kept("The IP changed after the router restart."), {})
        self.assertEqual(self.decisions("Format a US phone number with the area code.")["US"].rule, "short_acronym")
        # With a locating preposition the acronym is a genuine place.
        self.assertEqual(self.kept("We moved to LA last spring."), {"LA": "S2"})
        self.assertEqual(self.kept("I'm from the UK and I need advice."), {"UK": "S2"})

    def test_common_word_collision_is_suppressed_without_context(self) -> None:
        text = "Please send the Proposal to the committee."
        self.assertEqual(self.kept(text, enabled=False), {"Proposal": "S2"})
        self.assertEqual(self.kept(text), {})
        self.assertEqual(self.decisions(text)["Proposal"].rule, "common_phrase")

    def test_unusual_capitalised_names_are_not_common_words(self) -> None:
        decision = self.decisions("Dear Dhondup, please call back.").get("Dhondup")
        if decision is not None:
            self.assertNotEqual(decision.rule, "common_phrase")

    def test_disabling_a_span_rule_restores_the_entity_to_stage_two(self) -> None:
        with_rule = self.decisions("Show a sample like Xs instead of the real digits.")["Xs"]
        without = self.decisions("Show a sample like Xs instead of the real digits.", disabled=["placeholder"])["Xs"]
        self.assertFalse(with_rule.keep)
        self.assertNotEqual(without.rule, "placeholder")


class CombinationRuleTests(PostfilterTestCase):
    def test_person_linked_to_place_is_sensitive(self) -> None:
        kept = self.kept("Sarah Johnson lives in Denver.")
        self.assertEqual(kept, {"Sarah Johnson": "S2", "Denver": "S2"})

    def test_lone_place_is_not_sensitive(self) -> None:
        self.assertEqual(self.kept("The conference is held in Paris every year."), {})
        self.assertEqual(self.kept("Tell me about the UK economy."), {})

    def test_lone_place_pair_in_a_geography_fact_is_not_sensitive(self) -> None:
        self.assertEqual(self.kept("Berlin is the capital of Germany."), {})

    def test_lone_organisation_is_not_sensitive(self) -> None:
        self.assertEqual(self.kept("Microsoft released a new update yesterday."), {})
        self.assertEqual(self.kept("Acme Corporation announced earnings."), {})

    def test_relation_cue_makes_place_and_organisation_personal(self) -> None:
        self.assertEqual(self.kept("I live in Oslo."), {"Oslo": "S2"})
        kept = self.kept("I work at Globex Corporation in Leeds.")
        self.assertEqual(set(kept), {"Globex Corporation", "Leeds"})
        self.assertEqual(self.decisions("I work at Globex Corporation in Leeds.")["Leeds"].rule, "relation_anchored")

    def test_multi_token_name_is_corroborated(self) -> None:
        self.assertEqual(self.kept("Marcus Webb and Dana Cole discussed budgets."),
                         {"Marcus Webb": "S2", "Dana Cole": "S2"})

    def test_cue_introduced_single_name_is_kept(self) -> None:
        self.assertEqual(self.kept("Hello Sparky, how are you today?"), {"Sparky": "S2"})

    def test_recurring_single_name_is_kept(self) -> None:
        kept = self.kept("Jordan said Jordan would arrive by noon.")
        self.assertEqual(kept, {"Jordan": "S2"})

    def test_uncorroborated_single_name_is_dropped(self) -> None:
        self.assertEqual(self.kept("Who is Jordan?"), {})
        self.assertEqual(self.decisions("Who is Jordan?")["Jordan"].rule, "weak_person")

    def test_uncorroborated_single_name_can_be_downgraded_instead(self) -> None:
        decision = self.decisions("Who is Jordan?", weak_person=ner_postfilter.Sensitivity.S1)["Jordan"]
        self.assertTrue(decision.keep)
        self.assertEqual(decision.sensitivity, ner_postfilter.Sensitivity.S1)

    def test_street_beside_a_number_is_an_address(self) -> None:
        self.assertEqual(self.kept("We live at 12 Elm Street near the park."), {"Elm Street": "S2"})

    def test_person_with_place_via_salutation_and_relation(self) -> None:
        kept = self.kept("Hi Jordan, I am from LA and my sister Dana lives in Oslo.")
        self.assertEqual(set(kept), {"Jordan", "LA", "Dana", "Oslo"})


class RuleTableTests(unittest.TestCase):
    def test_every_rule_has_a_unique_name_and_principle(self) -> None:
        names = [r.name for r in ner_postfilter.COMBINATION_RULES] + [n for n, _ in ner_postfilter.SPAN_RULES]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(r.principle for r in ner_postfilter.COMBINATION_RULES))


if __name__ == "__main__":
    unittest.main()
