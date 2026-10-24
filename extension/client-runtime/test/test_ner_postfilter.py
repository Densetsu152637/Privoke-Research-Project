"""Tests for the NER post-filter (author-written generic sentences)."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
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
    def test_flag_defaults_on_and_zero_disables(self) -> None:
        with mock.patch.dict("os.environ"):
            os.environ.pop("PRIVOKE_NER_POSTFILTER", None)
            self.assertTrue(type(GLOBAL_CONFIG)().ner_postfilter)
        with mock.patch.dict("os.environ", {"PRIVOKE_NER_POSTFILTER": "0"}):
            self.assertFalse(type(GLOBAL_CONFIG)().ner_postfilter)

    def test_disabled_flag_passes_raw_entities_through(self) -> None:
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

    def test_single_heading_word_read_as_a_person_is_dropped(self) -> None:
        self.assertEqual(self.kept("Show the Voter list."), {})
        self.assertEqual(self.decisions("Show the Voter list.")["Voter"].rule, "common_phrase")

    def test_people_inside_headings_and_title_lines_are_kept(self) -> None:
        self.assertEqual(self.kept("## Meeting notes with Sarah Connor"), {"Sarah Connor": "S2"})
        self.assertEqual(self.kept("Jane Doe Senior Account Manager"), {"Jane Doe Senior": "S2"})

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

    def test_uncommon_single_name_is_not_a_common_word(self) -> None:
        decisions = self.decisions("Forward this to Kowalski before Friday.")
        if "Kowalski" not in decisions:
            self.skipTest("spaCy did not tag the probe name as an entity")
        self.assertEqual(decisions["Kowalski"].rule, "weak_person")

    def test_multi_word_names_of_ordinary_words_are_not_common_phrases(self) -> None:
        self.assertEqual(self.kept("Ask Will Young to sign the lease."), {"Will Young": "S2"})

    def test_mask_conventions_are_not_tied_to_one_letter(self) -> None:
        def masked(text: str) -> bool:
            return ner_postfilter._placeholder(text, SimpleNamespace(text=text, start=0, end=len(text)), None)

        for text in ("XXXX", "Xs", "Zs", "Ns", "aaaa"):
            self.assertTrue(masked(text), text)
        for text in ("US", "Ann", "Sam", "UK"):
            self.assertFalse(masked(text), text)

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

    def test_uncorroborated_single_name_is_kept_at_s1(self) -> None:
        self.assertEqual(self.kept("Who is Jordan?"), {"Jordan": "S1"})
        self.assertEqual(self.decisions("Who is Jordan?")["Jordan"].rule, "weak_person")

    def test_uncorroborated_single_name_can_be_dropped_instead(self) -> None:
        decision = self.decisions("Who is Jordan?", weak_person=None)["Jordan"]
        self.assertFalse(decision.keep)

    def test_street_beside_a_number_is_an_address(self) -> None:
        self.assertEqual(self.kept("We live at 12 Elm Street near the park."), {"Elm Street": "S2"})

    def test_person_with_place_via_salutation_and_relation(self) -> None:
        kept = self.kept("Hi Jordan, I am from LA and my sister Dana lives in Oslo.")
        self.assertEqual(set(kept), {"Jordan", "LA", "Dana", "Oslo"})


class RecallGuardTests(PostfilterTestCase):
    """Genuine disclosures that earlier rule sets lost or could lose."""

    def test_third_party_single_names_stay_sensitive(self) -> None:
        self.assertEqual(self.kept("Can you write a reference letter for Hannah?"), {"Hannah": "S1"})
        self.assertEqual(self.kept("Forward this to Kowalski before Friday."), {"Kowalski": "S1"})

    def test_possessed_role_nouns_corroborate_names(self) -> None:
        self.assertEqual(self.kept("My therapist, Angela, says I should rest."), {"Angela": "S2"})
        self.assertEqual(self.kept("Tomas, my accountant, filed it."), {"Tomas": "S2"})

    def test_parenthetical_field_label_corroborates_a_name(self) -> None:
        self.assertEqual(self.kept("Dana Ruiz (patient) arrived at noon."), {"Dana Ruiz": "S2"})

    def test_role_at_organisation_ties_it_and_its_city_to_the_speaker(self) -> None:
        kept = self.kept("I am a nurse at St Mary's Hospital in Leeds.")
        self.assertEqual(set(kept), {"St Mary's Hospital", "Leeds"})
        kept = self.kept("I'm a teacher at Lincoln High School in Omaha.")
        self.assertEqual(set(kept), {"Lincoln High School", "Omaha"})
        self.assertEqual(set(self.kept("My doctor at Mayo Clinic changed my dose.")), {"Mayo Clinic"})

    def test_possessive_place_cue_covers_every_possessive(self) -> None:
        self.assertEqual(self.kept("Our office in SF closed."), {"SF": "S2"})

    def test_person_and_place_without_independent_evidence_are_not_linked(self) -> None:
        # A bare locating preposition is true of any event; it does not corroborate.
        kept = self.kept("Napoleon was defeated at Waterloo in 1815.")
        self.assertNotIn("S2", kept.values())


class LexiconCacheTests(unittest.TestCase):
    @staticmethod
    def _stub_nlp(name: str, words: set) -> SimpleNamespace:
        table = SimpleNamespace(values=lambda: [words])
        lookups = SimpleNamespace(has_table=lambda key: key == "lemma_index", get_table=lambda key: table)
        lemmatizer = SimpleNamespace(lookups=lookups)
        return SimpleNamespace(
            meta={"lang": "en", "name": name, "version": "9.9.9"},
            pipe_names=["lemmatizer"],
            get_pipe=lambda _name: lemmatizer,
        )

    def setUp(self) -> None:
        patcher = mock.patch.dict(ner_postfilter._LEXICON_CACHE, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_cache_is_keyed_by_model_meta_not_object_identity(self) -> None:
        first = ner_postfilter._english_lexicon(self._stub_nlp("model_a", {"table"}))
        again = ner_postfilter._english_lexicon(self._stub_nlp("model_a", {"other"}))
        self.assertIs(first, again)
        self.assertEqual(first, frozenset({"table"}))
        other = ner_postfilter._english_lexicon(self._stub_nlp("model_b", {"chair"}))
        self.assertEqual(other, frozenset({"chair"}))

    def test_model_without_identity_is_not_cached(self) -> None:
        nlp = self._stub_nlp("model_c", {"desk"})
        nlp.meta = {}
        self.assertEqual(ner_postfilter._english_lexicon(nlp), frozenset({"desk"}))
        self.assertEqual(ner_postfilter._LEXICON_CACHE, {})


class AnalyseTextIntegrationTests(PostfilterTestCase):
    def test_both_flags_through_the_pipeline_ner_layer(self) -> None:
        from src import pipeline

        text = "My name is Maria Lopez and I live in Madrid. The format uses XXXX for digits."
        with mock.patch.object(GLOBAL_CONFIG, "case_preserving_detectors", True), \
                mock.patch.object(GLOBAL_CONFIG, "ner_postfilter", True):
            analysis = pipeline.analyse_text(text, layers=["ner"], regex_first=False)
        self.assertEqual([layer.layer for layer in analysis.layers], ["ner"])
        layer = analysis.layers[0]
        self.assertEqual(layer.status, "ok")
        found = {r.section_of_text: r.metadata["postfilter_rule"] for r in layer.results}
        self.assertEqual(found, {"Maria Lopez": "person_linked", "Madrid": "place_org_linked"})


class RuleTableTests(unittest.TestCase):
    def test_every_rule_has_a_unique_name_and_principle(self) -> None:
        names = [r.name for r in ner_postfilter.COMBINATION_RULES] + [n for n, _ in ner_postfilter.SPAN_RULES]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(r.principle for r in ner_postfilter.COMBINATION_RULES))


if __name__ == "__main__":
    unittest.main()
