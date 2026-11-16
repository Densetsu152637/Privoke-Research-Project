"""Robustness canonicalisations (all default off): format characters, obfuscated
digit identifiers, e-mail spellings, and the NER caseless gate. Author-written
generic strings only."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

import spacy  # noqa: F401  (pre-import in the main thread)

from src import pipeline
from src.NER import EntityNERDetector, ner_postfilter
from src.config import GLOBAL_CONFIG
from src.detection.preprocessing import RobustnessOptions, normalize_text, normalize_with_offsets

ALL = RobustnessOptions(True, True, True)
FORMAT = RobustnessOptions(strip_format_chars=True)
DIGITS = RobustnessOptions(canonicalise_digits=True)
EMAIL = RobustnessOptions(canonicalise_email_words=True)


def norm(text: str, options: RobustnessOptions = ALL) -> str:
    return normalize_with_offsets(text, lowercase=False, robustness=options).text


def original(text: str, normalised, needle: str) -> str:
    start = normalised.text.index(needle)
    span = normalised.original_span((start, start + len(needle)))
    return text[slice(*span)]


class FlagDefaultsTests(unittest.TestCase):
    def test_flags_default_off(self) -> None:
        with mock.patch.dict("os.environ", clear=False) as env:
            for name in ("PRIVOKE_STRIP_FORMAT_CHARS", "PRIVOKE_CANONICALISE_DIGITS",
                         "PRIVOKE_CANONICALISE_EMAIL_WORDS", "PRIVOKE_NER_CASELESS_GATE"):
                env.pop(name, None)
            config = type(GLOBAL_CONFIG)()
        self.assertFalse(config.strip_format_chars)
        self.assertFalse(config.canonicalise_digits)
        self.assertFalse(config.canonicalise_email_words)
        self.assertFalse(config.ner_caseless_gate)

    def test_environment_enables_each_flag(self) -> None:
        with mock.patch.dict("os.environ", {"PRIVOKE_STRIP_FORMAT_CHARS": "1",
                                            "PRIVOKE_CANONICALISE_DIGITS": "true",
                                            "PRIVOKE_CANONICALISE_EMAIL_WORDS": "1",
                                            "PRIVOKE_NER_CASELESS_GATE": "1"}):
            config = type(GLOBAL_CONFIG)()
        self.assertTrue(config.strip_format_chars and config.canonicalise_digits
                        and config.canonicalise_email_words and config.ner_caseless_gate)

    def test_off_leaves_text_unchanged(self) -> None:
        text = "a​b 5-5-5-1-2-3-4 five five five one two three four john dot x at example dot com"
        self.assertEqual(norm(text, RobustnessOptions()),
                         "a​b 5-5-5-1-2-3-4 five five five one two three four john dot x at example dot com")

    def test_semantic_view_ignores_the_flags(self) -> None:
        text = "a​b 5-5-5-1-2-3-4"
        with mock.patch.multiple(GLOBAL_CONFIG, strip_format_chars=True, canonicalise_digits=True,
                                 canonicalise_email_words=True):
            self.assertEqual(normalize_text(text), "a​b 5-5-5-1-2-3-4")
            self.assertEqual(normalize_with_offsets(text, lowercase=False).text, "ab 5551234")

    def test_detector_view_follows_config(self) -> None:
        with mock.patch.object(GLOBAL_CONFIG, "strip_format_chars", True):
            self.assertEqual(normalize_with_offsets("a​b", lowercase=False).text, "ab")
        self.assertEqual(normalize_with_offsets("a​b", lowercase=False).text, "a​b")


class FormatCharacterTests(unittest.TestCase):
    def test_invisible_characters_are_removed(self) -> None:
        for char in ("​", "‌", "‍", "⁠", "﻿", "­", "‎", "‏", "‮",
                     "\U000e0041"):
            self.assertEqual(norm(f"jo{char}hn", FORMAT), "john", repr(char))

    def test_visible_text_and_other_marks_are_kept(self) -> None:
        text = "Zoë 日本語 é  x"
        self.assertEqual(norm(text, FORMAT), norm(text, RobustnessOptions()))

    def test_digits_split_by_zero_width_join_into_a_run(self) -> None:
        self.assertEqual(norm("12​34‌5678", FORMAT), "12345678")

    def test_offsets_cover_the_removed_character(self) -> None:
        text = "Call jo​hn﻿ now"
        normalised = normalize_with_offsets(text, lowercase=False, robustness=FORMAT)
        self.assertEqual(normalised.text, "Call john now")
        self.assertEqual(original(text, normalised, "john"), "jo​hn﻿")
        self.assertEqual(original(text, normalised, "now"), "now")
        self.assertEqual(len(normalised.origins), len(normalised.text))

    def test_leading_and_trailing_format_characters(self) -> None:
        text = "﻿​Abc​"
        normalised = normalize_with_offsets(text, lowercase=False, robustness=FORMAT)
        self.assertEqual(normalised.text, "Abc")
        self.assertEqual(original(text, normalised, "Abc"), "Abc​")

    def test_composition_survives_an_intervening_format_character(self) -> None:
        self.assertEqual(norm("e​́", FORMAT), norm("é", FORMAT))


class DigitCanonicalisationTests(unittest.TestCase):
    def test_single_digit_chains_are_joined(self) -> None:
        self.assertEqual(norm("id 5-5-5-1-2-3-4-5-6", DIGITS), "id 555123456")
        self.assertEqual(norm("tel 5.5.5.1.2.3.4.5.6.7.", DIGITS), "tel 5551234567.")
        self.assertEqual(norm("no 5/5/5/1/2/3/4", DIGITS), "no 5551234")
        self.assertEqual(norm("pin 1-2-3-4.", DIGITS), "pin 1234.")

    def test_grouped_and_punctuated_numbers_are_not_merged(self) -> None:
        for text in (
            "call 555-123-4567", "ssn 123-45-6789", "card 4111-1111-1111-1111", "date 2024-01-02", "d 1-2-2024",
            "range 3-4", "ratio 1:2:3:4", "score 5-5-5", "decimal 3.14159", "version 1.2.3", "version 1.2.3.4.5",
            "ip 192.168.0.1", "ip 1.2.3.4", "fraction 1/2/3",
            "dotted 1.2.3.4.5.6",
        ):
            self.assertEqual(norm(text, DIGITS), text, text)

    def test_only_the_single_digit_chain_is_joined_and_groups_stay(self) -> None:
        self.assertEqual(norm("born 1-9-7-3-01-29", DIGITS), "born 1973-01-29")
        self.assertEqual(norm("ssn 522-48-5-5-4-6", DIGITS), "ssn 522-48-5546")
        self.assertEqual(norm("dashes 12-3-4-5-6 and 1-2-3-4-56", DIGITS), "dashes 12-3456 and 1234-56")

    def test_chain_after_a_label_or_letters_is_joined(self) -> None:
        self.assertEqual(norm("MRN-8-8-2-5-9-2 ok", DIGITS), "MRN-882592 ok")
        self.assertEqual(norm("id AB1-2-3-4-5-6", DIGITS), "id AB123456")

    def test_chain_keeps_surrounding_text_and_offsets(self) -> None:
        text = "Acct: 5-5-5-1-2-3-4, thanks"
        normalised = normalize_with_offsets(text, lowercase=False, robustness=DIGITS)
        self.assertEqual(normalised.text, "Acct: 5551234, thanks")
        self.assertEqual(original(text, normalised, "5551234"), "5-5-5-1-2-3-4")
        self.assertEqual(original(text, normalised, "thanks"), "thanks")
        start = normalised.text.index("5551234")
        self.assertEqual(normalised.origins[start + 2], (text.index("5-5-5") + 4, text.index("5-5-5") + 5))

    def test_spelled_digits_become_digits(self) -> None:
        self.assertEqual(norm("it is five five five one two three four", DIGITS), "it is 5551234")
        self.assertEqual(norm("Five Five FIVE one TWO three four.", DIGITS), "5551234.")
        self.assertEqual(norm("oh six four zero nine one two", DIGITS), "0640912")
        self.assertEqual(norm("nine nine nine zero zero zero zero zero", DIGITS), "99900000")

    def test_spelled_digits_keep_stated_grouping(self) -> None:
        self.assertEqual(norm("five five five - one two three four", DIGITS), "555-1234")
        self.assertEqual(norm("five-five-five-one-two-three-four", DIGITS), "5551234")   # then a single-digit chain
        self.assertEqual(norm("nine nine nine, zero zero zero zero zero", DIGITS),
                         "nine nine nine, zero zero zero zero zero")

    def test_short_or_ambiguous_spelled_runs_are_left_alone(self) -> None:
        for text in (
            "one two three", "call me on five five five one two three", "oh oh oh oh oh oh oh oh",
            "one two three four five six seven", "nine eight seven six five four three two", "someone five",
            "five-star", "the one and only", "oh oh oh one two",
        ):
            self.assertEqual(norm(text, DIGITS), text, text)

    def test_spelled_offsets(self) -> None:
        text = "pin five five five one two three four ok"
        normalised = normalize_with_offsets(text, lowercase=False, robustness=DIGITS)
        self.assertEqual(normalised.text, "pin 5551234 ok")
        self.assertEqual(original(text, normalised, "5551234"), "five five five one two three four")
        self.assertEqual(original(text, normalised, "ok"), "ok")
        three = normalised.text.index("1") + 2
        self.assertEqual(text[slice(*normalised.origins[three])], "three")

    def test_existing_digit_space_collapse_still_applies(self) -> None:
        self.assertEqual(norm("5 5 5 1 2 3 4", DIGITS), "5551234")
        self.assertEqual(norm("5 5 5 1 2 3 4", RobustnessOptions()), "5551234")


class EmailSpellingTests(unittest.TestCase):
    def test_bracket_and_paren_dots(self) -> None:
        self.assertEqual(norm("mail john [dot] smith [at] example [dot] com now", EMAIL),
                         "mail john.smith@example.com now")
        self.assertEqual(norm("mail john(dot)smith(at)example(dot)com now", EMAIL),
                         "mail john.smith@example.com now")
        self.assertEqual(norm("mail John[DOT]Smith@Example[Dot]COM", EMAIL), "mail John.Smith@Example.COM")

    def test_word_spellings(self) -> None:
        self.assertEqual(norm("mail john dot smith at example dot com now", EMAIL), "mail john.smith@example.com now")
        self.assertEqual(norm("mail jsmith at mail dot example dot co dot uk", EMAIL), "mail jsmith@mail.example.co.uk")
        self.assertEqual(norm("mail JOHN AT Example DOT org.", EMAIL), "mail JOHN@Example.org.")
        self.assertEqual(norm("mail bob@example dot com", EMAIL), "mail bob@example.com")

    def test_real_addresses_and_prose_are_untouched(self) -> None:
        for text in (
            "mail bob@example.com", "meet me at noon dot com", "look at example dot com", "he was at home dot",
            "we arrive at 5 dot", "see you at example", "the dot at the end", "say hello at example dot zzzz1",
            "ask them at example dot commentary", "it is at the dot com", "item at store dot",
            "write to (dot) or [dot] marks", "points: a dot b",
        ):
            self.assertEqual(norm(text, EMAIL), text, text)

    def test_offsets(self) -> None:
        text = "x john dot smith at example dot com y"
        normalised = normalize_with_offsets(text, lowercase=False, robustness=EMAIL)
        self.assertEqual(normalised.text, "x john.smith@example.com y")
        self.assertEqual(original(text, normalised, "john.smith@example.com"), "john dot smith at example dot com")
        self.assertEqual(original(text, normalised, "smith"), "smith")
        self.assertEqual(original(text, normalised, "example"), "example")
        self.assertEqual(original(text, normalised, "y"), "y")
        dot = normalised.text.index(".")
        self.assertEqual(text[slice(*normalised.origins[dot])], " dot ")

    def test_bracket_at_offsets_cover_both_markers(self) -> None:
        text = "bob[at]example[dot]com"
        normalised = normalize_with_offsets(text, lowercase=False, robustness=EMAIL)
        self.assertEqual(normalised.text, "bob@example.com")
        self.assertEqual(original(text, normalised, "bob@example.com"), text)
        self.assertEqual(text[slice(*normalised.origins[3])], "[at]")
        self.assertEqual(text[slice(*normalised.origins[11])], "[dot]")


class PipelineIntegrationTests(unittest.TestCase):
    def _regex_spans(self, text: str, **flags) -> list[str]:
        with mock.patch.multiple(GLOBAL_CONFIG, **flags):
            analysis = pipeline.analyse_text(text, layers=["regex"], regex_first=False)
        self.assertEqual([layer.layer for layer in analysis.layers], ["regex"])
        spans = []
        for result in analysis.layers[0].results:
            if result.span:
                spans.append(text[result.span[0]:result.span[1]])
        return spans

    def test_obfuscated_email_is_detected_only_when_enabled(self) -> None:
        text = "contact john dot smith at example dot com today"
        self.assertEqual(self._regex_spans(text, canonicalise_email_words=False), [])
        spans = self._regex_spans(text, canonicalise_email_words=True)
        self.assertIn("john dot smith at example dot com", spans)

    def test_zero_width_split_email_is_detected_only_when_enabled(self) -> None:
        text = "write to jo​hn.smith@exam‌ple.com please"
        self.assertNotIn("jo​hn.smith@exam‌ple.com", self._regex_spans(text, strip_format_chars=False))
        spans = self._regex_spans(text, strip_format_chars=True)
        self.assertIn("jo​hn.smith@exam‌ple.com", spans)


class CaselessGateTests(unittest.TestCase):
    def test_case_signal(self) -> None:
        has = ner_postfilter.has_case_signal
        self.assertTrue(has("Alice lives in Paris"))
        self.assertTrue(has("hello there Bob"))
        self.assertTrue(has("Hello world"))
        self.assertFalse(has("alice lives in paris"))
        self.assertFalse(has("ALICE LIVES IN PARIS"))
        self.assertFalse(has("12345 !!"))
        self.assertFalse(has(""))

    def test_pronoun_i_is_not_a_case_signal(self) -> None:
        has = ner_postfilter.has_case_signal
        self.assertFalse(has("i think I live in paris and I'm sure I'll stay, I've said so"))
        self.assertFalse(has("what should I do about alice"))
        self.assertTrue(has("what should I do about Alice"))
        self.assertTrue(has("what is ID"))      # all-caps token beside lower case is a signal

    def test_fold_case_preserves_length(self) -> None:
        for text in ("ALICE İSTANBUL ΣΑΣ", "Straße", "ǅ x"):
            self.assertEqual(len(ner_postfilter.fold_case(text)), len(text), text)
        self.assertEqual(ner_postfilter.fold_case("ALICE Smith"), "alice smith")


class CaselessGateDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.detector = EntityNERDetector()
        except OSError as exc:
            raise unittest.SkipTest(f"spaCy model unavailable: {exc}")

    def _texts_seen_by_model(self, text: str, gate: bool) -> str:
        seen = []
        real = self.detector.nlp

        def spy(value):
            seen.append(value)
            return real(value)

        with mock.patch.object(GLOBAL_CONFIG, "ner_caseless_gate", gate), \
                mock.patch.object(self.detector, "nlp", side_effect=spy):
            self.detector.extract_entities(text)
        return seen[-1]

    def test_gate_off_passes_text_through(self) -> None:
        self.assertEqual(self._texts_seen_by_model("ALICE LIVES IN PARIS", False), "ALICE LIVES IN PARIS")

    def test_gate_lowercases_caseless_text_only(self) -> None:
        self.assertEqual(self._texts_seen_by_model("ALICE LIVES IN PARIS", True), "alice lives in paris")
        self.assertEqual(self._texts_seen_by_model("Alice lives in Paris", True), "Alice lives in Paris")

    def test_spans_stay_aligned_with_the_input(self) -> None:
        text = "MY SISTER SARA LIVES IN PARIS."
        with mock.patch.object(GLOBAL_CONFIG, "ner_caseless_gate", True):
            results = self.detector.extract_entities(text)
        for result in results:
            start, end = result.span
            self.assertEqual(text[start:end].lower(), result.section_of_text.lower())

    def test_gate_never_changes_cased_input_results(self) -> None:
        text = "My sister Sara moved from Paris to Berlin to join Acme Corp."
        with mock.patch.object(GLOBAL_CONFIG, "ner_caseless_gate", False):
            expected = [(r.span, r.classification.sensitivity().name) for r in self.detector.extract_entities(text)]
        with mock.patch.object(GLOBAL_CONFIG, "ner_caseless_gate", True):
            actual = [(r.span, r.classification.sensitivity().name) for r in self.detector.extract_entities(text)]
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
