"""Mechanics tests for the robustness probe transforms (no detectors, synthetic strings only)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "extension/client-runtime")]

import robustness_probe as rp  # noqa: E402


def apply(name, text, row_id="r1"):
    return rp.apply_transform(name, text, row_id)


class TransformTests(unittest.TestCase):
    def test_deterministic_and_row_seeded(self):
        text = "Contact Zed at zed@mail.example or 5550001234, phone line open."
        for name in rp.TRANSFORMS:
            self.assertEqual(apply(name, text), apply(name, text), name)
        self.assertNotEqual(apply("homoglyph", text * 5, "a"), apply("homoglyph", text * 5, "b"))

    def test_case_transforms(self):
        self.assertEqual(apply("lowercase", "Ada LOVES Rust"), "ada loves rust")
        self.assertEqual(apply("uppercase", "Ada loves Rust"), "ADA LOVES RUST")

    def test_digit_separators_only_touch_long_runs(self):
        self.assertEqual(apply("digits_space", "pin 12 and 4155550123"), "pin 12 and 4 1 5 5 5 5 0 1 2 3")
        self.assertEqual(apply("digits_dot", "id 1234"), "id 1.2.3.4")
        self.assertEqual(apply("digits_dash", "id 123"), "id 123")
        self.assertEqual(apply("digits_dash", "id 12345"), "id 1-2-3-4-5")

    def test_digit_words_threshold_and_separators(self):
        self.assertEqual(apply("digits_words", "zip 90210"), "zip 90210")
        self.assertEqual(apply("digits_words", "call 555-0123"), "call five five five zero one two three")
        self.assertEqual(apply("digits_words", "n 100.200.3004").split()[1:4], ["one", "zero", "zero"])

    def test_email_variants(self):
        text = "write to a.b@ex-ample.co.uk now"
        self.assertEqual(apply("email_bracket", text), "write to a.b[at]ex-ample[dot]co[dot]uk now")
        self.assertEqual(apply("email_paren", text), "write to a.b(at)ex-ample(dot)co(dot)uk now")
        self.assertEqual(apply("email_word", text), "write to a.b at ex-ample dot co dot uk now")
        self.assertEqual(apply("email_bracket_at_only", text), "write to a.b[at]ex-ample.co.uk now")
        self.assertEqual(apply("email_word", "no mail here"), "no mail here")

    def test_unicode_transforms(self):
        text = "Open the account for Pam Cole at 555 0100 " * 4
        homo = apply("homoglyph", text)
        self.assertNotEqual(homo, text)
        self.assertEqual(len(homo), len(text))
        self.assertTrue(any(ord(c) > 0x37f for c in homo))
        zw = apply("zero_width", text)
        self.assertTrue(any(c in rp.ZERO_WIDTH for c in zw))
        self.assertEqual("".join(c for c in zw if c not in rp.ZERO_WIDTH), text)
        self.assertEqual(apply("fullwidth_digits", "ab 0129"), "ab ０１２９")

    def test_label_transforms(self):
        self.assertEqual(apply("label_leet", "Phone: none"), "Ph0ne: none")
        self.assertEqual(apply("label_leet", "phonetic"), "phonetic")
        self.assertNotIn("password", apply("label_leet", "my password is x"))
        typo = apply("label_typo", "phone and email and ssn")
        self.assertEqual(sorted(typo.split()[0]), sorted("phone"))
        self.assertNotEqual(typo, "phone and email and ssn")
        self.assertTrue(typo.endswith("ssn"))  # words under four letters are left alone

    def test_unchanged_text_is_reported_unchanged(self):
        self.assertEqual(apply("digits_words", "nothing numeric"), "nothing numeric")
        self.assertEqual(apply("email_word", "nothing"), "nothing")


class CandidateCanonicaliseTests(unittest.TestCase):
    def test_undoes_what_the_transforms_do(self):
        c = rp.candidate_canonicalise
        self.assertEqual(c("a​b﻿c"), "abc")
        self.assertEqual(c("id 4-1-5-5-5-5-0-1-2-3"), "id 4155550123")
        self.assertEqual(c("id 4.1.5.5.5.5.0.1.2.3"), "id 4155550123")
        self.assertEqual(c("call five five five zero one two three now").split()[1], "5550123")
        self.assertEqual(c("write a.b at ex-ample dot co dot uk now"), "write a.b@ex-ample.co.uk now")
        self.assertEqual(c("a.b@ex-ample[dot]co(dot)uk"), "a.b@ex-ample.co.uk")

    def test_word_email_shape_is_inherently_ambiguous(self):
        # prose shaped like "x at y dot z" is rewritten too; the false-conversion risk is measured, not hidden
        self.assertEqual(rp.candidate_canonicalise("see you at the dot com"), "see you@the.com")

    def test_leaves_ordinary_text_alone(self):
        c = rp.candidate_canonicalise
        for text in ("version 1.2.3 and 555-0123 at noon", "one two three go",
                     "ratio 3-1 and 4.5 stars", "ip 10.0.0.1"):
            self.assertEqual(c(text), text)


class StatsTests(unittest.TestCase):
    def test_wilson(self):
        lo, hi = rp.wilson(50, 100)
        self.assertAlmostEqual(lo, 0.404, places=2)
        self.assertAlmostEqual(hi, 0.596, places=2)
        self.assertTrue(all(map(lambda v: v != v, rp.wilson(0, 0))))
        self.assertEqual(rp.wilson(0, 10)[0], 0.0)

    def test_metrics_on_mask(self):
        expected = [True, True, False, False]
        m = rp.metrics(expected, [True, False, True, False], [True, True, True, False], [True, True, False, False])
        self.assertEqual((m["tp"], m["pos"], m["fp"], m["neg"]), (1, 2, 1, 1))
        self.assertEqual((m["base_tp"], m["base_fp"]), (2, 0))


class PreprocessingNeutralisationTests(unittest.TestCase):
    """Which transforms the shipped canonicalisation already undoes (documentation evidence)."""

    @classmethod
    def setUpClass(cls):
        from src.detection.preprocessing import normalize_with_offsets
        cls.norm = staticmethod(lambda s, lower=True: normalize_with_offsets(s, lowercase=lower).text)

    def test_neutralised(self):
        self.assertEqual(self.norm(apply("digits_space", "id 4155550123")), "id 4155550123")
        self.assertEqual(self.norm(apply("fullwidth_digits", "id 4155550123")), "id 4155550123")
        self.assertEqual(self.norm(apply("email_bracket_at_only", "mail a.b@ex.com")), "mail a.b@ex.com")
        self.assertEqual(self.norm(apply("email_paren", "mail a@b.co")), "mail a@b(dot)co")

    def test_not_neutralised(self):
        for name in ("digits_dot", "digits_dash", "digits_words", "email_word", "email_bracket", "label_leet"):
            sample = {"digits_dot": "id 4155550123", "digits_dash": "id 4155550123", "digits_words": "id 4155550123",
                      "email_word": "mail a.b@ex.com", "email_bracket": "mail a.b@ex.com",
                      "label_leet": "phone x"}[name]
            self.assertNotEqual(self.norm(apply(name, sample)), self.norm(sample), name)
        zw = apply("zero_width", "identifier token " * 6)
        self.assertNotEqual(self.norm(zw), self.norm("identifier token " * 6))
        self.assertNotEqual(self.norm(apply("homoglyph", "open account " * 8)), self.norm("open account " * 8))


if __name__ == "__main__":
    unittest.main()
