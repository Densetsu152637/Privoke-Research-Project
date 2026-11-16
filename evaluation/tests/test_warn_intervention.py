"""Hand-computed checks for the WARN intervention experiment (no model, spaCy or service)."""
from pathlib import Path
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import warn_intervention as wi

VECTORS = Path(__file__).resolve().parents[2] / "extension/test/fixtures/mask-vectors.json"


def rec(action, text_len, gold, pred):
    return {"action": action, "text_len": text_len,
            "gold": [{"start": s, "end": e, "core": True} for s, e in gold],
            "pred": [{"start": s, "end": e, "categories": ["IDENTITY"]} for s, e in pred]}


class SharedVectorTests(unittest.TestCase):
    def test_python_port_matches_extension_vectors(self):
        vectors = json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]
        self.assertGreaterEqual(len(vectors), 10)
        for vector in vectors:
            with self.subTest(vector["name"]):
                result = wi.mask_text(vector["text"], vector["spans"])
                self.assertEqual(result["text"], vector["masked"])
                self.assertEqual(result["masked_chars"], vector["masked_chars"])


class StatisticsTests(unittest.TestCase):
    def test_wilson_known_values(self):
        lo, hi = wi.wilson(5, 10)
        self.assertAlmostEqual(lo, 0.2366, places=3)
        self.assertAlmostEqual(hi, 0.7634, places=3)
        self.assertEqual(wi.wilson(0, 0), (None, None))
        self.assertEqual(wi.wilson(0, 20)[0], 0.0)
        self.assertEqual(wi.wilson(20, 20)[1], 1.0)

    def test_exact_sign_test(self):
        self.assertEqual(wi.exact_sign_test(0, 0), 1.0)
        self.assertAlmostEqual(wi.exact_sign_test(5, 0), 2 / 32)
        self.assertEqual(wi.exact_sign_test(3, 3), 1.0)


class OutcomeTests(unittest.TestCase):
    def test_arm_semantics_on_one_warned_prompt(self):
        r = rec("WARN", 30, gold=[(0, 5), (10, 15)], pred=[(0, 5)])
        plain = wi.prompt_outcome("plain_warn", r, "all")
        self.assertTrue(plain["sent"]); self.assertEqual(plain["intact_spans"], 2)
        mask = wi.prompt_outcome("warn_mask", r, "all")
        self.assertEqual((mask["intact_spans"], mask["removed_spans"], mask["masked_chars"], mask["over_chars"]), (1, 1, 5, 0))
        self.assertTrue(mask["exposed_intact"])
        self.assertFalse(wi.prompt_outcome("block", r, "all")["sent"])
        self.assertFalse(wi.prompt_outcome("warn_confirm", r, "all", 1)["sent"])
        self.assertTrue(wi.prompt_outcome("warn_confirm", r, "all", 0)["sent"])
        with self.assertRaises(ValueError):
            wi.prompt_outcome("warn_confirm", r, "all", 0.5)

    def test_allow_is_untouched_and_block_never_sent(self):
        allow = rec("ALLOW", 20, gold=[(0, 5)], pred=[(0, 5)])
        self.assertEqual(wi.prompt_outcome("warn_mask", allow, "all")["masked_chars"], 0)
        self.assertTrue(wi.prompt_outcome("warn_mask", allow, "all")["exposed_intact"])
        blocked = rec("BLOCK", 20, gold=[(0, 5)], pred=[(0, 5)])
        for arm in ("plain_warn", "warn_mask", "block"):
            self.assertFalse(wi.prompt_outcome(arm, blocked, "all")["exposed_intact"])

    def test_partial_cover_is_exposed_any_but_not_intact(self):
        r = rec("WARN", 30, gold=[(10, 20)], pred=[(10, 15)])
        out = wi.prompt_outcome("warn_mask", r, "all")
        self.assertEqual((out["intact_spans"], out["removed_spans"], out["residual_chars"]), (0, 0, 5))
        self.assertFalse(out["exposed_intact"]); self.assertTrue(out["exposed_any"])

    def test_over_redaction_counts_masked_chars_outside_gold(self):
        r = rec("WARN", 40, gold=[(10, 15)], pred=[(8, 20)])
        out = wi.prompt_outcome("warn_mask", r, "all")
        self.assertEqual((out["masked_chars"], out["over_chars"], out["removed_spans"]), (12, 7, 1))

    def test_clean_prompt_altered_only_on_warn_with_spans(self):
        self.assertTrue(wi.prompt_outcome("warn_mask", rec("WARN", 20, [], [(2, 6)]), "all")["altered"])
        self.assertFalse(wi.prompt_outcome("warn_mask", rec("ALLOW", 20, [], []), "all")["altered"])
        self.assertFalse(wi.prompt_outcome("warn_mask", rec("WARN", 20, [], []), "all")["altered"])

    def test_overlapping_predicted_spans_merge_before_counting(self):
        r = rec("WARN", 30, gold=[(5, 9)], pred=[(5, 9), (7, 12)])
        self.assertEqual(wi.prompt_outcome("warn_mask", r, "all")["masked_chars"], 7)

    def test_core_scope_drops_attribute_only_gold(self):
        r = rec("WARN", 30, gold=[(0, 4)], pred=[])
        r["gold"][0]["core"] = False
        self.assertEqual(wi.prompt_outcome("plain_warn", r, "core")["gold_spans"], 0)
        self.assertEqual(wi.prompt_outcome("plain_warn", r, "all")["gold_spans"], 1)


class ConfirmAnalyticTests(unittest.TestCase):
    def setUp(self):
        self.sensitive = [rec("ALLOW", 20, [(0, 3)], []), rec("WARN", 20, [(0, 3)], []),
                          rec("WARN", 20, [(0, 3)], []), rec("BLOCK", 20, [(0, 3)], [])]

    def test_endpoints_equal_plain_warn_and_block(self):
        plain = sum(wi.prompt_outcome("plain_warn", r, "all")["exposed_intact"] for r in self.sensitive) / 4
        block = sum(wi.prompt_outcome("block", r, "all")["exposed_intact"] for r in self.sensitive) / 4
        self.assertAlmostEqual(wi.confirm_expected(self.sensitive, 0, "all")["transmitted_intact_fraction"], plain)
        self.assertAlmostEqual(wi.confirm_expected(self.sensitive, 1, "all")["transmitted_intact_fraction"], block)

    def test_linear_in_compliance(self):
        half = wi.confirm_expected(self.sensitive, 0.5, "all")
        self.assertAlmostEqual(half["transmitted_intact_fraction"], (1 + 2 * 0.5) / 4)
        self.assertAlmostEqual(half["prevented_fraction"], 1 - 0.5)
        self.assertIn("analytic", half["label"])


class SummaryTests(unittest.TestCase):
    def test_summary_numbers_by_hand(self):
        records = [
            rec("WARN", 30, [(0, 5)], [(0, 5)]),           # masked fully
            rec("WARN", 30, [(0, 5)], []),                 # warned, nothing located: exposed under mask
            rec("ALLOW", 30, [(0, 5)], []),                # missed by the detector
            rec("BLOCK", 30, [(0, 5)], [(0, 5)]),          # blocked
            rec("WARN", 20, [], [(2, 6)]),                 # clean, altered by MASK
            rec("ALLOW", 20, [], []),                      # clean
        ]
        s = wi.summarise(records, "all")
        self.assertEqual((s["sensitive_prompts"], s["clean_prompts"]), (4, 2))
        arms = s["arms"]
        self.assertEqual(arms["plain_warn"]["transmitted_with_intact_gold_span"]["k"], 3)
        self.assertEqual(arms["warn_mask"]["transmitted_with_intact_gold_span"]["k"], 2)
        self.assertEqual(arms["block"]["transmitted_with_intact_gold_span"]["k"], 1)
        self.assertEqual(arms["warn_mask"]["clean_prompts_altered"]["k"], 1)
        self.assertEqual(arms["warn_mask"]["masked_chars_outside_gold"], 0)
        self.assertEqual(arms["warn_mask"]["clean_masked_chars"], 4)
        self.assertAlmostEqual(arms["warn_mask"]["clean_masked_chars_per_1k"], 100.0)
        self.assertEqual(arms["warn_mask"]["over_redaction_share_incl_clean"]["k"], 4)
        self.assertEqual(arms["block"]["clean_prompts_not_sent"]["k"], 1)
        self.assertEqual(arms["plain_warn"]["clean_prompts_altered"]["k"], 0)
        self.assertEqual(s["mask_vs_plain_warn"]["prompts_exposed_under_plain_not_under_mask"], 1)
        # c* = 1 - (mask_intact - allow_intact) / warn_intact = 1 - (2 - 1) / 2
        self.assertAlmostEqual(s["confirm_vs_mask"]["critical_compliance_for_confirm_to_match_mask"], 0.5)
        ws = s["warn_subset"]
        self.assertEqual(ws["n"], 2)
        self.assertEqual(ws["transmitted_with_intact_gold_span"]["plain_warn"]["k"], 2)
        self.assertEqual(ws["transmitted_with_intact_gold_span"]["warn_mask"]["k"], 1)
        self.assertEqual(ws["transmitted_with_intact_gold_span"]["block"]["k"], 0)
        sweep = {row["c"]: row for row in s["arms"]["warn_confirm"]["sweep"]}
        self.assertAlmostEqual(sweep[0.0]["transmitted_intact_fraction"], 3 / 4)
        self.assertAlmostEqual(sweep[1.0]["transmitted_intact_fraction"], 1 / 4)

    def test_rederive_is_deterministic(self):
        records = [rec("WARN", 30, [(0, 5)], [(0, 5)]), rec("ALLOW", 20, [], [])]
        self.assertEqual(json.dumps(wi.summarise(records, "all"), sort_keys=True),
                         json.dumps(wi.summarise(records, "all"), sort_keys=True))


class FreezeTests(unittest.TestCase):
    def test_wrong_hash_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dev_spans.jsonl"
            path.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                wi.freeze_inputs(path)

    def test_locked_names_are_refused(self):
        with self.assertRaises(SystemExit):
            wi.load_gold(Path("locked.jsonl"))


if __name__ == "__main__":
    unittest.main()
