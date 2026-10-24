"""Hand-computed checks for span-level scoring (no model, spaCy or service)."""
from pathlib import Path
import sys
import unittest

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import span_scoring as ss


def gold(*items):
    return [{"start": s, "end": e, "label": label} for s, e, label in items]


def pred(*items):
    return [{"start": s, "end": e, "categories": list(cats), "source": src} for s, e, cats, src in items]


class IntervalTests(unittest.TestCase):
    def test_merge_joins_touching_and_overlapping(self):
        self.assertEqual(ss.merge_intervals([(5, 8), (0, 3), (3, 4), (7, 10), (12, 12)]), [(0, 4), (5, 10)])

    def test_intersect_and_subtract(self):
        a, b = [(0, 10), (20, 30)], [(5, 25)]
        self.assertEqual(ss.intersect_len(a, b), 10)
        self.assertEqual(ss.subtract_intervals(a, b), [(0, 5), (25, 30)])
        self.assertEqual(ss.subtract_len(a, b), 10)

    def test_iou_and_overlap(self):
        self.assertAlmostEqual(ss.iou((0, 10), (5, 15)), 5 / 15)
        self.assertEqual(ss.iou((0, 10), (10, 20)), 0.0)
        self.assertEqual(ss.overlap_len((0, 10), (9, 20)), 1)

    def test_max_matching_needs_augmenting_path(self):
        # left0 can use right0 or right1; left1 only right0 -> greedy first-choice would block left1
        self.assertEqual(ss.max_matching(2, [[0, 1], [0]]), [(0, 1), (1, 0)])


class MatchingTests(unittest.TestCase):
    def setUp(self):
        self.g = ss._norm_gold(gold((0, 10, "PERSON"), (20, 30, "email")))

    def test_criteria(self):
        p = ss.collapse_pred(pred((0, 10, ["IDENTITY"], "a"), (22, 40, ["IDENTITY"], "b")))
        self.assertEqual(len(ss.match_entities(self.g, p, "exact")), 1)
        self.assertEqual(len(ss.match_entities(self.g, p, "iou50")), 1)  # (22,40) vs (20,30): 8/20 < 0.5
        self.assertEqual(len(ss.match_entities(self.g, p, "overlap")), 2)

    def test_iou_boundary_is_inclusive(self):
        g = ss._norm_gold(gold((0, 10, "PERSON")))
        p = ss.collapse_pred(pred((0, 5, ["IDENTITY"], "x")))  # IoU exactly 0.5
        self.assertEqual(len(ss.match_entities(g, p, "iou50")), 1)

    def test_typed_requires_category_intersection(self):
        p = ss.collapse_pred(pred((0, 10, ["LOCATION"], "x"), (20, 30, ["IDENTITY"], "y")))
        self.assertEqual(len(ss.match_entities(self.g, p, "overlap")), 2)
        self.assertEqual(len(ss.match_entities(self.g, p, "overlap_typed")), 1)

    def test_one_predicted_span_cannot_match_two_gold(self):
        g = ss._norm_gold(gold((0, 5, "GIVENNAME"), (6, 12, "SURNAME")))
        p = ss.collapse_pred(pred((0, 12, ["IDENTITY"], "PERSON")))
        self.assertEqual(len(ss.match_entities(g, p, "overlap")), 1)

    def test_collapse_unions_categories_and_drops_empty(self):
        out = ss.collapse_pred(pred((0, 4, ["IDENTITY"], "r1"), (0, 4, ["FINANCIAL"], "r2"), (6, 6, ["X"], "e")))
        self.assertEqual(out, [{"start": 0, "end": 4, "categories": ("FINANCIAL", "IDENTITY"),
                                "sources": ("r1", "r2")}])


class LabelMappingTests(unittest.TestCase):
    def test_label_normalisation_across_sources(self):
        self.assertEqual(ss.family_of("EMAIL_ADDRESS"), "CONTACT")
        self.assertEqual(ss.family_of("email"), "CONTACT")
        self.assertEqual(ss.family_of("GIVENNAME"), "NAME")
        self.assertEqual(ss.family_of("first_name"), "NAME")
        self.assertEqual(ss.family_of("occupation"), "OCCUPATION")
        self.assertEqual(ss.family_of("no_such_label"), "UNMAPPED")

    def test_unmapped_labels_are_reported(self):
        rows = [{"entities": gold((0, 1, "weird"), (2, 3, "email"), (4, 5, "weird"))}]
        self.assertEqual(ss.unmapped_labels(rows), {"weird": 2})

    def test_core_scope_excludes_attribute_families(self):
        self.assertIn("NAME", ss.CORE_FAMILIES)
        self.assertIn("TEMPORAL", ss.CORE_FAMILIES)
        self.assertNotIn("DEMOGRAPHIC", ss.CORE_FAMILIES)
        self.assertNotIn("OCCUPATION", ss.CORE_FAMILIES)


class PromptScoreTests(unittest.TestCase):
    GOLD = gold((10, 20, "PERSON"), (30, 40, "email"), (50, 60, "TITLE"))
    PRED = pred((10, 20, ["IDENTITY"], "PERSON"), (35, 45, ["IDENTITY"], "email"), (70, 80, ["LOCATION"], "gpe"))

    def test_all_scope_counts(self):
        s = ss.score_prompt(self.GOLD, self.PRED, 100, "all")
        self.assertEqual((s["n_gold"], s["n_pred"]), (3, 3))
        self.assertEqual((s["tp_exact"], s["tp_iou50"], s["tp_overlap"], s["tp_overlap_typed"]), (1, 1, 2, 2))
        self.assertEqual((s["gold_overlapped"], s["pred_overlapping"]), (2, 2))
        self.assertEqual((s["gold_chars"], s["pred_chars"], s["covered_chars"], s["over_chars"]), (30, 30, 15, 15))
        self.assertEqual((s["gold_full"], s["all_masked"], s["all_touched"]), (1, 0, 0))
        self.assertEqual(s["n_prompts_gold"], 1)
        m = ss.metrics_from_counts(s)
        self.assertAlmostEqual(m["precision_exact"], 1 / 3)
        self.assertAlmostEqual(m["recall_overlap"], 2 / 3)
        self.assertAlmostEqual(m["char_recall"], 0.5)
        self.assertAlmostEqual(m["over_masking_share"], 0.5)
        self.assertAlmostEqual(m["over_mask_chars_per_1k"], 150.0)

    def test_core_scope_ignores_attribute_gold(self):
        s = ss.score_prompt(self.GOLD, self.PRED, 100, "core")
        self.assertEqual((s["n_gold"], s["n_pred"], s["tp_overlap"]), (2, 3, 2))
        self.assertEqual((s["gold_chars"], s["covered_chars"], s["all_touched"], s["all_masked"]), (20, 15, 1, 0))

    def test_core_scope_drops_predictions_inside_attribute_gold_only(self):
        # (52, 58) lies inside the TITLE span: ignored, not a false positive; (31, 33) overlaps core gold: kept
        p = pred((52, 58, ["IDENTITY"], "x"), (31, 33, ["IDENTITY"], "y"), (90, 95, ["IDENTITY"], "z"))
        s = ss.score_prompt(self.GOLD, p, 100, "core")
        self.assertEqual(s["n_pred"], 2)
        self.assertEqual(s["pred_chars"], 7)  # 2 + 5, the ignored 6 chars are subtracted
        s_all = ss.score_prompt(self.GOLD, p, 100, "all")
        self.assertEqual((s_all["n_pred"], s_all["pred_chars"]), (3, 13))
        self.assertEqual(s_all["pred_overlapping"], 2)

    def test_one_wide_span_masks_everything(self):
        s = ss.score_prompt(self.GOLD, pred((0, 100, ["IDENTITY"], "wide")), 100)
        self.assertEqual((s["tp_overlap"], s["gold_overlapped"], s["all_masked"], s["all_touched"]), (1, 3, 1, 1))
        self.assertEqual((s["covered_chars"], s["over_chars"]), (30, 70))

    def test_clean_prompt(self):
        s = ss.score_prompt([], pred((0, 5, ["IDENTITY"], "x")), 40)
        self.assertEqual((s["n_prompts_clean"], s["clean_flagged"], s["clean_pred_chars"], s["n_prompts_gold"]), (1, 1, 5, 0))
        s0 = ss.score_prompt([], [], 40)
        self.assertEqual((s0["clean_flagged"], s0["pred_chars"]), (0, 0))

    def test_partial_cover_is_touched_not_full(self):
        s = ss.score_prompt(gold((10, 20, "ssn")), pred((12, 20, ["IDENTITY"], "r")), 30)
        self.assertEqual((s["all_masked"], s["all_touched"], s["covered_chars"]), (0, 1, 8))

    def test_per_family_and_category_detail(self):
        s = ss.score_prompt(self.GOLD, self.PRED, 100, "all")
        self.assertEqual(s["by_family"]["NAME"], {"n_gold": 1, "exact": 1, "iou50": 1, "overlap": 1, "touched": 1,
                                                   "full": 1, "gold_chars": 10, "covered_chars": 10})
        self.assertEqual(s["by_family"]["DEMOGRAPHIC"]["touched"], 0)
        self.assertEqual(s["by_category"]["LOCATION"], {"n_pred": 1, "overlapping_gold": 0, "typed_overlap": 0})
        self.assertEqual(s["by_category"]["IDENTITY"]["typed_overlap"], 2)
        self.assertEqual(s["by_source"]["gpe"], {"n_pred": 1, "overlapping_gold": 0})

    def test_invalid_gold_span_rejected(self):
        with self.assertRaises(ValueError):
            ss.score_prompt(gold((5, 5, "email")), [], 10)


class MetricVectorTests(unittest.TestCase):
    def test_vectorised_metrics_match_scalar(self):
        rows = [ss.score_prompt(PromptScoreTests.GOLD, PromptScoreTests.PRED, 100),
                ss.score_prompt(gold((0, 4, "email")), pred((0, 4, ["IDENTITY"], "r")), 20),
                ss.score_prompt([], pred((1, 3, ["IDENTITY"], "r")), 20)]
        totals = np.array([[r[k] for k in ss.COUNT_FIELDS] for r in rows]).sum(axis=0)
        scalar = ss.metrics_from_counts(dict(zip(ss.COUNT_FIELDS, totals)))
        vec = ss.metrics_on_totals(totals[None, :])
        for name, value in scalar.items():
            self.assertAlmostEqual(value, float(vec[name][0]), msg=name)

    def test_zero_denominators_are_none_and_nan(self):
        zero = {k: 0 for k in ss.COUNT_FIELDS}
        self.assertTrue(all(v is None for v in ss.metrics_from_counts(zero).values()))
        vec = ss.metrics_on_totals(np.zeros((1, len(ss.COUNT_FIELDS)), dtype=np.int64))
        self.assertTrue(all(np.isnan(v[0]) for v in vec.values()))


class LayerAndComparisonTests(unittest.TestCase):
    def record(self, rid, regex=(), ner=(), group=None):
        spans = lambda items: [{"start": s, "end": e, "categories": ["IDENTITY"], "sensitivity": "S3", "source": "r"}
                               for s, e in items]
        return {"id": rid, "group_id": group, "layers": {"regex": spans(regex), "ner": spans(ner)},
                "fired": {"regex": bool(regex), "ner": bool(ner)}, "spanless": {"regex": 0, "ner": 0}}

    def test_p4_adds_ner_only_when_regex_fired(self):
        fired = self.record("a", regex=[(0, 3)], ner=[(10, 14)])
        silent = self.record("b", ner=[(10, 14)])
        self.assertEqual({(s["start"], s["end"]) for s in ss.layer_spans(fired, "p4")}, {(0, 3), (10, 14)})
        self.assertEqual(ss.layer_spans(silent, "p4"), [])
        self.assertEqual(len(ss.layer_spans(silent, "union")), 1)
        with self.assertRaises(ValueError):
            ss.layer_spans(fired, "semantic")

    def test_p4_masking_recall_gain_and_overmasking(self):
        gold_rows = [{"id": "a", "group_id": "g1", "text": "x" * 40, "entities": gold((0, 5, "email"), (10, 20, "PERSON"))},
                     {"id": "b", "group_id": "g2", "text": "x" * 40, "entities": gold((10, 20, "PERSON"))}]
        preds = [self.record("a", regex=[(0, 5)], ner=[(10, 20), (30, 34)], group="g1"),
                 self.record("b", ner=[(10, 20)], group="g2")]
        regex = ss.score_layer(gold_rows, preds, "regex")
        p4 = ss.score_layer(gold_rows, preds, "p4")
        union = ss.score_layer(gold_rows, preds, "union")
        self.assertEqual((regex["counts"]["covered_chars"], p4["counts"]["covered_chars"], union["counts"]["covered_chars"]),
                         (5, 15, 25))
        self.assertEqual((regex["counts"]["over_chars"], p4["counts"]["over_chars"], union["counts"]["over_chars"]), (0, 4, 4))
        self.assertAlmostEqual(p4["metrics"]["all_masked_rate"], 0.5)
        self.assertAlmostEqual(union["metrics"]["all_masked_rate"], 1.0)

    def test_subset_and_id_mismatch(self):
        gold_rows = [{"id": "a", "group_id": "g1", "text": "x" * 10, "entities": gold((0, 3, "email"))},
                     {"id": "b", "group_id": "g2", "text": "x" * 10, "entities": []}]
        preds = [self.record("a", regex=[(0, 3)], group="g1"), self.record("b", group="g2")]
        res = ss.score_layer(gold_rows, preds, "regex", subset=lambda g: g["id"] == "a")
        self.assertEqual(res["counts"]["n_prompts"], 1)
        with self.assertRaises(ValueError):
            ss.join_rows(gold_rows, preds[:1])

    def test_paired_comparison_mcnemar_and_delta(self):
        n = 12
        gold_rows = [{"id": f"p{i}", "group_id": f"g{i}", "text": "x" * 20, "entities": gold((0, 5, "email"))}
                     for i in range(n)]
        old = [self.record(f"p{i}", regex=[(0, 5)] if i < 4 else [], group=f"g{i}") for i in range(n)]
        new = [self.record(f"p{i}", regex=[(0, 5)] if i < 10 else [], group=f"g{i}") for i in range(n)]
        out = ss.paired_comparison(gold_rows, old, new, "regex", n_boot=200, seed=1)
        self.assertEqual(out["all_masked_flips"]["gained"], 6)
        self.assertEqual(out["all_masked_flips"]["lost"], 0)
        self.assertAlmostEqual(out["all_masked_flips"]["mcnemar"]["p_two_sided"], 2 * 0.5 ** 6)
        d = out["deltas"]["new"]["all_masked_rate"]
        self.assertAlmostEqual(d["estimate"], 6 / 12)
        self.assertTrue(d["excludes_zero"])
        self.assertEqual(out["n_clusters"], n)
        again = ss.paired_comparison(gold_rows, old, new, "regex", n_boot=200, seed=1)
        self.assertEqual(out["deltas"], again["deltas"])

    def test_half_assignment_is_deterministic(self):
        self.assertIn(ss.half_of("group-a"), ("tune", "check"))
        self.assertEqual(ss.half_of("group-a"), ss.half_of("group-a"))

    def test_locked_file_refused(self):
        with self.assertRaises(SystemExit):
            ss.refuse_locked("some/dir/final.jsonl")
        ss.refuse_locked("some/dir/dev_spans.jsonl")


if __name__ == "__main__":
    unittest.main()
