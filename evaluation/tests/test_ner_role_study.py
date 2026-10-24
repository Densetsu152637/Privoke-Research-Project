"""Policy-layer tests for evaluation/ner_role_study.py (synthetic records, no spaCy, no datasets)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ner_role_study as study  # noqa: E402


def ent(label="PERSON", span=(0, 5), **features):
    return {"span": list(span), "label": label, **features}


def row(expected, regex=(), ner=(), half=None, categories=()):
    return {"id": "x", "expected": expected, "half": half, "expected_categories": list(categories),
            "regex": [{"span": list(s), "rule": "r", "sens": sens, "cats": []} for s, sens in regex],
            "ner": list(ner)}


class PolicyFlagTests(unittest.TestCase):
    def test_p0_is_regex_only_and_p1_is_union(self):
        r = row(True, ner=[ent()])
        flags = study.policy_flags(r, "ner")
        self.assertFalse(flags["P0"])
        self.assertTrue(flags["P1"])

    def test_p3_and_p4_cannot_create_positives(self):
        r = row(True, ner=[ent(multi_token=True, cue=True)])
        flags = study.policy_flags(r, "ner")
        self.assertFalse(flags["P3"] or flags["P4"])
        self.assertTrue(study.policy_flags(row(True, regex=[((0, 3), "S3")]), "ner")["P3"])

    def test_p2_requires_corroboration(self):
        bare = row(False, ner=[ent()])
        multi = row(False, ner=[ent(multi_token=True)])
        flags = study.policy_flags(bare, "ner")
        self.assertTrue(flags["P1"])
        self.assertFalse(flags["P2:person_any"])
        self.assertTrue(study.policy_flags(multi, "ner")["P2:person_any"])
        self.assertTrue(study.policy_flags(row(False, ner=[ent(recurring=True)]), "ner")["P2:person_cue_or_recurring"])
        self.assertFalse(study.policy_flags(row(False, ner=[ent(recurring=True)]), "ner")["P2:person_cue"])

    def test_relation_variants_use_place_and_org_cues(self):
        place = row(False, ner=[ent("GPE", relation_cue=True)])
        geo = row(False, ner=[ent("GPE", geo_or_org_cue=True)])
        self.assertTrue(study.policy_flags(place, "ner")["P2:person_any_or_relation"])
        self.assertFalse(study.policy_flags(geo, "ner")["P2:person_any_or_relation"])
        self.assertTrue(study.policy_flags(geo, "ner")["P2:person_any_or_relation_or_geo"])

    def test_chosen_variant_alias(self):
        flags = study.policy_flags(row(False, ner=[ent(multi_token=True)]), "ner", "person_multi_token")
        self.assertEqual(flags["P2"], flags["P2:person_multi_token"])

    def test_every_p2_variant_is_a_superset_of_p0_and_subset_of_p1(self):
        rows = [row(True, ner=[ent(multi_token=True)]), row(False, ner=[ent()]), row(True, regex=[((0, 1), "S2")])]
        for r in rows:
            flags = study.policy_flags(r, "ner")
            for name in study.P2_VARIANTS:
                self.assertTrue(flags[f"P2:{name}"] >= flags["P0"])
                self.assertTrue(flags["P1"] >= flags[f"P2:{name}"])


class MetricTests(unittest.TestCase):
    def test_confusion(self):
        c = study.confusion([True, True, False, False], [True, False, True, False])
        self.assertEqual((c["TP"], c["FN"], c["FP"], c["TN"]), (1, 1, 1, 1))
        self.assertAlmostEqual(c["balanced_accuracy"], 0.5)

    def test_split_halves(self):
        records = {"dev": [row(True, half="tune"), row(False, half="check"), row(True, half="tune")],
                   "personalized": [row(True)], "openai": [row(False)]}
        self.assertEqual(len(study.split_rows(records, "tune")), 2)
        self.assertEqual(len(study.split_rows(records, "check")), 1)

    def test_choice_uses_design_splits_only(self):
        # On check/openai a different variant would win; the design splits decide.
        good = ent(multi_token=True)
        bad = ent(cue=True)
        records = {
            "dev": [row(True, ner=[good], half="tune"), row(False, ner=[bad], half="tune"),
                    row(True, ner=[bad], half="check")],
            "personalized": [row(True, ner=[good]), row(False)],
            "openai": [row(True, ner=[bad])],
        }
        variant, scores = study.choose_variant(records, "ner")
        self.assertIn("person_multi_token", scores)
        self.assertEqual(variant, "person_multi_token")
        self.assertEqual(scores[variant]["design_FP"], 0)

    def test_paired_counts(self):
        records = {"dev": [row(True, ner=[ent()], half="tune"), row(False, ner=[ent()], half="tune")],
                   "personalized": [], "openai": []}
        paired = study.paired_vs(records, "ner", "P0", "P1", None)
        self.assertEqual(paired["tune"], {"+TP": 1, "+FP": 1})


class AmplificationTests(unittest.TestCase):
    def test_counts_extra_spans_and_category_coverage(self):
        r = row(True, regex=[((10, 20), "S3")], ner=[ent("PERSON", (0, 5)), ent("GPE", (12, 15))],
                half="tune", categories=["first_name"])
        clean = row(False, regex=[((0, 4), "S1")], ner=[ent("ORG", (30, 40))], half="tune")
        records = {"dev": [r, clean, row(False, ner=[ent()], half="tune")], "personalized": [], "openai": []}
        stats = study.amplification(records, "ner")["tune"]
        self.assertEqual(stats["regex_positive_rows"], 2)
        self.assertEqual(stats["P4_extra_spans_pii"], 1)      # PERSON; the GPE overlaps a regex span
        self.assertEqual(stats["P4_extra_spans_nopii"], 1)
        self.assertEqual(stats["P3_gate_rows"], 1)            # only the S3 finding opens the gate
        self.assertEqual(stats["P3_extra_spans_pii"], 1)
        self.assertNotIn("P3_extra_spans_nopii", stats)
        self.assertEqual(stats["name_expected_rows"], 1)
        self.assertEqual(stats["name_expected_and_ner_entity"], 1)
        self.assertEqual(stats["place_not_expected_but_ner_entity"], 0)   # the GPE overlaps a regex span


class DumpJoinTests(unittest.TestCase):
    def test_attach_features_matches_on_span_and_label(self):
        shipped = [{"span": [0, 5], "label": "PERSON", "sens": "S2"}]
        raw = [{"span": [0, 5], "label": "PERSON", "multi_token": True}, {"span": [0, 5], "label": "ORG", "cue": True}]
        merged = study.attach_features(shipped, raw)
        self.assertTrue(merged[0]["multi_token"])
        self.assertNotIn("cue", merged[0])
        self.assertEqual(merged[0]["sens"], "S2")

    def test_overlap(self):
        self.assertTrue(study.overlaps([0, 5], [4, 8]))
        self.assertFalse(study.overlaps([0, 5], [5, 8]))

    def test_build_config_records_rejects_mismatched_dumps(self):
        base = {"id": "a", "expected": True, "expected_categories": [], "half": None, "regex": [], "ner_shipped": []}
        old = {"records": {"openai": [base]}}
        new = {"records": {"openai": [{**base, "expected": False, "ner_raw_cp": [], "ner_raw_lc": []}]}}
        with self.assertRaises(ValueError):
            study.build_config_records(old, new)

    def test_old_parity(self):
        shipped = [{"span": [0, 3], "label": "ORG"}]
        old = {"records": {"openai": [{"ner_shipped": shipped}]}}
        new = {"records": {"openai": [{"ner_raw_lc": list(shipped)}]}}
        self.assertEqual(study.old_parity(old, new)["rows_where_old_shipped_ner_differs_from_raw_lowercase"], 0)

    def test_final_is_not_selectable(self):
        self.assertNotIn("final", study.SPLIT_FILES)


if __name__ == "__main__":
    unittest.main()
