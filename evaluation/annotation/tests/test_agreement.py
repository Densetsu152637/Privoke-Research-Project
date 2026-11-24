"""Hand-computed checks for the agreement statistics."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agreement as ag  # noqa: E402
import annotation_schema as schema  # noqa: E402


def table_ratings(a, b, c, d):
    """Two raters, Y/N, contingency a=YY, b=YN, c=NY, d=NN."""
    first = ["Y"] * a + ["Y"] * b + ["N"] * c + ["N"] * d
    second = ["Y"] * a + ["N"] * b + ["Y"] * c + ["N"] * d
    return first, second


class KappaTests(unittest.TestCase):
    def test_two_by_two_table(self):
        # n=50, po=35/50=.7, raters say Y 25 and 30 times, pe=.5*.6+.5*.4=.5, kappa=.4
        kappa, po, pe = ag.cohen_kappa(*table_ratings(20, 5, 10, 15))
        self.assertAlmostEqual(po, 0.7)
        self.assertAlmostEqual(pe, 0.5)
        self.assertAlmostEqual(kappa, 0.4)

    def test_three_classes(self):
        a = ["a", "a", "b", "b", "c", "c"]
        b = ["a", "b", "b", "b", "c", "a"]
        kappa, po, pe = ag.cohen_kappa(a, b)  # po=4/6, pe=(2*2+2*3+2*1)/36=1/3
        self.assertAlmostEqual(po, 4 / 6)
        self.assertAlmostEqual(pe, 1 / 3)
        self.assertAlmostEqual(kappa, 0.5)

    def test_no_variation_is_undefined(self):
        self.assertIsNone(ag.cohen_kappa(["x", "x"], ["x", "x"])[0])

    def test_specific_agreement_and_confusion(self):
        a, b = table_ratings(20, 5, 10, 15)
        spec = ag.specific_agreement(a, b, ["Y", "N", "Z"])
        self.assertAlmostEqual(spec["Y"], 40 / 55)   # 2*20 / (25+30)
        self.assertAlmostEqual(spec["N"], 30 / 45)   # 2*15 / (25+20)
        self.assertIsNone(spec["Z"])
        self.assertEqual(ag.confusion_matrix(a, b, ["Y", "N"]), {"Y": {"Y": 20, "N": 5}, "N": {"Y": 10, "N": 15}})


class AlphaTests(unittest.TestCase):
    def test_nominal_two_raters(self):
        # coincidence o_YN=o_NY=15, o_YY=40, o_NN=30, n=100: Do=.3, De=2*55*45/9900=.5, alpha=.4
        first, second = table_ratings(20, 5, 10, 15)
        units = [[x, y] for x, y in zip(first, second)]
        self.assertAlmostEqual(ag.krippendorff_alpha(units, "nominal"), 0.4)

    def test_ordinal_hand_example(self):
        # units (1,1)(2,3)(3,3)(1,2); n=8; n1=3,n2=2,n3=3; d2(1,2)=d2(2,3)=6.25, d2(1,3)=25
        # Do=25/8; De=600/56; alpha=1-(25/8)/(600/56)=17/24
        units = [[1, 1], [2, 3], [3, 3], [1, 2]]
        self.assertAlmostEqual(ag.krippendorff_alpha(units, "ordinal", [1, 2, 3]), 17 / 24)

    def test_single_rating_units_are_ignored(self):
        units = [[1, 1], [2, 3], [3, 3], [1, 2], [2]]
        self.assertAlmostEqual(ag.krippendorff_alpha(units, "ordinal", [1, 2, 3]), 17 / 24)

    def test_missing_rater_allowed_with_three_raters(self):
        units = [["a", "a", "a"], ["b", "b"], ["a", "b", "b"]]
        value = ag.krippendorff_alpha(units, "nominal")
        self.assertTrue(0 < value < 1)

    def test_perfect_and_degenerate(self):
        self.assertAlmostEqual(ag.krippendorff_alpha([["a", "a"], ["b", "b"]], "nominal"), 1.0)
        self.assertIsNone(ag.krippendorff_alpha([["a", "a"], ["a", "a"]], "nominal"))


class IntervalTests(unittest.TestCase):
    def test_wilson(self):
        lo, hi = ag.wilson_interval(50, 100)
        self.assertAlmostEqual(lo, 0.4038, places=3)
        self.assertAlmostEqual(hi, 0.5962, places=3)
        self.assertEqual(ag.wilson_interval(0, 0), (None, None))

    def test_sample_size_formula(self):
        self.assertEqual(ag.required_n_for_kappa(0.85, 0.5), 196)   # 3.8415*.1275/(.25*.01)=195.9
        self.assertEqual(ag.required_n_for_kappa(0.75, 0.5), 289)   # 3.8415*.1875/(.25*.01)=288.1
        self.assertAlmostEqual(ag.kappa_half_width(360, 0.75, 0.5), 1.959964 * (0.1875 / (360 * 0.25)) ** 0.5)

    def test_cluster_bootstrap_is_deterministic_and_brackets_constant(self):
        items = [f"i{n}" for n in range(12)]
        clusters = {i: f"c{n // 3}" for n, i in enumerate(items)}
        stat = lambda subset: 1.0
        first = ag.cluster_bootstrap(items, clusters, stat, n_boot=50, seed=1)
        self.assertEqual(first, ag.cluster_bootstrap(items, clusters, stat, n_boot=50, seed=1))
        self.assertEqual(first[:2], (1.0, 1.0))


class SchemaV2AndGateTests(unittest.TestCase):
    """Stage 13a: the v2 validator, --min-kappa/--fields and --check-adjudication gates."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def sheet(self, name, rows):
        path = self.dir / name
        schema.write_csv(path, schema.SHEET_COLUMNS_V2, rows)
        return path

    def good_row(self, item, **override):
        row = {"item_id": item, "text": "invented sentence", "sensitive": "yes", "subject": "SELF", "audience": "P1",
               "categories": "HEALTH", "action": "WARN", "notes": ""}
        row.update(override)
        return row

    def test_validator_accepts_a_complete_v2_sheet(self):
        path = self.sheet("ok.csv", [self.good_row("it-1"),
                                     self.good_row("it-2", sensitive="no", categories="NONE", action="ALLOW", subject="NONE")])
        self.assertEqual(schema.validate_sheet(path, 2), [])
        self.assertEqual(schema.main(["--validate", str(path), "--schema", "2"]), 0)

    def test_validator_rejects_empty_and_invalid_cells(self):
        for bad in ({"sensitive": ""}, {"subject": "BYSTANDER"}, {"audience": "P9"}, {"action": "DENY"}, {"categories": ""},
                    {"categories": "NONE|HEALTH"}):
            path = self.sheet("bad.csv", [self.good_row("it-1", **bad)])
            self.assertTrue(schema.validate_sheet(path, 2), bad)
            self.assertEqual(schema.main(["--validate", str(path), "--schema", "2"]), 1, bad)

    def test_validator_rejects_duplicate_ids_missing_columns_and_v1_cells(self):
        dup = self.sheet("dup.csv", [self.good_row("it-1"), self.good_row("it-1")])
        self.assertTrue(any("duplicate" in p for p in schema.validate_sheet(dup, 2)))
        schema.write_csv(self.dir / "cols.csv", ["item_id", "sensitive"], [{"item_id": "it-1", "sensitive": "yes"}])
        self.assertTrue(any("missing columns" in p for p in schema.validate_sheet(self.dir / "cols.csv", 2)))
        v1 = self.dir / "v1.csv"
        schema.write_csv(v1, schema.SHEET_COLUMNS, [{"item_id": "it-1", "disclosure": "yes", "sensitivity": "S2", "visibility": "P1",
                                                     "categories": "HEALTH", "action": "WARN"}])
        self.assertEqual(schema.validate_sheet(v1, 1), [])
        self.assertTrue(schema.validate_sheet(v1, 2))

    def two_sheets(self, second_sensitive):
        first = [self.good_row(f"it-{n}", sensitive=("yes" if n % 2 else "no")) for n in range(10)]
        second = [self.good_row(f"it-{n}", sensitive=second_sensitive[n]) for n in range(10)]
        return self.sheet("A.csv", first), self.sheet("B.csv", second)

    def run_iaa(self, a, b, *extra):
        import compute_iaa
        return compute_iaa.main(["--sheet", f"A={a}", "--sheet", f"B={b}", "--schema", "2", "--n-boot", "10",
                                 "--out-json", str(self.dir / "iaa.json"), *extra])

    def test_min_kappa_passes_above_and_fails_below_the_bar(self):
        agree = ["yes" if n % 2 else "no" for n in range(10)]
        a, b = self.two_sheets(agree)
        self.run_iaa(a, b, "--min-kappa", "0.6", "--fields", "sensitive")
        disagree = ["no" if n % 2 else "yes" for n in range(10)]
        a, b = self.two_sheets(disagree)
        with self.assertRaises(SystemExit) as ctx:
            self.run_iaa(a, b, "--min-kappa", "0.6", "--fields", "sensitive")
        self.assertEqual(ctx.exception.code, 1)

    def test_min_kappa_needs_fields_and_known_field_names(self):
        a, b = self.two_sheets(["yes"] * 10)
        with self.assertRaises(SystemExit):
            self.run_iaa(a, b, "--min-kappa", "0.6")
        with self.assertRaises(SystemExit):
            self.run_iaa(a, b, "--min-kappa", "0.6", "--fields", "disclosure")

    def test_undefined_kappa_fails_the_gate(self):
        a, b = self.two_sheets(["yes"] * 10)
        with self.assertRaises(SystemExit) as ctx:
            self.run_iaa(a, b, "--min-kappa", "0.0", "--fields", "audience")
        self.assertEqual(ctx.exception.code, 1)

    def adjudication(self, rows):
        path = self.dir / "adj.csv"
        base = {"item_id": "it-1", "sensitive": "yes", "subject": "SELF", "audience": "P1", "categories": "HEALTH",
                "action": "WARN", "resolution": "consensus", "reason": "", "adjudicator": "J"}
        schema.write_csv(path, schema.ADJUDICATION_COLUMNS_V2, [{**base, **row} for row in rows])
        return path

    def disagreeing_sheets(self):
        first = ["yes" if n % 2 else "no" for n in range(10)]
        second = list(first)
        for n in (1, 4):  # the two disagreement items
            second[n] = "no" if first[n] == "yes" else "yes"
        return self.two_sheets(second)

    def check(self, adjudicated, *extra, expect):
        import compute_iaa
        a, b = self.disagreeing_sheets()
        with self.assertRaises(SystemExit) as ctx:
            compute_iaa.main(["--check-adjudication", str(adjudicated), "--sheet", f"A={a}", "--sheet", f"B={b}",
                              "--schema", "2", *extra])
        self.assertEqual(ctx.exception.code, expect)

    def test_check_adjudication_requires_full_coverage_resolution_adjudicator_and_valid_final_cells(self):
        full = [{"item_id": "it-1"}, {"item_id": "it-4", "resolution": "third_adjudicator"}]
        self.check(self.adjudication(full), expect=0)
        for bad in ({"resolution": ""}, {"adjudicator": ""}, {"resolution": "agreed-by-me"}, {"sensitive": "maybe"},
                    {"categories": ""}, {"action": "DENY"}):
            self.check(self.adjudication([full[0], {**full[1], **bad}]), expect=1)

    def test_check_adjudication_fails_when_a_disagreement_row_was_deleted(self):
        self.check(self.adjudication([{"item_id": "it-1"}]), expect=1)

    def test_check_adjudication_fails_on_an_extra_item_or_a_duplicate(self):
        self.check(self.adjudication([{"item_id": "it-1"}, {"item_id": "it-4"}, {"item_id": "it-7"}]), expect=1)
        self.check(self.adjudication([{"item_id": "it-1"}, {"item_id": "it-4"}, {"item_id": "it-4"}]), expect=1)

    def test_final_columns_are_read_and_an_excluded_item_needs_no_final_label(self):
        path = self.dir / "adj_final.csv"
        columns = ["item_id", "final_sensitive", "final_subject", "final_audience", "final_action", "final_categories",
                   "resolution", "reason", "adjudicator"]
        good = {"final_sensitive": "yes", "final_subject": "SELF", "final_audience": "P1", "final_action": "WARN",
                "final_categories": "HEALTH", "resolution": "consensus", "adjudicator": "J"}
        schema.write_csv(path, columns, [{"item_id": "it-1", **good},
                                         {"item_id": "it-4", "resolution": "excluded_ambiguous", "adjudicator": "J"}])
        self.check(path, expect=0)
        schema.write_csv(path, columns, [{"item_id": "it-1", **good, "final_audience": "P7"},
                                         {"item_id": "it-4", "resolution": "excluded_ambiguous", "adjudicator": "J"}])
        self.check(path, expect=1)

    def test_check_adjudication_accepts_the_export_as_the_disagreement_set_and_needs_one_of_them(self):
        import compute_iaa
        export = self.dir / "export.csv"
        schema.write_csv(export, ["item_id"], [{"item_id": "it-1"}, {"item_id": "it-4"}])
        adjudicated = self.adjudication([{"item_id": "it-1"}, {"item_id": "it-4"}])
        with self.assertRaises(SystemExit) as ok:
            compute_iaa.main(["--check-adjudication", str(adjudicated), "--to-adjudicate", str(export), "--schema", "2"])
        self.assertEqual(ok.exception.code, 0)
        with self.assertRaises(SystemExit) as ctx:
            compute_iaa.main(["--check-adjudication", str(adjudicated), "--schema", "2"])
        self.assertEqual(ctx.exception.code, 2)

    def test_schema2_adjudication_export_is_confined_to_the_returned_directory(self):
        import os
        agree = ["yes" if n % 2 else "no" for n in range(10)]
        a, b = self.two_sheets(agree)
        returned = self.dir / "returned"
        for name, value in (("S13A_RETURNED_ROOT", str(returned)), ("S13A_TESTING", "1")):
            os.environ[name] = value
            self.addCleanup(os.environ.pop, name, None)
        with self.assertRaises(SystemExit):
            self.run_iaa(a, b, "--disagreements-csv", str(self.dir / "elsewhere.csv"))
        returned.mkdir()
        self.run_iaa(a, b, "--disagreements-csv", str(returned / "to_adjudicate.csv"))
        self.assertTrue((returned / "to_adjudicate.csv").is_file())


if __name__ == "__main__":
    unittest.main()
