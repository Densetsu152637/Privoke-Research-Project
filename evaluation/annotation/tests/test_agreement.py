"""Hand-computed checks for the agreement statistics."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agreement as ag  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
