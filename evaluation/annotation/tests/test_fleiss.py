"""Fleiss' kappa against hand-computed fixtures, and its use inside compute_iaa."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agreement as ag  # noqa: E402
import annotation_schema as schema  # noqa: E402
import compute_iaa  # noqa: E402


class FleissTests(unittest.TestCase):
    def test_two_categories_three_raters(self):
        # Per-item agreement 1, 1/3, 1, 1/3 -> Pbar 2/3; both categories used 6 of 12 times -> Pe 1/2; kappa 1/3.
        units = [["A", "A", "A"], ["A", "A", "B"], ["B", "B", "B"], ["A", "B", "B"]]
        self.assertAlmostEqual(ag.fleiss_kappa(units), 1 / 3)

    def test_perfect_and_undefined(self):
        self.assertAlmostEqual(ag.fleiss_kappa([["A", "A", "A"], ["B", "B", "B"]]), 1.0)
        self.assertIsNone(ag.fleiss_kappa([["A", "A", "A"], ["A", "A", "A"]]))

    def test_matches_cohen_for_two_raters_up_to_the_known_difference(self):
        # For two raters Fleiss' kappa equals Scott's pi: Pe uses pooled marginals. Hand value: po=.7, pooled p(Y)=.55.
        first = ["Y"] * 25 + ["N"] * 25
        second = ["Y"] * 20 + ["N"] * 5 + ["Y"] * 10 + ["N"] * 15
        pe = 0.55 ** 2 + 0.45 ** 2
        self.assertAlmostEqual(ag.fleiss_kappa(list(map(list, zip(first, second)))), (0.7 - pe) / (1 - pe))

    def test_unequal_rater_counts_are_rejected(self):
        with self.assertRaises(ValueError):
            ag.fleiss_kappa([["A", "A", "B"], ["A", "B"]])

    def test_compute_iaa_adds_fleiss_for_three_annotators_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            ids = [f"it-{n}" for n in range(8)]
            sens = {"A": "yes yes no no yes no yes no", "B": "yes yes no no yes no no no", "C": "yes no no no yes no yes no"}
            for who, labels in sens.items():
                rows = [{"item_id": i, "sensitive": s, "subject": "SELF", "audience": "P1", "categories": "NONE",
                         "action": "ALLOW"} for i, s in zip(ids, labels.split())]
                schema.write_csv(tmp / f"{who}.csv", schema.COMMITTED_LABEL_COLUMNS_V2, rows)
            specs = [x for who in "ABC" for x in ("--sheet", f"{who}={tmp / (who + '.csv')}")]
            compute_iaa.main([*specs, "--schema", "2", "--n-boot", "10", "--out-json", str(tmp / "three.json")])
            three = json.loads((tmp / "three.json").read_text())["fields"]["sensitive"]
            self.assertIn("fleiss", three)
            self.assertEqual(len(three["pairs"]), 3)
            units = [[labels.split()[k] for labels in sens.values()] for k in range(8)]
            self.assertAlmostEqual(three["fleiss"], ag.fleiss_kappa(units))
            compute_iaa.main(["--sheet", f"A={tmp / 'A.csv'}", "--sheet", f"B={tmp / 'B.csv'}", "--schema", "2", "--n-boot", "10",
                              "--out-json", str(tmp / "two.json")])
            self.assertNotIn("fleiss", json.loads((tmp / "two.json").read_text())["fields"]["sensitive"])


if __name__ == "__main__":
    unittest.main()
