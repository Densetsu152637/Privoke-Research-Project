"""End-to-end IAA and accuracy checks on a tiny hand-made fixture (4 items, 2 annotators)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import annotation_schema as schema  # noqa: E402
import compute_iaa  # noqa: E402
import provisional_accuracy as pa  # noqa: E402

# item: (disclosure, sensitivity A, sensitivity B, visibility, categories, action)
LABELS = {
    "it-1": ("no", "S0", "S0", "P0", "NONE", "ALLOW"),
    "it-2": ("yes", "S3", "S3", "P1", "HEALTH", "BLOCK"),
    "it-3": ("yes", "S3", "S2", "P2", "HEALTH", "BLOCK"),
    "it-4": ("yes", "S1", "S1", "PU", "NONE", "ALLOW"),
}
KEY = {
    "it-1": ("no", "S0", "P0", [], ["ALLOW"]),
    "it-2": ("yes", "S3", "P1", ["HEALTH"], ["WARN", "BLOCK"]),
    "it-3": ("yes", "S3", "P2", ["HEALTH"], ["WARN", "BLOCK"]),
    "it-4": ("yes", "S2", "PU", [], ["WARN", "BLOCK"]),
}


def write_sheet(path, which):
    rows = []
    for item, (disc, sens_a, sens_b, vis, cats, act) in LABELS.items():
        rows.append({"item_id": item, "text": f"text {item}", "disclosure": disc,
                     "sensitivity": sens_a if which == "A" else sens_b,
                     "visibility": vis, "categories": cats, "action": act, "notes": ""})
    schema.write_csv(path, schema.SHEET_COLUMNS, rows)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        for who in "AB":
            write_sheet(self.dir / f"{who}.csv", who)
        entries = []
        for item, (disc, sens, vis, cats, allowed) in KEY.items():
            entries.append({"item_id": item, "case_id": "c" + item, "split": "main", "family_id": "fam-" + item[-1],
                            "stratum": "s", "control": "x", "design_weight": None,
                            "provisional": {"disclosure": disc, "sensitivity": sens, "visibility": vis,
                                            "categories": cats, "allowed_actions": allowed}})
        schema.write_jsonl(self.dir / "key.jsonl", entries)

    def sheets_args(self):
        return ["--sheet", f"A={self.dir / 'A.csv'}", "--sheet", f"B={self.dir / 'B.csv'}"]

    def test_iaa(self):
        compute_iaa.main([*self.sheets_args(), "--key", str(self.dir / "key.jsonl"), "--n-boot", "20",
                          "--out-json", str(self.dir / "iaa.json"), "--out-md", str(self.dir / "iaa.md"),
                          "--disagreements-csv", str(self.dir / "adj.csv")])
        result = json.loads((self.dir / "iaa.json").read_text())
        sens = result["fields"]["sensitivity"]["pairs"]["A-B"]
        self.assertAlmostEqual(sens["observed_agreement"], 0.75)
        self.assertAlmostEqual(sens["expected_agreement"], 0.25)   # (1*1 + 1*1 + 0*1 + 2*1)/16
        self.assertAlmostEqual(sens["kappa"], 2 / 3)
        self.assertAlmostEqual(result["fields"]["visibility"]["pairs"]["A-B"]["kappa"], 1.0)
        self.assertAlmostEqual(result["fields"]["visibility"]["alpha"], 1.0)
        self.assertEqual(result["bootstrap_unit"], "family")
        rows = schema.read_rows(self.dir / "adj.csv")
        self.assertEqual([r["item_id"] for r in rows], ["it-3"])
        self.assertEqual(rows[0]["differing_fields"], "sensitivity")
        self.assertEqual((rows[0]["A_sensitivity"], rows[0]["B_sensitivity"]), ("S3", "S2"))

    def test_accuracy_with_adjudication(self):
        adjudicated = self.dir / "adj_done.csv"
        schema.write_csv(adjudicated, ["item_id", "disclosure", "sensitivity", "visibility", "categories", "action", "resolution", "reason"],
                         [{"item_id": "it-3", "disclosure": "yes", "sensitivity": "S3", "visibility": "P2", "categories": "HEALTH",
                           "action": "BLOCK", "resolution": "consensus", "reason": "diagnosis is stated as fact"}])
        pa.main(["--key", str(self.dir / "key.jsonl"), *self.sheets_args(), "--adjudicated", str(adjudicated),
                 "--n-boot", "20", "--out-json", str(self.dir / "acc.json")])
        result = json.loads((self.dir / "acc.json").read_text())
        self.assertEqual(result["resolution"], {"annotators_agree": 3, "adjudicated": 1})
        overall = result["overall"]
        self.assertEqual(result["items"], 4)
        self.assertEqual(overall["disclosure"]["correct"], 4)
        self.assertEqual(overall["sensitivity"]["correct"], 3)   # it-4 provisional S2 vs reference S1
        self.assertEqual(overall["action"]["correct"], 3)        # it-4 reference ALLOW outside {WARN,BLOCK}
        self.assertEqual(overall["categories"]["correct"], 4)
        self.assertEqual(overall["joint"]["correct"], 3)
        self.assertAlmostEqual(overall["joint"]["sample_accuracy"], 0.75)
        self.assertEqual(result["confusion"]["sensitivity_provisional_rows_reference_columns"]["S2"]["S1"], 1)

    def test_unadjudicated_disagreement_is_excluded_not_guessed(self):
        pa.main(["--key", str(self.dir / "key.jsonl"), *self.sheets_args(), "--n-boot", "20",
                 "--out-json", str(self.dir / "acc2.json")])
        result = json.loads((self.dir / "acc2.json").read_text())
        self.assertEqual(result["items"], 3)
        self.assertEqual(result["resolution"]["disagreement_not_adjudicated"], 1)

    def test_validation(self):
        with self.assertRaises(schema.SheetError):
            schema.normalise_row({"item_id": "x", "disclosure": "yes", "sensitivity": "S9", "visibility": "P0",
                                  "categories": "NONE", "action": "ALLOW"})
        with self.assertRaises(schema.SheetError):
            schema.parse_categories("")
        with self.assertRaises(schema.SheetError):
            schema.parse_categories("NONE|HEALTH")
        self.assertEqual(schema.parse_categories("identity; health"), ["HEALTH", "IDENTITY"])
        self.assertEqual(schema.parse_categories("none"), [])


if __name__ == "__main__":
    unittest.main()
