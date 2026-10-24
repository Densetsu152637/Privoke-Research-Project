"""Sampler checks on a small synthetic dataset (the real data is gitignored)."""
import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import annotation_schema as schema  # noqa: E402
import sample_annotation as sa  # noqa: E402

AUDIENCES = ["P0", "P1", "P2", "P3", "P4", "PU"]
CELLS = [("actual_disclosure", "S3", 8, True), ("actual_disclosure", "S2", 4, True), ("mild_personal", "S1", 3, True),
         ("absent_record", "S0", 6, False), ("quoted_synthetic_placeholder", "S0", 7, False)]


def synthetic_rows():
    rows = []
    for aud in AUDIENCES:
        for control, sens, count, required in CELLS:
            for n in range(count):
                case_id = f"X/fam{n % 5}/{aud}/{control}/{sens}/{n}"
                rows.append({
                    "id": case_id, "family_id": f"X/fam{n % 5}", "required_sensitive": required,
                    "classification": {"sensitivity": sens, "visibility": aud, "categories": ["HEALTH"] if required else []},
                    "allowed_actions": ["ALLOW"] if sens in ("S0", "S1") else ["WARN", "BLOCK"],
                    "text": f"synthetic text number {len(rows)} body",
                    "metadata": {"control": control, "audience_expression_group_id": f"expr{n % 3}"}})
    return rows


class SamplerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.input = Path(self.tmp.name) / "in.jsonl"
        schema.write_jsonl(self.input, synthetic_rows())

    def run_sampler(self, name, *extra):
        out = Path(self.tmp.name) / name
        sa.main(["--input", str(self.input), "--output-dir", str(out), "--skip-hash-check",
                 "--main-size", "60", "--pilot-size", "12", "--min-per-cell", "2", *extra])
        return out

    def test_allocation_floors_and_totals(self):
        self.assertEqual(sa.allocate(10, {"a": 5, "b": 3, "c": 2}), {"a": 5, "b": 3, "c": 2})
        alloc = sa.allocate(6, {"a": 60, "b": 30, "c": 10}, minimum=2)
        self.assertEqual(sum(alloc.values()), 6)
        self.assertTrue(all(v >= 2 for v in alloc.values()))
        with self.assertRaises(ValueError):
            sa.allocate(3, {"a": 5, "b": 5}, minimum=2)

    def test_deterministic_outputs(self):
        first, second = self.run_sampler("one"), self.run_sampler("two")
        for rel in ("sheets/main_A.csv", "sheets/main_B.csv", "sheets/pilot_A.csv", "key/sampling_key.jsonl"):
            self.assertEqual((first / rel).read_bytes(), (second / rel).read_bytes(), rel)
        other = self.run_sampler("three", "--seed", "7")
        self.assertNotEqual((first / "key/sampling_key.jsonl").read_bytes(), (other / "key/sampling_key.jsonl").read_bytes())

    def test_sizes_disjointness_and_balance(self):
        out = self.run_sampler("run")
        key = [json.loads(l) for l in (out / "key/sampling_key.jsonl").read_text().splitlines()]
        main = [k for k in key if k["split"] == "main"]
        pilot = [k for k in key if k["split"] == "pilot"]
        self.assertEqual((len(main), len(pilot)), (60, 12))
        self.assertFalse({k["case_id"] for k in main} & {k["case_id"] for k in pilot})
        for aud in AUDIENCES:
            self.assertEqual(sum(k["provisional"]["visibility"] == aud for k in main), 10)
        manifest = json.loads((out / "key/manifest.json").read_text())
        for stratum, size in manifest["population_by_stratum"].items():
            members = [k for k in main if k["stratum"] == stratum]
            self.assertAlmostEqual(sum(k["design_weight"] for k in members), size)

    def test_sheets_are_blinded_blank_and_reordered(self):
        out = self.run_sampler("run")
        key = {json.loads(l)["item_id"]: json.loads(l) for l in (out / "key/sampling_key.jsonl").read_text().splitlines()}
        sheets = {}
        for who in ("A", "B"):
            with (out / f"sheets/main_{who}.csv").open(newline="", encoding="utf8") as handle:
                reader = csv.DictReader(handle)
                self.assertEqual(reader.fieldnames, schema.SHEET_COLUMNS)
                sheets[who] = list(reader)
        for rows in sheets.values():
            for row in rows:
                self.assertRegex(row["item_id"], r"^it-[0-9a-f]{10}$")
                self.assertTrue(all(row[c] == "" for c in schema.LABEL_COLUMNS))
                self.assertNotIn(key[row["item_id"]]["case_id"], row["item_id"])
        self.assertEqual({r["item_id"] for r in sheets["A"]}, {r["item_id"] for r in sheets["B"]})
        self.assertNotEqual([r["item_id"] for r in sheets["A"]], [r["item_id"] for r in sheets["B"]])
        blob = (out / "sheets/main_A.csv").read_text(encoding="utf8")
        self.assertNotIn("actual_disclosure", blob)
        self.assertNotIn("design_weight", blob)

    def test_hash_check_rejects_other_inputs(self):
        with self.assertRaises(SystemExit):
            sa.main(["--input", str(self.input), "--output-dir", str(Path(self.tmp.name) / "x")])


if __name__ == "__main__":
    unittest.main()
