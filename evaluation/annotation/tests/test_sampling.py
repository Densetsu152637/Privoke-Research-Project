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

    def test_blinding_audit_flags_dataset_markers(self):
        clean = sa.blinding_audit(synthetic_rows())
        self.assertEqual(clean["items_with_marker"], 0)
        rows = synthetic_rows()
        rows[0]["text"] += " fresh_eval-folio-03"
        rows[1]["text"] += " see release-07"
        audit = sa.blinding_audit(rows)
        self.assertEqual(audit["items_with_marker"], 2)
        out = self.run_sampler("audit")
        self.assertEqual(json.loads((out / "key/manifest.json").read_text())["blinding_audit"]["items_with_marker"], 0)


class MarkerGateTests(SamplerTests):
    """13a-0: hard marker gate, folio normalisation and extra source-name patterns."""

    def marked_input(self, text_for):
        rows = synthetic_rows()
        for i, row in enumerate(rows):
            row["text"] = text_for(i, row["text"])
        schema.write_jsonl(self.input, rows)
        return rows

    def test_gate_fails_on_marker_and_writes_nothing(self):
        self.marked_input(lambda i, t: f"{t} fresh_eval-folio-{i % 24:02d}")
        out = Path(self.tmp.name) / "gate"
        with self.assertRaises(SystemExit) as ctx:
            sa.main(["--input", str(self.input), "--output-dir", str(out), "--skip-hash-check", "--main-size", "60",
                     "--pilot-size", "12", "--min-per-cell", "2", "--fail-on-marker"])
        self.assertIn("blinding gate failed", str(ctx.exception))
        self.assertFalse(out.exists())

    def test_gate_passes_on_clean_input_and_default_only_warns(self):
        out = self.run_sampler("clean", "--fail-on-marker")
        self.assertEqual(json.loads((out / "key/manifest.json").read_text())["blinding_audit"]["items_with_marker"], 0)
        self.marked_input(lambda i, t: f"{t} fresh_eval-folio-07")
        warned = self.run_sampler("warned")
        self.assertGreater(json.loads((warned / "key/manifest.json").read_text())["blinding_audit"]["items_with_marker"], 0)

    def test_normalisation_leaves_no_alternative_matching(self):
        rows = self.marked_input(lambda i, t: f"{t} fresh_eval-folio-{i % 24:02d}")
        normalised = sa.normalise_markers(rows, "folio")
        for row, original in zip(normalised, rows):
            self.assertTrue(row["text"].endswith(" folio"))
            self.assertFalse(sa.DATASET_MARKER.search(row["text"]), row["text"])
            self.assertEqual(row["id"], original["id"])
        out = self.run_sampler("norm", "--fail-on-marker", "--normalise-marker", "folio")
        audit = json.loads((out / "key/manifest.json").read_text())["blinding_audit"]
        self.assertEqual(audit["items_with_marker"], 0)
        norm = audit["normalisation"]
        self.assertEqual(norm["replacement"], "folio")
        self.assertEqual(norm["original_sha256"], __import__("hashlib").sha256(self.input.read_bytes()).hexdigest())
        self.assertEqual(norm["normalised_sha256"], sa.jsonl_sha256(normalised))
        self.assertNotEqual(norm["original_sha256"], norm["normalised_sha256"])
        for who in "AB":
            self.assertNotIn("fresh_eval", (out / f"sheets/main_{who}.csv").read_text(encoding="utf8"))

    def test_normalisation_is_identical_for_every_annotator(self):
        self.marked_input(lambda i, t: f"{t} fresh_eval-folio-{i % 24:02d}")
        out = self.run_sampler("norm2", "--normalise-marker", "folio")
        texts = {who: {r["item_id"]: r["text"] for r in schema.read_rows(out / f"sheets/main_{who}.csv")} for who in "AB"}
        self.assertEqual(texts["A"], texts["B"])

    def test_partial_replacement_fails_the_gate(self):
        # Hand-edited texts that the whole-token normaliser must not silently accept.
        for partial in ("fresh_eval-X", "xfresh_eval-folio-03", "folio-03"):
            self.marked_input(lambda i, t, partial=partial: f"{t} {partial}")
            with self.assertRaises(SystemExit, msg=partial):
                sa.main(["--input", str(self.input), "--output-dir", str(Path(self.tmp.name) / "p"), "--skip-hash-check",
                         "--main-size", "60", "--pilot-size", "12", "--min-per-cell", "2", "--fail-on-marker",
                         "--normalise-marker", "folio"])

    def test_extra_marker_pattern_is_part_of_the_gate(self):
        self.marked_input(lambda i, t: f"{t} from the lakeside corpus")
        self.run_sampler("nopattern", "--fail-on-marker")
        with self.assertRaises(SystemExit):
            self.run_sampler("pattern", "--fail-on-marker", "--marker-pattern", r"lakeside\s+corpus")
        audit = sa.blinding_audit(synthetic_rows(), [r"lakeside"])
        self.assertEqual(len(audit["patterns"]), 2)


def quota_rows():
    """Invented fresh-set rows: 10 categories x 3 audiences x 2 sensitivity values, 5 prompts per cell."""
    rows = []
    for category in schema.CATEGORIES:
        for audience in ("P0", "P2", "PU"):
            for sensitive in ("yes", "no"):
                for n in range(5):
                    rows.append({"id": f"fs-{len(rows):04d}", "text": f"invented quota sentence {len(rows)} for the study",
                                 "category": category, "audience": audience, "sensitive": sensitive,
                                 "quota_cell": f"{category}/{audience}/{sensitive}"})
    return rows


class QuotaModeAndVerifyTests(unittest.TestCase):
    """13a-1: quota_cell stratification, packet_manifest.json and --verify-against."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.input = self.dir / "frozen_set.jsonl"
        schema.write_jsonl(self.input, quota_rows())
        import hashlib
        self.set_manifest = self.dir / "set_manifest.json"
        self.set_manifest.write_text(json.dumps({"sha256_jsonl": hashlib.sha256(self.input.read_bytes()).hexdigest()}))

    def args(self, out, *extra):
        return ["--input", str(self.input), "--set-manifest", str(self.set_manifest), "--stratify-by", "quota_cell",
                "--output-dir", str(out), "--main-size", "120", "--pilot-size", "12", "--fail-on-marker", *extra]

    def sample(self, name, *extra):
        out = self.dir / name
        sa.main(self.args(out, *extra))
        return out

    def test_quota_mode_writes_v2_blank_sheets_and_a_text_free_packet_manifest(self):
        out = self.sample("one")
        with (out / "sheets/main_A.csv").open(newline="", encoding="utf8") as handle:
            reader = csv.DictReader(handle)
            self.assertEqual(reader.fieldnames, schema.SHEET_COLUMNS_V2)
            rows = list(reader)
        self.assertEqual(len(rows), 120)
        self.assertTrue(all(r[c] == "" for r in rows for c in schema.LABEL_COLUMNS_V2))
        packet = json.loads((out / "packet_manifest.json").read_text())
        self.assertEqual(packet["schema"], "privoke-s13a-packet-v1")
        self.assertEqual(sorted(packet["files"]), ["key/sampling_key.jsonl", "sheets/main_A.csv", "sheets/main_B.csv",
                                                   "sheets/pilot_A.csv", "sheets/pilot_B.csv"])
        self.assertNotIn("invented", (out / "packet_manifest.json").read_text())
        key = [json.loads(l) for l in (out / "key/sampling_key.jsonl").read_text().splitlines()]
        self.assertTrue(all(k["quota_cell"] == k["family_id"] and "provisional" not in k for k in key))
        main = [k for k in key if k["split"] == "main"]
        pilot = [k for k in key if k["split"] == "pilot"]
        self.assertEqual((len(main), len(pilot)), (120, 12))
        self.assertFalse({k["case_id"] for k in main} & {k["case_id"] for k in pilot})
        self.assertEqual(len({k["quota_cell"] for k in main}), 60)  # the floor reaches every cell

    def test_quota_mode_needs_a_set_manifest_and_the_right_hash(self):
        with self.assertRaises(SystemExit):
            sa.main(["--input", str(self.input), "--stratify-by", "quota_cell", "--output-dir", str(self.dir / "x")])
        self.set_manifest.write_text(json.dumps({"sha256_jsonl": "0" * 64}))
        with self.assertRaises(SystemExit):
            self.sample("y")

    def test_verify_against_passes_on_an_identical_resample(self):
        out = self.sample("one")
        with self.assertRaises(SystemExit) as ctx:
            sa.main(self.args(out, "--verify-against", str(out / "packet_manifest.json")))
        self.assertEqual(ctx.exception.code, 0)

    def test_verify_against_fails_on_a_changed_sheet_on_disk(self):
        out = self.sample("one")
        sheet = out / "sheets/main_A.csv"
        sheet.write_text(sheet.read_text(encoding="utf8").replace("invented", "altered", 1), encoding="utf8")
        with self.assertRaises(SystemExit) as ctx:
            sa.main(self.args(out, "--verify-against", str(out / "packet_manifest.json")))
        self.assertEqual(ctx.exception.code, 1)

    def test_verify_against_fails_when_the_input_or_a_recorded_hash_changes(self):
        out = self.sample("one")
        manifest = json.loads((out / "packet_manifest.json").read_text())
        manifest["files"]["sheets/main_B.csv"] = "0" * 64
        tampered = self.dir / "tampered.json"
        tampered.write_text(json.dumps(manifest))
        with self.assertRaises(SystemExit) as ctx:
            sa.main(self.args(self.dir / "scratch-check", "--verify-against", str(tampered)))
        self.assertEqual(ctx.exception.code, 1)
        rows = quota_rows()
        rows[0]["text"] = "an invented replacement sentence"
        schema.write_jsonl(self.input, rows)
        import hashlib
        self.set_manifest.write_text(json.dumps({"sha256_jsonl": hashlib.sha256(self.input.read_bytes()).hexdigest()}))
        with self.assertRaises(SystemExit) as ctx:
            sa.main(self.args(out, "--verify-against", str(out / "packet_manifest.json")))
        self.assertEqual(ctx.exception.code, 1)

    def test_verify_against_fails_on_a_changed_seed(self):
        out = self.sample("one")
        with self.assertRaises(SystemExit) as ctx:
            sa.main(self.args(out, "--seed", "99", "--verify-against", str(out / "packet_manifest.json")))
        self.assertEqual(ctx.exception.code, 1)

    def test_the_gate_applies_to_quota_mode(self):
        rows = quota_rows()
        for row in rows:
            row["text"] += " AU3"
        schema.write_jsonl(self.input, rows)
        import hashlib
        self.set_manifest.write_text(json.dumps({"sha256_jsonl": hashlib.sha256(self.input.read_bytes()).hexdigest()}))
        with self.assertRaises(SystemExit):
            self.sample("gate")


if __name__ == "__main__":
    unittest.main()
