"""fresh_set.py on invented sentences only: dedup, contamination, markers, quotas, dry run and output confinement."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import annotation_schema as schema  # noqa: E402
import fresh_set  # noqa: E402

WORDS = ["amber", "birch", "cedar", "delta", "ember", "fjord", "grove", "harbor", "island", "juniper", "kettle", "lantern",
         "meadow", "nectar", "orchid", "pebble", "quartz", "ripple", "saddle", "thimble", "umber", "velvet", "willow", "yonder"]


def sentence(n):
    """A distinct invented sentence of 12 tokens that shares no 8-gram with any other index."""
    a, b, c = WORDS[n % 24], WORDS[(n * 7 + 3) % 24], WORDS[(n * 5 + 11) % 24]
    return f"zz{n} {a} told {b} that tomorrow the {c} number{n} will arrive near station{n} before noon{n}"


def raw_rows(total=40):
    """Invented rows: 10 categories, half sensitive; every category has at least four prompts."""
    rows = []
    for n in range(total):
        category = schema.CATEGORIES[n % 10]
        rows.append({"text": sentence(n), "category": category if n % 2 == 0 else "NONE" if n % 4 == 1 else category,
                     "audience": schema.AUDIENCES[n % 6], "sensitive": "yes" if n % 2 == 0 else "no"})
    return rows


class FreshSetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.raw = self.dir / "raw"
        self.raw.mkdir()
        self.results = self.dir / "results" / "s13a"
        os.environ["S13A_RESULTS_ROOT"] = str(self.results)
        self.addCleanup(os.environ.pop, "S13A_RESULTS_ROOT", None)
        self.source = self.dir / "source"
        self.source.mkdir()
        (self.source / "old.jsonl").write_text(json.dumps({"text": "a completely unrelated invented sentence about gardens and rain"}) + "\n")
        self.write_raw(raw_rows())

    def write_raw(self, rows, name="writer1.jsonl"):
        (self.raw / name).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf8")

    def run_main(self, *extra, capture=True):
        argv = ["--input", str(self.raw), "--source", f"src={self.source}", *extra]
        return fresh_set.main(argv)

    def freeze(self):
        return fresh_set.freeze(type("A", (), {"input": str(self.raw), "source": [f"src={self.source}"], "dry_run": True,
                                               "check_quotas": False, "source_kind": "writers", "marker_pattern": [],
                                               "id_salt": "t", "out": None})())

    def test_dry_run_reports_counts_and_writes_nothing(self):
        self.run_main("--dry-run")
        self.assertFalse(self.results.exists())

    def test_exact_duplicates_are_removed_after_whitespace_normalisation(self):
        rows = raw_rows()
        rows.append({**rows[0], "text": "  " + rows[0]["text"].replace(" ", "   ") + " "})
        self.write_raw(rows)
        manifest = self.freeze()
        self.assertEqual(manifest["duplicates_removed"], 1)
        self.assertEqual(manifest["n"], 40)

    def test_planted_exact_and_near_duplicates_are_flagged_and_removed(self):
        exact, near = sentence(3), sentence(4)
        (self.source / "leak.jsonl").write_text(
            json.dumps({"prompt": exact}) + "\n" +
            json.dumps({"nested": [{"x": near + " plus a short invented tail"}]}) + "\n", encoding="utf8")
        manifest = self.freeze()
        self.assertEqual((manifest["contamination"]["exact"], manifest["contamination"]["near"]), (1, 1))
        self.assertEqual(len(manifest["contamination"]["removed_ids"]), 2)
        self.assertEqual(manifest["n"], 38)
        self.assertEqual(manifest["contamination"]["sources_checked"][0]["files"], 2)

    def test_a_clean_source_flags_nothing(self):
        manifest = self.freeze()
        self.assertEqual((manifest["contamination"]["exact"], manifest["contamination"]["near"]), (0, 0))

    def test_marker_matches_are_removed(self):
        rows = raw_rows()
        rows[5]["text"] += " fresh_eval-folio-07"
        self.write_raw(rows)
        manifest = self.freeze()
        self.assertEqual(manifest["contamination"]["marker"], 1)
        self.assertEqual(manifest["n"], 39)

    def test_quota_rules(self):
        counts = fresh_set.quota_counts([{**r, "quota_cell": "x"} for r in raw_rows(40)])
        problems = fresh_set.quota_violations(counts)
        self.assertTrue(any(p.startswith("total 40") for p in problems))
        self.assertTrue(any("category HEALTH has" in p for p in problems))
        rows = [{"category": schema.CATEGORIES[n % 10], "audience": "P1", "sensitive": "yes" if n % 100 < 46 else "no", "quota_cell": "x"}
                for n in range(400)]
        self.assertEqual(fresh_set.quota_violations(fresh_set.quota_counts(rows)), [])
        rows = [{**r, "sensitive": "yes" if n % 100 < 44 else "no"} for n, r in enumerate(rows)]
        self.assertTrue(any("sensitive share" in p for p in fresh_set.quota_violations(fresh_set.quota_counts(rows))))

    def test_check_quotas_exits_non_zero_when_unmet(self):
        with self.assertRaises(SystemExit) as ctx:
            self.run_main("--dry-run", "--check-quotas")
        self.assertEqual(ctx.exception.code, 1)

    def test_check_quotas_exits_zero_when_met(self):
        rows = [{"text": sentence(n), "category": schema.CATEGORIES[n % 10], "audience": schema.AUDIENCES[n % 6],
                 "sensitive": "yes" if n % 2 == 0 else "no"} for n in range(400)]
        self.write_raw(rows)
        self.run_main("--dry-run", "--check-quotas")

    def test_invalid_rows_are_rejected_without_echoing_text(self):
        rows = raw_rows()
        rows[2]["audience"] = "P9"
        self.write_raw(rows)
        with self.assertRaises(SystemExit) as ctx:
            self.freeze()
        message = str(ctx.exception)
        self.assertIn("writer1.jsonl:3: invalid audience", message)
        self.assertNotIn(rows[2]["text"], message)

    def test_freeze_writes_manifest_without_text_and_a_matching_hash(self):
        out = self.results / "packet"
        self.run_main("--out", str(out))
        manifest = json.loads((out / "set_manifest.json").read_text(encoding="utf8"))
        blob = (out / "set_manifest.json").read_text(encoding="utf8")
        self.assertNotIn("told", blob)
        self.assertEqual(manifest["schema"], "privoke-s13a-set-v1")
        import hashlib
        self.assertEqual(manifest["sha256_jsonl"], hashlib.sha256((out / "frozen_set.jsonl").read_bytes()).hexdigest())
        frozen = [json.loads(l) for l in (out / "frozen_set.jsonl").read_text(encoding="utf8").splitlines()]
        self.assertEqual(len(frozen), manifest["n"])
        self.assertTrue(all(r["id"].startswith("fs-") and r["quota_cell"].count("/") == 2 for r in frozen))

    def test_freeze_refuses_an_output_directory_outside_the_results_root(self):
        with self.assertRaises(SystemExit):
            self.run_main("--out", str(self.dir / "committed"))
        self.assertFalse((self.dir / "committed").exists())

    def test_check_quotas_blocks_the_freeze(self):
        with self.assertRaises(SystemExit):
            self.run_main("--out", str(self.results / "packet"), "--check-quotas")
        self.assertFalse((self.results / "packet" / "frozen_set.jsonl").exists())

    def test_the_raw_input_is_not_treated_as_its_own_source(self):
        manifest = fresh_set.freeze(type("A", (), {"input": str(self.raw), "source": [f"raw={self.raw}"], "dry_run": True,
                                                   "check_quotas": False, "source_kind": "writers", "marker_pattern": [],
                                                   "id_salt": "t", "out": None})())
        self.assertEqual(manifest["contamination"]["exact"], 0)


if __name__ == "__main__":
    unittest.main()
