"""Synthetic tests for evaluation/build_fresh_sets.py (fabricated rows only; no network, no real data)."""
import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import build_fresh_sets as build  # noqa: E402

try:
    import faker  # noqa: F401
    import pyarrow  # noqa: F401
    HAVE_DEPS = True
except ImportError:  # the host Python venv without the fresh-data requirements
    HAVE_DEPS = False


def spy_row() -> dict:
    tokens = ["Please", "contact", "NAME", "at", "EMAIL", "or", "NAME", ".", "Thanks"]
    tags = ["O", "O", "B-NAME", "O", "B-EMAIL", "O", "B-NAME", "O", "O"]
    return {"tokens": tokens, "ent_tags": tags, "trailing_whitespaces": [True] * 7 + [False, False],
            "labels": [0] * 9}


@unittest.skipUnless(HAVE_DEPS, "needs the evaluation/requirements-fresh-data.txt environment")
class SpyFillTests(unittest.TestCase):
    def test_fill_is_deterministic_spans_exact_and_same_value_per_type(self):
        text_a, spans_a = build.fill_spy_row(spy_row(), "legal_questions:3", 7)
        text_b, spans_b = build.fill_spy_row(spy_row(), "legal_questions:3", 7)
        self.assertEqual((text_a, spans_a), (text_b, spans_b))
        self.assertEqual([label for _, _, label in spans_a], ["NAME", "EMAIL", "NAME"])
        names = [text_a[s:e] for s, e, label in spans_a if label == "NAME"]
        self.assertEqual(names[0], names[1])
        text_c, _ = build.fill_spy_row(spy_row(), "legal_questions:4", 7)
        self.assertNotEqual(text_a, text_c)

    def test_f3_command_writes_manifest_with_hashes_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for name in ("legal.jsonl", "medical.jsonl"):
                (directory / name).write_text("".join(json.dumps(spy_row()) + "\n" for _ in range(20)),
                                              encoding="utf-8")
            argv = ["f3", "--legal", str(directory / "legal.jsonl"), "--medical", str(directory / "medical.jsonl"),
                    "--per-domain", "5", "--output", str(directory / "out")]
            self.assertEqual(build.main(argv), 0)
            rows = [json.loads(line) for line in (directory / "out" / "f3_spy.jsonl").read_text().splitlines()]
            self.assertEqual(len(rows), 10)
            self.assertTrue(all(r["expected_has_pii"] and r["entities"] for r in rows))
            manifest = json.loads((directory / "out" / "manifest_f3.json").read_text())
            self.assertEqual(len(manifest["output_sha256"]), 64)
            with self.assertRaises(SystemExit):
                build.main(argv)


@unittest.skipUnless(HAVE_DEPS, "needs the evaluation/requirements-fresh-data.txt environment")
class F2Tests(unittest.TestCase):
    def fabricate(self, directory: Path):
        piimb = directory / "piimb.jsonl"
        piimb.write_text("".join(json.dumps({"text": "x" * (10 + i % 90), "language": "en"}) + "\n"
                                 for i in range(200)), encoding="utf-8")
        oasst = directory / "oasst.jsonl.gz"
        with gzip.open(oasst, "wt", encoding="utf-8") as handle:
            for i in range(300):
                handle.write(json.dumps({"message_id": f"m{i}", "message_tree_id": f"t{i}", "parent_id": None,
                                         "role": "prompter", "lang": "en" if i % 3 else "es", "deleted": False,
                                         "text": f"prompt number {i % 250}",
                                         "labels": {"pii": {"value": 0.0, "count": 3}}}) + "\n")
        dolly = directory / "dolly.jsonl"
        dolly.write_text("".join(json.dumps({"instruction": ("long " * 200) if i == 0 else f"question {i}",
                                             "context": "", "response": "", "category": "open_qa"}) + "\n"
                                 for i in range(300)), encoding="utf-8")
        import pyarrow as pa
        import pyarrow.parquet as pq
        turns = [[{"content": f"hello wild {i}", "role": "user", "language": "English", "toxic": False,
                   "redacted": i % 5 == 0}] for i in range(300)]
        table = pa.table({"conversation_hash": [f"h{i}" for i in range(300)], "conversation": turns,
                          "language": ["English" if i % 4 else "French" for i in range(300)]})
        pq.write_table(table, directory / "wild.parquet")
        return piimb, oasst, dolly, directory / "wild.parquet"

    def test_f2_quotas_cap_dedupe_and_blinded_packets(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            piimb, oasst, dolly, wild = self.fabricate(directory)
            original = dict(build.F2_QUOTAS)
            build.F2_QUOTAS.update({"oasst2": 50, "wildchat": 60, "dolly": 40})
            try:
                build.main(["f2", "--oasst2", str(oasst), "--dolly", str(dolly), "--wildchat", str(wild),
                            "--piimb-sentences", str(piimb), "--output", str(directory / "f2")])
            finally:
                build.F2_QUOTAS.clear()
                build.F2_QUOTAS.update(original)
            rows = [json.loads(line) for line in
                    (directory / "f2" / "f2_natural_prompts.jsonl").read_text().splitlines()]
            self.assertEqual(len(rows), 150)
            self.assertEqual(len({r["text"] for r in rows}), 150)
            manifest = json.loads((directory / "f2" / "manifest_f2.json").read_text())
            self.assertLessEqual(max(r["length"] for r in rows), manifest["length_cap_chars"])
            self.assertTrue(all(r["expected_has_pii"] is None for r in rows))
            self.assertNotIn("wildchat_redacted", rows[0])
            build.main(["adjudication", "--f2", str(directory / "f2" / "f2_natural_prompts.jsonl"),
                        "--packet-size", "40", "--output", str(directory / "adj")])
            packets = sorted((directory / "adj" / "packets").glob("packet-*.jsonl"))
            self.assertEqual(len(packets), 4)
            items = [json.loads(line) for p in packets for line in p.read_text().splitlines()]
            self.assertEqual(len(items), 150)
            self.assertEqual(set(items[0]), {"item", "text"})
            key = json.loads((directory / "adj" / "coordinator" / "adjudication_key.json").read_text())
            self.assertEqual(len(key["key"]), 150)
            self.assertEqual(sorted(key["audit_order"]), sorted(key["key"]))


if __name__ == "__main__":
    unittest.main()
