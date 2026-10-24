"""Synthetic tests for evaluation/fresh_set_plan.py (fabricated rows only; no network, no real data)."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fresh_set_plan as plan  # noqa: E402


def fabricate(path: Path, documents: int = 120, sentences: int = 3) -> str:
    rows = []
    for doc in range(documents):
        parent = f"nemotron-pii:{doc:032x}"
        for index in range(sentences):
            has_pii = (doc + index) % 2 == 0
            name = f"Person{doc}x{index}"
            body = f"Contact {name} now." if has_pii else f"Plain sentence {doc}-{index}."
            text = (" " if index == 0 else "") + body + "  "
            entities = []
            if has_pii:
                start = text.index(name)
                entities = [{"start": start, "end": start + len(name), "label": "name"}]
            rows.append({"uid": f"{parent}_s{index}", "task_name": "nemotron-pii", "source_dataset": "synthetic",
                         "source_uid": parent, "parent_id": parent, "text": text, "entities": entities,
                         "language": "en" if doc % 10 else "fr"})
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PowerTests(unittest.TestCase):
    def test_exact_power_matches_one_directional_poisson_intuition(self):
        # delta == psi: every discordant pair favours the candidate, need >= 6 of them for p < 0.05.
        self.assertGreaterEqual(plan.mcnemar_power(790, 0.01, 0.01), 0.80)
        self.assertLess(plan.mcnemar_power(500, 0.01, 0.01), 0.80)

    def test_null_effect_does_not_exceed_alpha(self):
        self.assertLessEqual(plan.mcnemar_power(2000, 0.0, 0.05), 0.05 + 1e-9)

    def test_required_n_is_monotone_in_effect_and_discordance(self):
        self.assertLess(plan.required_n_mcnemar(0.02, 0.04), plan.required_n_mcnemar(0.01, 0.04))
        self.assertLess(plan.required_n_mcnemar(0.01, 0.02), plan.required_n_mcnemar(0.01, 0.04))

    def test_noninferiority_formula_is_self_consistent(self):
        n = plan.noninferiority_n(0.0, 0.114, 0.01)
        self.assertAlmostEqual(plan.noninferiority_power(n, 0.0, 0.114, 0.01), 0.80, delta=0.01)
        with self.assertRaises(ValueError):
            plan.noninferiority_n(-0.02, 0.1, 0.01)


class DrawTests(unittest.TestCase):
    def run_draw(self, directory: Path, **overrides):
        source = directory / "sentences.jsonl"
        digest = fabricate(source)
        exclusion = directory / "exclude.json"
        exclusion.write_text(json.dumps({"groups": [f"nemotron-pii:{doc:032x}" for doc in range(30)]}),
                             encoding="utf-8")
        output = directory / overrides.pop("name", "out")
        argv = ["draw", "--sentences", str(source), "--expect-sha256", digest, "--exclude", str(exclusion),
                "--seed", "5", "--positives", "40", "--negatives", "40", "--output", str(output)]
        for key, value in overrides.items():
            argv += [f"--{key.replace('_', '-')}", str(value)]
        self.assertEqual(plan.main(argv), 0)
        rows = [json.loads(line) for line in (output / "piimb_fresh_v1.jsonl").read_text(encoding="utf-8").splitlines()]
        return rows, json.loads((output / "manifest.json").read_text(encoding="utf-8")), exclusion

    def test_draw_is_disjoint_balanced_capped_and_spans_valid(self):
        with tempfile.TemporaryDirectory() as raw:
            rows, manifest, exclusion = self.run_draw(Path(raw))
            excluded = set(json.loads(exclusion.read_text())["groups"])
            self.assertEqual(len(rows), 80)
            self.assertEqual(sum(row["expected_has_pii"] for row in rows), 40)
            self.assertFalse(any(row["group_id"] in excluded for row in rows))
            self.assertEqual(len({row["group_id"] for row in rows}), 80)
            for row in rows:
                for entity in row["entities"]:
                    self.assertTrue(row["text"][entity["start"]:entity["end"]].startswith("Person"))
            self.assertEqual(manifest["max_per_group"], 1)

    def test_draw_is_deterministic_and_group_cap_relaxes(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            rows_a, manifest_a, _ = self.run_draw(Path(first))
            rows_b, manifest_b, _ = self.run_draw(Path(second))
            self.assertEqual(manifest_a["output_sha256"], manifest_b["output_sha256"])
            capped, _, _ = self.run_draw(Path(first), name="out2", max_per_group=2)
            counts = {}
            for row in capped:
                counts[row["group_id"]] = counts.get(row["group_id"], 0) + 1
            self.assertLessEqual(max(counts.values()), 2)

    def test_scan_collects_group_tokens_without_text_and_honours_skip(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            (directory / "a.jsonl").write_text('{"group_id": "gretel:abc_s3", "text": "x"}\n', encoding="utf-8")
            (directory / "held.jsonl").write_text('{"group_id": "privy:zzz"}\n', encoding="utf-8")
            out = directory / "o.json"
            plan.main(["scan", str(directory), "--output", str(out), "--skip", str(directory / "held.jsonl")])
            self.assertEqual(json.loads(out.read_text())["groups"], ["gretel:abc"])

    def test_hash_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            source = directory / "sentences.jsonl"
            fabricate(source)
            (directory / "e.json").write_text(json.dumps({"groups": []}), encoding="utf-8")
            with self.assertRaises(SystemExit):
                plan.main(["draw", "--sentences", str(source), "--expect-sha256", "0" * 64, "--exclude",
                           str(directory / "e.json"), "--seed", "1", "--positives", "1", "--negatives", "1",
                           "--output", str(directory / "o")])


if __name__ == "__main__":
    unittest.main()
