"""freeze, build and --check of the HUMANEVAL record on a fixture repository of invented labels."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import annotation_schema as schema  # noqa: E402
import check_order  # noqa: E402
import human_eval_report as her  # noqa: E402
import score_privoke as sp  # noqa: E402

N = 24
CELLS = ["HEALTH/P0/yes", "HEALTH/P1/no", "CRIMINAL/P2/yes", "NONE/P3/no"]
S13A = "docs/research/s13a"


def git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                             "-c", "commit.gpgsign=false", *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def label(n, flip=False):
    sensitive = "yes" if n % 3 else "no"
    if flip and n % 5 == 0:
        sensitive = "no" if sensitive == "yes" else "yes"
    return {"item_id": f"it-{n:02d}", "sensitive": sensitive, "subject": ("SELF", "THIRD_PARTY")[n % 2],
            "audience": ("P0", "P1", "P2", "PU")[n % 4],
            "categories": "HEALTH" if sensitive == "yes" else "NONE",
            "action": "BLOCK" if sensitive == "yes" and n % 2 else "WARN" if sensitive == "yes" else "ALLOW"}


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        self.s13a = self.repo / S13A
        (self.s13a / "labels").mkdir(parents=True)
        self.scratch = Path(self.tmp.name) / "scratch"
        self.scratch.mkdir()

    def commit(self, message, *paths):
        git(self.repo, "add", *paths)
        git(self.repo, "commit", "-q", "-m", message)

    def build_everything(self):
        (self.s13a / "set_manifest.json").write_text(json.dumps(
            {"sha256_jsonl": "ab" * 32, "n": N, "source_kind": "writers", "contamination": {"exact": 0, "near": 0, "marker": 0}}))
        self.commit("set", S13A + "/set_manifest.json")
        (self.s13a / "packet_manifest.json").write_text("{}")
        self.commit("packet", S13A + "/packet_manifest.json")
        cols = schema.COMMITTED_LABEL_COLUMNS_V2
        schema.write_csv(self.s13a / "labels" / "A.csv", cols, [label(n) for n in range(N)])
        schema.write_csv(self.s13a / "labels" / "B.csv", cols, [label(n, flip=True) for n in range(N)])
        schema.write_csv(self.s13a / "labels" / "adjudicated.csv", cols, [label(n) for n in range(N)])
        key = self.scratch / "key.jsonl"
        schema.write_jsonl(key, [{"item_id": f"it-{n:02d}", "family_id": CELLS[n % 4], "quota_cell": CELLS[n % 4], "split": "main"}
                                 for n in range(N)])
        self.assertEqual(her.main(["freeze", "--labels-dir", str(self.s13a / "labels"), "--key", str(key),
                                   "--out", str(self.s13a / "iaa.json"), "--n-boot", "40"]), 0)
        self.commit("labels", S13A + "/labels", S13A + "/iaa.json")
        reference = schema.read_labels(self.s13a / "labels" / "adjudicated.csv", version=2)
        clusters = json.loads((self.s13a / "iaa.json").read_text())["clusters"]
        arms = self.scratch / "arms"
        arms.mkdir()
        for arm in sp.ARMS:
            predictions = {i: ("WARN" if reference[i]["sensitive"] == "yes" and int(i[-2:]) % 4 else "ALLOW") for i in reference}
            (arms / f"arm_{arm}.json").write_text(json.dumps(sp.arm_report(arm, predictions, reference, clusters, 40)))
        self.assertEqual(her.main(["build", "--freeze-dir", str(self.s13a), "--arms", str(arms), "--date", "20261201",
                                   "--out-dir", str(self.repo / "paper" / "research")]), 0)
        self.record = self.repo / "paper" / "research" / "human-annotated-eval-20261201.json"
        self.commit("record", "paper")

    def test_a_consistent_record_passes_the_check_and_the_order_check(self):
        self.build_everything()
        self.assertEqual(her.check_record(self.record), [])
        self.assertEqual(her.main(["--check", str(self.record)]), 0)
        self.assertEqual(check_order.main(["--repo", str(self.repo)]), 0)
        record = json.loads(self.record.read_text())
        self.assertEqual(record["annotators"]["agent_labels"], 0)
        self.assertEqual({a["arm"]: a["layers_requested"] for a in record["arms"]}, {"product": [2, 3, 4], "semantic_only": [4]})
        self.assertEqual(record["scope_label"], "human ground truth")
        self.assertIn("cohen", record["iaa"]["sensitive"])
        self.assertEqual(record["adjudication"]["items"], len([n for n in range(N) if n % 5 == 0]))

    def test_the_record_and_labels_hold_no_text_or_notes(self):
        self.build_everything()
        for path in list((self.s13a / "labels").glob("*.csv")) + [self.record, self.s13a / "iaa.json"]:
            head = path.read_text(encoding="utf8").splitlines()[0]
            self.assertNotIn("text", head.replace("item_id", "")) if path.suffix == ".csv" else None
            self.assertNotIn('"notes"', path.read_text(encoding="utf8"))

    def test_a_changed_label_file_fails_the_check(self):
        self.build_everything()
        path = self.s13a / "labels" / "A.csv"
        path.write_text(path.read_text().replace("BLOCK", "WARN", 1))
        problems = her.check_record(self.record)
        self.assertTrue(any("freeze.files" in p for p in problems), problems)

    def test_a_changed_score_or_prediction_fails_the_check(self):
        self.build_everything()
        record = json.loads(self.record.read_text())
        record["arms"][0]["metrics"]["recall"]["value"] = 0.99
        self.record.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        self.assertTrue(any("recall" in p for p in her.check_record(self.record)))
        record = json.loads(self.record.read_text())
        first = sorted(record["arms"][0]["predictions"])[0]
        record["arms"][0]["metrics"]["recall"]["value"] = json.loads((self.record).read_text())["arms"][0]["metrics"]["recall"]["value"]
        record["arms"][0]["predictions"][first] = "BLOCK" if record["arms"][0]["predictions"][first] != "BLOCK" else "ALLOW"
        self.record.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        self.assertTrue(her.check_record(self.record))

    def test_a_changed_kappa_fails_the_check(self):
        self.build_everything()
        record = json.loads(self.record.read_text())
        record["iaa"]["sensitive"]["cohen"][0]["kappa"] = 0.123
        self.record.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        self.assertTrue(any("iaa.sensitive" in p for p in her.check_record(self.record)))

    def test_markdown_must_be_the_rendering_of_the_json(self):
        self.build_everything()
        md = self.record.with_suffix(".md")
        md.write_text(md.read_text().replace("Annotators:", "Annotators (edited):"))
        self.assertTrue(any("Markdown" in p for p in her.check_record(self.record)))

    def test_empty_layers_or_an_agent_label_claim_fail_the_check(self):
        self.build_everything()
        record = json.loads(self.record.read_text())
        record["arms"][1]["layers_requested"] = []
        self.record.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        self.assertTrue(any("layers_requested" in p for p in her.check_record(self.record)))
        record["arms"][1]["layers_requested"] = [4]
        record["annotators"]["agent_labels"] = 3
        self.record.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        self.assertTrue(any("no agent" in p for p in her.check_record(self.record)))

    def test_freeze_needs_two_annotators_and_the_adjudicated_file(self):
        schema.write_csv(self.s13a / "labels" / "A.csv", schema.COMMITTED_LABEL_COLUMNS_V2, [label(0)])
        key = self.scratch / "key.jsonl"
        schema.write_jsonl(key, [{"item_id": "it-00", "family_id": "c", "quota_cell": "c"}])
        with self.assertRaises(SystemExit):
            her.main(["freeze", "--labels-dir", str(self.s13a / "labels"), "--key", str(key), "--out", str(self.s13a / "iaa.json")])


if __name__ == "__main__":
    unittest.main()
