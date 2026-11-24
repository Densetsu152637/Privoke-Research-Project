"""check_order.py on fixture repositories: right order passes, any wrong order fails."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_order  # noqa: E402

SET = "docs/research/s13a/set_manifest.json"
PACKET = "docs/research/s13a/packet_manifest.json"
LABEL = "docs/research/s13a/labels/adjudicated.csv"
RECORD = "paper/research/human-annotated-eval-20261201.json"
NAMES = ["set_manifest_commit", "packet_manifest_commit", "label_commit"]


def git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                             "-c", "commit.gpgsign=false", *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


class OrderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q", "-b", "main")
        self.n = 0

    def commit(self, path, content="{}"):
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf8")
        git(self.repo, "add", path)
        self.n += 1
        git(self.repo, "commit", "-q", "-m", f"c{self.n}")
        return git(self.repo, "rev-parse", "HEAD")

    def run_check(self, **kw):
        return check_order.check(self.repo, "HEAD", SET, PACKET, "docs/research/s13a/labels", kw.get("record", RECORD),
                                 kw.get("allow_missing_record", False))

    def test_the_right_order_passes(self):
        shas = [self.commit(path) for path in (SET, PACKET, LABEL)]
        self.commit(RECORD, json.dumps({"freeze": dict(zip(NAMES, shas))}))
        result = self.run_check()
        self.assertTrue(result["ok"], result["problems"])

    def test_a_record_without_a_freeze_block_fails(self):
        for path in (SET, PACKET, LABEL, RECORD):
            self.commit(path)
        self.assertFalse(self.run_check()["ok"])

    def test_labels_before_the_packet_manifest_fail(self):
        for path in (SET, LABEL, PACKET, RECORD):
            self.commit(path)
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertTrue(any("packet_manifest_commit is not a strict ancestor of label_commit" in p for p in result["problems"]))

    def test_packet_manifest_before_the_set_manifest_fails(self):
        for path in (PACKET, SET, LABEL, RECORD):
            self.commit(path)
        self.assertFalse(self.run_check()["ok"])

    def test_record_before_labels_fails(self):
        for path in (SET, PACKET, RECORD, LABEL):
            self.commit(path)
        self.assertFalse(self.run_check()["ok"])

    def test_two_files_in_one_commit_are_not_an_order(self):
        self.commit(SET)
        (self.repo / PACKET).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / PACKET).write_text("{}")
        (self.repo / LABEL).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / LABEL).write_text("x")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "both")
        self.commit(RECORD)
        self.assertFalse(self.run_check()["ok"])

    def test_a_missing_file_fails_unless_it_is_the_record_and_allowed(self):
        for path in (SET, PACKET, LABEL):
            self.commit(path)
        self.assertFalse(self.run_check(record=None)["ok"])
        self.assertTrue(self.run_check(record=None, allow_missing_record=True)["ok"])
        self.assertFalse(self.run_check(record=None, allow_missing_record=False)["ok"])

    def test_the_record_must_name_the_commits_it_computed(self):
        shas = [self.commit(path) for path in (SET, PACKET, LABEL)]
        freeze = {"set_manifest_commit": shas[0], "packet_manifest_commit": shas[1], "label_commit": shas[2]}
        self.commit(RECORD, json.dumps({"freeze": freeze}))
        self.assertTrue(self.run_check()["ok"])
        freeze["label_commit"] = shas[0]
        (self.repo / RECORD).write_text(json.dumps({"freeze": freeze}))
        git(self.repo, "commit", "-q", "-am", "edit")
        self.assertFalse(self.run_check()["ok"])

    def test_labels_changed_after_the_label_commit_fail(self):
        shas = [self.commit(path) for path in (SET, PACKET, LABEL)]
        self.commit(RECORD, json.dumps({"freeze": dict(zip(NAMES, shas))}))
        self.assertTrue(self.run_check()["ok"])
        self.commit(LABEL, "changed after the freeze")
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertTrue(any("labels changed" in p for p in result["problems"]))

    def test_main_exit_codes(self):
        for path in (SET, LABEL, PACKET):
            self.commit(path)
        self.assertEqual(check_order.main(["--repo", str(self.repo), "--allow-missing-record"]), 1)
        self.assertEqual(check_order.main(["--repo", str(self.repo / "nowhere")]), 2)


class CleanOrderTests(unittest.TestCase):
    def test_main_exits_zero_on_a_good_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git(repo, "init", "-q", "-b", "main")
            shas = []
            for i, path in enumerate((SET, PACKET, LABEL, RECORD)):
                file = repo / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(json.dumps({"freeze": dict(zip(NAMES, shas))}) if path == RECORD else "{}")
                git(repo, "add", path)
                git(repo, "commit", "-q", "-m", f"c{i}")
                shas.append(git(repo, "rev-parse", "HEAD"))
            self.assertEqual(check_order.main(["--repo", str(repo)]), 0)


if __name__ == "__main__":
    unittest.main()
