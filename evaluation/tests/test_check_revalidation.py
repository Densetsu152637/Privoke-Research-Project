"""Tests for the G7 revalidation check (evaluation/check_revalidation.py), on a synthetic plan and a throwaway git repository."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_revalidation as check  # noqa: E402

PLAN = """# Plan

## Research evidence and revalidation

Intro text.

| Claim | Why | Stage | Status after stage 9 |
| --- | --- | --- | --- |
| A | x | 9 | revalidated (paper/research/new.md) |
| B | x | 9 | historical (paper/research/old.md) |
| C | x | 9 | not claimed for the Rust build |

## Next section
"""


def git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *arguments], cwd=root, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class RevalidationTests(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name)
        (self.root / "paper/research").mkdir(parents=True)
        (self.root / "docs/experiments").mkdir(parents=True)
        for name in ("old.md", "update-security-20261116.md", "update-security-20261116.json", "claims.md"):
            (self.root / "paper/research" / name).write_text("one\n", encoding="utf-8")
        git(self.root, "init", "-q")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "base")
        git(self.root, "tag", "base")
        (self.root / "paper/research/new.md").write_text("new\n", encoding="utf-8")

    def tearDown(self):
        self._directory.cleanup()

    def test_the_table_is_parsed_and_every_status_is_accepted(self):
        header, rows = check.table_rows(PLAN)
        self.assertEqual(len(rows), 3)
        self.assertEqual(check.check_statuses(PLAN, "base", self.root), [])

    def test_a_missing_status_column_or_value_or_path_is_an_error(self):
        self.assertIn("no Status column", check.check_statuses(PLAN.replace("Status after stage 9", "Note"), "base", self.root)[0])
        self.assertIn("not revalidated", check.check_statuses(PLAN.replace("not claimed for the Rust build", "fine"), "base", self.root)[0])
        self.assertIn("does not exist", check.check_statuses(PLAN.replace("paper/research/new.md", "paper/research/absent.md"), "base", self.root)[0])

    def test_a_historical_path_must_be_unchanged_since_the_base(self):
        (self.root / "paper/research/old.md").write_text("two\n", encoding="utf-8")
        errors = check.check_statuses(PLAN, "base", self.root)
        self.assertEqual(len(errors), 1)
        self.assertIn("changed since base", errors[0])

    def test_evidence_may_only_be_added_to(self):
        self.assertEqual(check.check_evidence_only_added("base", self.root), [])
        with (self.root / "paper/research/claims.md").open("a", encoding="utf-8") as handle:
            handle.write("two\n")
        self.assertEqual(check.check_evidence_only_added("base", self.root), [])
        (self.root / "paper/research/claims.md").write_text("rewritten\n", encoding="utf-8")
        self.assertEqual(len(check.check_evidence_only_added("base", self.root)), 1)
        (self.root / "paper/research/old.md").unlink()
        self.assertEqual(len(check.check_evidence_only_added("base", self.root)), 2)

    def test_the_recorded_update_security_files_must_match_the_base(self):
        self.assertEqual(check.check_pinned_records("base", self.root), [])
        (self.root / "paper/research/update-security-20261116.json").write_text("changed\n", encoding="utf-8")
        self.assertEqual(len(check.check_pinned_records("base", self.root)), 1)


if __name__ == "__main__":
    unittest.main()
