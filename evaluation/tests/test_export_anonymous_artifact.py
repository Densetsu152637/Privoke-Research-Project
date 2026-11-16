"""Tests for evaluation/export_anonymous_artifact.py on a throwaway git repository."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import export_anonymous_artifact as exp  # noqa: E402

NAME = "Nicholas " + "Bisset"
HANDLE = "Densetsu" + "152637"
PATTERNS = f"# comment\nBisset\nMonash\n{HANDLE}\nnbis0006\n"


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=T", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        self.repo.mkdir()
        self.out = base / "out" / "export"
        self.patterns = base / "patterns.txt"
        self.patterns.write_text(PATTERNS, encoding="utf8")
        git(self.repo, "init", "-q")
        git(self.repo, "remote", "add", "origin", f"https://github.com/{HANDLE}/demo.git")
        files = {
            "README.md": f"Written by {NAME}, Monash University Malaysia.\nSee https://github.com/{HANDLE}/demo/issues/1\n",
            "LICENSE": "Copyright (c) 2026 " + NAME + "\nCopyright and Related Rights stay.\n",
            "src/code.py": "# contact nbis0006@student.monash.edu\nprint('hi')\n",
            "paper/main.pdf": "build output",
            "paper/old/draft.tex": NAME,
            "untouched.txt": "nothing here\n",
        }
        for rel, text in files.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf8", newline="\n")
        (self.repo / "blob.bin").write_bytes(b"\0\1\2binary")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "init")
        (self.repo / "untracked.txt").write_text(NAME)

    def run_export(self, **kw):
        return exp.export(self.repo, "HEAD", self.out, self.patterns, **kw)

    def test_rewrites_and_verifies(self):
        dest, manifest = self.run_export()
        self.assertTrue(manifest["verification"]["passed"])
        self.assertFalse((dest / ".git").exists())
        self.assertFalse((dest / "untracked.txt").exists())
        readme = (dest / "README.md").read_text(encoding="utf8")
        self.assertIn("Anonymous Author", readme)
        self.assertIn(exp.PLACEHOLDER_URL, readme)
        self.assertNotIn("Monash", readme)
        self.assertIn("Copyright (c) Anonymous Authors", (dest / "LICENSE").read_text())
        self.assertIn("Copyright and Related Rights stay.", (dest / "LICENSE").read_text())
        self.assertIn(exp.PLACEHOLDER_EMAIL, (dest / "src/code.py").read_text())
        self.assertEqual(manifest["redactions"]["per_file"]["README.md"], 3)
        everything = "".join(p.read_text(encoding="utf8", errors="ignore") for p in dest.rglob("*") if p.is_file())
        self.assertNotIn("github.com/" + HANDLE, everything)
        self.assertNotIn("origin", everything.lower().replace("original", ""))

    def test_exclusions_and_manifest(self):
        dest, manifest = self.run_export()
        self.assertFalse((dest / "paper/main.pdf").exists())
        self.assertFalse((dest / "paper/old/draft.tex").exists())
        self.assertIn("paper/main.pdf", manifest["exclusions"]["excluded_files"])
        on_disk = json.loads((dest / exp.MANIFEST_NAME).read_text())
        self.assertEqual(on_disk["file_count"], 5)
        self.assertEqual(on_disk["tree_sha256"], manifest["tree_sha256"])
        self.assertIn("blob.bin", on_disk["verification"]["binary_files"])
        self.assertNotIn("commit", json.dumps(on_disk["source_revision_commitment"]))

    def test_extra_exclude_and_determinism(self):
        _, first = self.run_export(extra_excludes=["untouched.txt"])
        self.assertEqual(first["file_count"], 4)
        _, second = self.run_export(extra_excludes=["untouched.txt"], clean=True)
        self.assertEqual(first["tree_sha256"], second["tree_sha256"])

    def test_refuses_destination_inside_repo(self):
        for inner in (self.repo / "export", self.repo, self.repo.parent):
            with self.assertRaises(exp.ExportError):
                exp.export(self.repo, "HEAD", inner, self.patterns)

    def test_refuses_non_empty_destination(self):
        self.out.mkdir(parents=True)
        (self.out / "x").write_text("x")
        with self.assertRaises(exp.ExportError):
            self.run_export()
        with self.assertRaises(exp.ExportError):
            self.run_export(clean=True)  # no manifest: not a previous export

    def test_verification_flags_unhandled_identity(self):
        extra = "ZZunhandled\\d+"
        self.patterns.write_text(PATTERNS + extra + "\n", encoding="utf8")
        (self.repo / "late.txt").write_text("ZZunhandled42\n")
        git(self.repo, "add", "late.txt")
        git(self.repo, "commit", "-q", "-m", "late")
        _, manifest = self.run_export()
        self.assertFalse(manifest["verification"]["passed"])
        self.assertIn("late.txt", manifest["verification"]["text_matches"])

    def test_binary_byte_match_fails(self):
        (self.repo / "bad.bin").write_bytes(b"\0" + NAME.encode())
        git(self.repo, "add", "bad.bin")
        git(self.repo, "commit", "-q", "-m", "bin")
        _, manifest = self.run_export()
        self.assertFalse(manifest["verification"]["passed"])
        self.assertIn("bad.bin", manifest["verification"]["binary_byte_scan_matches"])

    def test_main_exit_codes(self):
        argv = ["--repo", str(self.repo), "--dest", str(self.out), "--patterns", str(self.patterns)]
        self.assertEqual(exp.main(argv), 0)
        self.assertEqual(exp.main(argv), 2)  # non-empty destination
        self.assertEqual(exp.main(["--repo", str(self.repo), "--dest", str(self.repo / "e"),
                                   "--patterns", str(self.patterns)]), 2)


if __name__ == "__main__":
    unittest.main()
