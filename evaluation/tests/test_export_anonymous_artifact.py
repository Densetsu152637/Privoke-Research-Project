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

    def test_user_home_paths_rewritten_and_verified(self):
        real = Path(__file__).resolve().parents[2] / exp.DEFAULT_PATTERNS
        home = [line for line in real.read_text(encoding="utf8").splitlines() if "Users" in line and not line.startswith("#")]
        self.assertEqual(len(home), 2)
        self.patterns.write_text(PATTERNS + "\n".join(home) + "\n", encoding="utf8")
        account = "Someone" + "42"
        paths = {
            "plain.md": f"Ran C:\\Users\\{account}\\AppData\\x.exe and c:/users/{account}/.cache\n",
            "escaped.json": '{"command": "\\"C:\\\\Users\\\\' + account + '\\\\AppData\\\\py.exe\\""}\n',
            "mac.txt": f"see /Users/{account}/work and (/Users/{account})\n",
            "rule.toml": "regex = '''/Users/(?i)[a-z0-9]+'''\nurl = 'https://example.com/api/users/5'\n",
        }
        for rel, text in paths.items():
            (self.repo / rel).write_text(text, encoding="utf8", newline="\n")
        git(self.repo, "add", *paths)
        git(self.repo, "commit", "-q", "-m", "paths")
        dest, manifest = self.run_export()
        self.assertTrue(manifest["verification"]["passed"], manifest["verification"])
        for rel in ("plain.md", "escaped.json", "mac.txt"):
            text = (dest / rel).read_text(encoding="utf8")
            self.assertNotIn(account, text)
            self.assertIn(exp.PLACEHOLDER_USER, text)
        self.assertEqual(json.loads((dest / "escaped.json").read_text())["command"].count("<user>"), 1)
        self.assertEqual((dest / "rule.toml").read_text(encoding="utf8"), paths["rule.toml"])

    def test_user_home_pattern_flags_unrewritten_path(self):
        real = Path(__file__).resolve().parents[2] / exp.DEFAULT_PATTERNS
        patterns = [p for p in exp.load_patterns(real) if "Users" in p.pattern]
        for text in ("C:\\Users\\abc", "C:\\\\Users\\\\abc", "C:/Users/abc", " /Users/abc"):
            self.assertTrue(any(p.search(text) for p in patterns), text)
        for text in ("C:\\Users\\<user>", "/Users/<user>", "/Users/(?i)[a-z]", "api/users/5"):
            self.assertFalse(any(p.search(text) for p in patterns), text)

    def test_checkout_paths_and_go_module_rewritten_consistently(self):
        real = Path(__file__).resolve().parents[2] / exp.DEFAULT_PATTERNS
        repo_lines = [line for line in real.read_text(encoding="utf8").splitlines()
                      if "privoke" in line.lower() and not line.startswith("#")]
        self.assertGreaterEqual(len(repo_lines), 3)
        self.patterns.write_text(PATTERNS + "\n".join(repo_lines) + "\n", encoding="utf8")
        name = "Privoke-" + "Research-Project"
        module = "github.com/" + "privoke/research-project"
        files = {
            "notes.md": (f"Ran in `D:/Git Repositories/{name}/evaluation` and "
                         f"[x](<D:\\Git Repositories\\{name}\\results\\a.json>), "
                         f"worktree D:/Git-Worktrees/{name}/wt-a and D:/Git Repositories/{name}-wt-c/x, "
                         f"posix ~/src/{name}/paper.\n"),
            "rec.json": '{"path": "D:\\\\Git Worktrees\\\\paper-evidence\\\\' + name + '\\\\models\\\\m.bin"}\n',
            "compose.yml": f"image: ${{IMG:-{name.lower()}-client-runtime}}\nname: {name.lower()}\n",
            "svc/go.mod": f"module {module}/services/svc\n\ngo 1.22\n",
            "svc/main.go": f'package main\n\nimport pb "{module}/services/svc/gen/v1"\n\nvar _ = pb.X\n',
            "shared/p.proto": f'option go_package = "{module}/services/svc/gen/v1;pb";\n',
        }
        for rel, text in files.items():
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf8", newline="\n")
        git(self.repo, "add", *files)
        git(self.repo, "commit", "-q", "-m", "paths")
        dest, manifest = self.run_export()
        self.assertTrue(manifest["verification"]["passed"], manifest["verification"])
        notes = (dest / "notes.md").read_text(encoding="utf8")
        self.assertIn("`<repo>/evaluation`", notes)
        self.assertIn("(<<repo>\\results\\a.json>)", notes)
        self.assertIn("worktree <repo>/wt-a and <repo>/x", notes)
        self.assertIn("posix <repo>/paper.", notes)
        self.assertEqual(json.loads((dest / "rec.json").read_text())["path"], "<repo>\\models\\m.bin")
        compose = (dest / "compose.yml").read_text(encoding="utf8")
        self.assertIn(f"{exp.ANONYMOUS_PROJECT_NAME}-client-runtime", compose)
        self.assertIn(f"name: {exp.ANONYMOUS_PROJECT_NAME}\n", compose)
        go_mod = (dest / "svc/go.mod").read_text(encoding="utf8")
        self.assertIn(f"module {exp.ANONYMOUS_GO_MODULE}/services/svc\n", go_mod)
        self.assertIn(f'"{exp.ANONYMOUS_GO_MODULE}/services/svc/gen/v1"', (dest / "svc/main.go").read_text())
        self.assertIn(f'"{exp.ANONYMOUS_GO_MODULE}/services/svc/gen/v1;pb"', (dest / "shared/p.proto").read_text())
        everything = "".join(p.read_text(encoding="utf8", errors="ignore") for p in dest.rglob("*") if p.is_file())
        self.assertNotIn(module, everything)
        self.assertNotIn(name.lower(), everything.lower())

    def test_main_exit_codes(self):
        argv = ["--repo", str(self.repo), "--dest", str(self.out), "--patterns", str(self.patterns)]
        self.assertEqual(exp.main(argv), 0)
        self.assertEqual(exp.main(argv), 2)  # non-empty destination
        self.assertEqual(exp.main(["--repo", str(self.repo), "--dest", str(self.repo / "e"),
                                   "--patterns", str(self.patterns)]), 2)


if __name__ == "__main__":
    unittest.main()
