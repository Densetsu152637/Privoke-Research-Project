"""Fixture tests for evaluation/check_s13_commit_hygiene.py (Stage 13-H).

Every test builds a throwaway git repository in a temp directory. Prompts are
invented sentences. Secret-looking strings are assembled at run time so this
file never contains a literal key marker.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "check_s13_commit_hygiene.py")
PROMPT = "the quarterly lantern festival committee will review wooden boat rental prices on thursday morning"
OTHER = "seven grey herons crossed the frozen estuary before the lighthouse keeper woke up today"
ALLOWLIST = "evaluation/s13_allowlist.json"
GUIDE = "docs/research/annotation-guideline-v2-20261201.md"
BRIEF = "docs/research/s13a-writer-brief-20261201.md"
TRANSFORMS = "evaluation/e2e_evasion_transforms.py"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="s13h-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.empty_root = os.path.join(self.tmp, "no-inputs")
        os.makedirs(self.empty_root)
        for args in (["init", "-q"], ["config", "user.name", "Fixture"],
                     ["config", "user.email", "fixture@example.invalid"],
                     ["config", "core.autocrlf", "false"], ["config", "commit.gpgsign", "false"]):
            self.git(*args)
        self.write({"README.md": "fixture\n", ".gitignore": "evaluation/results/\n"})
        self.base = self.commit("base")

    def git(self, *args):
        out = subprocess.run(["git", "-C", self.repo, *args], capture_output=True, check=True)
        return out.stdout.decode().strip()

    def write(self, files):
        for rel, content in files.items():
            full = os.path.join(self.repo, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            mode = "wb" if isinstance(content, bytes) else "w"
            kw = {} if mode == "wb" else {"encoding": "utf-8", "newline": "\n"}
            with open(full, mode, **kw) as fh:
                fh.write(content)

    def commit(self, msg, files=None):
        if files:
            self.write(files)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def local_dir(self, rel="inputs/s13a/raw", prompt=PROMPT):
        d = os.path.join(self.tmp, rel)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "items.jsonl"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"id": 1, "label": "x", "content": prompt}) + "\n")
        return d

    def run_check(self, *extra, root=None, base=None):
        env = dict(os.environ, S13_LOCAL_INPUTS_ROOT=root or self.empty_root)
        proc = subprocess.run(
            [sys.executable, SCRIPT, "--repo", self.repo, "--range", f"{base or self.base}..HEAD", *extra],
            capture_output=True, text=True, env=env)
        try:
            report = json.loads(proc.stdout)
        except ValueError:
            report = None
        return proc.returncode, report, proc.stderr

    def rules(self, report):
        return sorted((v["file"], v["rule"]) for v in report["violations"])


class NameKeyWeightTests(Fixture):
    def test_text_field_fails(self):
        self.commit("add", {"paper/research/r.json": json.dumps({"rows": [{"id": 1, "text": "x"}]})})
        rc, rep, _ = self.run_check()
        self.assertEqual(rc, 1)
        self.assertEqual(self.rules(rep), [("paper/research/r.json", "forbidden_field")])

    def test_other_forbidden_names_and_csv_column(self):
        for key in ("prompt", "body", "notes"):
            self.commit(key, {f"d/{key}.json": json.dumps({key: 1})})
        self.commit("csv", {"d/t.csv": "id,Notes\n1,a\n"})
        rc, rep, _ = self.run_check()
        self.assertEqual(rc, 1)
        self.assertEqual(len(rep["violations"]), 4)

    def test_clean_json_passes(self):
        self.commit("ok", {"d/ok.json": json.dumps({"id": 1, "label": "pii", "sha256": "ab"})})
        rc, rep, _ = self.run_check()
        self.assertEqual((rc, rep["violations"]), (0, []))

    def test_safetensors_and_other_weights(self):
        self.commit("w", {"m/a.safetensors": b"\x00\x01", "m/b.onnx": b"x", "m/c.bin": b"x",
                          "m/d.pt": b"x", "m/e.pth": b"x"})
        rc, rep, _ = self.run_check()
        self.assertEqual(rc, 1)
        self.assertEqual({v["rule"] for v in rep["violations"]}, {"weight_file"})
        self.assertEqual(len(rep["violations"]), 5)

    def test_key_patterns(self):
        marker = "-----BEGIN " + "{}PRIVATE KEY-----"
        self.commit("k", {
            "k/openssh.txt": marker.format("OPENSSH ") + "\n",
            "k/enc.txt": marker.format("ENCRYPTED ") + "\n",
            "k/plain.txt": marker.format("") + "\n",
            "k/seed.md": "signing seed = " + "a1" * 32 + "\n",
            "k/py_secret.py": "PRIVATE = '" + "b2" * 32 + "'\n",
        })
        rc, rep, _ = self.run_check()
        self.assertEqual(rc, 1)
        self.assertEqual({v["rule"] for v in rep["violations"]}, {"key_pattern"})
        self.assertEqual(len(rep["violations"]), 5)

    def test_sha256_on_unrelated_line_passes(self):
        self.commit("h", {"docs/hash.md": "artifact digest: " + "c3" * 32 + "\n"})
        rc, rep, _ = self.run_check()
        self.assertEqual((rc, rep["violations"]), (0, []))

    def test_ignored_output_path_committed(self):
        self.commit("ig", {".gitignore": "results/\n"})
        base = self.git("rev-parse", "HEAD")
        os.makedirs(os.path.join(self.repo, "evaluation/results/s13a/raw"))
        self.write({"evaluation/results/s13a/raw/n.dat": "1\n"})
        self.git("add", "-f", "evaluation/results/s13a/raw/n.dat")
        self.git("commit", "-q", "-m", "forced")
        rc, rep, _ = self.run_check(base=base)
        self.assertEqual(rc, 1)
        self.assertEqual(self.rules(rep), [("evaluation/results/s13a/raw/n.dat", "prompt_output_path")])


class EightGramTests(Fixture):
    def test_planted_prompt_in_record_json_fails(self):
        d = self.local_dir()
        self.commit("rec", {"paper/research/rec.json": json.dumps({"id": 1, "label": PROMPT})})
        rc, rep, _ = self.run_check("--local-inputs", d)
        self.assertEqual(rc, 1)
        self.assertEqual(self.rules(rep), [("paper/research/rec.json", "prompt_8gram")])
        self.assertEqual(rep["local_inputs"], 1)

    def test_python_source_is_exempt(self):
        d = self.local_dir()
        self.commit("tpl", {"evaluation/tpl.py": f'T = "{PROMPT}"\n', "x/a.rs": f"// {PROMPT}\n",
                            "x/b.mjs": f"// {PROMPT}\n"})
        rc, rep, _ = self.run_check("--local-inputs", d)
        self.assertEqual((rc, rep["violations"]), (0, []))

    def test_markdown_and_tex_fail(self):
        d = self.local_dir()
        self.commit("m", {"docs/research/n.md": f"intro\n{PROMPT}\n", "paper/main.tex": f"a\n{PROMPT}\n"})
        rc, rep, _ = self.run_check("--local-inputs", d)
        self.assertEqual(rc, 1)
        self.assertEqual(self.rules(rep), [("docs/research/n.md", "prompt_8gram"),
                                           ("paper/main.tex", "prompt_8gram")])

    def test_old_line_passes_new_line_fails(self):
        d = self.local_dir()
        self.commit("old", {"docs/n.md": f"{PROMPT}\nplain\n"})
        base = self.git("rev-parse", "HEAD")
        self.commit("edit", {"docs/n.md": f"{PROMPT}\nplain\nextra harmless line\n"})
        rc, rep, _ = self.run_check("--local-inputs", d, base=base)
        self.assertEqual((rc, rep["violations"]), (0, []))
        self.commit("edit2", {"docs/n.md": f"{PROMPT}\nplain\nextra harmless line\n{PROMPT}\n"})
        rc, rep, _ = self.run_check("--local-inputs", d, base=base)
        self.assertEqual(rc, 1)
        self.assertEqual([(v["rule"], v["line"]) for v in rep["violations"]], [("prompt_8gram", 4)])

    def test_wrapped_prompt_over_three_lines_fails(self):
        d = self.local_dir()
        words = PROMPT.split()
        wrapped = "\n".join([" ".join(words[:4]), " ".join(words[4:8]), " ".join(words[8:])])
        self.commit("w", {"docs/w.md": "keep\n"})
        base = self.git("rev-parse", "HEAD")
        self.commit("w2", {"docs/w.md": "keep\n" + wrapped + "\n"})
        rc, rep, _ = self.run_check("--local-inputs", d, base=base)
        self.assertEqual(rc, 1)
        self.assertEqual({r for r in self.rules(rep)}, {("docs/w.md", "prompt_8gram")})

    def test_default_scan_root_override(self):
        root = os.path.join(self.tmp, "root")
        self.local_dir("root/s13a/raw")
        self.commit("rec", {"docs/n.md": PROMPT + "\n"})
        rc, rep, _ = self.run_check(root=root)
        self.assertEqual(rc, 1)
        self.assertEqual(rep["local_inputs"], 1)
        self.assertEqual(self.rules(rep), [("docs/n.md", "prompt_8gram")])

    def test_default_glob_finds_seven_directories_and_ignores_lock(self):
        root = os.path.join(self.tmp, "root")
        subdirs = ["s13a/raw", "s13a/packet", "s13a/returned", "s13b/pilot", "s13b/run", "s13e", "s13f"]
        prompts = []
        for i, sub in enumerate(subdirs):
            p = f"zq{i} alpha{i} bravo{i} charlie{i} delta{i} echo{i} foxtrot{i} golf{i} hotel{i}"
            prompts.append(p)
            self.local_dir(f"root/{sub}", prompt=p)
        # s13a/raw etc. are nested; the default glob matches the s13* top-level dirs.
        with open(os.path.join(root, "s13-host.lock"), "w") as fh:
            fh.write("13e 1234\n")
        self.commit("all", {"docs/all.md": "\n".join(prompts) + "\n"})
        rc, rep, _ = self.run_check(root=root)
        self.assertEqual(rc, 1)
        # Top-level s13* directories: s13a, s13b, s13e, s13f (the lock file is not a directory).
        self.assertEqual(rep["local_inputs"], 4)
        self.assertEqual(len(rep["violations"]), 7)

    def test_default_glob_matches_each_s13_directory_at_root(self):
        root = os.path.join(self.tmp, "root")
        names = ["s13a", "s13b", "s13e", "s13f"]
        for n in names:
            self.local_dir(f"root/{n}", prompt=f"{n} one two three four five six seven eight nine ten")
        with open(os.path.join(root, "s13-host.lock"), "w") as fh:
            fh.write("x\n")
        self.local_dir("root/other", prompt=PROMPT)
        self.commit("c", {"docs/c.md": PROMPT + "\n"})
        rc, rep, _ = self.run_check(root=root)
        self.assertEqual((rc, rep["local_inputs"]), (0, 4))

    def test_no_local_inputs(self):
        self.commit("c", {"docs/c.md": PROMPT + "\n"})
        rc, rep, _ = self.run_check()
        self.assertEqual((rc, rep["local_inputs"], rep["violations"]), (0, 0, []))
        rc, rep, err = self.run_check("--require-local-inputs")
        self.assertEqual(rc, 2)
        self.assertEqual(rep["local_inputs"], 0)

    def test_require_local_inputs_satisfied(self):
        d = self.local_dir()
        self.commit("c", {"docs/c.md": "harmless\n"})
        rc, rep, _ = self.run_check("--local-inputs", d, "--require-local-inputs")
        self.assertEqual((rc, rep["local_inputs"]), (0, 1))


class AllowlistTests(Fixture):
    def test_pin_match_exempts_8gram_and_mismatch_fails(self):
        d = self.local_dir()
        body = f"brief\n{PROMPT}\n"
        pins = {BRIEF: sha(body)}
        self.commit("pin", {BRIEF: body, ALLOWLIST: json.dumps(pins)})
        rc, rep, _ = self.run_check("--local-inputs", d)
        self.assertEqual((rc, rep["violations"]), (0, []))
        self.commit("drift", {BRIEF: body + "more\n"})
        rc, rep, _ = self.run_check("--local-inputs", d)
        self.assertEqual(rc, 1)
        self.assertIn((BRIEF, "allowlist_pin"), self.rules(rep))

    def test_pin_is_read_from_range_tip_not_base(self):
        d = self.local_dir()
        self.commit("file first", {BRIEF: "old brief\n"})
        base = self.git("rev-parse", "HEAD")
        new = f"new brief\n{PROMPT}\n"
        self.commit("change and pin", {BRIEF: new, ALLOWLIST: json.dumps({BRIEF: sha(new)})})
        rc, rep, _ = self.run_check("--local-inputs", d, base=base)
        self.assertEqual((rc, rep["violations"]), (0, []))

    def test_missing_allowlist_counts_as_empty(self):
        self.commit("c", {"docs/c.md": "x\n"})
        rc, rep, _ = self.run_check("--stage", "13b-1")
        self.assertEqual((rc, rep["violations"]), (0, []))

    def test_pin_scope(self):
        body = "guideline text\n"
        self.commit("guide", {GUIDE: body, ALLOWLIST: json.dumps({GUIDE: sha(body)})})
        rc, rep, _ = self.run_check("--stage", "13b-1")
        self.assertEqual(rc, 1)
        self.assertEqual(self.rules(rep), [(GUIDE, "pin_scope")])
        rc, rep, _ = self.run_check()
        self.assertEqual((rc, rep["violations"]), (0, []))
        rc, rep, _ = self.run_check("--stage", "13a-1")
        self.assertEqual((rc, rep["violations"]), (0, []))
        rc, rep, _ = self.run_check("--stage", "13-H")
        self.assertEqual(rc, 1)

    def test_scope_allows_own_pin_only(self):
        tbody = "TEMPLATES = []\n"
        gbody = "g\n"
        self.commit("pins", {TRANSFORMS: tbody, GUIDE: gbody,
                             ALLOWLIST: json.dumps({TRANSFORMS: sha(tbody), GUIDE: sha(gbody)})})
        rc, rep, _ = self.run_check("--stage", "13b-1")
        self.assertEqual(self.rules(rep), [(GUIDE, "pin_scope")])

    def test_unchanged_pin_is_not_a_scope_violation(self):
        body = "g\n"
        self.commit("pins", {GUIDE: body, ALLOWLIST: json.dumps({GUIDE: sha(body)})})
        base = self.git("rev-parse", "HEAD")
        self.commit("other", {"docs/o.md": "o\n"})
        rc, rep, _ = self.run_check("--stage", "13c-1", base=base)
        self.assertEqual((rc, rep["violations"]), (0, []))

    def test_unknown_stage_exits_2(self):
        rc, rep, err = self.run_check("--stage", "13z-9")
        self.assertEqual(rc, 2)
        self.assertIn("unknown stage", err)

    def test_bad_range_exits_2(self):
        env = dict(os.environ, S13_LOCAL_INPUTS_ROOT=self.empty_root)
        proc = subprocess.run([sys.executable, SCRIPT, "--repo", self.repo, "--range", "nope..HEAD"],
                              capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 2)


ACCENTED = ("the café committee reviewed naïve résumé drafts "
            "before the quarterly lantern festival")


class HardeningTests(Fixture):
    def expect(self, rc, rules, *extra, base=None, root=None):
        got_rc, rep, _ = self.run_check(*extra, base=base, root=root)
        self.assertEqual((got_rc, self.rules(rep)), (rc, rules))

    def test_utf16_markdown_fails(self):
        d = self.local_dir()
        self.commit("u16", {"docs/u.md": ("intro\n" + PROMPT + "\n").encode("utf-16")})
        self.expect(1, [("docs/u.md", "prompt_8gram")], "--local-inputs", d)

    def test_modified_utf16_markdown_fails(self):
        d = self.local_dir()
        self.commit("u16", {"docs/u.md": "intro\n".encode("utf-16")})
        base = self.git("rev-parse", "HEAD")
        self.commit("u16b", {"docs/u.md": ("intro\n" + PROMPT + "\n").encode("utf-16")})
        self.expect(1, [("docs/u.md", "prompt_8gram")], "--local-inputs", d, base=base)

    def test_trailing_nul_fails(self):
        d = self.local_dir()
        self.commit("nul", {"docs/n.md": (PROMPT + "\n").encode() + bytes([0])})
        self.expect(1, [("docs/n.md", "prompt_8gram")], "--local-inputs", d)

    def test_key_marker_with_nul_fails(self):
        marker = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
        self.commit("k", {"k/a.txt": marker.encode() + bytes([0, 1]) + b"\n"})
        self.expect(1, [("k/a.txt", "key_pattern")])

    def test_diff_attribute_cannot_hide_hunks(self):
        d = self.local_dir()
        self.commit("attr", {".gitattributes": "*.md -diff\n", "docs/h.md": "plain\n"})
        base = self.git("rev-parse", "HEAD")
        self.commit("edit", {"docs/h.md": "plain\n" + PROMPT + "\n"})
        self.expect(1, [("docs/h.md", "prompt_8gram")], "--local-inputs", d, base=base)

    def test_utf16_local_input_contributes(self):
        d = os.path.join(self.tmp, "inputs16", "s13a")
        os.makedirs(d)
        with open(os.path.join(d, "items.jsonl"), "wb") as fh:
            fh.write((json.dumps({"c": PROMPT}) + "\n").encode("utf-16"))
        self.commit("c", {"docs/c.md": PROMPT + "\n"})
        self.expect(1, [("docs/c.md", "prompt_8gram")], "--local-inputs", d)

    def test_json_unicode_escapes_caught(self):
        d = self.local_dir(prompt=ACCENTED)
        text = json.dumps({"id": 1, "label": ACCENTED})  # ensure_ascii writes é
        self.assertIn("\\u00e9", text)
        self.commit("rec", {"rec.json": text})
        self.expect(1, [("rec.json", "prompt_8gram")], "--local-inputs", d)

    def test_nfd_prompt_caught(self):
        import unicodedata
        d = self.local_dir(prompt=ACCENTED)
        self.commit("nfd", {"docs/n.md": unicodedata.normalize("NFD", ACCENTED) + "\n"})
        self.expect(1, [("docs/n.md", "prompt_8gram")], "--local-inputs", d)

    def test_html_entity_prompt_caught(self):
        d = self.local_dir()
        self.commit("nb", {"docs/e.md": PROMPT.replace(" ", "&nbsp;") + "\n"})
        self.expect(1, [("docs/e.md", "prompt_8gram")], "--local-inputs", d)

    def test_bom_pretty_json_text_field(self):
        body = b"\xef\xbb\xbf" + json.dumps({"rows": [{"id": 1, "text": "x"}]}, indent=2).encode()
        self.commit("j", {"d/b.json": body})
        self.expect(1, [("d/b.json", "forbidden_field")])

    def test_invalid_json_fallback_field(self):
        self.commit("j", {"d/bad.json": '{"id": 1, "text" : "x",\n'})
        self.expect(1, [("d/bad.json", "forbidden_field")])

    def test_bom_csv_and_semicolon_header(self):
        self.commit("c1", {"d/a.csv": b"\xef\xbb\xbftext,id\n1,a\n", "d/b.csv": "text;id\n1;a\n"})
        self.expect(1, [("d/a.csv", "forbidden_field"), ("d/b.csv", "forbidden_field")])

    def test_output_dirs_not_ignored(self):
        self.commit("rm", {".gitignore": "other/\n"})
        rc, rep, _ = self.run_check()
        self.assertEqual(rc, 1)
        self.assertEqual({v["rule"] for v in rep["violations"]}, {"output_not_ignored"})
        self.assertEqual(len(rep["violations"]), 7)

    def test_empty_input_dir_with_require_exits_2(self):
        root = os.path.join(self.tmp, "root")
        os.makedirs(os.path.join(root, "s13a"))
        self.commit("c", {"docs/c.md": "x\n"})
        rc, rep, _ = self.run_check("--require-local-inputs", root=root)
        self.assertEqual((rc, rep["local_inputs"], rep["local_grams"]), (2, 1, 0))

    def test_prompt_added_then_removed_in_range(self):
        d = self.local_dir()
        self.commit("add", {"docs/tmp.md": PROMPT + "\n"})
        self.git("rm", "-q", "docs/tmp.md")
        self.git("commit", "-q", "-m", "remove")
        self.expect(1, [("docs/tmp.md", "prompt_8gram")], "--local-inputs", d)

    def test_glob_star_does_not_cross_slash(self):
        path = "docs/research/sub/annotation-guideline-v2-1.md"
        self.commit("p", {path: "g\n", ALLOWLIST: json.dumps({path: sha("g\n")})})
        self.expect(1, [(path, "pin_scope")], "--stage", "13a-1")

    def test_triple_dot_range(self):
        self.commit("c", {"d/t.json": json.dumps({"text": 1})})
        env = dict(os.environ, S13_LOCAL_INPUTS_ROOT=self.empty_root)
        proc = subprocess.run([sys.executable, SCRIPT, "--repo", self.repo, "--range",
                               f"{self.base}...HEAD"], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 1)


if __name__ == "__main__":
    unittest.main()
