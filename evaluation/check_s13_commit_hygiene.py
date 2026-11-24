#!/usr/bin/env python3
"""Stage 13-H commit-hygiene check (S13-G8).

Usage:
    check_s13_commit_hygiene.py --repo <path> --range <a..b>
        [--local-inputs <dir>...] [--require-local-inputs] [--stage <id>]

Scans what a git range adds for forbidden material: prompt-bearing field names,
8-grams of local prompt inputs, model weights, private keys and committed
prompt-output paths. Uses only the standard library and imports nothing from the
target repository.

Exit codes: 0 clean, 1 violations, 2 usage or configuration error (including an
unknown stage id, or --require-local-inputs with no local inputs). When both a
violation and an unmet --require-local-inputs occur, 2 wins.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import glob
import hashlib
import io
import json
import os
import re
import subprocess
import sys

DEFAULT_LOCAL_ROOT = "D:/Git Repositories/Privoke-Research-Project/evaluation/results"
ALLOWLIST_PATH = "evaluation/s13_allowlist.json"
NGRAM = 8
FORBIDDEN_FIELDS = {"text", "prompt", "body", "notes"}
SOURCE_SUFFIXES = (".py", ".rs", ".mjs")
WEIGHT_SUFFIXES = (".safetensors", ".onnx", ".bin", ".pt", ".pth")
KEY_RE = re.compile(r"BEGIN (EC |RSA |OPENSSH |ENCRYPTED |)PRIVATE KEY")
HEX64_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
KEY_CONTEXT_RE = re.compile(r"seed|secret|private", re.IGNORECASE)
TOKEN_RE = re.compile(r"[^\W_]+")
ESCAPE_RE = re.compile(r"\\[ntr]")
PROMPT_PATH_RE = re.compile(r"(^|/)results/s13[^/]*/")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

# Pin paths (fnmatch patterns) each stage may add or change.
GUIDELINE_PINS = [
    "docs/research/s13a-writer-brief-*.md",
    "docs/research/annotation-guideline-v2-*.md",
]
STAGE_PIN_SCOPES: dict[str, list[str]] = {
    "13a-1": GUIDELINE_PINS,
    "13b-1": ["evaluation/e2e_evasion_transforms.py"],
}
for _stage in (
    "13-H", "13a-0", "13a-3", "13a-5", "13b-2", "13b-3", "13c-1", "13c-2",
    "13d-1", "13d-1a", "13d-1b", "13d-2", "13e", "13f-1", "13f-2", "13-P",
):
    STAGE_PIN_SCOPES.setdefault(_stage, [])


class UsageError(Exception):
    pass


def git(repo: str, *args: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", repo, "-c", "core.quotepath=off", *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise UsageError(f"git {' '.join(args)} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def tokens_of(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


def grams_of(tokens: list[str]):
    for i in range(len(tokens) - NGRAM + 1):
        yield i, hash(tuple(tokens[i:i + NGRAM]))


# ---------------------------------------------------------------- local inputs

def _strings(node, out: list[str]) -> None:
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _strings(v, out)


def prompt_strings(path: str) -> list[str]:
    """Texts of one local input file: every string value of JSON, every CSV cell, else the whole text."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if b"\0" in raw:
        return []
    text = raw.decode("utf-8", errors="replace")
    suffix = os.path.splitext(path)[1].lower()
    out: list[str] = []
    if suffix in (".json", ".jsonl"):
        try:
            _strings(json.loads(text), out)
            return out
        except ValueError:
            pass
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                _strings(json.loads(line), out)
            except ValueError:
                out.append(line)
        return out
    if suffix == ".csv":
        for row in csv.reader(io.StringIO(text)):
            out.extend(row)
        return out
    return [text]


def build_gram_set(dirs: list[str]) -> set[int]:
    grams: set[int] = set()
    for root in dirs:
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                for s in prompt_strings(os.path.join(dirpath, name)):
                    grams.update(h for _, h in grams_of(tokens_of(s)))
    return grams


def resolve_local_inputs(explicit: list[str] | None) -> list[str]:
    if explicit:
        missing = [d for d in explicit if not os.path.isdir(d)]
        if missing:
            raise UsageError(f"--local-inputs is not a directory: {missing[0]}")
        return list(explicit)
    root = os.environ.get("S13_LOCAL_INPUTS_ROOT") or DEFAULT_LOCAL_ROOT
    return sorted(p for p in glob.glob(os.path.join(root, "s13*")) if os.path.isdir(p))


# ------------------------------------------------------------------- git views

def split_range(rng: str) -> tuple[str, str]:
    if ".." not in rng:
        raise UsageError("--range must look like <a>..<b>")
    a, _, b = rng.partition("..")
    return a or "HEAD", b.lstrip(".") or "HEAD"


def show(repo: str, rev: str, path: str) -> bytes | None:
    proc = subprocess.run(
        ["git", "-C", repo, "show", f"{rev}:{path}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc.stdout if proc.returncode == 0 else None


def names(repo: str, rng: str, filt: str) -> list[str]:
    out = git(repo, "diff", "--name-only", "--no-renames", f"--diff-filter={filt}", "-z", rng)
    return [n.decode("utf-8", errors="replace") for n in out.split(b"\0") if n]


def added_lines_of_diff(repo: str, rng: str, path: str) -> list[list[tuple[int, str]]]:
    """Added (lineno, text) lines of `git diff -U0`, grouped per hunk."""
    out = git(repo, "diff", "-U0", "--no-renames", "--no-color", "--no-ext-diff", rng, "--", path)
    hunks: list[list[tuple[int, str]]] = []
    cur: list[tuple[int, str]] | None = None
    lineno = 0
    for raw in out.decode("utf-8", errors="replace").split("\n"):
        m = HUNK_RE.match(raw)
        if m:
            cur = []
            hunks.append(cur)
            lineno = int(m.group(1))
        elif cur is not None and raw.startswith("+"):
            cur.append((lineno, raw[1:].rstrip("\r")))
            lineno += 1
    return [h for h in hunks if h]


def read_allowlist(repo: str, rev: str) -> tuple[dict[str, str], str | None]:
    blob = show(repo, rev, ALLOWLIST_PATH)
    if blob is None:
        return {}, None
    try:
        data = json.loads(blob.decode("utf-8"))
        if not isinstance(data, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in data.items()
        ):
            raise ValueError("not a {path: sha256} object")
        return {k.replace("\\", "/"): v.lower() for k, v in data.items()}, None
    except ValueError as exc:
        return {}, str(exc)


# ----------------------------------------------------------------------- rules

def forbidden_fields(path: str, text: str) -> list[int]:
    """Line numbers where a forbidden field or column appears (0 if unknown)."""
    suffix = os.path.splitext(path)[1].lower()

    def walk_keys(node, found: set[str]) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and k.lower() in FORBIDDEN_FIELDS:
                    found.add(k)
                walk_keys(v, found)
        elif isinstance(node, list):
            for v in node:
                walk_keys(v, found)

    if suffix == ".csv":
        header = next(csv.reader(io.StringIO(text)), [])
        return [1] if any(c.strip().lower() in FORBIDDEN_FIELDS for c in header) else []
    lines = text.splitlines()
    found: set[str] = set()
    try:
        walk_keys(json.loads(text), found)
    except ValueError:
        hits: list[int] = []
        for i, ln in enumerate(lines, 1):
            if not ln.strip():
                continue
            try:
                f: set[str] = set()
                walk_keys(json.loads(ln), f)
            except ValueError:
                continue
            if f:
                hits.append(i)
        return hits
    result: list[int] = []
    for key in sorted(found):
        needle = json.dumps(key)
        result.append(next((i for i, ln in enumerate(lines, 1) if needle in ln), 0))
    return result


def scan_lines(path: str, lines: list[tuple[int, str]], grams: set[int] | None,
               violations: list[dict]) -> None:
    """Key rules on every line; 8-gram rule on the joined lines when grams is given."""
    for no, line in lines:
        if KEY_RE.search(line) or (HEX64_RE.search(line) and KEY_CONTEXT_RE.search(line)):
            violations.append({"file": path, "rule": "key_pattern", "line": no})
    if not grams:
        return
    toks: list[str] = []
    owner: list[int] = []
    for no, line in lines:
        t = tokens_of(ESCAPE_RE.sub(" ", line))
        toks.extend(t)
        owner.extend([no] * len(t))
    hit_lines = {owner[i] for i, h in grams_of(toks) if h in grams}
    for no in sorted(hit_lines):
        violations.append({"file": path, "rule": "prompt_8gram", "line": no})


def check(repo: str, rng: str, local_dirs: list[str], stage: str | None) -> dict:
    base, tip = split_range(rng)
    changed = names(repo, rng, "ACMRT")
    added = set(names(repo, rng, "A"))
    violations: list[dict] = []

    grams = build_gram_set(local_dirs) if local_dirs else set()
    pins_tip, bad = read_allowlist(repo, tip)
    if bad:
        violations.append({"file": ALLOWLIST_PATH, "rule": "allowlist_format", "line": 0})
    pins_base, _ = read_allowlist(repo, base)

    if stage is not None:
        scope = STAGE_PIN_SCOPES[stage]
        for p in sorted(set(pins_tip) | set(pins_base)):
            if pins_tip.get(p) != pins_base.get(p) and not any(fnmatch.fnmatchcase(p, pat) for pat in scope):
                violations.append({"file": p, "rule": "pin_scope", "line": 0})

    for path in changed:
        norm = path.replace("\\", "/")
        lower = norm.lower()
        if PROMPT_PATH_RE.search(norm):
            violations.append({"file": path, "rule": "prompt_output_path", "line": 0})
        if path in added and lower.endswith(WEIGHT_SUFFIXES):
            violations.append({"file": path, "rule": "weight_file", "line": 0})
            continue
        blob = show(repo, tip, path)
        if blob is None or b"\0" in blob:
            continue
        text = blob.decode("utf-8", errors="replace")

        pinned_ok = False
        pin = pins_tip.get(norm)
        if pin is not None:
            if hashlib.sha256(blob).hexdigest() == pin:
                pinned_ok = True
            else:
                violations.append({"file": path, "rule": "allowlist_pin", "line": 0})

        if lower.endswith((".json", ".jsonl", ".csv")):
            for no in forbidden_fields(path, text):
                violations.append({"file": path, "rule": "forbidden_field", "line": no})

        use_grams = None if (lower.endswith(SOURCE_SUFFIXES) or pinned_ok) else grams
        if path in added:
            scan_lines(path, [(i, ln.rstrip("\r")) for i, ln in enumerate(text.split("\n"), 1)],
                       use_grams, violations)
        else:
            for hunk in added_lines_of_diff(repo, rng, path):
                scan_lines(path, hunk, use_grams, violations)

    unique = {(v["file"], v["rule"], v["line"]): v for v in violations}
    return {
        "range": rng,
        "stage": stage,
        "files_checked": len(changed),
        "local_inputs": len(local_dirs),
        "violations": [unique[k] for k in sorted(unique)],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stage 13-H commit-hygiene check (S13-G8).")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--range", required=True, dest="rng")
    ap.add_argument("--local-inputs", nargs="*", default=None)
    ap.add_argument("--require-local-inputs", action="store_true")
    ap.add_argument("--stage")
    args = ap.parse_args(argv)
    try:
        if args.stage is not None and args.stage not in STAGE_PIN_SCOPES:
            raise UsageError(f"unknown stage id: {args.stage}")
        dirs = resolve_local_inputs(args.local_inputs)
        report = check(args.repo, args.rng, dirs, args.stage)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    if args.require_local_inputs and report["local_inputs"] == 0:
        print("error: --require-local-inputs set but no local inputs found", file=sys.stderr)
        return 2
    return 1 if report["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
