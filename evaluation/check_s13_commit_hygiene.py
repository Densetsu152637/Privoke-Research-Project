#!/usr/bin/env python3
"""Stage 13-H commit-hygiene check (S13-G8).

Usage:
    check_s13_commit_hygiene.py --repo <path> --range <a..b | a...b>
        [--local-inputs <dir>...] [--require-local-inputs] [--stage <id>]

Scans what a git range adds for forbidden material: prompt-bearing field names,
8-grams of local prompt inputs, model weights, private keys and committed
prompt-output paths. Both the net two-point diff and every commit of the range
are scanned, so content added and later removed inside the range is still
reported. Uses only the standard library and imports nothing from the target
repository.

Exit codes: 0 clean, 1 violations, 2 usage or configuration error (including an
unknown stage id, an unreadable changed file, an unexpected exception, or
--require-local-inputs with no local prompt 8-grams). When both a violation and
an unmet --require-local-inputs occur, 2 wins.
"""
from __future__ import annotations

import argparse
import codecs
import csv
import glob
import hashlib
import html
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata

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
UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4})+")
FIELD_FALLBACK_RE = re.compile(r'"(text|prompt|body|notes)"\s*:', re.IGNORECASE)
HEADER_SPLIT_RE = re.compile(r"[,;\t|]")
PROMPT_PATH_RE = re.compile(r"(^|/)results/s13[^/]*/")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# Output directories of the Shared conventions; each probe must be Git-ignored.
OUTPUT_PROBES = [
    f"evaluation/results/{d}/probe.txt"
    for d in ("s13a/raw", "s13a/packet", "s13a/returned", "s13b/pilot", "s13b/run", "s13e", "s13f")
]

# Pin paths (glob patterns; `*` does not cross `/`) each stage may add or change.
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


def glob_match(path: str, pattern: str) -> bool:
    rx = "".join("[^/]*" if c == "*" else re.escape(c) for c in pattern)
    return re.fullmatch(rx, path) is not None


def git(repo: str, *args: str) -> bytes:
    proc = subprocess.run(
        ["git", "-C", repo, "-c", "core.quotepath=off", *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise UsageError(f"git {' '.join(args)} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


# ------------------------------------------------------- decoding, normalising

def is_utf16(raw: bytes) -> bool:
    return raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE)


def decode_bytes(raw: bytes) -> str:
    """BOM-aware decode; NUL bytes become spaces so they cannot hide text."""
    if is_utf16(raw):
        text = raw.decode("utf-16", errors="replace")
    elif raw.startswith(codecs.BOM_UTF8):
        text = raw.decode("utf-8-sig", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    return text.replace("\0", " ").lstrip("\ufeff")


def _unescape_unicode(match: re.Match) -> str:
    try:
        return json.loads('"' + match.group(0) + '"')
    except ValueError:
        return match.group(0)


def normalise(s: str, unescape_unicode: bool = False) -> str:
    if unescape_unicode:
        s = UNICODE_ESCAPE_RE.sub(_unescape_unicode, s)
    s = html.unescape(s)
    s = ESCAPE_RE.sub(" ", s)
    return unicodedata.normalize("NFKC", s).casefold()


def tokens_of(s: str, unescape_unicode: bool = False) -> list[str]:
    return TOKEN_RE.findall(normalise(s, unescape_unicode))


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
        text = decode_bytes(fh.read())
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

def split_range(repo: str, rng: str) -> tuple[str, str]:
    """Return (base, tip). For a...b the base is the merge-base."""
    if "..." in rng:
        a, _, b = rng.partition("...")
        a, b = a or "HEAD", b or "HEAD"
        base = git(repo, "merge-base", a, b).decode().strip()
    elif ".." in rng:
        a, _, b = rng.partition("..")
        base, b = a or "HEAD", b or "HEAD"
    else:
        raise UsageError("--range must look like <a>..<b>")
    return base, b


def show(repo: str, rev: str, path: str) -> bytes | None:
    proc = subprocess.run(
        ["git", "-C", repo, "show", f"{rev}:{path}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc.stdout if proc.returncode == 0 else None


def names(repo: str, old: str, new: str, filt: str) -> list[str]:
    out = git(repo, "diff", "--name-only", "--no-renames", f"--diff-filter={filt}", "-z", old, new)
    return [n.decode("utf-8", errors="replace") for n in out.split(b"\0") if n]


def added_lines_of_diff(repo: str, old: str, new: str, path: str) -> list[list[tuple[int, str]]]:
    """Added (lineno, text) lines of `git diff -U0`, grouped per hunk."""
    out = git(repo, "diff", "-U0", "--text", "--no-textconv", "--no-renames", "--no-color",
              "--no-ext-diff", old, new, "--", f":(literal){path}")
    hunks: list[list[tuple[int, str]]] = []
    cur: list[tuple[int, str]] | None = None
    lineno = 0
    for raw in decode_bytes(out).split("\n"):
        m = HUNK_RE.match(raw)
        if m:
            cur = []
            hunks.append(cur)
            lineno = int(m.group(1))
        elif cur is not None and raw.startswith("+"):
            cur.append((lineno, raw[1:].rstrip("\r")))
            lineno += 1
    return [h for h in hunks if h]


def text_variants(raw: bytes) -> list[str]:
    """Primary decoding first. A file with any NUL byte and no BOM adds UTF-16 LE/BE and NUL-stripped readings."""
    out = [decode_bytes(raw)]
    if raw and not is_utf16(raw) and b"\0" in raw:
        for offset in (0, 1):  # both byte alignments, in case odd-length padding precedes the text
            chunk = raw[offset:len(raw) - ((len(raw) - offset) % 2)]
            out.append(chunk.decode("utf-16-le", errors="replace").replace("\0", " "))
            out.append(chunk.decode("utf-16-be", errors="replace").replace("\0", " "))
        out.append(raw.replace(b"\0", b"").decode("utf-8", errors="replace"))
    return out


def added_lines_by_set(old_blob: bytes | None, new_text: str) -> list[list[tuple[int, str]]]:
    """Fallback for NUL-heavy files, whose diff output is not line-readable: lines absent from the old text."""
    old: set[str] = set()
    if old_blob is not None:
        for t in text_variants(old_blob):
            old.update(ln.rstrip("\r") for ln in t.split("\n"))
    group: list[tuple[int, str]] = []
    groups: list[list[tuple[int, str]]] = []
    for no, line in enumerate(new_text.split("\n"), 1):
        line = line.rstrip("\r")
        if line not in old:
            group.append((no, line))
        elif group:
            groups.append(group)
            group = []
    if group:
        groups.append(group)
    return groups


def read_allowlist(repo: str, rev: str) -> tuple[dict[str, str], str | None]:
    blob = show(repo, rev, ALLOWLIST_PATH)
    if blob is None:
        return {}, None
    try:
        data = json.loads(decode_bytes(blob))
        if not isinstance(data, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in data.items()
        ):
            raise ValueError("not a {path: sha256} object")
        return {k.replace("\\", "/"): v.lower() for k, v in data.items()}, None
    except ValueError as exc:
        return {}, str(exc)


def not_ignored_probes(repo: str, tip: str) -> list[str]:
    """Probe output paths that the .gitignore files of the range tip do not ignore."""
    listing = git(repo, "ls-tree", "-r", "--name-only", "-z", tip)
    ignores = [p.decode("utf-8", errors="replace") for p in listing.split(b"\0")
               if p and p.split(b"/")[-1] == b".gitignore"]
    with tempfile.TemporaryDirectory(prefix="s13h-ignore-") as tmp:
        subprocess.run(["git", "-C", tmp, "init", "-q"], check=True, stdout=subprocess.DEVNULL)
        os.makedirs(os.path.join(tmp, ".git", "info"), exist_ok=True)
        with open(os.path.join(tmp, ".git", "info", "exclude"), "w") as fh:
            fh.write("")
        for rel in ignores:
            blob = show(repo, tip, rel)
            if blob is None:
                continue
            dest = os.path.join(tmp, *rel.split("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(blob)
        missing = []
        for probe in OUTPUT_PROBES:
            rc = subprocess.run(["git", "-C", tmp, "-c", "core.excludesFile=", "check-ignore", "-q", "--", probe],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
            if rc != 0:
                missing.append(probe)
        return missing


# ----------------------------------------------------------------------- rules

def forbidden_fields(path: str, text: str) -> list[int]:
    """Line numbers where a forbidden field or column appears (0 if unknown)."""
    suffix = os.path.splitext(path)[1].lower()

    def walk_keys(node, found: set[str]) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and k.strip().lower() in FORBIDDEN_FIELDS:
                    found.add(k)
                walk_keys(v, found)
        elif isinstance(node, list):
            for v in node:
                walk_keys(v, found)

    lines = text.splitlines()
    if suffix == ".csv":
        header = next((ln.lstrip("\ufeff") for ln in lines if ln.lstrip("\ufeff").strip()), "")
        cols = [c.strip().strip("\"'").strip().lower() for c in HEADER_SPLIT_RE.split(header)]
        return [1] if any(c in FORBIDDEN_FIELDS for c in cols) else []
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
                if f:
                    hits.append(i)
            except ValueError:
                if FIELD_FALLBACK_RE.search(ln):
                    hits.append(i)
        return hits
    result: list[int] = []
    for key in sorted(found):
        needle = json.dumps(key)
        result.append(next((i for i, ln in enumerate(lines, 1) if needle in ln), 0))
    return result


def scan_lines(path: str, lines: list[tuple[int, str]], grams: set[int] | None,
               json_like: bool, violations: list[dict]) -> None:
    """Key rules on every line; 8-gram rule on the joined lines when grams is given."""
    for no, line in lines:
        if KEY_RE.search(line) or (HEX64_RE.search(line) and KEY_CONTEXT_RE.search(line)):
            violations.append({"file": path, "rule": "key_pattern", "line": no})
    if not grams:
        return
    toks: list[str] = []
    owner: list[int] = []
    for no, line in lines:
        t = tokens_of(line, json_like)
        toks.extend(t)
        owner.extend([no] * len(t))
    for no in sorted({owner[i] for i, h in grams_of(toks) if h in grams}):
        violations.append({"file": path, "rule": "prompt_8gram", "line": no})


def scan_pass(repo: str, old: str, new: str, grams: set[int], pins_new: dict[str, str],
              pins_extra: dict[str, str], final: bool, violations: list[dict]) -> int:
    """Scan the change old -> new. Returns the number of changed files."""
    changed = names(repo, old, new, "ACMRT")
    added = set(names(repo, old, new, "A"))
    for path in changed:
        norm = path.replace("\\", "/")
        lower = norm.lower()
        if PROMPT_PATH_RE.search(norm):
            violations.append({"file": path, "rule": "prompt_output_path", "line": 0})
        if path in added and lower.endswith(WEIGHT_SUFFIXES):
            violations.append({"file": path, "rule": "weight_file", "line": 0})
            continue
        blob = show(repo, new, path)
        if blob is None:
            raise UsageError(f"cannot read changed file {path} at {new}")
        variants = text_variants(blob)

        pinned_ok = False
        digest = hashlib.sha256(blob).hexdigest()
        pin = pins_new.get(norm)
        if pin is not None:
            pinned_ok = digest == pin
            if not pinned_ok and final:
                violations.append({"file": path, "rule": "allowlist_pin", "line": 0})
        if not pinned_ok and pins_extra.get(norm) == digest:
            pinned_ok = True

        json_like = lower.endswith((".json", ".jsonl"))
        if json_like or lower.endswith(".csv"):
            for text in variants:
                for no in forbidden_fields(path, text):
                    violations.append({"file": path, "rule": "forbidden_field", "line": no})

        use_grams = None if (lower.endswith(SOURCE_SUFFIXES) or pinned_ok) else grams
        if path in added:
            for text in variants:
                scan_lines(path, [(i, ln.rstrip("\r")) for i, ln in enumerate(text.split("\n"), 1)],
                           use_grams, json_like, violations)
        elif is_utf16(blob) or len(variants) > 1:
            old_blob = show(repo, old, path)
            for text in variants:
                for hunk in added_lines_by_set(old_blob, text):
                    scan_lines(path, hunk, use_grams, json_like, violations)
        else:
            for hunk in added_lines_of_diff(repo, old, new, path):
                scan_lines(path, hunk, use_grams, json_like, violations)
    return len(changed)


def check(repo: str, rng: str, gram_set: set[int], n_dirs: int, stage: str | None) -> dict:
    base, tip = split_range(repo, rng)
    violations: list[dict] = []

    pins_tip, bad = read_allowlist(repo, tip)
    if bad:
        violations.append({"file": ALLOWLIST_PATH, "rule": "allowlist_format", "line": 0})
    pins_base, _ = read_allowlist(repo, base)

    def pin_scope(before: dict[str, str], after: dict[str, str]) -> None:
        if stage is None:
            return
        scope = STAGE_PIN_SCOPES[stage]
        for p in sorted(set(before) | set(after)):
            if after.get(p) != before.get(p) and not any(glob_match(p, pat) for pat in scope):
                violations.append({"file": p, "rule": "pin_scope", "line": 0})

    pin_scope(pins_base, pins_tip)

    files_checked = scan_pass(repo, base, tip, gram_set, pins_tip, {}, True, violations)

    # Every commit of the range, so content added and later removed is still seen.
    commits = [c for c in git(repo, "rev-list", "--reverse", f"{base}..{tip}").decode().split() if c]
    for c in commits:
        parent = subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "-q", f"{c}^"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        old = parent.stdout.decode().strip() if parent.returncode == 0 else EMPTY_TREE
        # Pins edited inside the range are checked per commit, but only the base and tip pins are trusted.
        pins_old = read_allowlist(repo, old)[0] if old != EMPTY_TREE else {}
        pin_scope(pins_old, read_allowlist(repo, c)[0])
        scan_pass(repo, old, c, gram_set, {}, {**pins_base, **pins_tip}, False, violations)

    for probe in not_ignored_probes(repo, tip):
        violations.append({"file": probe, "rule": "output_not_ignored", "line": 0})

    unique = {(v["file"], v["rule"], v["line"]): v for v in violations}
    return {
        "range": rng,
        "stage": stage,
        "files_checked": files_checked,
        "local_inputs": n_dirs,
        "local_grams": len(gram_set),
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
        grams = build_gram_set(dirs) if dirs else set()
        report = check(args.repo, args.rng, grams, len(dirs), args.stage)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - any failure must be a hard error, never a pass
        print(f"error: unexpected {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    if args.require_local_inputs and report["local_grams"] == 0:
        print("error: --require-local-inputs set but no local prompt 8-grams found", file=sys.stderr)
        return 2
    return 1 if report["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())
