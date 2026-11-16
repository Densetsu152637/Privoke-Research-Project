#!/usr/bin/env python
"""Export an anonymized copy of the tracked repository for double-blind review.

Usage (host Python, standard library only):
  python evaluation/export_anonymous_artifact.py [--revision HEAD] [--dest DIR]
      [--patterns paper/scripts/anonymity-patterns.txt] [--exclude GLOB ...]

The export reads tracked files only, through `git archive`, so the copy has no `.git`
directory, no remote URL and no history. Identity occurrences are rewritten with the
rules below, then the whole tree is verified against the shared pattern file (one
case-insensitive regular expression per line). The destination must be outside the
repository. Nothing is uploaded. A manifest (ARTIFACT-MANIFEST.json) is written into the
destination. The exit status is 0 only when verification finds no match.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import shutil
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATTERNS = "paper/scripts/anonymity-patterns.txt"
MANIFEST_NAME = "ARTIFACT-MANIFEST.json"
MANIFEST_VERSION = 1

# Declared exclusions: build outputs, pre-anonymization submissions, third-party source
# PDFs (large, not needed to run the code) and the tooling that must name the identity
# strings in order to find them.
DEFAULT_EXCLUDES = [
    "paper/main.aux", "paper/main.bbl", "paper/main.blg", "paper/main.log",
    "paper/main.out", "paper/main.pdf", "paper/main.fls", "paper/main.fdb_latexmk",
    "paper/main.synctex.gz", "paper/main.toc",
    "paper/old/*",
    "paper/sources/*.pdf",
    "paper/sources/**/*.pdf",
    "paper/scripts/anonymity-patterns.txt",
    "evaluation/export_anonymous_artifact.py",
    "evaluation/tests/test_export_anonymous_artifact.py",
]

PLACEHOLDER_URL = "https://anonymous.invalid/repository"
PLACEHOLDER_EMAIL = "anonymous@example.invalid"
URL_TAIL = r"""(?:/[^\s)\]>"'}\\,;]*)?"""

# Ordered rewrite rules (pattern, replacement). Longer, more specific forms come first.
REWRITE_RULES = [
    (r"\[git4san\]\(https?://github\.com/git4san\)", "the supervising professor"),
    (r"https?://github\.com/git4san" + URL_TAIL, "https://anonymous.invalid/supervisor"),
    (r"https?://(?:www\.)?github\.com/Densetsu152637" + URL_TAIL, PLACEHOLDER_URL),
    (r"https?://(?:www\.)?huggingface\.co/Densetsu152637" + URL_TAIL, PLACEHOLDER_URL),
    (r"\\\{[^}\n]*\}@student\.monash\.edu(?:\.my)?", PLACEHOLDER_EMAIL),
    (r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)*monash\.edu(?:\.my)?", PLACEHOLDER_EMAIL),
    (r"Monash University(?: Malaysia)?(?:,? Clayton)?(?:,? (?:Australia|Malaysia))?", "Anonymous Institution"),
    (r"Nicholas\s+Bisset", "Anonymous Author"),
    (r"Bisset,\s+Nicholas", "Author, Anonymous"),
    (r"Manpreet\s+(?:Sahadevan|Kaur)", "Anonymous Author"),
    (r"Sahadevan,\s+Manpreet", "Author, Anonymous"),
    (r"Nixon\s+Ngai", "Anonymous Author"),
    (r"Ngai,\s+Nixon", "Author, Anonymous"),
    (r"Sanoop\s+Mallissery", "Anonymous Author"),
    (r"Mallissery,\s+Sanoop", "Author, Anonymous"),
    (r"legend\.d\.1000", "anonymous-handle"),
    (r"git4san", "the supervising professor"),
    (r"(?:nbis0006|msah0018|nnga0004|Densetsu152637)", "anonymous-handle"),
    (r"Monash", "Anonymous Institution"),
    (r"Manpreet|Sanoop|Sahadevan|Mallissery|Bisset|Ngai", "Anonymous"),
]
COMPILED_RULES = [(re.compile(p, re.IGNORECASE), r) for p, r in REWRITE_RULES]

COPYRIGHT_LINE = re.compile(
    r"^(?P<indent>[ \t]*)Copyright[ \t]*(?:\(c\)|©)[ \t]*(?:\d{4}(?:[ \t]*[-,–][ \t]*\d{4})*)?[ \t]+"
    r"(?!and Related)(?P<holder>\S[^\r\n]*?)(?P<eol>\r?)$",
    re.IGNORECASE | re.MULTILINE,
)
COPYRIGHT_NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE")


class ExportError(Exception):
    pass


def run_git(repo, *args, binary=False):
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if proc.returncode != 0:
        raise ExportError(f"git {' '.join(args)} failed: {proc.stderr.decode('utf8', 'replace').strip()}")
    return proc.stdout if binary else proc.stdout.decode("utf8").strip()


def load_patterns(path):
    patterns = []
    for number, line in enumerate(Path(path).read_text(encoding="utf8").splitlines(), 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        try:
            patterns.append(re.compile(text, re.IGNORECASE))
        except re.error as exc:
            raise ExportError(f"{path}:{number}: invalid pattern: {exc}") from exc
    if not patterns:
        raise ExportError(f"{path}: no patterns")
    return patterns


def inside(child, parent):
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def guard_destination(dest, repo):
    """Refuse a destination inside the repository or any of its worktrees."""
    dest = dest.resolve()
    roots = {Path(run_git(repo, "rev-parse", "--show-toplevel")).resolve()}
    common = Path(run_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
    roots.add(common.parent)
    for line in run_git(repo, "worktree", "list", "--porcelain").splitlines():
        if line.startswith("worktree "):
            roots.add(Path(line[len("worktree "):]).resolve())
    for root in roots:
        if inside(dest, root) or inside(root, dest):
            raise ExportError("destination must be outside the repository and its worktrees")
    return dest


def is_excluded(path, globs):
    return any(fnmatch.fnmatchcase(path, g) for g in globs)


def is_binary(data):
    if b"\0" in data[:8192]:
        return True
    try:
        data.decode("utf8")
    except UnicodeDecodeError:
        return True
    return False


def rewrite_text(text, relpath):
    """Apply the rewrite rules. Returns (new_text, number_of_substitutions)."""
    count = 0
    if PurePosixPath(relpath).name.upper().split(".")[0] in COPYRIGHT_NAMES:
        text, n = COPYRIGHT_LINE.subn(lambda m: f"{m['indent']}Copyright (c) Anonymous Authors{m['eol']}", text)
        count += n
    for rule, replacement in COMPILED_RULES:
        text, n = rule.subn(replacement, text)
        count += n
    return text, count


def extract(repo, revision, dest, excludes):
    """Stream `git archive` into dest. Returns (files, excluded, skipped_links)."""
    # Read the whole archive before parsing: a streaming reader stops at the
    # end-of-archive marker and closing the pipe early makes git exit non-zero.
    proc = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", revision],
                          capture_output=True)
    if proc.returncode != 0:
        raise ExportError(f"git archive failed: {proc.stderr.decode('utf8', 'replace').strip()}")
    files, excluded, links = {}, [], []
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as tar:
        for member in tar:
            name = member.name
            parts = PurePosixPath(name).parts
            if PurePosixPath(name).is_absolute() or ".." in parts:
                raise ExportError(f"unsafe archive path: {name!r}")
            if member.isdir():
                continue
            if not member.isfile():
                links.append(name)
                continue
            if is_excluded(name, excludes):
                excluded.append(name)
                continue
            files[name] = tar.extractfile(member).read()
    return files, sorted(excluded), sorted(links)


def scan_text(patterns, text):
    hits = []
    for number, line in enumerate(text.splitlines(), 1):
        for index, pattern in enumerate(patterns):
            if pattern.search(line):
                hits.append((number, index))
    return hits


def scan_bytes(patterns, data):
    text = data.decode("latin-1")
    return sum(len(p.findall(text)) for p in patterns)


def verify_tree(root, patterns):
    """Scan every file name and file body under root. Returns a result dict."""
    text_matches, name_matches, binary_hits, binaries = {}, [], {}, []
    scanned = 0
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if path.name == MANIFEST_NAME:
            continue
        if any(p.search(rel) for p in patterns):
            name_matches.append(rel)
        data = path.read_bytes()
        scanned += 1
        if is_binary(data):
            binaries.append(rel)
            n = scan_bytes(patterns, data)
            if n:
                binary_hits[rel] = n
        else:
            hits = scan_text(patterns, data.decode("utf8"))
            if hits:
                text_matches[rel] = [{"line": ln, "pattern_index": i} for ln, i in hits]
    git_entries = [p.relative_to(root).as_posix() for p in root.rglob(".git*") if p.name in (".git", ".gitmodules")]
    return {
        "files_scanned": scanned,
        "text_matches": text_matches,
        "name_matches": name_matches,
        "binary_files": binaries,
        "binary_byte_scan_matches": binary_hits,
        "git_metadata_entries": git_entries,
        "passed": not (text_matches or name_matches or binary_hits or git_entries),
    }


def tree_digest(hashes):
    listing = "".join(f"{h}  {p}\n" for p, h in sorted(hashes.items()))
    return hashlib.sha256(listing.encode("utf8")).hexdigest()


def export(repo, revision, dest, patterns_path, extra_excludes=(), clean=False):
    repo = Path(repo).resolve()
    patterns = load_patterns(patterns_path)
    commit = run_git(repo, "rev-parse", "--verify", f"{revision}^{{commit}}")
    dest = guard_destination(Path(dest), repo)
    if dest.exists() and any(dest.iterdir()):
        if clean and (dest / MANIFEST_NAME).exists():
            shutil.rmtree(dest)
        else:
            raise ExportError("destination exists and is not empty (use --clean to replace a previous export)")
    dest.mkdir(parents=True, exist_ok=True)

    excludes = list(DEFAULT_EXCLUDES) + list(extra_excludes)
    files, excluded, links = extract(repo, commit, dest, excludes)

    redactions, hashes = {}, {}
    for rel in sorted(files):
        data = files[rel]
        count = 0
        if not is_binary(data):
            text, count = rewrite_text(data.decode("utf8"), rel)
            data = text.encode("utf8")
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        hashes[rel] = hashlib.sha256(data).hexdigest()
        if count:
            redactions[rel] = count

    verification = verify_tree(dest, patterns)
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "source_revision_commitment": hashlib.sha256(commit.encode()).hexdigest(),
        "file_count": len(hashes),
        "tree_sha256": tree_digest(hashes),
        "tree_sha256_definition": "sha256 of the sorted lines '<file sha256>  <path>\\n'; this manifest excluded",
        "exclusions": {"globs": excludes, "excluded_files": excluded, "skipped_links": links},
        "redactions": {"total": sum(redactions.values()), "files": len(redactions), "per_file": redactions},
        "verification": {
            "patterns_file_sha256": hashlib.sha256(Path(patterns_path).read_bytes()).hexdigest(),
            "pattern_count": len(patterns),
            **verification,
        },
    }
    (dest / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf8")
    if scan_text(patterns, (dest / MANIFEST_NAME).read_text(encoding="utf8")):
        manifest["verification"]["passed"] = False
        (dest / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf8")
    return dest, manifest


def default_dest():
    return Path(tempfile.gettempdir()) / "anonymous-artifact"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", default=str(REPO_ROOT), help="repository to export (default: this repository)")
    p.add_argument("--revision", default="HEAD")
    p.add_argument("--dest", default=None, help="destination outside the repository (default: system temp dir)")
    p.add_argument("--patterns", default=None, help=f"pattern file (default: <repo>/{DEFAULT_PATTERNS})")
    p.add_argument("--exclude", action="append", default=[], help="extra glob to exclude (repeatable)")
    p.add_argument("--clean", action="store_true", help="replace a previous export at the destination")
    args = p.parse_args(argv)
    patterns = args.patterns or str(Path(args.repo) / DEFAULT_PATTERNS)
    try:
        dest, manifest = export(args.repo, args.revision, args.dest or default_dest(), patterns, args.exclude, args.clean)
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    v = manifest["verification"]
    summary = {
        "destination": str(dest), "file_count": manifest["file_count"], "tree_sha256": manifest["tree_sha256"],
        "excluded_files": len(manifest["exclusions"]["excluded_files"]),
        "redactions": manifest["redactions"]["total"], "files_scanned": v["files_scanned"],
        "text_match_files": len(v["text_matches"]), "name_matches": len(v["name_matches"]),
        "binary_files_byte_scanned": len(v["binary_files"]), "binary_matches": len(v["binary_byte_scan_matches"]),
        "passed": v["passed"],
    }
    print(json.dumps(summary, indent=2))
    if not v["passed"]:
        for rel, hits in sorted(v["text_matches"].items()):
            print(f"match: {rel}: lines {[h['line'] for h in hits][:10]}", file=sys.stderr)
        for rel in v["name_matches"] + sorted(v["binary_byte_scan_matches"]):
            print(f"match: {rel}", file=sys.stderr)
        print("verification FAILED; do not upload this tree", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
