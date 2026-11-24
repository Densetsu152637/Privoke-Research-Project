#!/usr/bin/env python
"""Prove the Stage 13a commit order with Git ancestry.

Usage (run from the repository root, on the branch that holds the stage commits):
  python evaluation/annotation/check_order.py [--repo .] [--ref HEAD]
      [--set-manifest docs/research/s13a/set_manifest.json]
      [--packet-manifest docs/research/s13a/packet_manifest.json]
      [--labels-dir docs/research/s13a/labels]
      [--record paper/research/human-annotated-eval-*.json] [--allow-missing-record]

The order that must hold (each link a strict ancestor, verified with `git merge-base --is-ancestor`):
  set-manifest commit  ->  packet-manifest commit  ->  first label commit  ->  record commit
Each commit is the first one that added the file (the earliest label file for the labels, the earliest
record JSON for the record). Labels may be added in several commits, but modifying, deleting or renaming a label
file after it was added fails the check. When the record names its own freeze commits, they must equal the computed ones.
Exit 0 only when every link holds; exit 1 otherwise; exit 2 on a usage or Git error.
"""
from __future__ import annotations

import argparse
import glob
import json
import subprocess
import sys
from pathlib import Path

DEFAULT_SET = "docs/research/s13a/set_manifest.json"
DEFAULT_PACKET = "docs/research/s13a/packet_manifest.json"
DEFAULT_LABELS = "docs/research/s13a/labels"
DEFAULT_RECORD_GLOB = "paper/research/human-annotated-eval-*.json"


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def first_commit(repo, ref, path):
    """Earliest commit on ``ref`` that added a file at ``path`` (a directory: any file below it)."""
    result = git(repo, "log", ref, "--diff-filter=A", "--reverse", "--format=%H", "--", path)
    if result.returncode != 0:
        raise SystemExit(f"git log failed for {path}: {result.stderr.strip()}")
    commits = result.stdout.split()
    return commits[0] if commits else None


def is_strict_ancestor(repo, older, newer):
    if older == newer:
        return False
    return git(repo, "merge-base", "--is-ancestor", older, newer).returncode == 0


def computed_order(repo, ref, set_manifest, packet_manifest, labels_dir, record):
    return {"set_manifest_commit": first_commit(repo, ref, set_manifest),
            "packet_manifest_commit": first_commit(repo, ref, packet_manifest),
            "label_commit": first_commit(repo, ref, labels_dir),
            "record_commit": first_commit(repo, ref, record) if record else None}


def check(repo, ref, set_manifest, packet_manifest, labels_dir, record, allow_missing_record=False):
    commits = computed_order(repo, ref, set_manifest, packet_manifest, labels_dir, record)
    problems = []
    names = ["set_manifest_commit", "packet_manifest_commit", "label_commit", "record_commit"]
    for name in names:
        if commits[name] is None and not (name == "record_commit" and allow_missing_record):
            problems.append(f"{name}: no commit adds the file")
    for older, newer in zip(names, names[1:]):
        if commits[older] and commits[newer] and not is_strict_ancestor(repo, commits[older], commits[newer]):
            problems.append(f"{older} is not a strict ancestor of {newer}")
    if commits["label_commit"]:
        # Labels may be added over several commits (pilot, main, adjudicated); only a modification, deletion, rename or
        # type change of a file that already existed counts as a change after the freeze.
        changed = git(repo, "log", ref, "--diff-filter=MDRT", "--format=%H", "--", labels_dir)
        if changed.returncode != 0 or changed.stdout.strip():
            problems.append("the labels changed after they were committed")
    if record:
        path = Path(repo) / record
        if path.is_file():
            freeze = json.loads(path.read_text(encoding="utf8")).get("freeze")
            if not isinstance(freeze, dict):
                freeze = {}
                problems.append("the record has no freeze block")
            for name in names[:3]:
                if freeze.get(name) != commits[name]:
                    problems.append(f"record freeze.{name} differs from the computed commit")
    return {"commits": commits, "problems": problems, "ok": not problems}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", default=".")
    p.add_argument("--ref", default="HEAD")
    p.add_argument("--set-manifest", default=DEFAULT_SET)
    p.add_argument("--packet-manifest", default=DEFAULT_PACKET)
    p.add_argument("--labels-dir", default=DEFAULT_LABELS)
    p.add_argument("--record", default=None, help="record JSON path or glob (default: paper/research/human-annotated-eval-*.json)")
    p.add_argument("--allow-missing-record", action="store_true", help="check only the links before the record")
    args = p.parse_args(argv)
    repo = Path(args.repo)
    if git(repo, "rev-parse", "--git-dir").returncode != 0:
        print(json.dumps({"ok": False, "problems": [f"{repo} is not a Git repository"]}))
        return 2
    pattern = args.record or DEFAULT_RECORD_GLOB
    matches = sorted(Path(m).relative_to(repo).as_posix() for m in glob.glob(str(repo / pattern)))
    record = matches[-1] if matches else None
    result = check(repo, args.ref, args.set_manifest, args.packet_manifest, args.labels_dir, record, args.allow_missing_record)
    result["record"] = record
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
