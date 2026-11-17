#!/usr/bin/env python
"""Goal G7 of docs/plans/rust-server-rewrite.md: recorded evidence is not invalidated silently.

    python evaluation/check_revalidation.py --plan docs/plans/rust-server-rewrite.md --base rust-reference-20261117

It asserts, and exits 0 only if all three hold:

1. Every row of the revalidation table in the plan has a status from `revalidated (<record path>[, ...])`,
   `historical (<path>[, ...])` or `not claimed for the Rust build`; every cited path exists in the working tree, and a
   `historical` path has no change since the base revision.
2. `git diff --diff-filter=MD --name-only <base> -- paper/research docs/experiments` lists no deleted file and no file that
   lost or rewrote a line: existing evidence was only added to (an index such as `claims.md` may gain rows).
3. `paper/research/update-security-20261116.md` and its JSON are byte-identical to the base revision.

The plan names the tag `asiaccs-2027-submission`; stage 0 created the local tag `rust-reference-20261117` in its place, which
is the default base here. Any revision `git` can resolve is accepted.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECTION = "## Research evidence and revalidation"
EVIDENCE_PATHS = ("paper/research", "docs/experiments")
PINNED_RECORDS = ("paper/research/update-security-20261116.md", "paper/research/update-security-20261116.json")
STATUS_PATTERNS = (
    ("revalidated", re.compile(r"^revalidated \((?P<paths>[^()]+)\)$")),
    ("historical", re.compile(r"^historical \((?P<paths>[^()]+)\)$")),
    ("not claimed", re.compile(r"^not claimed for the Rust build$")),
)


def git(*arguments: str, root: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *arguments], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def table_rows(plan_text: str) -> tuple[list[str], list[list[str]]]:
    """The header cells and the body rows of the first table under the revalidation heading."""
    if SECTION not in plan_text:
        raise ValueError(f"the plan has no section {SECTION!r}")
    lines = plan_text.split(SECTION, 1)[1].splitlines()
    table = []
    started = False
    for line in lines:
        if line.startswith("## ") and started:
            break
        if line.startswith("|"):
            started = True
            table.append(line)
        elif started:
            break
    if len(table) < 3:
        raise ValueError("the revalidation table is missing")
    split = lambda line: [cell.strip() for cell in line.strip().strip("|").split("|")]  # noqa: E731
    header = split(table[0])
    body = [split(line) for line in table[2:]]
    for row in body:
        if len(row) != len(header):
            raise ValueError(f"a table row has {len(row)} cells, expected {len(header)}: {row[0][:60]!r}")
    return header, body


def check_statuses(plan_text: str, base: str, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    try:
        header, body = table_rows(plan_text)
    except ValueError as error:
        return [str(error)]
    status_columns = [index for index, name in enumerate(header) if name.lower().startswith("status")]
    if not status_columns:
        return ["the revalidation table has no Status column"]
    column = status_columns[0]
    for row in body:
        label, status = row[0][:70], row[column]
        for kind, pattern in STATUS_PATTERNS:
            match = pattern.match(status)
            if match:
                break
        else:
            errors.append(f"{label}: status {status!r} is not revalidated (<path>), historical (<path>) or 'not claimed for the Rust build'")
            continue
        if kind == "not claimed":
            continue
        for path in (item.strip().strip("`") for item in match.group("paths").split(",")):
            if not (root / path).exists():
                errors.append(f"{label}: cited path {path!r} does not exist")
            elif kind == "historical":
                changed = git("diff", "--name-only", base, "--", path, root=root)
                if changed.returncode or changed.stdout.strip():
                    errors.append(f"{label}: historical path {path!r} changed since {base}: {changed.stdout.strip()[:120] or changed.stderr.strip()[:120]}")
    return errors


def check_evidence_only_added(base: str, root: Path = ROOT) -> list[str]:
    """No evidence file is deleted, and an existing one only gains lines (index files such as claims.md gain rows)."""
    result = git("diff", "--diff-filter=MD", "--name-status", base, "--", *EVIDENCE_PATHS, root=root)
    if result.returncode:
        return [f"git diff against {base} failed: {result.stderr.strip()[:200]}"]
    errors = []
    for line in result.stdout.splitlines():
        status, _, path = line.partition("	")
        if status.startswith("D"):
            errors.append(f"existing evidence was deleted: {path}")
            continue
        counts = git("diff", "--numstat", base, "--", path, root=root).stdout.split()
        if len(counts) < 2 or counts[1] != "0":
            errors.append(f"existing evidence was modified (lines removed or rewritten): {path}")
    return errors


def check_pinned_records(base: str, root: Path = ROOT) -> list[str]:
    """The recorded UPDSEC files have no difference from the base (`git diff` ignores line-ending conversion, `core.autocrlf`)."""
    errors = []
    for path in PINNED_RECORDS:
        if not (root / path).is_file():
            errors.append(f"{path} is missing")
        elif git("cat-file", "-e", f"{base}:{path}", root=root).returncode:
            errors.append(f"{path} is not in {base}")
        elif git("diff", "--quiet", base, "--", path, root=root).returncode:
            errors.append(f"{path} differs from {base}")
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plan", type=Path, default=ROOT / "docs/plans/rust-server-rewrite.md")
    parser.add_argument("--base", default="rust-reference-20261117", help="the reference revision (the plan's asiaccs-2027-submission)")
    args = parser.parse_args(argv)
    if git("rev-parse", "--verify", "--quiet", f"{args.base}^{{commit}}").returncode:
        print(f"base revision {args.base!r} does not resolve in this checkout", file=sys.stderr)
        return 2
    plan = args.plan if args.plan.is_absolute() else ROOT / args.plan
    results = (("1. revalidation table statuses", check_statuses(plan.read_text(encoding="utf-8"), args.base)),
               ("2. evidence only added, never modified or deleted", check_evidence_only_added(args.base)),
               ("3. UPDSEC-20261116 identical to the base", check_pinned_records(args.base)))
    failed = False
    for title, errors in results:
        print(f"{'FAIL' if errors else 'PASS'}  {title}")
        for error in errors:
            print(f"      {error}")
        failed = failed or bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
