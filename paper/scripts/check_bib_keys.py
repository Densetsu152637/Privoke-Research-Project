#!/usr/bin/env python3
"""Source-pool check (G4): every key of the original BibTeX databases is in sample-base.bib.

The plan baseline databases are paper/ref.bib and paper/manuscript-completion-sources-20261014.bib;
the two further historical source files are checked as well. With --base REV the original files
are read from that Git revision (for example bca457df) instead of the working tree.
Exits 0 when no key is missing.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parents[1]
ORIGINALS = [
    "ref.bib",
    "manuscript-completion-sources-20261014.bib",
    "research/paper-completion-sources-20261014.bib",
    "research/literature-baseline-sources-20261015.bib",
]
KEY = re.compile(r"^@\w+\s*\{\s*([^,\s]+)\s*,", re.MULTILINE)


def keys_of(text: str) -> set[str]:
    return set(KEY.findall(text))


def original_text(name: str, base: str | None) -> str:
    if base is None:
        return (PAPER / name).read_text(encoding="utf-8")
    out = subprocess.run(["git", "show", f"{base}:paper/{name}"], capture_output=True, text=True,
                         encoding="utf-8", check=True, cwd=PAPER)
    return out.stdout


def main() -> int:
    base = sys.argv[sys.argv.index("--base") + 1] if "--base" in sys.argv else None
    target = keys_of((PAPER / "sample-base.bib").read_text(encoding="utf-8"))
    missing_total = 0
    for name in ORIGINALS:
        source = keys_of(original_text(name, base))
        missing = sorted(source - target)
        missing_total += len(missing)
        print(f"{name}: {len(source)} keys, {len(missing)} missing from sample-base.bib {missing}")
    print(f"sample-base.bib: {len(target)} keys; baseline: {base or 'working tree'}")
    return 1 if missing_total else 0


if __name__ == "__main__":
    sys.exit(main())
