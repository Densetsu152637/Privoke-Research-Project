#!/usr/bin/env python3
"""Check that no identity pattern matches the paper sources, PDF text or PDF metadata (G2).

Usage: python check_anonymity.py [--patterns FILE] [PATH ...]
With no PATH, checks main.tex, the pdftotext output of main.pdf and its pdfinfo metadata.
Other paths are scanned as text (a .pdf path is converted with pdftotext and pdfinfo; a directory
is scanned recursively for text files, which is how the Stage 8 artifact export reuses it).
Patterns are case-insensitive regular expressions, one per line, '#' for comments.
Exits 0 when nothing matches, 1 otherwise.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parents[1]


def load_patterns(path: Path):
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            # The shared pattern file uses the POSIX class so that grep -E and this script agree.
            patterns.append((line, re.compile(line.replace("[[:space:]]", r"\s"), re.IGNORECASE)))
    return patterns


def pdf_sources(pdf: Path):
    def run(*command):
        out = subprocess.run(command, capture_output=True, check=True).stdout
        return out.decode("utf-8", errors="replace")

    text = run("pdftotext", str(pdf), "-")
    info = run("pdfinfo", str(pdf))
    return [(f"{pdf.name} (pdftotext)", text), (f"{pdf.name} (pdfinfo)", info)]


def sources_for(path: Path):
    if path.is_dir():
        found = []
        for child in sorted(path.rglob("*")):
            if child.is_file() and ".git" not in child.parts:
                found += sources_for(child)
        return found
    if path.suffix.lower() == ".pdf":
        return pdf_sources(path)
    try:
        return [(str(path), path.read_text(encoding="utf-8"))]
    except (UnicodeDecodeError, OSError):
        return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--patterns", type=Path, default=Path(__file__).with_name("anonymity-patterns.txt"))
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    patterns = load_patterns(args.patterns)
    sources = []
    for path in args.paths or [PAPER / "main.tex", PAPER / "main.pdf"]:
        sources += sources_for(path)
    failures = 0
    for label, text in sources:
        for raw, regex in patterns:
            for match in regex.finditer(text):
                failures += 1
                line = text.count("\n", 0, match.start()) + 1
                print(f"MATCH {label}:{line}: /{raw}/ -> {match.group(0)!r}")
    print(f"checked {len(sources)} source(s) against {len(patterns)} pattern(s): {failures} match(es)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
