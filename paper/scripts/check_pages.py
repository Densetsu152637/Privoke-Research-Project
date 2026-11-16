#!/usr/bin/env python3
"""Page-limit check (G3) for the ASIACCS submission, read from main.aux.

Limits: the last body section ends on page 12 or earlier, the references start on page 13 or
earlier, and the whole PDF has at most 22 pages. main.tex marks the end of the body with the label
`body:end` and the start of the bibliography with `refs:start`; both pages come from main.aux.
The last body section is the last numbered section in the table of contents recorded in main.aux
(appendix sections carry letters). The total page count is read from pdfinfo when available,
otherwise from the last absolute page recorded in main.aux. Exits 0 when all limits hold.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

PAPER = Path(__file__).resolve().parents[1]
BODY_LIMIT, REF_START_LIMIT, TOTAL_LIMIT = 12, 13, 22


def label_page(aux: str, name: str) -> int:
    match = re.search(r"\\newlabel\{" + re.escape(name) + r"\}\{\{[^}]*\}\{(\d+)\}", aux)
    if not match:
        raise SystemExit(f"label {name!r} not found in main.aux (rebuild with latexmk)")
    return int(match.group(1))


def main() -> int:
    aux = (PAPER / "main.aux").read_text(encoding="utf-8")
    sections = re.findall(r"\\contentsline \{section\}\{\\numberline \{([^}]*)\}([^}]*)\}\{(\d+)\}", aux)
    body = [(n, t, int(p)) for n, t, p in sections if n.isdigit()]
    appendix = [(n, t, int(p)) for n, t, p in sections if not n.isdigit()]
    last_number, last_title, last_start = body[-1]
    body_end = label_page(aux, "body:end")
    refs_start = label_page(aux, "refs:start")
    total = None
    last_abs = re.search(r"\\gdef \\@abspage@last\{(\d+)\}", aux)
    if last_abs:
        total = int(last_abs.group(1))
    if shutil.which("pdfinfo"):
        info = subprocess.run(["pdfinfo", str(PAPER / "main.pdf")], capture_output=True, text=True, encoding="utf-8").stdout
        match = re.search(r"^Pages:\s+(\d+)", info, re.MULTILINE)
        if match:
            total = int(match.group(1))
    print(f"last body section: {last_number} {last_title!r} starts on page {last_start}; the body ends on page {body_end} (limit {BODY_LIMIT})")
    print(f"references start on page {refs_start} (limit {REF_START_LIMIT})")
    if appendix:
        print(f"appendices {appendix[0][0]}-{appendix[-1][0]}: first on page {appendix[0][2]}")
    print(f"total pages: {total} (limit {TOTAL_LIMIT})")
    ok = body_end <= BODY_LIMIT and refs_start <= REF_START_LIMIT and total is not None and total <= TOTAL_LIMIT
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
