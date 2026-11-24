"""Label space, sheet columns, parsing and validation for the double-annotation study.

The label space mirrors the product contract (`shared/python/privoke_model/v3_contract.py`):
sensitivity S0-S3, visibility P0-P4 plus PU, ten categories, and the three enforcement
actions. Annotator sheets are CSV or JSONL with one row per item.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

SCHEMA_VERSION = 2  # v1 sheets (disclosure/sensitivity/visibility) stay readable with version=1

SENSITIVITY = ["S0", "S1", "S2", "S3"]
VISIBILITY = ["P0", "P1", "P2", "P3", "P4", "PU"]
CATEGORIES = ["HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL",
              "CHILD", "LOCATION", "IDENTITY", "THIRD_PARTY"]
ACTIONS = ["ALLOW", "WARN", "BLOCK"]
DISCLOSURE = ["yes", "no", "unclear"]

# Fields compared in agreement/accuracy analyses and their measurement level.
FIELDS = {
    "disclosure": {"values": DISCLOSURE, "level": "nominal"},
    "sensitivity": {"values": SENSITIVITY, "level": "ordinal"},
    "visibility": {"values": VISIBILITY, "level": "nominal"},
    "action": {"values": ACTIONS, "level": "ordinal"},
}
LABEL_COLUMNS = ["disclosure", "sensitivity", "visibility", "categories", "action", "notes"]
SHEET_COLUMNS = ["item_id", "text"] + LABEL_COLUMNS
ADJUDICATION_COLUMNS = ["item_id"] + LABEL_COLUMNS[:-1] + ["resolution", "reason", "adjudicator"]

# Schema v2 (Stage 13a): sensitive yes/no, whose information it is, intended audience, categories, action.
SUBJECTS = ["SELF", "THIRD_PARTY", "PUBLIC_FIGURE", "NONE", "UNCLEAR"]
AUDIENCES = ["P0", "P1", "P2", "P3", "P4", "PU"]
SENSITIVE = ["yes", "no"]
FIELDS_V2 = {
    "sensitive": {"values": SENSITIVE, "level": "nominal"},
    "subject": {"values": SUBJECTS, "level": "nominal"},
    "audience": {"values": AUDIENCES, "level": "nominal"},
    "action": {"values": ACTIONS, "level": "ordinal"},
}
LABEL_COLUMNS_V2 = ["sensitive", "subject", "audience", "categories", "action", "notes"]
SHEET_COLUMNS_V2 = ["item_id", "text"] + LABEL_COLUMNS_V2
# Committed label files carry no text and no notes (notes can quote the text).
COMMITTED_LABEL_COLUMNS_V2 = ["item_id", "sensitive", "subject", "audience", "categories", "action"]
ADJUDICATION_COLUMNS_V2 = ["item_id"] + LABEL_COLUMNS_V2[:-1] + ["resolution", "reason", "adjudicator"]
LOWERCASE_FIELDS = {"disclosure", "sensitive"}


def fields_for(version: int) -> dict:
    return {1: FIELDS, 2: FIELDS_V2}[version]


def label_columns_for(version: int) -> list:
    return {1: LABEL_COLUMNS, 2: LABEL_COLUMNS_V2}[version]


def sheet_columns_for(version: int) -> list:
    return {1: SHEET_COLUMNS, 2: SHEET_COLUMNS_V2}[version]


RESOLUTIONS = ["consensus", "third_adjudicator", "rubric_clarification", "excluded_ambiguous"]


class SheetError(ValueError):
    """A completed sheet violates the annotation schema."""


def parse_categories(raw) -> list[str]:
    """Return a sorted category list; the explicit token NONE means no category."""
    if isinstance(raw, (list, tuple)):
        tokens = [str(t) for t in raw]
    else:
        text = (raw or "").strip()
        for sep in (";", ","):
            text = text.replace(sep, "|")
        tokens = [t for t in text.split("|")]
    tokens = [t.strip().upper() for t in tokens if t.strip()]
    if not tokens:
        raise SheetError("categories is empty; write NONE when no category applies")
    if "NONE" in tokens:
        if len(tokens) != 1:
            raise SheetError("NONE cannot be combined with other categories")
        return []
    bad = [t for t in tokens if t not in CATEGORIES]
    if bad:
        raise SheetError("unknown categories: " + ",".join(bad))
    return sorted(set(tokens))


def format_categories(categories) -> str:
    return "|".join(sorted(categories)) if categories else "NONE"


def normalise_row(row: dict, *, require_complete: bool = True, version: int = 1) -> dict:
    """Validate one completed row and return a normalised label record."""
    out = {"item_id": str(row.get("item_id", "")).strip()}
    if not out["item_id"]:
        raise SheetError("row without item_id")
    for name, spec in fields_for(version).items():
        raw = str(row.get(name, "") or "").strip()
        value = raw.lower() if name in LOWERCASE_FIELDS else raw.upper()
        if not value:
            if require_complete:
                raise SheetError(f"{out['item_id']}: {name} is empty")
            out[name] = None
            continue
        if value not in spec["values"]:
            raise SheetError(f"{out['item_id']}: invalid {name} {raw!r}")
        out[name] = value
    try:
        out["categories"] = parse_categories(row.get("categories"))
    except SheetError as error:
        if require_complete:
            raise SheetError(f"{out['item_id']}: {error}") from None
        out["categories"] = None
    out["notes"] = str(row.get("notes", "") or "")
    return out


def read_rows(path) -> list[dict]:
    path = Path(path)
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf8").splitlines() if line.strip()]
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def read_labels(path, *, require_complete: bool = True, version: int = 1) -> dict[str, dict]:
    """Read a completed sheet into {item_id: normalised labels}; duplicate ids are errors."""
    labels: dict[str, dict] = {}
    for row in read_rows(path):
        record = normalise_row(row, require_complete=require_complete, version=version)
        if record["item_id"] in labels:
            raise SheetError("duplicate item_id " + record["item_id"])
        labels[record["item_id"]] = record
    return labels


def write_csv(path, columns, rows) -> None:
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path, rows) -> None:
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def validate_sheet(path, version: int = SCHEMA_VERSION) -> list[str]:
    """Return every problem in a completed sheet (empty list when valid); never raises on content."""
    try:
        rows = read_rows(path)
    except (OSError, ValueError) as error:
        return [f"cannot read {path}: {error}"]
    if not rows:
        return ["sheet has no rows"]
    problems = []
    needed = {"item_id", *fields_for(version), "categories"}
    missing = sorted(needed - set(rows[0]))
    if missing:
        return ["missing columns: " + ",".join(missing)]
    seen = set()
    for number, row in enumerate(rows, start=2):
        try:
            record = normalise_row(row, version=version)
        except SheetError as error:
            problems.append(f"row {number}: {error}")
            continue
        if record["item_id"] in seen:
            problems.append(f"row {number}: duplicate item_id {record['item_id']}")
        seen.add(record["item_id"])
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate completed annotation sheets against the label schema.")
    parser.add_argument("--validate", required=True, nargs="+", metavar="SHEET", help="completed sheet (csv or jsonl)")
    parser.add_argument("--schema", type=int, choices=[1, 2], default=SCHEMA_VERSION)
    args = parser.parse_args(argv)
    failed = False
    for path in args.validate:
        problems = validate_sheet(path, args.schema)
        failed = failed or bool(problems)
        print(json.dumps({"sheet": str(path), "schema": args.schema, "valid": not problems, "problems": problems[:50],
                          "problem_count": len(problems)}))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
