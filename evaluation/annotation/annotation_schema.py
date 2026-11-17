"""Label space, sheet columns, parsing and validation for the double-annotation study.

The label space mirrors the product contract (`shared/python/privoke_model/v3_contract.py`):
sensitivity S0-S3, visibility P0-P4 plus PU, ten categories, and the three enforcement
actions. Annotator sheets are CSV or JSONL with one row per item.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

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


def normalise_row(row: dict, *, require_complete: bool = True) -> dict:
    """Validate one completed row and return a normalised label record."""
    out = {"item_id": str(row.get("item_id", "")).strip()}
    if not out["item_id"]:
        raise SheetError("row without item_id")
    for name, spec in FIELDS.items():
        raw = str(row.get(name, "") or "").strip()
        value = raw.lower() if name == "disclosure" else raw.upper()
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


def read_labels(path, *, require_complete: bool = True) -> dict[str, dict]:
    """Read a completed sheet into {item_id: normalised labels}; duplicate ids are errors."""
    labels: dict[str, dict] = {}
    for row in read_rows(path):
        record = normalise_row(row, require_complete=require_complete)
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
