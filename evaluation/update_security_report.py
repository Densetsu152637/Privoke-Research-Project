"""Render the generated tables of the update-security record from its JSON (UPDSEC-20261116)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- BEGIN GENERATED TABLES -->", "<!-- END GENERATED TABLES -->"
G7 = ("stale", "replayed", "duplicate", "malformed_tensor", "nan_inf", "wrong_shape", "excessive_change", "interrupted",
      "unauthorized_publication")
G8 = ("invalid_credentials", "invalid_certificate", "expired_credentials", "impersonation", "replayed_request",
      "unauthorized_retrieval", "unauthorized_update")


def escape(text) -> str:
    return str(text if text is not None else "").replace("|", "\|").replace("\n", " ")


def render_tables(record: dict) -> str:
    rows = {row["id"]: row for row in record["attacks"]}
    summary = record["summary"]
    lines = [f"Rows: {summary['total_rows']}. Rows whose security property was not met: "
             f"{len(summary['property_unmet_ids'])} ({', '.join(summary['property_unmet_ids']) or 'none'}).", ""]
    for goal, names, key in (("G7 guarded-update attack classes", G7, "G7"), ("G8 authentication test classes", G8, "G8")):
        lines += [f"### {goal}", "", "| Class | Rows | Rejected | Accepted | Idempotent / applied once | Not applicable | Property met | Property unmet |",
                  "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for name in names:
            members = [rows[i] for i in record["goal_coverage"][key][name]]
            count = lambda *outcomes: sum(row["observed"] in outcomes for row in members)  # noqa: E731
            lines.append(f"| {name} | {len(members)} | {count('rejected')} | {count('accepted')} | {count('idempotent_noop', 'applied_once')} | "
                         f"{count('not_applicable', 'not_run')} | {sum(r['property_met'] is True for r in members)} | "
                         f"{sum(r['property_met'] is False for r in members)} |")
        lines.append("")
    lines += ["### Attack by outcome", "", "| ID | Class | Path | Attack | Observed | Code | Model unchanged | Property met | Gap |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in record["attacks"]:
        met = {True: "yes", False: "NO", None: "n/a"}[row["property_met"]]
        unchanged = {True: "yes", False: "no", None: "n/a"}[row["model_unchanged"]]
        lines.append(f"| {row['id']} | {row['class']} | {row['path']} | {escape(row['description'])} | {row['observed']} | "
                     f"{escape(row['code'])} | {unchanged} | {met} | {escape(row.get('gap'))} |")
    lines += ["", "### Unmet properties (gaps)", "", "| Gap | Property | Status | Compensating control |", "| --- | --- | --- | --- |"]
    for gap in record["gaps"]:
        lines.append(f"| {gap['id']} | {escape(gap['property'])} | {escape(gap['status'])} | {escape(gap['compensating_control'])} |")
    lines += ["", "### Static evidence", "", "| ID | Claim | Holds | Detail |", "| --- | --- | --- | --- |"]
    for item in record["static_evidence"]:
        lines.append(f"| {item['id']} | {escape(item['claim'])} | {'yes' if item['holds'] else 'NO'} | {escape('; '.join(item['detail'])[:200])} |")
    return "\n".join(lines) + "\n"


def splice(document: str, tables: str) -> str:
    head, rest = document.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    return f"{head}{BEGIN}\n{tables}{END}{tail}"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=Path, default=ROOT / "paper/research/update-security-20261116.json")
    parser.add_argument("--document", type=Path, default=ROOT / "paper/research/update-security-20261116.md")
    args = parser.parse_args(argv)
    record = json.loads(args.record.read_text(encoding="utf-8"))
    args.document.write_text(splice(args.document.read_text(encoding="utf-8"), render_tables(record)), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
