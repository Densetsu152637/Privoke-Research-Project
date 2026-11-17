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


def render_stack_tables(record: dict) -> str:
    """The generated tables of a Rust-stack record (stage 9): goal checks, the eight-gap table, every row and the static rows."""
    summary, checks = record["summary"], record["goal_checks"]
    unmet = summary["property_unmet_ids"]
    lines = [f"Rows: {summary['total_rows']}; not run: {len(record['rows_not_run'])}; rows whose security property was not met: {len(unmet)} "
             f"({', '.join(unmet) or 'none'}). Missing row families: {', '.join(record['missing_row_families']) or 'none'}.", "",
             "### Goal checks", "", "| Goal | Check | Result |", "| --- | --- | --- |",
             f"| G2 | Rows A1, A3, T1, T3, T8, T12, T14 and R7 are rejected with the model unchanged | {'yes' if checks['G2']['all_rejected_with_model_unchanged'] and checks['G2']['families_present'] else 'NO'} |",
             f"| G2 | Static rows ST1, ST2, ST3, ST5 and ST6 hold | {'yes' if checks['G2']['static_rows_hold'] else 'NO'} |",
             f"| G2 | Every cloud image started without `--client-ca` or without `--crl` exits non-zero ({len(checks['G2']['startup_rows'])} rows) | {'yes' if checks['G2']['startup_all_refused'] else 'NO'} |",
             f"| G3 | All {checks['G3']['gaps']} gaps are verified by at least one row that ran | {'yes' if checks['G3']['all_verified'] else 'NO'} |", ""]
    lines += ["### Gap closure (G3)", "", "| Gap | Status | Reason | Rows that ran | Static rows |", "| --- | --- | --- | --- | --- |"]
    for gap in record["gaps"]:
        lines.append(f"| {gap['id']} | {escape(gap['status'])} | {escape(gap['reason'])} | {escape(', '.join(gap['rows_that_ran']))} | {escape(', '.join(gap['static']) or 'none')} |")
    lines += ["", "### Rows", "", "| ID | Service | Path | Row | Observed | Code | Store unchanged | Property met | Gap |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in record["attacks"]:
        met = {True: "yes", False: "NO", None: "n/a"}[row["property_met"]]
        unchanged = {True: "yes", False: "no", None: "n/a"}[row["model_unchanged"]]
        lines.append(f"| {row['id']} | {escape(row.get('service'))} | {row['path']} | {escape(row['description'])} | {row['observed']} | {escape(row['code'])} | "
                     f"{unchanged} | {met} | {escape(row.get('gap'))} |")
    lines += ["", "### Static rows", "", "| ID | Claim | Holds | Detail |", "| --- | --- | --- | --- |"]
    for item in record["static_evidence"]:
        lines.append(f"| {item['id']} | {escape(item['claim'])} | {'yes' if item['holds'] else 'NO'} | {escape('; '.join(item['detail'])[:200])} |")
    if record["rows_not_run"]:
        lines += ["", "### Rows not run", "", f"{', '.join(record['rows_not_run'])}. {record['limitations'][-1]}"]
    return "\n".join(lines) + "\n"


def render_tables(record: dict) -> str:
    if record.get("service") == "all":
        return render_stack_tables(record)
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
