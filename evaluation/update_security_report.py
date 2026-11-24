"""Render the generated tables of the update-security record from its JSON (UPDSEC-20261116)."""
from __future__ import annotations

import argparse
import fnmatch
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- BEGIN GENERATED TABLES -->", "<!-- END GENERATED TABLES -->"
G7 = ("stale", "replayed", "duplicate", "malformed_tensor", "nan_inf", "wrong_shape", "excessive_change", "interrupted",
      "unauthorized_publication")
G8 = ("invalid_credentials", "invalid_certificate", "expired_credentials", "impersonation", "replayed_request",
      "unauthorized_retrieval", "unauthorized_update")


def escape(text) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


# --------------------------------------------------------------------------------------
# Stage 13d: authentication and authorisation record (AUTHZ-<date>). `denied_by` names the layer that refused a request.
# --------------------------------------------------------------------------------------

AUTHZ_SCHEMA = "privoke.authn-authz.v1"
DENIED_BY = ("tls_handshake", "revocation", "registry", "role_policy", "rpc_surface", "application", "client_admission", "not_denied")
# The status codes a layer can produce. `application` and `client_admission` accept any non-OK status or rejected receipt.
HANDSHAKE_CODES = frozenset({"UNAVAILABLE", "CONNECTION_ABORTED"})
LAYER_CODES = {"tls_handshake": HANDSHAKE_CODES, "revocation": HANDSHAKE_CODES, "registry": frozenset({"PERMISSION_DENIED"}),
               "role_policy": frozenset({"PERMISSION_DENIED"}), "rpc_surface": frozenset({"UNIMPLEMENTED"}), "not_denied": frozenset({"OK"})}
# Rows whose request reached (or could reach) a handler carry a layer; a row that asserts a property of a log or a process does not.
LAYERED_EXPECTATIONS = ("rejected_unchanged", "positive_control")
NOT_RUN_OUTCOMES = ("not_run", "not_applicable")
CREDENTIAL_ISSUERS = ("privoke-pki", "openssl-helper", "none")
SCOPE_LABELS = ("product pipeline (in-process)", "product pipeline (installed extension, end to end)", "LLM-only (semantic)",
                "update path (Rust V3)", "transport (Rust)", "human ground truth")
RECORD_HEADER = ("schema", "study_id", "chain", "build", "host", "run_dates", "commands", "scope_label", "not_established", "user_actions")
CROSS_REFERENCED_RECORDS = ("UPDSEC-20261116", "UPDSEC-20261117")
# Rows that need the genuine 13c candidate; they are recorded as not_run (pending 13d-1b), never as a failure.
PENDING_13D_1B = ("CK8", "CK-positive-publisher-commit", "CK-positive-publisher-rollback", "CK-positive-runtime-stage")
# (attack, row matchers (exact id or fnmatch pattern), cross-references to the 13c record that AUTHZ cites)
S13D_ATTACKS = (
    ("Invalid credentials", ("R3-*", "R4", "R4-self-signed"), ()),
    ("Expired certificate", ("R3-expired", "R3-not-yet-valid"), ()),
    ("Missing credentials", ("R7-no-cert", "R8-no-cert", "CK5", "R10-no-cert"), ()),
    ("Wrong client identity", ("R7-unregistered", "CK3", "X8"), ()),
    ("Unauthorised model retrieval", ("R7-*", "R8-*", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"), ()),
    ("Unauthorised update submission", ("CK1", "CK3", "CK4", "R9-submit-update"), ()),
    ("Unauthorised publication", ("CK2", "CK6", "CK7"), ()),
    ("Replayed authenticated request", ("TL1",), ("13c C2a", "13c C2b")),
    ("Tampered request", ("TL2", "TL3"), ("13c C9",)),
    ("Cross-identity misuse", ("CK2", "CK4", "CK8", "R7-reporter", "R10-installation"), ()),
)


def row_ran(row: dict) -> bool:
    return row.get("observed") not in NOT_RUN_OUTCOMES


def denied_by_problems(row: dict) -> list[str]:
    """What is wrong with the `denied_by` of one row (empty when it is sound). A row that ran and asserts a denial or a positive
    control must name a layer, the layer must exist, and its status code must be one the layer can produce."""
    layer, code, expected = row.get("denied_by"), row.get("code"), row.get("expected")
    if "denied_by" not in row:
        return [f"{row['id']}: no denied_by field"]
    if not row_ran(row):
        return [f"{row['id']}: a row that did not run carries denied_by {layer!r}"] if layer is not None else []
    if expected not in LAYERED_EXPECTATIONS:
        return [f"{row['id']}: a property row carries denied_by {layer!r}"] if layer is not None else []
    if layer not in DENIED_BY:
        return [f"{row['id']}: denied_by {layer!r} is not in the vocabulary"]
    allowed = LAYER_CODES.get(layer)
    if allowed is not None and code not in allowed:
        return [f"{row['id']}: denied_by {layer} is inconsistent with the code {code}"]
    if layer in ("application", "client_admission") and (code == "OK" or row.get("observed") != "rejected"):
        return [f"{row['id']}: denied_by {layer} but the request was not rejected"]
    if layer == "not_denied" and row.get("observed") != "accepted":
        return [f"{row['id']}: denied_by not_denied but the request was {row.get('observed')}"]
    if layer != "not_denied" and row.get("observed") != "rejected":
        return [f"{row['id']}: denied_by {layer} but the request was {row.get('observed')}"]
    return []


def s13d_coverage(record: dict) -> dict:
    """Which attacks of the 13d map have at least one row with a `denied_by` value. A `not_denied` row counts, and is reported as
    an unmet property. Rows pending 13d-1b are listed, not failed."""
    rows = record["attacks"]
    attacks, problems = [], []
    for name, matchers, cross in S13D_ATTACKS:
        matched = [row for row in rows if any(fnmatch.fnmatchcase(row["id"], matcher) for matcher in matchers)]
        counted = [row for row in matched if row_ran(row) and row.get("denied_by") in DENIED_BY]
        attacks.append({"attack": name, "matchers": list(matchers), "rows": [row["id"] for row in matched], "counted": [row["id"] for row in counted],
                        "denied_by": sorted({row["denied_by"] for row in counted}), "cross_references": list(cross), "covered": bool(counted)})
        if not counted:
            problems.append(f"attack {name!r} has no row with a denied_by value")
    for row in rows:
        problems.extend(denied_by_problems(row))
    unmet = [row["id"] for row in rows if row_ran(row) and row.get("denied_by") == "not_denied" and row.get("expected") == "rejected_unchanged"]
    pending = [row["id"] for row in rows if row["id"] in PENDING_13D_1B and not row_ran(row)]
    return {"attacks": attacks, "problems": problems, "unmet_properties": unmet, "pending_13d_1b": pending, "ok": not problems}


def check_authz_record(record: dict) -> list[str]:
    """Everything `--check` verifies of an AUTHZ record: the header, the vocabulary of each row, the coverage, the cross-references to
    UPDSEC-20261116 and UPDSEC-20261117 in the gap table, and the totals re-derived from the rows."""
    problems = [f"header field {name} is missing" for name in RECORD_HEADER if name not in record]
    if record.get("schema") != AUTHZ_SCHEMA:
        problems.append(f"schema is {record.get('schema')!r}, not {AUTHZ_SCHEMA!r}")
    for row in record.get("attacks", []):
        if row.get("scope_label") not in SCOPE_LABELS:
            problems.append(f"{row['id']}: scope_label {row.get('scope_label')!r} is not in the vocabulary")
        if row.get("credential_issuer") not in CREDENTIAL_ISSUERS:
            problems.append(f"{row['id']}: credential_issuer {row.get('credential_issuer')!r} is not in the vocabulary")
        if "identity" not in row:
            problems.append(f"{row['id']}: no identity field")
    problems.extend(s13d_coverage(record)["problems"])
    ids = {gap["id"] for gap in record.get("gaps", [])}
    problems.extend(f"the gap table does not cite {name}" for name in CROSS_REFERENCED_RECORDS if name not in ids)
    rows = record.get("attacks", [])
    summary = record.get("summary", {})
    if summary.get("total_rows") != len(rows):
        problems.append(f"summary counts {summary.get('total_rows')} rows, the record holds {len(rows)}")
    unmet = sorted(row["id"] for row in rows if row.get("property_met") is False)
    if sorted(summary.get("property_unmet_ids", [])) != unmet:
        problems.append("summary property_unmet_ids differs from the rows")
    return problems


def render_authz_tables(record: dict) -> str:
    """The generated tables of an AUTHZ record: the attack coverage, the layer counts, every row, the unmet properties and the pending rows."""
    coverage = s13d_coverage(record)
    rows, summary = record["attacks"], record["summary"]
    unmet_ids = summary["property_unmet_ids"]
    lines = [f"Rows: {summary['total_rows']}; not run: {len(record['rows_not_run'])}; rows whose security property was not met: {len(unmet_ids)} "
             f"({', '.join(unmet_ids) or 'none'}). Coverage of the attack map: {'complete' if coverage['ok'] else 'INCOMPLETE'}.", "",
             "### Attack coverage", "", "| Attack | Rows that ran with a denied_by | Layers | Cross-reference | Covered |", "| --- | --- | --- | --- | --- |"]
    for attack in coverage["attacks"]:
        lines.append(f"| {attack['attack']} | {escape(', '.join(attack['counted']) or 'none')} | {escape(', '.join(attack['denied_by']) or 'none')} | "
                     f"{escape(', '.join(attack['cross_references']) or 'none')} | {'yes' if attack['covered'] else 'NO'} |")
    lines += ["", "### Rows by denying layer", "", "| denied_by | Rows |", "| --- | ---: |"]
    for layer in DENIED_BY:
        lines.append(f"| {layer} | {sum(1 for row in rows if row.get('denied_by') == layer)} |")
    lines.append(f"| (no layer: did not run, or a property row) | {sum(1 for row in rows if row.get('denied_by') is None)} |")
    lines += ["", "### Rows", "", "| ID | Service | Scope | Path | Row | Identity | Issuer | Observed | Code | denied_by | Store unchanged | Property met |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in rows:
        met = {True: "yes", False: "NO", None: "n/a"}[row["property_met"]]
        unchanged = {True: "yes", False: "no", None: "n/a"}[row["model_unchanged"]]
        lines.append(f"| {row['id']} | {escape(row.get('service'))} | {escape(row.get('scope_label'))} | {row['path']} | {escape(row['description'])} | "
                     f"{escape(row['identity'])} | {escape(row.get('credential_issuer'))} | {row['observed']} | {escape(row['code'])} | "
                     f"{escape(row.get('denied_by'))} | {unchanged} | {met} |")
    lines += ["", "### Unmet properties", ""]
    lines.append(", ".join(coverage["unmet_properties"]) + " (requests that nothing denied)." if coverage["unmet_properties"]
                 else "No request that should have been denied was admitted.")
    lines += ["", "### Pending rows (13d-1b)", "", ", ".join(coverage["pending_13d_1b"]) + "." if coverage["pending_13d_1b"] else "None.",
              "", "### Gap table", "", "| Gap | Status | Reason | Rows that ran | Static rows |", "| --- | --- | --- | --- | --- |"]
    for gap in record["gaps"]:
        lines.append(f"| {gap['id']} | {escape(gap['status'])} | {escape(gap['reason'])} | {escape(', '.join(gap.get('rows_that_ran', [])) or 'none')} | "
                     f"{escape(', '.join(gap.get('static', [])) or 'none')} |")
    return "\n".join(lines) + "\n"


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
    if record.get("schema") == AUTHZ_SCHEMA:
        return render_authz_tables(record)
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
    parser.add_argument("--document", type=Path, default=None,
                        help="the Markdown file whose generated tables to rewrite (default: the 20261116 record's, unless a check flag is given)")
    parser.add_argument("--check-s13d-coverage", action="store_true",
                        help="fail unless every attack of the 13d map has at least one row with a denied_by value; unmet properties are reported")
    parser.add_argument("--check", action="store_true", help="verify an AUTHZ record (header, vocabulary, coverage, cross-references, totals)")
    args = parser.parse_args(argv)
    record = json.loads(args.record.read_text(encoding="utf-8"))
    checking = args.check_s13d_coverage or args.check
    status = 0
    if args.check_s13d_coverage:
        coverage = s13d_coverage(record)
        for attack in coverage["attacks"]:
            print(f"{'ok  ' if attack['covered'] else 'FAIL'} {attack['attack']}: {', '.join(attack['counted']) or 'no row'} [{', '.join(attack['denied_by'])}]"
                  + (f" (cross-reference {', '.join(attack['cross_references'])})" if attack["cross_references"] else ""))
        for problem in coverage["problems"]:
            print(f"problem: {problem}")
        if coverage["unmet_properties"]:
            print(f"unmet properties (not_denied): {', '.join(coverage['unmet_properties'])}")
        if coverage["pending_13d_1b"]:
            print(f"pending 13d-1b: {', '.join(coverage['pending_13d_1b'])}")
        status = 0 if coverage["ok"] else 1
    if args.check:
        problems = check_authz_record(record)
        for problem in problems:
            print(f"problem: {problem}")
        print("record check: " + ("ok" if not problems else f"{len(problems)} problem(s)"))
        status = status or (1 if problems else 0)
    document = args.document
    if document is None and not checking:
        document = ROOT / "paper/research/update-security-20261116.md"
    if document is not None:
        document.write_text(splice(document.read_text(encoding="utf-8"), render_tables(record)), encoding="utf-8", newline="\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
