"""Stage 13c report: the active attacks on the V3 guarded update path (record ``V3UPDATK``).

The row manifest ``rust/services/param-update/tests/s13c_rows.json`` lists every attack variant. The Rust tests
(``s13c_update_attacks`` in param-update and ``s13c_client_admission`` in runtime-supervisor) write one row per variant when
``S13C_OUT`` is set, and the container leg of 13c-2 adds ``container`` rows. This script re-derives from those rows everything
the record states.

Modes:

* ``--check RECORD``: judge a V3UPDATK record (a JSON object with a ``rows`` list and an ``aggregates`` object). It fails when a
  manifest id has no row, when a row has no manifest id, when a ``wire_path: true`` variant that is not CI-only has neither a
  ``container`` row (with the version model-streaming served after the attack) nor a ``not_run_reason``, when a class has no row,
  when a row does not name its rejecting check or does not record the active model before and after, when a row's
  ``property_met`` differs from what its before and after states show, or when an aggregate differs from the rows.
* ``--ci-rows FILE ...``: judge the rows the two CI tests wrote (every manifest id with a ``ci`` leg has exactly one ``ci`` row).
* ``--check-manifest``: judge the manifest alone.
* ``--validate-allocations FILE``: judge a ``S13C_ALLOCATIONS`` file (the format of ``v3_allocations``, defined in 13c-1).
* ``--assemble HEADER --rows FILE ... --out RECORD [--markdown MD]`` (13c-2): join the header and the rows of the legs into a
  record, compute the aggregates, judge it as ``--check`` does and write it (with its Markdown) only when it passes.

"Unchanged" is the authority, not the blob directory: the ``current`` row, the number of ``versions``, the ``publications`` (count and
highest sequence), the version model-streaming serves and the client's high-water mark. Orphan blobs are reported and never counted.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "rust" / "services" / "param-update" / "tests" / "s13c_rows.json"

SCHEMA = "v3-update-attacks/1"
SCOPE_LABEL = "update path (Rust V3)"
ATTACK_CLASSES = [*range(1, 12), "S"]
EXPECTED = ("rejected_unchanged", "noop_unchanged", "applied_recovered", "accepted_by_design")
LEGS = ("ci", "real", "container")
CHAINS = ("main", "no_publisher")
MANIFEST_SURFACES = ("param-update", "model-streaming", "client", "store")
ROW_SURFACES = ("stage", "commit", "rollback", "serve", "client")
MANIFEST_KEYS = {"id", "attack_class", "expected", "chain", "surface", "wire_path", "legs", "ci_only_reason"}
HEADER_KEYS = (
    "schema",
    "study_id",
    "chain",
    "build",
    "host",
    "run_dates",
    "commands",
    "scope_label",
    "not_established",
    "user_actions",
)
ROW_KEYS = {
    "id",
    "attack_class",
    "variant",
    "combined",
    "chain",
    "leg",
    "surface",
    "identity",
    "attempted",
    "expected",
    "observed",
    "rejecting_check",
    "active_before",
    "active_after",
    "orphan_blobs",
    "property_met",
    "not_run_reason",
}
ATTEMPTED_KEYS = {"request_id", "model_id", "expected_base", "candidate_sha", "mutation"}
OBSERVED_KEYS = {"grpc_code", "receipt_status", "receipt_reason", "message"}
STATE_KEYS = {"store_current", "versions_count", "max_sequence", "served_manifest", "client_mark"}
# What a row may carry besides the interface: the scope label, the publication count and the evidence of one row's own property.
OPTIONAL_ROW_KEYS = {"scope_label", "race", "crash", "label", "updates_applied", "per_update_l2", "receipt_status_stored", "allowance", "eligible_rows"}
ALLOCATION_KEYS = (
    "request_id",
    "cycle",
    "model_id",
    "stage",
    "attempt",
    "sampler",
    "seed",
    "expected_base",
    "source_commitment",
    "state",
)
SAMPLERS = (
    "existing_taxonomy_benign_common_frozen_stream_v1",
    "audience_common_frozen_stream_v1",
)
MODELS = ("privoke-v3-efficient", "privoke-v3-balanced", "privoke-v3-quality")
SHA = re.compile(r"^[0-9a-f]{64}$")
# The one fail-closed value an at-rest fault may leave in place of the served version (C9f-serve only).
AT_REST_REFUSAL = "refused:DATA_LOSS"


def load_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_manifest(path: Path = DEFAULT_MANIFEST) -> list[dict[str, Any]]:
    return load_json(path)


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def check_manifest(manifest: Any) -> list[str]:
    """The manifest alone: every field, every enumeration and the CI-only rules."""
    if not isinstance(manifest, list) or not manifest:
        return ["the manifest is not a non-empty list"]
    errors: list[str] = []
    seen: set[str] = set()
    for row in manifest:
        if not isinstance(row, dict) or set(row) != MANIFEST_KEYS:
            errors.append(f"manifest row has unknown or missing fields: {row!r}")
            continue
        ident = row["id"]
        if not isinstance(ident, str) or not ident or ident in seen:
            errors.append(f"manifest id {ident!r} is empty or listed twice")
        seen.add(str(ident))
        if row["attack_class"] not in ATTACK_CLASSES:
            errors.append(f"{ident}: attack_class {row['attack_class']!r}")
        if row["expected"] not in EXPECTED:
            errors.append(f"{ident}: expected {row['expected']!r}")
        if row["chain"] not in CHAINS:
            errors.append(f"{ident}: chain {row['chain']!r}")
        if row["surface"] not in MANIFEST_SURFACES:
            errors.append(f"{ident}: surface {row['surface']!r}")
        if not isinstance(row["wire_path"], bool):
            errors.append(f"{ident}: wire_path is not a boolean")
        legs = row["legs"]
        if not isinstance(legs, list) or "ci" not in legs or any(leg not in ("ci", "container") for leg in legs):
            errors.append(f"{ident}: legs must hold ci, and may add container")
            continue
        ci_only = legs == ["ci"]
        reason = row["ci_only_reason"]
        if not isinstance(reason, str) or bool(reason) != ci_only:
            errors.append(f"{ident}: a CI-only row carries a ci_only_reason, and only a CI-only row does")
        if row["wire_path"] is False and not ci_only:
            errors.append(f"{ident}: a row without a wire path has no container leg")
        if row["wire_path"] is True and row["surface"] not in ("param-update", "model-streaming"):
            errors.append(f"{ident}: a wire_path row has the surface param-update or model-streaming")
    classes = {row.get("attack_class") for row in manifest if isinstance(row, dict)}
    for attack_class in ATTACK_CLASSES:
        if attack_class not in classes:
            errors.append(f"no manifest row of attack class {attack_class}")
    return errors


def check_allocations(items: Any) -> list[str]:
    """``S13C_ALLOCATIONS``: an array of objects that mirror the ``v3_allocations`` columns, nothing more and nothing less."""
    if not isinstance(items, list):
        return ["the allocations are not a JSON array"]
    errors: list[str] = []
    for index, item in enumerate(items):
        where = f"allocation {index}"
        if not isinstance(item, dict):
            errors.append(f"{where}: not an object")
            continue
        if set(item) != set(ALLOCATION_KEYS):
            errors.append(f"{where}: unknown or missing fields {sorted(set(item) ^ set(ALLOCATION_KEYS))}")
            continue
        request_id = item["request_id"]
        if not isinstance(request_id, str) or not 0 < len(request_id) <= 200:
            errors.append(f"{where}: request_id is not a bounded identity")
        if not _is_count(item["cycle"]) or not _is_count(item["attempt"]):
            errors.append(f"{where}: cycle and attempt are counts")
        if item["model_id"] not in MODELS:
            errors.append(f"{where}: model_id is not a V3 tier")
        if item["stage"] not in ("heads", "full_encoder"):
            errors.append(f"{where}: stage is heads or full_encoder")
        if item["sampler"] not in SAMPLERS:
            errors.append(f"{where}: sampler is not a frozen release")
        if not _is_count(item["seed"]) or item["seed"] > 0xFFFFFFFF:
            errors.append(f"{where}: seed is a 32-bit count")
        for key in ("expected_base", "source_commitment"):
            if not isinstance(item[key], str) or not SHA.match(item[key]):
                errors.append(f"{where}: {key} is 64 lowercase hexadecimal characters")
        if item["state"] != "allocated":
            errors.append(f"{where}: state must be allocated (candidate and reason are written only when a request settles)")
    return errors


def _state_equal(before: dict[str, Any], after: dict[str, Any], key: str, *, fail_closed: bool = False) -> bool:
    if key == "served_manifest" and fail_closed and after.get(key) == AT_REST_REFUSAL:
        return True
    return before.get(key) == after.get(key)


def derive_property(row: dict[str, Any]) -> bool | None:
    """What the row's before and after states show for its expected outcome (``None`` for a row that did not run)."""
    if row.get("not_run_reason"):
        return None
    before, after, expected = row["active_before"], row["active_after"], row["expected"]
    if expected in ("rejected_unchanged", "noop_unchanged"):
        race = row.get("race")
        if race is not None:
            # Two candidates raced on one base: exactly one was applied and signed, and the loser left nothing.
            return (
                race.get("applied") == 1
                and after.get("publications_count") == before.get("publications_count", 0) + 1
                and after.get("max_sequence") == before.get("max_sequence", 0) + 1
                and after.get("served_manifest") == after.get("store_current")
                and row["observed"].get("receipt_reason") == "stale_base"
            )
        unchanged = all(
            _state_equal(before, after, key, fail_closed=row["id"] == "C9f-serve")
            for key in (*sorted(STATE_KEYS), "publications_count")
        )
        return unchanged
    changed = after.get("store_current") not in (None, before.get("store_current"))
    if expected == "applied_recovered":
        # Applied before the crash; after the restart the authority and the served version agree on the new complete version.
        return changed and after.get("served_manifest") == after.get("store_current")
    return changed and after.get("served_manifest") == after.get("store_current")


def _check_state(where: str, state: Any) -> list[str]:
    if not isinstance(state, dict) or not STATE_KEYS <= set(state):
        return [f"{where}: records {sorted(STATE_KEYS)}"]
    return []


def check_observed(row: dict[str, Any]) -> list[str]:
    """Tie what was observed to what was expected: the receipt, the call and the named rejecting check."""
    if row.get("not_run_reason") or not isinstance(row["observed"], dict) or not isinstance(row["rejecting_check"], dict):
        return []
    ident, expected, observed = row["id"], row["expected"], row["observed"]
    status = observed.get("receipt_status")
    errors: list[str] = []
    if expected == "rejected_unchanged" and status == "applied":
        errors.append(f"{ident}: a rejected row cannot carry an applied receipt")
    if expected in ("noop_unchanged", "accepted_by_design"):
        if row["surface"] in ("commit", "rollback"):
            if status != "applied":
                errors.append(f"{ident}: {expected} requires an applied receipt, observed {status!r}")
        elif observed.get("grpc_code") != "OK":
            errors.append(f"{ident}: {expected} requires an OK call, observed {observed.get('grpc_code')!r}")
    reason, named = observed.get("receipt_reason"), row["rejecting_check"].get("reason")
    if reason and named and reason != named:
        errors.append(f"{ident}: the receipt reason {reason!r} differs from the rejecting check's {named!r}")
    return errors


def check_row(row: Any, manifest: dict[str, dict[str, Any]]) -> list[str]:
    """One row against its interface and its manifest entry."""
    if not isinstance(row, dict):
        return [f"row is not an object: {row!r}"]
    ident = row.get("id")
    missing = ROW_KEYS - set(row)
    unknown = set(row) - ROW_KEYS - OPTIONAL_ROW_KEYS
    if missing or unknown:
        return [f"{ident}: missing fields {sorted(missing)}, unknown fields {sorted(unknown)}"]
    errors: list[str] = []
    entry = manifest.get(ident)
    if entry is None:
        return [f"{ident}: the row has no manifest id"]
    for key in ("attack_class", "expected", "chain"):
        if row[key] != entry[key]:
            errors.append(f"{ident}: {key} {row[key]!r} differs from the manifest's {entry[key]!r}")
    if row["leg"] not in LEGS:
        errors.append(f"{ident}: leg {row['leg']!r}")
    if row["leg"] == "container" and "container" not in entry["legs"]:
        errors.append(f"{ident}: the manifest lists no container leg for it")
    if row["surface"] not in ROW_SURFACES:
        errors.append(f"{ident}: surface {row['surface']!r}")
    if row.get("scope_label", SCOPE_LABEL) != SCOPE_LABEL:
        errors.append(f"{ident}: scope_label must be {SCOPE_LABEL!r}")
    if not isinstance(row["combined"], bool) or not isinstance(row["variant"], str) or not isinstance(row["identity"], str):
        errors.append(f"{ident}: combined, variant and identity have the interface types")
    if not isinstance(row["attempted"], dict) or set(row["attempted"]) != ATTEMPTED_KEYS:
        errors.append(f"{ident}: attempted records {sorted(ATTEMPTED_KEYS)}")
    if not isinstance(row["observed"], dict) or set(row["observed"]) != OBSERVED_KEYS:
        errors.append(f"{ident}: observed records {sorted(OBSERVED_KEYS)}")
    if not _is_count(row["orphan_blobs"]):
        errors.append(f"{ident}: orphan_blobs is a count")
    errors += check_observed(row)
    not_run = row["not_run_reason"]
    if not_run is not None and (not isinstance(not_run, str) or not not_run):
        errors.append(f"{ident}: not_run_reason is a non-empty text or null")
        return errors
    check = row["rejecting_check"]
    if not_run is None:
        if not isinstance(check, dict) or set(check) != {"file", "symbol", "reason"} or not all(check.get(k) for k in check):
            errors.append(f"{ident}: the row must name its rejecting check (file, symbol, reason)")
        errors += _check_state(f"{ident}: active_before", row["active_before"])
        errors += _check_state(f"{ident}: active_after", row["active_after"])
        if not errors:
            derived = derive_property(row)
            if row["property_met"] is not derived:
                errors.append(f"{ident}: property_met {row['property_met']!r} differs from the states, which show {derived!r}")
    elif row["property_met"] is not None:
        errors.append(f"{ident}: a row that did not run has no property")
    return errors


def observed_label(row: dict[str, Any]) -> str:
    """What a row observed, in one label: ``not_run``, ``applied``, ``rejected:<reason>``, ``refused:<gRPC code>``, ``client_refused``
    (a client-side check, no call) or ``ok``."""
    if row.get("not_run_reason"):
        return "not_run"
    observed = row["observed"]
    code, status, reason = observed.get("grpc_code"), observed.get("receipt_status"), observed.get("receipt_reason")
    if not code:
        # A client-side admission check: no call, only the client's refusal.
        return "client_refused"
    if code != "OK":
        return f"refused:{code}"
    if status:
        return f"{status}:{reason}" if reason else status
    return "ok"


def _counted(items) -> dict[str, int]:
    return dict(sorted(Counter(items).items()))


def aggregates(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Every aggregate the record states, from the rows alone."""
    ran = [row for row in rows if not row.get("not_run_reason")]
    legs = sorted({row["leg"] for row in rows})
    return {
        "rows": len(rows),
        "rows_run": len(ran),
        "rows_not_run": len(rows) - len(ran),
        "by_leg": _counted(row["leg"] for row in rows),
        "by_attack_class": _counted(str(row["attack_class"]) for row in rows),
        "by_expected": _counted(row["expected"] for row in rows),
        "by_leg_expected": {leg: _counted(row["expected"] for row in rows if row["leg"] == leg) for leg in legs},
        "by_leg_observed": {leg: _counted(observed_label(row) for row in rows if row["leg"] == leg) for leg in legs},
        "property_met": sum(1 for row in ran if row["property_met"] is True),
        "property_not_met": sum(1 for row in ran if row["property_met"] is not True),
        "property_by_leg": {
            leg: {
                "met": sum(1 for row in ran if row["leg"] == leg and row["property_met"] is True),
                "not_met": sum(1 for row in ran if row["leg"] == leg and row["property_met"] is not True),
                "not_run": sum(1 for row in rows if row["leg"] == leg and row.get("not_run_reason")),
            }
            for leg in legs
        },
        "orphan_blobs": sum(row["orphan_blobs"] for row in rows),
    }


def check_coverage(rows: list[dict[str, Any]], manifest: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    by_id: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_id.setdefault(row["id"], []).append(row)
    for ident in sorted(set(manifest) - set(by_id)):
        errors.append(f"{ident}: the manifest id has no row")
    for ident in sorted(set(by_id) - set(manifest)):
        errors.append(f"{ident}: the row has no manifest id")
    classes = {row["attack_class"] for row in rows}
    for attack_class in ATTACK_CLASSES:
        if attack_class not in classes:
            errors.append(f"attack class {attack_class}: no row")
    for ident, entry in manifest.items():
        if not entry["wire_path"] or entry["legs"] == ["ci"] or ident not in by_id:
            continue
        mine = by_id[ident]
        container = [row for row in mine if row["leg"] == "container"]
        if not container:
            if not any(row.get("not_run_reason") for row in mine):
                errors.append(f"{ident}: a wire_path variant needs a container row or a not_run_reason")
            continue
        for row in container:
            served = (row.get("active_after") or {}).get("served_manifest")
            if not row.get("not_run_reason") and not served:
                errors.append(f"{ident}: its container row records no served version and carries no not_run_reason")
    return errors


def check_rows(rows: Any, manifest_rows: list[dict[str, Any]]) -> list[str]:
    if not isinstance(rows, list) or not rows:
        return ["rows is not a non-empty list"]
    manifest = {row["id"]: row for row in manifest_rows}
    errors: list[str] = []
    for row in rows:
        errors += check_row(row, manifest)
    if errors:
        return errors
    return check_coverage(rows, manifest)


def check_record(record: Any, manifest_rows: list[dict[str, Any]]) -> list[str]:
    """A V3UPDATK record: the header, the rows, the coverage of the manifest and the aggregates."""
    if not isinstance(record, dict):
        return ["the record is not an object"]
    errors = [f"the record header lacks {key}" for key in HEADER_KEYS if key not in record]
    if record.get("schema") not in (None, SCHEMA) and "schema" in record:
        errors.append(f"schema must be {SCHEMA}")
    if record.get("scope_label") not in (None, SCOPE_LABEL):
        errors.append(f"scope_label must be {SCOPE_LABEL}")
    rows = record.get("rows")
    errors += check_rows(rows, manifest_rows)
    if isinstance(rows, list) and not errors:
        if record.get("aggregates") != aggregates(rows):
            errors.append(f"aggregates differ from the rows: {aggregates(rows)}")
    return errors


def check_ci_rows(files: list[Path], manifest_rows: list[dict[str, Any]]) -> list[str]:
    """The rows of the two CI tests: one ``ci`` row for every manifest id (every id has a ``ci`` leg) and every property met."""
    rows: list[dict[str, Any]] = []
    for path in files:
        loaded = load_json(path)
        if not isinstance(loaded, list):
            return [f"{path}: not a JSON array of rows"]
        rows += loaded
    errors: list[str] = []
    manifest = {row["id"]: row for row in manifest_rows}
    for row in rows:
        errors += check_row(row, manifest)
    if errors:
        return errors
    counts = Counter(row["id"] for row in rows)
    errors += [f"{ident}: {count} ci rows" for ident, count in sorted(counts.items()) if count != 1]
    errors += [f"{ident}: the manifest id has no ci row" for ident in sorted(set(manifest) - set(counts))]
    errors += [f"{row['id']}: leg is {row['leg']}, not ci" for row in rows if row["leg"] != "ci"]
    errors += [f"{row['id']}: property not met" for row in rows if row["property_met"] is not True]
    return errors


LEG_ORDER = {leg: index for index, leg in enumerate(LEGS)}


def assemble(header: dict[str, Any], row_files: list[Path], manifest_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """A V3UPDATK record: the header, every row of the legs (in manifest order, then ci, real, container) and the aggregates."""
    order = {row["id"]: index for index, row in enumerate(manifest_rows)}
    rows: list[dict[str, Any]] = []
    for path in row_files:
        loaded = load_json(path)
        if not isinstance(loaded, list):
            raise ValueError(f"{path}: not a JSON array of rows")
        rows += loaded
    rows.sort(key=lambda row: (order.get(row.get("id"), len(order)), LEG_ORDER.get(row.get("leg"), len(LEG_ORDER))))
    record = {**{key: value for key, value in header.items() if key not in ("rows", "aggregates")}, "rows": rows}
    record["aggregates"] = aggregates(rows)
    return record


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(head: list[str], body: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join(" --- " for _ in head) + "|"]
    lines += ["| " + " | ".join(_cell(item) for item in row) + " |" for row in body]
    return lines


def _counts_table(title: str, by_leg: dict[str, dict[str, int]]) -> list[str]:
    labels = sorted({label for counts in by_leg.values() for label in counts})
    legs = list(by_leg)
    body = [[label, *[by_leg[leg].get(label, 0) for leg in legs]] for label in labels]
    return [f"### {title}", "", *_table(["outcome", *legs], body), ""]


def render_markdown(record: dict[str, Any]) -> str:
    """The Markdown of a record. Every number comes from the record's JSON."""
    build, totals, chain = record.get("build", {}), record["aggregates"], record.get("chain", {})
    lines = [f"# V3 update attacks ({record.get('study_id')})", ""]
    lines += ["Rendered from the JSON record of the same name by `evaluation/v3_update_attacks_report.py --assemble`.", ""]
    lines += ["## Header", ""]
    lines += _table(
        ["field", "value"],
        [
            ["schema", record.get("schema")],
            ["study_id", record.get("study_id")],
            ["scope_label", record.get("scope_label")],
            ["build.branch", build.get("branch")],
            ["build.sha", build.get("sha")],
            ["build.clean", build.get("clean")],
            ["build.update_path", build.get("update_path")],
            ["host", "; ".join(f"{key}: {value}" for key, value in record.get("host", {}).items())],
            ["run_dates", ", ".join(record.get("run_dates", []))],
        ],
    )
    legs = build.get("legs", {})
    if legs:
        lines += ["", "### Build of each leg", ""]
        lines += _table(["leg", "build"], [[leg, text] for leg, text in legs.items()])
    real_build = build.get("real_leg_build")
    if real_build:
        lines += ["", f"Real-weight rows: build `{real_build.get('sha')}`, clean `{real_build.get('clean')}`."]
    findings = record.get("findings", [])
    if findings:
        lines += ["", "## Findings", ""]
        for finding in findings:
            fixed = f" Fixed by `{finding['fixed_by']}`." if finding.get("fixed_by") else ""
            extra = " ".join(finding.get(key, "") for key in ("fix", "container_leg_build") if finding.get(key))
            lines.append(f"- **{finding.get('id')}**: {finding.get('summary')}{fixed} {extra}".rstrip())
    lines += ["", "## Chain", ""]
    lines += _table(["link", "statement"], [[key, chain.get(key)] for key in ("threat", "defense", "experiment", "metric", "evidence")])
    lines += ["", "## Aggregates", ""]
    lines += _table(
        ["measure", "value"],
        [
            ["rows", totals["rows"]],
            ["rows run", totals["rows_run"]],
            ["rows not run", totals["rows_not_run"]],
            ["property met", totals["property_met"]],
            ["property not met", totals["property_not_met"]],
            ["orphan blobs (reported, not a change)", totals["orphan_blobs"]],
        ],
    )
    by_leg = [
        [leg, totals["by_leg"][leg], counts["met"], counts["not_met"], counts["not_run"]] for leg, counts in totals["property_by_leg"].items()
    ]
    lines += ["", *_table(["leg", "rows", "met", "not met", "not run"], by_leg), ""]
    lines += _counts_table("Rows by expected outcome", totals["by_leg_expected"])
    lines += _counts_table("Rows by observed outcome", totals["by_leg_observed"])
    controls = record.get("controls", [])
    if controls:
        lines += ["## Positive controls (container leg)", ""]
        body = [
            [item.get("control"), item.get("request_id"), observed_label({"observed": item.get("observed", {})}), item.get("met")]
            for item in controls
        ]
        lines += [*_table(["control", "request", "observed", "met"], body), ""]
    real_leg = record.get("real_leg")
    if real_leg:
        lines += ["## Real-weight leg", ""]
        lines += _table(
            ["measure", "value"],
            [
                ["genuine request", real_leg.get("genuine", {}).get("request_id")],
                ["genuine scope", real_leg.get("genuine", {}).get("scope")],
                ["retention allowance", real_leg.get("allowance")],
                ["update bound (max_update_l2)", real_leg.get("update_bound")],
                ["scorer evaluations (run 2; run 1)", f"{real_leg.get('search_evaluations')}; {real_leg.get('first_search_evaluations')}"],
                ["search seconds (run 2)", real_leg.get("search_seconds")],
            ],
        )
        chosen = real_leg.get("chosen", {})
        if chosen:
            lines += ["", *_table(["row", "guard passes", "joint (base, candidate)", "retention violations", "L2 from the pin"], [
                [role, item.get("guard_passes"), f"{item.get('base_joint')}, {item.get('candidate_joint')}", item.get("retention_violations"), item.get("l2_from_pin")]
                for role, item in sorted(chosen.items())
            ])]
        lines.append("")
    timings = record.get("fit_timings", [])
    lines += ["## Fit timings (planning only, not a result)", ""]
    if timings:
        body = [
            [item.get("request_id"), item.get("tier"), item.get("scope"), item.get("wall_seconds"), item.get("cpus"), item.get("outcome")]
            for item in timings
        ]
        lines += _table(["request", "tier", "scope", "wall seconds", "cpus", "outcome"], body)
    else:
        lines.append("No fit ran.")
    lines += ["", "## Rows", ""]
    body = []
    for row in record["rows"]:
        check = row.get("rejecting_check") or {}
        body.append(
            [
                row["id"],
                row["leg"],
                row["surface"],
                row["expected"],
                observed_label(row),
                f"{check.get('symbol', '')}: {check.get('reason', '')}" if check else "",
                "not run" if row.get("not_run_reason") else row["property_met"],
                row.get("not_run_reason") or "",
            ]
        )
    lines += _table(["id", "leg", "surface", "expected", "observed", "rejecting check", "property", "not run reason"], body)
    sections = (
        ("Harness corrections during the run", "harness_corrections"),
        ("Deviations from the plan", "deviations"),
        ("Not established", "not_established"),
        ("User actions", "user_actions"),
        ("Commands", "commands"),
    )
    times = record.get("run_times_utc")
    if times:
        lines += ["", "## Run times (UTC)", ""]
        lines += _table(["run", "step", "time"], [[run, step, when] for run, steps in times.items() for step, when in steps.items()])
    for title, key in sections:
        items = record.get(key, [])
        lines += ["", f"## {title}", ""]
        lines += [f"- `{item}`" if key == "commands" else f"- {item}" for item in items] or ["- none"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST, help="the row manifest (s13c_rows.json)")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", type=Path, metavar="RECORD", help="judge a V3UPDATK record")
    modes.add_argument("--ci-rows", type=Path, nargs="+", metavar="ROWS", help="judge the rows the CI tests wrote")
    modes.add_argument("--check-manifest", action="store_true", help="judge the manifest alone")
    modes.add_argument("--validate-allocations", type=Path, metavar="FILE", help="judge an S13C_ALLOCATIONS file")
    modes.add_argument("--assemble", type=Path, metavar="HEADER", help="assemble a record from a header and the legs' rows")
    parser.add_argument("--rows", type=Path, nargs="+", default=[], help="with --assemble: the row files of the legs")
    parser.add_argument("--out", type=Path, help="with --assemble: the record JSON to write")
    parser.add_argument("--markdown", type=Path, help="with --assemble: the record Markdown to write")
    args = parser.parse_args(argv)
    if args.assemble:
        if not args.out or not args.rows:
            parser.error("--assemble needs --rows and --out")
        manifest_rows = load_manifest(args.manifest)
        record = assemble(load_json(args.assemble), args.rows, manifest_rows)
        errors = check_manifest(manifest_rows) or check_record(record, manifest_rows)
        if not errors:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
            if args.markdown:
                args.markdown.parent.mkdir(parents=True, exist_ok=True)
                args.markdown.write_text(render_markdown(record), encoding="utf-8", newline="\n")
    elif args.validate_allocations:
        errors = check_allocations(load_json(args.validate_allocations))
    else:
        manifest_rows = load_manifest(args.manifest)
        errors = check_manifest(manifest_rows)
        if not errors and args.check:
            errors = check_record(load_json(args.check), manifest_rows)
        elif not errors and args.ci_rows:
            errors = check_ci_rows(args.ci_rows, manifest_rows)
    for error in errors:
        print(f"FAIL {error}", file=sys.stderr)
    if not errors:
        print("PASS")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
