"""E2EEVADE record builder and checker (Stage 13b).

Builds ``paper/research/e2e-evasion-<date>.{md,json}`` from the per-row output of
``e2e_evasion.py run`` and the in-process detector scores, and re-derives every aggregate from the
per-row data::

    e2e_evasion_report.py --build --rows ROWS[,ROWS] --detector SCORES --detector-meta META --plan PLAN --run-meta META
                          --date YYYYMMDD --out-json J [--out-md M] [--out-summary S]
    e2e_evasion_report.py --check J [--md M] [--require-attended]

``--check`` exits 0 only when:

* the record header has every required field and a scope label from the vocabulary;
* every browser (chrome, edge, firefox) was run or is listed with a reason;
* ``host_guard.outside_lookups`` is 0 and equals the sum of its recorded host lists;
* every row has the full row fields, ids only, an explicit non-empty layer list equal to the
  configured set, and the executed layers of the configured set;
* ``e2e_outcome`` of every row and every aggregate of every group re-derive from the rows (the
  Stage 3 functions, on the pairs that both arms scored);
* the Markdown, when given or present beside the JSON, equals the Markdown rendered from the JSON.

``--require-attended`` additionally requires attended rows with the full row fields and reports
each disagreement with the headless rows of the same browser.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import e2e_evasion as e2e  # noqa: E402

REQUIRED_BROWSERS = ("chrome", "edge", "firefox")
SCOPE_VOCABULARY = (
    "product pipeline (in-process)",
    "product pipeline (installed extension, end to end)",
    "LLM-only (semantic)",
    "update path (Rust V3)",
    "transport (Rust)",
    "human ground truth",
)
HEADER_FIELDS = ("schema", "study_id", "chain", "build", "host", "run_dates", "commands", "scope_label",
                 "not_established", "user_actions")
CHAIN_FIELDS = ("threat", "defense", "experiment", "metric", "evidence")
BUILD_FIELDS = ("branch", "sha", "clean")
FORBIDDEN_KEYS = {"text", "prompt", "body", "notes"}
DETECTOR_FIELDS = ("action", "failed_closed", "layers_executed")

CHAIN = {
    "threat": "A user or a tool rewrites a prompt to evade detection.",
    "defense": "In-page interception, then detection, then BLOCK or WARN.",
    "experiment": "Declared transforms sent through the installed extension to the synthetic receiver.",
    "metric": "Conditional and unconditional end-to-end ASR, beside the detector-level ASR on the same applicable pairs.",
}
NOT_ESTABLISHED = [
    "Behaviour against a real provider: only the synthetic loopback receiver was used (decision D7).",
    "Rewrites beyond the declared transforms and templates, which are fixed and limited.",
    "Attended, headed-browser behaviour, which only the Stage 13b-3 subset confirms.",
    "Results for any extension or runtime build other than build.sha.",
    "The end-to-end and detector-level denominators differ: each is its own baseline-protected set.",
]
USER_ACTIONS = ["none for the headless run; the attended subset (13b-3) is a user stage"]


def group_key(browser: str, attended: bool) -> str:
    return f"{browser}|{'attended' if attended else 'headless'}"


def row_groups(rows: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(group_key(row["browser"], row["attended"]), []).append(row)
    return dict(sorted(groups.items()))


def compute_results(rows: list[dict], seed_groups: dict[str, str]) -> dict:
    return {key: e2e.score_group(group, seed_groups) for key, group in row_groups(rows).items()}


def _norm(value):
    return json.loads(json.dumps(value, sort_keys=True))


def git_build(repo: Path) -> dict:
    def run(*args: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False).stdout.strip()
    return {"branch": run("rev-parse", "--abbrev-ref", "HEAD"), "sha": run("rev-parse", "HEAD"),
            "clean": not run("status", "--porcelain", "--untracked-files=no")}


def observed_settings(rows: list[dict]) -> dict:
    """WARN masking as the run observed it: any MASKED_REQUEST_HANDED_OFF disposition means it was on."""
    masked = sum(1 for r in rows if r.get("request_disposition") == "MASKED_REQUEST_HANDED_OFF")
    return {"warn_masking": masked > 0, "masked_request_handed_off_rows": masked,
            "rows_with_disposition": sum(1 for r in rows if r.get("request_disposition")),
            "source": "derived from the request dispositions of the rows; the disposable profile uses DEFAULT_SETTINGS"}


def build_record(rows: list[dict], detector: dict[str, dict], plan: dict, meta: dict, date: str,
                 build: dict | None = None, detector_meta: dict | None = None) -> dict:
    """Assemble the record from rows, detector records, the run plan and the run meta."""
    rows = [dict(r) for r in rows]
    e2e.attach_detector(rows, detector)
    e2e.annotate_outcomes(rows)
    rows.sort(key=lambda r: (r["browser"], r["attended"], r["seed_id"], r["variant"]))
    dates = sorted({meta[k][:10].replace("-", "") for k in ("started_utc", "finished_utc") if meta.get(k)})
    study_id = f"{e2e.STUDY_PREFIX}-{date}"
    browsers = []
    for entry in meta["browsers"]:
        keep = ("key", "browser", "status", "reason", "browser_version", "file_version", "headless", "attended",
                "rows_written", "preflight", "foreign_requests_measured")
        browsers.append({k: entry[k] for k in keep if k in entry})
    seed_groups = plan["seed_group"]
    return {
        "schema": e2e.SCHEMA, "study_id": study_id,
        "chain": dict(CHAIN, evidence=study_id),
        "build": build or {"branch": meta.get("branch"), "sha": meta.get("revision"),
                           "clean": not meta.get("worktree_dirty", True)},
        "host": meta.get("host", {}), "run_dates": dates, "commands": list(meta.get("commands", [])),
        "scope_label": e2e.SCOPE_LABEL,
        "arms": {"end_to_end": {"scope_label": e2e.SCOPE_LABEL}, "detector_level": {"scope_label": e2e.DETECTOR_SCOPE_LABEL}},
        "not_established": list(NOT_ESTABLISHED), "user_actions": list(USER_ACTIONS),
        "layers": list(meta["layers"]),
        "semantic_model": {
            "model_id": (meta.get("stack") or {}).get("model_id", e2e.STACK_MODEL_ID),
            "e2e_artifact_checksum": meta.get("expected_checksum"),
            "detector_artifact_checksum": ((detector_meta or {}).get("identity") or {}).get("artifact_checksum"),
            "stack": meta.get("stack")},
        "settings": observed_settings(rows),
        "inputs": {k: plan[k] for k in (
            "frozen_set_sha256", "f4_source_sha256", "stage3_transform_module_sha256", "template_sha256",
            "run_set_sha256", "sample_seed", "n_seed", "rows_by_source", "excluded_ids", "variants",
            "applicable_by_variant", "e2e_generator_revision", "stage3_generator_revision")},
        "sample": {"seed_ids": plan["seed_ids"], "seed_group": seed_groups, "seed_source": plan["seed_source"]},
        "extension_build": meta.get("extension_build"),
        "browsers": browsers, "host_guard": meta["host_guard"],
        "leftover_ports_after_cleanup": meta.get("leftover_ports_after_cleanup", []),
        "rows": rows, "results": compute_results(rows, seed_groups),
    }


# ---------------------------------------------------------------- rendering
def fmt_rate(rate: dict | None) -> str:
    if not rate or rate.get("n") in (None, 0):
        return "n/a (0 pairs)"
    low, high = rate.get("wilson_low"), rate.get("wilson_high")
    return f"{rate['k']}/{rate['n']} = {rate['rate'] * 100:.1f}% (Wilson 95% {low * 100:.1f}-{high * 100:.1f}%)"


def _summary_line(label: str, s: dict) -> str:
    return (f"| {label} | {s['applicable']} | {s['protected_pairs']} | {s['evaded']} | {fmt_rate(s['asr_conditional'])} | "
            f"{fmt_rate(s['asr_unconditional'])} | {s['downgraded_block_to_warn']}/{s['block_pairs']} | "
            f"{s['failed_closed_after']} |")


TABLE_HEAD = ("| Group | Applicable | Protected | Evaded | Conditional ASR | Unconditional ASR | BLOCK to WARN | Fail-closed |\n"
              "| --- | --- | --- | --- | --- | --- | --- | --- |")


def render_markdown(record: dict) -> str:
    """The Markdown of the record; every number is read from the JSON."""
    lines = [f"# {record['study_id']}: end-to-end evasion through the installed extension", "",
             f"Scope: {record['scope_label']}. Detector-level arm: {record['arms']['detector_level']['scope_label']}.", "",
             "## Header", "",
             f"- Build: branch {record['build']['branch']}, sha {record['build']['sha']}, clean {record['build']['clean']}",
             f"- Run dates: {', '.join(record['run_dates'])}",
             f"- Layers requested and asserted: {', '.join(record['layers'])}",
             f"- Semantic model: {record['semantic_model']['model_id']}, artifact checksum "
             f"{record['semantic_model']['e2e_artifact_checksum']} (detector arm "
             f"{record['semantic_model']['detector_artifact_checksum']}), served by the local Docker model-streaming stack",
             f"- WARN masking in the disposable profile: {'on' if record['settings']['warn_masking'] else 'off'}",
             f"- Threat: {record['chain']['threat']}", f"- Defense: {record['chain']['defense']}",
             f"- Experiment: {record['chain']['experiment']}", f"- Metric: {record['chain']['metric']}",
             "", "## Inputs", ""]
    inputs = record["inputs"]
    lines += [f"- Frozen Stage 3 set sha256: {inputs['frozen_set_sha256']}",
              f"- F4 source sha256: {inputs['f4_source_sha256']}",
              f"- Template file sha256: {inputs['template_sha256']}",
              f"- Seeds: {inputs['n_seed']} (sample seed {inputs['sample_seed']}), by source: "
              + ", ".join(f"{k} {v}" for k, v in sorted(inputs["rows_by_source"].items())),
              "", "## Browsers", "", "| Browser | Status | Version | Reason |", "| --- | --- | --- | --- |"]
    for entry in record["browsers"]:
        lines.append(f"| {entry['key']} | {entry['status']} | {entry.get('browser_version') or ''} | {entry.get('reason') or ''} |")
    guard = record["host_guard"]
    lines += ["", f"Outside lookups: {guard['outside_lookups']} (receiver foreign hosts {len(guard['foreign_host_requests'])}, "
              f"browser foreign requests {len(guard['driver_foreign_requests'])}, "
              f"non-loopback connections {len(guard['outbound_non_loopback_connections'])}).", ""]
    for key, result in sorted(record["results"].items()):
        lines += [f"## Results: {key}", "",
                  f"Seeds {result['seeds']} ({result['seeds_scored_in_both_arms']} scored in both arms); applicable pairs sent "
                  f"{result['applicable_pairs_sent']}, scored in both arms {result['pairs_scored_in_both']}, excluded "
                  f"{result['pairs_excluded']}.", "",
                  "Each arm's denominator is its own baseline-protected set: "
                  f"end to end {result['arms']['end_to_end']['protected_baselines']} seeds, "
                  f"detector level {result['arms']['detector_level']['protected_baselines']} seeds.", "",
                  TABLE_HEAD]
        for arm in ("end_to_end", "detector_level"):
            level = result["arms"][arm]["action_level"]
            lines.append(_summary_line(f"{arm}, all families", level["overall"]))
            lines.append(_summary_line(f"{arm}, without value-removing", level["overall_excluding_value_removing"]))
        lines += ["", "Fail-closed rows are counted separately and never as protection. The detection-level reading "
                  "(a fail-closed answer counted as a missed detection):", "", TABLE_HEAD]
        for arm in ("end_to_end", "detector_level"):
            level = result["arms"][arm]["detection_level"]
            lines.append(_summary_line(f"{arm}, all families", level["overall"]))
            lines.append(_summary_line(f"{arm}, without value-removing", level["overall_excluding_value_removing"]))
        for scope, label in (("all_families", "all families"), ("excluding_value_removing", "without value-removing")):
            p = result["paired_conditional"][scope]
            lines += ["", f"Paired ({label}): {p['protected_in_both']} pairs protected in both arms; evaded end to end only "
                      f"{p['evaded_e2e_only']}, detector only {p['evaded_detector_only']}, both {p['evaded_both']}, neither "
                      f"{p['evaded_neither']}; exact McNemar p = {p['exact_mcnemar_p']:.4g}; conditional ASR end to end "
                      f"{fmt_rate(p['asr_conditional_e2e'])}, detector {fmt_rate(p['asr_conditional_detector'])}."]
        lines += ["", "By family, end to end (action level):", "", TABLE_HEAD]
        for family, summary in sorted(result["arms"]["end_to_end"]["action_level"]["by_family"].items()):
            lines.append(_summary_line(family, summary))
        lines += ["", "By family, detector level (action level):", "", TABLE_HEAD]
        for family, summary in sorted(result["arms"]["detector_level"]["action_level"]["by_family"].items()):
            lines.append(_summary_line(family, summary))
        lines += ["", "Value-removing families (indirect_pointer) are reported separately above; a delivery of one is not a "
                  "leak of the original value.", "",
                  "Excluded pairs by reason: " + (", ".join(f"{k} {v}" for k, v in sorted(result["excluded_by_reason"].items())) or "none")
                  + ".", "",
                  "Row outcomes: " + ", ".join(f"{k} {result['e2e_outcomes'][k]}" for k in e2e.E2E_OUTCOMES) + ".",
                  "Anomalies: " + ", ".join(f"{k} {v}" for k, v in sorted(result["anomalies"].items())) + "."]
        lines.append("")
    lines += ["## Not established", ""] + [f"- {item}" for item in record["not_established"]]
    lines += ["", "## User actions", ""] + [f"- {item}" for item in record["user_actions"]]
    return "\n".join(lines) + "\n"


def render_summary(record: dict) -> str:
    """The short ``docs/experiments`` summary; it links to the full record by stem."""
    stem = f"e2e-evasion-{record['study_id'].split('-', 1)[1]}"
    lines = [f"# {record['study_id']}", "", f"Full record: paper/research/{stem}.md and paper/research/{stem}.json.", "",
             f"Scope: {record['scope_label']}; build {record['build']['sha']} on {record['build']['branch']}.", ""]
    for key, result in sorted(record["results"].items()):
        e2e_level = result["arms"]["end_to_end"]["action_level"]["overall_excluding_value_removing"]
        det_level = result["arms"]["detector_level"]["action_level"]["overall_excluding_value_removing"]
        lines.append(f"- {key}: end-to-end conditional ASR {fmt_rate(e2e_level['asr_conditional'])}; "
                     f"detector level {fmt_rate(det_level['asr_conditional'])} (without value-removing families).")
    return "\n".join(lines) + "\n"


def dumps_record(record: dict) -> str:
    """JSON with the header indented and one row per line (valid JSON)."""
    rest = {k: v for k, v in record.items() if k != "rows"}
    head = json.dumps(rest, indent=1, sort_keys=True, ensure_ascii=False)
    rows = ",\n".join(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for r in record["rows"])
    return head[:-2] + ',\n "rows": [\n' + rows + "\n ]\n}\n"


# ---------------------------------------------------------------- the check
def _forbidden_keys(node, path: str, found: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key.strip().lower() in FORBIDDEN_KEYS:
                found.append(f"{path}/{key}")
            _forbidden_keys(value, f"{path}/{key}", found)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _forbidden_keys(value, f"{path}[{index}]", found)


def _check_row(row: dict, expected: tuple[str, ...], index: int) -> list[str]:
    problems = []
    missing = [f for f in e2e.EXPECTED_ROW_FIELDS + e2e.EXTRA_ROW_FIELDS if f not in row]
    if missing:
        return [f"row {index}: missing fields {missing}"]
    if row["scope_label"] != e2e.SCOPE_LABEL:
        problems.append(f"row {index}: scope_label {row['scope_label']!r}")
    if row["e2e_outcome"] not in (None, *e2e.E2E_OUTCOMES):
        problems.append(f"row {index}: e2e_outcome {row['e2e_outcome']!r}")
    if not row["error"]:
        if row["decision"] not in e2e.ACTIONS:
            problems.append(f"row {index}: decision {row['decision']!r}")
        if sorted(row["layers_requested"]) != sorted(expected) or not row["layers_requested"]:
            problems.append(f"row {index}: layers_requested {row['layers_requested']} differ from {list(expected)}")
        if sorted(row["layers_executed"]) != sorted(expected):
            problems.append(f"row {index}: layers_executed {list(row['layers_executed'])} differ from {list(expected)}")
    detector = row["detector_level"]
    if detector is not None:
        if any(f not in detector for f in DETECTOR_FIELDS):
            problems.append(f"row {index}: detector_level lacks fields")
        elif sorted(detector["layers_executed"]) != sorted(expected):
            problems.append(f"row {index}: detector layers {list(detector['layers_executed'])} differ from {list(expected)}")
    return problems


def attended_report(rows: list[dict]) -> dict:
    headless = {(r["seed_id"], r["variant"], r["browser"]): e2e.e2e_action(r) for r in rows if not r["attended"]}
    attended = [r for r in rows if r["attended"]]
    disagreements = []
    for row in attended:
        key = (row["seed_id"], row["variant"], row["browser"])
        if key not in headless:
            disagreements.append({"seed_id": key[0], "variant": key[1], "browser": key[2], "kind": "no_headless_row"})
        elif headless[key] != e2e.e2e_action(row):
            disagreements.append({"seed_id": key[0], "variant": key[1], "browser": key[2], "kind": "different_action",
                                  "headless": headless[key], "attended": e2e.e2e_action(row)})
    return {"attended_rows": len(attended), "disagreements": disagreements}


def check_record(record: dict, md_text: str | None = None, require_attended: bool = False) -> list[str]:
    problems: list[str] = []
    for field in HEADER_FIELDS:
        if field not in record:
            problems.append(f"missing header field {field}")
    if problems:
        return problems
    problems += [f"chain lacks {f}" for f in CHAIN_FIELDS if f not in record["chain"]]
    problems += [f"build lacks {f}" for f in BUILD_FIELDS if f not in record["build"]]
    if record["scope_label"] not in SCOPE_VOCABULARY:
        problems.append(f"scope_label {record['scope_label']!r} is not in the vocabulary")
    for arm, body in record.get("arms", {}).items():
        if body.get("scope_label") not in SCOPE_VOCABULARY:
            problems.append(f"arm {arm} has scope_label {body.get('scope_label')!r}")
    model = record.get("semantic_model") or {}
    if not model.get("e2e_artifact_checksum") or model.get("e2e_artifact_checksum") != model.get("detector_artifact_checksum"):
        problems.append("semantic_model: the end-to-end and detector arms are not both checked against one artifact checksum")
    settings = record.get("settings") or {}
    derived = observed_settings(record.get("rows", []))
    if settings != derived:
        problems.append("settings do not re-derive from the row dispositions")
    if derived["warn_masking"] or settings.get("warn_masking") is not False:
        problems.append("settings.warn_masking: a masked hand-off was observed (or it is not recorded false)")
    leaks: list[str] = []
    _forbidden_keys(record, "", leaks)
    problems += [f"forbidden prompt-bearing key {p}" for p in leaks]
    try:
        expected = e2e.parse_layers(record["layers"])
    except e2e.HarnessError as exc:
        return problems + [f"layers: {exc}"]
    rows = record["rows"]
    entries = {b["key"]: b for b in record["browsers"]}
    for key in REQUIRED_BROWSERS:
        entry = entries.get(key)
        if entry is None:
            problems.append(f"browser {key} is neither run nor listed with a reason")
        elif entry["status"] != "run" and not entry.get("reason"):
            problems.append(f"browser {key} is {entry['status']} without a reason")
        elif entry["status"] == "run" and not any(r["browser"] == key for r in rows):
            problems.append(f"browser {key} is marked run but has no rows")
    for key in {r["browser"] for r in rows}:
        if entries.get(key, {}).get("status") != "run":
            problems.append(f"rows exist for browser {key}, which is not marked run")
    guard = record["host_guard"]
    recorded = (len(guard["foreign_host_requests"]) + len(guard["driver_foreign_requests"])
                + len(guard["outbound_non_loopback_connections"]))
    if guard["outside_lookups"] != recorded:
        problems.append(f"host_guard.outside_lookups {guard['outside_lookups']} differs from its recorded lists ({recorded})")
    if guard["outside_lookups"] != 0:
        problems.append(f"host_guard.outside_lookups is {guard['outside_lookups']}, not 0")
    for index, row in enumerate(rows):
        problems += _check_row(row, expected, index)
    if problems:
        return problems
    rederived = e2e.annotate_outcomes([dict(r) for r in rows])
    for index, (stored, fresh) in enumerate(zip(rows, rederived)):
        if stored["e2e_outcome"] != fresh["e2e_outcome"]:
            problems.append(f"row {index}: stored e2e_outcome {stored['e2e_outcome']!r} re-derives as {fresh['e2e_outcome']!r}")
    fresh_results = compute_results(rows, record["sample"]["seed_group"])
    if _norm(fresh_results) != _norm(record["results"]):
        for key in sorted(set(fresh_results) | set(record["results"])):
            if _norm(fresh_results.get(key)) != _norm(record["results"].get(key)):
                problems.append(f"results for {key} do not re-derive from the rows")
    if md_text is not None and md_text != render_markdown(record):
        problems.append("the Markdown differs from the Markdown rendered from the JSON")
    if require_attended:
        report = attended_report(rows)
        if report["attended_rows"] == 0:
            problems.append("--require-attended: the record has no attended rows")
    return problems


def cmd_check(args) -> int:
    path = Path(args.check)
    record = json.loads(path.read_text(encoding="utf-8"))
    md_path = Path(args.md) if args.md else path.with_suffix(".md")
    md_text = md_path.read_text(encoding="utf-8") if md_path.is_file() else None  # universal newlines fold CRLF
    problems = check_record(record, md_text, args.require_attended)
    if args.require_attended and not problems:
        report = attended_report(record["rows"])
        print(json.dumps({"attended_rows": report["attended_rows"], "disagreements": report["disagreements"]}, indent=1))
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if not problems:
        print(f"check passed: {record['study_id']}, {len(record['rows'])} rows, {len(record['results'])} groups")
    return 1 if problems else 0


def cmd_build(args) -> int:
    rows: list[dict] = []
    for name in args.rows.split(","):
        rows += e2e.read_jsonl(Path(name))
    detector = {r["vid"]: r for r in e2e.read_jsonl(Path(args.detector))}
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    meta = json.loads(Path(args.run_meta).read_text(encoding="utf-8"))
    detector_meta = json.loads(Path(args.detector_meta).read_text(encoding="utf-8")) if args.detector_meta else None
    record = build_record(rows, detector, plan, meta, args.date,
                          git_build(HERE.parent) if args.git_build else None, detector_meta)
    Path(args.out_json).write_text(dumps_record(record), encoding="utf-8", newline="\n")
    if args.out_md:
        Path(args.out_md).write_text(render_markdown(record), encoding="utf-8", newline="\n")
    if args.out_summary:
        Path(args.out_summary).write_text(render_summary(record), encoding="utf-8", newline="\n")
    print(f"wrote {args.out_json} at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", metavar="JSON")
    parser.add_argument("--md", default=None, help="Markdown to compare with the rendering (default: beside the JSON)")
    parser.add_argument("--require-attended", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--rows")
    parser.add_argument("--detector")
    parser.add_argument("--plan")
    parser.add_argument("--detector-meta", help="detector_run_meta.json of the in-process arm (artifact checksum)")
    parser.add_argument("--run-meta")
    parser.add_argument("--date")
    parser.add_argument("--out-json")
    parser.add_argument("--out-md")
    parser.add_argument("--out-summary")
    parser.add_argument("--git-build", action="store_true", help="read build.{branch,sha,clean} from git instead of the run meta")
    args = parser.parse_args(argv)
    if args.check:
        return cmd_check(args)
    if args.build:
        missing = [n for n in ("rows", "detector", "plan", "run_meta", "date", "out_json") if not getattr(args, n)]
        if missing:
            parser.error(f"--build needs {missing}")
        return cmd_build(args)
    parser.error("give --check or --build")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
