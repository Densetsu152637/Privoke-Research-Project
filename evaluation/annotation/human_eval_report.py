#!/usr/bin/env python
"""Freeze summary, HUMANEVAL record and re-derivation check for Stage 13a (standard library only).

Sub-commands (run from the repository root):
  freeze  --labels-dir docs/research/s13a/labels --key <sampling_key.jsonl> --out docs/research/s13a/iaa.json
          Hashes the label-only CSVs and derives the agreement figures (iaa.json, the freeze record).
  build   --freeze-dir docs/research/s13a --arms <dir with arm_*.json> --date YYYYMMDD --out-dir paper/research
          [--set-manifest ...] [--resolution-counts JSON] [--familiarity JSON] [--branch B]
          Writes human-annotated-eval-<date>.{json,md} from the frozen labels and the per-arm scores.
  --check <record.json>
          Re-derives every kappa, alpha, interval, adjudication count and score from the committed label files
          and the recorded predictions, re-renders the Markdown, and exits non-zero on any difference.

Label files (no text, no notes): labels/<annotator>.csv, labels/adjudicated.csv, optional labels/pilot_<annotator>.csv.
No agent produced any label; this script only reads files that humans produced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import annotation_schema as schema  # noqa: E402
import check_order as order  # noqa: E402
import compute_iaa as iaa_tool  # noqa: E402
import score_privoke as scorer  # noqa: E402

RECORD_SCHEMA = "privoke-s13a-v1"
FREEZE_SCHEMA = "privoke-s13a-iaa-v1"
SCOPE_LABELS = {"product pipeline (in-process)", "product pipeline (installed extension, end to end)",
                "LLM-only (semantic)", "update path (Rust V3)", "transport (Rust)", "human ground truth"}
N_BOOT = 1000
METRIC_ORDER = list(scorer.METRIC_NAMES)
SEED = 20261124
STATEMENT = "No agent produced, simulated, imputed or adjudicated any label; every label was written by a person."
REQUIRED_HEADER = ["schema", "study_id", "chain", "build", "host", "run_dates", "commands", "scope_label",
                   "not_established", "user_actions"]
NOT_ESTABLISHED = [
    "Agreement at the reported rate with adjudicated labels from the stated annotators; not 'validated'.",
    "Any claim about prompts outside the quota design or about other languages.",
    "Whether annotators were fully independent of project knowledge beyond their declarations.",
]


# ---------------------------------------------------------------- label files and agreement
def label_files(labels_dir):
    """Return ({annotator: path}, {annotator: path} pilot, adjudicated path)."""
    labels_dir = Path(labels_dir)
    main, pilot, adjudicated = {}, {}, None
    for path in sorted(labels_dir.glob("*.csv")):
        stem = path.stem
        if stem == "adjudicated":
            adjudicated = path
        elif stem.startswith("pilot_"):
            pilot[stem[len("pilot_"):]] = path
        else:
            main[stem] = path
    return main, pilot, adjudicated


def file_hashes(root, labels_dir):
    base = Path(root)
    return {p.relative_to(base).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(labels_dir).glob("*.csv"))}


def iaa_block(paths, clusters, n_boot=N_BOOT, seed=SEED):
    """Agreement per v2 field and for categories, from label-only files; clusters map item -> quota cell."""
    sheets = {name: schema.read_labels(path, version=2) for name, path in paths.items()}
    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    cl = {i: clusters[i] for i in common}
    block = {}
    for field, spec in schema.FIELDS_V2.items():
        rep = iaa_tool.field_report(sheets, field, spec, cl, n_boot, seed)
        entry = {"cohen": [{"pair": pair, "kappa": p["kappa"], "ci95": p["kappa_ci95"], "n": len(common)}
                           for pair, p in rep["pairs"].items()],
                 "alpha": rep["alpha"], "ci95": rep["alpha_ci95"]}
        if "fleiss" in rep:
            entry["fleiss"] = {"kappa": rep["fleiss"], "ci95": rep["fleiss_ci95"]}
        block[field] = entry
    block["categories"] = iaa_tool.category_report(sheets, cl, n_boot, seed)
    return block, len(common)


def disagreement_summary(paths):
    sheets = {name: schema.read_labels(path, version=2) for name, path in paths.items()}
    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    types = {f: 0 for f in list(schema.FIELDS_V2) + ["categories"]}
    items = 0
    for item in common:
        differing = [f for f in schema.FIELDS_V2 if len({sheets[n][item][f] for n in sheets}) > 1]
        if len({tuple(sheets[n][item]["categories"]) for n in sheets}) > 1:
            differing.append("categories")
        items += bool(differing)
        for f in differing:
            types[f] += 1
    return {"items": items, "disagreement_types": types}


# ---------------------------------------------------------------- freeze
def load_clusters_from_key(key_path):
    clusters = {}
    for line in Path(key_path).read_text(encoding="utf8").splitlines():
        if line.strip():
            row = json.loads(line)
            clusters[row["item_id"]] = row.get("quota_cell") or row["family_id"]
    return clusters


def cmd_freeze(args):
    labels_dir = Path(args.labels_dir)
    root = labels_dir.parent
    main, _pilot, adjudicated = label_files(labels_dir)
    if adjudicated is None or len(main) < 2:
        raise SystemExit("need labels/adjudicated.csv and at least two annotator label files")
    clusters = load_clusters_from_key(args.key)
    in_reference = set(schema.read_labels(adjudicated, version=2))
    block, n = iaa_block(main, clusters, args.n_boot, SEED)
    record = {"schema": FREEZE_SCHEMA, "files": file_hashes(root, labels_dir), "annotators": sorted(main), "items": n,
              "bootstrap": {"unit": "quota_cell", "replicates": args.n_boot, "seed": SEED},
              "clusters": {i: clusters[i] for i in sorted(clusters) if i in in_reference},
              "iaa": block}
    Path(args.out).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf8")
    print(json.dumps({"files": len(record["files"]), "items": n}))
    return 0


# ---------------------------------------------------------------- build
def repo_top(path):
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    return Path(result.stdout.strip()) if result.returncode == 0 else None


def build_record(freeze_dir, arms_dir, date, branch, set_manifest, resolution_counts, familiarity, record_rel, host="", commands=None):
    freeze_dir = Path(freeze_dir)
    freeze = json.loads((freeze_dir / "iaa.json").read_text(encoding="utf8"))
    top = repo_top(freeze_dir)
    main, pilot, adjudicated = label_files(freeze_dir / "labels")
    clusters = freeze["clusters"]
    reference = schema.read_labels(adjudicated, version=2)
    arms = []
    for name in sorted(scorer.ARMS):
        path = Path(arms_dir) / f"arm_{name}.json"
        arms.append(json.loads(path.read_text(encoding="utf8")))
    for arm in arms:
        arm.pop("semantic_identity", None)
    pilot_block = {"iaa": None}
    if len(pilot) >= 2:
        pilot_block = {"iaa": iaa_block(pilot, {i: i for i in set.intersection(*(set(schema.read_labels(p, version=2)) for p in pilot.values()))},
                                        N_BOOT, SEED)[0], "annotators": sorted(pilot)}
    status = subprocess.run(["git", "-C", str(top), "status", "--porcelain"], capture_output=True, text=True).stdout.strip()
    sha = subprocess.run(["git", "-C", str(top), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    freeze_rel = freeze_dir.resolve().relative_to(top.resolve()).as_posix()
    commits = order.computed_order(top, "HEAD", f"{freeze_rel}/set_manifest.json", f"{freeze_rel}/packet_manifest.json",
                                   f"{freeze_rel}/labels", None)
    disagreement = disagreement_summary(main)
    return {
        "schema": RECORD_SCHEMA, "study_id": f"HUMANEVAL-{date}",
        "chain": {"threat": "developer-made labels inflate the measured protection and under-enforcement goes unseen",
                  "defense": "the shipped PriVoke pipeline and policy",
                  "experiment": "score PriVoke on a fresh, blind, human-labelled set",
                  "metric": "kappa per field; precision, recall, specificity, F1; under- and over-enforcement",
                  "evidence": "this record, the set hash and the commit that froze the labels"},
        "build": {"branch": branch, "sha": sha, "clean": status == ""},
        "host": host, "run_dates": [date], "commands": commands or [],
        "scope_label": "human ground truth",
        "set": {"sha256": set_manifest["sha256_jsonl"], "n": set_manifest["n"], "source_kind": set_manifest["source_kind"],
                "contamination": {k: set_manifest["contamination"][k] for k in ("exact", "near", "marker")}},
        "annotators": {"count": len(main), "familiarity_declared": familiarity or {}, "agent_labels": 0, "statement": STATEMENT},
        "pilot": pilot_block,
        "iaa": freeze["iaa"],
        "iaa_bootstrap": freeze["bootstrap"], "iaa_clusters": clusters,
        "adjudication": {"items": disagreement["items"], "resolution_counts": resolution_counts,
                         "disagreement_types": disagreement["disagreement_types"]},
        "freeze": {**{k: commits[k] for k in ("set_manifest_commit", "packet_manifest_commit", "label_commit")},
                   "labels_dir": f"{freeze_rel}/labels", "files": freeze["files"]},
        "arms": arms,
        "not_established": NOT_ESTABLISHED,
        "user_actions": ["recruit and brief the annotators", "adjudicate every disagreement", "approve the freeze"],
        "record_path": record_rel,
    }


def cmd_build(args):
    freeze_dir = Path(args.freeze_dir)
    set_manifest = json.loads((freeze_dir / "set_manifest.json").read_text(encoding="utf8"))
    resolutions = json.loads(Path(args.resolution_counts).read_text(encoding="utf8")) if args.resolution_counts else None
    familiarity = json.loads(Path(args.familiarity).read_text(encoding="utf8")) if args.familiarity else None
    out_dir = Path(args.out_dir)
    stem = f"human-annotated-eval-{args.date}"
    record = build_record(freeze_dir, args.arms, args.date, args.branch, set_manifest, resolutions, familiarity,
                          f"{out_dir.as_posix()}/{stem}.json", args.host, args.commands_run)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{stem}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf8")
    (out_dir / f"{stem}.md").write_text(render_markdown(record), encoding="utf8")
    print(json.dumps({"record": f"{stem}.json"}))
    return 0


# ---------------------------------------------------------------- rendering
def fmt(v):
    return "n/a" if v is None else f"{v:.3f}"


def render_markdown(record):
    lines = [f"# {record['study_id']}: human-annotated evaluation", "",
             f"Scope: {record['scope_label']}. Build {record['build']['branch']} {record['build']['sha'][:12]} "
             f"(clean: {record['build']['clean']}).", "",
             f"Annotators: {record['annotators']['count']}. {record['annotators']['statement']}", "",
             f"Set: n = {record['set']['n']}, sha256 {record['set']['sha256']}, source {record['set']['source_kind']}.", "",
             "## Agreement", "", "| Field | Pair | Kappa | 95% CI | n |", "|---|---|---|---|---|"]
    for field in schema.FIELDS_V2:
        entry = record["iaa"][field]
        for row in entry["cohen"]:
            lines.append(f"| {field} | {row['pair']} | {fmt(row['kappa'])} | {fmt(row['ci95'][0])} to {fmt(row['ci95'][1])} | {row['n']} |")
        if "fleiss" in entry:
            lines.append(f"| {field} | Fleiss | {fmt(entry['fleiss']['kappa'])} | {fmt(entry['fleiss']['ci95'][0])} to {fmt(entry['fleiss']['ci95'][1])} | |")
        lines.append(f"| {field} | alpha | {fmt(entry['alpha'])} | {fmt(entry['ci95'][0])} to {fmt(entry['ci95'][1])} | |")
    adj = record["adjudication"]
    lines += ["", f"Adjudicated items: {adj['items']}; disagreement types: {json.dumps(adj['disagreement_types'], sort_keys=True)}.", "",
              "## Scores against the adjudicated labels", "",
              "| Arm | Scope | Metric | Value | 95% CI | num/den |", "|---|---|---|---|---|---|"]
    for arm in record["arms"]:
        for name in METRIC_ORDER:
            m = arm["metrics"][name]
            lines.append(f"| {arm['arm']} | {arm['scope_label']} | {name} | {fmt(m['value'])} | {fmt(m['ci95'][0])} to {fmt(m['ci95'][1])} | {m['num']}/{m['den']} |")
    lines += ["", "## Not established", ""] + [f"- {item}" for item in record["not_established"]]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- check
def close(a, b, path, problems, tol=1e-9):
    if isinstance(a, bool) or isinstance(b, bool) or a is None or b is None:
        if a != b:
            problems.append(f"{path}: {a!r} != {b!r}")
    elif isinstance(a, (int, float)) and isinstance(b, (int, float)):
        if not math.isclose(a, b, rel_tol=tol, abs_tol=tol):
            problems.append(f"{path}: {a!r} != {b!r}")
    elif isinstance(a, dict) and isinstance(b, dict):
        if set(a) != set(b):
            problems.append(f"{path}: keys differ")
            return
        for k in a:
            close(a[k], b[k], f"{path}.{k}", problems, tol)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            problems.append(f"{path}: length differs")
            return
        for i, (x, y) in enumerate(zip(a, b)):
            close(x, y, f"{path}[{i}]", problems, tol)
    elif a != b:
        problems.append(f"{path}: {a!r} != {b!r}")


def check_record(record_path, root=None):
    record_path = Path(record_path)
    record = json.loads(record_path.read_text(encoding="utf8"))
    problems = []
    for key in REQUIRED_HEADER:
        if key not in record:
            problems.append(f"missing header field {key}")
    if record.get("schema") != RECORD_SCHEMA:
        problems.append("schema is not " + RECORD_SCHEMA)
    if record.get("scope_label") not in SCOPE_LABELS:
        problems.append("scope_label outside the vocabulary")
    ann = record.get("annotators", {})
    if ann.get("agent_labels") != 0 or "No agent" not in ann.get("statement", ""):
        problems.append("the record must state that no agent produced a label")
    if problems:
        return problems
    root = Path(root) if root else (repo_top(record_path.resolve().parent) or Path("."))
    labels_dir = root / record["freeze"]["labels_dir"]
    # files and hashes
    actual = file_hashes(labels_dir.parent, labels_dir)
    close(record["freeze"]["files"], actual, "freeze.files", problems)
    main, pilot, adjudicated = label_files(labels_dir)
    if adjudicated is None or len(main) < 2:
        return problems + ["label files missing"]
    if ann.get("count") != len(main):
        problems.append("annotators.count differs from the annotator label files")
    boot = record["iaa_bootstrap"]
    block, n = iaa_block(main, record["iaa_clusters"], boot["replicates"], boot["seed"])
    close(record["iaa"], json.loads(json.dumps(block)), "iaa", problems)
    summary = disagreement_summary(main)
    close(record["adjudication"]["items"], summary["items"], "adjudication.items", problems)
    close(record["adjudication"]["disagreement_types"], summary["disagreement_types"], "adjudication.disagreement_types", problems)
    if len(pilot) >= 2 and record["pilot"].get("iaa") is not None:
        ids = set.intersection(*(set(schema.read_labels(p, version=2)) for p in pilot.values()))
        close(record["pilot"]["iaa"], json.loads(json.dumps(iaa_block(pilot, {i: i for i in ids}, N_BOOT, SEED)[0])), "pilot.iaa", problems)
    reference = schema.read_labels(adjudicated, version=2)
    clusters = record["iaa_clusters"]
    for arm in record["arms"]:
        spec = scorer.ARMS.get(arm["arm"])
        if spec is None:
            problems.append(f"unknown arm {arm['arm']}")
            continue
        if not arm.get("layers_requested") or arm["layers_requested"] != spec["layers"]:
            problems.append(f"{arm['arm']}: layers_requested must be {spec['layers']}")
        if arm.get("layers_executed_ok") is not True:
            problems.append(f"{arm['arm']}: executed layers were not asserted")
        if arm["scope_label"] != spec["scope_label"] or arm["scope_label"] not in SCOPE_LABELS:
            problems.append(f"{arm['arm']}: wrong scope_label")
        bootstrap = arm["bootstrap"]
        fresh = scorer.arm_report(arm["arm"], arm["predictions"], reference, clusters, bootstrap["replicates"], bootstrap["seed"],
                                  executed_ok=arm.get("layers_executed_ok") is True)
        close(arm, json.loads(json.dumps(fresh)), f"arms.{arm['arm']}", problems)
    md = record_path.with_suffix(".md")
    if md.is_file() and md.read_text(encoding="utf8") != render_markdown(record):
        problems.append("the Markdown does not equal the rendering of the JSON")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", metavar="RECORD_JSON")
    sub = parser.add_subparsers(dest="command")
    f = sub.add_parser("freeze")
    f.add_argument("--labels-dir", required=True)
    f.add_argument("--key", required=True)
    f.add_argument("--out", required=True)
    f.add_argument("--n-boot", type=int, default=N_BOOT)
    b = sub.add_parser("build")
    b.add_argument("--freeze-dir", required=True)
    b.add_argument("--arms", required=True)
    b.add_argument("--date", required=True)
    b.add_argument("--out-dir", default="paper/research")
    b.add_argument("--branch", default="feat/asiaccs-s13a")
    b.add_argument("--resolution-counts")
    b.add_argument("--familiarity")
    b.add_argument("--host", default="")
    b.add_argument("--command", dest="commands_run", action="append", default=[])
    args = parser.parse_args(argv)
    if args.check:
        problems = check_record(args.check)
        print(json.dumps({"record": args.check, "ok": not problems, "problem_count": len(problems), "problems": problems[:50]}))
        return 1 if problems else 0
    if args.command == "freeze":
        return cmd_freeze(args)
    if args.command == "build":
        return cmd_build(args)
    parser.error("give --check or a sub-command")


if __name__ == "__main__":
    sys.exit(main())
