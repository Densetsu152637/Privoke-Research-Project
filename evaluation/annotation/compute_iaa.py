#!/usr/bin/env python
"""Inter-annotator agreement for completed annotation sheets.

Usage:
  python compute_iaa.py --sheet A=main_A_done.csv --sheet B=main_B_done.csv \
      [--key key/sampling_key.jsonl] [--split main] --out-json iaa.json [--out-md iaa.md] \
      [--disagreements-csv to_adjudicate.csv] [--schema 1|2] [--min-kappa X --fields f1,f2]
  python compute_iaa.py --check-adjudication adjudicated.csv

Stage 13a additions: --schema 2 reads the v2 sheets (sensitive, subject, audience, categories, action);
Fleiss' kappa is added when three or more annotators are present; --min-kappa/--fields exit non-zero when
any listed field's kappa (every pair, and Fleiss) is below the bar; --check-adjudication exits non-zero
unless every row of the adjudication file has a valid resolution and an adjudicator. With --schema 2 the
adjudication export holds text, so it may only be written under the main checkout's
evaluation/results/s13a/returned/ (override the root with S13A_RETURNED_ROOT in tests). Keys that carry a
quota_cell make the bootstrap resample quota cells instead of scenario families.

Reports per field (disclosure, sensitivity, visibility, action) and per category:
raw agreement, Cohen's kappa per annotator pair, Krippendorff's alpha (nominal; ordinal for
sensitivity and action), per-label specific agreement and confusion matrices, with percentile
intervals from a bootstrap that resamples scenario families when a key is supplied (otherwise
items). The key is used only for clustering; no provisional target enters any statistic here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agreement as ag  # noqa: E402
import annotation_schema as schema  # noqa: E402


RETURNED_ROOT = Path("D:/Git Repositories/Privoke-Research-Project/evaluation/results/s13a/returned")


def require_returned_path(path):
    """The adjudication export contains text: refuse any path outside the Git-ignored returned/ directory."""
    root = Path(os.environ.get("S13A_RETURNED_ROOT") or RETURNED_ROOT).resolve()
    target = Path(path).resolve()
    if root != target and root not in target.parents:
        raise SystemExit(f"{path} holds text and may only be written under {root}")


def load_sheets(specs, version=1):
    sheets = {}
    for spec in specs:
        name, _, path = spec.partition("=")
        if not path:
            raise SystemExit("--sheet expects NAME=PATH")
        sheets[name] = schema.read_labels(path, version=version)
    return sheets


def load_clusters(key_path, split, item_ids):
    if not key_path:
        return {i: i for i in item_ids}, "item"
    clusters, unit = {}, "family"
    for line in Path(key_path).read_text(encoding="utf8").splitlines():
        if line.strip():
            row = json.loads(line)
            if split is None or row["split"] == split:
                if "quota_cell" in row:
                    unit = "quota_cell"
                clusters[row["item_id"]] = row.get("quota_cell") or row["family_id"]
    missing = [i for i in item_ids if i not in clusters]
    if missing:
        raise SystemExit(f"{len(missing)} sheet items are absent from the key for split {split!r}")
    return {i: clusters[i] for i in item_ids}, unit


def field_report(sheets, field, spec, clusters, n_boot, seed):
    values, level = spec["values"], spec["level"]
    names = sorted(sheets)
    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    report = {"level": level, "items": len(common), "pairs": {}}

    def alpha_of(items):
        units = [[sheets[n][i][field] for n in names] for i in items]
        return ag.krippendorff_alpha(units, level, values if level == "ordinal" else None)

    report["alpha"] = alpha_of(common)
    lo, hi, used = ag.cluster_bootstrap(common, clusters, alpha_of, n_boot, seed)
    report["alpha_ci95"] = [lo, hi]
    if len(names) >= 3:
        def fleiss_of(items):
            return ag.fleiss_kappa([[sheets[n][i][field] for n in names] for i in items])

        report["fleiss"] = fleiss_of(common)
        flo, fhi, _ = ag.cluster_bootstrap(common, clusters, fleiss_of, n_boot, seed)
        report["fleiss_ci95"] = [flo, fhi]
    for a, b in ag.pairs(names):
        xa = [sheets[a][i][field] for i in common]
        xb = [sheets[b][i][field] for i in common]
        kappa, po, pe = ag.cohen_kappa(xa, xb)

        def kappa_of(items, a=a, b=b):
            return ag.cohen_kappa([sheets[a][i][field] for i in items], [sheets[b][i][field] for i in items])[0]

        klo, khi, _ = ag.cluster_bootstrap(common, clusters, kappa_of, n_boot, seed)
        report["pairs"][f"{a}-{b}"] = {
            "kappa": kappa, "kappa_ci95": [klo, khi], "observed_agreement": po, "expected_agreement": pe,
            "specific_agreement": ag.specific_agreement(xa, xb, values),
            "confusion_rows_first_columns_second": ag.confusion_matrix(xa, xb, values),
        }
    return report


def category_report(sheets, clusters, n_boot, seed):
    names = sorted(sheets)
    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    out = {"items": len(common), "per_category": {}, "pairs": {}}
    for cat in schema.CATEGORIES:
        def alpha_of(items, cat=cat):
            return ag.krippendorff_alpha([[int(cat in sheets[n][i]["categories"]) for n in names] for i in items], "nominal")
        entry = {"alpha": alpha_of(common), "pairs": {}}
        for a, b in ag.pairs(names):
            xa = [int(cat in sheets[a][i]["categories"]) for i in common]
            xb = [int(cat in sheets[b][i]["categories"]) for i in common]
            kappa, po, _ = ag.cohen_kappa(xa, xb)
            entry["pairs"][f"{a}-{b}"] = {"kappa": kappa, "observed_agreement": po,
                                          "specific_agreement_present": ag.specific_agreement(xa, xb, [1])[1],
                                          "n_present_a": sum(xa), "n_present_b": sum(xb)}
        out["per_category"][cat] = entry
    for a, b in ag.pairs(names):
        exact = [sheets[a][i]["categories"] == sheets[b][i]["categories"] for i in common]
        jacc = []
        for i in common:
            sa, sb = set(sheets[a][i]["categories"]), set(sheets[b][i]["categories"])
            jacc.append(1.0 if not (sa | sb) else len(sa & sb) / len(sa | sb))

        def exact_of(items, a=a, b=b):
            return sum(sheets[a][i]["categories"] == sheets[b][i]["categories"] for i in items) / len(items)

        lo, hi, _ = ag.cluster_bootstrap(common, clusters, exact_of, n_boot, seed)
        out["pairs"][f"{a}-{b}"] = {"exact_set_match": sum(exact) / len(exact), "exact_set_match_ci95": [lo, hi],
                                    "mean_jaccard": sum(jacc) / len(jacc)}
    return out


def disagreements(sheets, texts, version=1):
    fields = schema.fields_for(version)
    names = sorted(sheets)
    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    rows = []
    for i in common:
        differing = [f for f in fields if len({sheets[n][i][f] for n in names}) > 1]
        if len({tuple(sheets[n][i]["categories"]) for n in names}) > 1:
            differing.append("categories")
        if not differing:
            continue
        row = {"item_id": i, "text": texts.get(i, ""), "differing_fields": "|".join(differing)}
        for n in names:
            for f in list(fields) + ["categories"]:
                value = sheets[n][i][f]
                row[f"{n}_{f}"] = schema.format_categories(value) if f == "categories" else value
            row[f"{n}_notes"] = sheets[n][i]["notes"]
        for f in list(fields) + ["categories"]:
            row[f"final_{f}"] = ""
        row.update({"resolution": "", "reason": "", "adjudicator": ""})
        rows.append(row)
    columns = (["item_id", "text", "differing_fields"] + [f"{n}_{f}" for n in names for f in list(fields) + ["categories", "notes"]]
               + [f"final_{f}" for f in list(fields) + ["categories"]] + ["resolution", "reason", "adjudicator"])
    return columns, rows


def render_markdown(result):
    fmt = lambda v: "n/a" if v is None else f"{v:.3f}"
    lines = [f"# Inter-annotator agreement", "", f"Annotators: {', '.join(result['annotators'])}; items: {result['items']}; "
             f"bootstrap unit: {result['bootstrap_unit']}; replicates: {result['bootstrap_replicates']}.", "",
             "| Field | Level | Alpha | Alpha 95% CI | Pair | Kappa | Kappa 95% CI | Raw agreement |", "|---|---|---|---|---|---|---|---|"]
    for field, rep in result["fields"].items():
        for pair, p in rep["pairs"].items():
            lines.append(f"| {field} | {rep['level']} | {fmt(rep['alpha'])} | {fmt(rep['alpha_ci95'][0])} to {fmt(rep['alpha_ci95'][1])} "
                         f"| {pair} | {fmt(p['kappa'])} | {fmt(p['kappa_ci95'][0])} to {fmt(p['kappa_ci95'][1])} | {fmt(p['observed_agreement'])} |")
    lines += ["", "| Category | Alpha | Pair | Kappa | Specific agreement (present) | n present (first, second) |", "|---|---|---|---|---|---|"]
    for cat, entry in result["categories"]["per_category"].items():
        for pair, p in entry["pairs"].items():
            lines.append(f"| {cat} | {fmt(entry['alpha'])} | {pair} | {fmt(p['kappa'])} | {fmt(p['specific_agreement_present'])} | {p['n_present_a']}, {p['n_present_b']} |")
    for pair, p in result["categories"]["pairs"].items():
        lines.append("")
        lines.append(f"Category sets {pair}: exact match {fmt(p['exact_set_match'])} (95% CI {fmt(p['exact_set_match_ci95'][0])} to {fmt(p['exact_set_match_ci95'][1])}), mean Jaccard {fmt(p['mean_jaccard'])}.")
    return "\n".join(lines) + "\n"


def check_adjudication(path):
    """Every disagreement row needs a valid resolution and a named adjudicator; returns the problem list."""
    rows = schema.read_rows(path)
    if not rows:
        return ["adjudication file has no rows"]
    problems = []
    for number, row in enumerate(rows, start=2):
        who = str(row.get("item_id", "")).strip() or f"row {number}"
        resolution = str(row.get("resolution", "") or "").strip()
        if not resolution:
            problems.append(f"{who}: resolution is empty")
        elif resolution not in schema.RESOLUTIONS:
            problems.append(f"{who}: invalid resolution {resolution!r}")
        if not str(row.get("adjudicator", "") or "").strip():
            problems.append(f"{who}: adjudicator is empty")
    return problems


def kappa_failures(result, fields, minimum):
    """Fields whose lowest pairwise (or Fleiss) kappa is below the bar; an undefined kappa also fails."""
    failures = {}
    for field in fields:
        rep = result["fields"][field]
        values = [p["kappa"] for p in rep["pairs"].values()] + ([rep["fleiss"]] if "fleiss" in rep else [])
        if any(v is None or v < minimum for v in values):
            failures[field] = values
    return failures


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sheet", action="append", help="NAME=PATH of a completed sheet (repeat)")
    p.add_argument("--key", help="sampling_key.jsonl, used only for family clustering")
    p.add_argument("--split", help="restrict key to this split (main|pilot)")
    p.add_argument("--n-boot", type=int, default=2000)
    p.add_argument("--seed", type=int, default=20261024)
    p.add_argument("--out-json")
    p.add_argument("--schema", type=int, choices=[1, 2], default=1, help="sheet schema version (2 for Stage 13a)")
    p.add_argument("--min-kappa", type=float, help="exit non-zero when a --fields kappa is below this bar")
    p.add_argument("--fields", help="comma-separated fields that --min-kappa applies to")
    p.add_argument("--check-adjudication", metavar="ADJUDICATED_CSV",
                   help="exit non-zero unless every row has a valid resolution and an adjudicator")
    p.add_argument("--out-md")
    p.add_argument("--disagreements-csv")
    args = p.parse_args(argv)

    if args.check_adjudication:
        problems = check_adjudication(args.check_adjudication)
        print(json.dumps({"adjudication": str(args.check_adjudication), "complete": not problems,
                          "problem_count": len(problems), "problems": problems[:50]}))
        raise SystemExit(1 if problems else 0)
    if not args.sheet or not args.out_json:
        p.error("--sheet and --out-json are required unless --check-adjudication is given")
    if (args.min_kappa is None) != (args.fields is None):
        p.error("--min-kappa and --fields go together")
    fields = schema.fields_for(args.schema)
    gated = [f.strip() for f in args.fields.split(",") if f.strip()] if args.fields else []
    unknown = [f for f in gated if f not in fields]
    if unknown:
        p.error("unknown --fields for schema %d: %s" % (args.schema, ",".join(unknown)))
    if args.schema == 2 and args.disagreements_csv:
        require_returned_path(args.disagreements_csv)

    sheets = load_sheets(args.sheet, args.schema)
    if len(sheets) < 2:
        raise SystemExit("need at least two annotators")
    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    if not common:
        raise SystemExit("no items are shared by all sheets")
    clusters, unit = load_clusters(args.key, args.split, common)
    result = {
        "annotators": sorted(sheets), "items": len(common), "bootstrap_unit": unit, "bootstrap_replicates": args.n_boot,
        "items_not_shared": {n: len(set(s) - set(common)) for n, s in sheets.items()},
        "fields": {f: field_report(sheets, f, spec, clusters, args.n_boot, args.seed) for f, spec in fields.items()},
        "categories": category_report(sheets, clusters, args.n_boot, args.seed),
    }
    Path(args.out_json).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf8")
    if args.out_md:
        Path(args.out_md).write_text(render_markdown(result), encoding="utf8")
    if args.disagreements_csv:
        texts = {r["item_id"]: r.get("text", "") for r in schema.read_rows(args.sheet[0].partition("=")[2])}
        columns, rows = disagreements(sheets, texts, args.schema)
        schema.write_csv(args.disagreements_csv, columns, rows)
    print(json.dumps({"items": len(common), "alpha": {f: r["alpha"] for f, r in result["fields"].items()}}))
    if gated:
        failures = kappa_failures(result, gated, args.min_kappa)
        print(json.dumps({"min_kappa": args.min_kappa, "fields": gated, "below_bar": failures}))
        if failures:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
