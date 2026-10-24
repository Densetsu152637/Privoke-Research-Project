#!/usr/bin/env python
"""Inter-annotator agreement for completed annotation sheets.

Usage:
  python compute_iaa.py --sheet A=main_A_done.csv --sheet B=main_B_done.csv \
      [--key key/sampling_key.jsonl] [--split main] --out-json iaa.json [--out-md iaa.md] \
      [--disagreements-csv to_adjudicate.csv]

Reports per field (disclosure, sensitivity, visibility, action) and per category:
raw agreement, Cohen's kappa per annotator pair, Krippendorff's alpha (nominal; ordinal for
sensitivity and action), per-label specific agreement and confusion matrices, with percentile
intervals from a bootstrap that resamples scenario families when a key is supplied (otherwise
items). The key is used only for clustering; no provisional target enters any statistic here.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agreement as ag  # noqa: E402
import annotation_schema as schema  # noqa: E402


def load_sheets(specs):
    sheets = {}
    for spec in specs:
        name, _, path = spec.partition("=")
        if not path:
            raise SystemExit("--sheet expects NAME=PATH")
        sheets[name] = schema.read_labels(path)
    return sheets


def load_clusters(key_path, split, item_ids):
    if not key_path:
        return {i: i for i in item_ids}, "item"
    clusters = {}
    for line in Path(key_path).read_text(encoding="utf8").splitlines():
        if line.strip():
            row = json.loads(line)
            if split is None or row["split"] == split:
                clusters[row["item_id"]] = row["family_id"]
    missing = [i for i in item_ids if i not in clusters]
    if missing:
        raise SystemExit(f"{len(missing)} sheet items are absent from the key for split {split!r}")
    return {i: clusters[i] for i in item_ids}, "family"


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


def disagreements(sheets, texts):
    names = sorted(sheets)
    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    rows = []
    for i in common:
        differing = [f for f in schema.FIELDS if len({sheets[n][i][f] for n in names}) > 1]
        if len({tuple(sheets[n][i]["categories"]) for n in names}) > 1:
            differing.append("categories")
        if not differing:
            continue
        row = {"item_id": i, "text": texts.get(i, ""), "differing_fields": "|".join(differing)}
        for n in names:
            for f in list(schema.FIELDS) + ["categories"]:
                value = sheets[n][i][f]
                row[f"{n}_{f}"] = schema.format_categories(value) if f == "categories" else value
            row[f"{n}_notes"] = sheets[n][i]["notes"]
        for f in list(schema.FIELDS) + ["categories"]:
            row[f"final_{f}"] = ""
        row.update({"resolution": "", "reason": "", "adjudicator": ""})
        rows.append(row)
    columns = (["item_id", "text", "differing_fields"] + [f"{n}_{f}" for n in names for f in list(schema.FIELDS) + ["categories", "notes"]]
               + [f"final_{f}" for f in list(schema.FIELDS) + ["categories"]] + ["resolution", "reason", "adjudicator"])
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


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sheet", action="append", required=True, help="NAME=PATH of a completed sheet (repeat)")
    p.add_argument("--key", help="sampling_key.jsonl, used only for family clustering")
    p.add_argument("--split", help="restrict key to this split (main|pilot)")
    p.add_argument("--n-boot", type=int, default=2000)
    p.add_argument("--seed", type=int, default=20261024)
    p.add_argument("--out-json", required=True)
    p.add_argument("--out-md")
    p.add_argument("--disagreements-csv")
    args = p.parse_args(argv)

    sheets = load_sheets(args.sheet)
    if len(sheets) < 2:
        raise SystemExit("need at least two annotators")
    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    if not common:
        raise SystemExit("no items are shared by all sheets")
    clusters, unit = load_clusters(args.key, args.split, common)
    result = {
        "annotators": sorted(sheets), "items": len(common), "bootstrap_unit": unit, "bootstrap_replicates": args.n_boot,
        "items_not_shared": {n: len(set(s) - set(common)) for n, s in sheets.items()},
        "fields": {f: field_report(sheets, f, spec, clusters, args.n_boot, args.seed) for f, spec in schema.FIELDS.items()},
        "categories": category_report(sheets, clusters, args.n_boot, args.seed),
    }
    Path(args.out_json).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf8")
    if args.out_md:
        Path(args.out_md).write_text(render_markdown(result), encoding="utf8")
    if args.disagreements_csv:
        texts = {r["item_id"]: r.get("text", "") for r in schema.read_rows(args.sheet[0].partition("=")[2])}
        columns, rows = disagreements(sheets, texts)
        schema.write_csv(args.disagreements_csv, columns, rows)
    print(json.dumps({"items": len(common), "alpha": {f: r["alpha"] for f, r in result["fields"].items()}}))


if __name__ == "__main__":
    main()
