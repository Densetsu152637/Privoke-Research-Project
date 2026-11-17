#!/usr/bin/env python
"""Accuracy of the provisional (assistant-authored) targets against human reference labels.

Usage:
  python provisional_accuracy.py --key key/sampling_key.jsonl \
      --sheet A=main_A_done.csv --sheet B=main_B_done.csv \
      [--adjudicated adjudicated.csv] --out-json accuracy.json [--out-md accuracy.md]

Reference label per item: the annotators' labels when all annotators agree on every field,
otherwise the adjudicated row (columns item_id, disclosure, sensitivity, visibility,
categories, action, resolution, ...; `final_*` columns from compute_iaa.py are accepted).
Items without an adjudicated row, or resolved `excluded_ambiguous`, are excluded and counted.
Accuracy is reported for the sample (Wilson interval) and as a design-weighted population
estimate (family-cluster bootstrap), plus every annotator separately and a stratified breakdown.
The provisional action field is the allowed action set: a reference action is correct when it
belongs to that set. A `disclosure` reference of `unclear` counts as a mismatch for the
provisional yes/no target and is also reported separately.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agreement as ag  # noqa: E402
import annotation_schema as schema  # noqa: E402

CHECKS = ["disclosure", "sensitivity", "visibility", "categories", "action", "joint"]


def load_key(path, split="main"):
    key = {}
    for line in Path(path).read_text(encoding="utf8").splitlines():
        if line.strip():
            row = json.loads(line)
            if row["split"] == split:
                key[row["item_id"]] = row
    return key


def load_adjudicated(path):
    out = {}
    for row in schema.read_rows(path):
        mapped = {k: row.get("final_" + k, row.get(k)) for k in ("disclosure", "sensitivity", "visibility", "categories", "action")}
        mapped["item_id"] = row["item_id"]
        resolution = (row.get("resolution") or "").strip()
        if resolution and resolution not in schema.RESOLUTIONS:
            raise schema.SheetError(f"{row['item_id']}: unknown resolution {resolution!r}")
        record = {"excluded": resolution == "excluded_ambiguous"}
        record["labels"] = None if record["excluded"] and not mapped["sensitivity"] else schema.normalise_row(mapped)
        out[row["item_id"]] = record
    return out


def build_reference(sheets, adjudicated):
    """Return (reference {item: labels}, counts of how each item was resolved)."""
    names = sorted(sheets)
    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    reference, counts = {}, Counter()
    for item in common:
        records = [sheets[n][item] for n in names]
        if all(r[f] == records[0][f] for r in records for f in list(schema.FIELDS) + ["categories"]):
            reference[item] = records[0]
            counts["annotators_agree"] += 1
        elif adjudicated is not None and item in adjudicated:
            if adjudicated[item]["excluded"]:
                counts["excluded_ambiguous"] += 1
            else:
                reference[item] = adjudicated[item]["labels"]
                counts["adjudicated"] += 1
        else:
            counts["disagreement_not_adjudicated"] += 1
    return reference, counts


def correctness(provisional, labels):
    p = provisional
    result = {
        "disclosure": labels["disclosure"] == p["disclosure"],
        "sensitivity": labels["sensitivity"] == p["sensitivity"],
        "visibility": labels["visibility"] == p["visibility"],
        "categories": sorted(labels["categories"]) == sorted(p["categories"]),
        "action": labels["action"] in p["allowed_actions"],
    }
    result["joint"] = all(result[f] for f in ("disclosure", "sensitivity", "visibility", "categories", "action"))
    return result


def weighted_accuracy(items, flags, weights):
    total = sum(weights[i] for i in items)
    return sum(weights[i] for i in items if flags[i]) / total if total else None


def evaluate(key, reference, n_boot=2000, seed=20261024):
    items = sorted(i for i in reference if i in key)
    flags = {i: correctness(key[i]["provisional"], reference[i]) for i in items}
    weights = {i: key[i]["design_weight"] or 1.0 for i in items}
    clusters = {i: key[i]["family_id"] for i in items}
    out = {"items": len(items), "overall": {}, "by_stratum_group": {}, "confusion": {}}
    for check in CHECKS:
        ok = {i: flags[i][check] for i in items}
        k = sum(ok.values())
        entry = {"correct": k, "n": len(items), "sample_accuracy": k / len(items) if items else None,
                 "wilson95": list(ag.wilson_interval(k, len(items)))}
        entry["weighted_accuracy"] = weighted_accuracy(items, ok, weights)
        lo, hi, _ = ag.cluster_bootstrap(items, clusters, lambda s, ok=ok: weighted_accuracy(s, ok, weights), n_boot, seed)
        entry["weighted_cluster_bootstrap95"] = [lo, hi]
        out["overall"][check] = entry
    for name, group_of in (("audience", lambda r: r["provisional"]["visibility"]),
                           ("control", lambda r: r["control"]),
                           ("provisional_sensitivity", lambda r: r["provisional"]["sensitivity"])):
        groups = defaultdict(list)
        for i in items:
            groups[group_of(key[i])].append(i)
        out["by_stratum_group"][name] = {
            g: {c: {"n": len(m), "correct": sum(flags[i][c] for i in m),
                    "wilson95": list(ag.wilson_interval(sum(flags[i][c] for i in m), len(m)))} for c in CHECKS}
            for g, m in sorted(groups.items())}
    for field, values in (("disclosure", schema.DISCLOSURE), ("sensitivity", schema.SENSITIVITY), ("visibility", schema.VISIBILITY)):
        matrix = {p: {r: 0 for r in values} for p in values if p != "unclear" or field != "disclosure"}
        for i in items:
            matrix[key[i]["provisional"][field]][reference[i][field]] += 1
        out["confusion"][field + "_provisional_rows_reference_columns"] = matrix
    action = {"ALLOW": Counter(), "WARN|BLOCK": Counter()}
    for i in items:
        action["|".join(key[i]["provisional"]["allowed_actions"])][reference[i]["action"]] += 1
    out["confusion"]["action_provisional_allowed_set_rows_reference_columns"] = {k: dict(v) for k, v in action.items()}
    unclear = sum(reference[i]["disclosure"] == "unclear" for i in items)
    out["reference_disclosure_unclear"] = unclear
    cat_rows = {}
    for cat in schema.CATEGORIES:
        tp = sum(cat in key[i]["provisional"]["categories"] and cat in reference[i]["categories"] for i in items)
        fp = sum(cat in key[i]["provisional"]["categories"] and cat not in reference[i]["categories"] for i in items)
        fn = sum(cat not in key[i]["provisional"]["categories"] and cat in reference[i]["categories"] for i in items)
        cat_rows[cat] = {"tp": tp, "fp": fp, "fn": fn}
    out["category_counts_provisional_vs_reference"] = cat_rows
    return out


def render_markdown(result):
    fmt = lambda v: "n/a" if v is None else f"{100 * v:.1f}"
    lines = ["# Accuracy of provisional targets", "",
             f"Reference items: {result['items']}; resolution: {json.dumps(result['resolution'], sort_keys=True)}.", "",
             "| Check | Correct / n | Sample % | Wilson 95% | Weighted % | Cluster-bootstrap 95% |", "|---|---|---|---|---|---|"]
    for check, e in result["overall"].items():
        lines.append(f"| {check} | {e['correct']}/{e['n']} | {fmt(e['sample_accuracy'])} | {fmt(e['wilson95'][0])} to {fmt(e['wilson95'][1])} "
                     f"| {fmt(e['weighted_accuracy'])} | {fmt(e['weighted_cluster_bootstrap95'][0])} to {fmt(e['weighted_cluster_bootstrap95'][1])} |")
    lines.append("")
    for name, groups in result["by_stratum_group"].items():
        lines += [f"By {name} (joint correct / n, Wilson 95%):", ""]
        for g, e in groups.items():
            j = e["joint"]
            lines.append(f"- {g}: {j['correct']}/{j['n']} ({fmt(j['wilson95'][0])} to {fmt(j['wilson95'][1])})")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--key", required=True)
    p.add_argument("--sheet", action="append", required=True, help="NAME=PATH of a completed sheet (repeat)")
    p.add_argument("--adjudicated")
    p.add_argument("--split", default="main")
    p.add_argument("--n-boot", type=int, default=2000)
    p.add_argument("--seed", type=int, default=20261024)
    p.add_argument("--out-json", required=True)
    p.add_argument("--out-md")
    args = p.parse_args(argv)

    key = load_key(args.key, args.split)
    sheets = {}
    for spec in args.sheet:
        name, _, path = spec.partition("=")
        sheets[name] = schema.read_labels(path)
    extra = {i for s in sheets.values() for i in s} - set(key)
    if extra:
        raise SystemExit(f"{len(extra)} sheet items are not in the {args.split} key")
    adjudicated = load_adjudicated(args.adjudicated) if args.adjudicated else None
    reference, counts = build_reference(sheets, adjudicated)
    result = evaluate(key, reference, args.n_boot, args.seed)
    result["resolution"] = dict(counts)
    result["per_annotator"] = {n: evaluate(key, {i: r for i, r in s.items() if i in key}, args.n_boot, args.seed)["overall"]
                               for n, s in sorted(sheets.items())}
    Path(args.out_json).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf8")
    if args.out_md:
        Path(args.out_md).write_text(render_markdown(result), encoding="utf8")
    print(json.dumps({"items": result["items"], "joint": result["overall"]["joint"]["sample_accuracy"]}))


if __name__ == "__main__":
    main()
