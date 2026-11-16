"""Apply detector_stats to old-vs-new per-row runs and verify them against recorded aggregates.

Detector-layer scope (regex, NER, union = regex OR NER cascade); not LLM-only evidence.

    python evaluation/detector_uncertainty_report.py --rows <dir with <label>-<split>.rows.jsonl> \
        --recorded docs/experiments/detector-precision-installed-20261024.json \
        --out <aggregate.json> [--splits dev personalized openai final]

Comparison units: ``dev`` (all), ``dev-TUNE``/``dev-CHECK`` (the ``half`` field), ``personalized``,
``openai`` and optionally ``final``. Dev and final cluster by ``group_id``; the synthetic sets carry
no document/template id, so they use a plain row bootstrap (a ``stratum`` cluster sensitivity
analysis is added for them). Decision rules: ``positive`` (the benchmark's definition), ``warn_or_block``
and ``block`` (runtime policy action from the pipeline's own ``strongest_result``).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

import detector_stats as ds

UNITS = {
    "dev": ("dev", None),
    "dev-TUNE": ("dev", lambda r: r.get("half") == "tune"),
    "dev-CHECK": ("dev", lambda r: r.get("half") == "check"),
    "personalized": ("personalized", None),
    "openai": ("openai", None),
    "final": ("final", None),
}
SYNTHETIC = {"personalized", "openai"}


def recorded_check(old_rows, new_rows, recorded: dict, split: str) -> list[str]:
    """Compare per-row-derived confusion counts with the recorded aggregate; return mismatches."""
    problems = []
    for label, rows in (("old", old_rows), ("new", new_rows)):
        report = recorded[label]["splits"][split]
        parts = {"all": rows}
        if split == "dev":
            parts.update({half: [r for r in rows if r.get("half") == half] for half in ("tune", "check")})
        for part, subset in parts.items():
            expected = report[part]
            if expected["n"] != len(subset) or expected["positives"] != sum(r["expected_has_pii"] for r in subset):
                problems.append(f"{label}/{split}/{part}: n or positives differ")
            for layer in ds.LAYERS:
                got = ds.confusion(ds.labels_of(subset), ds.predictions(subset, layer, "positive"))
                want = {k.lower(): expected[layer][k] for k in ("TP", "TN", "FP", "FN")}
                if got != want:
                    problems.append(f"{label}/{split}/{part}/{layer}: derived {got} != recorded {want}")
    return problems


def action_table(rows) -> dict:
    """Action counts per layer set split by label (shows where `positive` and actions diverge)."""
    out = {}
    for layer in ds.LAYERS:
        counts = {"positives": Counter(), "negatives": Counter()}
        for r in rows:
            counts["positives" if r["expected_has_pii"] else "negatives"][r[layer]["action"]] += 1
        out[layer] = {k: {a: v.get(a, 0) for a in ("ALLOW", "WARN", "BLOCK")} for k, v in counts.items()}
        out[layer]["positive_but_allowed"] = sum(1 for r in rows if r[layer]["positive"] and r[layer]["action"] == "ALLOW")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rows", type=Path, required=True)
    parser.add_argument("--recorded", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--splits", nargs="+", default=["dev", "personalized", "openai"],
                        choices=sorted({u[0] for u in UNITS.values()}))
    parser.add_argument("--baseline-label", default="old")
    parser.add_argument("--candidate-label", default="new")
    parser.add_argument("--n-boot", type=int, default=ds.DEFAULT_BOOTSTRAP)
    parser.add_argument("--seed", type=int, default=ds.DEFAULT_SEED)
    args = parser.parse_args()

    recorded = json.loads(args.recorded.read_text(encoding="utf-8"))
    names = (args.baseline_label, args.candidate_label)
    out: dict = {"scope": "detector-layer (regex, NER, union=regex OR NER); not LLM-only", "seed": args.seed,
                 "n_boot": args.n_boot, "level": 0.95, "delta": "candidate - baseline", "names": list(names),
                 "recorded_check": {}, "units": {}}
    for split in args.splits:
        old_rows = ds.load_rows(args.rows / f"{names[0]}-{split}.rows.jsonl")
        new_rows = ds.load_rows(args.rows / f"{names[1]}-{split}.rows.jsonl")
        out["recorded_check"][split] = recorded_check(old_rows, new_rows, recorded, split) or "all counts equal"
        for unit, (unit_split, subset) in UNITS.items():
            if unit_split != split:
                continue
            groupings = ["row", "stratum"] if unit in SYNTHETIC else ["group_id"]
            entry = {"grouping_primary": groupings[0], "layers": {}}
            kept = [a for a, _ in ds.align_rows(old_rows, new_rows) if subset is None or subset(a)]
            entry["n"] = len(kept)
            entry["positives"] = sum(r["expected_has_pii"] for r in kept)
            entry["action_counts"] = {names[0]: action_table(kept),
                                      names[1]: action_table([b for a, b in ds.align_rows(old_rows, new_rows)
                                                              if subset is None or subset(a)])}
            for layer in ds.LAYERS:
                entry["layers"][layer] = {}
                for rule in ds.RULES:
                    per_group = {}
                    for grouping in groupings:
                        res = ds.compare_runs(old_rows, new_rows, layer=layer, rule=rule, grouping=grouping,
                                              subset=subset, names=names, n_boot=args.n_boot, seed=args.seed)
                        if grouping != groupings[0]:  # sensitivity analysis: CIs and sign tests only
                            res = {"grouping": grouping, "n_clusters": res["n_clusters"], "metrics": res["metrics"],
                                   "deltas": res["deltas"], "cluster_sign_test": res["cluster_sign_test"]}
                        per_group[grouping] = res
                    entry["layers"][layer][rule] = per_group
            out["units"][unit] = entry
            print(f"done {unit}", flush=True)
    args.out.write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")


if __name__ == "__main__":
    main()
