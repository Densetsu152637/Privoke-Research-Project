"""Follow-up tables for the Wave 3 results record (detector-layer scope; docs-only, no rescoring).

Reads the per-row outputs of ``w3_scoring.py`` (ids, flags, spans) and the F1 gold spans (never printed), and writes
one JSON with two clearly separated parts:

* ``registered_secondary``: the source-stratified secondary analysis of pre-registration section 10 (per
  ``source_dataset``: H1, H2, H2b, H3a, H3b, H3c cells), computed with the same ``detector_stats.compare_runs``
  conventions as the primary analysis (grouped paired bootstrap, 10,000 replicates, seed 20261024).
* ``exploratory_post_hoc``: layer attribution of the H2 result by exact layer swapping under the positive rule,
  per-rule tables of the regex-caused lost rows, BLOCK-level breakdown, N+lg versus O. Post hoc: none of this can
  satisfy or replace a registered hypothesis.

    python evaluation/w3_followup.py --results <w3_scoring dir> --f1-gold <piimb_fresh_f1.jsonl> --out <json>
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detector_stats as ds  # noqa: E402

N_BOOT = ds.DEFAULT_BOOTSTRAP
SEED = ds.DEFAULT_SEED


def load(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def cell(res: dict, metric: str) -> dict:
    d = res["deltas"]["new"][metric]
    return {"estimate": d["estimate"], "lo": d["lo"], "hi": d["hi"]}


def compare(base, cand, layer: str, subset=None) -> dict:
    res = ds.compare_runs(base, cand, layer=layer, rule="positive", subset=subset, n_boot=N_BOOT, seed=SEED)
    fl = res["flips"]
    return {"n_pos": res["counts"]["old"]["tp"] + res["counts"]["old"]["fn"], "n_neg": res["counts"]["old"]["tn"] + res["counts"]["old"]["fp"],
            "recall": cell(res, "recall"), "specificity": cell(res, "specificity"),
            "recall_flips": {"gained": fl["fn_to_tp"], "lost": fl["tp_to_fn"]},
            "specificity_flips": {"gained": fl["fp_to_tn"], "lost": fl["tn_to_fp"]},
            "mcnemar_p_positives": fl["mcnemar_positives"]["p_two_sided"], "mcnemar_p_negatives": fl["mcnemar_negatives"]["p_two_sided"]}


def stratified(O, N, LG) -> dict:
    out = {}
    for source in sorted({r["stratum"] for r in O}):
        sub = lambda r, s=source: r["stratum"] == s  # noqa: E731
        out[source] = {
            "H1_regex__N_minus_O": compare(O, N, "regex", sub),
            "H2_H2b_union__N_minus_O": compare(O, N, "union", sub),
            "H3a_H3c_union__lg_minus_N": compare(N, LG, "union", sub),
            "H3b_ner__lg_minus_N": compare(N, LG, "ner", sub)}
    return out


def hybrid(regex_rows, ner_rows) -> list[dict]:
    """Rows whose union decision is regex(regex_rows) OR ner(ner_rows); the other fields are not meaningful."""
    out = []
    for x, y in zip(regex_rows, ner_rows):
        z = dict(x)
        z["union"] = {"positive": bool(x["regex"]["positive"] or y["ner"]["positive"]), "action": "ALLOW",
                      "categories": [], "max_sensitivity": "S0"}
        out.append(z)
    return out


def overlaps(span, gold) -> bool:
    return any(span["start"] < e and s < span["end"] for s, e, _ in gold)


def attribution(O, N, LG, OS, NS, gold) -> dict:
    out: dict = {}
    for name, rows in (("O_regex+N_ner", hybrid(O, N)), ("N_regex+O_ner", hybrid(N, O)), ("O_regex+lg_ner", hybrid(O, LG))):
        out[f"hybrid__{name}__minus_O"] = compare(O, rows, "union")
    out["N_lg_minus_O_union"] = compare(O, LG, "union")
    lost = [(a, b) for a, b in zip(O, N) if a["expected_has_pii"] and a["union"]["positive"] and not b["union"]["positive"]]
    gained = [(a, b) for a, b in zip(O, N) if a["expected_has_pii"] and not a["union"]["positive"] and b["union"]["positive"]]
    out["lost_rows"] = len(lost)
    out["gained_rows"] = len(gained)
    out["lost_by_O_layer"] = dict(Counter("regex-only" if a["regex"]["positive"] and not a["ner"]["positive"]
                                          else "ner-only" if a["ner"]["positive"] and not a["regex"]["positive"] else "both"
                                          for a, _ in lost))
    out["gained_by_N_layer"] = dict(Counter(("regex" if b["regex"]["positive"] else "") + ("ner" if b["ner"]["positive"] else "")
                                            for _, b in gained))
    regex_lost = [(a, b) for a, b in lost if a["regex"]["positive"]]
    out["regex_caused_lost_rows"] = len(regex_lost)
    out["regex_caused_lost_rows_with_a_regex_span_on_gold"] = sum(
        1 for a, _ in regex_lost if any(overlaps(sp, gold[a["example_id"]]) for sp in OS[a["example_id"]]["layers"]["regex"]))
    table: dict[str, Counter] = defaultdict(Counter)
    for a, _ in regex_lost:
        rules = {sp["source"] for sp in OS[a["example_id"]]["layers"]["regex"]}
        for rule in rules:
            table[rule]["lost_rows_containing_rule"] += 1
            if len(rules) == 1:
                table[rule]["lost_rows_sole_rule"] += 1
        for sp in OS[a["example_id"]]["layers"]["regex"]:
            table[sp["source"]]["spans_on_gold" if overlaps(sp, gold[a["example_id"]]) else "spans_off_gold"] += 1
    fixed = [(a, b) for a, b in zip(O, N) if not a["expected_has_pii"] and a["union"]["positive"] and not b["union"]["positive"]]
    for a, _ in fixed:
        if a["regex"]["positive"]:
            rules = {sp["source"] for sp in OS[a["example_id"]]["layers"]["regex"]}
            for rule in rules:
                table[rule]["clean_union_fp_rows_fixed_containing_rule"] += 1
                if len(rules) == 1:
                    table[rule]["clean_union_fp_rows_fixed_sole_rule"] += 1
    block = [(a, b) for a, b in zip(O, N) if a["expected_has_pii"] and a["union"]["action"] == "BLOCK" and b["union"]["action"] != "BLOCK"]
    block_gain = [1 for a, b in zip(O, N) if a["expected_has_pii"] and a["union"]["action"] != "BLOCK" and b["union"]["action"] == "BLOCK"]
    for a, _ in block:
        for rule in {sp["source"] for sp in OS[a["example_id"]]["layers"]["regex"] if sp["sensitivity"] == "S3"}:
            table[rule]["block_lost_rows_with_S3_span_of_rule"] += 1
    out["per_rule_O_regex"] = {rule: dict(c) for rule, c in sorted(table.items(), key=lambda kv: -kv[1]["lost_rows_containing_rule"])}
    out["clean_union_fp_fixed"] = len(fixed)
    out["clean_union_fp_fixed_by_O_layer"] = dict(Counter(("regex" if a["regex"]["positive"] else "") + ("ner" if a["ner"]["positive"] else "") for a, _ in fixed))
    out["block_lost"] = len(block)
    out["block_gained"] = len(block_gain)
    out["block_lost_to_action"] = dict(Counter(b["union"]["action"] for _, b in block))
    out["block_lost_O_regex_action"] = dict(Counter(a["regex"]["action"] for a, _ in block))
    # per-rule firing on positives and clean rows, O versus N (rows where the rule produced a span)
    fire = {"positives": (defaultdict(set), defaultdict(set)), "clean": (defaultdict(set), defaultdict(set))}
    for a in O:
        key = "positives" if a["expected_has_pii"] else "clean"
        for sp in OS[a["example_id"]]["layers"]["regex"]:
            fire[key][0][sp["source"]].add(a["example_id"])
        for sp in NS[a["example_id"]]["layers"]["regex"]:
            fire[key][1][sp["source"]].add(a["example_id"])
    out["rule_firing_rows_O_to_N"] = {key: {rule: [len(fo[rule]), len(fn[rule])] for rule in sorted(set(fo) | set(fn), key=lambda r: -(len(fo[r]) - len(fn[r])))
                                            if len(fo[rule]) != len(fn[rule])} for key, (fo, fn) in fire.items()}
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--f1-gold", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    R = args.results
    O, N, LG = (load(R / d / "f1.rows.jsonl") for d in ("O", "N", "N_lg"))
    OS = {s["id"]: s for s in load(R / "O" / "f1.spans.jsonl")}
    NS = {s["id"]: s for s in load(R / "N" / "f1.spans.jsonl")}
    gold = {}
    for row in load(args.f1_gold):
        gold[row["id"]] = [(e["start"], e["end"], e["label"]) for e in row.get("entities") or []]
    result = {"scope": "detector-layer; F1; positive rule; n_boot %d seed %d" % (N_BOOT, SEED),
              "source_mix_positives": dict(Counter(r["stratum"] for r in O if r["expected_has_pii"])),
              "source_mix_clean": dict(Counter(r["stratum"] for r in O if not r["expected_has_pii"])),
              "registered_secondary": {"label": "pre-registration section 10: source-stratified secondary analysis (not used for promotion)",
                                       "by_source": stratified(O, N, LG)},
              "exploratory_post_hoc": {"label": "post hoc, exploratory: cannot satisfy or replace a registered hypothesis",
                                       **attribution(O, N, LG, OS, NS, gold)}}
    args.out.write_text(json.dumps(result, indent=1, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
