import json, sys
a = json.load(open(sys.argv[1])); C = a["comparisons"]
layer = sys.argv[2]; fixes = sys.argv[3].split(","); conds_filter = sys.argv[4].split(",") if len(sys.argv) > 4 else None
SUB = ["dev-TUNE", "personalized", "dev-CHECK", "openai"]
def pct(x): return f"{100*x:.1f}"
def p(x): return "<.001" if x < .001 else f"{x:.3f}"
for fix in fixes:
    print(f"\n### {fix} ({layer})")
    print("| condition | subset | n_pos | recall base -> fix (delta [95% CI]) gains/losses p | n_neg | FP base -> fix gains/losses p |")
    print("|---|---|---|---|---|---|")
    conds = sorted({v["condition"] for v in C.values() if v["fix"] == fix}, key=lambda c: (c != "identity", c))
    for cond in conds:
        if conds_filter and cond not in conds_filter and cond != "identity": continue
        for s in SUB:
            v = C[f"{fix}|{cond}|{s}|{layer}"]
            b, f = v["base"], v["fixed"]; rd = v["recall_delta"]
            n_neg = b["fp"] + b["tn"]
            print(f"| {cond} | {s} | {b['tp']+b['fn']} | {pct(b['recall'])} -> {pct(f['recall'])} ({100*rd['estimate']:+.1f} [{100*rd['lo']:+.1f},{100*rd['hi']:+.1f}]) +{v['fn_to_tp']}/-{v['tp_to_fn']} p={p(v['mcnemar_positives_p'])} | {n_neg} | {pct(b['fp_rate'])} -> {pct(f['fp_rate'])} +{v['tn_to_fp']}FP/-{v['fp_to_tn']}FP p={p(v['mcnemar_negatives_p'])} |")
