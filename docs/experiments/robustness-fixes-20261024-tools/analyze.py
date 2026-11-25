"""Paired analysis of base vs fix configurations with detector_stats (read-only import)."""
import json, sys
sys.dont_write_bytecode = True
from pathlib import Path
sys.path.insert(0, "D:/Git Repositories/Privoke-Research-Project-wt-a-stats/evaluation")
import detector_stats as ds

D = Path(sys.argv[1]); OUT = Path(sys.argv[2]); N_BOOT = int(sys.argv[3]) if len(sys.argv) > 3 else 5000
SUBSETS = {  # name -> (split, subset predicate, grouping, design/post-review)
    "dev-TUNE": ("dev", lambda r: r.get("half") == "tune", "group_id", "design"),
    "dev-CHECK": ("dev", lambda r: r.get("half") == "check", "group_id", "post-review"),
    "personalized": ("personalized", None, "row", "design"),
    "openai": ("openai", None, "row", "post-review"),
}
FIXES = {  # config -> conditions it targets
    "strip": ["zero_width"],
    "digits": ["digits_space", "digits_dot", "digits_dash", "digits_words"],
    "email": ["email_bracket", "email_paren", "email_word"],
    "caseless": ["lowercase", "uppercase"],
    "all": ["zero_width", "digits_space", "digits_dot", "digits_dash", "digits_words", "email_bracket",
            "email_paren", "email_word", "lowercase", "uppercase"],
}

def rows(label, cond, split):
    return ds.load_rows(D / f"{label}__{cond}__{split}.rows.jsonl")

def summary(rs, layer):
    labels = ds.labels_of(rs); pred = ds.predictions(rs, layer)
    tp = sum(1 for y, p in zip(labels, pred) if y and p); fn = sum(1 for y, p in zip(labels, pred) if y and not p)
    fp = sum(1 for y, p in zip(labels, pred) if not y and p); tn = sum(1 for y, p in zip(labels, pred) if not y and not p)
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "recall": tp / max(tp + fn, 1), "fp_rate": fp / max(fp + tn, 1)}

result = {"n_boot": N_BOOT, "comparisons": {}}
for fix, conds in FIXES.items():
    for cond in ["identity"] + conds:
        for sname, (split, pred, grouping, role) in SUBSETS.items():
            base = rows("base", cond, split); cand = rows(fix, cond, split)
            for layer in ("regex", "ner", "union"):
                r = ds.compare_runs(base, cand, layer=layer, rule="positive", grouping=grouping, subset=pred,
                                    n_boot=N_BOOT)
                sel = [x for x in base if pred is None or pred(x)]
                key = f"{fix}|{cond}|{sname}|{layer}"
                fl = r["flips"]
                result["comparisons"][key] = {
                    "fix": fix, "condition": cond, "subset": sname, "role": role, "layer": layer, "grouping": grouping,
                    "n": r["n_rows"], "n_positive": sum(ds.labels_of(sel)),
                    "base": summary(sel, layer),
                    "fixed": summary([c for b, c in ds.align_rows(base, cand) if pred is None or pred(b)], layer),
                    "recall_delta": r["deltas"]["new"]["recall"], "specificity_delta": r["deltas"]["new"]["specificity"],
                    "fn_to_tp": fl["fn_to_tp"], "tp_to_fn": fl["tp_to_fn"], "fp_to_tn": fl["fp_to_tn"], "tn_to_fp": fl["tn_to_fp"],
                    "mcnemar_positives_p": fl["mcnemar_positives"]["p_two_sided"],
                    "mcnemar_negatives_p": fl["mcnemar_negatives"]["p_two_sided"],
                }
    print("done", fix, file=sys.stderr, flush=True)
# recovery to clean: fix on perturbed vs base on clean (union), no CI
result["recovery"] = {}
for fix, conds in FIXES.items():
    for cond in conds:
        for sname, (split, pred, grouping, role) in SUBSETS.items():
            b_clean = [x for x in rows("base", "identity", split) if pred is None or pred(x)]
            b_pert = [x for x in rows("base", cond, split) if pred is None or pred(x)]
            f_pert = [x for x in rows(fix, cond, split) if pred is None or pred(x)]
            result["recovery"][f"{fix}|{cond}|{sname}"] = {l: {"clean": summary(b_clean, l), "perturbed": summary(b_pert, l), "fixed": summary(f_pert, l)} for l in ("regex", "ner", "union")}
OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")
