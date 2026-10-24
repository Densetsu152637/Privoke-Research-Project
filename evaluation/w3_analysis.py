"""Wave 3 confirmatory analysis (detector-layer scope), applied to the per-row outputs of ``w3_scoring.py``.

Reads only ids, flags and spans (plus, for the span metrics, the length and gold spans of the registered
fresh files, which are never printed). Implements the pre-registered tests exactly as written in
``docs/research/preregistration-detector-v2-20261024.md`` using ``detector_stats.py`` (prompt level and
paired bootstrap) and ``span_scoring.py`` (spans). Part of the freeze addendum; frozen before scoring.

Sub-commands: ``analyse`` (writes the aggregate JSON), ``render`` (Markdown tables from that JSON).

Statistics conventions (all from the pre-registration, section 5)
* paired comparisons are baseline vs candidate on identical rows, delta = candidate - baseline;
* grouped paired percentile bootstrap, whole ``group_id`` clusters, 10,000 replicates, seed 20261024;
  a 95 % two-sided percentile interval; its lower limit is the one-sided 97.5 % lower bound used for the
  non-inferiority tests and its upper limit the one-sided 97.5 % upper bound;
* exact two-sided McNemar on the discordant counts for superiority tests; Wald paired bounds alongside;
* Holm-Bonferroni inside the H3a/H3b family and inside the H5a-H5e family; H1, H1b, H2, H2b, H4 are each
  tested at their own level; H3c and H6 are conjuncts (no correction).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Mapping, Sequence

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import detector_stats as ds  # noqa: E402
import span_scoring as ss  # noqa: E402

SCORED_CONFIGS = ["O", "N", "N+strip", "N+digits", "N+email", "N+caseless", "N+all", "N+lg", "N+trf"]
R_CONFIGS = ["N+strip", "N+digits", "N+email", "N+caseless", "N+all"]
NER_CONFIGS = ["N+lg", "N+trf"]
CANDIDATES = R_CONFIGS + NER_CONFIGS
PAIRS = [("O", "N")] + [("N", c) for c in CANDIDATES]
LAYERS = ("regex", "ner", "union")
RULES = ds.RULES
MARGIN = 0.01          # 1.0 percentage point (recall / specificity)
MARGIN_PER_1K = 10.0   # 1.0 point of the over-masking share per character, expressed per 1000 characters
ALPHA = 0.05
Z975 = 1.959964

H5_SPEC = {
    "H5a": ("N+strip", ["zero_width"]),
    "H5b": ("N+digits", ["digits_space", "digits_dot", "digits_dash", "digits_words"]),
    "H5c": ("N+email", ["email_bracket", "email_paren", "email_word"]),
    "H5d": ("N+caseless", ["lowercase", "uppercase"]),
    "H5e": ("N+all", ["zero_width", "digits_space", "digits_dot", "digits_dash", "digits_words",
                      "email_bracket", "email_paren", "email_word", "lowercase", "uppercase"]),
}
ALL_TRANSFORMS = H5_SPEC["H5e"][1]
# R-configuration -> the hypothesis it is promoted on
H5_OF = {"N+strip": "H5a", "N+digits": "H5b", "N+email": "H5c", "N+caseless": "H5d", "N+all": "H5e"}

# Historical clean-text context for promotion criterion 3 (not re-scored, not fresh). Union recall, positive rule.
# Sources: docs/experiments/detector-precision-installed-20261024.json (O, N) and, on branch research/wt-g-nermodels,
# docs/experiments/ner-models-20261024.md (N+lg and N+trf versus N; sm-pf1 is N).
HISTORICAL_CRITERION3 = {
    "O>N": {"personalized": {"base": 1.000, "cand": 1.000}, "openai": {"base": 0.942, "cand": 0.918},
            "note": "openai drop is exempt for N by the owner decision recorded in the pre-registration"},
    "N>N+lg": {"personalized": {"base": 1.000, "cand": 1.000}, "openai": {"base": 0.918, "cand": 0.920},
               "note": "agent G record (post-review split for openai)"},
    "N>N+trf": {"personalized": {"base": 1.000, "cand": 1.000}, "openai": {"base": 0.918, "cand": 0.922},
                "note": "agent G record; N+trf is not promotable this round"},
    "N>R": {"note": "docs/experiments/robustness-fixes-20261024.md on research/wt-r-robustfix reports no outcome flips on "
                    "clean development, personalized and openai text for every flag (context, not re-scored)"},
}


# ------------------------------------------------------------------------------------ small helpers


def load_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def label_of(config: str) -> str:
    return config.replace("+", "_")


def holm(pvalues: Mapping[str, float]) -> dict[str, float]:
    """Holm-Bonferroni adjusted p-values (monotone, capped at 1)."""
    order = sorted(pvalues, key=lambda k: pvalues[k])
    m = len(order)
    adjusted, running = {}, 0.0
    for rank, key in enumerate(order):
        running = max(running, (m - rank) * pvalues[key])
        adjusted[key] = min(1.0, running)
    return adjusted


def wilson(k: int, n: int, z: float = Z975) -> tuple[float | None, float | None]:
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def paired_wald(labels: Sequence[bool], baseline: Sequence[bool], candidate: Sequence[bool], groups: Sequence[str],
                klass: str) -> dict:
    """Wald paired bound on delta (candidate - baseline) of the correct-decision rate in one class.

    ``klass`` is ``"pos"`` (recall) or ``"neg"`` (specificity). Returns the row-level paired Wald standard
    error and the cluster-robust one (whole ``group_id`` clusters), each with a one-sided 97.5 % lower bound.
    """
    diffs, cl = [], []
    for y, a, b, g in zip(labels, baseline, candidate, groups):
        if (klass == "pos") != bool(y):
            continue
        diffs.append(int(b == y) - int(a == y))
        cl.append(g)
    n = len(diffs)
    if n < 2:
        return {"n": n, "delta": None}
    mean = sum(diffs) / n
    var_row = (sum(d * d for d in diffs) / n - mean * mean) * n / (n - 1)
    se_row = math.sqrt(max(var_row, 0.0) / n)
    sums: dict[str, list[float]] = {}
    for d, g in zip(diffs, cl):
        s = sums.setdefault(g, [0.0, 0.0])
        s[0] += d
        s[1] += 1
    m = len(sums)
    se_cl = None
    if m > 1:
        resid = sum((s[0] - mean * s[1]) ** 2 for s in sums.values())
        se_cl = math.sqrt(max(m / (m - 1) * resid, 0.0)) / n
    return {"n": n, "delta": mean, "se_row": se_row, "lower_row_one_sided_975": mean - Z975 * se_row,
            "upper_row_one_sided_975": mean + Z975 * se_row, "se_cluster": se_cl,
            "lower_cluster_one_sided_975": None if se_cl is None else mean - Z975 * se_cl,
            "upper_cluster_one_sided_975": None if se_cl is None else mean + Z975 * se_cl}


KEEP_METRICS = ("recall", "specificity", "precision", "f2", "cost_2", "cost_4", "cost_9")


def trim_pair(res: Mapping) -> dict:
    """Compact form of a ``detector_stats.compare_pair`` result."""
    return {"n_rows": res["n_rows"], "n_clusters": res["n_clusters"], "counts": res["counts"],
            "metrics": {n: {m: res["metrics"][n][m] for m in KEEP_METRICS} for n in res["metrics"]},
            "deltas": {n: {m: res["deltas"][n][m] for m in KEEP_METRICS} for n in res["deltas"]},
            "flips": res["flips"], "cluster_sign_test": res["cluster_sign_test"]}


def pair_cell(ref_rows: Sequence[dict], cand_rows: Sequence[dict], layer: str, rule: str, n_boot: int, seed: int) -> dict:
    pairs = ds.align_rows(ref_rows, cand_rows)
    a_rows = [a for a, _ in pairs]
    b_rows = [b for _, b in pairs]
    labels = ds.labels_of(a_rows)
    groups = ds.cluster_groups(a_rows, "group_id")
    pa, pb = ds.predictions(a_rows, layer, rule), ds.predictions(b_rows, layer, rule)
    res = ds.compare_pair(labels, groups, pa, pb, names=("base", "cand"), n_boot=n_boot, seed=seed)
    cell = trim_pair(res)
    cell["wald_recall"] = paired_wald(labels, pa, pb, groups, "pos")
    cell["wald_specificity"] = paired_wald(labels, pa, pb, groups, "neg")
    return cell


def config_metrics(rows_by_cfg: Mapping[str, Sequence[dict]], layer: str, rule: str, n_boot: int, seed: int) -> dict:
    """Per-configuration confusion counts, point metrics and 95 % grouped-bootstrap intervals on the same rows."""
    base = rows_by_cfg[SCORED_CONFIGS[0]]
    for cfg in SCORED_CONFIGS[1:]:
        ds.align_rows(base, rows_by_cfg[cfg])
    labels = ds.labels_of(base)
    groups = ds.cluster_groups(base, "group_id")
    decisions = {cfg: ds.predictions(rows_by_cfg[cfg], layer, rule) for cfg in SCORED_CONFIGS}
    res = ds.paired_bootstrap(labels, groups, decisions, baseline=SCORED_CONFIGS[0], n_boot=n_boot, seed=seed)
    return {cfg: {"counts": res["counts"][cfg], "metrics": {m: res["metrics"][cfg][m] for m in KEEP_METRICS}}
            for cfg in SCORED_CONFIGS}


def prompt_level(rows_by_cfg: Mapping[str, Sequence[dict]], n_boot: int, seed: int, label: str) -> dict:
    base = rows_by_cfg["O"]
    labels = ds.labels_of(base)
    out = {"set": label, "n_rows": len(base), "n_positive": sum(labels), "n_negative": len(labels) - sum(labels),
           "n_clusters": len(set(ds.cluster_groups(base, "group_id"))), "per_config": {}, "pairs": {}}
    for layer in LAYERS:
        for rule in RULES:
            out["per_config"].setdefault(layer, {})[rule] = config_metrics(rows_by_cfg, layer, rule, n_boot, seed)
    for ref, cand in PAIRS:
        for layer in LAYERS:
            for rule in RULES:
                out["pairs"].setdefault(f"{ref}>{cand}", {}).setdefault(layer, {})[rule] = pair_cell(
                    rows_by_cfg[ref], rows_by_cfg[cand], layer, rule, n_boot, seed)
    return out


# ------------------------------------------------------------------------------------ spans


def span_pair_headline(study: Mapping) -> dict:
    """Compact span results: per subset / min_sens / scope / layer old and new scores plus paired deltas."""
    out: dict = {}
    for sub, per_sens in study["subsets"].items():
        for sens, per_scope in per_sens.items():
            for scope, cell in per_scope.items():
                entry = {"scores": {}, "old_vs_new": {}, "p4": {}}
                for layer, per_tag in cell["scores"].items():
                    entry["scores"][layer] = {
                        tag: {"counts": sc["counts"], "metrics": sc["metrics"],
                              "n_spanless_positive_results": sc["n_spanless_positive_results"]}
                        for tag, sc in per_tag.items()}
                for layer, comp in cell["old_vs_new"].items():
                    entry["old_vs_new"][layer] = {
                        "n_prompts": comp["n_prompts"], "n_prompts_gold": comp["n_prompts_gold"],
                        "n_clusters": comp["n_clusters"], "deltas": comp["deltas"],
                        "metrics": comp["metrics"], "all_masked_flips": comp["all_masked_flips"],
                        "all_masked_cluster_sign_test": comp["all_masked_cluster_sign_test"]}
                for tag, per_vs in cell["p4"].items():
                    entry["p4"][tag] = {vs: {"deltas": comp["deltas"], "metrics": comp["metrics"],
                                             "all_masked_flips": comp["all_masked_flips"]}
                                        for vs, comp in per_vs.items()}
                out.setdefault(sub, {}).setdefault(sens, {})[scope] = entry
    return out


def _span_worker(task: tuple) -> tuple[str, dict]:
    """One run_study over one (reference, candidate) pair; module-level for process pools."""
    set_name, ref, cand, gold_path, results_dir, n_boot, seed = task
    gold = load_jsonl(Path(gold_path))
    old = load_jsonl(Path(results_dir) / label_of(ref) / f"{set_name}.spans.jsonl")
    new = load_jsonl(Path(results_dir) / label_of(cand) / f"{set_name}.spans.jsonl")
    ss.SUBSETS = {"all": None}  # the fresh sets are scored as one subset (no dev-TUNE / dev-CHECK split)
    study = ss.run_study(gold, old, new, n_boot=n_boot, seed=seed)
    study["unmapped_gold_labels"] = dict(ss.unmapped_labels(gold))
    return f"{ref}>{cand}", span_pair_headline(study)


def span_studies(set_name: str, gold_path: Path, results_dir: Path, n_boot: int, seed: int, workers: int) -> dict:
    tasks = [(set_name, ref, cand, str(gold_path), str(results_dir), n_boot, seed) for ref, cand in PAIRS]
    out = {}
    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            for key, value in pool.map(_span_worker, tasks):
                out[key] = value
    else:
        for task in tasks:
            key, value = _span_worker(task)
            out[key] = value
    return out


# ------------------------------------------------------------------------------------ perturbed items (H5, H6)


def perturbed_items(items: Sequence[dict], transforms: Sequence[str]) -> list[dict]:
    wanted = set(transforms)
    return [i for i in items if i["transform"] in wanted]


def h5_cell(base_items: Sequence[dict], cand_items: Sequence[dict], layer: str, n_boot: int, seed: int) -> dict:
    """Candidate minus N on identical perturbed items (union recall by default); items of one row stay together."""
    key = lambda i: (i["example_id"], i["transform"])  # noqa: E731
    if [key(i) for i in base_items] != [key(i) for i in cand_items]:
        raise ValueError("perturbed item sets differ between the reference and the candidate")
    labels = [True] * len(base_items)
    groups = [str(i["group_id"]) if i.get("group_id") is not None else f"row:{i['example_id']}" for i in base_items]
    pa = [bool(i[layer]) for i in base_items]
    pb = [bool(i[layer]) for i in cand_items]
    res = ds.compare_pair(labels, groups, pa, pb, names=("N", "cand"), n_boot=n_boot, seed=seed)
    cell = trim_pair(res)
    cell["wald_recall"] = paired_wald(labels, pa, pb, groups, "pos")
    cell["n_items"] = len(base_items)
    cell["n_rows"] = len({i["example_id"] for i in base_items})
    return cell


def perturbed_analysis(items_by_cfg: Mapping[str, Sequence[dict]], n_boot: int, seed: int) -> dict:
    base = items_by_cfg["N"]
    out = {"n_items_all_transforms": len(base), "items_per_transform": dict(Counter(i["transform"] for i in base)),
           "hypotheses": {}, "per_transform": {}, "unperturbed_note": "N+R candidates on the unperturbed sets: see f1/f3 pairs (H6)"}
    for hyp, (cand, transforms) in H5_SPEC.items():
        b = perturbed_items(base, transforms)
        c = perturbed_items(items_by_cfg[cand], transforms)
        entry = {"candidate": cand, "transforms": transforms, "union": h5_cell(b, c, "union", n_boot, seed),
                 "ner_only": h5_cell(b, c, "ner", n_boot, seed), "regex_only": h5_cell(b, c, "regex", n_boot, seed)}
        out["hypotheses"][hyp] = entry
    p_values = {h: v["union"]["flips"]["mcnemar_positives"]["p_two_sided"] for h, v in out["hypotheses"].items()}
    adjusted = holm(p_values)
    for hyp, entry in out["hypotheses"].items():
        cell = entry["union"]["deltas"]["cand"]["recall"]
        entry["p_two_sided"] = p_values[hyp]
        entry["p_holm"] = adjusted[hyp]
        entry["delta"], entry["ci"] = cell["estimate"], [cell["lo"], cell["hi"]]
        entry["passes"] = bool(cell["estimate"] is not None and cell["estimate"] > 0 and cell["lo"] is not None
                               and cell["lo"] > 0 and adjusted[hyp] < ALPHA)
    # exploratory: every candidate on every transform (union recall), not used for promotion
    for cand in R_CONFIGS:
        for transform in ALL_TRANSFORMS:
            b = perturbed_items(base, [transform])
            c = perturbed_items(items_by_cfg[cand], [transform])
            if not b:
                continue
            cell = h5_cell(b, c, "union", n_boot, seed)
            out["per_transform"].setdefault(cand, {})[transform] = {
                "n_items": cell["n_items"], "counts": cell["counts"], "deltas": {"recall": cell["deltas"]["cand"]["recall"]},
                "mcnemar_positives": cell["flips"]["mcnemar_positives"],
                "recall_base": cell["metrics"]["N"]["recall"]["estimate"], "recall_cand": cell["metrics"]["cand"]["recall"]["estimate"]}
    return out


# ------------------------------------------------------------------------------------ F2 (descriptive)


def f2_descriptive(rows_by_cfg: Mapping[str, Sequence[dict]]) -> dict:
    base = rows_by_cfg["O"]
    out = {"n": len(base), "labels": "none (F2 is unlabelled; descriptive flag rates only, no verdicts)",
           "per_config": {}, "vs_N_union_positive": {}}
    strata = sorted({r["stratum"] for r in base if r.get("stratum")})
    for cfg in SCORED_CONFIGS:
        rows = rows_by_cfg[cfg]
        out["per_config"][cfg] = {}
        for layer in LAYERS:
            for rule in RULES:
                flags = [ds.row_prediction(r, layer, rule) for r in rows]
                k, n = sum(flags), len(flags)
                lo, hi = wilson(k, n)
                by_stratum = {}
                for s in strata:
                    fs = [f for f, r in zip(flags, rows) if r.get("stratum") == s]
                    by_stratum[s] = {"flagged": sum(fs), "n": len(fs)}
                out["per_config"][cfg].setdefault(layer, {})[rule] = {
                    "flagged": k, "n": n, "rate": k / n if n else None, "wilson95": [lo, hi], "by_stratum": by_stratum}
    ref = {r["example_id"]: r["union"]["positive"] for r in rows_by_cfg["N"]}
    for cfg in SCORED_CONFIGS:
        if cfg == "N":
            continue
        cand = {r["example_id"]: r["union"]["positive"] for r in rows_by_cfg[cfg]}
        out["vs_N_union_positive"][cfg] = {"flagged_only_by_config": sum(1 for i in ref if cand[i] and not ref[i]),
                                           "flagged_only_by_N": sum(1 for i in ref if ref[i] and not cand[i]),
                                           "both": sum(1 for i in ref if ref[i] and cand[i])}
    union_ids = {r["example_id"] for rows in rows_by_cfg.values() for r in rows if r["union"]["positive"]}
    out["flagged_by_any_configuration"] = len(union_ids)
    return out


# ------------------------------------------------------------------------------------ hypotheses


def delta_of(cell: Mapping, metric: str, name: str = "cand") -> dict:
    return cell["deltas"][name][metric]


def ni_from_bootstrap(delta: Mapping, margin: float = MARGIN, direction: str = "lower") -> dict:
    """Non-inferiority from a percentile interval. ``lower``: lower limit > -margin (recall / specificity).
    ``upper``: upper limit < +margin (an error that must not rise)."""
    lo, hi, est = delta["lo"], delta["hi"], delta["estimate"]
    if direction == "lower":
        ok = lo is not None and lo > -margin
    else:
        ok = hi is not None and hi < margin
    return {"estimate": est, "lo": lo, "hi": hi, "margin": margin, "direction": direction, "passes": bool(ok)}


def superiority(cell: Mapping, metric: str, mcnemar_key: str, p_override: float | None = None) -> dict:
    d = delta_of(cell, metric)
    p = cell["flips"][mcnemar_key]["p_two_sided"] if p_override is None else p_override
    return {"estimate": d["estimate"], "lo": d["lo"], "hi": d["hi"], "p_mcnemar_two_sided": cell["flips"][mcnemar_key]["p_two_sided"],
            "p_used": p, "flips": {k: cell["flips"][k] for k in ("fn_to_tp", "tp_to_fn", "fp_to_tn", "tn_to_fp")},
            "passes": bool(d["estimate"] is not None and d["estimate"] > 0 and d["lo"] is not None and d["lo"] > 0 and p < ALPHA)}


def evaluate_hypotheses(f1: Mapping, f3: Mapping, spans_f1: Mapping, perturbed: Mapping) -> dict:
    pairs1, pairs3 = f1["pairs"], f3["pairs"]
    H: dict = {}
    on = pairs1["O>N"]
    # H1: regex-only specificity gain, F1 clean (primary decision rule = positive)
    h1 = superiority(on["regex"]["positive"], "specificity", "mcnemar_negatives")
    h1["regex_recall_delta"] = delta_of(on["regex"]["positive"], "recall")
    h1["regex_recall_flips"] = {k: on["regex"]["positive"]["flips"][k] for k in ("fn_to_tp", "tp_to_fn")}
    h1["note"] = "regex-only recall change is reported but is not a pass/fail gate (pre-registered)"
    H["H1"] = h1
    H["H1b"] = {"status": "not evaluated: F2 is unlabelled; human adjudication pending (pre-registration section 11)"}
    # H2: union recall non-inferiority N vs O (F1 positives), margin 1 pt
    u = on["union"]["positive"]
    h2 = ni_from_bootstrap(delta_of(u, "recall"))
    h2["wald_recall"] = u["wald_recall"]
    h2["flips"] = {k: u["flips"][k] for k in ("fn_to_tp", "tp_to_fn")}
    h2["n_positive"] = f1["n_positive"]
    H["H2"] = h2
    h2b = ni_from_bootstrap(delta_of(u, "specificity"))
    h2b["wald_specificity"] = u["wald_specificity"]
    h2b["flips"] = {k: u["flips"][k] for k in ("fp_to_tn", "tn_to_fp")}
    h2b["scope"] = "F1 clean only"
    h2b["f2_part"] = "not evaluated: F2 unlabelled; human adjudication pending"
    H["H2b"] = h2b
    H["H2_exploratory_union_specificity_superiority"] = superiority(u, "specificity", "mcnemar_negatives")
    # H3: larger spaCy NER model (candidate N+lg; N+trf descriptive with the same estimates)
    for cand in NER_CONFIGS:
        pc = pairs1[f"N>{cand}"]
        h3a = superiority(pc["union"]["positive"], "specificity", "mcnemar_negatives")
        h3b = superiority(pc["ner"]["positive"], "specificity", "mcnemar_negatives")
        adjusted = holm({"H3a": h3a["p_mcnemar_two_sided"], "H3b": h3b["p_mcnemar_two_sided"]})
        for key, h in (("H3a", h3a), ("H3b", h3b)):
            h["p_holm"] = adjusted[key]
            d = h["estimate"]
            h["passes"] = bool(d is not None and d > 0 and h["lo"] is not None and h["lo"] > 0 and adjusted[key] < ALPHA)
        h3c1 = ni_from_bootstrap(delta_of(pc["union"]["positive"], "recall"))
        h3c1["wald_recall"] = pc["union"]["positive"]["wald_recall"]
        h3c3 = ni_from_bootstrap(delta_of(pairs3[f"N>{cand}"]["union"]["positive"], "recall"))
        h3c3["wald_recall"] = pairs3[f"N>{cand}"]["union"]["positive"]["wald_recall"]
        H[f"H3[{cand}]"] = {
            "registered_status": "promotable candidate" if cand == "N+lg" else "descriptive comparator only (no test promoted)",
            "H3a_union_specificity_F1": h3a, "H3b_ner_specificity_F1": h3b,
            "H3c_union_recall_F1": h3c1, "H3c_union_recall_F3": h3c3,
            "H3c_passes": bool(h3c1["passes"] and h3c3["passes"]),
            "H3_family_passes": bool(h3a["passes"] and h3b["passes"] and h3c1["passes"] and h3c3["passes"]),
            "H3a_prime_F2": "not evaluated: F2 unlabelled; human adjudication pending",
            "recall_gain_exploratory": delta_of(pc["union"]["positive"], "recall")}
    # H4: span-level masking, N vs O on F1, union spans, scope all, min_sens 0
    cell = spans_f1["O>N"]["all"]["min_sens=0"]["all"]["old_vs_new"]["union"]
    leak = cell["deltas"]["new"]["char_recall"]       # delta of masked-character share (leak = 1 - recall)
    over = cell["deltas"]["new"]["over_mask_chars_per_1k"]
    h4_leak = ni_from_bootstrap(leak, MARGIN, "lower")
    h4_leak["leak_rate_old"] = 1 - cell["metrics"]["old"]["char_recall"]["estimate"]
    h4_leak["leak_rate_new"] = 1 - cell["metrics"]["new"]["char_recall"]["estimate"]
    h4_over = ni_from_bootstrap(over, MARGIN_PER_1K, "upper")
    h4_over["old_per_1k"] = cell["metrics"]["old"]["over_mask_chars_per_1k"]["estimate"]
    h4_over["new_per_1k"] = cell["metrics"]["new"]["over_mask_chars_per_1k"]["estimate"]
    spanless = spans_f1["O>N"]["all"]["min_sens=0"]["all"]["scores"]["union"]
    H["H4"] = {"character_leak_non_inferiority": h4_leak, "over_masking_non_inferiority": h4_over,
               "passes": bool(h4_leak["passes"] and h4_over["passes"]),
               "spanless_positive_results": {tag: spanless[tag]["n_spanless_positive_results"] for tag in spanless},
               "definition": "leak = share of annotated PII characters not covered by any union span; over-masking = "
                             "characters detected outside annotated spans per character of all F1 rows (positives and clean); "
                             "margins 1.0 pt each; delta = N - O; scope 'all', min_sens 0"}
    # H5: perturbed-recall superiority, Holm over H5a-H5e
    H["H5"] = {h: {k: v for k, v in e.items() if k in ("candidate", "transforms", "delta", "ci", "p_two_sided", "p_holm", "passes")}
               | {"n_items": e["union"]["n_items"], "n_rows": e["union"]["n_rows"],
                  "flips": {k: e["union"]["flips"][k] for k in ("fn_to_tp", "tp_to_fn")},
                  "ner_only_recall_delta": delta_of(e["ner_only"], "recall"),
                  "wald_recall": e["union"]["wald_recall"]}
               for h, e in perturbed["hypotheses"].items()}
    # H6: clean-text non-inferiority of each N+R configuration versus N (conjunction)
    H["H6"] = {}
    for cand in R_CONFIGS:
        p1, p3 = pairs1[f"N>{cand}"]["union"]["positive"], pairs3[f"N>{cand}"]["union"]["positive"]
        cells = {"F1_union_recall": ni_from_bootstrap(delta_of(p1, "recall")),
                 "F1_union_specificity": ni_from_bootstrap(delta_of(p1, "specificity")),
                 "F3_union_recall": ni_from_bootstrap(delta_of(p3, "recall")),
                 "F2_union_specificity": {"status": "not evaluated: F2 unlabelled; human adjudication pending"}}
        flips = {"F1": {k: p1["flips"][k] for k in ("fn_to_tp", "tp_to_fn", "fp_to_tn", "tn_to_fp")},
                 "F3": {k: p3["flips"][k] for k in ("fn_to_tp", "tp_to_fn")}}
        evaluated = all(cells[k]["passes"] for k in ("F1_union_recall", "F1_union_specificity", "F3_union_recall"))
        H["H6"][cand] = {"cells": cells, "clean_flips": flips, "evaluated_cells_pass": evaluated,
                         "overall": ("fail" if not evaluated else "pending (F2 cell needs adjudication)")}
    return H


def promotion(H: Mapping, checks: Mapping) -> dict:
    """Promotion verdicts under section 6 of the pre-registration. Criteria needing other parties stay 'pending'."""
    out = {}
    pending45 = {"criterion_4_critic_review": "pending (root dispatches the critic)",
                 "criterion_5_latency": "pending (separate serialized latency step)"}
    # N versus O
    h1, h2, h2b = H["H1"], H["H2"], H["H2b"]
    c1 = h1["passes"]
    c2 = h2["passes"] and h2b["passes"]
    n_entry = {"configuration": "N (shipped defaults, reference O)",
               "criterion_1_primary_delta_excludes_zero_and_mcnemar": {"H1_regex_specificity_F1": h1["passes"], "H1b_F2": "pending adjudication"},
               "criterion_2_union_recall_non_inferior": {"H2": h2["passes"], "H2b_F1": h2b["passes"], "H2b_F2": "pending adjudication"},
               "criterion_3_synthetic_recall": {
                   "personalized": HISTORICAL_CRITERION3["O>N"]["personalized"],
                   "openai": HISTORICAL_CRITERION3["O>N"]["openai"],
                   "status": "personalized: no regression; openai: regression exempt by the owner decision (replaced by H2)"},
               **pending45}
    n_entry["verdict"] = ("not promoted: " + ", ".join(k for k, v in (("criterion 1 (H1)", c1), ("criterion 2 (H2/H2b)", c2)) if not v)
                          if not (c1 and c2) else "criteria 1-3 met on the F1/F3 evidence; promotion remains conditional on F2 "
                          "(H1b, H2b F2 part), the critic review and the latency report")
    out["N"] = n_entry
    for cand in NER_CONFIGS:
        h = H[f"H3[{cand}]"]
        if cand == "N+trf":
            out[cand] = {"configuration": "N+trf (comparator)", "verdict": "not eligible for promotion this round (pre-registered); "
                         "estimates are descriptive", "descriptive_family_passes": h["H3_family_passes"]}
            continue
        c1_ = h["H3a_union_specificity_F1"]["passes"] and h["H3b_ner_specificity_F1"]["passes"]
        c2_ = h["H3c_passes"]
        entry = {"configuration": f"{cand} (reference N)",
                 "criterion_1_H3a_H3b_after_Holm": {"H3a": h["H3a_union_specificity_F1"]["passes"], "H3b": h["H3b_ner_specificity_F1"]["passes"]},
                 "criterion_2_H3c_recall_guard": {"F1": h["H3c_union_recall_F1"]["passes"], "F3": h["H3c_union_recall_F3"]["passes"]},
                 "criterion_3_synthetic_recall": {"personalized": HISTORICAL_CRITERION3[f"N>{cand}"]["personalized"],
                                                  "openai": HISTORICAL_CRITERION3[f"N>{cand}"]["openai"],
                                                  "status": "historical context versus N: no regression of more than 1 pt"},
                 "H3a_prime_F2": "pending adjudication", **pending45}
        entry["verdict"] = ("not promoted: " + ", ".join(k for k, v in (("criterion 1 (H3a/H3b)", c1_), ("criterion 2 (H3c)", c2_)) if not v)
                            if not (c1_ and c2_) else "criteria 1-3 met on F1/F3; conditional on F2 (H3a'), the critic review and latency")
        out[cand] = entry
    for cand in R_CONFIGS:
        hyp = H_FOR_R[cand]
        h5 = H["H5"][hyp]
        h6 = H["H6"][cand]
        entry = {"configuration": f"{cand} (reference N)", "H5": {"hypothesis": hyp, "passes": h5["passes"], "p_holm": h5["p_holm"], "delta": h5["delta"], "ci": h5["ci"]},
                 "H6_evaluated_cells_pass": h6["evaluated_cells_pass"], "H6_F2_cell": "pending adjudication",
                 "frozen_commit_checks": checks.get("robustfix", {}), "criterion_3": HISTORICAL_CRITERION3["N>R"]["note"], **pending45}
        if cand == "N+all":
            entry["rule"] = ("N+all is promoted only if every constituent flag passes individually, or N+all passes H5e and H6 while no "
                             "constituent flag fails H6")
            constituent_pass = all(H["H5"][H_FOR_R[c]]["passes"] and H["H6"][c]["evaluated_cells_pass"] for c in R_CONFIGS[:4])
            constituent_h6 = all(H["H6"][c]["evaluated_cells_pass"] for c in R_CONFIGS[:4])
            ok = constituent_pass or (h5["passes"] and h6["evaluated_cells_pass"] and constituent_h6)
        else:
            ok = h5["passes"] and h6["evaluated_cells_pass"]
        entry["verdict"] = ("not promoted: H5 and H6 not both met" if not ok else
                            "H5 and H6 (F1/F3 cells) met; conditional on the H6 F2 cell, the critic review and latency")
        out[cand] = entry
    return out


H_FOR_R = H5_OF


# ------------------------------------------------------------------------------------ analyse


def frozen_commit_checks(repo: Path) -> dict:
    """Pre-declared check: the per-flag unit tests and the default-off flag documentation at b1975bc2.

    Reports what exists at the frozen commit and which files the docs-only follow-up commit 3f9aa450 adds, so the
    report can state exactly where the documentation lives (it is a later docs-only commit, not the frozen one).
    """
    import subprocess

    def git(*cmd: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *cmd], capture_output=True, text=True).stdout

    tests = "extension/client-runtime/test/test_robustness_fixes.py"
    present = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"b1975bc2:{tests}"], capture_output=True).returncode == 0
    mention = git("grep", "-l", "PRIVOKE_STRIP_FORMAT_CHARS", "b1975bc2", "--", "docs", "extension").split()
    docs_commit = [f for f in git("diff-tree", "--no-commit-id", "--name-only", "-r", "3f9aa450").split() if f.startswith("docs/")]
    docs_mention = git("grep", "-l", "PRIVOKE_STRIP_FORMAT_CHARS", "3f9aa450", "--", "docs").split()
    return {"commit": "b1975bc2", "unit_tests_file": tests, "unit_tests_present_at_frozen_commit": present,
            "files_mentioning_the_flags_at_frozen_commit": mention,
            "docs_only_followup_commit": "3f9aa450", "doc_files_changed_by_followup": docs_commit,
            "doc_files_mentioning_the_flags_at_followup": docs_mention}


def analyse(args) -> None:
    results = args.results
    rows = {s: {cfg: load_jsonl(results / label_of(cfg) / f"{s}.rows.jsonl") for cfg in SCORED_CONFIGS} for s in ("f1", "f2", "f3")}
    perturbed = {cfg: load_jsonl(results / label_of(cfg) / "f1.perturbed.jsonl")
                 for cfg in ("N", *R_CONFIGS)}
    metas = {cfg: json.loads((results / label_of(cfg) / "run_meta.json").read_text(encoding="utf-8")) for cfg in SCORED_CONFIGS}
    out = {"scope": "detector-layer (regex, NER, union); not LLM-only, not semantic, not full-product",
           "n_boot": args.n_boot, "seed": args.seed, "margin_points": 1.0, "configs": SCORED_CONFIGS,
           "run_meta": {cfg: {k: m[k] for k in ("tree", "tree_export_sha", "observed_flags", "ner_model", "ner_model_version", "spacy", "python", "sets", "driver_sha256")}
                        for cfg, m in metas.items()}}
    out["f1"] = prompt_level(rows["f1"], args.n_boot, args.seed, "F1")
    out["f3"] = prompt_level(rows["f3"], args.n_boot, args.seed, "F3")
    out["f2"] = f2_descriptive(rows["f2"])
    spans_dir = results / "analysis"
    spans_dir.mkdir(parents=True, exist_ok=True)
    out["spans_f1"] = span_studies("f1", args.f1_gold, results, args.n_boot, args.seed, args.workers)
    out["spans_f3"] = span_studies("f3", args.f3_gold, results, args.n_boot, args.seed, args.workers)
    out["perturbed"] = perturbed_analysis(perturbed, args.n_boot, args.seed)
    out["hypotheses"] = evaluate_hypotheses(out["f1"], out["f3"], out["spans_f1"], out["perturbed"])
    checks = {"robustfix": frozen_commit_checks(args.repo)} if args.repo else {}
    out["promotion"] = promotion(out["hypotheses"], checks)
    out["historical_criterion3_context"] = HISTORICAL_CRITERION3
    args.out.write_text(json.dumps(out, indent=1, sort_keys=True), encoding="utf-8")
    print(f"wrote {args.out}", file=sys.stderr)


# ------------------------------------------------------------------------------------ compact


def _slim_pair(cell: Mapping, full: bool) -> dict:
    metrics = KEEP_METRICS if full else ("recall", "specificity", "f2")
    out = {k: cell[k] for k in ("n_rows", "n_clusters", "counts", "flips", "cluster_sign_test", "wald_recall", "wald_specificity") if k in cell}
    out["deltas"] = {n: {m: cell["deltas"][n][m] for m in metrics} for n in cell["deltas"]}
    return out


def _slim_spans(spans: Mapping) -> dict:
    keep = ("recall_overlap", "precision_overlap", "f1_overlap", "recall_iou50", "f1_iou50", "recall_exact", "f1_exact",
            "char_recall", "over_masking_share", "over_mask_chars_per_1k", "all_masked_rate", "clean_prompt_flag_rate")
    out: dict = {}
    for pair, subs in spans.items():
        cell_out = out.setdefault(pair, {})
        for sens, per_scope in subs["all"].items():
            for scope, cell in per_scope.items():
                e = {"scores": {}, "deltas": {}, "p4": {}}
                for layer, per_tag in cell["scores"].items():
                    e["scores"][layer] = {tag: {"metrics": {m: v["metrics"][m] for m in keep},
                                                "n_spanless_positive_results": v["n_spanless_positive_results"]}
                                          for tag, v in per_tag.items()}
                for layer, comp in cell["old_vs_new"].items():
                    e["deltas"][layer] = {"deltas": {m: comp["deltas"]["new"][m] for m in keep if m in comp["deltas"]["new"]},
                                          "all_masked_flips": comp["all_masked_flips"]}
                for tag, per_vs in cell["p4"].items():
                    e["p4"][tag] = {vs: {m: comp["deltas"][next(iter(comp["deltas"]))][m]
                                         for m in ("recall_overlap", "precision_overlap", "char_recall", "over_mask_chars_per_1k", "all_masked_rate")
                                         if m in comp["deltas"][next(iter(comp["deltas"]))]} for vs, comp in per_vs.items()}
                cell_out[f"{sens}/{scope}"] = e
    return out


def compact(res: Mapping) -> dict:
    """Committed form of the result: every hypothesis and promotion record in full, the prompt-level and span
    tables slimmed to their decision-relevant cells. Numbers are copied, never recomputed."""
    out = {k: res[k] for k in ("scope", "n_boot", "seed", "margin_points", "configs", "run_meta", "hypotheses", "promotion",
                               "historical_criterion3_context", "f2")}
    for name in ("f1", "f3"):
        s = res[name]
        out[name] = {"n_rows": s["n_rows"], "n_positive": s["n_positive"], "n_negative": s["n_negative"], "n_clusters": s["n_clusters"],
                     "per_config": s["per_config"],
                     "pairs": {pair: {layer: {rule: _slim_pair(cell, full=(rule == "positive")) for rule, cell in per_rule.items()}
                                      for layer, per_rule in per_layer.items()} for pair, per_layer in s["pairs"].items()}}
    out["spans_f1"] = _slim_spans(res["spans_f1"])
    out["spans_f3"] = _slim_spans(res["spans_f3"])
    p = res["perturbed"]
    out["perturbed"] = {"n_items_all_transforms": p["n_items_all_transforms"], "items_per_transform": p["items_per_transform"],
                        "hypotheses": {h: {"candidate": e["candidate"], "transforms": e["transforms"], "delta": e["delta"], "ci": e["ci"],
                                           "p_two_sided": e["p_two_sided"], "p_holm": e["p_holm"], "passes": e["passes"],
                                           "union": _slim_pair(e["union"], True) | {"n_items": e["union"]["n_items"], "n_rows": e["union"]["n_rows"]},
                                           "ner_only": _slim_pair(e["ner_only"], False), "regex_only": _slim_pair(e["regex_only"], False)}
                                       for h, e in p["hypotheses"].items()},
                        "per_transform": p["per_transform"]}
    return out


def command_compact(args) -> None:
    res = json.loads(args.input.read_text(encoding="utf-8"))
    args.output.write_text(json.dumps(compact(res), indent=1, sort_keys=True), encoding="utf-8")


# ------------------------------------------------------------------------------------ render


def pct(x, digits: int = 2) -> str:
    return "n/a" if x is None else f"{100 * x:.{digits}f}"


def ci_str(d: Mapping) -> str:
    return f"{pct(d['estimate'])} [{pct(d['lo'])}, {pct(d['hi'])}]"


def render(args) -> None:
    res = json.loads(args.input.read_text(encoding="utf-8"))
    H = res["hypotheses"]
    L: list[str] = []
    add = L.append
    add("## Hypothesis results (detector-layer; deltas in percentage points, 95 % grouped paired bootstrap, 10,000 replicates)\n")
    add("| Hypothesis | Estimate [95 % CI] (pt) | Test | Verdict |")
    add("|---|---|---|---|")
    h1 = H["H1"]
    add(f"| H1 regex specificity N - O, F1 clean | {ci_str(h1)} | McNemar p={h1['p_mcnemar_two_sided']:.4f}; gains {h1['flips']['fp_to_tn']}, losses {h1['flips']['tn_to_fp']} | {'pass' if h1['passes'] else 'not met'} |")
    add(f"| H1b F2 benign | - | - | {H['H1b']['status']} |")
    h2 = H["H2"]
    add(f"| H2 union recall N - O, F1 positives (NI, margin 1 pt) | {ci_str(h2)} | lower bound {pct(h2['lo'])} vs -1.00; Wald lower (row) {pct(h2['wald_recall']['lower_row_one_sided_975'])}, (cluster) {pct(h2['wald_recall']['lower_cluster_one_sided_975'])} | {'pass' if h2['passes'] else 'fail'} |")
    h2b = H["H2b"]
    add(f"| H2b union specificity N - O, F1 clean (NI, margin 1 pt) | {ci_str(h2b)} | lower bound {pct(h2b['lo'])} vs -1.00 | {'pass' if h2b['passes'] else 'fail'} (F2 part pending) |")
    ex = H["H2_exploratory_union_specificity_superiority"]
    add(f"| exploratory: union specificity superiority N - O, F1 | {ci_str(ex)} | McNemar p={ex['p_mcnemar_two_sided']:.4f} | exploratory |")
    for cand in NER_CONFIGS:
        h = H[f"H3[{cand}]"]
        tag = "" if cand == "N+lg" else " (descriptive)"
        for key, label in (("H3a_union_specificity_F1", "H3a union specificity, F1 clean"), ("H3b_ner_specificity_F1", "H3b NER-only specificity, F1 clean")):
            c = h[key]
            add(f"| {cand}{tag} {label} (vs N) | {ci_str(c)} | McNemar p={c['p_mcnemar_two_sided']:.4f}, Holm p={c['p_holm']:.4f} | {'pass' if c['passes'] else 'not met'} |")
        for key, label in (("H3c_union_recall_F1", "H3c union recall F1 (NI)"), ("H3c_union_recall_F3", "H3c union recall F3 (NI)")):
            c = h[key]
            add(f"| {cand}{tag} {label} (vs N) | {ci_str(c)} | lower bound {pct(c['lo'])} vs -1.00 | {'pass' if c['passes'] else 'fail'} |")
    h4 = H["H4"]
    a, b = h4["character_leak_non_inferiority"], h4["over_masking_non_inferiority"]
    add(f"| H4 char coverage N - O, F1 (leak NI, 1 pt) | {ci_str(a)} | lower bound {pct(a['lo'])} vs -1.00; leak {pct(a['leak_rate_old'])} -> {pct(a['leak_rate_new'])} | {'pass' if a['passes'] else 'fail'} |")
    add(f"| H4 over-masked chars per 1000 N - O, F1 (NI, 10 per 1000) | {b['estimate']:.3f} [{b['lo']:.3f}, {b['hi']:.3f}] | upper bound vs +10 per 1000; {b['old_per_1k']:.2f} -> {b['new_per_1k']:.2f} | {'pass' if b['passes'] else 'fail'} |")
    for hyp, e in H["H5"].items():
        add(f"| {hyp} {e['candidate']} perturbed union recall - N ({e['n_items']} items, {e['n_rows']} rows) | {pct(e['delta'])} [{pct(e['ci'][0])}, {pct(e['ci'][1])}] | gains {e['flips']['fn_to_tp']}, losses {e['flips']['tp_to_fn']}; McNemar p={e['p_two_sided']:.4g}, Holm p={e['p_holm']:.4g} | {'pass' if e['passes'] else 'not met'} |")
    for cand, e in H["H6"].items():
        cells = e["cells"]
        cs = "; ".join(f"{k.replace('_', ' ')} {pct(cells[k]['lo'])}" for k in ("F1_union_recall", "F1_union_specificity", "F3_union_recall"))
        add(f"| H6 {cand} clean non-inferiority (lower bounds, pt) | {cs} | flips F1 {e['clean_flips']['F1']}, F3 {e['clean_flips']['F3']} | {e['overall']} |")
    add("\n## Promotion verdicts\n")
    for cfg, v in res["promotion"].items():
        add(f"- **{cfg}**: {v['verdict']}")
    args.output.write_text("\n".join(L) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    an = sub.add_parser("analyse")
    an.add_argument("--results", type=Path, required=True)
    an.add_argument("--f1-gold", type=Path, required=True)
    an.add_argument("--f3-gold", type=Path, required=True)
    an.add_argument("--out", type=Path, required=True)
    an.add_argument("--repo", type=Path, default=None, help="git repository for the frozen-commit checks")
    an.add_argument("--n-boot", type=int, default=ds.DEFAULT_BOOTSTRAP)
    an.add_argument("--seed", type=int, default=ds.DEFAULT_SEED)
    an.add_argument("--workers", type=int, default=8)
    an.set_defaults(func=analyse)
    rd = sub.add_parser("render")
    rd.add_argument("--input", type=Path, required=True)
    rd.add_argument("--output", type=Path, required=True)
    rd.set_defaults(func=render)
    cp = sub.add_parser("compact")
    cp.add_argument("--input", type=Path, required=True)
    cp.add_argument("--output", type=Path, required=True)
    cp.set_defaults(func=command_compact)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
