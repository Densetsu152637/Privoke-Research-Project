"""v3 confirmatory analysis (detector-layer scope): H7, H8, guards G1/G2, H9, per-source and standardised cells.

Reads only the per-row outputs of ``w3_scoring.py`` / ``v3_scoring.py`` (ids, flags, spans) plus, for strata, span
tests and per-rule tables, the length, categories and gold spans of the registered fresh files (never printed).
Implements exactly the tests of ``docs/research/preregistration-detector-v3-20261025.md`` with the statistics of
``detector_stats.py`` (via the unchanged helpers of ``w3_analysis.py``). Part of the v3 freeze addendum; nothing here
may change after scoring starts.

Sub-commands: ``analyse`` (aggregate JSON), ``pool`` (extra blinded F2 packets for prompts K flags that the existing
pool does not hold), ``render`` (Markdown tables from the JSON).

Conventions (registration sections 6 and 7)
* delta = candidate - reference on identical rows; grouped (``group_id``) paired percentile bootstrap, 10,000
  replicates, seed 20261024; the lower limit of the 95 % interval is the one-sided 97.5 % lower bound;
* non-inferiority: ``pass`` iff lower limit > margin; ``fail`` iff upper limit <= margin; otherwise ``inconclusive``
  (an inconclusive result is not a pass);
* H7: union recall, rule ``positive``, margin -1.0 pt; H8: union recall, rule ``block``, margin -0.5 pt (K vs O, F4);
* G1: union specificity K vs O (margin -1.0 pt), G2: union specificity K vs N (margin -2.0 pt), on S1 (F1 clean rows).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import detector_stats as ds  # noqa: E402
import span_scoring as ss  # noqa: E402
import w3_analysis as wa  # noqa: E402

CONFIGS = ["O", "N", "K", "K+all"]
REUSED = ("O", "N")                      # Wave 3 per-row outputs are reused for F1, F2 and F3 (registration section 8)
SETS = ("f1", "f2", "f3", "f4")
REGISTERED_COUNTS = {"f4": 8646, "f1": 16446, "f1_pos": 10000, "f1_clean": 6446, "f3": 2000, "f2": 6000}
LAYERS = ("regex", "ner", "union")
RULES = ds.RULES
M_H7, M_H8, M_G1, M_G2, M_HET = -0.01, -0.005, -0.01, -0.02, -0.01
SOURCE_KEYS = [("ai4privacy", "ai4privacy"), ("Gretel", "gretel"), ("Nemotron-PII", "nemotron"), ("Privy", "privy")]
W_F1_MIX = (0.3374, 0.3325, 0.1687, 0.1614)
W_EQUAL = (0.25, 0.25, 0.25, 0.25)
MIN_ROWS_HETEROGENEITY = 700
F4_PAIRS = [("O", "K"), ("O", "N"), ("N", "K"), ("K", "K+all"), ("O", "K+all")]
F1_PAIRS = F4_PAIRS
F3_PAIRS = [("O", "K"), ("O", "N"), ("N", "K"), ("K", "K+all")]
SPAN_PAIRS_F4 = [("O", "K"), ("N", "K"), ("O", "N"), ("K", "K+all")]
SPAN_PAIRS_OTHER = [("O", "K"), ("N", "K")]
# Historical development-record context for promotion criterion 6 (not fresh; K's design sets).
# Source: docs/experiments/regex-rework-20261025.md at c8ceaacc (union, any finding, recall).
HISTORICAL_CRITERION6 = {
    "personalized": {"N": 1.0000, "K": 1.0000},
    "openai": {"N": 0.9180, "K": 0.9200},
    "source": "docs/experiments/regex-rework-20261025.md (research/wt-k-rework c8ceaacc); K's design/post-review sets",
}


# ------------------------------------------------------------------------------------ small helpers


def label_of(cfg: str) -> str:
    return cfg.replace("+", "_")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path: Path) -> list[dict]:
    return wa.load_jsonl(path)


def pct(x, digits: int = 2) -> str:
    return "n/a" if x is None else f"{100 * x:.{digits}f}"


def ni_verdict(lo, hi, margin: float) -> str:
    """Registered non-inferiority decision from a two-sided 95 % percentile interval (lower limit = one-sided 97.5 %)."""
    if lo is None or hi is None:
        return "undefined"
    if lo > margin:
        return "pass"
    if hi <= margin:
        return "fail"
    return "inconclusive"


def source_of(stratum: str | None) -> str | None:
    s = (stratum or "").lower()
    for name, key in SOURCE_KEYS:
        if key.lower() in s:
            return name
    return None


def row_dirs(results_w3: Path, results_v3: Path, cfg: str, set_name: str) -> Path:
    """Directory holding a configuration's output for a set: O and N reuse the Wave 3 outputs for F1, F2, F3."""
    if cfg in REUSED and set_name in ("f1", "f2", "f3"):
        return results_w3 / label_of(cfg)
    return results_v3 / label_of(cfg)


def load_rows(results_w3: Path, results_v3: Path, set_name: str) -> dict[str, list[dict]]:
    return {cfg: load(row_dirs(results_w3, results_v3, cfg, set_name) / f"{set_name}.rows.jsonl") for cfg in CONFIGS}


def completeness(rows: Mapping[str, Mapping[str, Sequence[dict]]], expect: bool = True) -> dict:
    """Row counts and identical id lists/labels across configurations; raise on any mismatch."""
    out: dict = {}
    for set_name, per_cfg in rows.items():
        base = per_cfg[CONFIGS[0]]
        ids = [r["example_id"] for r in base]
        labels = [r["expected_has_pii"] for r in base]
        entry = {"n_rows": len(base), "n_positive": sum(1 for x in labels if x), "n_clean": sum(1 for x in labels if x is False),
                 "unlabelled": sum(1 for x in labels if x is None), "per_config": {}}
        for cfg in CONFIGS:
            r = per_cfg[cfg]
            same = [x["example_id"] for x in r] == ids and [x["expected_has_pii"] for x in r] == labels
            if not same or len(set(ids)) != len(ids):
                raise ValueError(f"{set_name}/{cfg}: ids or labels differ from {CONFIGS[0]} (or duplicate ids)")
            entry["per_config"][cfg] = len(r)
        out[set_name] = entry
    if expect:
        want = REGISTERED_COUNTS
        got = {"f4": out["f4"]["n_rows"], "f1": out["f1"]["n_rows"], "f1_pos": out["f1"]["n_positive"],
               "f1_clean": out["f1"]["n_clean"], "f3": out["f3"]["n_rows"], "f2": out["f2"]["n_rows"]}
        if got != want:
            raise ValueError(f"row counts {got} differ from the registered {want}")
        if out["f4"]["n_clean"] or out["f4"]["unlabelled"]:
            raise ValueError("F4 must be positives only")
    return out


# ------------------------------------------------------------------------------------ pair cells


def sub_rows(rows: Sequence[dict], keep) -> list[dict]:
    return [r for r in rows if keep(r)]


def cell(ref: Sequence[dict], cand: Sequence[dict], layer: str, rule: str, n_boot: int, seed: int, keep=None) -> dict:
    if keep is not None:
        ids = {r["example_id"] for r in ref if keep(r)}
        ref = [r for r in ref if r["example_id"] in ids]
        cand = [r for r in cand if r["example_id"] in ids]
    return wa.pair_cell(ref, cand, layer, rule, n_boot, seed)


def headline(c: Mapping, metric: str = "recall", wald: str = "wald_recall") -> dict:
    d = c["deltas"]["cand"][metric]
    flips = c["flips"]
    pos = metric == "recall"
    gained = flips["fn_to_tp"] if pos else flips["fp_to_tn"]
    lost = flips["tp_to_fn"] if pos else flips["tn_to_fp"]
    mc = flips["mcnemar_positives" if pos else "mcnemar_negatives"]
    n = c["counts"]["base"]["tp"] + c["counts"]["base"]["fn"] if pos else c["counts"]["base"]["tn"] + c["counts"]["base"]["fp"]
    base_est = c["metrics"]["base"][metric]["estimate"]
    cand_est = c["metrics"]["cand"][metric]["estimate"]
    w = c.get(wald) or {}
    return {"n": n, "base": base_est, "cand": cand_est, "delta": d["estimate"], "lo": d["lo"], "hi": d["hi"],
            "gained": gained, "lost": lost, "discordant": gained + lost, "p_mcnemar_two_sided": mc["p_two_sided"],
            "wald_lower_row": w.get("lower_row_one_sided_975"), "wald_lower_cluster": w.get("lower_cluster_one_sided_975"),
            "n_clusters": c["n_clusters"]}


def ni_cell(c: Mapping, metric: str, margin: float, wald: str) -> dict:
    h = headline(c, metric, wald)
    h["margin"] = margin
    h["verdict"] = ni_verdict(h["lo"], h["hi"], margin)
    return h


def config_table(rows: Mapping[str, Sequence[dict]], n_boot: int, seed: int) -> dict:
    """Per-configuration confusion counts and point metrics with 95 % grouped-bootstrap intervals (same rows)."""
    base = rows[CONFIGS[0]]
    labels, groups = ds.labels_of(base), ds.cluster_groups(base, "group_id")
    out: dict = {}
    for layer in LAYERS:
        for rule in RULES:
            decisions = {c: ds.predictions(rows[c], layer, rule) for c in CONFIGS}
            res = ds.paired_bootstrap(labels, groups, decisions, baseline=CONFIGS[0], n_boot=n_boot, seed=seed)
            out.setdefault(layer, {})[rule] = {c: {"counts": res["counts"][c], "metrics": {m: res["metrics"][c][m] for m in wa.KEEP_METRICS}}
                                               for c in CONFIGS}
    return out


def full_pairs(rows: Mapping[str, Sequence[dict]], pairs, n_boot: int, seed: int, keep=None) -> dict:
    out: dict = {}
    for ref, cand in pairs:
        for layer in LAYERS:
            for rule in RULES:
                out.setdefault(f"{ref}>{cand}", {}).setdefault(layer, {})[rule] = wa._slim_pair(
                    cell(rows[ref], rows[cand], layer, rule, n_boot, seed, keep), full=(rule == "positive"))
    return out


# ------------------------------------------------------------------------------------ standardised H7


def standardised_delta(ref: Sequence[dict], cand: Sequence[dict], weights_by_name: Mapping[str, Sequence[float]],
                       layer: str = "union", rule: str = "positive", n_boot: int = 10_000, seed: int = ds.DEFAULT_SEED) -> dict:
    """Sum over sources of weight x within-source delta of recall (cand - ref), with a stratified cluster bootstrap.

    Whole ``group_id`` clusters are resampled within each source (positives only: F4 has no clean class), 10,000
    replicates, one shared stream of draws for every weight vector. Returns point estimates and 95 % percentile
    intervals per weight vector plus the per-source deltas of the same replicates.
    """
    pairs = ds.align_rows(ref, cand)
    names = [n for n, _ in SOURCE_KEYS]
    per_source: dict[str, dict] = {}
    for a, b in pairs:
        if not a["expected_has_pii"]:
            continue
        src = source_of(a.get("stratum"))
        if src is None:
            raise ValueError(f"unmapped source stratum {a.get('stratum')!r}")
        g = str(a["group_id"]) if a.get("group_id") is not None else f"row:{a['example_id']}"
        pa, pb = ds.row_prediction(a, layer, rule), ds.row_prediction(b, layer, rule)
        slot = per_source.setdefault(src, {}).setdefault(g, [0, 0])
        slot[0] += int(pb) - int(pa)
        slot[1] += 1
    rng = np.random.default_rng(seed)
    arrays = {}
    boot = {}
    for src in names:
        clusters = per_source.get(src, {})
        d = np.array([v[0] for v in clusters.values()], dtype=float)
        n = np.array([v[1] for v in clusters.values()], dtype=float)
        arrays[src] = (d, n)
        k = len(d)
        draws = []
        done = 0
        while done < n_boot:
            b = min(1000, n_boot - done)
            idx = rng.integers(0, k, size=(b, k))
            draws.append(d[idx].sum(axis=1) / n[idx].sum(axis=1))
            done += b
        boot[src] = np.concatenate(draws)
    point = {src: float(arrays[src][0].sum() / arrays[src][1].sum()) for src in names}
    out: dict = {"per_source_delta": point, "n_rows_per_source": {s: int(arrays[s][1].sum()) for s in names},
                 "n_clusters_per_source": {s: len(arrays[s][0]) for s in names}, "n_boot": n_boot, "seed": seed,
                 "per_source_ci": {s: [float(np.quantile(boot[s], 0.025)), float(np.quantile(boot[s], 0.975))] for s in names},
                 "weights": {}}
    for label, w in weights_by_name.items():
        est = float(sum(wi * point[s] for wi, s in zip(w, names)))
        dist = sum(wi * boot[s] for wi, s in zip(w, names))
        out["weights"][label] = {"vector": list(w), "estimate": est, "lo": float(np.quantile(dist, 0.025)),
                                 "hi": float(np.quantile(dist, 0.975))}
    return out


# ------------------------------------------------------------------------------------ flips and layer identity


def layer_identity(a_rows: Sequence[dict], b_rows: Sequence[dict], layer: str) -> dict:
    """Row-level equality of a layer's record (flags, sensitivity, categories, action) between two configurations."""
    mism = sum(1 for x, y in zip(a_rows, b_rows) if x[layer] != y[layer])
    flag = sum(1 for x, y in zip(a_rows, b_rows) if x[layer]["positive"] != y[layer]["positive"])
    return {"rows": len(a_rows), "records_differ": mism, "positive_flag_differs": flag}


def union_flips(a_rows: Sequence[dict], b_rows: Sequence[dict]) -> dict:
    out = {}
    for rule in RULES:
        pa, pb = ds.predictions(a_rows, "union", rule), ds.predictions(b_rows, "union", rule)
        out[rule] = {"b_only": sum(1 for x, y in zip(pa, pb) if y and not x), "a_only": sum(1 for x, y in zip(pa, pb) if x and not y)}
    return out


def hybrid(regex_rows: Sequence[dict], ner_rows: Sequence[dict]) -> list[dict]:
    """Union decision = regex(regex_rows) OR ner(ner_rows) under the positive rule (other fields not meaningful)."""
    out = []
    for x, y in zip(regex_rows, ner_rows):
        z = dict(x)
        z["union"] = {"positive": bool(x["regex"]["positive"] or y["ner"]["positive"]), "action": "ALLOW",
                      "categories": [], "max_sensitivity": "S0"}
        out.append(z)
    return out


# ------------------------------------------------------------------------------------ exploratory per-rule tables


def overlaps(span: Mapping, gold) -> bool:
    return any(span["start"] < e and s < span["end"] for s, e, _ in gold)


def rule_table(ref: Sequence[dict], cand: Sequence[dict], ref_spans: Mapping[str, Mapping], cand_spans: Mapping[str, Mapping],
               gold: Mapping[str, list]) -> dict:
    """EXPLORATORY: which regex rules sit behind union-recall flips (cand vs ref, positive rule) and BLOCK flips."""
    lost = [(a, b) for a, b in zip(ref, cand) if a["expected_has_pii"] and a["union"]["positive"] and not b["union"]["positive"]]
    gained = [(a, b) for a, b in zip(ref, cand) if a["expected_has_pii"] and not a["union"]["positive"] and b["union"]["positive"]]
    out: dict = {"lost_rows": len(lost), "gained_rows": len(gained)}
    out["lost_by_ref_layer"] = dict(Counter("regex-only" if a["regex"]["positive"] and not a["ner"]["positive"] else
                                            "ner-only" if a["ner"]["positive"] and not a["regex"]["positive"] else "both" for a, _ in lost))
    out["gained_by_cand_layer"] = dict(Counter("regex-only" if b["regex"]["positive"] and not b["ner"]["positive"] else
                                               "ner-only" if b["ner"]["positive"] and not b["regex"]["positive"] else "both" for _, b in gained))
    lost_tab: dict[str, Counter] = defaultdict(Counter)
    for a, _ in [(a, b) for a, b in lost if a["regex"]["positive"]]:
        sp = ref_spans[a["example_id"]]["layers"]["regex"]
        rules = {s["source"] for s in sp}
        for r in rules:
            lost_tab[r]["lost_rows_containing_rule"] += 1
            if len(rules) == 1:
                lost_tab[r]["lost_rows_sole_rule"] += 1
        for s in sp:
            lost_tab[s["source"]]["spans_on_gold" if overlaps(s, gold[a["example_id"]]) else "spans_off_gold"] += 1
    gained_tab: dict[str, Counter] = defaultdict(Counter)
    for _, b in [(a, b) for a, b in gained if b["regex"]["positive"]]:
        sp = cand_spans[b["example_id"]]["layers"]["regex"]
        rules = {s["source"] for s in sp}
        for r in rules:
            gained_tab[r]["gained_rows_containing_rule"] += 1
            if len(rules) == 1:
                gained_tab[r]["gained_rows_sole_rule"] += 1
        for s in sp:
            gained_tab[s["source"]]["spans_on_gold" if overlaps(s, gold[b["example_id"]]) else "spans_off_gold"] += 1
    blk_lost = [(a, b) for a, b in zip(ref, cand) if a["expected_has_pii"] and a["union"]["action"] == "BLOCK" and b["union"]["action"] != "BLOCK"]
    blk_gain = [(a, b) for a, b in zip(ref, cand) if a["expected_has_pii"] and a["union"]["action"] != "BLOCK" and b["union"]["action"] == "BLOCK"]
    blk_lost_rules: Counter = Counter()
    for a, _ in blk_lost:
        for r in {s["source"] for s in ref_spans[a["example_id"]]["layers"]["regex"] if s["sensitivity"] == "S3"}:
            blk_lost_rules[r] += 1
    blk_gain_rules: Counter = Counter()
    for _, b in blk_gain:
        for r in {s["source"] for s in cand_spans[b["example_id"]]["layers"]["regex"] if s["sensitivity"] == "S3"}:
            blk_gain_rules[r] += 1
    out.update({"regex_caused_lost_by_ref_rule": {r: dict(c) for r, c in sorted(lost_tab.items(), key=lambda kv: -kv[1]["lost_rows_containing_rule"])},
                "regex_caused_gained_by_cand_rule": {r: dict(c) for r, c in sorted(gained_tab.items(), key=lambda kv: -kv[1]["gained_rows_containing_rule"])},
                "block_lost": len(blk_lost), "block_gained": len(blk_gain),
                "block_lost_to_action": dict(Counter(b["union"]["action"] for _, b in blk_lost)),
                "block_lost_ref_S3_rules": dict(blk_lost_rules.most_common()),
                "block_gained_cand_S3_rules": dict(blk_gain_rules.most_common())})
    return out


# ------------------------------------------------------------------------------------ strata


def length_strata(gold: Sequence[dict], n_groups: int = 4) -> dict[str, str]:
    """Row id -> length stratum label (quartiles of the character length of the registered file)."""
    lens = sorted(len(g["text"]) for g in gold)
    cuts = [lens[int(len(lens) * (i + 1) / n_groups) - 1] for i in range(n_groups - 1)]
    out = {}
    for g in gold:
        n = len(g["text"])
        i = sum(1 for c in cuts if n > c)
        lo = 0 if i == 0 else cuts[i - 1] + 1
        hi = cuts[i] if i < len(cuts) else None
        out[str(g["id"])] = f"Q{i + 1} ({lo}-{hi if hi is not None else 'max'} chars)"
    return out


def strata_cells(rows: Mapping[str, Sequence[dict]], strata_of: Mapping[str, list], pairs, n_boot: int, seed: int,
                 min_rows: int = 100) -> dict:
    """EXPLORATORY: union-recall delta (positive and block rules) per stratum (a row may carry several strata)."""
    labels = sorted({s for v in strata_of.values() for s in v})
    out: dict = {}
    for lab in labels:
        ids = {i for i, v in strata_of.items() if lab in v}
        if len(ids) < min_rows:
            continue
        for ref, cand in pairs:
            for rule in ("positive", "block"):
                c = cell(rows[ref], rows[cand], "union", rule, n_boot, seed, keep=lambda r, ids=ids: r["example_id"] in ids)
                out.setdefault(lab, {}).setdefault(f"{ref}>{cand}", {})[rule] = headline(c)
    return out


# ------------------------------------------------------------------------------------ spans


def _span_task(task: tuple) -> tuple[str, str, dict]:
    set_name, ref, cand, gold_path, ref_path, cand_path, n_boot, seed = task
    gold = load(Path(gold_path))
    old, new = load(Path(ref_path)), load(Path(cand_path))
    ss.SUBSETS = {"all": None}
    study = ss.run_study(gold, old, new, n_boot=n_boot, seed=seed)
    study["unmapped_gold_labels"] = dict(ss.unmapped_labels(gold))
    return set_name, f"{ref}>{cand}", wa.span_pair_headline(study)


def span_studies(tasks_spec: Sequence[tuple], workers: int) -> dict:
    out: dict = {}
    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(_span_task, tasks_spec))
    else:
        results = [_span_task(t) for t in tasks_spec]
    for set_name, key, value in results:
        out.setdefault(set_name, {})[key] = value
    return out


# ------------------------------------------------------------------------------------ F2


def f2_descriptive(rows: Mapping[str, Sequence[dict]]) -> dict:
    base = rows["O"]
    strata = sorted({r["stratum"] for r in base if r.get("stratum")})
    out: dict = {"n": len(base), "labels": "none (F2 is unlabelled; flag rates only, no verdicts)", "per_config": {}, "flips": {}}
    for cfg in CONFIGS:
        out["per_config"][cfg] = {}
        for layer in LAYERS:
            for rule in RULES:
                flags = [ds.row_prediction(r, layer, rule) for r in rows[cfg]]
                k, n = sum(flags), len(flags)
                lo, hi = wa.wilson(k, n)
                by = {s: {"flagged": sum(f for f, r in zip(flags, rows[cfg]) if r.get("stratum") == s),
                          "n": sum(1 for r in rows[cfg] if r.get("stratum") == s)} for s in strata}
                out["per_config"][cfg].setdefault(layer, {})[rule] = {"flagged": k, "n": n, "rate": k / n, "wilson95": [lo, hi], "by_stratum": by}
    for ref, cand in (("O", "K"), ("N", "K"), ("K", "K+all"), ("O", "N")):
        a = {r["example_id"]: r for r in rows[ref]}
        b = {r["example_id"]: r for r in rows[cand]}
        out["flips"][f"{ref}>{cand}"] = {
            layer: {"cand_only": sum(1 for i in a if b[i][layer]["positive"] and not a[i][layer]["positive"]),
                    "ref_only": sum(1 for i in a if a[i][layer]["positive"] and not b[i][layer]["positive"]),
                    "both": sum(1 for i in a if a[i][layer]["positive"] and b[i][layer]["positive"])} for layer in LAYERS}
    return out


def extra_pool_ids(rows_k: Sequence[dict], key: Mapping, existing_pool_items: set[str]) -> list[str]:
    """Opaque ids of prompts K flags (union layer, positive rule) that the existing review pool does not hold."""
    opaque_of = {f2: opaque for opaque, f2 in key["key"].items()}
    if {r["example_id"] for r in rows_k} != set(opaque_of):
        raise ValueError("F2 ids of the scored rows differ from the adjudication key")
    flagged = {opaque_of[r["example_id"]] for r in rows_k if r["union"]["positive"]}
    return sorted(flagged - set(existing_pool_items))


# ------------------------------------------------------------------------------------ analyse


def dump(path: Path, obj) -> str:
    text = json.dumps(obj, indent=1, sort_keys=True)
    path.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def analyse(args) -> None:
    n_boot, seed = args.n_boot, args.seed
    rows = {s: load_rows(args.results_w3, args.results_v3, s) for s in SETS}
    comp = completeness(rows, expect=not args.standin)
    metas = {c: json.loads((args.results_v3 / label_of(c) / "run_meta.json").read_text(encoding="utf-8")) for c in CONFIGS}
    reused_hashes = {f"{c}/{s}.rows.jsonl": sha256_file(args.results_w3 / label_of(c) / f"{s}.rows.jsonl")
                     for c in REUSED for s in ("f1", "f2", "f3")}
    out: dict = {"scope": "detector-layer (regex, NER, regex OR NER); not LLM-only, not semantic, not full-product",
                 "registration": "docs/research/preregistration-detector-v3-20261025.md", "n_boot": n_boot, "seed": seed,
                 "standin_mode": bool(args.standin), "configs": CONFIGS, "completeness": comp,
                 "reused_wave3_outputs_sha256": reused_hashes,
                 "run_meta": {c: {k: m.get(k) for k in ("tree", "tree_export_sha", "observed_flags", "ner_model", "ner_model_version", "spacy",
                                                        "python", "sets", "driver_sha256", "env")} for c, m in metas.items()}}
    f4, f1, f3, f2 = rows["f4"], rows["f1"], rows["f3"], rows["f2"]

    # ---- F4: the confirmatory set
    f4_cells = full_pairs(f4, F4_PAIRS, n_boot, seed)
    out["f4"] = {"n_rows": len(f4["O"]), "n_clusters": len({r["group_id"] for r in f4["O"]}),
                 "per_config": config_table(f4, n_boot, seed), "pairs": f4_cells}
    k_o_pos = cell(f4["O"], f4["K"], "union", "positive", n_boot, seed)
    k_o_blk = cell(f4["O"], f4["K"], "union", "block", n_boot, seed)
    h7 = ni_cell(k_o_pos, "recall", M_H7, "wald_recall")
    h8 = ni_cell(k_o_blk, "recall", M_H8, "wald_recall")
    H: dict = {"H7": h7, "H8": h8}
    # context for H7/H8: N vs O and K vs N on the same cells
    H["context"] = {
        "N_minus_O_union_positive": headline(cell(f4["O"], f4["N"], "union", "positive", n_boot, seed)),
        "N_minus_O_union_block": headline(cell(f4["O"], f4["N"], "union", "block", n_boot, seed)),
        "K_minus_N_union_positive": headline(cell(f4["N"], f4["K"], "union", "positive", n_boot, seed)),
        "K_minus_N_union_block": headline(cell(f4["N"], f4["K"], "union", "block", n_boot, seed)),
        "K_minus_N_regex_positive": headline(cell(f4["N"], f4["K"], "regex", "positive", n_boot, seed)),
        "K_minus_O_regex_positive": headline(cell(f4["O"], f4["K"], "regex", "positive", n_boot, seed)),
        "K_minus_O_ner_positive": headline(cell(f4["O"], f4["K"], "ner", "positive", n_boot, seed)),
        "K_all_minus_O_union_positive_NI_margin_1pt_descriptive": ni_cell(cell(f4["O"], f4["K+all"], "union", "positive", n_boot, seed),
                                                                           "recall", M_H7, "wald_recall")}

    # ---- per-source secondaries and standardised H7
    by_source: dict = {}
    for name, _ in SOURCE_KEYS:
        keep = lambda r, name=name: source_of(r.get("stratum")) == name  # noqa: E731
        entry = {"n_rows": sum(1 for r in f4["O"] if keep(r)), "n_clusters": len({r["group_id"] for r in f4["O"] if keep(r)})}
        for ref, cand in (("O", "K"), ("O", "N"), ("N", "K")):
            for rule, label in (("positive", "H7"), ("block", "H8")):
                entry[f"{ref}>{cand}__union_{rule}"] = headline(cell(f4[ref], f4[cand], "union", rule, n_boot, seed, keep))
            entry[f"{ref}>{cand}__regex_positive"] = headline(cell(f4[ref], f4[cand], "regex", "positive", n_boot, seed, keep))
        h7s = entry["O>K__union_positive"]
        entry["heterogeneity_rule"] = ("reportable" if entry["n_rows"] >= MIN_ROWS_HETEROGENEITY else "reported only (fewer than 700 rows)")
        entry["whole_interval_below_margin"] = bool(h7s["hi"] is not None and h7s["hi"] < M_HET)
        entry["documented_negative_heterogeneity_finding"] = bool(entry["whole_interval_below_margin"] and entry["n_rows"] >= MIN_ROWS_HETEROGENEITY)
        by_source[name] = entry
    weights = {"F1_positive_mix": W_F1_MIX, "equal": W_EQUAL}
    standardised = {f"{ref}>{cand}": standardised_delta(f4[ref], f4[cand], weights, "union", "positive", n_boot, seed)
                    for ref, cand in (("O", "K"), ("O", "N"), ("N", "K"))}
    H["per_source"] = by_source
    H["standardised_H7"] = standardised
    H["standardised_H7_note"] = ("secondary, descriptive, not used for promotion; stratified cluster bootstrap within source "
                                 f"({n_boot} replicates, seed {seed}); NI verdict against -1.0 pt shown for information")
    for key, st in standardised.items():
        for label, w in st["weights"].items():
            w["verdict_vs_minus_1pt_information_only"] = ni_verdict(w["lo"], w["hi"], M_H7)

    # ---- S1 (F1 clean): H9, G1, G2
    clean = lambda r: r["expected_has_pii"] is False  # noqa: E731
    s1 = {}
    for ref, cand in F1_PAIRS:
        for layer in ("regex", "ner", "union"):
            for rule in RULES:
                c = cell(f1[ref], f1[cand], layer, rule, n_boot, seed, clean)
                s1.setdefault(f"{ref}>{cand}", {}).setdefault(layer, {})[rule] = headline(c, "specificity", "wald_specificity")
    g1 = ni_cell(cell(f1["O"], f1["K"], "union", "positive", n_boot, seed, clean), "specificity", M_G1, "wald_specificity")
    g2 = ni_cell(cell(f1["N"], f1["K"], "union", "positive", n_boot, seed, clean), "specificity", M_G2, "wald_specificity")
    H["G1"], H["G2"] = g1, g2
    H["H9_S1_clean_specificity"] = s1
    pos = lambda r: r["expected_has_pii"] is True  # noqa: E731
    s1_recall = {}
    for ref, cand in F1_PAIRS:
        for layer in LAYERS:
            for rule in RULES:
                s1_recall.setdefault(f"{ref}>{cand}", {}).setdefault(layer, {})[rule] = headline(cell(f1[ref], f1[cand], layer, rule, n_boot, seed, pos))
    H["second_look_F1_positive_recall"] = s1_recall
    out["f1"] = {"n_rows": len(f1["O"]), "n_positive": comp["f1"]["n_positive"], "n_clean": comp["f1"]["n_clean"],
                 "per_config": config_table(f1, n_boot, seed)}
    out["f3"] = {"n_rows": len(f3["O"]), "per_config": config_table(f3, n_boot, seed), "pairs": full_pairs(f3, F3_PAIRS, n_boot, seed)}
    out["f2"] = f2_descriptive(f2)

    # ---- equivalences observed on the scored rows
    ident = {}
    for s in ("f4", "f1", "f3", "f2"):
        ident[s] = {"K_vs_N_ner_layer": layer_identity(rows[s]["N"], rows[s]["K"], "ner"),
                    "K_all_vs_K_union_flips": union_flips(rows[s]["K"], rows[s]["K+all"]),
                    "K_all_vs_K_regex_records": layer_identity(rows[s]["K"], rows[s]["K+all"], "regex"),
                    "K_all_vs_K_ner_records": layer_identity(rows[s]["K"], rows[s]["K+all"], "ner")}
    out["identities"] = ident

    # ---- gold-dependent material (strata, per-rule tables, spans); gold files are read, never printed
    gold4 = load(args.f4_gold)
    gold_ent = {str(g["id"]): [(e["start"], e["end"], e["label"]) for e in g.get("entities") or []] for g in gold4}
    spans = {c: {s: {x["id"]: x for x in load(row_dirs(args.results_w3, args.results_v3, c, s) / f"{s}.spans.jsonl")} for s in ("f4",)}
             for c in CONFIGS}
    expl: dict = {"label": "EXPLORATORY: produced after the registered results; cannot satisfy or replace a registered hypothesis"}
    attribution = {}
    for name, regex_cfg, ner_cfg in (("O_regex+N_ner", "O", "N"), ("N_regex+O_ner", "N", "O"), ("K_regex+O_ner", "K", "O"),
                                      ("O_regex+K_ner", "O", "K"), ("K_regex+N_ner", "K", "N")):
        hy = hybrid(f4[regex_cfg], f4[ner_cfg])
        attribution[f"{name}__minus_O"] = headline(wa.pair_cell(f4["O"], hy, "union", "positive", n_boot, seed))
    attribution["note"] = ("exact layer swapping on F4, positive rule; K and N share the NER layer, so K_regex+N_ner equals K and the "
                           "K-O difference sits in the regex layer when 'K_regex+O_ner' accounts for it")
    expl["layer_attribution_F4"] = attribution
    expl["rule_tables_F4"] = {f"{r}>{c}": rule_table(f4[r], f4[c], spans[r]["f4"], spans[c]["f4"], gold_ent)
                              for r, c in (("O", "K"), ("O", "N"), ("N", "K"))}
    lengths = length_strata(gold4)
    cat_of = {str(g["id"]): [f"category:{c}" for c in (g.get("expected_categories") or [])] for g in gold4}
    len_of = {i: [lab] for i, lab in lengths.items()}
    expl["strata_length_F4"] = strata_cells(f4, len_of, [("O", "K"), ("O", "N")], n_boot, seed)
    expl["strata_category_F4"] = strata_cells(f4, cat_of, [("O", "K"), ("O", "N")], n_boot, seed)
    out["exploratory"] = expl
    out["historical_criterion6"] = HISTORICAL_CRITERION6

    # ---- spans (secondary, no hypothesis)
    if not args.no_spans:
        specs = []
        for ref, cand in SPAN_PAIRS_F4:
            specs.append(("f4", ref, cand, str(args.f4_gold), str(row_dirs(args.results_w3, args.results_v3, ref, "f4") / "f4.spans.jsonl"),
                          str(row_dirs(args.results_w3, args.results_v3, cand, "f4") / "f4.spans.jsonl"), n_boot, seed))
        for set_name, gold_path in (("f1", args.f1_gold), ("f3", args.f3_gold)):
            for ref, cand in SPAN_PAIRS_OTHER:
                specs.append((set_name, ref, cand, str(gold_path),
                              str(row_dirs(args.results_w3, args.results_v3, ref, set_name) / f"{set_name}.spans.jsonl"),
                              str(row_dirs(args.results_w3, args.results_v3, cand, set_name) / f"{set_name}.spans.jsonl"), n_boot, seed))
        out["spans"] = span_studies(specs, args.workers)

    out["hypotheses"] = H
    out["promotion"] = promotion(H)
    dump(args.out, out)
    print(f"wrote {args.out}", file=sys.stderr)


# ------------------------------------------------------------------------------------ promotion


def promotion(H: Mapping) -> dict:
    """Registered promotion rule for K (registration section 6). Criteria 4 and 5 are outside this script."""
    c1, c2 = H["H7"]["verdict"], H["H8"]["verdict"]
    g1, g2 = H["G1"]["verdict"], H["G2"]["verdict"]
    crit6 = {s: v["K"] >= v["N"] - 0.01 for s, v in HISTORICAL_CRITERION6.items() if isinstance(v, dict) and "K" in v}
    met = {"1_H7_pass": c1 == "pass", "2_H8_pass": c2 == "pass", "3_G1_and_G2_hold": g1 == "pass" and g2 == "pass",
           "6_historical_synthetic_context": all(crit6.values())}
    if not (met["1_H7_pass"] and met["2_H8_pass"]):
        verdict = "not promoted (criterion 1 or 2 not met; the pre-registered conclusion is the trade-off)"
    elif not met["3_G1_and_G2_hold"]:
        verdict = "not promoted (a false-positive guard failed)"
    elif not met["6_historical_synthetic_context"]:
        verdict = "not promoted (criterion 6 not met)"
    else:
        verdict = "criteria 1, 2, 3 and 6 met; recommendation still requires criterion 4 (critic review) and 5 (latency record)"
    return {"K": {"criteria": met, "H7": c1, "H8": c2, "G1": g1, "G2": g2, "criterion6_detail": crit6,
                  "criterion4_critic_review": "pending", "criterion5_latency": "pending (separate record; not measured here)",
                  "verdict": verdict}}


# ------------------------------------------------------------------------------------ extra F2 packets


def command_pool(args) -> None:
    rows_k = load(args.results_v3 / "K" / "f2.rows.jsonl")
    rows_ka = load(args.results_v3 / "K_all" / "f2.rows.jsonl")
    key = json.loads((args.adjudication / "coordinator" / "adjudication_key.json").read_text(encoding="utf-8"))
    existing = set()
    for p in sorted((args.adjudication / "pool" / "packets").glob("pool-packet-*.jsonl")):
        existing.update(r["item"] for r in load(p))
    extra = extra_pool_ids(rows_k, key, existing)
    extra_ka = extra_pool_ids(rows_ka, key, existing | set(extra))
    texts = {}
    for p in sorted((args.adjudication / "packets").glob("packet-*.jsonl")):
        for r in load(p):
            texts[r["item"]] = r["text"]
    if set(extra) - set(texts):
        raise ValueError("extra item missing from the blinded packets")
    out_packets = args.out / "packets"
    (args.out / "coordinator").mkdir(parents=True, exist_ok=True)
    out_packets.mkdir(parents=True, exist_ok=True)
    packets = []
    for number, start in enumerate(range(0, len(extra), 100), start=1):
        block = extra[start:start + 100]
        name = f"pool-extra-packet-{number:03d}.jsonl"
        payload = "".join(json.dumps({"item": i, "text": texts[i]}, sort_keys=True) + "\n" for i in block).encode("utf-8")
        (out_packets / name).write_bytes(payload)
        packets.append({"packet": name, "items": len(block), "first": block[0], "last": block[-1], "sha256": hashlib.sha256(payload).hexdigest()})
    flagged_k = sum(1 for r in rows_k if r["union"]["positive"])
    manifest = {"set": "F2 review pool, K extension (v3)", "existing_pool_size": len(existing), "k_flagged_union_positive": flagged_k,
                "extra_items": len(extra), "extra_items_flagged_only_by_K_all": len(extra_ka),
                "purpose": "blinded rating packets, same format as the existing pool: opaque id and prompt text only, no labels, no detector output",
                "rule": "every prompt K flags (union layer, positive rule) that is not in the existing 2,449-prompt pool",
                "packets": packets}
    (args.out / "coordinator" / "pool_extra_manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8")
    (args.out / "coordinator" / "pool_extra_items.json").write_text(json.dumps({"extra": extra, "extra_flagged_only_by_K_all": extra_ka}, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ("existing_pool_size", "k_flagged_union_positive", "extra_items", "extra_items_flagged_only_by_K_all")}, indent=1))


# ------------------------------------------------------------------------------------ render


def pm(x) -> str:
    return "n/a" if x is None else f"{100 * x:+.2f}"


def cell_row(label: str, h: Mapping) -> str:
    return (f"| {label} | {h['n']} | {pct(h['base'])} -> {pct(h['cand'])} | {pm(h['delta'])} [{pm(h['lo'])}, {pm(h['hi'])}] | "
            f"{h['gained']} / {h['lost']} | {h['p_mcnemar_two_sided']:.3g} |")


def render(args) -> None:
    res = json.loads(args.input.read_text(encoding="utf-8"))
    H = res["hypotheses"]
    L: list[str] = []
    add = L.append
    add("Notation: a pair `A>B` is B minus A (reference A, candidate B); deltas in percentage points; intervals are 95 % grouped paired percentile bootstrap.\n")
    head = "| Cell | n | rate base -> cand (%) | delta pt [95 % CI] | gained / lost | exact McNemar p |\n|---|---|---|---|---|---|"
    add("### Registered primary and guards\n")
    add("| Hypothesis | n | rate ref -> K (%) | delta pt [95 % CI] | gained / lost | margin (pt) | Wald lower (row / cluster) | verdict |\n|---|---|---|---|---|---|---|---|")
    for key, label in (("H7", "H7 union recall K - O, F4, positive"), ("H8", "H8 union recall K - O, F4, block"),
                       ("G1", "G1 union specificity K - O, S1 (F1 clean)"), ("G2", "G2 union specificity K - N, S1 (F1 clean)")):
        h = H[key]
        add(f"| {label} | {h['n']} | {pct(h['base'])} -> {pct(h['cand'])} | {pm(h['delta'])} [{pm(h['lo'])}, {pm(h['hi'])}] | "
            f"{h['gained']} / {h['lost']} | {100 * h['margin']:+.1f} | {pm(h['wald_lower_row'])} / {pm(h['wald_lower_cluster'])} | **{h['verdict']}** |")
    add("\n### Context cells on F4 (union unless stated)\n")
    add(head)
    for k, h in H["context"].items():
        add(cell_row(k.replace("_", " "), h))
    add("\n### Per-source (F4; descriptive)\n")
    add("| Source | rows | clusters | H7 K-O | H8 K-O | H7 N-O | H7 K-N | regex K-N | whole interval below -1.0 | rule |\n|---|---|---|---|---|---|---|---|---|---|")
    for s, e in H["per_source"].items():
        def f(k):
            h = e[k]
            return f"{pm(h['delta'])} [{pm(h['lo'])}, {pm(h['hi'])}] ({h['gained']}/{h['lost']})"
        add(f"| {s} | {e['n_rows']} | {e['n_clusters']} | {f('O>K__union_positive')} | {f('O>K__union_block')} | {f('O>N__union_positive')} | "
            f"{f('N>K__union_positive')} | {f('N>K__regex_positive')} | {e['whole_interval_below_margin']} | {e['heterogeneity_rule']} |")
    add("\n### Source-standardised union recall (F4; stratified cluster bootstrap)\n")
    add("| Pair | weights | delta pt [95 % CI] |\n|---|---|---|")
    for pair, st in H["standardised_H7"].items():
        for lab, w in st["weights"].items():
            add(f"| {pair} | {lab} {w['vector']} | {pm(w['estimate'])} [{pm(w['lo'])}, {pm(w['hi'])}] |")
    add("\n### H9 second look (S1 = F1 clean, specificity)\n")
    add("| Pair | layer | rule | n | spec base -> cand (%) | delta pt [95 % CI] | gained / lost | p |\n|---|---|---|---|---|---|---|---|")
    for pair in ("O>K", "N>K", "O>N"):
        for layer in ("regex", "union"):
            for rule in RULES:
                h = H["H9_S1_clean_specificity"][pair][layer][rule]
                add(f"| {pair} | {layer} | {rule} | {h['n']} | {pct(h['base'])} -> {pct(h['cand'])} | {pm(h['delta'])} [{pm(h['lo'])}, {pm(h['hi'])}] | {h['gained']} / {h['lost']} | {h['p_mcnemar_two_sided']:.3g} |")
    add("\n## Promotion (registration section 6)\n")
    for cfg, v in res["promotion"].items():
        add(f"- **{cfg}**: {v['verdict']}; criteria {v['criteria']}")
    args.output.write_text("\n".join(L) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    an = sub.add_parser("analyse")
    an.add_argument("--results-w3", type=Path, required=True, help="Wave 3 output directory (O and N for F1, F2, F3)")
    an.add_argument("--results-v3", type=Path, required=True, help="v3 output directory (everything else)")
    an.add_argument("--f4-gold", type=Path, required=True)
    an.add_argument("--f1-gold", type=Path, required=True)
    an.add_argument("--f3-gold", type=Path, required=True)
    an.add_argument("--out", type=Path, required=True)
    an.add_argument("--n-boot", type=int, default=ds.DEFAULT_BOOTSTRAP)
    an.add_argument("--seed", type=int, default=ds.DEFAULT_SEED)
    an.add_argument("--workers", type=int, default=4)
    an.add_argument("--no-spans", action="store_true")
    an.add_argument("--standin", action="store_true", help="harness test on stand-in data: registered row counts are not enforced")
    an.set_defaults(func=analyse)
    pl = sub.add_parser("pool")
    pl.add_argument("--results-v3", type=Path, required=True)
    pl.add_argument("--adjudication", type=Path, required=True)
    pl.add_argument("--out", type=Path, required=True)
    pl.set_defaults(func=command_pool)
    rd = sub.add_parser("render")
    rd.add_argument("--input", type=Path, required=True)
    rd.add_argument("--output", type=Path, required=True)
    rd.set_defaults(func=render)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
