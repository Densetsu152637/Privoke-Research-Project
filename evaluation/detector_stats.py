"""Paired uncertainty statistics for detector comparisons (detector-layer scope).

Reusable, seeded and deterministic. Works on the per-row JSONL written by
``evaluate_installed_detectors.py --per-row-dir`` (or any records with the same keys) but the
numeric functions only need aligned lists of booleans, so later studies can call them directly.

Conventions
-----------
* ``labels``: list[bool], True = the row contains PII (``expected_has_pii``).
* ``preds``: list[bool], True = the detector/action flagged the row. A comparison is always
  *baseline* (e.g. old) versus *candidate* (e.g. new) on the same rows; deltas are
  ``candidate - baseline``.
* ``groups``: one hashable cluster id per row. The grouped bootstrap resamples whole clusters
  with replacement, so correlated rows (same source document) move together. Pass row-unique
  ids (``row_groups``) for a plain row bootstrap.
* Metrics: recall, specificity, precision, f2, plus ``cost_<k>`` = mean cost per row with
  ``k`` * FN + 1 * FP, divided by n (FN:FP cost ratio ``k``). Undefined values (zero
  denominator) are ``None`` for point estimates and dropped from bootstrap percentiles (the
  number dropped is reported as ``n_undefined``).
* Percentile bootstrap CIs, default 95 % (2.5 / 97.5), 10 000 replicates, seed 20261024.
  Baseline and candidate share the same resampled clusters in each replicate, so delta CIs are
  properly paired.
* Exact McNemar: two-sided exact binomial test on the discordant counts (mid-p also given).
  Run separately on positives and negatives (correctness-paired). Because rows in one cluster
  are not independent, ``cluster_sign_test`` gives a cluster-level exact sign test on the net
  flips per cluster as a conservative companion.

Only the Python standard library and numpy are required.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from fractions import Fraction
from pathlib import Path
from typing import Callable, Mapping, Sequence

import numpy as np

DEFAULT_SEED = 20261024
DEFAULT_BOOTSTRAP = 10_000
DEFAULT_COST_RATIOS = (2, 4, 9)
LAYERS = ("regex", "ner", "union")
# decision rule applied to a per-row record: which fields/actions count as "flagged"
RULES = ("positive", "warn_or_block", "block")


# ---------------------------------------------------------------------------------- loading


def load_rows(path: Path | str) -> list[dict]:
    """Read a per-row JSONL file written by ``evaluate_installed_detectors.py``."""
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def align_rows(baseline: Sequence[dict], candidate: Sequence[dict]) -> list[tuple[dict, dict]]:
    """Pair two runs by ``example_id``; raise unless the id sets and labels agree exactly."""
    base = {r["example_id"]: r for r in baseline}
    cand = {r["example_id"]: r for r in candidate}
    if len(base) != len(baseline) or len(cand) != len(candidate):
        raise ValueError("duplicate example_id in a per-row file")
    if base.keys() != cand.keys():
        raise ValueError("baseline and candidate cover different example_ids")
    pairs = []
    for key in (r["example_id"] for r in baseline):
        if base[key]["expected_has_pii"] != cand[key]["expected_has_pii"]:
            raise ValueError(f"label mismatch for {key!r}")
        pairs.append((base[key], cand[key]))
    return pairs


def row_prediction(record: Mapping, layer: str, rule: str = "positive") -> bool:
    """Decision of one layer set on one record under a rule.

    ``positive``: the detector found anything (sensitivity != S0 or a category).
    ``warn_or_block`` / ``block``: the runtime policy action (as computed by the pipeline's own
    ``strongest_result`` over that layer's results; ``union`` uses ``analysis.action``).
    """
    if layer not in LAYERS:
        raise ValueError(f"layer must be one of {LAYERS}")
    entry = record[layer]
    if rule == "positive":
        return bool(entry["positive"])
    if rule == "warn_or_block":
        return entry["action"] in ("WARN", "BLOCK")
    if rule == "block":
        return entry["action"] == "BLOCK"
    raise ValueError(f"rule must be one of {RULES}")


def predictions(rows: Sequence[Mapping], layer: str, rule: str = "positive") -> list[bool]:
    return [row_prediction(r, layer, rule) for r in rows]


def labels_of(rows: Sequence[Mapping]) -> list[bool]:
    return [bool(r["expected_has_pii"]) for r in rows]


def row_groups(rows: Sequence[Mapping]) -> list[str]:
    """Row-level resampling: every row is its own cluster."""
    return [str(r["example_id"]) for r in rows]


def cluster_groups(rows: Sequence[Mapping], key: str = "group_id") -> list[str]:
    """Cluster by ``key`` (default ``group_id``); rows with a null key fall back to their own id."""
    return [str(r[key]) if r.get(key) is not None else f"row:{r['example_id']}" for r in rows]


# ---------------------------------------------------------------------------------- metrics

Counts = Mapping[str, float]


def confusion(labels: Sequence[bool], preds: Sequence[bool]) -> dict[str, int]:
    if len(labels) != len(preds):
        raise ValueError("labels and preds differ in length")
    tp = tn = fp = fn = 0
    for y, p in zip(labels, preds):
        if y:
            tp += bool(p)
            fn += not p
        else:
            fp += bool(p)
            tn += not p
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def _div(num, den):
    """Elementwise division returning nan where den == 0 (works on numpy arrays and scalars)."""
    num = np.asarray(num, dtype=float)
    den = np.asarray(den, dtype=float)
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.where(den > 0, num / np.where(den > 0, den, 1.0), np.nan)


def metric_functions(cost_ratios: Sequence[int] = DEFAULT_COST_RATIOS) -> dict[str, Callable]:
    """Vectorised metrics over (tp, tn, fp, fn) arrays or scalars."""
    fns: dict[str, Callable] = {
        "recall": lambda tp, tn, fp, fn: _div(tp, tp + fn),
        "specificity": lambda tp, tn, fp, fn: _div(tn, tn + fp),
        "precision": lambda tp, tn, fp, fn: _div(tp, tp + fp),
        # F-beta with beta=2: (1+4) TP / ((1+4) TP + 4 FN + FP)
        "f2": lambda tp, tn, fp, fn: _div(5.0 * np.asarray(tp, float),
                                          5.0 * np.asarray(tp, float) + 4.0 * np.asarray(fn, float)
                                          + np.asarray(fp, float)),
    }
    for k in cost_ratios:
        fns[f"cost_{k}"] = (lambda kk: lambda tp, tn, fp, fn: _div(
            kk * np.asarray(fn, float) + np.asarray(fp, float), tp + tn + fp + fn))(k)
    return fns


def point_metrics(counts: Counts, cost_ratios: Sequence[int] = DEFAULT_COST_RATIOS) -> dict[str, float | None]:
    """Point estimates for one confusion table (``None`` where undefined)."""
    out: dict[str, float | None] = {}
    for name, fn in metric_functions(cost_ratios).items():
        value = float(fn(counts["tp"], counts["tn"], counts["fp"], counts["fn"]))
        out[name] = None if math.isnan(value) else value
    return out


# ---------------------------------------------------------------------------------- McNemar


def _binom_cdf_half(k: int, n: int) -> Fraction:
    """P(X <= k) for X ~ Binomial(n, 1/2), exact."""
    return Fraction(sum(math.comb(n, i) for i in range(0, k + 1)), 2 ** n)


def mcnemar_exact(b: int, c: int) -> dict[str, float | int]:
    """Exact McNemar test on discordant counts ``b`` and ``c``.

    ``p_two_sided = min(1, 2 * P(X <= min(b, c)))``, X ~ Binomial(b + c, 1/2). With no
    discordant pairs p = 1. ``p_mid`` subtracts half the point probability (mid-p).
    """
    if b < 0 or c < 0:
        raise ValueError("counts must be non-negative")
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "n_discordant": 0, "p_two_sided": 1.0, "p_mid": 1.0}
    low = min(b, c)
    cdf = _binom_cdf_half(low, n)
    point = Fraction(math.comb(n, low), 2 ** n)
    p = min(Fraction(1), 2 * cdf)
    p_mid = min(Fraction(1), 2 * cdf - point)
    return {"b": b, "c": c, "n_discordant": n, "p_two_sided": float(p), "p_mid": float(p_mid)}


def paired_flips(labels: Sequence[bool], baseline: Sequence[bool], candidate: Sequence[bool]) -> dict:
    """Per-row transitions between two decision vectors plus exact McNemar tests.

    Positives: ``fn_to_tp`` (gains) vs ``tp_to_fn`` (losses). Negatives: ``fp_to_tn`` (gains) vs
    ``tn_to_fp`` (losses). McNemar ``b`` = baseline-correct/candidate-wrong, ``c`` = the reverse.
    """
    if not (len(labels) == len(baseline) == len(candidate)):
        raise ValueError("length mismatch")
    flips = {"fn_to_tp": 0, "tp_to_fn": 0, "fp_to_tn": 0, "tn_to_fp": 0,
             "pos_unchanged_correct": 0, "pos_unchanged_wrong": 0,
             "neg_unchanged_correct": 0, "neg_unchanged_wrong": 0}
    for y, a, b in zip(labels, baseline, candidate):
        if y:
            if a == b:
                flips["pos_unchanged_correct" if a else "pos_unchanged_wrong"] += 1
            elif b:
                flips["fn_to_tp"] += 1
            else:
                flips["tp_to_fn"] += 1
        else:
            if a == b:
                flips["neg_unchanged_correct" if not a else "neg_unchanged_wrong"] += 1
            elif not b:
                flips["fp_to_tn"] += 1
            else:
                flips["tn_to_fp"] += 1
    flips["mcnemar_positives"] = mcnemar_exact(flips["tp_to_fn"], flips["fn_to_tp"])
    flips["mcnemar_negatives"] = mcnemar_exact(flips["tn_to_fp"], flips["fp_to_tn"])
    both = mcnemar_exact(flips["tp_to_fn"] + flips["tn_to_fp"], flips["fn_to_tp"] + flips["fp_to_tn"])
    flips["mcnemar_all_rows"] = both
    return flips


def cluster_sign_test(labels: Sequence[bool], baseline: Sequence[bool], candidate: Sequence[bool],
                      groups: Sequence[str], *, on: str = "all") -> dict:
    """Exact sign test on per-cluster net correctness change (conservative for clustered rows).

    For each cluster the net = (#rows candidate right & baseline wrong) - (#rows baseline right &
    candidate wrong), restricted to ``on`` in {"all", "positives", "negatives"}. Clusters with net
    0 are dropped; the remaining signs are tested against Binomial(m, 1/2).
    """
    net: dict[str, int] = defaultdict(int)
    for y, a, b, g in zip(labels, baseline, candidate, groups):
        if (on == "positives" and not y) or (on == "negatives" and y):
            continue
        ca, cb = (a == y), (b == y)
        net[g] += int(cb and not ca) - int(ca and not cb)
    pos = sum(v > 0 for v in net.values())
    neg = sum(v < 0 for v in net.values())
    res = mcnemar_exact(neg, pos)  # b = baseline better clusters, c = candidate better clusters
    return {"clusters_candidate_better": pos, "clusters_baseline_better": neg,
            "p_two_sided": res["p_two_sided"]}


# ---------------------------------------------------------------------------------- bootstrap


def _cluster_table(groups: Sequence[str]) -> tuple[np.ndarray, int]:
    """Map each row to a dense cluster index in first-appearance order."""
    index: dict[str, int] = {}
    out = np.empty(len(groups), dtype=np.int64)
    for i, g in enumerate(groups):
        out[i] = index.setdefault(g, len(index))
    return out, len(index)


def _cluster_counts(labels: Sequence[bool], preds: Sequence[bool], cluster_of: np.ndarray, k: int) -> np.ndarray:
    """K x 4 matrix of per-cluster (tp, tn, fp, fn)."""
    y = np.asarray(labels, dtype=bool)
    p = np.asarray(preds, dtype=bool)
    table = np.zeros((k, 4), dtype=np.int64)
    for col, mask in enumerate((y & p, ~y & ~p, ~y & p, y & ~p)):
        table[:, col] = np.bincount(cluster_of[mask], minlength=k)
    return table


def _replicate_weights(k: int, n_boot: int, seed: int, chunk: int = 1000):
    """Yield (B_chunk x K) cluster multiplicity matrices; deterministic for a given seed."""
    rng = np.random.default_rng(seed)
    done = 0
    while done < n_boot:
        b = min(chunk, n_boot - done)
        draws = rng.integers(0, k, size=(b, k))
        flat = (np.arange(b)[:, None] * k + draws).ravel()
        yield np.bincount(flat, minlength=b * k).reshape(b, k)
        done += b


def _percentile_ci(values: np.ndarray, level: float) -> dict:
    finite = values[~np.isnan(values)]
    alpha = (1.0 - level) / 2.0
    if finite.size == 0:
        return {"lo": None, "hi": None, "n_undefined": int(values.size)}
    lo, hi = np.quantile(finite, [alpha, 1.0 - alpha])
    return {"lo": float(lo), "hi": float(hi), "n_undefined": int(values.size - finite.size)}


def paired_bootstrap(labels: Sequence[bool], groups: Sequence[str],
                     decisions: Mapping[str, Sequence[bool]], *, baseline: str | None = None,
                     n_boot: int = DEFAULT_BOOTSTRAP, seed: int = DEFAULT_SEED, level: float = 0.95,
                     cost_ratios: Sequence[int] = DEFAULT_COST_RATIOS) -> dict:
    """Grouped paired bootstrap for any number of named decision vectors on the same rows.

    ``decisions`` maps a name (e.g. ``"old"``, ``"new"``) to a bool vector. Returns::

        {"n_rows", "n_clusters", "n_boot", "seed", "level", "counts": {name: {tp,tn,fp,fn}},
         "metrics": {name: {metric: {"estimate", "lo", "hi", "n_undefined"}}},
         "deltas": {name: {metric: {"estimate", "lo", "hi", "excludes_zero", "n_undefined"}}}}

    ``deltas`` are ``name - baseline`` for every name other than ``baseline`` (default: the first
    key). Resampling is by whole cluster, shared across all names within each replicate.
    """
    names = list(decisions)
    if not names:
        raise ValueError("no decision vectors given")
    baseline = baseline or names[0]
    cluster_of, k = _cluster_table(groups)
    if len(cluster_of) != len(labels):
        raise ValueError("groups and labels differ in length")
    tables = {n: _cluster_counts(labels, decisions[n], cluster_of, k) for n in names}
    fns = metric_functions(cost_ratios)
    boot: dict[str, dict[str, list[np.ndarray]]] = {n: {m: [] for m in fns} for n in names}
    for weights in _replicate_weights(k, n_boot, seed):
        for n in names:
            totals = weights @ tables[n]  # (B x 4) bootstrap confusion counts
            for m, fn in fns.items():
                boot[n][m].append(fn(totals[:, 0], totals[:, 1], totals[:, 2], totals[:, 3]))
    boot_arrays = {n: {m: np.concatenate(v) for m, v in per.items()} for n, per in boot.items()}

    counts = {n: {c: int(tables[n][:, i].sum()) for i, c in enumerate(("tp", "tn", "fp", "fn"))} for n in names}
    estimates = {n: point_metrics(counts[n], cost_ratios) for n in names}
    metrics = {n: {m: {"estimate": estimates[n][m], **_percentile_ci(boot_arrays[n][m], level)} for m in fns}
               for n in names}
    deltas: dict[str, dict] = {}
    for n in names:
        if n == baseline:
            continue
        deltas[n] = {}
        for m in fns:
            diff = boot_arrays[n][m] - boot_arrays[baseline][m]
            ci = _percentile_ci(diff, level)
            est_a, est_b = estimates[baseline][m], estimates[n][m]
            est = None if est_a is None or est_b is None else est_b - est_a
            ci["excludes_zero"] = (ci["lo"] is not None and (ci["lo"] > 0 or ci["hi"] < 0))
            deltas[n][m] = {"estimate": est, **ci}
    return {"n_rows": len(labels), "n_clusters": k, "n_boot": n_boot, "seed": seed, "level": level,
            "baseline": baseline, "counts": counts, "metrics": metrics, "deltas": deltas}


def compare_pair(labels: Sequence[bool], groups: Sequence[str], baseline: Sequence[bool],
                 candidate: Sequence[bool], *, names: tuple[str, str] = ("old", "new"),
                 n_boot: int = DEFAULT_BOOTSTRAP, seed: int = DEFAULT_SEED, level: float = 0.95,
                 cost_ratios: Sequence[int] = DEFAULT_COST_RATIOS) -> dict:
    """Bootstrap CIs, flips, exact McNemar and cluster sign tests for one baseline/candidate pair."""
    result = paired_bootstrap(labels, groups, {names[0]: baseline, names[1]: candidate},
                              baseline=names[0], n_boot=n_boot, seed=seed, level=level,
                              cost_ratios=cost_ratios)
    flips = paired_flips(labels, baseline, candidate)
    result["flips"] = flips
    result["cluster_sign_test"] = {on: cluster_sign_test(labels, baseline, candidate, groups, on=on)
                                   for on in ("all", "positives", "negatives")}
    return result


# ---------------------------------------------------------------------------------- driver


def compare_runs(baseline_rows: Sequence[dict], candidate_rows: Sequence[dict], *, layer: str, rule: str,
                 grouping: str = "group_id", subset: Callable[[dict], bool] | None = None,
                 **kwargs) -> dict:
    """Align two per-row runs and run ``compare_pair`` for one layer set / decision rule.

    ``grouping``: ``"group_id"`` (cluster by the record's group_id; null ids become singletons),
    ``"stratum"`` (cluster by scenario/task label) or ``"row"`` (plain row bootstrap).
    ``subset`` filters on the baseline record (e.g. ``lambda r: r.get("half") == "check"``).
    """
    pairs = align_rows(baseline_rows, candidate_rows)
    if subset is not None:
        pairs = [(a, b) for a, b in pairs if subset(a)]
    a_rows = [a for a, _ in pairs]
    b_rows = [b for _, b in pairs]
    if grouping == "row":
        groups = row_groups(a_rows)
    elif grouping in ("group_id", "stratum"):
        groups = cluster_groups(a_rows, grouping)
    else:
        raise ValueError("grouping must be group_id, stratum or row")
    result = compare_pair(labels_of(a_rows), groups, predictions(a_rows, layer, rule),
                          predictions(b_rows, layer, rule), **kwargs)
    result.update({"layer": layer, "rule": rule, "grouping": grouping})
    return result


def _main() -> None:
    parser = argparse.ArgumentParser(description="Paired grouped-bootstrap comparison of two per-row runs")
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--layer", choices=LAYERS, default="union")
    parser.add_argument("--rule", choices=RULES, default="positive")
    parser.add_argument("--grouping", choices=("group_id", "stratum", "row"), default="group_id")
    parser.add_argument("--n-boot", type=int, default=DEFAULT_BOOTSTRAP)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    out = compare_runs(load_rows(args.baseline), load_rows(args.candidate), layer=args.layer, rule=args.rule,
                       grouping=args.grouping, n_boot=args.n_boot, seed=args.seed)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    _main()
