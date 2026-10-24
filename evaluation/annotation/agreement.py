"""Pure-Python agreement and accuracy statistics (no third-party dependencies)."""
from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from itertools import combinations


def cohen_kappa(a, b):
    """Return (kappa, observed_agreement, expected_agreement) for paired label lists.

    kappa is None when expected agreement is 1 (no label variation) and the raters agree fully.
    """
    if len(a) != len(b) or not a:
        raise ValueError("paired non-empty label lists required")
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[v] * cb[v] for v in set(ca) | set(cb)) / (n * n)
    if pe == 1.0:
        return None, po, pe
    return (po - pe) / (1.0 - pe), po, pe


def confusion_matrix(a, b, values):
    """Rows = first rater, columns = second rater; returns nested dict of counts."""
    matrix = {r: {c: 0 for c in values} for r in values}
    for x, y in zip(a, b):
        matrix[x][y] += 1
    return matrix


def specific_agreement(a, b, values):
    """Per-label positive specific agreement 2*n_ll / (n_l. + n_.l); None when label unused."""
    ca, cb = Counter(a), Counter(b)
    out = {}
    for v in values:
        both = sum(1 for x, y in zip(a, b) if x == v and y == v)
        denom = ca[v] + cb[v]
        out[v] = (2.0 * both / denom) if denom else None
    return out


def krippendorff_alpha(units, level="nominal", order=None):
    """Krippendorff's alpha for any number of raters with missing data.

    units: iterable of per-unit rating lists (missing ratings omitted). Units with fewer than
    two ratings are ignored. level: 'nominal' or 'ordinal' (order = ordered value list).
    Returns None when the expected disagreement is zero.
    """
    coincidence = defaultdict(float)
    for ratings in units:
        m = len(ratings)
        if m < 2:
            continue
        for i, j in ((i, j) for i in range(m) for j in range(m) if i != j):
            coincidence[(ratings[i], ratings[j])] += 1.0 / (m - 1)
    if not coincidence:
        return None
    marginals = Counter()
    for (c, _k), weight in coincidence.items():
        marginals[c] += weight
    n = sum(marginals.values())
    if n <= 1:
        return None
    values = list(order) if order is not None else sorted(marginals)

    def delta2(c, k):
        if c == k:
            return 0.0
        if level == "nominal":
            return 1.0
        lo, hi = sorted((values.index(c), values.index(k)))
        span = sum(marginals.get(values[g], 0.0) for g in range(lo, hi + 1))
        return (span - (marginals.get(values[lo], 0.0) + marginals.get(values[hi], 0.0)) / 2.0) ** 2

    d_obs = sum(w * delta2(c, k) for (c, k), w in coincidence.items()) / n
    d_exp = sum(marginals[c] * marginals[k] * delta2(c, k)
                for c in marginals for k in marginals) / (n * (n - 1))
    if d_exp == 0:
        return None
    return 1.0 - d_obs / d_exp


def wilson_interval(successes, n, z=1.959964):
    if n == 0:
        return (None, None)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def percentile_interval(samples, level=0.95):
    clean = sorted(s for s in samples if s is not None)
    if not clean:
        return (None, None)
    lo = clean[int((1 - level) / 2 * (len(clean) - 1))]
    hi = clean[int(math.ceil((1 + level) / 2 * (len(clean) - 1)))]
    return (lo, hi)


def cluster_bootstrap(item_ids, cluster_of, statistic, n_boot=2000, seed=0, level=0.95):
    """Percentile CI for statistic(list_of_item_ids), resampling whole clusters with replacement.

    cluster_of maps item id -> cluster id (use the item id itself for an item bootstrap).
    Returns (low, high, replicates_used).
    """
    clusters = defaultdict(list)
    for item in item_ids:
        clusters[cluster_of[item]].append(item)
    keys = sorted(clusters)
    rng = random.Random(seed)
    samples = []
    for _ in range(n_boot):
        drawn = []
        for _ in keys:
            drawn.extend(clusters[keys[rng.randrange(len(keys))]])
        samples.append(statistic(drawn))
    lo, hi = percentile_interval(samples, level)
    return lo, hi, sum(s is not None for s in samples)


def kappa_half_width(n, po, pe, deff=1.0, z=1.959964):
    """Large-sample half-width of a Cohen's kappa interval, var = po(1-po) / (n (1-pe)^2)."""
    variance = po * (1 - po) / (n * (1 - pe) ** 2)
    return z * math.sqrt(variance * deff)


def required_n_for_kappa(po, pe, half_width=0.1, deff=1.0, z=1.959964):
    return math.ceil(z * z * po * (1 - po) * deff / ((1 - pe) ** 2 * half_width ** 2))


def pairs(annotators):
    return list(combinations(sorted(annotators), 2))
