"""EX14 official source-category reference; no broad privacy labels inferred."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from collections import Counter, defaultdict

SEED = 20261014
QUOTAS = {"hard_negative": 250, "negative": 750, "positive": 1000}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def file_hash(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def retain(path, value):
    path = Path(path)
    payload = value if isinstance(value, bytes) else canonical(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(payload)


def ranked(value):
    return digest(value.encode())


def select_components(components, categories, eligible, quotas=None):
    """Fixed scarce-first allocation; components never cross strata or repeat."""
    quotas = QUOTAS if quotas is None else quotas
    selected, used = [], set()
    capacity = {}
    for category, quota in quotas.items():
        candidates = []
        for component in components:
            if component.exclusion_reasons:
                continue
            members = [uid for uid in component.member_uids if uid in eligible and categories[uid] == category]
            if members:
                candidates.append((component.component_id, members))
        capacity[category] = len(candidates)
        candidates.sort(key=lambda item: ranked(f"{SEED}|{category}|{item[0]}"))
        count = 0
        for component_id, members in candidates:
            if component_id in used:
                continue
            uid = min(members, key=lambda uid: ranked(f"{SEED}|row|{uid}"))
            selected.append({"uid": uid, "component_id": component_id, "category": category,
                             "source_positive": category == "positive"})
            used.add(component_id)
            count += 1
            if count == quota:
                break
        require(count == quota, f"Prospective quota unavailable: {category}: {count}/{quota}")
    require(len(used) == sum(quotas.values()), "Repeated component selected")
    return selected, capacity


def category_conflicts(components, categories, raw_rows, text_key):
    """Conservative native-label conflict exclusion, never human review."""
    conflicts = set()
    for component in components:
        keys = defaultdict(set)
        for uid in component.member_uids:
            row = raw_rows[uid]
            keys[text_key(row["llm_input"])].add(categories[uid] == "positive")
        if any(values == {True, False} for values in keys.values()):
            conflicts.add(component.component_id)
    return conflicts


def confusion(rows):
    """Errors retain their class denominator; never silently become negatives."""
    result = Counter(TP=0, TN=0, FP=0, FN=0, errors_positive=0, errors_negative=0)
    for row in rows:
        truth = row["source_positive"]
        prediction = row.get("predicted")
        if prediction is None:
            result["errors_positive" if truth else "errors_negative"] += 1
        else:
            result[("TP" if prediction else "FN") if truth else ("FP" if prediction else "TN")] += 1
    positives = result["TP"] + result["FN"] + result["errors_positive"]
    negatives = result["TN"] + result["FP"] + result["errors_negative"]
    return {**result, "rows": len(rows), "positive_support": positives, "negative_support": negatives,
            "recall": result["TP"] / positives if positives else None,
            "specificity": result["TN"] / negatives if negatives else None,
            "complete_case_recall": result["TP"] / (result["TP"] + result["FN"]) if result["TP"] + result["FN"] else None,
            "complete_case_specificity": result["TN"] / (result["TN"] + result["FP"]) if result["TN"] + result["FP"] else None}


def paired_bootstrap(left, right):
    import numpy as np
    require(len(left) == len(right) and all(a["uid"] == b["uid"] and a["component_id"] == b["component_id"] for a,b in zip(left,right)), "Unpaired rows")
    require(len({a["component_id"] for a in left}) == len(left), "Bootstrap requires one row per component")
    require(all(a.get("predicted") is not None and b.get("predicted") is not None for a,b in zip(left,right)), "Errors invalidate bootstrap comparison")
    truth = np.array([a["source_positive"] for a in left], dtype=bool)
    a = np.array([v["predicted"] for v in left], dtype=bool)
    b = np.array([v["predicted"] for v in right], dtype=bool)
    generator, values = np.random.default_rng(SEED), {"recall": [], "specificity": []}
    for _ in range(2000):
        sample = generator.integers(0, len(left), len(left))
        for metric, mask in (("recall", truth[sample]), ("specificity", ~truth[sample])):
            if mask.any():
                difference = (b[sample][mask] == truth[sample][mask]).mean() - (a[sample][mask] == truth[sample][mask]).mean()
                values[metric].append(float(difference))
    result = {}
    for metric, replicates in values.items():
        require(len(replicates) >= 1900, "Too few defined bootstrap replicates")
        result[metric] = {"valid_resamples": len(replicates), "undefined_resamples": 2000-len(replicates),
                          "percentile_95": [float(v) for v in np.quantile(replicates, [.025, .975])]}
    return result
