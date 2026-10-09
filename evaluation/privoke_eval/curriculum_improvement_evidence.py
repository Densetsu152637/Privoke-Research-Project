"""Pure scorers and archive checks for the prospective curriculum comparison.

Contextual targets remain separate from binary annotation-presence targets.
No scorer in this module installs models or reads a dataset outside its inputs.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import closing
import hashlib
import json
from pathlib import Path
import random
import sqlite3
import statistics

from privoke_eval.continual_fuzzer_study import metrics, percentile

RANK = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
CONTEXT_METRICS = ("sensitivity_accuracy", "visibility_accuracy", "category_exact_accuracy",
                   "joint_accuracy", "action_accuracy", "under_restriction_rate", "over_restriction_rate")


def digest(value):
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def matched(before, after):
    left, right = ({row["id"]: row for row in rows} for rows in (before, after))
    if len(left) != len(before) or len(right) != len(after) or left.keys() != right.keys():
        raise ValueError("Paired evidence requires identical unique IDs.")
    pairs = [(left[key], right[key]) for key in sorted(left)]
    truth = ("group_id", "target", "allowed_actions", "quantitative", "expected_has_pii")
    if any(any(a.get(key) != b.get(key) for key in truth) for a, b in pairs):
        raise ValueError("Paired groups or targets changed.")
    if any(row.get("status") != "ok" for pair in pairs for row in pair):
        raise ValueError("Incomplete endpoint evidence cannot establish a comparison.")
    return pairs


def contextual_metrics(rows):
    selected = [row for row in rows if row["quantitative"]]
    if not selected or any(row["status"] != "ok" for row in selected):
        raise ValueError("Complete quantitative contextual evidence is required.")
    totals = Counter()
    for row in selected:
        target, observed = row["target"], row["classification"]
        correct = [observed["sensitivity"] == target["sensitivity"],
                   observed["visibility"] == target["visibility"],
                   set(observed.get("categories", [])) == set(target["categories"])]
        for key, value in zip(CONTEXT_METRICS[:3], correct):
            totals[key] += value
        totals["joint_accuracy"] += all(correct)
        totals["action_accuracy"] += row["action"] in row["allowed_actions"]
        ranks = [RANK[action] for action in row["allowed_actions"]]
        totals["under_restriction_rate"] += RANK[row["action"]] < min(ranks)
        totals["over_restriction_rate"] += RANK[row["action"]] > max(ranks)
    return {"rows": len(selected), "groups": len({r["group_id"] for r in selected}),
            **{key: totals[key] / len(selected) for key in CONTEXT_METRICS}}


def contextual_changes(before, after, iterations=2000, seed=10102026):
    pairs = [(a, b) for a, b in matched(before, after) if a["quantitative"]]
    groups = defaultdict(list)
    for index, (row, _) in enumerate(pairs):
        groups[row["group_id"]].append(index)
    def delta(indexes):
        a = contextual_metrics([pairs[i][0] for i in indexes])
        b = contextual_metrics([pairs[i][1] for i in indexes])
        return {key: b[key] - a[key] for key in CONTEXT_METRICS}
    point = delta(range(len(pairs)))
    draws, rng, keys = defaultdict(list), random.Random(seed), sorted(groups)
    for _ in range(iterations):
        for key, value in delta([i for group in rng.choices(keys, k=len(keys)) for i in groups[group]]).items():
            draws[key].append(value)
    return {"method": "paired declared-family percentile bootstrap; descriptive scenario uncertainty",
            "iterations": iterations, "seed": seed, "rows": len(pairs), "groups": len(groups),
            "changes": {key: {"estimate": value, "interval_95": [percentile(draws[key], .025), percentile(draws[key], .975)]}
                        for key, value in point.items()}}


def restriction_harms(before, after):
    under, over, newly_incorrect = [], [], []
    for a, b in matched(before, after):
        if not a["quantitative"]:
            continue
        minimum = min(RANK[action] for action in a["allowed_actions"])
        maximum = max(RANK[action] for action in a["allowed_actions"])
        if a["action"] in a["allowed_actions"] and b["action"] not in b["allowed_actions"]:
            newly_incorrect.append(a["id"])
        # Capture newly worse restrictions even when baseline already failed.
        if RANK[b["action"]] < minimum and RANK[b["action"]] < RANK[a["action"]]:
            under.append(a["id"])
        if RANK[b["action"]] > maximum and RANK[b["action"]] > RANK[a["action"]]:
            over.append(a["id"])
    return {"new_under_restrictions": len(under), "new_over_restrictions": len(over),
            "newly_incorrect_actions": len(newly_incorrect),
            "passed": not under and not over and not newly_incorrect}


def seed_statistics(values):
    if not values:
        raise ValueError("Seed statistics require observations.")
    return {"values": values, "mean": statistics.mean(values), "minimum": min(values),
            "maximum": max(values), "sample_sd": statistics.stdev(values) if len(values) > 1 else None}


def accepted_metadata(record, durable_metadata=None):
    response = record["response"]
    if response["metadata"].get("replayed") != "true":
        return response["metadata"]
    request = record["request"]
    key = (request["source_id"], request["request_id"])
    if durable_metadata is None or key not in durable_metadata:
        raise ValueError("Replay-only acknowledgment requires exact durable publication metadata.")
    return durable_metadata[key]


def audit_allocations(database_path, rounds, lookup, sampler_policy, sampler_seed, replay_weight, durable_metadata=None, *, new_count=192, replay_count=64):
    """Reconcile durable reservations and quotas, including rejected attempts."""
    with closing(sqlite3.connect(Path(database_path).resolve().as_uri() + "?mode=ro", uri=True)) as database:
        reservations = list(database.execute("SELECT identity, fingerprint, allocation FROM batches"))
    keyed = {}
    for identity, fingerprint, allocation in reservations:
        source, model, request_id = json.loads(identity)
        key = (source, model, request_id)
        if key in keyed or not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise ValueError("Invalid or duplicate durable reservation.")
        keyed[key] = json.loads(allocation)
    if len(keyed) != len(rounds):
        raise ValueError("Durable reservation count differs from attempts.")
    exposed, exposed_families = Counter(), set()
    previous = {}
    for record in rounds:
        request, response = record["request"], record["response"]
        allocation = keyed[(request["source_id"], request["model_id"], request["request_id"])]
        train, replay = allocation["train"], allocation["replay"]
        if len(train) != new_count or len(replay) != replay_count or len(set(train + replay)) != new_count + replay_count:
            raise ValueError("Allocation violates fixed train/replay unique-row budget.")
        counts = Counter()
        for role, ids in (("train", train), ("replay", replay)):
            for row_id in ids:
                split, row = lookup[row_id]
                if split != role:
                    raise ValueError("Allocation includes an endpoint, gate, or wrong-role row.")
                sensitive = row["classification"]["sensitivity"] != "S0" or bool(row["classification"]["categories"])
                counts[(role, row["metadata"]["curriculum_role"], sensitive)] += 1
                exposed[row_id] += 1
                exposed_families.add(row["metadata"]["group_id"])
        if new_count % 6 or replay_count % 2:
            raise ValueError("Audit requires balanced integral role/class quotas.")
        if any(counts[("train", role, sensitive)] != new_count // 6 for role in ("grammar", "teacher", "evolved") for sensitive in (False, True)):
            raise ValueError("Training role/class quotas differ.")
        if sum(n for (role, _, sensitive), n in counts.items() if role == "replay" and sensitive) != replay_count // 2:
            raise ValueError("Replay class quota differs.")
        positions = allocation.get("positions", {})
        if len(positions) != 8:
            raise ValueError("Missing sampler cursor audit.")
        expected_ids = {"train": [], "replay": []}
        for stratum in [f"{role}:{sensitive}" for role in ("grammar", "teacher", "evolved", "replay") for sensitive in (False, True)]:
            cursor = positions[stratum]
            role, sensitive_string = stratum.split(":")
            split = "replay" if role == "replay" else "train"
            sensitive = sensitive_string == "True"
            required = replay_count // 2 if split == "replay" else new_count // 6
            pool = [row for row_split, row in lookup.values() if row_split == split and row["metadata"]["curriculum_role"] == role
                    and (row["classification"]["sensitivity"] != "S0" or bool(row["classification"]["categories"])) == sensitive]
            if cursor["pool_size"] != len(pool):
                raise ValueError("Cursor pool size differs from frozen rows.")
            if cursor["start"] != previous.get(stratum, 0) or cursor["stop"] <= cursor["start"] or cursor["pool_size"] < required:
                raise ValueError("Sampler cursor chain differs.")
            if cursor["start_epoch"] != cursor["start"] // cursor["pool_size"] or cursor["stop_epoch"] != cursor["stop"] // cursor["pool_size"]:
                raise ValueError("Sampler epoch audit differs.")
            previous[stratum] = cursor["stop"]
            position, selected, order, last_epoch = cursor["start"], [], [], None
            while len(selected) < required:
                epoch = position // len(pool)
                if epoch != last_epoch:
                    families = defaultdict(list)
                    for row in sorted(pool, key=lambda r: r["id"]):
                        families[row["metadata"]["group_id"]].append(row)
                    groups = list(families)
                    if sampler_policy == "seeded_family_v1":
                        rng = random.Random(digest([sampler_seed, stratum, epoch]))
                        groups = sorted(groups)
                        rng.shuffle(groups)
                        for siblings in families.values():
                            rng.shuffle(siblings)
                    order = [families[group][i]["id"] for i in range(max(map(len, families.values()))) for group in groups if i < len(families[group])]
                    last_epoch = epoch
                row_id = order[position % len(pool)]
                position += 1
                if row_id not in expected_ids[split] and row_id not in selected:
                    selected.append(row_id)
            if position != cursor["stop"]:
                raise ValueError("Cursor consumption differs from independently reconstructed sampler.")
            expected_ids[split].extend(selected)
        if expected_ids != {"train": train, "replay": replay}:
            raise ValueError("Durable IDs differ from independently reconstructed allocation.")
        if response["accepted"]:
            meta = accepted_metadata(record, durable_metadata)
            expected = {"curriculum_train_ids_sha256": digest(train), "curriculum_replay_ids_sha256": digest(replay),
                        "curriculum_sampler_policy": sampler_policy, "curriculum_sampler_seed": str(sampler_seed),
                        "curriculum_replay_weight": str(replay_weight)}
            if any(meta.get(key) != value for key, value in expected.items()):
                raise ValueError("Accepted receipt differs from durable allocation/settings.")
            if json.loads(meta["curriculum_sampler_positions"]) != positions:
                raise ValueError("Accepted cursor receipt differs from SQLite.")
    return {"reservations": len(keyed), "presentations": sum(exposed.values()), "unique_rows": len(exposed),
            "unique_families": len(exposed_families), "maximum_row_exposures": max(exposed.values(), default=0)}


def binary_counts(rows):
    result = metrics(rows)
    if result["runtime_errors"] or result["coverage"] != 1:
        raise ValueError("Binary endpoint is incomplete.")
    return result
