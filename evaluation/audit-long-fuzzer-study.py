"""Independently verify sustained-study round chains and paired intervals.

Reads explicit archived outputs only. No dataset, service or final-split access.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import random
import statistics


METRICS = ("recall", "specificity", "precision", "f1", "accuracy", "balanced_accuracy")
PROFILES = ("efficient", "balanced", "quality")


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rates(counts):
    tp, tn, fp, fn = counts
    ratio = lambda a, b: a / b if b else None
    recall, specificity = ratio(tp, tp + fn), ratio(tn, tn + fp)
    return dict(zip(METRICS, (recall, specificity, ratio(tp, tp + fp),
        ratio(2 * tp, 2 * tp + fp + fn), ratio(tp + tn, tp + tn + fp + fn),
        (recall + specificity) / 2 if recall is not None and specificity is not None else None)))


def cell(row):
    return {(True, True): 0, (False, False): 1, (False, True): 2, (True, False): 3}[
        row["expected_has_pii"], row["detected_sensitive"]]


def verify_paired(before, after, saved):
    left, right = ({row["id"]: row for row in rows} for rows in (before, after))
    if len(left) != len(before) or len(right) != len(after) or left.keys() != right.keys():
        raise ValueError("Paired IDs differ or are duplicated.")
    groups = defaultdict(lambda: [0] * 8)
    improved = deteriorated = 0
    for key in sorted(left):
        a, b = left[key], right[key]
        if (a["expected_has_pii"], a["group_id"]) != (b["expected_has_pii"], b["group_id"]):
            raise ValueError("Paired labels or groups differ.")
        if a["status"] != "ok" or b["status"] != "ok":
            raise ValueError("Cannot verify complete intervals with endpoint errors.")
        counts = groups[a["group_id"]]
        counts[cell(a)] += 1
        counts[4 + cell(b)] += 1
        correct_a = a["expected_has_pii"] == a["detected_sensitive"]
        correct_b = b["expected_has_pii"] == b["detected_sensitive"]
        improved += not correct_a and correct_b
        deteriorated += correct_a and not correct_b
    if (not saved["valid"] or saved["rows"] != len(before) or saved["groups"] != len(groups)
            or saved["improved"] != improved or saved["deteriorated"] != deteriorated):
        raise ValueError("Paired comparison totals differ.")
    keys = sorted(groups)

    def differences(weights):
        total = [sum(groups[key][i] * weight for key, weight in weights.items()) for i in range(8)]
        first, last = rates(total[:4]), rates(total[4:])
        return {name: last[name] - first[name] if first[name] is not None and last[name] is not None else None for name in METRICS}

    point = differences(dict.fromkeys(keys, 1))
    rng = random.Random(saved["seed"])
    distributions = {name: [] for name in METRICS}
    for _ in range(saved["iterations"]):
        delta = differences(Counter(rng.choices(keys, k=len(keys))))
        for name, value in delta.items():
            if value is not None:
                distributions[name].append(value)
    for name in METRICS:
        values = distributions[name]
        # statistics.quantiles(method='inclusive') independently implements the
        # interpolation used for percentile bounds on the grouped replicates.
        bounds = None
        if len(values) >= 2:
            quantiles = statistics.quantiles(values, n=40, method="inclusive")
            bounds = [quantiles[0], quantiles[-1]]
        elif values:
            bounds = [values[0], values[0]]
        actual = saved["changes"][name]
        if actual["defined_replicates"] != len(values) or (actual["estimate"] is None) != (point[name] is None):
            raise ValueError("Paired estimate coverage differs.")
        if point[name] is not None and abs(actual["estimate"] - point[name]) > 1e-12:
            raise ValueError("Paired point estimate differs.")
        if (actual["interval_95"] is None) != (bounds is None) or bounds and any(abs(a - b) > 1e-12 for a, b in zip(actual["interval_95"], bounds)):
            raise ValueError("Independent group-bootstrap interval differs.")
    return len(METRICS)


def audit(root, minimum_hours=6):
    if not math.isfinite(minimum_hours) or minimum_hours < 0:
        raise ValueError("Minimum hours must be finite and nonnegative.")
    protocol = read(root / "protocol.json")
    duration = protocol["duration_seconds_per_profile"]
    if duration <= 0 or duration * len(PROFILES) < minimum_hours * 3600:
        raise ValueError("Protocol is shorter than the required multi-hour study.")
    if protocol["profiles"] != [f"privoke-{short}" for short in PROFILES]:
        raise ValueError("Protocol profiles differ.")
    summary = read(root / "summary.json")
    supervisor = read(root / "supervisor.json")
    if supervisor["status"] != "complete" or supervisor["summary_sha256"] != digest(root / "summary.json"):
        raise ValueError("Supervisor completion or summary commitment differs.")
    if summary["protocol_sha256"] != digest(root / "protocol.json"):
        raise ValueError("Compiled protocol commitment differs.")
    if digest(root / "curriculum/manifest.json") != protocol["curriculum_manifest_sha256"]:
        raise ValueError("Prepared curriculum commitment differs.")
    profiles = {}
    for short in PROFILES:
        model_id = f"privoke-{short}"
        directory = root / short / model_id
        manifest = read(root / short / "run-manifest.json")
        model = manifest["models"][model_id]
        if manifest["status"] != "complete" or model["timed_training_seconds"] < duration:
            raise ValueError("Required training window is incomplete.")
        if (abs(model["training_deadline_unix"] - model["duration_started_unix"] - duration) > 1e-6
                or model["duration_finished_unix"] - model["duration_started_unix"] < duration):
            raise ValueError("Persisted elapsed window does not satisfy the protocol.")
        config = manifest["config"]
        if (config["duration_seconds"] != duration or config["prompt_count"] != protocol["prompt_count"]
                or config["seed"] != protocol["seed_start"] or config["bootstrap_iterations"] != protocol["bootstrap_iterations"]
                or config["checkpoint_interval_seconds"] != protocol["checkpoint_interval_seconds"]
                or config["round_pause_seconds"] != protocol["round_pause_seconds"]):
            raise ValueError("Controller settings differ from protocol.")
        if digest(root / f"operations-{short}.json") != config["inputs"]["operations"]["sha256"]:
            raise ValueError("Frozen operation settings differ.")
        checkpoint = model["checkpoints"]["0"]
        baseline_path = directory / checkpoint["path"]
        if digest(baseline_path) != checkpoint["sha256"]:
            raise ValueError("Baseline checkpoint changed.")
        baseline = read(baseline_path)
        identity = checkpoint["identity"]
        for number, row in enumerate(model["rounds"], 1):
            if row != read(directory / f"round-{number:03d}.json") or row["cycle"] != number:
                raise ValueError("Round archive differs from manifest.")
            request, response = row["request"], row["response"]
            if (request["model_id"] != model_id or request["seed"] != protocol["seed_start"] + number - 1
                    or request["prompt_count"] != protocol["prompt_count"]
                    or request["request_id"] != f"continual-{manifest['run_id']}-{model_id}-{number:03d}"):
                raise ValueError("Request sequence differs from protocol.")
            response_path = directory / row["response_path"]
            if digest(response_path) != row["response_sha256"] or response != read(response_path):
                raise ValueError("Response archive differs from manifest.")
            if response["model_id"] != model_id:
                raise ValueError("Response model differs.")
            if response["accepted"]:
                if (response["base_version"] != identity["model_version"]
                        or response["applied_version"] != row["identity"]["model_version"]
                        or row["identity"] == identity):
                    raise ValueError("Accepted publication chain differs.")
                metadata = response["metadata"]
                for key, expected in (("new_examples", 192), ("golden_examples", 64), ("learning_rate", .003), ("max_gradient", .05)):
                    if float(metadata[key]) != expected:
                        raise ValueError("Accepted training settings differ.")
            elif row["identity"] != identity:
                raise ValueError("A rejected round changed the model.")
            identity = row["identity"]
        if identity != model["current_identity"] or len(model["rounds"]) != model["final_cycle"]:
            raise ValueError("Final identity or attempt count differs.")
        comparisons = 0
        for cycle, saved in model["checkpoints"].items():
            path = directory / saved["path"]
            if digest(path) != saved["sha256"]:
                raise ValueError("Checkpoint changed.")
            if cycle == "0":
                continue
            for layer, evidence in read(path).items():
                paired = evidence["paired_vs_baseline"]
                if paired["seed"] != protocol["seed_start"] or paired["iterations"] != protocol["bootstrap_iterations"]:
                    raise ValueError("Bootstrap settings differ from protocol.")
                comparisons += verify_paired(baseline[layer]["predictions"], evidence["predictions"], paired)
        profiles[short] = {"attempts_verified": len(model["rounds"]), "paired_metrics_verified": comparisons,
                           "window_seconds": model["timed_training_seconds"]}
    return {"status": "passed", "minimum_hours": minimum_hours, "profiles": profiles,
            "auditor_sha256": digest(Path(__file__)),
            "summary_sha256": digest(root / "summary.json"), "method": "Independent grouped count vectors and inclusive quantiles; archived round/version chains"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-root", type=Path, required=True)
    parser.add_argument("--minimum-hours", type=float, default=6)
    args = parser.parse_args()
    result = audit(args.study_root.resolve(), args.minimum_hours)
    (args.study_root / "independent-audit.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
