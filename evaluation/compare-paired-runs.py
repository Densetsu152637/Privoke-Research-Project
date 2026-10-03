"""Source-cluster paired intervals for changes on exactly the same labeled rows."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import random
import numpy as np


def align(left, right):
    def keyed(report):
        rows = report["metadata"]["predictions"]
        if any(row["status"] != "ok" for row in rows):
            raise ValueError("Paired primary comparisons require no runtime errors.")
        result = {row["example_id"]: row for row in rows}
        if len(result) != len(rows):
            raise ValueError("Duplicate prediction IDs.")
        return result
    a, b = keyed(left), keyed(right)
    if a.keys() != b.keys():
        raise ValueError("Paired runs used different example IDs.")
    pairs = [(a[key], b[key]) for key in sorted(a)]
    if any(x["expected_has_pii"] != y["expected_has_pii"] or x["group_id"] != y["group_id"] for x, y in pairs):
        raise ValueError("Labels or source groups differ between paired runs.")
    return pairs


def rate_changes(pairs, indexes):
    rows = [pairs[index] for index in indexes]
    positive = [(x, y) for x, y in rows if x["expected_has_pii"]]
    negative = [(x, y) for x, y in rows if not x["expected_has_pii"]]
    if not positive or not negative:
        return None
    recall = sum(int(y["detected_sensitive"]) - int(x["detected_sensitive"]) for x, y in positive) / len(positive)
    specificity = sum(int(x["detected_sensitive"]) - int(y["detected_sensitive"]) for x, y in negative) / len(negative)
    return recall, specificity, (recall + specificity) / 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    parser.add_argument("updated", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Refusing to overwrite a paired comparison.")
    pairs = align(json.loads(args.baseline.read_text()), json.loads(args.updated.read_text()))
    groups = defaultdict(list)
    for index, (row, _) in enumerate(pairs):
        groups[row["group_id"]].append(index)
    randomizer = random.Random(3102026)
    keys = sorted(groups)
    samples = []
    for _ in range(2000):
        indexes = [index for key in randomizer.choices(keys, k=len(keys)) for index in groups[key]]
        changes = rate_changes(pairs, indexes)
        if changes is not None:
            samples.append(changes)
    point = rate_changes(pairs, range(len(pairs)))
    if point is None or not samples:
        raise SystemExit("Both truth classes are required.")
    intervals = np.quantile(np.asarray(samples), [0.025, 0.975], axis=0)
    report = {"scope": "development", "method": "paired source-cluster percentile bootstrap",
              "iterations": 2000, "seed": 3102026, "rows": len(pairs), "groups": len(groups),
              "source_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in [args.baseline, args.updated]},
              "changes": {name: {"estimate": point[index], "low": intervals[0, index], "high": intervals[1, index]}
                          for index, name in enumerate(["recall", "specificity", "balanced_accuracy"])}}
    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps(report["changes"]))

if __name__ == "__main__":
    main()
