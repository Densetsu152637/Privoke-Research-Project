"""Prepare grouped, protected-source-disjoint rows for the frozen encoder probe."""
import hashlib
import json
import random
from collections import Counter
from pathlib import Path

from privoke_eval.datasets import load_examples
from privoke_model.training_data import training_text_key

ROOT = Path(__file__).resolve().parents[1]
LOCKED = ROOT / "evaluation/results/locked-public"
OUT = ROOT / "evaluation/results/frozen-representation-study"


def read_locked(path):
    raw = path.read_bytes()
    return raw, [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]


def select_rows(examples, locked_rows, anchors, count=2400, seed=5102026):
    protected_groups = {str(row["group_id"]) for row in locked_rows}
    protected_ids = {str(row["id"]) for row in locked_rows}
    protected_keys = {training_text_key(row["text"]) for row in locked_rows}
    protected_keys.update(training_text_key(item[0]) for item in anchors)
    exclusions = Counter()
    by_key = {}
    for row in examples:
        group = str(row.metadata.get("group_id") or "")
        identifier = str(row.metadata.get("example_id") or "")
        key = training_text_key(row.text)
        if not group or not identifier or not key:
            exclusions["missing_provenance"] += 1
            continue
        if group in protected_groups or identifier in protected_ids or key in protected_keys:
            exclusions["protected_group_id_or_text"] += 1
            continue
        if key in by_key:
            prior = by_key[key]
            exclusions["normalized_duplicate"] += 1
            if prior is not None and prior.expected_has_pii != row.expected_has_pii:
                by_key[key] = None
                exclusions["normalized_conflict"] += 1
            continue
        by_key[key] = row
    unique = [row for row in by_key.values() if row is not None]
    selected = []
    sampler = random.Random(seed)
    for label in (True, False):
        pool = sorted((row for row in unique if row.expected_has_pii is label),
                      key=lambda row: row.metadata["example_id"])
        if len(pool) < count:
            raise ValueError(f"Only {len(pool)} eligible {'positive' if label else 'clean'} rows; {count} required.")
        selected.extend(sampler.sample(pool, count))
    selected.sort(key=lambda row: row.metadata["example_id"])
    groups = sorted({str(row.metadata["group_id"]) for row in selected})
    shuffled = groups[:]
    random.Random(6102026).shuffle(shuffled)
    validation_groups = set(shuffled[: max(1, (len(groups) + 4) // 5)])
    train = [row for row in selected if str(row.metadata["group_id"]) not in validation_groups]
    validation = [row for row in selected if str(row.metadata["group_id"]) in validation_groups]
    for name, partition in (("train", train), ("validation", validation)):
        counts = Counter(row.expected_has_pii for row in partition)
        if min(counts[True], counts[False]) < 50:
            raise ValueError(f"{name} partition has fewer than 50 examples of each truth class.")
    if {row.metadata["group_id"] for row in train} & {row.metadata["group_id"] for row in validation}:
        raise ValueError("Source group overlaps across partitions.")
    if {training_text_key(row.text) for row in train} & {training_text_key(row.text) for row in validation}:
        raise ValueError("Normalized text overlaps across partitions.")
    return selected, train, validation, {"exclusions": dict(exclusions), "protected_groups": len(protected_groups),
        "protected_ids": len(protected_ids), "protected_text_keys": len(protected_keys),
        "source_counts": dict(Counter(row.metadata["source_dataset"] for row in selected)),
        "selected_groups": len(groups), "validation_groups": sorted(validation_groups)}


def serialize(row):
    return {"id": row.metadata["example_id"], "group_id": row.metadata["group_id"],
            "text": row.text, "text_key": training_text_key(row.text),
            "expected_has_pii": bool(row.expected_has_pii)}


def main():
    if OUT.exists():
        raise SystemExit(f"Refusing to replace existing study output: {OUT}")
    manifest = json.loads((LOCKED / "manifest.json").read_text(encoding="utf-8"))
    locked = []
    locked_hashes = {}
    for name in ("development", "final"):
        raw, rows = read_locked(LOCKED / f"{name}.jsonl")
        digest = hashlib.sha256(raw).hexdigest()
        if digest != manifest["partitions"][name]["sha256"]:
            raise ValueError(f"Locked {name} partition digest mismatch.")
        locked.extend(rows)
        locked_hashes[name] = digest
    # Only text keys, IDs and groups from protected prompts participate in exclusions.
    protected = [{key: row[key] for key in ("id", "group_id", "text")} for row in locked]
    spec, loaded = load_examples("piimb", None, seed=5102026, strategy="balanced", english_only=True)
    if spec.revision != manifest["revision"] or not loaded.population_scan_complete:
        raise ValueError("Full English scan must match the locked PIIMB revision.")
    source = ROOT / "models/generate_baseline.py"
    import ast
    tree = ast.parse(source.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "training_samples")
    ns = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "bootstrap_samples", "exec"), ns)
    anchors = ns["training_samples"]()
    selected, train, validation, details = select_rows(loaded.examples, protected, anchors)
    development = [json.loads(line) for line in (LOCKED / "development.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    partitions = {"train": train, "validation": validation, "development": development}
    OUT.mkdir(parents=True)
    hashes = {}
    for name, rows in partitions.items():
        content = "".join(json.dumps(serialize(row), ensure_ascii=False) + "\n" for row in rows)
        path = OUT / f"{name}.jsonl"
        path.write_text(content, encoding="utf-8")
        hashes[name] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    partition_digests = {}
    for name, rows in partitions.items():
        normalized = [serialize(row) for row in rows]
        partition_digests[name] = {
            "ids_sha256": hashlib.sha256("\n".join(sorted(row["id"] for row in normalized)).encode()).hexdigest(),
            "groups_sha256": hashlib.sha256("\n".join(sorted({row["group_id"] for row in normalized})).encode()).hexdigest(),
            "text_keys_sha256": hashlib.sha256("\n".join(sorted(row["text_key"] for row in normalized)).encode()).hexdigest(),
        }
    record = {"scope": "offline frozen representation diagnostic; not production training",
              "dataset": "piimb", "revision": spec.revision, "seed": 5102026, "validation_seed": 6102026,
              "rows": {name: len(rows) for name, rows in partitions.items()}, "counts": details,
              "selected_ids": [row.metadata["example_id"] for row in selected],
              "selected_groups": sorted({str(row.metadata["group_id"]) for row in selected}),
              "partition_digests": partition_digests,
              "locked_sha256": locked_hashes, "bootstrap_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "partition_sha256": hashes, "population_scan": {k: v for k, v in vars(loaded).items() if k != "examples"}}
    (OUT / "manifest.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps({"output": OUT.as_posix(), "rows": record["rows"], "partition_sha256": hashes}))


if __name__ == "__main__":
    main()
