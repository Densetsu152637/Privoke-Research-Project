"""Prepare a source-disjoint negative-coverage curriculum without scoring final data."""
import argparse
import ast
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random

from privoke_eval.datasets import load_examples
from privoke_model.training_data import training_text_key

ROOT = Path(__file__).resolve().parents[1]


def bootstrap_examples(source):
    """Read the existing literal training-sample function without regenerating models."""
    tree = ast.parse(source)
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "training_samples")
    namespace = {}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "bootstrap_samples", "exec"), namespace)
    return namespace["training_samples"]()


def select_clean_pool(examples, locked, anchors, count, seed):
    if count <= 0:
        raise ValueError("Clean sample count must be positive.")
    blocked_groups = {str(row["group_id"]) for row in locked}
    blocked_ids = {str(row["id"]) for row in locked}
    blocked_keys = {training_text_key(row["text"]) for row in locked}
    blocked_keys.update(training_text_key(item[0]) for item in anchors)
    exclusions = Counter()
    by_key = {}
    for item in examples:
        group = str(item.metadata.get("group_id") or "")
        identifier = str(item.metadata.get("example_id") or "")
        key = training_text_key(item.text)
        if not group or not identifier or not key:
            exclusions["missing_provenance"] += 1
            continue
        if group in blocked_groups or identifier in blocked_ids or key in blocked_keys:
            exclusions["locked_group_id_or_text_or_anchor"] += 1
            continue
        if key in by_key:
            previous = by_key[key]
            exclusions["normalized_duplicate"] += 1
            if previous is not None and previous.expected_has_pii != item.expected_has_pii:
                by_key[key] = None
                exclusions["normalized_conflicting_key"] += 1
            continue
        by_key[key] = item
    pool = sorted((item for item in by_key.values()
                   if item is not None and not item.expected_has_pii),
                  key=lambda item: item.metadata["example_id"])
    if len(pool) < count:
        raise ValueError(f"Only {len(pool)} eligible clean rows; {count} requested.")
    selected = random.Random(seed).sample(pool, count)
    # Verify the serialized selection rather than relying on the filtering intent.
    if any(str(item.metadata["group_id"]) in blocked_groups
           or str(item.metadata["example_id"]) in blocked_ids
           or training_text_key(item.text) in blocked_keys for item in selected):
        raise ValueError("Selected training data overlaps protected data.")
    if len({training_text_key(item.text) for item in selected}) != count:
        raise ValueError("Selected training texts are not distinct.")
    return selected, {"eligible_clean_pool": len(pool), "excluded_locked_groups": len(blocked_groups),
                      "excluded_locked_ids": len(blocked_ids), "exclusions": dict(exclusions)}


def escape_template(text):
    return text.replace("{", "{{").replace("}", "}}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation/results/public-negative-curriculum")
    parser.add_argument("--count", type=int, default=2400)
    parser.add_argument("--seed", type=int, default=4102026)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Refusing to replace a generated curriculum or its manifest.")
    protected = ROOT / "evaluation/results/locked-public"
    locked_manifest = json.loads((protected / "manifest.json").read_text(encoding="utf-8"))
    locked = []
    protected_hashes = {}
    for name in ("development", "final"):
        content = (protected / (name + ".jsonl")).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest != locked_manifest["partitions"][name]["sha256"]:
            raise SystemExit("A protected partition differs from its locked digest.")
        protected_hashes[name] = digest
        locked.extend(json.loads(line) for line in content.decode("utf-8").splitlines() if line.strip())
    bootstrap_path = ROOT / "models/generate_baseline.py"
    anchors = bootstrap_examples(bootstrap_path.read_text(encoding="utf-8"))
    spec, loaded = load_examples("piimb", None, seed=args.seed, strategy="balanced", english_only=True)
    if spec.revision != locked_manifest["revision"] or not loaded.population_scan_complete:
        raise SystemExit("Training scan must use the locked revision and finish the population.")
    selected, selection = select_clean_pool(loaded.examples, locked, anchors, args.count, args.seed)
    rows = [{"template": escape_template(item.text),
             "classification": {"sensitivity": "S0", "visibility": "PU", "categories": []},
             "metadata": {**item.metadata, "training_role": "public_annotation_negative",
                          "label_status": "provisional_annotation_presence_policy_target"}}
            for item in selected]
    rows.extend({"template": escape_template(text),
                 "classification": {"sensitivity": sensitivity, "visibility": visibility,
                                    "categories": list(categories)},
                 "metadata": {"group_id": f"bootstrap:{index}",
                              "training_role": "existing_bootstrap_replay",
                              "label_status": "existing_training_label"}}
                for index, (text, sensitivity, visibility, categories) in enumerate(anchors))
    content = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    provenance = asdict(loaded)
    del provenance["examples"]
    manifest = {"dataset": "piimb", "revision": spec.revision, "upstream_split": "test",
                "scope": "Custom source-disjoint negative-coverage training, not official benchmark-test evaluation",
                "seed": args.seed, "public_clean_rows": len(selected), "bootstrap_replay_rows": len(anchors),
                "selection": selection, "population_scan": provenance, "protected_sha256": protected_hashes,
                "bootstrap_source_sha256": hashlib.sha256(bootstrap_path.read_bytes()).hexdigest(),
                "curriculum_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "public_source_counts": dict(Counter(item.metadata["source_dataset"] for item in selected)),
                "public_source_groups": len({item.metadata["group_id"] for item in selected}),
                "overlaps": {"locked_groups": 0, "locked_ids": 0, "normalized_text": 0}}
    args.output.mkdir(parents=True)
    (args.output / "prompts.jsonl").write_text(content, encoding="utf-8")
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({key: manifest[key] for key in
                     ("public_clean_rows", "bootstrap_replay_rows", "selection", "public_source_counts", "overlaps")}))


if __name__ == "__main__":
    main()
