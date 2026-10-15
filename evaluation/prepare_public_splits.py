"""Lock document-disjoint public development and final sets before tuning."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import random

from privoke_eval.datasets import load_examples


def partition_examples(examples, seed):
    groups = sorted({str(item.metadata.get("group_id") or item.metadata["example_id"]) for item in examples})
    random.Random(seed).shuffle(groups)
    final_groups = set(groups[:len(groups) // 2])
    development, final = [], []
    for item in examples:
        group = str(item.metadata.get("group_id") or item.metadata["example_id"])
        (final if group in final_groups else development).append(item)
    if any({item.expected_has_pii for item in split} != {False, True} for split in (development, final)):
        raise ValueError("Both partitions must contain sensitive and clean examples.")
    return development, final


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("results/locked-public"))
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=3102026)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Refusing to replace an existing locked data directory.")
    spec, selected = load_examples("piimb", args.samples, None, seed=args.seed, strategy="balanced", english_only=True)
    development, final = partition_examples(selected.examples, args.seed)
    args.output.mkdir(parents=True)
    manifest = {"dataset": "piimb", "revision": spec.revision, "seed": args.seed,
                "grouping": "source document", "selection": asdict(selected), "partitions": {}}
    # The manifest records provenance and counts, without duplicating full prompt text.
    del manifest["selection"]["examples"]
    for name, examples in (("development", development), ("final", final)):
        records = [{"id": item.metadata["example_id"], "text": item.text,
                    "expected_has_pii": item.expected_has_pii,
                    "expected_categories": list(item.expected_categories),
                    **item.metadata, "protocol_partition": name} for item in examples]
        content = "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records)
        (args.output / (name + ".jsonl")).write_text(content, encoding="utf-8")
        manifest["partitions"][name] = {"count": len(examples),
            "sensitive": sum(item.expected_has_pii for item in examples),
            "sha256": hashlib.sha256(content.encode()).hexdigest()}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest["partitions"], indent=2))


if __name__ == "__main__":
    main()
