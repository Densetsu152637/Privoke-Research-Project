#!/usr/bin/env python
"""Deterministic stratified sampler producing blinded double-annotation sheets.

Usage (host Python):
  python sample_annotation.py --input <fresh_eval.jsonl> --output-dir <dir> [--seed N]
      [--main-size 360] [--pilot-size 30] [--annotators A B] [--format csv|jsonl|both]

Outputs:
  <dir>/sheets/{pilot,main}_<annotator>.{csv,jsonl}  blank label columns, opaque ids and text only
  <dir>/key/sampling_key.jsonl                      coordinator-only: opaque id -> case id, family,
                                                    stratum, design weight, provisional targets
  <dir>/key/manifest.json                           seed, input hash, allocation, population sizes

Annotators and adjudicators must never receive the key directory. No labels are generated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import annotation_schema as schema  # noqa: E402

PINNED_INPUT_SHA256 = "e965c21a0d43babc0984f46eb70785c8d66d878e00e647eefb9565f219b2da0c"
DEFAULT_SEED = 20261024
VERSION = 1


def load_rows(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf8").splitlines() if line.strip()]


def stratum_of(row):
    """(audience group, control type, provisional sensitivity) - used only inside the key."""
    return (row["classification"]["visibility"], row["metadata"]["control"], row["classification"]["sensitivity"])


def allocate(total, sizes, minimum=0):
    """Proportional allocation with a per-cell floor, summing to total (largest remainder)."""
    keys = sorted(sizes)
    population = sum(sizes[k] for k in keys)
    if total > population:
        raise ValueError("requested sample exceeds available population")
    floor_total = sum(min(minimum, sizes[k]) for k in keys)
    if floor_total > total:
        raise ValueError("per-cell minimum exceeds the requested sample size")
    quota = {k: total * sizes[k] / population for k in keys}
    alloc = {k: min(sizes[k], max(min(minimum, sizes[k]), math.floor(quota[k]))) for k in keys}
    while sum(alloc.values()) > total:
        candidates = [k for k in keys if alloc[k] > min(minimum, sizes[k])]
        k = max(candidates, key=lambda c: (alloc[c] - quota[c], c))
        alloc[k] -= 1
    while sum(alloc.values()) < total:
        candidates = [k for k in keys if alloc[k] < sizes[k]]
        k = max(candidates, key=lambda c: (quota[c] - alloc[c], c))
        alloc[k] += 1
    return alloc


def draw_cell(rows, count, rng):
    """Round-robin over shuffled families so each cell spreads across scenario families."""
    by_family = defaultdict(list)
    for row in rows:
        by_family[row["family_id"]].append(row)
    families = sorted(by_family)
    rng.shuffle(families)
    for family in families:
        by_family[family].sort(key=lambda r: r["id"])
        rng.shuffle(by_family[family])
    picked = []
    while len(picked) < count:
        progressed = False
        for family in families:
            if by_family[family] and len(picked) < count:
                picked.append(by_family[family].pop())
                progressed = True
        if not progressed:
            break
    return picked


def stratified_sample(rows, total, seed, tag, minimum):
    """Equal allocation across audience groups, proportional (floored) across cells inside."""
    cells = defaultdict(list)
    for row in rows:
        cells[stratum_of(row)].append(row)
    groups = sorted({k[0] for k in cells})
    available = {g: sum(len(v) for k, v in cells.items() if k[0] == g) for g in groups}
    # Equal shares per audience group (largest remainder, capped by availability).
    per_group = {g: 0 for g in groups}
    for i in range(total):
        open_groups = [g for g in groups if per_group[g] < available[g]]
        g = min(open_groups, key=lambda c: (per_group[c], c))
        per_group[g] += 1
    chosen, allocation = [], {}
    for group in groups:
        sizes = {k: len(v) for k, v in cells.items() if k[0] == group}
        sub = allocate(per_group[group], sizes, minimum)
        for key in sorted(sub):
            rng = random.Random(f"{seed}:{tag}:{'/'.join(key)}")
            chosen.extend(draw_cell(cells[key], sub[key], rng))
            allocation["/".join(key)] = sub[key]
    return chosen, allocation


def blinded_ids(case_ids, salt):
    width = 10
    while True:
        ids = {c: "it-" + hashlib.sha256(f"{salt}|{c}".encode()).hexdigest()[:width] for c in case_ids}
        if len(set(ids.values())) == len(ids):
            return ids
        width += 2


def provisional_targets(row):
    return {
        "disclosure": "yes" if row["required_sensitive"] else "no",
        "sensitivity": row["classification"]["sensitivity"],
        "visibility": row["classification"]["visibility"],
        "categories": sorted(row["classification"]["categories"]),
        "allowed_actions": list(row["allowed_actions"]),
    }


def sheet_rows(items, ids, order_seed):
    ordered = sorted(items, key=lambda r: ids[r["id"]])
    random.Random(order_seed).shuffle(ordered)
    return [{"item_id": ids[r["id"]], "text": r["text"], **{c: "" for c in schema.LABEL_COLUMNS}} for r in ordered]


def build(args):
    path = Path(args.input)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not args.skip_hash_check and digest != PINNED_INPUT_SHA256:
        raise SystemExit(f"input sha256 {digest} differs from the pinned fresh_eval file; use --skip-hash-check to override")
    rows = load_rows(path)
    if len({r["id"] for r in rows}) != len(rows):
        raise SystemExit("duplicate case ids in input")
    main, main_alloc = stratified_sample(rows, args.main_size, args.seed, "main", args.min_per_cell)
    taken = {r["id"] for r in main}
    rest = [r for r in rows if r["id"] not in taken]
    pilot, pilot_alloc = stratified_sample(rest, args.pilot_size, args.pilot_seed if args.pilot_seed is not None else args.seed, "pilot", 0)
    salt = args.id_salt or f"privoke-annotation-{args.seed}"
    ids = blinded_ids([r["id"] for r in main + pilot], salt)

    population = defaultdict(int)
    for r in rows:
        population["/".join(stratum_of(r))] += 1
    out = Path(args.output_dir)
    (out / "sheets").mkdir(parents=True, exist_ok=True)
    (out / "key").mkdir(parents=True, exist_ok=True)
    for split, items in (("pilot", pilot), ("main", main)):
        for annotator in args.annotators:
            sheet = sheet_rows(items, ids, f"{args.seed}:order:{split}:{annotator}")
            stem = out / "sheets" / f"{split}_{annotator}"
            if args.format in ("csv", "both"):
                schema.write_csv(stem.with_suffix(".csv"), schema.SHEET_COLUMNS, sheet)
            if args.format in ("jsonl", "both"):
                schema.write_jsonl(stem.with_suffix(".jsonl"), sheet)

    key = []
    for split, items, alloc in (("main", main, main_alloc), ("pilot", pilot, pilot_alloc)):
        for r in sorted(items, key=lambda r: ids[r["id"]]):
            cell = "/".join(stratum_of(r))
            key.append({
                "item_id": ids[r["id"]], "case_id": r["id"], "split": split, "family_id": r["family_id"],
                "expression_group_id": r["metadata"]["audience_expression_group_id"],
                "stratum": cell, "control": r["metadata"]["control"],
                "design_weight": (population[cell] / alloc[cell]) if split == "main" else None,
                "provisional": provisional_targets(r),
            })
    schema.write_jsonl(out / "key" / "sampling_key.jsonl", key)
    manifest = {
        "version": VERSION, "seed": args.seed, "id_salt_commitment": hashlib.sha256(salt.encode()).hexdigest(),
        "input_sha256": digest, "input_rows": len(rows), "annotators": args.annotators, "format": args.format,
        "main_size": len(main), "pilot_size": len(pilot), "min_per_cell": args.min_per_cell,
        "population_by_stratum": dict(sorted(population.items())),
        "main_allocation": dict(sorted(main_alloc.items())), "pilot_allocation": dict(sorted(pilot_alloc.items())),
        "stratum_format": "visibility/control/sensitivity (provisional; coordinator only)",
        "main_families": len({r["family_id"] for r in main}),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (out / "key" / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf8")
    return manifest


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", required=True, help="AU3 fresh_eval.jsonl (1,560 rows)")
    p.add_argument("--output-dir", required=True)
    p.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p.add_argument("--pilot-seed", type=int, default=None, help="seed for a repeat pilot round; the main sample is unaffected")
    p.add_argument("--main-size", type=int, default=360)
    p.add_argument("--pilot-size", type=int, default=30)
    p.add_argument("--min-per-cell", type=int, default=4)
    p.add_argument("--annotators", nargs="+", default=["A", "B"])
    p.add_argument("--format", choices=["csv", "jsonl", "both"], default="csv")
    p.add_argument("--id-salt", default=None)
    p.add_argument("--skip-hash-check", action="store_true")
    manifest = build(p.parse_args(argv))
    print(json.dumps({k: manifest[k] for k in ("main_size", "pilot_size", "main_families", "input_sha256")}))


if __name__ == "__main__":
    main()
