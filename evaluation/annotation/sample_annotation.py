#!/usr/bin/env python
"""Deterministic stratified sampler producing blinded double-annotation sheets.

Usage (host Python):
  python sample_annotation.py --input <fresh_eval.jsonl> --output-dir <dir> [--seed N]
      [--main-size 360] [--pilot-size 30] [--annotators A B] [--format csv|jsonl|both]
      [--fail-on-marker] [--marker-pattern REGEX ...] [--normalise-marker folio]
  python sample_annotation.py --input <frozen_set.jsonl> --set-manifest <set_manifest.json> \
      --stratify-by quota_cell --output-dir <results/s13a/packet>     (Stage 13a fresh set, schema v2 sheets;
      the marker gate is always on and --output-dir must lie under the main checkout's evaluation/results/s13a)
  python sample_annotation.py <the same arguments> --verify-against <packet_manifest.json>

Outputs:
  <dir>/sheets/{pilot,main}_<annotator>.{csv,jsonl}  blank label columns, opaque ids and text only
  <dir>/key/sampling_key.jsonl                      coordinator-only: opaque id -> case id, family,
                                                    stratum, design weight, provisional targets
  <dir>/key/manifest.json                           seed, input hash, allocation, population sizes
  <dir>/packet_manifest.json                        sha256 of every blank sheet and of the key (no text)

--verify-against resamples into a scratch directory, compares every hash with the manifest (and with the
files already in --output-dir, when given), and exits non-zero on any difference.

Annotators and adjudicators must never receive the key directory. No labels are generated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import annotation_schema as schema  # noqa: E402
import s13_paths  # noqa: E402

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


def quota_sample(rows, total, seed, tag, minimum):
    """Proportional allocation over quota cells (category/audience/sensitive) with a per-cell floor."""
    cells = defaultdict(list)
    for row in rows:
        cells[row["quota_cell"]].append(row)
    alloc = allocate(total, {k: len(v) for k, v in cells.items()}, minimum)
    chosen = []
    for key in sorted(cells):
        members = sorted(cells[key], key=lambda r: r["id"])
        random.Random(f"{seed}:{tag}:{key}").shuffle(members)
        chosen.extend(members[:alloc[key]])
    return chosen, {k: v for k, v in alloc.items() if v}


def blinded_ids(case_ids, salt):
    width = 10
    while True:
        ids = {c: "it-" + hashlib.sha256(f"{salt}|{c}".encode()).hexdigest()[:width] for c in case_ids}
        if len(set(ids.values())) == len(ids):
            return ids
        width += 2


DATASET_MARKER = re.compile(r"fresh_eval|release-\d+|AU3|folio-\d+", re.IGNORECASE)
# The AU3 partition token that Stage 8 found in every fresh_eval text; 13a-0 normalises it to a constant.
FOLIO_TOKEN = re.compile(r"(?<![\w-])fresh_eval-folio-\d+(?![\w-])", re.IGNORECASE)


def marker_patterns(extra=()):
    """The built-in marker pattern followed by any caller-supplied source-name patterns."""
    return [DATASET_MARKER] + [re.compile(p, re.IGNORECASE) for p in extra]


def jsonl_sha256(rows):
    """Canonical hash of a row set (sorted keys, one JSON object per line)."""
    blob = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows)
    return hashlib.sha256(blob.encode("utf8")).hexdigest()


def normalise_markers(rows, replacement):
    """Replace every whole fresh_eval-folio-NN token in each text; identical for every annotator."""
    return [{**r, "text": FOLIO_TOKEN.sub(replacement, r["text"])} for r in rows]


def blinding_audit(items, extra_patterns=(), normalisation=None):
    """Annotator-facing texts that embed dataset or partition markers (coordinator decision needed)."""
    patterns = marker_patterns(extra_patterns)
    flagged = [r["id"] for r in items if any(p.search(r["text"]) for p in patterns)]
    return {"patterns": [p.pattern for p in patterns], "items_checked": len(items),
            "items_with_marker": len(flagged), "normalisation": normalisation}


def provisional_targets(row):
    return {
        "disclosure": "yes" if row["required_sensitive"] else "no",
        "sensitivity": row["classification"]["sensitivity"],
        "visibility": row["classification"]["visibility"],
        "categories": sorted(row["classification"]["categories"]),
        "allowed_actions": list(row["allowed_actions"]),
    }


def sheet_rows(items, ids, order_seed, label_columns=None):
    ordered = sorted(items, key=lambda r: ids[r["id"]])
    random.Random(order_seed).shuffle(ordered)
    return [{"item_id": ids[r["id"]], "text": r["text"], **{c: "" for c in (label_columns or schema.LABEL_COLUMNS)}}
            for r in ordered]


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(args, out):
    quota = args.stratify_by == "quota_cell"
    min_per_cell = args.min_per_cell if args.min_per_cell is not None else (1 if quota else 4)
    path = Path(args.input)
    digest = file_sha256(path)
    if quota:
        if args.set_manifest:
            expected = json.loads(Path(args.set_manifest).read_text(encoding="utf8"))["sha256_jsonl"]
            if digest != expected:
                raise SystemExit(f"input sha256 {digest} differs from the set manifest {expected}")
        elif not args.skip_hash_check:
            raise SystemExit("quota_cell mode needs --set-manifest (or --skip-hash-check)")
    elif not args.skip_hash_check and digest != PINNED_INPUT_SHA256:
        raise SystemExit(f"input sha256 {digest} differs from the pinned fresh_eval file; use --skip-hash-check to override")
    rows = load_rows(path)
    if len({r["id"] for r in rows}) != len(rows):
        raise SystemExit("duplicate case ids in input")
    normalisation = None
    if args.normalise_marker:
        original_rows_sha256 = jsonl_sha256(rows)
        rows = normalise_markers(rows, args.normalise_marker)
        normalisation = {"pattern": FOLIO_TOKEN.pattern, "replacement": args.normalise_marker,
                         "original_sha256": digest, "original_rows_sha256": original_rows_sha256,
                         "normalised_sha256": jsonl_sha256(rows)}
    sampler = quota_sample if quota else stratified_sample
    cell_of = (lambda r: r["quota_cell"]) if quota else (lambda r: "/".join(stratum_of(r)))
    main, main_alloc = sampler(rows, args.main_size, args.seed, "main", min_per_cell)
    taken = {r["id"] for r in main}
    rest = [r for r in rows if r["id"] not in taken]
    pilot, pilot_alloc = sampler(rest, args.pilot_size, args.pilot_seed if args.pilot_seed is not None else args.seed, "pilot", 0)
    salt = args.id_salt or f"privoke-annotation-{args.seed}"
    ids = blinded_ids([r["id"] for r in main + pilot], salt)

    audit = blinding_audit(main + pilot, args.marker_pattern, normalisation)
    if audit["items_with_marker"]:
        message = (f"{audit['items_with_marker']} of {audit['items_checked']} annotator-facing texts embed a dataset "
                   "marker (partition name or scenario token)")
        if args.fail_on_marker or quota:  # the gate is always on for the Stage 13a fresh set
            raise SystemExit(f"blinding gate failed: {message}; nothing was written")
        print(f"warning: {message}; see blinding_audit in key/manifest.json", file=sys.stderr)

    population = defaultdict(int)
    for r in rows:
        population[cell_of(r)] += 1
    out = Path(out)
    label_columns = schema.label_columns_for(2 if quota else 1)
    sheet_columns = schema.sheet_columns_for(2 if quota else 1)
    (out / "sheets").mkdir(parents=True, exist_ok=True)
    (out / "key").mkdir(parents=True, exist_ok=True)
    for split, items in (("pilot", pilot), ("main", main)):
        for annotator in args.annotators:
            sheet = sheet_rows(items, ids, f"{args.seed}:order:{split}:{annotator}", label_columns)
            stem = out / "sheets" / f"{split}_{annotator}"
            if args.format in ("csv", "both"):
                schema.write_csv(stem.with_suffix(".csv"), sheet_columns, sheet)
            if args.format in ("jsonl", "both"):
                schema.write_jsonl(stem.with_suffix(".jsonl"), sheet)

    key = []
    for split, items, alloc in (("main", main, main_alloc), ("pilot", pilot, pilot_alloc)):
        for r in sorted(items, key=lambda r: ids[r["id"]]):
            cell = cell_of(r)
            weight = (population[cell] / alloc[cell]) if split == "main" else None
            if quota:
                key.append({"item_id": ids[r["id"]], "case_id": r["id"], "split": split, "family_id": cell,
                            "quota_cell": cell, "stratum": cell, "design_weight": weight})
                continue
            key.append({
                "item_id": ids[r["id"]], "case_id": r["id"], "split": split, "family_id": r["family_id"],
                "expression_group_id": r["metadata"]["audience_expression_group_id"],
                "stratum": cell, "control": r["metadata"]["control"],
                "design_weight": weight,
                "provisional": provisional_targets(r),
            })
    schema.write_jsonl(out / "key" / "sampling_key.jsonl", key)
    manifest = {
        "version": VERSION, "blinding_audit": audit, "seed": args.seed, "id_salt_commitment": hashlib.sha256(salt.encode()).hexdigest(),
        "input_sha256": digest, "input_rows": len(rows), "annotators": args.annotators, "format": args.format,
        "main_size": len(main), "pilot_size": len(pilot), "min_per_cell": min_per_cell,
        "stratify_by": args.stratify_by,
        "population_by_stratum": dict(sorted(population.items())),
        "main_allocation": dict(sorted(main_alloc.items())), "pilot_allocation": dict(sorted(pilot_alloc.items())),
        "stratum_format": "category/audience/sensitive (writer-declared quota cell)" if quota
        else "visibility/control/sensitivity (provisional; coordinator only)",
        "main_families": len({cell_of(r) if quota else r["family_id"] for r in main}),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (out / "key" / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf8")
    files = {f"sheets/{split}_{a}.{ext}": file_sha256(out / "sheets" / f"{split}_{a}.{ext}")
             for split in ("pilot", "main") for a in args.annotators
             for ext in (("csv", "jsonl") if args.format == "both" else (args.format,))}
    files["key/sampling_key.jsonl"] = file_sha256(out / "key" / "sampling_key.jsonl")
    manifest["packet"] = {
        "schema": "privoke-s13a-packet-v1",
        "parameters": {"stratify_by": args.stratify_by, "seed": args.seed, "pilot_seed": args.pilot_seed,
                       "main_size": args.main_size, "pilot_size": args.pilot_size, "min_per_cell": min_per_cell,
                       "annotators": args.annotators, "format": args.format,
                       "id_salt_commitment": manifest["id_salt_commitment"],
                       "normalise_marker": args.normalise_marker, "marker_patterns": audit["patterns"]},
        "input_sha256": digest, "files": dict(sorted(files.items())),
    }
    (out / "packet_manifest.json").write_text(json.dumps(manifest["packet"], indent=2, sort_keys=True) + "\n", encoding="utf8")
    return manifest


def verify(args):
    """Resample into a scratch directory and compare every hash with the packet manifest."""
    expected = json.loads(Path(args.verify_against).read_text(encoding="utf8"))
    with tempfile.TemporaryDirectory() as scratch:
        fresh = build(args, scratch)["packet"]
    problems = []
    for name, value in expected["parameters"].items():
        if fresh["parameters"].get(name) != value:
            problems.append(f"parameter {name} differs")
    if expected.get("input_sha256") != fresh["input_sha256"]:
        problems.append("input_sha256 differs")
    names = sorted(set(expected["files"]) | set(fresh["files"]))
    on_disk = Path(args.output_dir) if args.output_dir else None
    if on_disk is not None and on_disk.is_dir():
        allowed = set(expected["files"]) | {"packet_manifest.json", "key/manifest.json"}
        for file in sorted(p for p in on_disk.rglob("*") if p.is_file()):
            rel = file.relative_to(on_disk).as_posix()
            if rel not in allowed:
                problems.append(f"{rel}: file in {on_disk} is not listed in the manifest")
    for name in names:
        if expected["files"].get(name) != fresh["files"].get(name):
            problems.append(f"{name}: resampled hash differs from the manifest")
        if on_disk is not None and (on_disk / name).exists() and expected["files"].get(name) != file_sha256(on_disk / name):
            problems.append(f"{name}: file in {on_disk} differs from the manifest")
    print(json.dumps({"verify_against": str(args.verify_against), "files": len(names), "match": not problems,
                      "problems": problems}))
    return 1 if problems else 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", required=True, help="AU3 fresh_eval.jsonl (1,560 rows)")
    p.add_argument("--output-dir", help="required unless --verify-against is given")
    p.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p.add_argument("--pilot-seed", type=int, default=None, help="seed for a repeat pilot round; the main sample is unaffected")
    p.add_argument("--main-size", type=int, default=360)
    p.add_argument("--pilot-size", type=int, default=30)
    p.add_argument("--min-per-cell", type=int, default=None, help="per-cell floor (default 4; 1 for quota_cell)")
    p.add_argument("--stratify-by", choices=["au3", "quota_cell"], default="au3",
                   help="au3: audience/control/sensitivity strata of the AU3 file; quota_cell: Stage 13a fresh set")
    p.add_argument("--set-manifest", help="set_manifest.json whose sha256_jsonl must equal the input (quota_cell mode)")
    p.add_argument("--verify-against", metavar="PACKET_MANIFEST",
                   help="resample into a scratch directory and exit non-zero on any hash difference")
    p.add_argument("--annotators", nargs="+", default=["A", "B"])
    p.add_argument("--format", choices=["csv", "jsonl", "both"], default="csv")
    p.add_argument("--id-salt", default=None)
    p.add_argument("--skip-hash-check", action="store_true")
    p.add_argument("--fail-on-marker", action="store_true",
                   help="exit non-zero, writing nothing, when any sampled text matches a marker pattern")
    p.add_argument("--marker-pattern", action="append", default=[], metavar="REGEX",
                   help="extra case-insensitive source-name pattern for the blinding audit (repeatable)")
    p.add_argument("--normalise-marker", choices=["folio"], default=None,
                   help="replace every whole fresh_eval-folio-NN token with this constant before sampling")
    args = p.parse_args(argv)
    if args.verify_against:
        raise SystemExit(verify(args))
    if not args.output_dir:
        p.error("--output-dir is required")
    if args.stratify_by == "quota_cell":
        s13_paths.require_under(args.output_dir, s13_paths.results_root(), "--output-dir")
    manifest = build(args, args.output_dir)
    print(json.dumps({k: manifest[k] for k in ("main_size", "pilot_size", "main_families", "input_sha256")}))


if __name__ == "__main__":
    main()
