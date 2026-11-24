#!/usr/bin/env python
"""Freeze the Stage 13a fresh prompt set: normalise, de-duplicate, check contamination, check quotas.

Usage (host Python):
  python fresh_set.py --input <raw file or directory> --dry-run --check-quotas
  python fresh_set.py --input <raw> --out <results/s13a/packet> --source-kind writers [--check-quotas]

Raw input (Git-ignored, delivered by the writers): JSONL or CSV rows with the columns
  text, category (one of the 10 categories or NONE), audience (P0-P4 or PU), sensitive (yes|no)
A directory is read file by file in sorted order (*.jsonl, *.csv). Only whitespace is normalised.

Steps: normalise whitespace; remove exact duplicates; assign opaque ids; remove every prompt that has an exact
match, or an 8-gram Jaccard of at least 0.5, or a containment of at least 0.5 (shared n-grams over the prompt's
own n-grams; a prompt shorter than 8 tokens uses n-grams down to its own length), against the prompt-bearing
files of the contamination sources; remove every prompt that matches a dataset marker. The default sources are
evaluation/datasets/ of this checkout, evaluation/results/ of the main checkout (the frozen Stage 3 set, the s13*
directories excluded). The fuzzer outputs are covered only through that results/ tree; pass any other curriculum
path with --source. --source adds to the defaults. A real freeze fails when a source is missing or holds no scanned file. The brief's quotas are then
checked on what remains.

Outputs (never in Git, because they hold text) go under evaluation/results/s13a/ of the main checkout:
  <out>/frozen_set.jsonl   {id, text, category, audience, sensitive, quota_cell}
  <out>/set_manifest.json  no text: {schema, n, sha256_jsonl, source_kind, contamination, quota_counts, ...}
--dry-run reports counts only and writes nothing. --check-quotas exits 1 when the quotas are unmet.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import annotation_schema as schema  # noqa: E402
import s13_paths  # noqa: E402
import sample_annotation as sampler  # noqa: E402

SCHEMA = "privoke-s13a-set-v1"
MAIN_CHECKOUT = Path("D:/Git Repositories/Privoke-Research-Project")
REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_KINDS = ["writers", "public_corpus", "agent_generated"]
NGRAM = 8
NEAR_JACCARD = 0.5
MIN_NGRAM_TOKENS = 3  # a prompt of fewer tokens is only compared for exact equality
TEXT_SUFFIXES = {".jsonl", ".json", ".csv", ".txt", ".md"}

# The writer brief's quotas (docs/research/s13a-writer-brief-*.md). 390 = 360 main + 30 pilot items (D3).
QUOTAS = {"min_total": 390, "min_sensitive_share": 0.45, "min_per_category": 20}


def normalise_text(text):
    return " ".join(str(text).split())


def tokens(text):
    return re.findall(r"\w+", text.lower())


def opaque_id(text, salt):
    return "fs-" + hashlib.sha256(f"{salt}|{text}".encode("utf8")).hexdigest()[:12]


def raw_files(path):
    path = Path(path)
    if path.is_dir():
        return sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in (".jsonl", ".csv"))
    return [path]


def read_raw(path):
    """Return (rows, problems); problems name files and row numbers, never text."""
    rows, problems = [], []
    for file in raw_files(path):
        if file.suffix.lower() == ".csv":
            with file.open(newline="", encoding="utf-8-sig") as handle:
                records = list(csv.DictReader(handle))
        else:
            records = [json.loads(line) for line in file.read_text(encoding="utf8").splitlines() if line.strip()]
        for number, record in enumerate(records, start=1):
            where = f"{file.name}:{number}"
            text = normalise_text(record.get("text", ""))
            category = str(record.get("category", "") or "").strip().upper()
            audience = str(record.get("audience", "") or "").strip().upper()
            sensitive = str(record.get("sensitive", "") or "").strip().lower()
            if not text:
                problems.append(f"{where}: empty text")
            if category != "NONE" and category not in schema.CATEGORIES:
                problems.append(f"{where}: invalid category")
            if audience not in schema.AUDIENCES:
                problems.append(f"{where}: invalid audience")
            if sensitive not in schema.SENSITIVE:
                problems.append(f"{where}: invalid sensitive")
            rows.append({"text": text, "category": category, "audience": audience, "sensitive": sensitive})
    return rows, problems


def deduplicate(rows):
    seen, kept = set(), []
    for row in rows:
        if row["text"] in seen:
            continue
        seen.add(row["text"])
        kept.append(row)
    return kept


def quota_counts(rows):
    n = len(rows)
    sensitive = sum(r["sensitive"] == "yes" for r in rows)
    return {
        "n": n, "sensitive": sensitive, "sensitive_share": (sensitive / n) if n else 0.0,
        "by_category": {c: sum(r["category"] == c for r in rows) for c in schema.CATEGORIES + ["NONE"]},
        "by_audience": {a: sum(r["audience"] == a for r in rows) for a in schema.AUDIENCES},
        "cells": dict(sorted(Counter(r["quota_cell"] for r in rows).items())),
    }


def quota_violations(counts, quotas=QUOTAS):
    problems = []
    if counts["n"] < quotas["min_total"]:
        problems.append(f"total {counts['n']} < {quotas['min_total']}")
    if counts["sensitive_share"] < quotas["min_sensitive_share"]:
        problems.append(f"sensitive share {counts['sensitive_share']:.3f} < {quotas['min_sensitive_share']}")
    for category in schema.CATEGORIES:
        if counts["by_category"][category] < quotas["min_per_category"]:
            problems.append(f"category {category} has {counts['by_category'][category]} < {quotas['min_per_category']}")
    return problems


def source_texts(path, max_bytes):
    """Yield every string of at least three tokens from one prompt-bearing file."""
    suffix = path.suffix.lower()

    def walk(node):
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for value in node.values():
                yield from walk(value)
        elif isinstance(node, list):
            for value in node:
                yield from walk(value)

    try:
        if path.stat().st_size > max_bytes:
            return
        if suffix == ".jsonl":
            with path.open(encoding="utf8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        try:
                            yield from walk(json.loads(line))
                        except ValueError:
                            yield line
        elif suffix == ".json":
            try:
                yield from walk(json.loads(path.read_text(encoding="utf8", errors="replace")))
            except ValueError:
                return
        elif suffix == ".csv":
            with path.open(newline="", encoding="utf8", errors="replace") as handle:
                for record in csv.reader(handle):
                    yield from record
        else:
            for paragraph in re.split(r"\n\s*\n", path.read_text(encoding="utf8", errors="replace")):
                yield paragraph
    except OSError:
        return


def source_files(root, excluded):
    root = Path(root)
    if root.is_file():
        yield root
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not (Path(current) == root and d.lower().startswith("s13")))
        for name in sorted(files):
            file = Path(current) / name
            if file.suffix.lower() in TEXT_SUFFIXES and file.resolve() not in excluded:
                yield file


def default_sources():
    return {"datasets": REPO_ROOT / "evaluation" / "datasets",
            "results": MAIN_CHECKOUT / "evaluation" / "results"}


def resolve_sources(extra, no_defaults=False):
    """The defaults plus every --source LABEL=PATH (a repeated label replaces its default)."""
    if no_defaults and not s13_paths.under_tests():
        raise SystemExit("--no-default-sources is only allowed under tests")
    sources = {} if no_defaults else default_sources()
    for spec in extra or []:
        label, _, path = spec.partition("=")
        if not path:
            raise SystemExit("--source expects LABEL=PATH")
        sources[label] = Path(path)
    return sources


def contamination_scan(rows, sources, excluded=frozenset(), max_bytes=256 * 1024 * 1024, threshold=NEAR_JACCARD):
    """Return ({id: reason}, sources_checked). Reasons are 'exact' or 'near'; exact wins."""
    by_text = {}
    item_grams = {}
    indices = defaultdict(lambda: defaultdict(set))  # n -> gram -> item ids
    for row in rows:
        toks = tokens(row["text"])
        by_text.setdefault(" ".join(toks), []).append(row["id"])
        n = min(NGRAM, len(toks))
        if n < MIN_NGRAM_TOKENS:
            item_grams[row["id"]] = 0  # too short for n-gram rules: exact matches only
            continue
        grams = {hash(tuple(toks[i:i + n])) for i in range(len(toks) - n + 1)}
        item_grams[row["id"]] = len(grams)
        for g in grams:
            indices[n][g].add(row["id"])
    flagged, checked = {}, []
    for label, root in sources.items():
        files = texts = skipped = 0
        for file in source_files(root, excluded):
            if file.stat().st_size > max_bytes:
                skipped += 1
                continue
            files += 1
            for text in source_texts(file, max_bytes):
                toks = tokens(text)
                if len(toks) < 3:
                    continue
                texts += 1
                for item in by_text.get(" ".join(toks), ()):
                    flagged[item] = "exact"
                for n, index in indices.items():
                    if len(toks) < n:
                        continue
                    grams = {hash(tuple(toks[i:i + n])) for i in range(len(toks) - n + 1)}
                    hits = Counter(item for g in grams for item in index.get(g, ()))
                    for item, shared in hits.items():
                        contained = shared / item_grams[item] >= threshold
                        jaccard = n == NGRAM and shared / (item_grams[item] + len(grams) - shared) >= threshold
                        if contained or jaccard:
                            flagged.setdefault(item, "near")
        checked.append({"source": label, "path": str(root), "files": files, "texts": texts, "skipped_large_files": skipped})
    return flagged, checked


def freeze(args):
    rows, problems = read_raw(args.input)
    if problems:
        raise SystemExit("raw input is invalid (%d problems): %s" % (len(problems), "; ".join(problems[:20])))
    raw_n = len(rows)
    rows = deduplicate(rows)
    for row in rows:
        row["id"] = opaque_id(row["text"], args.id_salt)
        row["quota_cell"] = f"{row['category']}/{row['audience']}/{row['sensitive']}"
    patterns = sampler.marker_patterns(args.marker_pattern)
    marker_ids = {r["id"] for r in rows if any(p.search(r["text"]) for p in patterns)}
    sources = resolve_sources(args.source, getattr(args, "no_default_sources", False))
    missing = [k for k, v in sources.items() if not Path(v).exists()]
    if missing and not args.dry_run:
        raise SystemExit("contamination sources are missing: " + ",".join(missing))
    present = {k: v for k, v in sources.items() if k not in missing}
    excluded = {f.resolve() for f in raw_files(args.input)}
    flagged, checked = contamination_scan(rows, present, excluded)
    empty = [c["source"] for c in checked if c["files"] == 0]
    if empty and not args.dry_run:
        raise SystemExit("contamination sources hold no scanned file: " + ",".join(empty))
    removed = {**{i: "marker" for i in marker_ids}, **flagged}
    kept = [r for r in rows if r["id"] not in removed]
    counts = quota_counts(kept)
    violations = quota_violations(counts)
    reasons = Counter(removed.values())
    manifest = {
        "schema": SCHEMA, "n": len(kept), "sha256_jsonl": None, "source_kind": args.source_kind,
        "raw_rows": raw_n, "duplicates_removed": raw_n - len(rows),
        "contamination": {"sources_checked": checked, "sources_missing": missing, "exact": reasons["exact"],
                          "near": reasons["near"], "marker": reasons["marker"], "removed_ids": sorted(removed)},
        "quota_counts": counts, "quotas": QUOTAS, "quota_violations": violations,
    }
    if not args.dry_run:
        if not args.out:
            raise SystemExit("--out is required for a real freeze")
        out = s13_paths.require_under(args.out, s13_paths.results_root(), "--out")
        if args.check_quotas and violations:
            raise SystemExit("quotas unmet; nothing was written: " + "; ".join(violations))
        out.mkdir(parents=True, exist_ok=True)
        frozen = sorted(kept, key=lambda r: r["id"])
        schema.write_jsonl(out / "frozen_set.jsonl", [{k: r[k] for k in ("id", "text", "category", "audience", "sensitive", "quota_cell")} for r in frozen])
        manifest["sha256_jsonl"] = hashlib.sha256((out / "frozen_set.jsonl").read_bytes()).hexdigest()
        (out / "set_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf8")
    return manifest


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--input", required=True, help="raw prompts: a JSONL/CSV file or a directory of them")
    p.add_argument("--out", help="output directory under the main checkout's evaluation/results/s13a/")
    p.add_argument("--dry-run", action="store_true", help="report counts only; write nothing")
    p.add_argument("--check-quotas", action="store_true", help="exit 1 when the brief's quotas are unmet")
    p.add_argument("--source-kind", choices=SOURCE_KINDS, default="writers")
    p.add_argument("--source", action="append", metavar="LABEL=PATH",
                   help="extra contamination source (repeatable); added to the defaults")
    p.add_argument("--no-default-sources", action="store_true", help="tests only (refused in a real run)")
    p.add_argument("--marker-pattern", action="append", default=[], metavar="REGEX")
    p.add_argument("--id-salt", default="s13a-fresh-set")
    args = p.parse_args(argv)
    manifest = freeze(args)
    summary = {"n": manifest["n"], "raw_rows": manifest["raw_rows"], "duplicates_removed": manifest["duplicates_removed"],
               "exact": manifest["contamination"]["exact"], "near": manifest["contamination"]["near"],
               "marker": manifest["contamination"]["marker"], "sources_missing": manifest["contamination"]["sources_missing"],
               "quota_counts": {k: v for k, v in manifest["quota_counts"].items() if k != "cells"},
               "quota_violations": manifest["quota_violations"], "quotas_met": not manifest["quota_violations"],
               "dry_run": args.dry_run, "sha256_jsonl": manifest["sha256_jsonl"]}
    print(json.dumps(summary, sort_keys=True))
    if args.check_quotas and manifest["quota_violations"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
