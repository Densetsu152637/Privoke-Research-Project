"""Detector-layer evaluation of one source tree's shipped (default) configuration.

Detector layers only: every prompt goes through
``pipeline.analyse_text(layers=["regex", "ner"], regex_first=False)`` with an explicit
layer list (never empty, never semantic). This is NOT LLM-only evidence. The runtime
configuration is left at the tree's own defaults (no flag is set here); the script records
the flag values it observed. Positive = any hit with sensitivity != S0 or with categories.

Reports regex-only, NER-only and union (regex OR NER) TP/TN/FP/FN, recall, specificity and
mean ms/prompt per split. ``dev`` is the whole development file; ``tune``/``check`` are its
halves by ``sha256(group_id) % 2`` (same definition as compare_ner_postfilter.py), computed
from the same pass.

A ``<out>/<label>.final-scored`` marker is written after a final run; a later final run
with the same ``--out`` and ``--label`` is refused while it exists.
``final`` (the locked held-out file) is refused unless ``--allow-final-once`` is given. For
``final`` only aggregate counts and timing are written: no text, id or per-row outcome is
stored or printed.

    python evaluation/evaluate_installed_detectors.py --tree <source root> --label new \
        --data-root <checkout holding datasets> --generated <protobuf dir> --out <dir> \
        dev personalized openai
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
import time
from pathlib import Path

LAYERS = ["regex", "ner"]
SPLIT_FILES = {
    "dev": "evaluation/results/locked-public/development.jsonl",
    "personalized": "evaluation/datasets/privoke_personalized_synthetic.jsonl",
    "openai": "evaluation/datasets/privoke_openai_synthetic.jsonl",
    "final": "evaluation/results/locked-public/final.jsonl",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def positive(result) -> bool:
    return result.classification.sensitivity().name != "S0" or bool(result.classification.categories())


def _sens_value(result) -> int:
    return result.classification.sensitivity().value


def layer_row(results, strongest_result) -> dict:
    """Per-layer record: positive flag, max sensitivity, categories and the runtime policy action."""
    results = tuple(results)
    names = sorted({c.name for h in results for c in h.classification.categories()})
    top = max(results, key=_sens_value).classification.sensitivity().name if results else "S0"
    return {"positive": any(positive(h) for h in results), "max_sensitivity": top, "categories": names,
            "action": strongest_result(results)[1].name}


def union_row(regex_row: dict, ner_row: dict, analysis) -> dict:
    sens = max((regex_row["max_sensitivity"], ner_row["max_sensitivity"]), key=lambda n: int(n[1:]))
    return {"positive": regex_row["positive"] or ner_row["positive"], "max_sensitivity": sens,
            "categories": sorted(set(regex_row["categories"]) | set(ner_row["categories"])),
            "action": analysis.action.name}


def row_identity(row: dict, split: str) -> tuple[str, str | None]:
    example_id = str(row.get("example_id") or row["id"])
    group_id = row.get("group_id")
    if split == "final":
        example_id = hashlib.sha256(example_id.encode()).hexdigest()[:16]
        group_id = hashlib.sha256(str(group_id).encode()).hexdigest()[:16] if group_id is not None else None
    return example_id, group_id


def confusion(expected, predicted) -> dict:
    c = collections.Counter()
    for e, p in zip(expected, predicted):
        c[("TP" if p else "FN") if e else ("FP" if p else "TN")] += 1
    tp, tn, fp, fn = (c[k] for k in ("TP", "TN", "FP", "FN"))
    return {"TP": tp, "TN": tn, "FP": fp, "FN": fn, "recall": tp / max(tp + fn, 1),
            "specificity": tn / max(tn + fp, 1)}


def summarise(expected, regex, ner, ms) -> dict:
    union = [a or b for a, b in zip(regex, ner)]
    return {"n": len(expected), "positives": sum(expected),
            "regex": confusion(expected, regex), "ner": confusion(expected, ner),
            "union": confusion(expected, union), "mean_ms_per_prompt": sum(ms) / max(len(ms), 1)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("splits", nargs="+", choices=sorted(SPLIT_FILES))
    parser.add_argument("--tree", type=Path, required=True, help="root holding extension/client-runtime and shared/python")
    parser.add_argument("--label", required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--per-row-dir", type=Path, default=None,
                        help="also write per-row JSONL (see module doc); aggregates are unchanged")
    parser.add_argument("--allow-final-once", action="store_true",
                        help="permit the single locked held-out run; writes aggregates only")
    args = parser.parse_args()
    if "final" in args.splits and not args.allow_final_once:
        raise SystemExit("refusing the locked held-out file without --allow-final-once")
    marker = args.out / f"{args.label}.final-scored"
    if "final" in args.splits and marker.exists():
        raise SystemExit(f"refusing: {marker} exists, the held-out file was already scored for this label/output")

    sys.path[:0] = [str(args.tree / "extension/client-runtime"), str(args.tree / "shared/python"), str(args.generated)]
    import spacy  # noqa: F401  pre-import in the main thread (layer threads race on first import)
    from src import pipeline
    from src.config import GLOBAL_CONFIG
    from src.NER import EntityNERDetector
    from src.regex.rule_detector import RuleDetector

    RuleDetector()
    EntityNERDetector()
    args.out.mkdir(parents=True, exist_ok=True)
    flags = {"case_preserving_detectors": getattr(GLOBAL_CONFIG, "case_preserving_detectors", "absent"),
             "ner_postfilter": getattr(GLOBAL_CONFIG, "ner_postfilter", "absent")}
    import subprocess
    sha = subprocess.run(["git", "-C", str(args.tree), "rev-parse", "HEAD"], capture_output=True, text=True)
    tree_sha = sha.stdout.strip() if sha.returncode == 0 else "not-a-git-checkout (record the export's base SHA manually)"
    report = {"label": args.label, "tree": str(args.tree), "tree_commit_sha": tree_sha, "layers": LAYERS, "regex_first": False,
              "observed_flags": flags, "scope": "detector-layer (regex+NER); not LLM-only", "splits": {}}
    pipeline.analyse_text("warm up Alice Smith", layers=LAYERS, regex_first=False)
    for split in args.splits:
        path = args.data_root / SPLIT_FILES[split]
        report.setdefault("dataset_sha256", {})[split] = sha256_file(path)
        rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        expected = [bool(r["expected_has_pii"]) for r in rows]
        regex, ner, ms, per_row = [], [], [], []
        for row in rows:
            started = time.perf_counter()
            analysis = pipeline.analyse_text(row["text"], layers=LAYERS, regex_first=False)
            ms.append((time.perf_counter() - started) * 1000)
            if [l.layer for l in analysis.layers] != LAYERS or any(l.status != "ok" for l in analysis.layers):
                raise RuntimeError(f"unexpected layer execution: {[(l.layer, l.status, l.error) for l in analysis.layers]}")
            by_layer = {l.layer: any(positive(h) for h in l.results) for l in analysis.layers}
            regex.append(by_layer["regex"])
            ner.append(by_layer["ner"])
            if args.per_row_dir is not None:
                layer_rows = {l.layer: layer_row(l.results, pipeline.strongest_result) for l in analysis.layers}
                example_id, group_id = row_identity(row, split)
                record = {"split": split, "example_id": example_id, "group_id": group_id,
                          "stratum": row.get("scenario") or row.get("task_name"),
                          "expected_has_pii": bool(row["expected_has_pii"]),
                          "regex": layer_rows["regex"], "ner": layer_rows["ner"],
                          "union": union_row(layer_rows["regex"], layer_rows["ner"], analysis)}
                if split == "dev":
                    record["half"] = "check" if int(hashlib.sha256(row["group_id"].encode()).hexdigest(), 16) % 2 else "tune"
                per_row.append(record)
        out = {"all": summarise(expected, regex, ner, ms)}
        if split == "dev":
            for half, wanted in (("tune", 0), ("check", 1)):
                idx = [i for i, r in enumerate(rows)
                       if int(hashlib.sha256(r["group_id"].encode()).hexdigest(), 16) % 2 == wanted]
                out[half] = summarise([expected[i] for i in idx], [regex[i] for i in idx],
                                      [ner[i] for i in idx], [ms[i] for i in idx])
        report["splits"][split] = out
        if args.per_row_dir is not None:
            args.per_row_dir.mkdir(parents=True, exist_ok=True)
            (args.per_row_dir / f"{args.label}-{split}.rows.jsonl").write_text(
                "".join(json.dumps(r, sort_keys=True) + chr(10) for r in per_row), encoding="utf-8")
        print(f"[{args.label}] {split}: n={len(rows)}", file=sys.stderr)
    if "final" in args.splits:
        marker.write_text("scored\n", encoding="utf-8")
    (args.out / f"{args.label}-{'-'.join(args.splits)}.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
