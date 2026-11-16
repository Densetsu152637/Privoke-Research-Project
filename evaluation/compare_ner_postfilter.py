"""Detector-layer comparison of the NER post-filter (regex and NER layers only).

Not LLM or semantic evidence: every prompt goes through
``pipeline.analyse_text(layers=["regex", "ner"], regex_first=False)`` with an explicit
layer list (never empty, never the semantic layer). Four configurations are run per split:
lowercase (default), case-preserving, case-preserving + postfilter, lowercase + postfilter.

Splits: ``tune`` / ``check`` are the two halves of ``development.jsonl`` selected by
``sha256(group_id) % 2``; ``personalized`` and ``openai`` are the synthetic sets. The script
refuses to read any path named like ``final``.

Host Python only (spaCy ``en_core_web_sm``; protobuf client directory on ``--generated``)::

    python evaluation/compare_ner_postfilter.py tune check personalized openai \
        --data-root <checkout holding the datasets> --generated <dir> --out out_dir

``--ablation`` additionally switches single postfilter rules off in the case-preserving
configuration (stage-1 rules inside a span-only configuration, combination rules inside the
full one) and prints FP/TP deltas. Output: ``<out>/<split>.json`` plus Markdown tables on stdout.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LAYERS = ["regex", "ner"]
CONFIGS = {
    "lowercase": (False, False),
    "case-preserving": (True, False),
    "case-preserving + postfilter": (True, True),
    "lowercase + postfilter": (False, True),
}
SPLIT_FILES = {
    "tune": "evaluation/results/locked-public/development.jsonl",
    "check": "evaluation/results/locked-public/development.jsonl",
    "personalized": "evaluation/datasets/privoke_personalized_synthetic.jsonl",
    "openai": "evaluation/datasets/privoke_openai_synthetic.jsonl",
}
NER_LABELS = ("PERSON", "ORG", "GPE", "LOC", "FAC")


def load_rows(split: str, data_root: Path) -> list[dict]:
    path = data_root / SPLIT_FILES[split]
    if "final" in path.name.lower():
        raise SystemExit(f"refusing to read {path}")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if split in ("tune", "check"):
        wanted = 0 if split == "tune" else 1
        rows = [r for r in rows if int(hashlib.sha256(r["group_id"].encode()).hexdigest(), 16) % 2 == wanted]
    return rows


def confusion(rows, predictions) -> collections.Counter:
    c = collections.Counter()
    for row, predicted in zip(rows, predictions):
        expected = bool(row["expected_has_pii"])
        c[("TP" if predicted else "FN") if expected else ("FP" if predicted else "TN")] += 1
    return c


def cells(c: collections.Counter) -> str:
    tp, tn, fp, fn = (c[k] for k in ("TP", "TN", "FP", "FN"))
    return f"{tp} | {tn} | {fp} | {fn} | {tp / max(tp + fn, 1):.3f} | {tn / max(tn + fp, 1):.3f}"


def hit(result) -> dict:
    md = result.metadata or {}
    positive = result.classification.sensitivity().name != "S0" or bool(result.classification.categories())
    return {
        "label": md.get("rule_name") or md.get("label") or "?",
        "text": result.section_of_text[:60],
        "sens": result.classification.sensitivity().name,
        "positive": positive,
        "rule": md.get("postfilter_rule"),
    }


def run_split(split, rows, pipeline, config) -> dict:
    out = {"ids": [r["id"] for r in rows], "expected": [bool(r["expected_has_pii"]) for r in rows], "ms": {}}
    for name, (case, postfilter) in CONFIGS.items():
        config.case_preserving_detectors, config.ner_postfilter = case, postfilter
        pipeline.analyse_text("warm up Alice", layers=LAYERS, regex_first=False)
        started, per_row = time.perf_counter(), []
        for row in rows:
            analysis = pipeline.analyse_text(row["text"], layers=LAYERS, regex_first=False)
            assert [l.layer for l in analysis.layers] == LAYERS and all(l.status == "ok" for l in analysis.layers), (
                [(l.layer, l.status, l.error) for l in analysis.layers]
            )
            per_row.append({l.layer: [hit(h) for h in l.results] for l in analysis.layers})
        out["ms"][name] = (time.perf_counter() - started) * 1000 / len(rows)
        out[name] = per_row
        print(f"{split} {name}: {out['ms'][name]:.1f} ms/prompt", file=sys.stderr)
    return out


def tables(results: dict[str, dict]) -> str:
    lines = []
    for part, title in (("ner", "NER layer only"), ("union", "regex + NER union")):
        lines += [f"\n**{title}**\n", "| Split | n (pos) | Config | TP | TN | FP | FN | Recall | Specificity |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for split, res in results.items():
            expected = [{"expected_has_pii": e} for e in res["expected"]]
            for name in CONFIGS:
                ner = [any(h["positive"] for h in row["ner"]) for row in res[name]]
                predicted = ner if part == "ner" else [
                    n or any(h["positive"] for h in row["regex"]) for n, row in zip(ner, res[name])
                ]
                lines.append(f"| {split} | {len(expected)} ({sum(res['expected'])}) | {name} | "
                             f"{cells(confusion(expected, predicted))} |")
    lines += ["\n**NER entities by label**\n", "| Split | Config | " + " | ".join(NER_LABELS) + " |",
              "|---|---|" + "---|" * len(NER_LABELS)]
    for split, res in results.items():
        for name in CONFIGS:
            counts = collections.Counter(h["label"] for row in res[name] for h in row["ner"])
            lines.append(f"| {split} | {name} | " + " | ".join(str(counts[l]) for l in NER_LABELS) + " |")
    return "\n".join(lines)


def ablation(split, rows, nlp, pipeline, config, ner_postfilter) -> str:
    """Per-rule FP/TP deltas on case-preserved text, computed from spaCy docs directly."""
    from src.detection.preprocessing import normalize_with_offsets

    config.case_preserving_detectors, config.ner_postfilter = True, False
    regex_positive = []
    for row in rows:
        analysis = pipeline.analyse_text(row["text"], layers=["regex"], regex_first=False)
        regex_positive.append(any(hit(h)["positive"] for h in analysis.layers[0].results))
    docs = list(nlp.pipe([normalize_with_offsets(r["text"], lowercase=False).text for r in rows], batch_size=32))
    labels = {"PERSON", "GPE", "LOC", "FAC", "ORG"}
    span_rules = [name for name, _ in ner_postfilter.SPAN_RULES]
    combination_rules = [r.name for r in ner_postfilter.COMBINATION_RULES]

    def confs(disabled=None):
        ner_pred = []
        for doc in docs:
            ents = [e for e in doc.ents if e.label_ in labels]
            if disabled is None:
                ner_pred.append(bool(ents))
            else:
                decisions = ner_postfilter.postfilter(doc, ents, nlp=nlp, disabled=disabled)
                ner_pred.append(any(d.keep for d in decisions))
        return confusion(rows, ner_pred), confusion(rows, [n or r for n, r in zip(ner_pred, regex_positive)])

    full, full_u = confs(())
    span_only, span_only_u = confs(combination_rules)
    out = [f"\n**Ablation, {split} (case-preserving; delta when the rule is switched off)**\n",
           "| Rule | NER dFP | NER dTP | union dFP | union dTP |", "|---|---|---|---|---|"]

    def row(name, ref, ref_u, disabled):
        c, cu = confs(disabled)
        out.append(f"| -{name} | {c['FP'] - ref['FP']:+d} | {c['TP'] - ref['TP']:+d} | "
                   f"{cu['FP'] - ref_u['FP']:+d} | {cu['TP'] - ref_u['TP']:+d} |")

    for name in span_rules:
        row(name, span_only, span_only_u, combination_rules + [name])
    for name in combination_rules:
        row(name, full, full_u, [name])
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("splits", nargs="+", choices=sorted(SPLIT_FILES))
    parser.add_argument("--data-root", type=Path, default=REPO, help="checkout containing the dataset files")
    parser.add_argument("--generated", type=Path, help="directory with the generated protobuf clients")
    parser.add_argument("--out", type=Path, default=Path("ner-postfilter-results"))
    parser.add_argument("--ablation", action="store_true")
    args = parser.parse_args()

    paths = [REPO / "extension/client-runtime", REPO / "shared/python"]
    if args.generated:
        paths.append(args.generated)
    sys.path[:0] = [str(p) for p in paths]

    import spacy  # noqa: F401  pre-import in the main thread (layer threads race on first import)
    from src import pipeline
    from src.NER import EntityNERDetector, ner_postfilter
    from src.regex.rule_detector import RuleDetector
    from src.config import GLOBAL_CONFIG

    RuleDetector()
    nlp = EntityNERDetector().nlp
    args.out.mkdir(parents=True, exist_ok=True)
    results, extra = {}, []
    for split in args.splits:
        rows = load_rows(split, args.data_root)
        results[split] = run_split(split, rows, pipeline, GLOBAL_CONFIG)
        (args.out / f"{split}.json").write_text(json.dumps(results[split]), encoding="utf-8")
        if args.ablation:
            extra.append(ablation(split, rows, nlp, pipeline, GLOBAL_CONFIG, ner_postfilter))
    print(tables(results))
    print("\n".join(extra))


if __name__ == "__main__":
    main()
