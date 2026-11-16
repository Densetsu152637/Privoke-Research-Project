"""NER model-candidate study: spaCy sm/lg/trf and GLiNER PII small, with and without the post-filter.

Scope: DETECTOR LAYERS ONLY (regex + NER). Every prompt goes through
``pipeline.analyse_text(layers=["regex", "ner"], regex_first=False)`` with an explicit layer list
(never empty, never semantic). This is NOT LLM-only or semantic evidence and NOT a full-product
measurement. The locked held-out ``final`` file is not selectable here. Latencies are rough,
contended-machine CPU numbers, labelled non-final; real timing is a separate serialized step.

Protocol (anti-overfitting; enforced by the sub-commands):

* ``run --phase design``       reads dev-TUNE rows (sha256(group_id) % 2 == 0) and ``personalized``
                               ONLY. The post-review splits (dev-CHECK, ``openai``) are never loaded.
* ``select``                   picks the GLiNER configuration (label preset x threshold x post-filter)
                               on the design splits by mean union balanced accuracy over
                               (tune, personalized), ties by fewer design false positives, and writes
                               a freeze file. Commit it before the next step.
* ``run --phase post-review``  requires the freeze file to be committed and unmodified; evaluates dev-CHECK
                               and ``openai`` for the frozen GLiNER configuration and all spaCy models.
* ``stats``                    paired exact McNemar + grouped bootstrap versus the shipped spaCy
                               ``sm`` + post-filter configuration, using ``detector_stats.py``.

    python evaluation/ner_model_study.py run --phase design --tree <root> --data-root <checkout> \
        --generated <protobuf dir> --out <dir> --gliner-dir <weights dir> --cache <file> --configs ...
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

LAYERS = ["regex", "ner"]
SPLIT_FILES = {
    "dev": "evaluation/results/locked-public/development.jsonl",
    "personalized": "evaluation/datasets/privoke_personalized_synthetic.jsonl",
    "openai": "evaluation/datasets/privoke_openai_synthetic.jsonl",
}
GLINER_FLOOR = 0.3
GLINER_THRESHOLDS = (0.3, 0.4, 0.5, 0.6, 0.7)
GLINER_PRESETS = ("core", "pii")
DESIGN_SPLITS = ("tune", "personalized")
POST_REVIEW_SPLITS = ("check", "openai")
PHASE_SPLITS = {"design": DESIGN_SPLITS, "post-review": POST_REVIEW_SPLITS}
BASELINE = "sm-pf1"


# ----------------------------------------------------------------------------- configurations

def spacy_config(model: str, postfilter: bool) -> dict:
    return {"backend": "spacy", "model": model, "postfilter": postfilter}


def gliner_config(preset: str, threshold: float, postfilter: bool) -> dict:
    return {"backend": "gliner", "preset": preset, "threshold": threshold, "postfilter": postfilter}


def config_label(cfg: dict) -> str:
    pf = f"pf{int(cfg['postfilter'])}"
    if cfg["backend"] == "spacy":
        return f"{cfg['model'].replace('en_core_web_', '')}-{pf}"
    return f"gliner-{cfg['preset']}-t{cfg['threshold']:.1f}-{pf}"


def parse_label(label: str) -> dict:
    parts = label.split("-")
    postfilter = parts[-1] == "pf1"
    if parts[0] == "gliner":
        return gliner_config(parts[1], float(parts[2][1:]), postfilter)
    return spacy_config("en_core_web_" + parts[0], postfilter)


def all_design_labels() -> list[str]:
    labels = [config_label(spacy_config(f"en_core_web_{m}", pf)) for m in ("sm", "lg", "trf") for pf in (True, False)]
    labels += [config_label(gliner_config(p, t, pf)) for p in GLINER_PRESETS for t in GLINER_THRESHOLDS
               for pf in (True, False)]
    return labels


# ----------------------------------------------------------------------------- pure helpers

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dev_half(group_id: str) -> str:
    return "check" if int(hashlib.sha256(group_id.encode()).hexdigest(), 16) % 2 else "tune"


def confusion(expected, predicted) -> dict:
    tp = sum(1 for e, p in zip(expected, predicted) if e and p)
    fn = sum(1 for e, p in zip(expected, predicted) if e and not p)
    fp = sum(1 for e, p in zip(expected, predicted) if not e and p)
    tn = sum(1 for e, p in zip(expected, predicted) if not e and not p)
    recall = tp / (tp + fn) if tp + fn else None
    spec = tn / (tn + fp) if tn + fp else None
    return {"TP": tp, "TN": tn, "FP": fp, "FN": fn, "recall": recall, "specificity": spec}


def balanced_accuracy(cell: dict) -> float:
    return (cell["recall"] + cell["specificity"]) / 2


def select_gliner(design: dict[str, dict[str, dict]]) -> dict:
    """Pick the GLiNER configuration on the design splits only.

    ``design[label][split]`` is the ``union`` confusion cell (positive rule) of that split.
    Criterion: highest mean union balanced accuracy over the design splits; ties by fewer total
    design false positives, then by label for determinism.
    """
    scored = []
    for label, cells in design.items():
        if not label.startswith("gliner-"):
            continue
        splits = [cells[s] for s in DESIGN_SPLITS]
        mean_ba = sum(balanced_accuracy(c) for c in splits) / len(splits)
        fp = sum(c["FP"] for c in splits)
        scored.append((-mean_ba, fp, label, mean_ba))
    if not scored:
        raise ValueError("no GLiNER configurations in the design results")
    scored.sort()
    best = scored[0]
    twin = best[2][:-1] + ("0" if best[2].endswith("1") else "1")
    return {"chosen": best[2], "post_review_labels": [best[2], twin], "mean_union_balanced_accuracy": best[3],
            "ranking": [{"label": s[2], "mean_union_balanced_accuracy": s[3], "design_fp": s[1]} for s in scored]}


# ----------------------------------------------------------------------------- GLiNER cache

class CachingGliner:
    """Wraps a GLiNER model: runs it once per (text, labels) at the floor threshold and answers
    higher thresholds by filtering. Equivalent to running at the higher threshold because the
    decoder drops sub-threshold spans before its greedy non-overlap selection, and a span that
    suppresses another always scores at least as high as the span it suppresses."""

    def __init__(self, inner, path: Path | None, floor: float = GLINER_FLOOR):
        self.inner = inner
        self.floor = floor
        self.path = path
        self.memory: dict[str, list] = {}
        self.seconds: list[float] = []
        if path is not None and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    record = json.loads(line)
                    self.memory[record["key"]] = record["entities"]

    @staticmethod
    def key(text: str, labels) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest() + "|" + "|".join(labels)

    def predict_entities(self, text, labels, threshold=0.5, **kwargs):
        if threshold < self.floor:
            raise ValueError(f"threshold {threshold} is below the cache floor {self.floor}")
        key = self.key(text, labels)
        if key not in self.memory:
            started = time.perf_counter()
            entities = self.inner.predict_entities(text, list(labels), threshold=self.floor, **kwargs)
            self.seconds.append(time.perf_counter() - started)
            self.memory[key] = [{k: e[k] for k in ("start", "end", "label", "score")} | {"text": e["text"]}
                                for e in entities]
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"key": key, "entities": self.memory[key]}) + "\n")
        return [dict(e) for e in self.memory[key] if e["score"] >= threshold]


# ----------------------------------------------------------------------------- pipeline driver

def positive(result) -> bool:
    return result.classification.sensitivity().name != "S0" or bool(result.classification.categories())


def layer_row(results, strongest_result) -> dict:
    results = tuple(results)
    names = sorted({c.name for h in results for c in h.classification.categories()})
    top = max((h.classification.sensitivity().value for h in results), default=0)
    return {"positive": any(positive(h) for h in results), "max_sensitivity": f"S{top}", "categories": names,
            "action": strongest_result(results)[1].name}


def union_row(regex_row: dict, ner_row: dict, analysis) -> dict:
    sens = max((regex_row["max_sensitivity"], ner_row["max_sensitivity"]), key=lambda n: int(n[1:]))
    return {"positive": regex_row["positive"] or ner_row["positive"], "max_sensitivity": sens,
            "categories": sorted(set(regex_row["categories"]) | set(ner_row["categories"])),
            "action": analysis.action.name}


def load_split_rows(split: str, data_root: Path, phase: str) -> tuple[list[dict], str]:
    """Rows of a report split. ``tune``/``check`` are halves of dev; only phase-allowed splits load."""
    if split not in PHASE_SPLITS[phase]:
        raise SystemExit(f"split {split!r} is not allowed in phase {phase!r}")
    source = "dev" if split in ("tune", "check") else split
    path = data_root / SPLIT_FILES[source]
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if source == "dev":
        rows = [r for r in rows if dev_half(r["group_id"]) == split]
    return rows, sha256_file(path)


def apply_config(global_config, cfg: dict, gliner_dir: str | None) -> None:
    global_config.ner_postfilter = cfg["postfilter"]
    if cfg["backend"] == "spacy":
        global_config.ner_backend = "spacy"
        global_config.ner_model = cfg["model"]
    else:
        global_config.ner_backend = "gliner"
        global_config.ner_model = "en_core_web_sm"
        global_config.ner_gliner_model = gliner_dir
        global_config.ner_gliner_labels = cfg["preset"]
        global_config.ner_gliner_threshold = cfg["threshold"]


def run_config(pipeline, cfg: dict, rows: list[dict], split: str) -> tuple[list[dict], float]:
    records, started_all = [], time.perf_counter()
    for row in rows:
        started = time.perf_counter()
        analysis = pipeline.analyse_text(row["text"], layers=LAYERS, regex_first=False)
        ms = (time.perf_counter() - started) * 1000
        if [l.layer for l in analysis.layers] != LAYERS or any(l.status != "ok" for l in analysis.layers):
            raise RuntimeError(f"unexpected layer execution: {[(l.layer, l.status, l.error) for l in analysis.layers]}")
        rows_by_layer = {l.layer: layer_row(l.results, pipeline.strongest_result) for l in analysis.layers}
        record = {"split": split, "example_id": str(row.get("example_id") or row["id"]), "group_id": row.get("group_id"),
                  "stratum": row.get("scenario") or row.get("task_name"),
                  "expected_has_pii": bool(row["expected_has_pii"]),
                  "regex": rows_by_layer["regex"], "ner": rows_by_layer["ner"],
                  "union": union_row(rows_by_layer["regex"], rows_by_layer["ner"], analysis), "ms": round(ms, 2)}
        if split in ("tune", "check"):
            record["half"] = split
        records.append(record)
    return records, (time.perf_counter() - started_all) * 1000 / max(len(rows), 1)


def summarise(records: list[dict]) -> dict:
    expected = [r["expected_has_pii"] for r in records]
    out = {"n": len(records), "positives": sum(expected),
           "mean_ms_per_prompt_indicative": sum(r["ms"] for r in records) / max(len(records), 1)}
    for layer in ("regex", "ner", "union"):
        out[layer] = {"positive": confusion(expected, [r[layer]["positive"] for r in records]),
                      "block": confusion(expected, [r[layer]["action"] == "BLOCK" for r in records])}
    return out


# ----------------------------------------------------------------------------- freeze guard

def require_committed(freeze_path: Path, tree: Path) -> str:
    rel = freeze_path.resolve().relative_to(tree.resolve())
    tracked = subprocess.run(["git", "-C", str(tree), "ls-files", "--error-unmatch", str(rel)], capture_output=True)
    dirty = subprocess.run(["git", "-C", str(tree), "status", "--porcelain", "--", str(rel)],
                           capture_output=True, text=True).stdout.strip()
    if tracked.returncode != 0 or dirty:
        raise SystemExit(f"refusing post-review run: {rel} must be committed and unmodified (freeze before check/openai)")
    return subprocess.run(["git", "-C", str(tree), "log", "-1", "--format=%H", "--", str(rel)],
                          capture_output=True, text=True).stdout.strip()


# ----------------------------------------------------------------------------- commands

def cmd_run(args) -> None:
    phase = args.phase
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    labels = args.configs
    freeze_commit = None
    if phase == "post-review":
        if args.freeze is None:
            raise SystemExit("post-review requires --freeze")
        freeze_commit = require_committed(args.freeze, args.tree)
        frozen = json.loads(args.freeze.read_text(encoding="utf-8"))["post_review_labels"]
        allowed = {l for l in all_design_labels() if not l.startswith("gliner-")} | set(frozen)
        extra = [l for l in labels if l not in allowed]
        if extra:
            raise SystemExit(f"post-review may only run spaCy configurations and the frozen GLiNER ones ({frozen}); got {extra}")
    for label in labels:
        parse_label(label)

    sys.path[:0] = [str(args.tree / "extension/client-runtime"), str(args.tree / "shared/python"), str(args.generated)]
    import spacy  # noqa: F401  pre-import in the main thread
    from src import pipeline
    from src.config import GLOBAL_CONFIG
    from src.NER import gliner_detector
    from src.regex.rule_detector import RuleDetector

    RuleDetector()
    caching = None
    if any(l.startswith("gliner-") for l in labels):
        from gliner import GLiNER

        inner = GLiNER.from_pretrained(str(args.gliner_dir), local_files_only=True)
        caching = CachingGliner(inner, args.cache)
        gliner_detector._GLINER_MODELS[str(args.gliner_dir)] = gliner_detector._GlinerEntry(
            caching, __import__("threading").Lock())
    split_rows, dataset_hash = {}, {}
    for split in PHASE_SPLITS[phase]:
        split_rows[split], dataset_hash[split] = load_split_rows(split, args.data_root, phase)
    sha = subprocess.run(["git", "-C", str(args.tree), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    for label in labels:
        cfg = parse_label(label)
        apply_config(GLOBAL_CONFIG, cfg, str(args.gliner_dir) if args.gliner_dir else None)
        pipeline.analyse_text("warm up Alice Smith", layers=LAYERS, regex_first=False)
        report = {"label": label, "config": cfg, "phase": phase, "tree_commit_sha": sha, "freeze_commit": freeze_commit,
                  "layers": LAYERS, "regex_first": False, "scope": "detector-layer (regex+NER); not LLM-only",
                  "dataset_sha256": dataset_hash, "splits": {}}
        for split in PHASE_SPLITS[phase]:
            records, _ = run_config(pipeline, cfg, split_rows[split], split)
            (out / f"{label}-{split}.rows.jsonl").write_text(
                "".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8")
            report["splits"][split] = summarise(records)
            print(f"[{label}] {split}: n={len(records)} union={report['splits'][split]['union']['positive']}", file=sys.stderr)
        (out / f"{label}-{phase}.json").write_text(json.dumps(report, indent=1), encoding="utf-8")


def cmd_select(args) -> None:
    design = {}
    for path in sorted(args.out.glob("*-design.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        design[report["label"]] = {s: report["splits"][s]["union"]["positive"] for s in DESIGN_SPLITS}
    result = select_gliner(design)
    result["criterion"] = ("highest mean union balanced accuracy over (dev-TUNE, personalized); ties by fewer design FP; "
                           "positive rule; GLiNER configurations only")
    result["design_splits"] = list(DESIGN_SPLITS)
    args.freeze.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("chosen", "mean_union_balanced_accuracy")}, indent=1))


def compact_comparison(cmp: dict) -> dict:
    """The decision-relevant part of one ``detector_stats`` comparison (candidate minus baseline)."""
    deltas = cmp["deltas"]["new"]
    pick = lambda name: {k: deltas[name][k] for k in ("estimate", "lo", "hi")}  # noqa: E731
    flips = cmp["flips"]
    return {"counts": cmp["counts"], "n_rows": cmp["n_rows"], "n_clusters": cmp["n_clusters"],
            "delta": {m: pick(m) for m in ("recall", "specificity", "f2", "cost_4")},
            "flips": {k: flips[k] for k in ("fn_to_tp", "tp_to_fn", "fp_to_tn", "tn_to_fp")},
            "mcnemar_positives_p": flips["mcnemar_positives"]["p_two_sided"],
            "mcnemar_negatives_p": flips["mcnemar_negatives"]["p_two_sided"],
            "cluster_sign_positives_p": cmp["cluster_sign_test"]["positives"]["p_two_sided"],
            "cluster_sign_negatives_p": cmp["cluster_sign_test"]["negatives"]["p_two_sided"]}


def cmd_stats(args) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("detector_stats", args.stats_path)
    stats = importlib.util.module_from_spec(spec)
    sys.modules["detector_stats"] = stats
    spec.loader.exec_module(stats)
    result = {"baseline": BASELINE, "scope": "detector-layer (regex+NER); not LLM-only", "comparisons": {}}
    for split in args.splits:
        base_path = args.out / f"{BASELINE}-{split}.rows.jsonl"
        base_rows = stats.load_rows(base_path)
        for path in sorted(args.out.glob(f"*-{split}.rows.jsonl")):
            label = path.name[: -len(f"-{split}.rows.jsonl")]
            if label == BASELINE or (args.labels and label not in args.labels):
                continue
            rows = stats.load_rows(path)
            for layer in ("ner", "union"):
                for rule in ("positive", "block"):
                    cmp = stats.compare_runs(base_rows, rows, layer=layer, rule=rule, grouping="group_id",
                                             n_boot=args.n_boot)
                    result["comparisons"].setdefault(label, {}).setdefault(split, {}).setdefault(layer, {})[rule] = compact_comparison(cmp)
    args.stats_out.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"wrote {args.stats_out}", file=sys.stderr)


def _fmt(value) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def render_report(out: Path, splits: tuple[str, ...], labels: list[str] | None = None) -> str:
    """Markdown tables (one per split) from the aggregate JSON files in ``out``."""
    reports = {}
    for path in sorted(out.glob("*-design.json")) + sorted(out.glob("*-post-review.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        reports.setdefault(report["label"], {}).update(report["splits"])
    lines = []
    for split in splits:
        lines += [f"**{split}**", "",
                  "| Config | NER TP | NER FP | NER recall | NER spec | Union TP | Union FP | Union recall | Union spec "
                  "| Union BLOCK recall | Union BLOCK spec |",
                  "|---|---|---|---|---|---|---|---|---|---|---|"]
        for label in (labels or sorted(reports)):
            if label not in reports or split not in reports[label]:
                continue
            cell = reports[label][split]
            ner, union, block = cell["ner"]["positive"], cell["union"]["positive"], cell["union"]["block"]
            lines.append(f"| {label} | {ner['TP']} | {ner['FP']} | {_fmt(ner['recall'])} | {_fmt(ner['specificity'])} "
                         f"| {union['TP']} | {union['FP']} | {_fmt(union['recall'])} | {_fmt(union['specificity'])} "
                         f"| {_fmt(block['recall'])} | {_fmt(block['specificity'])} |")
        lines.append("")
    return "\n".join(lines)


def cmd_collect(args) -> None:
    """Merge the per-configuration aggregate JSON files of one phase into one file (no row data)."""
    merged = {"phase": args.phase, "scope": "detector-layer (regex+NER); not LLM-only", "configs": {}}
    for path in sorted(args.out.glob(f"*-{args.phase}.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        merged["configs"][report["label"]] = {k: report[k] for k in
                                              ("config", "tree_commit_sha", "freeze_commit", "dataset_sha256", "splits")}
    args.dest.write_text(json.dumps(merged, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def cmd_report(args) -> None:
    print(render_report(args.out, tuple(args.splits), args.labels))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--phase", choices=sorted(PHASE_SPLITS), required=True)
    run.add_argument("--tree", type=Path, required=True)
    run.add_argument("--data-root", type=Path, required=True)
    run.add_argument("--generated", type=Path, required=True)
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--gliner-dir", type=Path, default=None)
    run.add_argument("--cache", type=Path, default=None, help="JSONL cache of raw GLiNER predictions (kept outside Git)")
    run.add_argument("--freeze", type=Path, default=None)
    run.add_argument("--configs", nargs="+", required=True, help="labels such as sm-pf1 lg-pf0 gliner-core-t0.3-pf1")
    run.set_defaults(func=cmd_run)
    select = sub.add_parser("select")
    select.add_argument("--out", type=Path, required=True)
    select.add_argument("--freeze", type=Path, required=True)
    select.set_defaults(func=cmd_select)
    stats = sub.add_parser("stats")
    stats.add_argument("--out", type=Path, required=True)
    stats.add_argument("--stats-path", type=Path, default=Path(__file__).with_name("detector_stats.py"))
    stats.add_argument("--stats-out", type=Path, required=True)
    stats.add_argument("--splits", nargs="+", default=list(DESIGN_SPLITS + POST_REVIEW_SPLITS))
    stats.add_argument("--n-boot", type=int, default=10_000)
    stats.add_argument("--labels", nargs="+", default=None, help="restrict to these configuration labels")
    stats.set_defaults(func=cmd_stats)
    collect = sub.add_parser("collect")
    collect.add_argument("--out", type=Path, required=True)
    collect.add_argument("--phase", choices=sorted(PHASE_SPLITS), required=True)
    collect.add_argument("--dest", type=Path, required=True)
    collect.set_defaults(func=cmd_collect)
    report = sub.add_parser("report")
    report.add_argument("--out", type=Path, required=True)
    report.add_argument("--splits", nargs="+", default=list(DESIGN_SPLITS + POST_REVIEW_SPLITS))
    report.add_argument("--labels", nargs="+", default=None)
    report.set_defaults(func=cmd_report)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
