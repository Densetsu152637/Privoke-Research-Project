"""Detector-layer evaluation of the robustness fixes (regex+NER, explicit layers, never final).

One process = one flag configuration. For every requested condition (clean text or a seeded
perturbation from the robustness probe) it writes per-row JSONL in the evaluate_installed_detectors
format (aligned by example_id) so detector_stats can compare configurations pairwise.

    robust_eval.py --tree <wt> --config strip --splits dev personalized --conditions identity zero_width --out <dir>
"""
import argparse, hashlib, json, sys, time
from pathlib import Path

DATA = Path("D:/Git Repositories/Privoke-Research-Project")
PROBE = Path("D:/Git Repositories/Privoke-Research-Project-wt-c-robust/evaluation")
STATS = Path("D:/Git Repositories/Privoke-Research-Project-wt-a-stats/evaluation")
CONFIGS = {
    "base": {},
    "strip": {"strip_format_chars": True},
    "digits": {"canonicalise_digits": True},
    "email": {"canonicalise_email_words": True},
    "caseless": {"ner_caseless_gate": True},
    "all": {"strip_format_chars": True, "canonicalise_digits": True, "canonicalise_email_words": True,
            "ner_caseless_gate": True},
}
LAYERS = ["regex", "ner"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", type=Path, required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--splits", nargs="+", default=["dev", "personalized"])
    ap.add_argument("--conditions", nargs="+", required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--label", default=None)
    ap.add_argument("--spelled-min", type=int, default=None, help="ablation: override _MIN_SPELLED_DIGITS")
    ap.add_argument("--disable-caseless-rules", default=None, help="comma list or 'ALL' (experiment override)")
    a = ap.parse_args()
    assert "final" not in a.splits
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(a.tree / "extension/client-runtime"), str(a.tree / "shared/python"),
                    str(DATA / "extension/client-runtime/generated"), str(STATS), str(PROBE)]
    import spacy  # noqa
    import robustness_probe as probe
    import evaluate_installed_detectors as eid
    from src import pipeline
    from src.config import GLOBAL_CONFIG
    from src.NER import EntityNERDetector, ner_detector, ner_postfilter
    from src.regex.rule_detector import RuleDetector
    RuleDetector(); EntityNERDetector()
    if a.spelled_min is not None:
        from src.detection import preprocessing as _pp
        _pp._MIN_SPELLED_DIGITS = a.spelled_min
    for key, value in CONFIGS[a.config].items():
        setattr(GLOBAL_CONFIG, key, value)
    if a.disable_caseless_rules is not None:
        names = frozenset() if a.disable_caseless_rules == "NONE" else frozenset(a.disable_caseless_rules.split(","))
        ner_detector.CASELESS_DISABLED_RULES = names
    flags = {k: getattr(GLOBAL_CONFIG, k) for k in ("case_preserving_detectors", "ner_postfilter", "strip_format_chars",
             "canonicalise_digits", "canonicalise_email_words", "ner_caseless_gate")}
    flags["spelled_min_override"] = a.spelled_min
    flags["caseless_disabled_rules"] = sorted(ner_detector.CASELESS_DISABLED_RULES)
    pipeline.analyse_text("warm up Alice Smith", layers=LAYERS, regex_first=False)
    label = a.label or a.config
    a.out.mkdir(parents=True, exist_ok=True)

    def analyse(text):
        analysis = pipeline.analyse_text(text, layers=LAYERS, regex_first=False)
        if [l.layer for l in analysis.layers] != LAYERS or any(l.status != "ok" for l in analysis.layers):
            raise RuntimeError("unexpected layer execution")
        rows = {l.layer: eid.layer_row(l.results, pipeline.strongest_result) for l in analysis.layers}
        return {"regex": rows["regex"], "ner": rows["ner"], "union": eid.union_row(rows["regex"], rows["ner"], analysis)}

    meta = {"label": label, "config": a.config, "flags": flags, "tree": str(a.tree), "dataset_sha256": {}}
    for split in a.splits:
        path = DATA / probe.SPLIT_FILES[split]
        meta["dataset_sha256"][split] = hashlib.sha256(path.read_bytes()).hexdigest()
        rows = probe.load_rows(split, DATA)
        clean = None
        for cond in a.conditions:
            t0 = time.time()
            records, redone = [], 0
            for i, row in enumerate(rows):
                text = row["text"] if cond == "identity" else probe.apply_transform(cond, row["text"], row["id"])
                if cond != "identity" and text == row["text"] and clean is not None:
                    out = clean[i]; 
                else:
                    out = analyse(text); redone += 1
                example_id, group_id = eid.row_identity(row, split)
                rec = {"split": split, "example_id": example_id, "group_id": group_id,
                       "stratum": row.get("scenario") or row.get("task_name"),
                       "expected_has_pii": bool(row["expected_has_pii"]), **out}
                if split == "dev":
                    rec["half"] = "check" if int(hashlib.sha256(row["group_id"].encode()).hexdigest(), 16) % 2 else "tune"
                records.append(rec)
            if cond == "identity":
                clean = [{k: r[k] for k in ("regex", "ner", "union")} for r in records]
            (a.out / f"{label}__{cond}__{split}.rows.jsonl").write_text(
                "".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8")
            print(f"[{label}] {split} {cond}: analysed {redone}/{len(rows)} in {time.time()-t0:.0f}s", file=sys.stderr, flush=True)
    (a.out / f"{label}__meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
