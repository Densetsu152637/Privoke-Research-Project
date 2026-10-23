"""Head-to-head detector ablation: spaCy NER versus the experimental pattern detector.

This is an explicitly requested DETECTOR ABLATION (NER layer only).  It runs in
process, imports the detector classes directly, and uses no gRPC, Docker, LLM or
semantic layer; none of its numbers are LLM-layer evidence.

Data (prompt-level labels only, no gold spans):
  evaluation/datasets/privoke_personalized_synthetic.jsonl  (template generated)
  evaluation/datasets/privoke_openai_synthetic.jsonl        (LLM generated)

Splits: a seeded 50/50 split of the personalized file.  ``--dev-only`` evaluates
the dev half only and is the ONLY mode that may be used while tuning patterns.
The default mode evaluates the held-out half and the whole OOD file and
(re)writes docs/experiments/ner-pattern-detector-20261024.{md,json}.

Run from the repository root with a host Python that has spaCy and
en_core_web_sm, numpy:
  evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/compare_ner_pattern_detector.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import random
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Dict, List, Sequence, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "extension" / "client-runtime"
for _path in (CLIENT, ROOT / "shared" / "python"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from src.NER.ner_detector import EntityNERDetector  # noqa: E402
from src.NER.pattern_entity_detector import PatternEntityDetector  # noqa: E402
from src.detection.preprocessing import normalize_with_offsets  # noqa: E402

DATASETS = ROOT / "evaluation" / "datasets"
PERSONALIZED = DATASETS / "privoke_personalized_synthetic.jsonl"
OPENAI = DATASETS / "privoke_openai_synthetic.jsonl"
REPORT_MD = ROOT / "docs" / "experiments" / "ner-pattern-detector-20261024.md"
REPORT_JSON = ROOT / "docs" / "experiments" / "ner-pattern-detector-20261024.json"

SPLIT_SEED = 20261024
BOOTSTRAP_SEED = 7
BOOTSTRAP_ROUNDS = 1000
FAMILIES = ("person", "location", "any")
CONDITIONS = ("deployed", "original")
BEGIN, END = "<!-- BEGIN GENERATED -->", "<!-- END GENERATED -->"

ENTITY_FAMILY = {"name": "person", "location": "location", "organization": "org"}


# ----------------------------------------------------------------------- data

def load_jsonl(path: Path) -> List[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def split_personalized(rows: List[dict]) -> Tuple[List[dict], List[dict]]:
    """Seeded 50/50 split over ids sorted lexicographically (dev, held-out)."""
    ordered = sorted(rows, key=lambda r: r["id"])
    random.Random(SPLIT_SEED).shuffle(ordered)
    half = len(ordered) // 2
    return ordered[:half], ordered[half:]


def gold_personalized(row: dict) -> Dict[str, bool]:
    cats = set(row["expected_categories"])
    return {"person": "FULL_NAME" in cats, "location": "ADDRESS" in cats, "any": bool(row["expected_has_pii"])}


def gold_openai(row: dict) -> Dict[str, bool]:
    # Coarse IDENTITY covers ID numbers, phones, employee ids, ... (not person
    # identity), so name/location gold comes from the fine-grained labels.
    fine = set(row.get("fine_pii_categories", []))
    return {"person": "FULL_NAME" in fine, "location": bool(fine & {"ADDRESS", "PLACE_OF_BIRTH"}),
            "any": bool(row["expected_has_pii"])}


# -------------------------------------------------------------------- systems

class Entity(dict):
    """Plain record: family, mechanism, text, label."""


def to_entities(results, source: str) -> List[Entity]:
    entities = []
    for result in results:
        meta = result.metadata
        entities.append(Entity(
            family=ENTITY_FAMILY[meta["entity_type"]], label=meta["label"],
            text=result.section_of_text, mechanism=meta.get("mechanism", source), source=source,
        ))
    return entities


def build_systems(spacy_detector: EntityNERDetector):
    """Return {name: callable(text) -> (entities, seconds)}; spaCy output is shared."""
    patterns = {
        "prototype_cues": PatternEntityDetector(use_cues=True, use_shape=False, use_recurrence=False),
        "prototype_cues_shape": PatternEntityDetector(use_cues=True, use_shape=True, use_recurrence=False),
        "prototype": PatternEntityDetector(use_cues=True, use_shape=True, use_recurrence=True),
        "prototype_gazetteer": PatternEntityDetector(use_cues=True, use_shape=True, use_recurrence=True, use_gazetteer=True),
    }
    hybrid = PatternEntityDetector(use_cues=True, use_shape=False, use_recurrence=True)

    def run(text: str) -> Dict[str, Tuple[List[Entity], float]]:
        out: Dict[str, Tuple[List[Entity], float]] = {}
        t0 = time.perf_counter()
        spacy_results = spacy_detector.extract_entities(text)
        spacy_time = time.perf_counter() - t0
        out["spacy"] = (to_entities(spacy_results, "spacy"), spacy_time)
        pattern_time: Dict[str, float] = {}
        for name, detector in patterns.items():
            t0 = time.perf_counter()
            results = detector.extract_entities(text)
            pattern_time[name] = time.perf_counter() - t0
            out[name] = (to_entities(results, "pattern"), pattern_time[name])
        t0 = time.perf_counter()
        hybrid_results = hybrid.augment_entities(text, spacy_results)
        hybrid_time = time.perf_counter() - t0
        # Hybrid latency includes the spaCy pass that produced the seeds.
        out["hybrid_spacy_seeds_cues_recurrence"] = (to_entities(hybrid_results, "spacy"), spacy_time + hybrid_time)
        out["union_spacy_prototype"] = (
            out["spacy"][0] + out["prototype"][0], spacy_time + pattern_time["prototype"])
        return out

    return run


SYSTEM_ORDER = (
    "spacy", "prototype_cues", "prototype_cues_shape", "prototype", "prototype_gazetteer",
    "union_spacy_prototype", "hybrid_spacy_seeds_cues_recurrence",
)
SYSTEM_LABEL = {
    "spacy": "spaCy en_core_web_sm NER",
    "prototype_cues": "prototype: cues only",
    "prototype_cues_shape": "prototype: cues + shape",
    "prototype": "prototype: cues + shape + recurrence",
    "prototype_gazetteer": "prototype + gazetteer (extra)",
    "union_spacy_prototype": "union: spaCy U prototype",
    "hybrid_spacy_seeds_cues_recurrence": "hybrid: spaCy seeds + cues + recurrence",
}


def condition_text(text: str, condition: str) -> str:
    if condition == "deployed":
        return normalize_with_offsets(text).text
    return text


def run_all(rows: Sequence[dict], runner) -> Dict[str, Dict[str, dict]]:
    """predictions[condition][system] = {'entities': [...], 'seconds': [...]} aligned with rows."""
    predictions: Dict[str, Dict[str, dict]] = {
        c: {s: {"entities": [], "seconds": []} for s in SYSTEM_ORDER} for c in CONDITIONS}
    for row in rows:
        for condition in CONDITIONS:
            result = runner(condition_text(row["text"], condition))
            for system in SYSTEM_ORDER:
                entities, seconds = result[system]
                predictions[condition][system]["entities"].append(entities)
                predictions[condition][system]["seconds"].append(seconds)
    return predictions


# -------------------------------------------------------------------- metrics

def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def ratio(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"value": (k / n) if n else None, "k": k, "n": n, "ci95": [lo, hi]}


def fires(entities: List[Entity], family: str) -> bool:
    if family == "any":
        return bool(entities)
    return any(e["family"] == family for e in entities)


def f1_of(tp, fp, fn):
    denom = 2 * tp + fp + fn
    return (2 * tp / denom) if denom else float("nan")


def family_metrics(gold: np.ndarray, pred: np.ndarray, clean: np.ndarray) -> dict:
    tp = int(np.sum(gold & pred)); fp = int(np.sum(~gold & pred))
    fn = int(np.sum(gold & ~pred)); tn = int(np.sum(~gold & ~pred))
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    n = len(gold)
    idx = rng.integers(0, n, size=(BOOTSTRAP_ROUNDS, n))
    g, p = gold[idx], pred[idx]
    btp = np.sum(g & p, axis=1); bfp = np.sum(~g & p, axis=1); bfn = np.sum(g & ~p, axis=1)
    denom = 2 * btp + bfp + bfn
    with np.errstate(divide="ignore", invalid="ignore"):
        boot = np.where(denom > 0, 2 * btp / denom, np.nan)
    lo, hi = np.nanpercentile(boot, [2.5, 97.5])
    clean_n = int(clean.sum()); clean_fp = int(np.sum(clean & pred))
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": n, "positives": tp + fn,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "f1": {"value": f1_of(tp, fp, fn), "ci95_bootstrap": [float(lo), float(hi)]},
        # specificity on expected_has_pii == false prompts (family fired = false alarm)
        "specificity_clean": ratio(clean_n - clean_fp, clean_n),
        "fire_rate_all": ratio(tp + fp, n),
    }


def evaluate(rows, gold_fn, predictions) -> dict:
    gold = {f: np.array([gold_fn(r)[f] for r in rows], dtype=bool) for f in FAMILIES}
    clean = np.array([not r["expected_has_pii"] for r in rows], dtype=bool)
    out: dict = {}
    for condition in CONDITIONS:
        out[condition] = {}
        for system in SYSTEM_ORDER:
            ents = predictions[condition][system]["entities"]
            seconds = np.array(predictions[condition][system]["seconds"]) * 1000.0
            entry = {"latency_ms": {"mean": float(seconds.mean()), "p95": float(np.percentile(seconds, 95))}}
            for family in FAMILIES:
                pred = np.array([fires(e, family) for e in ents], dtype=bool)
                entry[family] = family_metrics(gold[family], pred, clean)
            # ORG: no gold, report firing rates only.
            org = np.array([fires(e, "org") for e in ents], dtype=bool)
            entry["org_fire"] = {
                "all": ratio(int(org.sum()), len(org)),
                "pii_positive": ratio(int(org[~clean].sum()), int((~clean).sum())),
                "clean": ratio(int(org[clean].sum()), int(clean.sum())),
            }
            entry["mechanism_prompts"] = mechanism_prompt_counts(ents, gold)
            out[condition][system] = entry
    return out


def mechanism_prompt_counts(entities_per_prompt, gold) -> dict:
    """Prompts in which at least one entity of (family, mechanism) was emitted."""
    counts: Dict[str, Counter] = {f: Counter() for f in ("person", "location", "org")}
    hits: Dict[str, Counter] = {f: Counter() for f in ("person", "location")}
    for i, entities in enumerate(entities_per_prompt):
        seen = {(e["family"], e["mechanism"]) for e in entities}
        for family, mechanism in seen:
            counts[family][mechanism] += 1
            if family in hits and gold[family][i]:
                hits[family][mechanism] += 1
    return {f: {"prompts": dict(counts[f]), "on_gold_positive": dict(hits.get(f, {}))} for f in counts}


def collect_examples(rows, gold_fn, predictions, sample_seed: int, per_kind: int = 5) -> dict:
    """Seeded FP and FN examples per system and condition (person and location pooled)."""
    out: dict = {}
    rng = random.Random(sample_seed)
    for condition in CONDITIONS:
        out[condition] = {}
        for system in SYSTEM_ORDER:
            fps, fns = [], []
            ents = predictions[condition][system]["entities"]
            for row, entities in zip(rows, ents):
                gold = gold_fn(row)
                for family in ("person", "location"):
                    fired = fires(entities, family)
                    values = [e["text"] for e in entities if e["family"] == family]
                    mechanisms = sorted({e["mechanism"] for e in entities if e["family"] == family})
                    item = {"id": row["id"], "family": family, "text": row["text"][:220],
                            "detected": values[:4], "mechanisms": mechanisms}
                    if fired and not gold[family]:
                        fps.append(item)
                    elif gold[family] and not fired:
                        fns.append(item)
            out[condition][system] = {
                "fp_total": len(fps), "fn_total": len(fns),
                "fp": rng.sample(fps, min(per_kind, len(fps))),
                "fn": rng.sample(fns, min(per_kind, len(fns))),
            }
    return out


# --------------------------------------------------------------------- report

def pct(entry: dict, ci: bool = True) -> str:
    value = entry["value"]
    if value is None:
        return "n/a"
    text = f"{100 * value:.1f}%"
    if ci:
        lo, hi = entry["ci95"]
        text += f" [{100 * lo:.0f}-{100 * hi:.0f}]"
    return text


def family_table(block: dict, condition: str, family: str) -> str:
    lines = [
        "| System | TP | FP | FN | Precision [95% CI] | Recall [95% CI] | F1 [95% boot CI] | Specificity on clean [95% CI] | mean / p95 ms |",
        "|---|---:|---:|---:|---|---|---|---|---|",
    ]
    for system in SYSTEM_ORDER:
        e = block[condition][system]
        m = e[family]
        f1 = m["f1"]
        lat = e["latency_ms"]
        lines.append(
            f"| {SYSTEM_LABEL[system]} | {m['tp']} | {m['fp']} | {m['fn']} | {pct(m['precision'])} | {pct(m['recall'])} "
            f"| {100 * f1['value']:.1f}% [{100 * f1['ci95_bootstrap'][0]:.0f}-{100 * f1['ci95_bootstrap'][1]:.0f}] "
            f"| {pct(m['specificity_clean'])} | {lat['mean']:.2f} / {lat['p95']:.2f} |")
    return "\n".join(lines)


def split_section(title: str, block: dict, sizes: dict) -> str:
    parts = [f"### {title}", "", sizes["text"], ""]
    for family, label in (("person", "PERSON family (gold: " + sizes["person_gold"] + ")"),
                          ("location", "Location family (gold: " + sizes["location_gold"] + ")"),
                          ("any", "Any NER-mapped entity vs `expected_has_pii` (comparable to the earlier any-hit diagnostic)")):
        for condition, cname in (("deployed", "Deployed condition: lowercased `normalize_with_offsets(text).text`"),
                                 ("original", "Case-preserved original text")):
            parts += [f"**{label} - {cname}**", "", family_table(block, condition, family), ""]
    parts += ["**ORG firing rates (no gold; share of prompts with at least one ORG entity)**", "",
              "| System | Condition | All prompts | `expected_has_pii=true` | `expected_has_pii=false` |", "|---|---|---|---|---|"]
    for system in SYSTEM_ORDER:
        for condition in CONDITIONS:
            o = block[condition][system]["org_fire"]
            parts.append(f"| {SYSTEM_LABEL[system]} | {condition} | {pct(o['all'])} | {pct(o['pii_positive'])} | {pct(o['clean'])} |")
    parts += ["", "**Mechanisms (prompt counts; prototype rows only; 'gold+' = prompts that are gold-positive for that family)**", "",
              "| System | Condition | Family | Mechanism | Prompts | Gold+ |", "|---|---|---|---|---:|---:|"]
    for system in ("prototype", "hybrid_spacy_seeds_cues_recurrence"):
        for condition in CONDITIONS:
            mech = block[condition][system]["mechanism_prompts"]
            for family in ("person", "location", "org"):
                for mechanism, count in sorted(mech[family]["prompts"].items()):
                    gold_hits = mech[family]["on_gold_positive"].get(mechanism, "-")
                    parts.append(f"| {SYSTEM_LABEL[system]} | {condition} | {family} | {mechanism} | {count} | {gold_hits} |")
    parts.append("")
    return "\n".join(parts)


def examples_section(title: str, examples: dict, systems=SYSTEM_ORDER) -> str:
    parts = [f"### {title}", ""]
    for condition in CONDITIONS:
        for system in systems:
            ex = examples[condition][system]
            parts.append(f"**{SYSTEM_LABEL[system]} ({condition})** - {ex['fp_total']} FP and {ex['fn_total']} FN prompt-family cases in total; seeded sample:")
            parts.append("")
            for kind, items in (("FP", ex["fp"]), ("FN", ex["fn"])):
                for item in items:
                    text = item["text"].replace("\n", " ").replace("|", "/")
                    parts.append(f"- {kind} [{item['family']}] `{item['id']}` detected={item['detected']} via {item['mechanisms']}: {text}")
            parts.append("")
    return "\n".join(parts)


def render(results: dict) -> str:
    meta = results["meta"]
    sections = [
        "## Generated results", "",
        f"Generated by `evaluation/compare_ner_pattern_detector.py` at git revision `{meta['git_revision']}` "
        f"(dirty working tree: {meta['git_dirty']}). Raw numbers: `docs/experiments/ner-pattern-detector-20261024.json`.", "",
        "Environment: " + meta["environment"], "",
        "### Data", "",
        "| Dataset | File SHA-256 | Rows | `expected_has_pii=true` |", "|---|---|---:|---:|",
    ]
    for name, d in meta["datasets"].items():
        sections.append(f"| {name} | `{d['sha256'][:16]}...` | {d['rows']} | {d['positives']} |")
    sections += ["", meta["split_note"], ""]
    for key, title in (("heldout", "Held-out personalized_synthetic (template generated; in-distribution to the dev half)"),
                       ("ood", "OOD: whole openai_synthetic (LLM generated; never used for development)")):
        sections.append(split_section(title, results[key]["metrics"], results[key]["sizes"]))
    for key, title in (("heldout", "Qualitative examples - held-out personalized"), ("ood", "Qualitative examples - OOD openai")):
        sections.append(examples_section(title, results[key]["examples"],
                                         ("spacy", "prototype", "union_spacy_prototype", "hybrid_spacy_seeds_cues_recurrence")))
    return "\n".join(sections)


def write_report(results: dict) -> None:
    generated = f"{BEGIN}\n{render(results)}\n{END}"
    if REPORT_MD.exists():
        text = REPORT_MD.read_text(encoding="utf-8")
        if BEGIN in text and END in text:
            head = text[: text.index(BEGIN)]
            tail = text[text.index(END) + len(END):]
            REPORT_MD.write_text(head + generated + tail, encoding="utf-8")
            return
    REPORT_MD.parent.mkdir(parents=True, exist_ok=True)
    REPORT_MD.write_text("# NER pattern detector vs spaCy NER (detector ablation)\n\n" + generated + "\n", encoding="utf-8")


# ----------------------------------------------------------------------- main

def git(*args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001 - metadata only
        return "unknown"


def sizes_for(rows: Sequence[dict], gold_fn, text: str, person_gold: str, location_gold: str) -> dict:
    gold = [gold_fn(r) for r in rows]
    return {"rows": len(rows), "has_pii": sum(r["expected_has_pii"] for r in rows),
            "person_positives": sum(g["person"] for g in gold), "location_positives": sum(g["location"] for g in gold),
            "text": text.format(n=len(rows), pii=sum(r["expected_has_pii"] for r in rows),
                                person=sum(g["person"] for g in gold), location=sum(g["location"] for g in gold)),
            "person_gold": person_gold, "location_gold": location_gold}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dev-only", action="store_true",
                        help="Evaluate only the dev half (for pattern tuning); writes nothing.")
    parser.add_argument("--examples", type=int, default=0, help="With --dev-only: print N FP/FN examples for the prototype.")
    parser.add_argument("--no-write", action="store_true", help="Do not write the report files.")
    args = parser.parse_args()

    personalized = load_jsonl(PERSONALIZED)
    openai = load_jsonl(OPENAI)
    dev, heldout = split_personalized(personalized)
    runner = build_systems(EntityNERDetector())
    runner("warm up Jane Doe lives in Paris")  # exclude lazy initialisation from latency

    if args.dev_only:
        predictions = run_all(dev, runner)
        metrics = evaluate(dev, gold_personalized, predictions)
        for family in FAMILIES:
            for condition in CONDITIONS:
                print(f"\n== DEV {family} / {condition} ==")
                for system in SYSTEM_ORDER:
                    m = metrics[condition][system][family]
                    print(f"{system:38s} TP={m['tp']:4d} FP={m['fp']:4d} FN={m['fn']:4d} "
                          f"P={pct(m['precision'], False)} R={pct(m['recall'], False)} F1={100 * m['f1']['value']:.1f}% "
                          f"spec={pct(m['specificity_clean'], False)}")
        if args.examples:
            examples = collect_examples(dev, gold_personalized, predictions, 1, args.examples)
            for condition in CONDITIONS:
                for kind in ("fp", "fn"):
                    print(f"\n-- DEV prototype {condition} {kind.upper()} ({examples[condition]['prototype'][kind + '_total']} total)")
                    for item in examples[condition]["prototype"][kind]:
                        print(f"  [{item['family']}] {item['detected']} {item['mechanisms']} :: {item['text'][:160]!r}")
        return

    results: dict = {}
    for key, rows, gold_fn, text, pg, lg in (
        ("heldout", heldout, gold_personalized,
         "{n} held-out rows ({pii} `expected_has_pii=true`); {person} PERSON-gold and {location} location-gold positives.",
         "`FULL_NAME` in `expected_categories`", "`ADDRESS` in `expected_categories`"),
        ("ood", openai, gold_openai,
         "{n} OOD rows ({pii} `expected_has_pii=true`); {person} PERSON-gold and {location} location-gold positives.",
         "`FULL_NAME` in `fine_pii_categories`", "`ADDRESS` or `PLACE_OF_BIRTH` in `fine_pii_categories`"),
    ):
        predictions = run_all(rows, runner)
        results[key] = {
            "sizes": sizes_for(rows, gold_fn, text, pg, lg),
            "metrics": evaluate(rows, gold_fn, predictions),
            "examples": collect_examples(rows, gold_fn, predictions, 20261024),
            "fired_ids": {c: {s: sorted(
                r["id"] for r, ents in zip(rows, predictions[c][s]["entities"]) if ents)
                for s in SYSTEM_ORDER} for c in CONDITIONS},
        }

    import spacy
    results["meta"] = {
        "git_revision": git("rev-parse", "HEAD"),
        "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "environment": f"Python {platform.python_version()}, spaCy {spacy.__version__}, numpy {np.__version__}, en_core_web_sm {spacy.load('en_core_web_sm').meta['version']}, {platform.platform()}",
        "split_seed": SPLIT_SEED, "bootstrap_seed": BOOTSTRAP_SEED, "bootstrap_rounds": BOOTSTRAP_ROUNDS,
        "datasets": {
            "personalized_synthetic": {"sha256": sha256(PERSONALIZED), "rows": len(personalized),
                                       "positives": sum(r["expected_has_pii"] for r in personalized)},
            "openai_synthetic": {"sha256": sha256(OPENAI), "rows": len(openai),
                                 "positives": sum(r["expected_has_pii"] for r in openai)},
        },
        "split_note": (f"Personalized split: ids sorted, shuffled with `random.Random({SPLIT_SEED})`, first {len(dev)} rows = dev "
                       f"(tuning only), remaining {len(heldout)} = held-out. Dev sha256 of ids: "
                       f"`{hashlib.sha256(chr(10).join(sorted(r['id'] for r in dev)).encode()).hexdigest()[:16]}...`."),
    }
    if not args.no_write:
        REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
        REPORT_JSON.write_text(json.dumps(results, indent=1, default=float), encoding="utf-8")
        write_report(results)
        print(f"wrote {REPORT_MD} and {REPORT_JSON}")
    for key in ("heldout", "ood"):
        for family in FAMILIES:
            for condition in CONDITIONS:
                for system in SYSTEM_ORDER:
                    m = results[key]["metrics"][condition][system][family]
                    print(f"{key:8s} {family:8s} {condition:8s} {system:38s} "
                          f"P={pct(m['precision'], False)} R={pct(m['recall'], False)} F1={100 * m['f1']['value']:.1f}%")


if __name__ == "__main__":
    main()
