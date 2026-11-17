"""NER-role study: is spaCy NER more useful as an amplifier of regex than as an independent detector?

Scope: detector layers only (regex + NER). This is NOT LLM-only or semantic evidence and NOT a
full-product measurement. Every pipeline call uses an explicit ``layers=["regex", "ner"]`` list
(never empty, never semantic). The locked held-out ``final`` file is not selectable here.

Two sub-commands share one record format so every policy is evaluated offline from the *same* runs:

``dump``     (needs spaCy + the protobuf clients; run once per source tree)
    Writes per-prompt records: the tree's own regex hits and shipped NER hits, and, when the tree
    carries ``src.NER.ner_postfilter``, the raw spaCy entities on case-preserved (``ner_raw_cp``)
    and lower-cased (``ner_raw_lc``) text with the post-filter's corroboration features.

``analyse``  (pure Python)
    Combines an OLD dump (original tree: lowercased input, no post-filter) and a NEW dump
    (installed defaults) and evaluates the combination policies below.

Policies (positive = the prompt is flagged):

* ``P0``  regex only.
* ``P1``  regex OR NER (the current union; NER hits as the configuration emits them).
* ``P2``  regex OR (a NER entity that is *corroborated*); the corroboration variants in
  ``P2_VARIANTS`` are compared and one is chosen on the design splits only (dev-TUNE and
  personalized), by mean balanced accuracy, ties broken by fewer false positives.
* ``P3``  NER may only add categories/spans when a regex contact/identifier finding is already
  present in the prompt. It cannot create a positive, so its flag decision equals ``P0`` by
  construction; the study reports what it would add (amplification).
* ``P4``  NER used only to extend masking spans of regex-positive prompts (same flag decision as
  ``P0``); reports how many extra spans would be masked.

NER configurations: ``OLD`` (original tree), ``NEW`` (installed defaults: case-preserving input
and post-filter on) and ``NEW-raw`` (case-preserving input, raw spaCy entities, no post-filter).

    python evaluation/ner_role_study.py dump --tree <root> --label new --data-root <checkout> \
        --generated <protobuf dir> --out <dir> dev personalized openai
    python evaluation/ner_role_study.py analyse --old <old dump> --new <new dump> --out <dir>
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Iterable, Sequence

LAYERS = ["regex", "ner"]
SPLIT_FILES = {
    "dev": "evaluation/results/locked-public/development.jsonl",
    "personalized": "evaluation/datasets/privoke_personalized_synthetic.jsonl",
    "openai": "evaluation/datasets/privoke_openai_synthetic.jsonl",
}
REPORT_SPLITS = ("tune", "personalized", "check", "openai")
DESIGN_SPLITS = ("tune", "personalized")
CONFIG_NAMES = ("OLD", "NEW", "NEW-raw")

# Row-level category families used only for the descriptive amplification coverage tables.
NAME_CATEGORIES = frozenset(c.lower() for c in (
    "GIVENNAME", "SURNAME", "PERSON", "first_name", "last_name", "name", "FULL_NAME"))
PLACE_CATEGORIES = frozenset(c.lower() for c in (
    "CITY", "STREET", "LOCATION", "city", "country", "county", "state", "address", "street_address", "ADDRESS"))
CONTACT_ID_SENSITIVITY = ("S2", "S3", "S4")   # P3 gate: regex finding at or above this sensitivity


# ---------------------------------------------------------------------------
# Pure-Python policy layer (no spaCy; unit-tested)
# ---------------------------------------------------------------------------

def overlaps(a: Sequence[int], b: Sequence[int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _person(e: dict) -> bool:
    return e["label"] == "PERSON"


def _place_org(e: dict) -> bool:
    return e["label"] in ("GPE", "LOC", "FAC", "ORG")


def _person_any(e: dict) -> bool:
    return _person(e) and bool(e.get("cue") or e.get("recurring") or e.get("multi_token"))


# name -> predicate over one entity record (entity-level corroboration)
P2_VARIANTS: dict[str, Callable[[dict], bool]] = {
    "person_multi_token": lambda e: _person(e) and bool(e.get("multi_token")),
    "person_cue": lambda e: _person(e) and bool(e.get("cue")),
    "person_cue_or_recurring": lambda e: _person(e) and bool(e.get("cue") or e.get("recurring")),
    "person_any": _person_any,
    "person_any_or_relation": lambda e: _person_any(e) or (_place_org(e) and bool(e.get("relation_cue"))),
    "person_any_or_relation_or_geo": lambda e: _person_any(e) or (
        _place_org(e) and bool(e.get("relation_cue") or e.get("geo_or_org_cue"))),
}


def regex_positive(row: dict) -> bool:
    return bool(row["regex"])


def policy_flags(row: dict, ner_key: str, variant: str | None = None) -> dict[str, bool]:
    """Flag decision of each policy for one prompt. ``ner_key`` selects the NER entity list."""
    regex = regex_positive(row)
    ents = row[ner_key]
    flags = {"P0": regex, "P1": regex or bool(ents)}
    for name, test in P2_VARIANTS.items():
        flags[f"P2:{name}"] = regex or any(test(e) for e in ents)
    flags["P3"] = regex   # NER cannot create a positive by construction
    flags["P4"] = regex
    if variant is not None:
        flags["P2"] = flags[f"P2:{variant}"]
    return flags


def confusion(expected: Iterable[bool], predicted: Iterable[bool]) -> dict:
    c = collections.Counter()
    for e, p in zip(expected, predicted):
        c[("TP" if p else "FN") if e else ("FP" if p else "TN")] += 1
    tp, tn, fp, fn = (c[k] for k in ("TP", "TN", "FP", "FN"))
    recall, spec = tp / max(tp + fn, 1), tn / max(tn + fp, 1)
    return {"TP": tp, "TN": tn, "FP": fp, "FN": fn, "recall": recall, "specificity": spec,
            "balanced_accuracy": (recall + spec) / 2}


def split_rows(records: dict, split: str) -> list[dict]:
    """``tune``/``check`` are the halves of ``dev`` by sha256(group_id) parity."""
    if split in ("tune", "check"):
        return [r for r in records["dev"] if r["half"] == split]
    return records[split]


def evaluate_policies(records: dict, ner_key: str, variant: str | None) -> dict:
    out: dict = {}
    for split in REPORT_SPLITS:
        rows = split_rows(records, split)
        expected = [r["expected"] for r in rows]
        flags = [policy_flags(r, ner_key, variant) for r in rows]
        out[split] = {"n": len(rows), "positives": sum(expected),
                      "policies": {p: confusion(expected, [f[p] for f in flags]) for p in flags[0]}}
    return out


def choose_variant(records: dict, ner_key: str) -> tuple[str, dict]:
    """Pick the P2 corroboration variant on the design splits only."""
    scores = {}
    for name in P2_VARIANTS:
        per_split = []
        for split in DESIGN_SPLITS:
            rows = split_rows(records, split)
            conf = confusion([r["expected"] for r in rows],
                             [policy_flags(r, ner_key)[f"P2:{name}"] for r in rows])
            per_split.append(conf)
        scores[name] = {"design_mean_balanced_accuracy": sum(c["balanced_accuracy"] for c in per_split) / len(per_split),
                        "design_FP": sum(c["FP"] for c in per_split)}
    best = max(scores, key=lambda n: (round(scores[n]["design_mean_balanced_accuracy"], 12), -scores[n]["design_FP"]))
    return best, scores


def paired_vs(records: dict, ner_key: str, base: str, other: str, variant: str | None) -> dict:
    """Prompts where ``other`` differs from ``base``: positives gained/lost and negatives gained/lost."""
    out = {}
    for split in REPORT_SPLITS:
        c = collections.Counter()
        for r in split_rows(records, split):
            f = policy_flags(r, ner_key, variant)
            if f[base] != f[other]:
                kind = "TP" if r["expected"] else "FP"
                c[f"{'+' if f[other] else '-'}{kind}"] += 1
        out[split] = dict(c)
    return out


def _ner_hit_overlaps_regex(row: dict, ent: dict) -> bool:
    return any(overlaps(ent["span"], h["span"]) for h in row["regex"])


def amplification(records: dict, ner_key: str) -> dict:
    """What P3/P4 would add on regex-positive prompts (descriptive; row-level category families)."""
    out = {}
    for split in REPORT_SPLITS:
        rows = [r for r in split_rows(records, split) if regex_positive(r)]
        stats = collections.Counter()
        by_label_extra = collections.Counter()
        for r in rows:
            gated = any(h["sens"] in CONTACT_ID_SENSITIVITY for h in r["regex"])
            cats = {c.lower() for c in r["expected_categories"]}
            stats["regex_positive_rows"] += 1
            stats["regex_positive_rows_expected_pii" if r["expected"] else "regex_positive_rows_no_pii"] += 1
            extra = [e for e in r[ner_key] if not _ner_hit_overlaps_regex(r, e)]
            suffix = "pii" if r["expected"] else "nopii"
            if extra:
                stats[f"P4_rows_with_extra_span_{suffix}"] += 1
            stats[f"P4_extra_spans_{suffix}"] += len(extra)
            stats["P3_gate_rows"] += int(gated)
            if gated:
                stats[f"P3_extra_spans_{suffix}"] += len(extra)
            for e in extra:
                by_label_extra[e["label"]] += 1
            for family, labels, wanted in (("name", ("PERSON",), NAME_CATEGORIES),
                                           ("place", ("GPE", "LOC", "FAC"), PLACE_CATEGORIES)):
                expects = bool(cats & wanted)
                present = any(e["label"] in labels for e in extra)   # entity regex does not already cover
                if expects:
                    stats[f"{family}_expected_rows"] += 1
                    stats[f"{family}_expected_and_ner_entity"] += int(present)
                else:
                    stats[f"{family}_not_expected_rows"] += 1
                    stats[f"{family}_not_expected_but_ner_entity"] += int(present)
        out[split] = {**stats, "P4_extra_spans_by_label": dict(by_label_extra)}
    return out


# ---------------------------------------------------------------------------
# Dump (needs spaCy)
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _positive(result) -> bool:
    return result.classification.sensitivity().name != "S0" or bool(result.classification.categories())


def _hit(result) -> dict:
    md = result.metadata or {}
    return {"span": list(result.span) if result.span else [0, 0],
            "rule": md.get("rule_name") or md.get("label") or "?",
            "label": md.get("label"), "sens": result.classification.sensitivity().name,
            "cats": sorted(c.name for c in result.classification.categories())}


def _half(group_id: str) -> str:
    return "tune" if int(hashlib.sha256(group_id.encode()).hexdigest(), 16) % 2 == 0 else "check"


def _raw_entities(nlp, norm, labels, postfilter, kept_only: bool = False) -> list[dict]:
    """Raw spaCy entities on ``norm.text`` with corroboration features (spans in original coordinates).

    ``kept_only`` returns only the entities the post-filter keeps (the shipped NER output for that model)."""
    doc = nlp(norm.text)
    ents = [e for e in doc.ents if e.label_ in labels]
    if kept_only:
        candidates, seen = [], set()
        for e in ents:
            key = (e.start_char, e.end_char, e.label_)
            if key not in seen:
                seen.add(key)
                candidates.append(e)
        ents = [d.candidate.span for d in postfilter.postfilter(doc, candidates, nlp=nlp) if d.keep]
    out = []
    for ent in ents:
        original = norm.original_span((ent.start_char, ent.end_char)) or (ent.start_char, ent.end_char)
        record = {"span": list(original), "label": ent.label_, "text_len": ent.end_char - ent.start_char}
        if postfilter is not None:
            cand = postfilter.Candidate(span=ent, label=ent.label_, text=ent.text, start=ent.start_char, end=ent.end_char)
            postfilter._annotate(doc.text, cand)
            before = postfilter._before(doc.text, cand.start)
            after = postfilter._after(doc.text, cand.end)
            record.update({
                "multi_token": cand.multi_token,
                "cue": bool(ent.label_ == "PERSON" and (
                    postfilter._PERSON_CUE.search(before) or postfilter._PERSON_TRAILING_CUE.match(after)
                    or postfilter._possessed_role_head(ent) or postfilter._is_speaker_label(doc.text, cand))),
                "recurring": bool(ent.label_ == "PERSON" and postfilter._is_recurring(doc.text, cand)),
                "relation_cue": cand.relation_cue, "geo_or_org_cue": cand.geo_or_org_cue,
            })
        out.append(record)
    return out


def run_dump(args: argparse.Namespace) -> None:
    sys.path[:0] = [str(args.tree / "extension/client-runtime"), str(args.tree / "shared/python"), str(args.generated)]
    import spacy  # noqa: F401  pre-import in the main thread (layer threads race on first import)
    from src import pipeline
    from src.config import GLOBAL_CONFIG
    from src.detection.preprocessing import normalize_with_offsets
    from src.NER import EntityNERDetector
    from src.NER.use_cases import NER_LABEL_USE_CASES
    from src.regex.rule_detector import RuleDetector
    try:
        from src.NER import ner_postfilter
    except ImportError:
        ner_postfilter = None

    RuleDetector()
    nlp = EntityNERDetector().nlp
    extra_nlps = {name: spacy.load(name) for name in (args.extra_model or [])}
    sha = subprocess.run(["git", "-C", str(args.tree), "rev-parse", "HEAD"], capture_output=True, text=True)
    report = {"label": args.label, "tree": str(args.tree),
              "tree_commit_sha": sha.stdout.strip() if sha.returncode == 0 else "not-a-git-checkout",
              "scope": "detector-layer (regex+NER); not LLM-only", "layers": LAYERS, "regex_first": False,
              "has_postfilter_module": ner_postfilter is not None,
              "observed_flags": {k: getattr(GLOBAL_CONFIG, k, "absent") for k in ("case_preserving_detectors", "ner_postfilter")},
              "spacy_model": nlp.meta.get("name"), "extra_models": {k: [v.meta.get("name"), v.meta.get("version")] for k, v in extra_nlps.items()}, "spacy_version": spacy.__version__,
              "dataset_sha256": {}, "records": {}}
    labels = set(NER_LABEL_USE_CASES)
    pipeline.analyse_text("warm up Alice Smith", layers=LAYERS, regex_first=False)
    for split in args.splits:
        path = args.data_root / SPLIT_FILES[split]
        report["dataset_sha256"][split] = sha256_file(path)
        rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        records, started = [], time.perf_counter()
        for row in rows:
            analysis = pipeline.analyse_text(row["text"], layers=LAYERS, regex_first=False)
            if [l.layer for l in analysis.layers] != LAYERS or any(l.status != "ok" for l in analysis.layers):
                raise RuntimeError(f"unexpected layer execution: {[(l.layer, l.status, l.error) for l in analysis.layers]}")
            by_layer = {l.layer: [_hit(h) for h in l.results if _positive(h)] for l in analysis.layers}
            record = {"id": row["id"], "expected": bool(row["expected_has_pii"]),
                      "expected_categories": list(row.get("expected_categories") or []),
                      "half": _half(row["group_id"]) if split == "dev" else None,
                      "regex": by_layer["regex"], "ner_shipped": by_layer["ner"]}
            for model_name, extra_nlp in extra_nlps.items():
                cp = normalize_with_offsets(row["text"], lowercase=False)
                record[f"ner_raw_cp@{model_name}"] = _raw_entities(extra_nlp, cp, labels, ner_postfilter)
                record[f"ner_shipped_cp@{model_name}"] = _raw_entities(extra_nlp, cp, labels, ner_postfilter, kept_only=True)
            if ner_postfilter is not None:
                record["ner_raw_cp"] = _raw_entities(nlp, normalize_with_offsets(row["text"], lowercase=False), labels, ner_postfilter)
                record["ner_raw_lc"] = _raw_entities(nlp, normalize_with_offsets(row["text"]), labels, ner_postfilter)
            records.append(record)
        report["records"][split] = records
        print(f"[{args.label}] {split}: n={len(rows)} {time.perf_counter() - started:.0f}s", file=sys.stderr)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report), encoding="utf-8")


# ---------------------------------------------------------------------------
# Analyse (pure Python)
# ---------------------------------------------------------------------------

def attach_features(shipped: list[dict], raw: list[dict]) -> list[dict]:
    """Give each shipped entity the corroboration features of the raw entity with the same span/label."""
    index = {(tuple(e["span"]), e["label"]): e for e in raw}
    out = []
    for ent in shipped:
        match = index.get((tuple(ent["span"]), ent["label"]), {})
        out.append({**{k: v for k, v in match.items() if k not in ("span", "label")}, **ent})
    return out


def build_config_records(old: dict, new: dict) -> dict[str, dict]:
    """Per configuration: split -> rows with ``regex`` (that tree's regex layer) and ``ner`` entities.

    Extra spaCy models dumped on the NEW tree add ``NEW@<model>`` (post-filtered) and
    ``NEW-raw@<model>`` (unfiltered) configurations with the same regex layer."""
    extra = list(new.get("extra_models", {}))
    names = list(CONFIG_NAMES) + [f"{kind}@{m}" for m in extra for kind in ("NEW", "NEW-raw")]
    configs: dict[str, dict] = {name: {} for name in names}
    for split, old_rows in old["records"].items():
        new_rows = {r["id"]: r for r in new["records"][split]}
        for name in names:
            configs[name][split] = []
        for o in old_rows:
            n = new_rows[o["id"]]
            if o["expected"] != n["expected"] or o["half"] != n["half"]:
                raise ValueError(f"dump mismatch for {o['id']}")
            base = {"id": o["id"], "expected": o["expected"], "half": o["half"],
                    "expected_categories": o["expected_categories"]}
            # OLD: the old tree's own regex and shipped NER; features from the same raw model on lower-cased text.
            configs["OLD"][split].append({**base, "regex": o["regex"],
                                          "ner": attach_features(o["ner_shipped"], n["ner_raw_lc"])})
            configs["NEW"][split].append({**base, "regex": n["regex"],
                                          "ner": attach_features(n["ner_shipped"], n["ner_raw_cp"])})
            configs["NEW-raw"][split].append({**base, "regex": n["regex"], "ner": n["ner_raw_cp"]})
            for m in extra:
                configs[f"NEW@{m}"][split].append({**base, "regex": n["regex"], "ner": n[f"ner_shipped_cp@{m}"]})
                configs[f"NEW-raw@{m}"][split].append({**base, "regex": n["regex"], "ner": n[f"ner_raw_cp@{m}"]})
    return configs


def old_parity(old: dict, new: dict) -> dict:
    """The OLD tree's shipped NER must equal the raw lower-cased entities (same model, no post-filter)."""
    mismatches = 0
    total = 0
    for split, rows in old["records"].items():
        for o, n in zip(rows, new["records"][split]):
            total += 1
            a = sorted((tuple(e["span"]), e["label"]) for e in o["ner_shipped"])
            b = sorted((tuple(e["span"]), e["label"]) for e in n["ner_raw_lc"])
            mismatches += int(a != b)
    return {"rows": total, "rows_where_old_shipped_ner_differs_from_raw_lowercase": mismatches}


def fmt_conf(c: dict) -> str:
    return f"{c['TP']} | {c['TN']} | {c['FP']} | {c['FN']} | {c['recall']:.3f} | {c['specificity']:.3f}"


def run_analyse(args: argparse.Namespace) -> None:
    old = json.loads(args.old.read_text(encoding="utf-8"))
    new = json.loads(args.new.read_text(encoding="utf-8"))
    if not new["has_postfilter_module"] or old["has_postfilter_module"]:
        raise SystemExit("--old must be the original tree and --new the installed-default tree")
    configs = build_config_records(old, new)
    result = {"scope": "detector-layer (regex+NER); not LLM-only", "old_commit": old["tree_commit_sha"],
              "new_commit": new["tree_commit_sha"], "old_flags": old["observed_flags"],
              "new_flags": new["observed_flags"], "dataset_sha256": new["dataset_sha256"],
              "design_splits": list(DESIGN_SPLITS), "old_parity": old_parity(old, new), "configs": {}}
    md = ["## Policy results (detector-layer; design = tune + personalized; check and openai post-review)\n"]
    for name in configs:
        variant, scores = choose_variant(configs[name], "ner")
        evaluated = evaluate_policies(configs[name], "ner", variant)
        result["configs"][name] = {
            "chosen_P2_variant": variant, "variant_design_scores": scores, "policies": evaluated,
            "P2_vs_P0": paired_vs(configs[name], "ner", "P0", "P2", variant),
            "P1_vs_P0": paired_vs(configs[name], "ner", "P0", "P1", variant),
            "P2_vs_P1": paired_vs(configs[name], "ner", "P1", "P2", variant),
            "amplification": amplification(configs[name], "ner")}
        md += [f"\n### {name} (chosen P2 variant on design splits: `{variant}`)\n",
               "| Split | n (pos) | Policy | TP | TN | FP | FN | Recall | Specificity |", "|---|---|---|---|---|---|---|---|---|"]
        for split in REPORT_SPLITS:
            e = evaluated[split]
            shown = ["P0", "P1", "P2", *[f"P2:{v}" for v in P2_VARIANTS if v != variant]]
            for p in shown:
                md.append(f"| {split} | {e['n']} ({e['positives']}) | {p} | {fmt_conf(e['policies'][p])} |")
        md += ["\nP3 and P4 flag exactly the P0 set (NER cannot create a positive); see the amplification table.\n"]
    md += ["\n## Change against P0 (positives gained / negatives newly flagged)\n",
           "| Config | Policy | " + " | ".join(f"{s} +TP/+FP" for s in REPORT_SPLITS) + " |",
           "|---|---|" + "---|" * len(REPORT_SPLITS)]
    for name in configs:
        cfg = result["configs"][name]
        for label, key in (("P1", "P1_vs_P0"), (f"P2 ({cfg['chosen_P2_variant']})", "P2_vs_P0")):
            cells_ = [f"{cfg[key][s].get('+TP', 0)}/{cfg[key][s].get('+FP', 0)}" for s in REPORT_SPLITS]
            md.append(f"| {name} | {label} | " + " | ".join(cells_) + " |")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "ner-role.json").write_text(json.dumps(result, indent=1), encoding="utf-8")
    (args.out / "ner-role-tables.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    dump = sub.add_parser("dump")
    dump.add_argument("splits", nargs="+", choices=sorted(SPLIT_FILES))
    dump.add_argument("--tree", type=Path, required=True)
    dump.add_argument("--label", required=True)
    dump.add_argument("--data-root", type=Path, required=True)
    dump.add_argument("--generated", type=Path, required=True)
    dump.add_argument("--out", type=Path, required=True)
    dump.add_argument("--extra-model", action="append", help="already-installed spaCy model to evaluate offline (no download)")
    analyse = sub.add_parser("analyse")
    analyse.add_argument("--old", type=Path, required=True)
    analyse.add_argument("--new", type=Path, required=True)
    analyse.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    (run_dump if args.command == "dump" else run_analyse)(args)


if __name__ == "__main__":
    main()
