"""Wave 3 confirmatory scoring driver (detector-layer scope: regex, NER, regex OR NER).

Scope: NOT LLM-only, NOT semantic-layer, NOT full-product. Every row is analysed with
``pipeline.analyse_text(layers=["regex", "ner"], regex_first=False)``: an explicit, non-empty layer list,
never the semantic layer, no Docker, no network. Governing documents:
``docs/research/preregistration-detector-v2-20261024.md`` and the freeze records. This file is part of the
freeze addendum (its sha256 is recorded there); nothing here may change after scoring starts.

Sub-commands
------------
``run``    score one frozen configuration (``--config``) on the fresh sets (and, for the equivalence check,
           on development-type sets). Writes aggregates-free per-row outputs: ids, flags, spans. NEVER row
           texts.
``equiv``  compare two run directories row by row (merge equivalence check, development rows only).
``pool``   build the blinded F2 review pool (union of flagged prompts plus the seeded 400-item audit sample).

Outputs per configuration under ``<out>/<label>/``:
``<set>.rows.jsonl``   detector_stats per-row records (regex / ner / union with positive, sensitivity,
                       categories, runtime action);
``<set>.spans.jsonl``  span_scoring prediction records (original-text offsets);
``f1.perturbed.jsonl`` H5 items: (positive F1 row, transform) pairs whose text the transform changed;
``run_meta.json``      configuration, observed flags, package and model versions, file hashes, counts.

Row texts are read in memory only. Nothing printed here contains a text.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Mapping, Sequence

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

LAYERS = ["regex", "ner"]
MAIN_CHECKOUT = Path("D:/Git Repositories/Privoke-Research-Project")
FRESH_DIR = "evaluation/results/fresh_sets_20261024"

# registered files (sha256 of the on-disk bytes, from docs/research/fresh-sets-freeze-20261024.md)
REGISTERED_SETS = {
    "f1": (f"{FRESH_DIR}/f1_piimb/piimb_fresh_f1.jsonl", "4ff0832331f0b3f8d58026cca5cb26fd25833f98864b5822fb7c8d21172a9167"),
    "f2": (f"{FRESH_DIR}/f2_natural_prompts/f2_natural_prompts.jsonl", "6cbf0a5ae551e4148a569c87d5e4308d5ffc8803ec69d161ed392b7ede093914"),
    "f3": (f"{FRESH_DIR}/f3_spy/f3_spy.jsonl", "42b2747af71c5db552ffc1c7b2082f039a0a3e1cbd4b4e512890d6f23c3a34ee"),
}
# development-type sets, used only for the merge-equivalence check and for harness tests (not held out)
EQUIVALENCE_SETS = {
    "dev": "evaluation/results/locked-public/development.jsonl",
    "personalized": "evaluation/datasets/privoke_personalized_synthetic.jsonl",
    "openai": "evaluation/datasets/privoke_openai_synthetic.jsonl",
    "dev_spans": f"{FRESH_DIR}/dev_spans.jsonl",
}
LOCKED_NAMES = {"final.jsonl"}

# H5 transforms (robustness_probe.TRANSFORMS names), pre-registration section 4
H5_TRANSFORMS = ["zero_width", "digits_space", "digits_dot", "digits_dash", "digits_words",
                 "email_bracket", "email_paren", "email_word", "lowercase", "uppercase"]

FLAG_ENV = ["PRIVOKE_CASE_PRESERVING_DETECTORS", "PRIVOKE_NER_POSTFILTER", "PRIVOKE_STRIP_FORMAT_CHARS",
            "PRIVOKE_CANONICALISE_DIGITS", "PRIVOKE_CANONICALISE_EMAIL_WORDS", "PRIVOKE_NER_CASELESS_GATE",
            "PRIVOKE_NER_MODEL"]
FLAG_ATTRS = {"case_preserving_detectors": None, "ner_postfilter": None, "strip_format_chars": None,
              "canonicalise_digits": None, "canonicalise_email_words": None, "ner_caseless_gate": None,
              "ner_model": None}
ABSENT = "absent"


def _expect(case=True, post=True, strip=False, digits=False, email=False, caseless=False, model="en_core_web_sm"):
    return {"case_preserving_detectors": case, "ner_postfilter": post, "strip_format_chars": strip,
            "canonicalise_digits": digits, "canonicalise_email_words": email, "ner_caseless_gate": caseless,
            "ner_model": model}


_O_EXPECT = {k: ABSENT for k in FLAG_ATTRS}
_N_EXPECT = {**{k: ABSENT for k in FLAG_ATTRS}, "case_preserving_detectors": True, "ner_postfilter": True}

# Frozen configuration table (pre-registration section 3). ``tree`` is a subdirectory of --trees-root:
#   O = export of e6c177ff, N = export of e70e3a2e, C = export of research/w3-candidate (N + flags + NER model).
CONFIGS: dict[str, dict] = {
    "O": {"tree": "O", "env": {}, "expect": _O_EXPECT},
    "N": {"tree": "N", "env": {}, "expect": _N_EXPECT},
    "N+strip": {"tree": "C", "env": {"PRIVOKE_STRIP_FORMAT_CHARS": "1"}, "expect": _expect(strip=True)},
    "N+digits": {"tree": "C", "env": {"PRIVOKE_CANONICALISE_DIGITS": "1"}, "expect": _expect(digits=True)},
    "N+email": {"tree": "C", "env": {"PRIVOKE_CANONICALISE_EMAIL_WORDS": "1"}, "expect": _expect(email=True)},
    "N+caseless": {"tree": "C", "env": {"PRIVOKE_NER_CASELESS_GATE": "1"}, "expect": _expect(caseless=True)},
    "N+all": {"tree": "C", "env": {"PRIVOKE_STRIP_FORMAT_CHARS": "1", "PRIVOKE_CANONICALISE_DIGITS": "1",
                                   "PRIVOKE_CANONICALISE_EMAIL_WORDS": "1", "PRIVOKE_NER_CASELESS_GATE": "1"},
              "expect": _expect(strip=True, digits=True, email=True, caseless=True)},
    "N+lg": {"tree": "C", "env": {"PRIVOKE_NER_MODEL": "en_core_web_lg"}, "expect": _expect(model="en_core_web_lg")},
    "N+trf": {"tree": "C", "env": {"PRIVOKE_NER_MODEL": "en_core_web_trf"}, "expect": _expect(model="en_core_web_trf")},
    # equivalence check only: the merged candidate tree with every new flag off (must equal N)
    "C0": {"tree": "C", "env": {}, "expect": _expect()},
}
# H5 perturbed items are scored for these configurations only (N is the reference of H5)
PERTURBED_CONFIGS = ("N", "N+strip", "N+digits", "N+email", "N+caseless", "N+all")
SCORED_CONFIGS = ["O", "N", "N+strip", "N+digits", "N+email", "N+caseless", "N+all", "N+lg", "N+trf"]


def label_of(config: str) -> str:
    return config.replace("+", "_")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stratum_of(row: Mapping) -> str | None:
    for key in ("source_dataset", "source", "domain", "scenario", "task_name"):
        if row.get(key):
            return str(row[key])
    return None


def refuse_locked(path: Path) -> None:
    if path.name in LOCKED_NAMES:
        raise SystemExit(f"refusing locked held-out file {path}")


def load_jsonl(path: Path) -> list[dict]:
    refuse_locked(path)
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def dump_jsonl(path: Path, records: Sequence[Mapping]) -> str:
    """Write atomically (temp file then rename); return sha256 of the bytes written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records).encode("utf-8")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, path)
    return hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------- one row


def span_record(analysis, row_id: str, group_id) -> dict:
    """Prediction record in the format of ``span_scoring.extract_predictions`` (same logic, one analysis)."""
    rec = {"id": row_id, "group_id": group_id, "layers": {}, "fired": {}, "spanless": {}}
    for layer in analysis.layers:
        spans, spanless, fired = [], 0, False
        for res in layer.results:
            cls = res.classification
            cats = [c.name for c in cls.categories()]
            if cls.sensitivity().name == "S0" and not cats:
                continue
            fired = True
            if res.span is None:
                spanless += 1
                continue
            meta = res.metadata or {}
            source = meta.get("label") or meta.get("rule_name") or meta.get("rule") or ""
            spans.append({"start": int(res.span[0]), "end": int(res.span[1]), "categories": cats,
                          "sensitivity": cls.sensitivity().name, "source": str(source)})
        rec["layers"][layer.layer] = spans
        rec["fired"][layer.layer] = fired
        rec["spanless"][layer.layer] = spanless
    return rec


def analyse_row(pipeline, eid, text: str):
    """Run the detector layers; return (analysis, per-layer rows, union row). Raises on any layer anomaly."""
    analysis = pipeline.analyse_text(text, layers=LAYERS, regex_first=False)
    if [l.layer for l in analysis.layers] != LAYERS or any(l.status != "ok" for l in analysis.layers):
        raise RuntimeError(f"unexpected layer execution: {[(l.layer, l.status, l.error) for l in analysis.layers]}")
    layer_rows = {l.layer: eid.layer_row(l.results, pipeline.strongest_result) for l in analysis.layers}
    union = eid.union_row(layer_rows["regex"], layer_rows["ner"], analysis)
    return analysis, layer_rows, union


# --------------------------------------------------------------------------- run


def resolve_set(name: str, data_root: Path, test_mode: bool, overrides: Mapping[str, Path]) -> tuple[Path, str | None]:
    if name in overrides:
        if not test_mode:
            raise SystemExit("--set-path overrides require --test-mode (stand-in data, never the registered sets)")
        return overrides[name], None
    if name in REGISTERED_SETS:
        rel, sha = REGISTERED_SETS[name]
        return data_root / rel, sha
    if name in EQUIVALENCE_SETS:
        return data_root / EQUIVALENCE_SETS[name], None
    raise SystemExit(f"unknown set {name}")


def command_run(args) -> None:
    cfg = CONFIGS[args.config]
    out_dir = args.out / label_of(args.config)
    overrides = dict(item.split("=", 1) for item in args.set_path)
    overrides = {k: Path(v) for k, v in overrides.items()}
    for key in FLAG_ENV:  # never inherit a flag from the calling shell
        os.environ.pop(key, None)
    os.environ.update(cfg["env"])
    tree = args.trees_root / cfg["tree"]
    sys.path[:0] = [str(tree / "extension/client-runtime"), str(tree / "shared/python"), str(args.generated)]
    import spacy  # noqa: F401  pre-import in the main thread (layer threads race on first import)
    import evaluate_installed_detectors as eid
    import robustness_probe as rp
    from src import pipeline
    from src.config import GLOBAL_CONFIG
    from src.NER import EntityNERDetector
    from src.regex.rule_detector import RuleDetector

    observed = {attr: getattr(GLOBAL_CONFIG, attr, ABSENT) for attr in FLAG_ATTRS}
    if observed != cfg["expect"]:
        raise SystemExit(f"observed flags {observed} differ from the frozen configuration {cfg['expect']}")
    RuleDetector()
    EntityNERDetector()
    model_name = observed["ner_model"] if observed["ner_model"] != ABSENT else "en_core_web_sm"
    try:
        model_version = importlib.metadata.version(model_name.replace("_", "-"))
    except importlib.metadata.PackageNotFoundError:
        model_version = "unknown"
    pipeline.analyse_text("warm up Alice Smith", layers=LAYERS, regex_first=False)
    export_sha = (tree / "EXPORT_SHA")
    meta = {"config": args.config, "label": label_of(args.config), "tree": cfg["tree"],
            "tree_export_sha": export_sha.read_text().strip() if export_sha.exists() else "unknown",
            "env": cfg["env"], "observed_flags": observed, "ner_model": model_name, "ner_model_version": model_version,
            "python": sys.version.split()[0], "spacy": spacy.__version__,
            "packages": {p: _version(p) for p in ("numpy", "torch", "presidio-analyzer", "transformers", "en-core-web-sm")},
            "layers": LAYERS, "regex_first": False, "scope": "detector-layer (regex, NER, union); not LLM-only",
            "test_mode": bool(args.test_mode), "sets": {}, "driver_sha256": sha256_file(Path(__file__)),
            "started_unix": time.time()}
    meta_path = out_dir / "run_meta.json"
    if meta_path.exists():
        previous = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["sets"] = previous.get("sets", {})
        meta["resumed"] = True
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in args.sets:
        rows_path = out_dir / f"{name}.rows.jsonl"
        if rows_path.exists():
            print(f"[{args.config}] {name}: output exists, not rescoring (single-scoring rule)", file=sys.stderr, flush=True)
            continue
        path, expected_sha = resolve_set(name, args.data_root, args.test_mode, overrides)
        actual_sha = sha256_file(path)
        if expected_sha is not None and actual_sha != expected_sha:
            raise SystemExit(f"{name}: file hash {actual_sha} differs from the registered {expected_sha}")
        rows = load_jsonl(path)
        if args.limit:
            rows = rows[: args.limit]
        records, spans = [], []
        for row in rows:
            analysis, layer_rows, union = analyse_row(pipeline, eid, row["text"])
            label = row.get("expected_has_pii")
            records.append({"split": name, "example_id": str(row["id"]), "group_id": row.get("group_id"),
                            "stratum": stratum_of(row), "expected_has_pii": None if label is None else bool(label),
                            "regex": layer_rows["regex"], "ner": layer_rows["ner"], "union": union})
            if name != "f2":
                spans.append(span_record(analysis, str(row["id"]), row.get("group_id")))
        sha_rows = dump_jsonl(rows_path, records)
        sha_spans = dump_jsonl(out_dir / f"{name}.spans.jsonl", spans) if spans else None
        meta["sets"][name] = {"path_sha256": actual_sha, "n_rows": len(rows), "rows_sha256": sha_rows,
                              "spans_sha256": sha_spans}
        print(f"[{args.config}] {name}: scored {len(rows)} rows", file=sys.stderr, flush=True)
        meta["elapsed_s"] = time.time() - meta["started_unix"]
        meta_path.write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")
    perturbed_path = out_dir / "f1.perturbed.jsonl"
    if "f1" in args.sets and args.config in PERTURBED_CONFIGS and not args.no_perturbed and not perturbed_path.exists():
        path, _ = resolve_set("f1", args.data_root, args.test_mode, overrides)
        rows = load_jsonl(path)
        if args.limit:
            rows = rows[: args.limit]
        items = []
        for row in rows:
            if not row.get("expected_has_pii"):
                continue
            for transform in args.transforms:
                changed = rp.apply_transform(transform, row["text"], row["id"])
                if changed == row["text"]:
                    continue
                _, layer_rows, union = analyse_row(pipeline, eid, changed)
                items.append({"example_id": str(row["id"]), "group_id": row.get("group_id"), "transform": transform,
                              "regex": layer_rows["regex"]["positive"], "ner": layer_rows["ner"]["positive"],
                              "union": union["positive"]})
        meta["sets"]["f1_perturbed"] = {"n_items": len(items), "items_sha256": dump_jsonl(perturbed_path, items),
                                        "transforms": list(args.transforms)}
        print(f"[{args.config}] f1 perturbed: {len(items)} items", file=sys.stderr, flush=True)
    meta["elapsed_s"] = time.time() - meta["started_unix"]
    meta_path.write_text(json.dumps(meta, indent=1, sort_keys=True), encoding="utf-8")


def _version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "absent"


# --------------------------------------------------------------------------- equivalence


def command_equiv(args) -> None:
    """Row-by-row equality of two run directories (rows and spans). Development-type sets only."""
    report = {"a": str(args.a), "b": str(args.b), "sets": {}}
    ok = True
    for name in args.sets:
        if name in REGISTERED_SETS:
            raise SystemExit("equivalence check is restricted to development-type sets")
        ra, rb = load_jsonl(args.a / f"{name}.rows.jsonl"), load_jsonl(args.b / f"{name}.rows.jsonl")
        mism = [i for i, (x, y) in enumerate(zip(ra, rb)) if x != y]
        entry = {"n_a": len(ra), "n_b": len(rb), "row_mismatches": len(mism)}
        pa, pb = args.a / f"{name}.spans.jsonl", args.b / f"{name}.spans.jsonl"
        if pa.exists() and pb.exists():
            sa, sb = load_jsonl(pa), load_jsonl(pb)
            entry["span_mismatches"] = sum(1 for x, y in zip(sa, sb) if x != y) + abs(len(sa) - len(sb))
        entry["identical"] = len(ra) == len(rb) and not mism and entry.get("span_mismatches", 0) == 0
        ok = ok and entry["identical"]
        report["sets"][name] = entry
    report["identical"] = ok
    text = json.dumps(report, indent=1, sort_keys=True)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    print(text)


# --------------------------------------------------------------------------- F2 review pool


def build_pool(f2_rows_by_config: Mapping[str, Sequence[Mapping]], key: Mapping, packets_dir: Path, out_dir: Path,
               audit_size: int = 400, packet_size: int = 100) -> dict:
    """Blinded review pool: union of prompts flagged (union layer, positive rule) by any configuration plus the
    first ``audit_size`` items of the key's seeded audit order that no configuration flags.

    Packets carry only ``{"item", "text"}`` (the opaque id and the prompt). The coordinator files (membership,
    audit marks, per-configuration flag lists) are kept apart and are not for raters.
    """
    opaque_of = {f2: opaque for opaque, f2 in key["key"].items()}
    flagged_by: dict[str, list[str]] = {}
    for config, rows in f2_rows_by_config.items():
        for row in rows:
            if row["union"]["positive"]:
                flagged_by.setdefault(row["example_id"], []).append(config)
    all_ids = {row["example_id"] for rows in f2_rows_by_config.values() for row in rows}
    if all_ids != set(opaque_of):
        raise ValueError("F2 ids of the scored rows differ from the adjudication key")
    audit = []
    for opaque in key["audit_order"]:
        if len(audit) == audit_size:
            break
        if key["key"][opaque] not in flagged_by:
            audit.append(opaque)
    if len(audit) < audit_size:
        raise ValueError("not enough unflagged prompts for the audit sample")
    pool = sorted({opaque_of[i] for i in flagged_by} | set(audit))
    texts = {}
    for packet in sorted(packets_dir.glob("packet-*.jsonl")):
        for rec in load_jsonl(packet):
            texts[rec["item"]] = rec["text"]
    if set(pool) - set(texts):
        raise ValueError("pooled item missing from the blinded packets")
    out_packets = out_dir / "packets"
    (out_dir / "coordinator").mkdir(parents=True, exist_ok=True)
    packets = []
    for number, start in enumerate(range(0, len(pool), packet_size), start=1):
        block = pool[start:start + packet_size]
        name = f"pool-packet-{number:03d}.jsonl"
        sha = dump_jsonl(out_packets / name, [{"item": item, "text": texts[item]} for item in block])
        packets.append({"packet": name, "items": len(block), "first": block[0], "last": block[-1], "sha256": sha})
    membership = {opaque_of[i]: sorted(cfgs) for i, cfgs in flagged_by.items()}
    per_config = {c: sum(1 for r in rows if r["union"]["positive"]) for c, rows in f2_rows_by_config.items()}
    manifest = {"set": "F2 review pool", "purpose": "blinded rating packets for the pooled adjudication; items carry only "
                "an opaque id and the prompt text; no labels, no detector output",
                "pool_size": len(pool), "flagged_union": len(flagged_by), "audit_items": len(audit),
                "per_config_flagged_union_layer": per_config, "packet_size": packet_size, "packets": packets,
                "audit_rule": "first 400 items of the key's audit_order that no configuration flags (union layer, positive rule)",
                "configurations": list(f2_rows_by_config)}
    (out_dir / "coordinator" / "pool_manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8")
    (out_dir / "coordinator" / "pool_membership.json").write_text(
        json.dumps({"flagged_by": membership, "audit": audit}, sort_keys=True), encoding="utf-8")
    return manifest


def command_pool(args) -> None:
    f2_rows = {c: load_jsonl(args.results / label_of(c) / "f2.rows.jsonl") for c in SCORED_CONFIGS}
    key = json.loads((args.adjudication / "coordinator" / "adjudication_key.json").read_text(encoding="utf-8"))
    manifest = build_pool(f2_rows, key, args.adjudication / "packets", args.out)
    print(json.dumps({k: manifest[k] for k in ("pool_size", "flagged_union", "audit_items", "per_config_flagged_union_layer")},
                     indent=1, sort_keys=True))


# --------------------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="score one frozen configuration")
    run.add_argument("--config", choices=sorted(CONFIGS), required=True)
    run.add_argument("--trees-root", type=Path, required=True, help="directory holding the O, N and C exports")
    run.add_argument("--generated", type=Path, required=True, help="protobuf generated directory")
    run.add_argument("--data-root", type=Path, default=MAIN_CHECKOUT)
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--sets", nargs="+", default=["f1", "f3", "f2"],
                     choices=sorted([*REGISTERED_SETS, *EQUIVALENCE_SETS]))
    run.add_argument("--transforms", nargs="+", default=H5_TRANSFORMS, choices=H5_TRANSFORMS)
    run.add_argument("--no-perturbed", action="store_true")
    run.add_argument("--test-mode", action="store_true", help="stand-in data / limits for harness tests only")
    run.add_argument("--set-path", nargs="*", default=[], metavar="NAME=PATH", help="test mode only")
    run.add_argument("--limit", type=int, default=0, help="test mode only: first N rows")
    run.set_defaults(func=command_run)
    eq = sub.add_parser("equiv", help="row-level equality of two run directories (development sets)")
    eq.add_argument("--a", type=Path, required=True)
    eq.add_argument("--b", type=Path, required=True)
    eq.add_argument("--sets", nargs="+", required=True)
    eq.add_argument("--out", type=Path, default=None)
    eq.set_defaults(func=command_equiv)
    pl = sub.add_parser("pool", help="build the blinded F2 review pool")
    pl.add_argument("--results", type=Path, required=True)
    pl.add_argument("--adjudication", type=Path, required=True)
    pl.add_argument("--out", type=Path, required=True)
    pl.set_defaults(func=command_pool)
    args = parser.parse_args(argv)
    if getattr(args, "limit", 0) and not args.test_mode:
        raise SystemExit("--limit requires --test-mode")
    if getattr(args, "test_mode", False) is False and getattr(args, "set_path", None):
        raise SystemExit("--set-path requires --test-mode")
    args.func(args)


if __name__ == "__main__":
    main()
