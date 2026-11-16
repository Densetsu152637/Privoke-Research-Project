"""WARN intervention experiment (WARNINT-20261116): how much sensitive transmission does each
post-WARN intervention actually prevent?

Scope: product detector pipeline (regex + NER layers, explicit layer list, product default
``regex_first=True``) on the declared development set. This is product/intervention evidence, NOT
LLM-only or semantic evidence (the semantic layer needs the model-streaming service and is not run).

Arms (the action is the pipeline's ALLOW / WARN / BLOCK for the prompt):

* ``plain_warn``    WARN forwards the original request (shipped default). BLOCK is not sent.
* ``warn_mask``     WARN replaces every positive detector span with a typed placeholder before the
                    request is sent (the extension's opt-in ``warnMasking`` setting). BLOCK is not sent.
* ``warn_confirm``  WARN asks the user; cancel = not sent, confirm = original sent. The user's
                    compliance rate ``c`` (probability of cancelling a WARN) is unknown, so results are
                    an ANALYTIC function of ``c``, never a measurement. BLOCK is not sent.
* ``block``         WARN and BLOCK are both not sent.

``mask_text`` / ``normalize_spans`` below are a line-for-line port of ``extension/src/redaction.js``;
``extension/test/fixtures/mask-vectors.json`` is run through both implementations.

Commands (host Python; see the experiment record for the exact invocation)::

    warn_intervention.py extract --gold dev_spans.jsonl --out results.json
    warn_intervention.py rederive results.json          # recompute every number from the JSON alone
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Iterable, Mapping, Sequence

STUDY_ID = "WARNINT-20261116"
SEED = 20261116  # no stochastic step exists; recorded so any future sampling is pinned
LAYERS = ["regex", "ner"]
REGEX_FIRST = True  # product default (extension setting waitForRegex=true)
ARMS = ("plain_warn", "warn_mask", "warn_confirm", "block")
SCOPES = ("all", "core")
COMPLIANCE_GRID = [round(i / 10, 1) for i in range(11)]
MANIFEST_LF_SHA256 = "43e1d382da6b9ae29d6cb6e76ae16876388b430f1476e1ef32bcc107a109a4fe"
LOCKED_NAMES = ("test_locked.jsonl", "locked.jsonl")


# --------------------------------------------------------------------------- masking (port of redaction.js)

def _clean_category(value) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(ch if ("A" <= ch <= "Z" or "0" <= ch <= "9" or ch == "_") else "_"
                   for ch in value.upper())[:32]


def normalize_spans(spans: Iterable[Mapping] | None, length: int) -> list[dict]:
    """Validate, sort and merge overlapping spans (adjacent spans stay separate)."""
    valid = []
    for span in spans or []:
        start, end = span.get("start"), span.get("end")
        if type(start) is not int or type(end) is not int:
            continue
        if start < 0 or end <= start or end > length:
            continue
        cats = [_clean_category(c) for c in (span.get("categories") or [])]
        valid.append({"start": start, "end": end, "categories": [c for c in cats if c]})
    valid.sort(key=lambda s: (s["start"], s["end"]))
    merged: list[dict] = []
    for span in valid:
        last = merged[-1] if merged else None
        if last is not None and span["start"] < last["end"]:
            last["end"] = max(last["end"], span["end"])
            for c in span["categories"]:
                if c not in last["categories"]:
                    last["categories"].append(c)
        else:
            merged.append({"start": span["start"], "end": span["end"],
                           "categories": list(dict.fromkeys(span["categories"]))})
    for span in merged:
        span["categories"].sort()
    return merged


def placeholder_for(categories: Sequence[str]) -> str:
    return f"[PRIVOKE_{categories[0] if len(categories) == 1 else 'SENSITIVE'}]"


def mask_text(text: str, spans: Iterable[Mapping] | None) -> dict:
    """Replace merged spans by typed placeholders. Offsets are code points (Python str indices)."""
    merged = normalize_spans(spans, len(text))
    out, cursor, masked = [], 0, 0
    for span in merged:
        out.append(text[cursor:span["start"]])
        out.append(placeholder_for(span["categories"]))
        masked += span["end"] - span["start"]
        cursor = span["end"]
    out.append(text[cursor:])
    return {"text": "".join(out), "spans": merged, "masked_chars": masked}


# --------------------------------------------------------------------------- statistics

def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float | None, float | None]:
    if n == 0:
        return None, None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def proportion(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "p": (k / n if n else None), "wilson95": [lo, hi]}


def exact_sign_test(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the discordant counts b, c."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(0, min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


# --------------------------------------------------------------------------- interval helpers

def _merge(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for s, e in sorted(i for i in intervals if i[1] > i[0]):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]


def _overlap(a: tuple[int, int], intervals: Sequence[tuple[int, int]]) -> int:
    return sum(max(0, min(a[1], e) - max(a[0], s)) for s, e in intervals)


# --------------------------------------------------------------------------- per-prompt outcomes

def prompt_outcome(arm: str, record: Mapping, scope: str, compliance: float | None = None) -> dict:
    """Outcome of one prompt under one arm.

    ``record`` carries ``text_len``, ``action``, ``gold`` (list of ``{start, end, core}``) and ``pred``
    (list of ``{start, end, categories}``). For ``warn_confirm`` the outcome is the deterministic result
    when the user CONFIRMS (``compliance=0``) or CANCELS (``compliance=1``); intermediate compliance is
    handled analytically by ``confirm_expected``.
    """
    action = record["action"]
    gold = [g for g in record["gold"] if scope == "all" or g["core"]]
    if arm == "plain_warn":
        sent, mask = action != "BLOCK", False
    elif arm == "warn_mask":
        sent, mask = action != "BLOCK", action == "WARN"
    elif arm == "block":
        sent, mask = action == "ALLOW", False
    elif arm == "warn_confirm":
        if compliance not in (0, 1):
            raise ValueError("warn_confirm is deterministic only at compliance 0 or 1; use confirm_expected")
        sent, mask = (action == "ALLOW") or (action == "WARN" and compliance == 0), False
    else:
        raise ValueError(arm)
    merged = normalize_spans(record["pred"], record["text_len"]) if mask else []
    mask_iv = _merge((s["start"], s["end"]) for s in merged)
    masked_chars = sum(e - s for s, e in mask_iv)
    all_gold_iv = _merge((g["start"], g["end"]) for g in record["gold"])
    over_chars = masked_chars - sum(_overlap(iv, all_gold_iv) for iv in mask_iv) if mask_iv else 0
    gold_total = len(gold)
    intact = removed = 0
    gold_chars = residual_chars = 0
    for g in gold:
        length = g["end"] - g["start"]
        hit = _overlap((g["start"], g["end"]), mask_iv)
        gold_chars += length
        if sent:
            residual_chars += length - hit
            intact += hit == 0
            removed += hit == length
    exposed_intact = bool(sent and intact > 0)
    exposed_any = bool(sent and any(
        _overlap((g["start"], g["end"]), mask_iv) < g["end"] - g["start"] for g in gold))
    return {
        "sent": sent, "altered": bool(sent and masked_chars > 0), "masked_chars": masked_chars if sent else 0,
        "over_chars": over_chars if sent else 0, "gold_spans": gold_total,
        "intact_spans": intact if sent else 0, "removed_spans": removed if sent else 0,
        "gold_chars": gold_chars, "residual_chars": residual_chars if sent else 0,
        "exposed_intact": exposed_intact, "exposed_any": exposed_any,
        "text_len": record["text_len"], "interrupted": action == "WARN" if arm == "warn_confirm" else False,
    }


def confirm_expected(sensitive: Sequence[Mapping], compliance: float, scope: str) -> dict:
    """ANALYTIC expectation for WARN+CONFIRM at compliance ``c`` (probability a WARN is cancelled).

    Prompts with action ALLOW are sent whatever ``c`` is, BLOCK is not sent, and a WARN is sent with
    probability ``1-c`` (the original text). Linear in ``c``; ``c=0`` equals plain WARN and ``c=1``
    equals the BLOCK arm. This is an analytic bound under an assumed user behaviour, not a measurement.
    """
    n = len(sensitive)
    expected_intact = expected_any = expected_spans = 0.0
    for rec in sensitive:
        sent_prob = 1.0 if rec["action"] == "ALLOW" else (1 - compliance if rec["action"] == "WARN" else 0.0)
        keep = prompt_outcome("plain_warn", rec, scope)
        expected_intact += sent_prob * keep["exposed_intact"]
        expected_any += sent_prob * keep["exposed_any"]
        expected_spans += sent_prob * keep["intact_spans"]
    return {"c": compliance, "label": "analytic bound, not a measurement",
            "transmitted_intact_fraction": expected_intact / n if n else None,
            "prevented_fraction": 1 - expected_intact / n if n else None,
            "transmitted_any_residual_fraction": expected_any / n if n else None,
            "expected_intact_spans": expected_spans}


# --------------------------------------------------------------------------- aggregation

def summarise(records: Sequence[Mapping], scope: str) -> dict:
    """All headline numbers for one scope, from per-prompt records only."""
    sensitive = [r for r in records if any(scope == "all" or g["core"] for g in r["gold"])]
    clean = [r for r in records if not r["gold"]]
    # Prompts whose only gold is out-of-scope (core scope, attribute-only) are neither sensitive nor clean.
    arms: dict[str, dict] = {}
    for arm in ("plain_warn", "warn_mask", "block"):
        arms[arm] = _arm_block(arm, [prompt_outcome(arm, r, scope) for r in sensitive],
                               [prompt_outcome(arm, r, scope) for r in clean])
    # warn_confirm at c=0 equals plain_warn and at c=1 equals block; its content is the analytic sweep.
    arms["warn_confirm"] = {
        "note": "WARN+CONFIRM depends on the unknown compliance rate c; only the analytic sweep is reported. "
                "c=0 equals plain_warn, c=1 equals block.",
        "sweep": [confirm_expected(sensitive, c, scope) for c in COMPLIANCE_GRID],
        "clean_prompts_interrupted": proportion(sum(r["action"] == "WARN" for r in clean), len(clean)),
        "clean_prompts_cancelled_by_compliant_user_expected_fraction_at_c": {
            "formula": "c * (clean WARN rate)", "clean_warn_rate": proportion(
                sum(r["action"] == "WARN" for r in clean), len(clean))["p"]},
    }
    mask, plain = arms["warn_mask"], arms["plain_warn"]
    exposed_plain = [prompt_outcome("plain_warn", r, scope)["exposed_intact"] for r in sensitive]
    exposed_mask = [prompt_outcome("warn_mask", r, scope)["exposed_intact"] for r in sensitive]
    b = sum(p and not m for p, m in zip(exposed_plain, exposed_mask))
    c_rev = sum(m and not p for p, m in zip(exposed_plain, exposed_mask))
    n_s = len(sensitive)
    allow_intact = sum(r["action"] == "ALLOW" and prompt_outcome("plain_warn", r, scope)["exposed_intact"] for r in sensitive)
    warn_intact = sum(r["action"] == "WARN" and prompt_outcome("plain_warn", r, scope)["exposed_intact"] for r in sensitive)
    mask_intact = mask["transmitted_with_intact_gold_span"]["k"]
    crit = None
    if warn_intact:
        crit = 1 - (mask_intact - allow_intact) / warn_intact
    warned = [r for r in sensitive if r["action"] == "WARN"]
    warn_subset = {
        "n": len(warned),
        "note": "Sensitive prompts the pipeline WARNs: the only prompts these interventions can change. "
                "ALLOW prompts are detector misses and BLOCK prompts are already not sent.",
        "transmitted_with_intact_gold_span": {
            arm: proportion(sum(prompt_outcome(arm, r, scope)["exposed_intact"] for r in warned), len(warned))
            for arm in ("plain_warn", "warn_mask", "block")},
        "confirm_expected_intact_at_c": {
            "label": "analytic bound, not a measurement", "formula": "(1-c) * plain_warn count",
            "plain_warn_count": sum(prompt_outcome("plain_warn", r, scope)["exposed_intact"] for r in warned)},
    }
    action_counts = {a: {"sensitive": sum(r["action"] == a for r in sensitive),
                         "clean": sum(r["action"] == a for r in clean)} for a in ("ALLOW", "WARN", "BLOCK")}
    return {
        "scope": scope, "sensitive_prompts": n_s, "clean_prompts": len(clean),
        "gold_spans": sum(sum(1 for g in r["gold"] if scope == "all" or g["core"]) for r in sensitive),
        "action_counts": action_counts, "warn_subset": warn_subset, "arms": arms,
        "mask_vs_plain_warn": {
            "prompts_exposed_under_plain_not_under_mask": b, "prompts_exposed_under_mask_not_under_plain": c_rev,
            "exact_sign_test_p": exact_sign_test(b, c_rev),
            "mask_exposure_bound": "WARN+MASK exposure is bounded by detector span recall: a gold span that "
                                   "no predicted span fully covers is transmitted (partly or fully intact), "
                                   "and prompts the pipeline ALLOWs are never touched.",
        },
        "confirm_vs_mask": {
            "allow_prompts_with_intact_span": allow_intact, "warn_prompts_with_intact_span": warn_intact,
            "mask_transmitted_intact": mask_intact,
            "critical_compliance_for_confirm_to_match_mask": crit,
            "reading": "None means no WARN prompt exposes an intact span. A value above 1 means even universal "
                       "cancellation cannot reach WARN+MASK's exposure; a value below 0 means MASK is worse "
                       "than plain WARN. Analytic, depends on the unknown compliance rate.",
        },
    }


def _arm_block(arm: str, rows: list[dict], clean_rows: list[dict]) -> dict:
    n = len(rows)
    sent = sum(r["sent"] for r in rows)
    gold_spans = sum(r["gold_spans"] for r in rows)
    intact = sum(r["intact_spans"] for r in rows)
    removed = sum(r["removed_spans"] for r in rows)
    gold_chars = sum(r["gold_chars"] for r in rows)
    residual_chars = sum(r["residual_chars"] for r in rows)
    masked = sum(r["masked_chars"] for r in rows)
    over = sum(r["over_chars"] for r in rows)
    text_chars = sum(r["text_len"] for r in rows)
    c_masked = sum(r["masked_chars"] for r in clean_rows)
    c_text = sum(r["text_len"] for r in clean_rows)
    return {
        "sensitive_prompts_sent": proportion(sent, n),
        "transmitted_with_intact_gold_span": proportion(sum(r["exposed_intact"] for r in rows), n),
        "transmitted_with_any_unmasked_gold_char": proportion(sum(r["exposed_any"] for r in rows), n),
        "prevented_fraction_intact_definition": proportion(n - sum(r["exposed_intact"] for r in rows), n),
        "gold_spans_transmitted_intact": proportion(intact, gold_spans),
        "gold_spans_fully_removed_when_sent": proportion(removed, gold_spans),
        "gold_chars_transmitted": proportion(residual_chars, gold_chars),
        "sensitive_prompts_altered": proportion(sum(r["altered"] for r in rows), n),
        "masked_chars_total": masked, "masked_chars_outside_gold": over,
        "over_redaction_share": proportion(over, masked),
        "over_masked_chars_per_1k_sensitive_prompt_chars": (1000 * over / text_chars if text_chars else None),
        "clean_prompts_altered": proportion(sum(r["altered"] for r in clean_rows), len(clean_rows)),
        "clean_prompts_not_sent": proportion(sum(not r["sent"] for r in clean_rows), len(clean_rows)),
        "clean_masked_chars": c_masked,
        "clean_masked_chars_per_1k": (1000 * c_masked / c_text if c_text else None),
        "over_redaction_share_incl_clean": proportion(over + c_masked, masked + c_masked),
    }


# --------------------------------------------------------------------------- inputs

def sha256_lf(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def sha256_raw(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_gold(path: Path) -> list[dict]:
    if Path(path).name in LOCKED_NAMES:
        raise SystemExit(f"refusing locked held-out file {path}")
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def freeze_inputs(gold_path: Path) -> dict:
    lf = sha256_lf(gold_path)
    if lf != MANIFEST_LF_SHA256:
        raise SystemExit(f"gold file hash {lf} does not match the frozen development-spans manifest")
    return {"path_name": Path(gold_path).name, "sha256_raw": sha256_raw(gold_path), "sha256_lf_normalised": lf,
            "manifest_sha256": MANIFEST_LF_SHA256}


# --------------------------------------------------------------------------- extraction

def extract(tree: Path, gold_path: Path, limit: int | None = None) -> dict:
    inputs = freeze_inputs(gold_path)  # freeze by hash BEFORE any prompt is scored
    rows = load_gold(gold_path)
    if limit:
        rows = rows[:limit]
    if any(r.get("protocol_partition") != "development_spans" for r in rows):
        raise SystemExit("only the development_spans partition is declared for this experiment")
    sys.path[:0] = [str(Path(tree) / "extension/client-runtime"), str(Path(tree) / "shared/python"),
                    str(Path(__file__).resolve().parent)]
    import spacy  # noqa: F401  pre-import in the main thread (layer threads race on first import)
    from src import pipeline
    from src.NER import EntityNERDetector
    from src.regex.rule_detector import RuleDetector
    import span_scoring as ss

    RuleDetector()
    EntityNERDetector()
    pipeline.analyse_text("warm up Alice Smith", layers=LAYERS, regex_first=REGEX_FIRST)
    out, mask_check = [], 0
    for row in rows:
        text = row["text"]
        analysis = pipeline.analyse_text(text, layers=LAYERS, regex_first=REGEX_FIRST)
        names = [l.layer for l in analysis.layers]
        if names != LAYERS:
            raise RuntimeError(f"unexpected executed layers {names}")
        regex_action = next(l for l in analysis.layers if l.layer == "regex")
        for layer in analysis.layers:
            ok = layer.status == "ok" or (layer.status == "skipped" and layer.layer != "regex"
                                          and analysis.action.name == "BLOCK")
            if not ok:
                raise RuntimeError(f"layer {layer.layer} status {layer.status}: {layer.error}")
        pred, spanless = [], 0
        for layer in analysis.layers:
            if layer.status != "ok":
                continue
            for res in layer.results:
                cls = res.classification
                cats = [c.name for c in cls.categories()]
                if cls.sensitivity().name == "S0" and not cats:
                    continue
                if res.span is None:
                    spanless += 1
                    continue
                pred.append({"start": int(res.span[0]), "end": int(res.span[1]), "categories": cats,
                             "layer": layer.layer})
        gold = [{"start": int(e["start"]), "end": int(e["end"]), "label": e["label"],
                 "core": ss.family_of(e["label"]) in ss.CORE_FAMILIES} for e in row["entities"]]
        masked = mask_text(text, pred)
        # Executable check: every merged span is replaced and the length bookkeeping is exact.
        expect = len(text) - masked["masked_chars"] + sum(len(placeholder_for(s["categories"])) for s in masked["spans"])
        if len(masked["text"]) != expect:
            raise RuntimeError("mask_text length bookkeeping mismatch")
        mask_check += 1
        out.append({"id": row["id"], "group_id": row["group_id"], "text_len": len(text),
                    "action": analysis.action.name, "layers": names,
                    "layer_status": [l.status for l in analysis.layers],
                    "spanless_findings": spanless, "gold": gold, "pred": pred,
                    "mask_chars_extension_algorithm": masked["masked_chars"]})
    return {"study_id": STUDY_ID, "seed": SEED, "layers": LAYERS, "regex_first": REGEX_FIRST,
            "inputs": inputs, "n_prompts": len(out), "records": out, "mask_checks": mask_check}


def score(extraction: Mapping) -> dict:
    records = extraction["records"]
    # cross-check: the interval-based mask size equals what mask_text computed on the real text
    for r in records:
        iv = _merge((s["start"], s["end"]) for s in normalize_spans(r["pred"], r["text_len"]))
        if sum(e - s for s, e in iv) != r["mask_chars_extension_algorithm"]:
            raise RuntimeError(f"mask size mismatch for {r['id']}")
    return {"study_id": STUDY_ID, "scopes": {scope: summarise(records, scope) for scope in SCOPES}}


# --------------------------------------------------------------------------- CLI

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("extract", help="run the product pipeline and write the per-prompt record + scores")
    ex.add_argument("--gold", type=Path, required=True)
    ex.add_argument("--tree", type=Path, default=Path(__file__).resolve().parents[1])
    ex.add_argument("--out", type=Path, required=True)
    ex.add_argument("--limit", type=int, default=None)
    rd = sub.add_parser("rederive", help="recompute every score from a results JSON alone")
    rd.add_argument("results", type=Path)
    args = parser.parse_args(argv)
    if args.command == "extract":
        extraction = extract(args.tree, args.gold, args.limit)
        extraction["scores"] = score(extraction)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(extraction, sort_keys=True, indent=1) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {args.out} sha256={sha256_raw(args.out)}")
        return 0
    data = json.loads(args.results.read_text(encoding="utf-8"))
    fresh = score(data)
    same = json.dumps(fresh, sort_keys=True) == json.dumps(data["scores"], sort_keys=True)
    print("rederived scores identical to stored scores" if same else "MISMATCH between rederived and stored scores")
    return 0 if same else 1


if __name__ == "__main__":
    raise SystemExit(main())
