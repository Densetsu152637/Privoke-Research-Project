"""Span-level scoring of detector outputs against character-offset gold spans (detector-layer scope).

Prompt-level "any hit" scoring cannot tell whether a detector found the *right* text. This module
scores predicted character spans against gold spans and is reusable on any set that provides rows
of the form ``{"id", "group_id", "text", "entities": [{"start", "end", "label"}]}`` (``start``
inclusive, ``end`` exclusive, offsets into ``text``).

Scope: regex and NER layers (and unions of their spans). It is NOT LLM/semantic evidence.

Pipeline
--------
1. ``extract_predictions(tree, rows)`` runs ``pipeline.analyse_text(layers=["regex", "ner"],
   regex_first=False)`` for one source tree (explicit layer list, never empty) and returns one
   prediction record per row with per-layer original-text spans (the pipeline already remaps
   normalised offsets through ``NormalizedText.original_span``). Positive results without a span
   are counted in ``spanless`` and cannot be scored.
2. ``score_layer(gold_rows, pred_rows, layer)`` scores one span source. ``layer`` is ``regex``,
   ``ner``, ``union`` (regex spans + NER spans) or ``p4`` (regex spans, plus NER spans only in
   prompts where the regex layer fired: NER used only to extend regex masking).
3. ``compare_layers(...)`` / ``paired_comparison(...)`` give grouped paired-bootstrap deltas and
   exact McNemar on the per-prompt "all mentions masked" outcome, reusing ``detector_stats``.

Definitions
-----------
* Predicted entities of a layer are its unique ``(start, end)`` intervals of positive results
  (identical intervals from several rules are one entity; their categories are unioned).
* Entity matching is one-to-one (maximum bipartite matching) under three criteria: ``exact``
  (identical offsets), ``iou50`` (character IoU >= 0.5) and ``overlap`` (any shared character).
  Precision = matched / predicted, recall = matched / gold. ``overlap_lenient`` drops the
  one-to-one constraint (a predicted span overlapping any gold span is a hit; a gold span
  overlapped by any predicted span is found), which is the fair view when one predicted span
  covers two gold spans (e.g. a full name versus GIVENNAME + SURNAME).
* ``overlap_typed`` is ``overlap`` with the extra requirement that the predicted PriVoke categories
  intersect the gold family's PriVoke categories (``FAMILY_CATEGORIES``). Gold families without a
  PriVoke category can never match typed.
* Character level: gold characters = union of gold spans; predicted characters = union of
  predicted spans. Masking recall = covered gold chars / gold chars. Over-masking =
  predicted chars outside gold / predicted chars (and per 1000 prompt characters).
* "All mentions masked" (per prompt with gold spans): every gold span is fully covered by the
  predicted union; ``all_touched`` is the lenient variant (every gold span has >= 1 covered char).
* ``min_sens`` (0 or 2 in the study) restricts predicted spans to sensitivity >= S<min_sens>: 0 keeps
  every positive finding (the detector-layer definition), 2 drops the weak S1 findings.
* Scopes: ``all`` scores every gold span. ``core`` treats gold spans whose family has no PriVoke
  detector category (titles, genders, ages, occupations, education, ...) as don't-care: they are removed
  from gold, predicted spans that overlap only don't-care gold are dropped, and their characters
  are removed from the predicted union.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import detector_stats as ds  # noqa: E402

DETECTOR_LAYERS = ("regex", "ner")
SCORED_LAYERS = ("regex", "ner", "union", "p4")
SCOPES = ("all", "core")
CRITERIA = ("exact", "iou50", "overlap", "overlap_typed")
DEFAULT_SEED = ds.DEFAULT_SEED
DEFAULT_BOOTSTRAP = ds.DEFAULT_BOOTSTRAP
LOCKED_NAMES = {"final.jsonl"}

# ----------------------------------------------------------------------------- label mapping
# PIIMB-style gold labels differ per source dataset (Nemotron-PII lowercase snake case, ai4privacy
# UPPERCASE, gretel snake case, presidio-style names). Keys are lowercased with every
# non-alphanumeric character removed. Each label maps to a *family*; each family maps to PriVoke
# categories (possibly none) and to the scope flag ``core``.

LABEL_FAMILY: dict[str, str] = {}


def _register(family: str, *labels: str) -> None:
    for label in labels:
        LABEL_FAMILY[re.sub(r"[^a-z0-9]", "", label.lower())] = family


_register("NAME", "PERSON", "name", "first_name", "last_name", "GIVENNAME", "SURNAME")
_register("CONTACT", "email", "EMAIL", "EMAIL_ADDRESS", "phone_number", "TELEPHONENUM", "fax_number", "url")
_register("GOV_ID", "ssn", "SOCIALNUM", "DRIVERLICENSENUM", "US_DRIVER_LICENSE", "PASSPORTNUM", "US_PASSPORT",
          "IDCARDNUM", "TAXNUM", "tax_id", "license_plate", "US_LICENSE_PLATE", "vehicle_identifier",
          "certificate_license_number")
_register("ACCOUNT_ID", "user_name", "customer_id", "employee_id", "unique_id", "unique_identifier",
          "device_identifier", "biometric_identifier", "http_cookie", "password", "pin", "mac_address", "ipv4")
_register("DOB", "date_of_birth")
_register("LOCATION", "STREET", "street_address", "address", "CITY", "city", "state", "county", "country",
          "ZIPCODE", "postcode", "BUILDINGNUM", "LOCATION", "coordinate")
_register("FINANCIAL", "CREDITCARDNUMBER", "credit_card_number", "credit_debit_card", "account_number",
          "bank_routing_number", "swift_bic", "FINANCIAL", "cvv")
_register("HEALTH", "medical_record_number", "health_plan_beneficiary_number", "blood_type")
_register("POLITICS", "political_view")
_register("RELIGION", "religious_belief")
_register("TEMPORAL", "DATE", "date", "DATE_TIME", "date_time", "time")
_register("ORG", "company_name", "ORGANIZATION")
# attribute families: PIIMB marks them as PII, but PriVoke has no matching detector category
_register("DEMOGRAPHIC", "TITLE", "gender", "GENDER", "SEX", "AGE", "age", "NRP", "language")
_register("OCCUPATION", "occupation", "education_level", "employment_status")

FAMILY_CATEGORIES: dict[str, tuple[str, ...]] = {
    "NAME": ("IDENTITY",), "CONTACT": ("IDENTITY",), "GOV_ID": ("IDENTITY",), "ACCOUNT_ID": ("IDENTITY",),
    "DOB": ("IDENTITY",), "LOCATION": ("LOCATION",), "FINANCIAL": ("FINANCIAL",), "HEALTH": ("HEALTH",),
    "POLITICS": ("POLITICS",), "RELIGION": ("RELIGION",),
    # the runtime itself files dates (regex) and organisations (NER ORG) under IDENTITY at S1
    "TEMPORAL": ("IDENTITY",), "ORG": ("IDENTITY",),
    "DEMOGRAPHIC": (), "OCCUPATION": (), "UNMAPPED": (),
}
CORE_FAMILIES = frozenset(f for f, cats in FAMILY_CATEGORIES.items() if cats)


def label_key(label: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(label).lower())


def family_of(label: str) -> str:
    return LABEL_FAMILY.get(label_key(label), "UNMAPPED")


def unmapped_labels(gold_rows: Iterable[Mapping]) -> Counter:
    """Gold labels that fall into the ``UNMAPPED`` family, with counts (should be empty)."""
    counts: Counter = Counter()
    for row in gold_rows:
        for ent in row.get("entities", []):
            if family_of(ent["label"]) == "UNMAPPED":
                counts[ent["label"]] += 1
    return counts


# ----------------------------------------------------------------------------- interval helpers

Interval = tuple[int, int]


def overlap_len(a: Interval, b: Interval) -> int:
    return max(0, min(a[1], b[1]) - max(a[0], b[0]))


def iou(a: Interval, b: Interval) -> float:
    inter = overlap_len(a, b)
    if inter == 0:
        return 0.0
    return inter / ((a[1] - a[0]) + (b[1] - b[0]) - inter)


def merge_intervals(spans: Iterable[Interval]) -> list[Interval]:
    """Union of half-open intervals; touching intervals (end == next start) are joined."""
    out: list[list[int]] = []
    for s, e in sorted((int(s), int(e)) for s, e in spans if e > s):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]


def total_len(merged: Sequence[Interval]) -> int:
    return sum(e - s for s, e in merged)


def intersect_len(a: Sequence[Interval], b: Sequence[Interval]) -> int:
    """Characters shared by two merged interval lists."""
    total = i = j = 0
    while i < len(a) and j < len(b):
        total += overlap_len(a[i], b[j])
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total


def subtract_len(a: Sequence[Interval], b: Sequence[Interval]) -> int:
    return total_len(a) - intersect_len(a, b)


def subtract_intervals(a: Sequence[Interval], b: Sequence[Interval]) -> list[Interval]:
    out: list[Interval] = []
    for s, e in a:
        cur = s
        for bs, be in b:
            if be <= cur or bs >= e:
                continue
            if bs > cur:
                out.append((cur, bs))
            cur = max(cur, be)
            if cur >= e:
                break
        if cur < e:
            out.append((cur, e))
    return out


def max_matching(n_left: int, edges: Sequence[Sequence[int]]) -> list[tuple[int, int]]:
    """Maximum bipartite matching (Kuhn's augmenting paths); ``edges[i]`` = right ids for left ``i``.

    Deterministic: left nodes are tried in order and right candidates in the given order.
    """
    match_right: dict[int, int] = {}

    def try_assign(left: int, seen: set[int]) -> bool:
        for right in edges[left]:
            if right in seen:
                continue
            seen.add(right)
            if right not in match_right or try_assign(match_right[right], seen):
                match_right[right] = left
                return True
        return False

    for left in range(n_left):
        try_assign(left, set())
    return sorted((left, right) for right, left in match_right.items())


# ----------------------------------------------------------------------------- prompt scoring

COUNT_FIELDS = (
    "n_prompts", "n_prompts_gold", "n_prompts_clean", "clean_flagged",
    "n_gold", "n_pred",
    "tp_exact", "tp_iou50", "tp_overlap", "tp_overlap_typed",
    "gold_overlapped", "pred_overlapping",
    "gold_chars", "pred_chars", "covered_chars", "over_chars", "text_chars", "clean_pred_chars",
    "gold_full", "all_masked", "all_touched",
)


def _norm_gold(entities: Sequence[Mapping]) -> list[dict]:
    out = []
    for ent in entities:
        s, e = int(ent["start"]), int(ent["end"])
        if e <= s:
            raise ValueError(f"empty or inverted gold span {ent!r}")
        fam = family_of(ent["label"])
        out.append({"start": s, "end": e, "label": ent["label"], "family": fam,
                    "categories": FAMILY_CATEGORIES[fam]})
    return sorted(out, key=lambda g: (g["start"], g["end"]))


def collapse_pred(spans: Iterable[Mapping]) -> list[dict]:
    """Unique ``(start, end)`` entities with unioned categories and sources, sorted."""
    merged: dict[Interval, dict] = {}
    for sp in spans:
        key = (int(sp["start"]), int(sp["end"]))
        if key[1] <= key[0]:
            continue
        cur = merged.setdefault(key, {"start": key[0], "end": key[1], "categories": set(), "sources": set()})
        cur["categories"].update(sp.get("categories", ()))
        if sp.get("source"):
            cur["sources"].add(sp["source"])
    return [{"start": v["start"], "end": v["end"], "categories": tuple(sorted(v["categories"])),
             "sources": tuple(sorted(v["sources"]))} for _, v in sorted(merged.items())]


def _compatible(criterion: str, g: Mapping, p: Mapping) -> bool:
    gi, pi = (g["start"], g["end"]), (p["start"], p["end"])
    if criterion == "exact":
        return gi == pi
    if criterion == "iou50":
        return iou(gi, pi) >= 0.5
    if criterion == "overlap":
        return overlap_len(gi, pi) > 0
    if criterion == "overlap_typed":
        return overlap_len(gi, pi) > 0 and bool(set(g["categories"]) & set(p["categories"]))
    raise ValueError(criterion)


def match_entities(gold: Sequence[Mapping], pred: Sequence[Mapping], criterion: str) -> list[tuple[int, int]]:
    """One-to-one maximum matching of gold to predicted entities; returns ``(gold_i, pred_j)`` pairs."""
    edges = [[j for j, p in enumerate(pred) if _compatible(criterion, g, p)] for g in gold]
    return max_matching(len(gold), edges)


def apply_scope(gold: list[dict], pred: list[dict], scope: str) -> tuple[list[dict], list[dict], list[Interval]]:
    """Return gold, predicted entities and the don't-care intervals for a scope."""
    if scope == "all":
        return gold, pred, []
    if scope != "core":
        raise ValueError(f"scope must be one of {SCOPES}")
    core = [g for g in gold if g["family"] in CORE_FAMILIES]
    ignore = [(g["start"], g["end"]) for g in gold if g["family"] not in CORE_FAMILIES]
    core_iv = [(g["start"], g["end"]) for g in core]
    kept = [p for p in pred
            if any(overlap_len((p["start"], p["end"]), c) > 0 for c in core_iv)
            or not any(overlap_len((p["start"], p["end"]), i) > 0 for i in ignore)]
    return core, kept, merge_intervals(ignore)


def score_prompt(gold_entities: Sequence[Mapping], pred_spans: Sequence[Mapping], text_len: int,
                 scope: str = "all") -> dict:
    """Raw counts for one prompt (see ``COUNT_FIELDS``) plus per-family and per-category detail."""
    gold, pred, ignore = apply_scope(_norm_gold(gold_entities), collapse_pred(pred_spans), scope)
    out = {k: 0 for k in COUNT_FIELDS}
    out["n_prompts"] = 1
    out["n_gold"], out["n_pred"] = len(gold), len(pred)
    out["text_chars"] = int(text_len)
    matched_gold: dict[str, set[int]] = {}
    for crit in CRITERIA:
        pairs = match_entities(gold, pred, crit)
        key = {"exact": "tp_exact", "iou50": "tp_iou50", "overlap": "tp_overlap",
               "overlap_typed": "tp_overlap_typed"}[crit]
        out[key] = len(pairs)
        matched_gold[crit] = {i for i, _ in pairs}
    gold_iv = [(g["start"], g["end"]) for g in gold]
    pred_iv = [(p["start"], p["end"]) for p in pred]
    gold_union = merge_intervals(gold_iv)
    pred_union = subtract_intervals(merge_intervals(pred_iv), ignore) if ignore else merge_intervals(pred_iv)
    touched = [any(overlap_len(g, p) > 0 for p in pred_iv) for g in gold_iv]
    pred_hit = [any(overlap_len(p, g) > 0 for g in gold_iv) for p in pred_iv]
    full = [intersect_len([g], pred_union) == g[1] - g[0] for g in gold_iv]
    out["gold_overlapped"] = sum(touched)
    out["pred_overlapping"] = sum(pred_hit)
    out["gold_chars"] = total_len(gold_union)
    out["pred_chars"] = total_len(pred_union)
    out["covered_chars"] = intersect_len(gold_union, pred_union)
    out["over_chars"] = out["pred_chars"] - out["covered_chars"]
    out["gold_full"] = sum(full)
    if gold:
        out["n_prompts_gold"] = 1
        out["all_masked"] = int(all(full))
        out["all_touched"] = int(all(intersect_len([g], pred_union) > 0 for g in gold_iv))
    else:
        out["n_prompts_clean"] = 1
        out["clean_flagged"] = int(bool(pred))
        out["clean_pred_chars"] = out["pred_chars"]
    by_family: dict[str, dict[str, int]] = defaultdict(lambda: Counter())
    for i, g in enumerate(gold):
        row = by_family[g["family"]]
        row["n_gold"] += 1
        row["exact"] += i in matched_gold["exact"]
        row["iou50"] += i in matched_gold["iou50"]
        row["overlap"] += i in matched_gold["overlap"]
        row["touched"] += touched[i]
        row["full"] += full[i]
        row["gold_chars"] += g["end"] - g["start"]
        row["covered_chars"] += intersect_len([(g["start"], g["end"])], pred_union)
    by_category: dict[str, dict[str, int]] = defaultdict(lambda: Counter())
    for j, p in enumerate(pred):
        cats = p["categories"] or ("NONE",)
        for cat in cats:
            row = by_category[cat]
            row["n_pred"] += 1
            row["overlapping_gold"] += pred_hit[j]
            row["typed_overlap"] += any(
                overlap_len((p["start"], p["end"]), (g["start"], g["end"])) > 0 and cat in g["categories"]
                for g in gold)
    by_source: dict[str, dict[str, int]] = defaultdict(lambda: Counter())
    for j, p in enumerate(pred):
        for src in p["sources"] or ("?",):
            by_source[src]["n_pred"] += 1
            by_source[src]["overlapping_gold"] += pred_hit[j]
            by_source[src]["chars"] += pred_iv[j][1] - pred_iv[j][0]
            by_source[src]["chars_outside_gold"] += (pred_iv[j][1] - pred_iv[j][0]
                                                     - intersect_len([pred_iv[j]], gold_union))
    out["by_family"] = {k: dict(v) for k, v in by_family.items()}
    out["by_category"] = {k: dict(v) for k, v in by_category.items()}
    out["by_source"] = {k: dict(v) for k, v in by_source.items()}
    return out


# ----------------------------------------------------------------------------- metrics from counts


def _ratio(num, den):
    return None if not den else num / den


def _f1(p, r):
    return None if p is None or r is None or (p + r) == 0 else 2 * p * r / (p + r)


def metrics_from_counts(c: Mapping[str, float]) -> dict[str, float | None]:
    """Every reported metric from summed counts (``None`` where the denominator is zero)."""
    out: dict[str, float | None] = {}
    for name, key in (("exact", "tp_exact"), ("iou50", "tp_iou50"), ("overlap", "tp_overlap"),
                      ("overlap_typed", "tp_overlap_typed")):
        p, r = _ratio(c[key], c["n_pred"]), _ratio(c[key], c["n_gold"])
        out[f"precision_{name}"], out[f"recall_{name}"], out[f"f1_{name}"] = p, r, _f1(p, r)
    p, r = _ratio(c["pred_overlapping"], c["n_pred"]), _ratio(c["gold_overlapped"], c["n_gold"])
    out["precision_overlap_lenient"], out["recall_overlap_lenient"], out["f1_overlap_lenient"] = p, r, _f1(p, r)
    out["char_recall"] = _ratio(c["covered_chars"], c["gold_chars"])
    out["char_precision"] = _ratio(c["covered_chars"], c["pred_chars"])
    out["over_masking_share"] = _ratio(c["over_chars"], c["pred_chars"])
    out["over_mask_chars_per_1k"] = _ratio(1000.0 * c["over_chars"], c["text_chars"])
    out["gold_span_fully_masked"] = _ratio(c["gold_full"], c["n_gold"])
    out["all_masked_rate"] = _ratio(c["all_masked"], c["n_prompts_gold"])
    out["all_touched_rate"] = _ratio(c["all_touched"], c["n_prompts_gold"])
    out["clean_prompt_flag_rate"] = _ratio(c["clean_flagged"], c["n_prompts_clean"])
    out["clean_prompt_masked_chars"] = _ratio(c["clean_pred_chars"], c["n_prompts_clean"])
    return out


METRIC_NAMES = tuple(metrics_from_counts({k: 1 for k in COUNT_FIELDS}))


def metrics_on_totals(totals: np.ndarray) -> dict[str, np.ndarray]:
    """Vectorised ``metrics_from_counts`` over rows of summed count vectors (columns = COUNT_FIELDS)."""
    col = {k: totals[:, i].astype(float) for i, k in enumerate(COUNT_FIELDS)}

    def div(a, b):
        with np.errstate(divide="ignore", invalid="ignore"):
            return np.where(b > 0, a / np.where(b > 0, b, 1.0), np.nan)

    out: dict[str, np.ndarray] = {}
    for name, key in (("exact", "tp_exact"), ("iou50", "tp_iou50"), ("overlap", "tp_overlap"),
                      ("overlap_typed", "tp_overlap_typed")):
        p, r = div(col[key], col["n_pred"]), div(col[key], col["n_gold"])
        out[f"precision_{name}"], out[f"recall_{name}"] = p, r
        out[f"f1_{name}"] = div(2 * p * r, p + r)
    p, r = div(col["pred_overlapping"], col["n_pred"]), div(col["gold_overlapped"], col["n_gold"])
    out["precision_overlap_lenient"], out["recall_overlap_lenient"] = p, r
    out["f1_overlap_lenient"] = div(2 * p * r, p + r)
    out["char_recall"] = div(col["covered_chars"], col["gold_chars"])
    out["char_precision"] = div(col["covered_chars"], col["pred_chars"])
    out["over_masking_share"] = div(col["over_chars"], col["pred_chars"])
    out["over_mask_chars_per_1k"] = div(1000.0 * col["over_chars"], col["text_chars"])
    out["gold_span_fully_masked"] = div(col["gold_full"], col["n_gold"])
    out["all_masked_rate"] = div(col["all_masked"], col["n_prompts_gold"])
    out["all_touched_rate"] = div(col["all_touched"], col["n_prompts_gold"])
    out["clean_prompt_flag_rate"] = div(col["clean_flagged"], col["n_prompts_clean"])
    out["clean_prompt_masked_chars"] = div(col["clean_pred_chars"], col["n_prompts_clean"])
    return out


# ----------------------------------------------------------------------------- predictions


def half_of(group_id: str) -> str:
    """dev-TUNE / dev-CHECK by sha256(group_id) parity (same as compare_ner_postfilter.py)."""
    return "check" if int(hashlib.sha256(group_id.encode()).hexdigest(), 16) % 2 else "tune"


def refuse_locked(path: Path | str) -> None:
    if Path(path).name in LOCKED_NAMES:
        raise SystemExit(f"refusing locked held-out file {path}")


def load_jsonl(path: Path | str) -> list[dict]:
    refuse_locked(path)
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def extract_predictions(tree: Path | str, rows: Sequence[Mapping], generated: Path | str | None = None,
                        label: str = "") -> list[dict]:
    """Run regex + NER (explicit layers, ``regex_first=False``) with ``tree``'s defaults.

    Returns one record per row: ``{"id", "group_id", "layers": {"regex": [span...], "ner": [...]},
    "fired": {"regex": bool, "ner": bool}, "spanless": {"regex": n, "ner": n}}`` where a span is
    ``{"start", "end", "categories", "sensitivity", "source"}`` in ORIGINAL-text offsets. Only
    positive results (sensitivity != S0 or any category) are kept. ``tree`` must contain
    ``extension/client-runtime`` and ``shared/python``.
    """
    tree = Path(tree)
    sys.path[:0] = [str(tree / "extension/client-runtime"), str(tree / "shared/python")]
    if generated is not None:
        sys.path.append(str(generated))
    import spacy  # noqa: F401  pre-import in the main thread (layer threads race on first import)
    from src import pipeline
    from src.NER import EntityNERDetector
    from src.regex.rule_detector import RuleDetector

    RuleDetector()
    EntityNERDetector()
    layers = list(DETECTOR_LAYERS)
    pipeline.analyse_text("warm up Alice Smith", layers=layers, regex_first=False)
    records = []
    for row in rows:
        analysis = pipeline.analyse_text(row["text"], layers=layers, regex_first=False)
        if [l.layer for l in analysis.layers] != layers or any(l.status != "ok" for l in analysis.layers):
            raise RuntimeError(f"unexpected layer execution: {[(l.layer, l.status, l.error) for l in analysis.layers]}")
        rec = {"id": row["id"], "group_id": row.get("group_id"), "layers": {}, "fired": {}, "spanless": {}}
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
        records.append(rec)
    return records


def _sens_rank(span: Mapping) -> int:
    return int(str(span.get("sensitivity", "S0"))[1:] or 0)


def layer_spans(pred: Mapping, layer: str, min_sens: int = 0) -> list[dict]:
    """Spans of a scored layer from a prediction record (see module docstring for ``p4``).

    ``min_sens`` keeps only spans whose sensitivity is at least S<min_sens> (0 = every positive
    finding, the detector-layer definition of "fired"). With ``min_sens > 0`` the p4 trigger is
    "the regex layer has a kept span".
    """
    regex, ner = pred["layers"].get("regex", []), pred["layers"].get("ner", [])
    fired = bool(pred["fired"].get("regex"))
    if min_sens:
        regex = [x for x in regex if _sens_rank(x) >= min_sens]
        ner = [x for x in ner if _sens_rank(x) >= min_sens]
        fired = bool(regex)
    if layer == "regex":
        return list(regex)
    if layer == "ner":
        return list(ner)
    if layer == "union":
        return list(regex) + list(ner)
    if layer == "p4":
        return list(regex) + (list(ner) if fired else [])
    raise ValueError(f"layer must be one of {SCORED_LAYERS}")


def join_rows(gold_rows: Sequence[Mapping], pred_rows: Sequence[Mapping]) -> list[tuple[dict, dict]]:
    """Pair gold and prediction records by ``id``; ids must agree exactly."""
    gold = {r["id"]: r for r in gold_rows}
    pred = {r["id"]: r for r in pred_rows}
    if len(gold) != len(gold_rows) or len(pred) != len(pred_rows):
        raise ValueError("duplicate id")
    if gold.keys() != pred.keys():
        raise ValueError("gold and predictions cover different ids")
    return [(gold[r["id"]], pred[r["id"]]) for r in gold_rows]


def _vector(counts: Mapping) -> list[int]:
    return [counts[k] for k in COUNT_FIELDS]


def prompt_table(pairs: Sequence[tuple[dict, dict]], layer: str, scope: str = "all",
                 min_sens: int = 0) -> tuple[np.ndarray, list[dict]]:
    """Per-prompt count matrix (n x len(COUNT_FIELDS)) and the raw per-prompt score dicts."""
    scored = [score_prompt(g["entities"], layer_spans(p, layer, min_sens), len(g["text"]), scope) for g, p in pairs]
    return np.array([_vector(s) for s in scored], dtype=np.int64), scored


def aggregate_detail(scored: Sequence[Mapping], key: str) -> dict[str, dict[str, int]]:
    total: dict[str, Counter] = defaultdict(Counter)
    for s in scored:
        for name, row in s[key].items():
            total[name].update(row)
    return {k: dict(v) for k, v in sorted(total.items())}


def score_layer(gold_rows: Sequence[Mapping], pred_rows: Sequence[Mapping], layer: str, scope: str = "all",
                subset: Callable[[Mapping], bool] | None = None, min_sens: int = 0) -> dict:
    """Aggregate metrics, per-family recall and per-category precision for one layer/scope/subset."""
    pairs = join_rows(gold_rows, pred_rows)
    if subset is not None:
        pairs = [(g, p) for g, p in pairs if subset(g)]
    table, scored = prompt_table(pairs, layer, scope, min_sens)
    totals = table.sum(axis=0)
    counts = {k: int(v) for k, v in zip(COUNT_FIELDS, totals)}
    fam = aggregate_detail(scored, "by_family")
    for row in fam.values():
        row["recall_exact"] = row.get("exact", 0) / row["n_gold"]
        row["recall_overlap"] = row.get("overlap", 0) / row["n_gold"]
        row["recall_touched"] = row.get("touched", 0) / row["n_gold"]
        row["char_recall"] = row.get("covered_chars", 0) / row["gold_chars"]
    cat = aggregate_detail(scored, "by_category")
    for row in cat.values():
        row["precision_overlap_lenient"] = row.get("overlapping_gold", 0) / row["n_pred"]
        row["precision_typed_overlap"] = row.get("typed_overlap", 0) / row["n_pred"]
    src = aggregate_detail(scored, "by_source")
    spanless = sum(p["spanless"].get("regex", 0) + p["spanless"].get("ner", 0) if layer in ("union", "p4")
                   else p["spanless"].get(layer, 0) for _, p in pairs)
    return {"layer": layer, "scope": scope, "min_sens": min_sens, "counts": counts, "metrics": metrics_from_counts(counts),
            "by_family": fam, "by_category": cat, "by_source": src, "n_spanless_positive_results": spanless}


# ----------------------------------------------------------------------------- paired statistics


def _boot_metrics(groups: Sequence[str], tables: Mapping[str, np.ndarray], names: Sequence[str],
                  baseline: str, n_boot: int, seed: int, level: float = 0.95) -> dict:
    """Grouped paired bootstrap over per-prompt count tables; metric CIs and deltas vs ``baseline``."""
    cluster_of, k = ds._cluster_table(groups)
    per_cluster = {}
    for name, table in tables.items():
        agg = np.zeros((k, table.shape[1]), dtype=np.int64)
        np.add.at(agg, cluster_of, table)
        per_cluster[name] = agg
    boot: dict[str, dict[str, list]] = {n: {m: [] for m in names} for n in tables}
    for weights in ds._replicate_weights(k, n_boot, seed):
        for name, agg in per_cluster.items():
            vals = metrics_on_totals(weights @ agg)
            for m in names:
                boot[name][m].append(vals[m])
    arrays = {n: {m: np.concatenate(v) for m, v in per.items()} for n, per in boot.items()}
    point = {n: metrics_from_counts({c: int(tables[n][:, i].sum()) for i, c in enumerate(COUNT_FIELDS)})
             for n in tables}
    out = {"n_clusters": k, "n_boot": n_boot, "seed": seed, "level": level, "baseline": baseline,
           "metrics": {}, "deltas": {}}
    for n in tables:
        out["metrics"][n] = {m: {"estimate": point[n][m], **ds._percentile_ci(arrays[n][m], level)} for m in names}
        if n == baseline:
            continue
        out["deltas"][n] = {}
        for m in names:
            ci = ds._percentile_ci(arrays[n][m] - arrays[baseline][m], level)
            a, b = point[baseline][m], point[n][m]
            ci["excludes_zero"] = ci["lo"] is not None and (ci["lo"] > 0 or ci["hi"] < 0)
            out["deltas"][n][m] = {"estimate": None if a is None or b is None else b - a, **ci}
    return out


HEADLINE_METRICS = ("recall_overlap", "precision_overlap", "f1_overlap", "recall_iou50", "f1_iou50",
                    "recall_exact", "f1_exact", "char_recall", "over_masking_share", "over_mask_chars_per_1k",
                    "all_masked_rate", "clean_prompt_flag_rate")


def paired_comparison(gold_rows: Sequence[Mapping], baseline_preds: Sequence[Mapping],
                      candidate_preds: Sequence[Mapping], layer: str, scope: str = "all",
                      subset: Callable[[Mapping], bool] | None = None, names: tuple[str, str] = ("old", "new"),
                      metrics: Sequence[str] = HEADLINE_METRICS, n_boot: int = DEFAULT_BOOTSTRAP,
                      seed: int = DEFAULT_SEED, min_sens: int = 0, candidate_layer: str | None = None) -> dict:
    """Old-vs-new on the same rows: grouped paired bootstrap (clusters = ``group_id``) plus exact McNemar
    and a cluster sign test on the per-prompt "all mentions masked" outcome (prompts with gold spans).

    ``layer`` selects the span source for the baseline; ``candidate_layer`` (default: ``layer``) the one
    for the candidate. Pass the same prediction list twice with different layers to compare span sources
    inside one tree (e.g. ``regex`` versus ``p4``).
    """
    base_pairs = join_rows(gold_rows, baseline_preds)
    cand_pairs = join_rows(gold_rows, candidate_preds)
    if subset is not None:
        keep = [subset(g) for g, _ in base_pairs]
        base_pairs = [x for x, k in zip(base_pairs, keep) if k]
        cand_pairs = [x for x, k in zip(cand_pairs, keep) if k]
    tab_a, _ = prompt_table(base_pairs, layer, scope, min_sens)
    tab_b, _ = prompt_table(cand_pairs, candidate_layer or layer, scope, min_sens)
    groups = [g["group_id"] if g.get("group_id") is not None else f"row:{g['id']}" for g, _ in base_pairs]
    result = _boot_metrics(groups, {names[0]: tab_a, names[1]: tab_b}, metrics, names[0], n_boot, seed)
    ci = COUNT_FIELDS.index("all_masked")
    has = tab_a[:, COUNT_FIELDS.index("n_prompts_gold")] > 0
    a = tab_a[has, ci].astype(bool)
    b = tab_b[has, ci].astype(bool)
    flips = ds.paired_flips([True] * len(a), a.tolist(), b.tolist())
    sub_groups = [g for g, h in zip(groups, has) if h]
    result["all_masked_flips"] = {
        "gained": flips["fn_to_tp"], "lost": flips["tp_to_fn"],
        "both_masked": flips["pos_unchanged_correct"], "neither_masked": flips["pos_unchanged_wrong"],
        "mcnemar": flips["mcnemar_positives"]}
    result["all_masked_cluster_sign_test"] = ds.cluster_sign_test(
        [True] * len(a), a.tolist(), b.tolist(), sub_groups, on="all")
    result.update({"layer": layer, "candidate_layer": candidate_layer or layer, "scope": scope,
                   "min_sens": min_sens, "n_prompts": len(base_pairs), "n_prompts_gold": int(has.sum())})
    return result


# ----------------------------------------------------------------------------- study driver

SUBSETS: dict[str, Callable[[Mapping], bool] | None] = {
    "all-dev": None,
    "dev-TUNE": lambda g: half_of(g["group_id"]) == "tune",
    "dev-CHECK": lambda g: half_of(g["group_id"]) == "check",
}


def run_study(gold_rows: Sequence[Mapping], old_preds: Sequence[Mapping], new_preds: Sequence[Mapping],
              n_boot: int = DEFAULT_BOOTSTRAP, seed: int = DEFAULT_SEED) -> dict:
    """Old/new scores, paired old-vs-new comparisons and P4-versus-regex/union comparisons on every
    subset x scope x minimum-sensitivity combination. Aggregates only (no text)."""
    out: dict = {"subsets": {}}
    for sub_name, subset in SUBSETS.items():
        sub = out["subsets"].setdefault(sub_name, {})
        for min_sens in (0, 2):
            for scope in SCOPES:
                cell = sub.setdefault(f"min_sens={min_sens}", {}).setdefault(scope, {"scores": {}, "old_vs_new": {}, "p4": {}})
                for layer in SCORED_LAYERS:
                    cell["scores"][layer] = {
                        tag: score_layer(gold_rows, preds, layer, scope, subset, min_sens)
                        for tag, preds in (("old", old_preds), ("new", new_preds))}
                    cell["old_vs_new"][layer] = paired_comparison(
                        gold_rows, old_preds, new_preds, layer, scope, subset, min_sens=min_sens,
                        n_boot=n_boot, seed=seed)
                for tag, preds in (("old", old_preds), ("new", new_preds)):
                    cell["p4"][tag] = {
                        "vs_regex": paired_comparison(gold_rows, preds, preds, "regex", scope, subset,
                                                      names=("regex", "p4"), candidate_layer="p4",
                                                      min_sens=min_sens, n_boot=n_boot, seed=seed),
                        "vs_union": paired_comparison(gold_rows, preds, preds, "p4", scope, subset,
                                                      names=("p4", "union"), candidate_layer="union",
                                                      min_sens=min_sens, n_boot=n_boot, seed=seed)}
    return out


# ----------------------------------------------------------------------------- CLI


def _cli_extract(args) -> None:
    rows = load_jsonl(args.gold)
    preds = extract_predictions(args.tree, rows, args.generated, args.label)
    Path(args.out).write_text("".join(json.dumps(p, sort_keys=True) + "\n" for p in preds), encoding="utf-8")
    print(f"wrote {len(preds)} prediction records to {args.out}", file=sys.stderr)


def _cli_score(args) -> None:
    gold = load_jsonl(args.gold)
    preds = load_jsonl(args.pred)
    out = {layer: {scope: score_layer(gold, preds, layer, scope) for scope in SCOPES} for layer in SCORED_LAYERS}
    print(json.dumps(out, indent=1))


def _cli_study(args) -> None:
    gold = load_jsonl(args.gold)
    study = run_study(gold, load_jsonl(args.old), load_jsonl(args.new), args.n_boot, args.seed)
    study["unmapped_gold_labels"] = dict(unmapped_labels(gold))
    study["gold_sha256"] = hashlib.sha256(Path(args.gold).read_bytes()).hexdigest()
    Path(args.out).write_text(json.dumps(study, indent=1), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("extract", help="run regex+NER on a gold file and write span predictions")
    ex.add_argument("--tree", required=True, type=Path)
    ex.add_argument("--gold", required=True, type=Path)
    ex.add_argument("--generated", type=Path, default=None)
    ex.add_argument("--label", default="")
    ex.add_argument("--out", required=True, type=Path)
    ex.set_defaults(func=_cli_extract)
    sc = sub.add_parser("score", help="score a prediction file against gold spans")
    sc.add_argument("--gold", required=True, type=Path)
    sc.add_argument("--pred", required=True, type=Path)
    sc.set_defaults(func=_cli_score)
    st = sub.add_parser("study", help="old/new/P4 study over dev subsets (aggregates only)")
    st.add_argument("--gold", required=True, type=Path)
    st.add_argument("--old", required=True, type=Path)
    st.add_argument("--new", required=True, type=Path)
    st.add_argument("--out", required=True, type=Path)
    st.add_argument("--n-boot", type=int, default=DEFAULT_BOOTSTRAP)
    st.add_argument("--seed", type=int, default=DEFAULT_SEED)
    st.set_defaults(func=_cli_study)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
