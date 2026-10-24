"""Detector-layer robustness probe: input perturbations versus regex / NER / union.

Scope: detector-layer only. Every prompt goes through
``pipeline.analyse_text(layers=["regex", "ner"], regex_first=False)`` (explicit list, never empty,
never semantic), so this is NOT LLM-only evidence.

Transforms are pure, deterministic functions ``(text, rng) -> text`` where ``rng`` is a
``random.Random`` seeded from ``sha256(seed, transform, row id)``. They never use detector output
or dataset-specific phrases. A transform that leaves a row unchanged reuses that row's baseline
outcome, so only changed rows are re-analysed.

Two sub-commands::

    python evaluation/robustness_probe.py run --tree <source root> --label old --data-root <checkout> \
        --generated <protobuf dir> --out <dir> [--splits dev personalized openai] [--transforms a b]
    python evaluation/robustness_probe.py report --old <old run files...> --new <new run files...> \
        --out-md <md> --out-json <json>

``run`` writes ``<out>/<label>-<split>-<transform>.json`` with per-row booleans for the changed rows.
The locked ``final`` split is refused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import sys
import unicodedata
from pathlib import Path

LAYERS = ["regex", "ner"]
SEED = 20261024
SPLIT_FILES = {
    "dev": "evaluation/results/locked-public/development.jsonl",
    "personalized": "evaluation/datasets/privoke_personalized_synthetic.jsonl",
    "openai": "evaluation/datasets/privoke_openai_synthetic.jsonl",
}

# ---------------------------------------------------------------- transforms ---------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
DIGIT_RUN_RE = re.compile(r"\d{4,}")
DIGIT_GROUP_RE = re.compile(r"\d(?:[-. ]?\d)+")
DIGIT_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]

HOMOGLYPHS = {  # Latin -> visually similar Cyrillic / Greek code points (NFKC leaves these alone)
    "a": ["а"], "e": ["е"], "o": ["о", "ο"], "p": ["р", "ρ"],
    "c": ["с"], "x": ["х"], "y": ["у"], "i": ["і", "ι"],
    "A": ["А", "Α"], "B": ["В", "Β"], "E": ["Е", "Ε"],
    "H": ["Н", "Η"], "K": ["К", "Κ"], "M": ["М", "Μ"],
    "O": ["О", "Ο"], "P": ["Р", "Ρ"], "C": ["С"], "T": ["Т", "Τ"],
    "X": ["Х", "Χ"], "S": ["Ѕ"], "I": ["І", "Ι"],
}
ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿"]

LABEL_LEET = {  # label word -> obfuscated spellings (generic PII label vocabulary)
    "phone": ["ph0ne"], "telephone": ["t3lephone"], "mobile": ["m0bile"], "email": ["e-mail", "e mail"],
    "e-mail": ["email", "e.mail"], "ssn": ["S.S.N.", "S5N"], "social": ["s0cial"], "security": ["s3curity"],
    "password": ["passw0rd", "p@ssword"], "passport": ["p4ssport"], "address": ["addr3ss", "adress"],
    "birth": ["b1rth"], "account": ["acc0unt"], "card": ["c4rd"], "credit": ["cr3dit"], "license": ["lic3nse"],
    "insurance": ["1nsurance"], "employee": ["3mployee"], "patient": ["pat1ent"], "number": ["numb3r", "no."],
    "bank": ["b4nk"], "medical": ["m3dical"], "salary": ["s4lary"], "name": ["n4me"], "date": ["d4te"],
}
LABEL_RE = re.compile(r"(?<![A-Za-z])(" + "|".join(sorted((re.escape(k) for k in LABEL_LEET), key=len, reverse=True))
                      + r")(?![A-Za-z])", re.IGNORECASE)


def row_rng(transform: str, row_id: str) -> random.Random:
    digest = hashlib.sha256(f"{SEED}:{transform}:{row_id}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def t_lower(text: str, rng: random.Random) -> str:
    return text.lower()


def t_upper(text: str, rng: random.Random) -> str:
    return text.upper()


def _separate_digit_runs(text: str, separator: str) -> str:
    return DIGIT_RUN_RE.sub(lambda m: separator.join(m.group(0)), text)


def t_digits_space(text: str, rng: random.Random) -> str:
    return _separate_digit_runs(text, " ")


def t_digits_dot(text: str, rng: random.Random) -> str:
    return _separate_digit_runs(text, ".")


def t_digits_dash(text: str, rng: random.Random) -> str:
    return _separate_digit_runs(text, "-")


def t_digits_words(text: str, rng: random.Random) -> str:
    """Spell digit groups (7+ digits, single - . or space allowed between digits) as English words."""
    def spell(match: re.Match) -> str:
        digits = [c for c in match.group(0) if c.isdigit()]
        return match.group(0) if len(digits) < 7 else " ".join(DIGIT_WORDS[int(d)] for d in digits)
    return DIGIT_GROUP_RE.sub(spell, text)


def _obfuscate_emails(text: str, at: str, dot: str | None) -> str:
    def rewrite(match: re.Match) -> str:
        local, domain = match.group(0).split("@", 1)
        return local + at + (domain.replace(".", dot) if dot is not None else domain)
    return EMAIL_RE.sub(rewrite, text)


def t_email_bracket(text: str, rng: random.Random) -> str:
    return _obfuscate_emails(text, "[at]", "[dot]")


def t_email_paren(text: str, rng: random.Random) -> str:
    return _obfuscate_emails(text, "(at)", "(dot)")


def t_email_word(text: str, rng: random.Random) -> str:
    return _obfuscate_emails(text, " at ", " dot ")


def t_email_bracket_at_only(text: str, rng: random.Random) -> str:
    return _obfuscate_emails(text, "[at]", None)


def t_homoglyph(text: str, rng: random.Random) -> str:
    """Replace each eligible Latin letter by a Cyrillic/Greek lookalike with probability 0.3."""
    out = []
    for ch in text:
        options = HOMOGLYPHS.get(ch)
        out.append(rng.choice(options) if options and rng.random() < 0.3 else ch)
    return "".join(out)


def t_zero_width(text: str, rng: random.Random) -> str:
    """Insert one zero-width character at a random interior position of half of the 4+ char tokens."""
    def mark(match: re.Match) -> str:
        token = match.group(0)
        if len(token) < 4 or rng.random() >= 0.5:
            return token
        pos = rng.randint(1, len(token) - 1)
        return token[:pos] + rng.choice(ZERO_WIDTH) + token[pos:]
    return re.sub(r"\S+", mark, text)


def t_fullwidth_digits(text: str, rng: random.Random) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "0" <= c <= "9" else c for c in text)


def _match_case(original: str, replacement: str) -> str:
    if original.isupper() and len(original) > 1:
        return replacement.upper()
    if original[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement


def t_label_leet(text: str, rng: random.Random) -> str:
    return LABEL_RE.sub(lambda m: _match_case(m.group(0), rng.choice(LABEL_LEET[m.group(0).lower()])), text)


def t_label_typo(text: str, rng: random.Random) -> str:
    """Swap two adjacent interior letters of each label word (phone -> phoen)."""
    def typo(match: re.Match) -> str:
        word = match.group(0)
        if len(word) < 4:
            return word
        i = rng.randint(1, len(word) - 3)
        return word[:i] + word[i + 1] + word[i] + word[i + 2:]
    return LABEL_RE.sub(typo, text)


TRANSFORMS = {
    "lowercase": t_lower,
    "uppercase": t_upper,
    "digits_space": t_digits_space,
    "digits_dot": t_digits_dot,
    "digits_dash": t_digits_dash,
    "digits_words": t_digits_words,
    "email_bracket": t_email_bracket,
    "email_paren": t_email_paren,
    "email_word": t_email_word,
    "email_bracket_at_only": t_email_bracket_at_only,
    "homoglyph": t_homoglyph,
    "zero_width": t_zero_width,
    "fullwidth_digits": t_fullwidth_digits,
    "label_leet": t_label_leet,
    "label_typo": t_label_typo,
}


def apply_transform(name: str, text: str, row_id: str) -> str:
    return TRANSFORMS[name](text, row_rng(name, row_id))


# --------------------------------------------- candidate input canonicalisation (simulation) ----
# NOT shipped. Applied to the probe input only, to estimate the effect of general preprocessing fixes
# without touching detection code. Each step is generic (no dataset phrases).

SPELLED_DIGITS = {w: str(i) for i, w in enumerate(DIGIT_WORDS)}
_WORD_ALT = "|".join(DIGIT_WORDS)
SPELLED_RUN_RE = re.compile(rf"\b(?:(?:{_WORD_ALT})(?:[ ,.\-]+|\b)){{7,}}", re.IGNORECASE)
SINGLE_DIGIT_CHAIN_RE = re.compile(r"(?<![\d.\-])\d(?:[.\-]\d){3,}(?![\d])")
WORD_EMAIL_RE = re.compile(r"\b([\w.+%\-]+) at ([\w\-]+(?: dot [\w\-]+)+)\b", re.IGNORECASE)
BRACKET_DOT_RE = re.compile(r"\s?[\[(]dot[\])]\s?", re.IGNORECASE)


def candidate_canonicalise(text: str) -> str:
    """Strip format (Cf) characters; join single-digit chains; read 7+ spelled digits as digits;
    undo ' at '/' dot ' and '[dot]'/'(dot)' e-mail spellings."""
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = SINGLE_DIGIT_CHAIN_RE.sub(lambda m: re.sub(r"[.\-]", "", m.group(0)), text)

    def words_to_digits(m: re.Match) -> str:
        return "".join(SPELLED_DIGITS[w.lower()] for w in re.findall(_WORD_ALT, m.group(0), re.IGNORECASE)) + " "
    text = SPELLED_RUN_RE.sub(words_to_digits, text)
    text = WORD_EMAIL_RE.sub(lambda m: m.group(1) + "@" + m.group(2).replace(" dot ", "."), text)
    return BRACKET_DOT_RE.sub(".", text)


# ---------------------------------------------------------------- run ---------------------------


def positive(result) -> bool:
    return result.classification.sensitivity().name != "S0" or bool(result.classification.categories())


def load_rows(split: str, data_root: Path) -> list[dict]:
    path = data_root / SPLIT_FILES[split]
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def analyse(pipeline, text: str) -> dict[str, bool]:
    analysis = pipeline.analyse_text(text, layers=LAYERS, regex_first=False)
    if [l.layer for l in analysis.layers] != LAYERS or any(l.status != "ok" for l in analysis.layers):
        raise RuntimeError(f"unexpected layer execution: {[(l.layer, l.status, l.error) for l in analysis.layers]}")
    return {l.layer: any(positive(h) for h in l.results) for l in analysis.layers}


def command_run(args) -> None:
    sys.path[:0] = [str(args.tree / "extension/client-runtime"), str(args.tree / "shared/python"), str(args.generated)]
    import spacy  # noqa: F401  pre-import in the main thread
    from src import pipeline
    from src.config import GLOBAL_CONFIG
    from src.NER import EntityNERDetector
    from src.regex.rule_detector import RuleDetector

    RuleDetector()
    EntityNERDetector()
    args.out.mkdir(parents=True, exist_ok=True)
    flags = {"case_preserving_detectors": getattr(GLOBAL_CONFIG, "case_preserving_detectors", "absent"),
             "ner_postfilter": getattr(GLOBAL_CONFIG, "ner_postfilter", "absent")}
    for assignment in args.set_flag:
        key, value = assignment.split("=", 1)
        if not hasattr(GLOBAL_CONFIG, key):
            raise SystemExit(f"unknown config flag {key}")
        setattr(GLOBAL_CONFIG, key, value.lower() == "true")
        flags[key] = value.lower() == "true"
    pipeline.analyse_text("warm up Alice Smith", layers=LAYERS, regex_first=False)
    for split in args.splits:
        rows = load_rows(split, args.data_root)
        for name in args.transforms:
            if name == "identity":
                texts = {i: r["text"] for i, r in enumerate(rows)}
            else:
                texts = {}
                for i, row in enumerate(rows):
                    changed = apply_transform(name, row["text"], row["id"])
                    if changed != row["text"]:
                        texts[i] = changed
            if args.defence:
                texts = {i: candidate_canonicalise(t) for i, t in texts.items()}
            outcomes = {i: analyse(pipeline, t) for i, t in texts.items()}
            idx = sorted(outcomes)
            payload = {"label": args.label, "split": split, "transform": name, "flags": flags, "defence": args.defence,
                       "n_rows": len(rows), "idx": idx,
                       "regex": [outcomes[i]["regex"] for i in idx], "ner": [outcomes[i]["ner"] for i in idx]}
            (args.out / f"{args.label}-{split}-{name}.json").write_text(json.dumps(payload), encoding="utf-8")
            print(f"[{args.label}] {split} {name}: changed {len(idx)}/{len(rows)}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------- report ------------------------


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def tune_check(row: dict) -> str:
    return "tune" if int(hashlib.sha256(row["group_id"].encode()).hexdigest(), 16) % 2 == 0 else "check"


def load_run(files: list[Path]) -> dict:
    runs: dict = {}
    for f in files:
        d = json.loads(f.read_text(encoding="utf-8"))
        runs[(d["split"], d["transform"])] = d
    return runs


def per_row_predictions(run: dict, split: str, transform: str, n: int) -> dict[str, list[bool]]:
    base = run[(split, "identity")]
    out = {layer: list(base[layer]) for layer in LAYERS}
    if transform != "identity":
        d = run[(split, transform)]
        for k, i in enumerate(d["idx"]):
            for layer in LAYERS:
                out[layer][i] = d[layer][k]
    out["union"] = [a or b for a, b in zip(out["regex"], out["ner"])]
    return out


def metrics(expected, pred, mask, base_pred) -> dict:
    """Recall over positives and FP rate over negatives inside ``mask`` for ``pred``, plus the
    unperturbed values on the same rows."""
    def counts(p):
        tp = sum(1 for e, x, m in zip(expected, p, mask) if m and e and x)
        pos = sum(1 for e, m in zip(expected, mask) if m and e)
        fp = sum(1 for e, x, m in zip(expected, p, mask) if m and not e and x)
        neg = sum(1 for e, m in zip(expected, mask) if m and not e)
        return tp, pos, fp, neg
    tp, pos, fp, neg = counts(pred)
    btp, _, bfp, _ = counts(base_pred)
    return {"tp": tp, "pos": pos, "fp": fp, "neg": neg, "base_tp": btp, "base_fp": bfp,
            "recall": tp / pos if pos else None, "fp_rate": fp / neg if neg else None,
            "base_recall": btp / pos if pos else None, "base_fp_rate": bfp / neg if neg else None,
            "recall_ci": wilson(tp, pos), "fp_rate_ci": wilson(fp, neg)}


GROUPS = ["dev", "dev-TUNE", "dev-CHECK", "personalized", "openai"]


def group_masks(rows_by_split: dict) -> dict:
    masks = {}
    dev = rows_by_split["dev"]
    masks["dev"] = ("dev", [True] * len(dev))
    masks["dev-TUNE"] = ("dev", [tune_check(r) == "tune" for r in dev])
    masks["dev-CHECK"] = ("dev", [tune_check(r) == "check" for r in dev])
    for s in ("personalized", "openai"):
        masks[s] = (s, [True] * len(rows_by_split[s]))
    return masks


def command_report(args) -> None:
    rows_by_split = {s: load_rows(s, args.data_root) for s in SPLIT_FILES}
    runs = {"old": load_run(args.old), "new": load_run(args.new)}
    variants: dict[str, dict] = {}
    for f in args.variants:
        d = json.loads(f.read_text(encoding="utf-8"))
        variants.setdefault(d["label"], {})[(d["split"], d["transform"])] = d
    transforms = ["identity"] + [t for t in TRANSFORMS if all((s, t) in runs["new"] for s in SPLIT_FILES)]
    masks = group_masks(rows_by_split)
    result: dict = {}
    for tree in ("old", "new"):
        for t in transforms:
            for g, (split, mask) in masks.items():
                rows = rows_by_split[split]
                expected = [bool(r["expected_has_pii"]) for r in rows]
                pred = per_row_predictions(runs[tree], split, t, len(rows))
                base = per_row_predictions(runs[tree], split, "identity", len(rows))
                changed = [True] * len(rows) if t == "identity" else [False] * len(rows)
                if t != "identity":
                    for i in runs[tree][(split, t)]["idx"]:
                        changed[i] = True
                for layer in ("regex", "ner", "union"):
                    full = metrics(expected, pred[layer], mask, base[layer])
                    aff_mask = [m and c for m, c in zip(mask, changed)]
                    affected = metrics(expected, pred[layer], aff_mask, base[layer])
                    result.setdefault(tree, {}).setdefault(t, {}).setdefault(g, {})[layer] = {"all": full, "affected": affected}
    result["variants"] = variant_results(variants, rows_by_split, masks)
    args.out_json.write_text(json.dumps(result, indent=1), encoding="utf-8")
    args.out_md.write_text(render_markdown(result, transforms), encoding="utf-8")


def variant_results(variants: dict, rows_by_split: dict, masks: dict) -> dict:
    out: dict = {}
    for label, run in variants.items():
        for (split, t) in sorted(k for k in run if k[0] == "dev"):
            if not all((s, t) in run and (s, "identity") in run for s in SPLIT_FILES):
                continue
            for g in ("dev", "personalized", "openai"):
                s, mask = masks[g]
                rows = rows_by_split[s]
                expected = [bool(r["expected_has_pii"]) for r in rows]
                pred = per_row_predictions(run, s, t, len(rows))
                base = per_row_predictions(run, s, "identity", len(rows))
                for layer in ("regex", "ner", "union"):
                    out.setdefault(label, {}).setdefault(t, {}).setdefault(g, {})[layer] = metrics(expected, pred[layer], mask, base[layer])
    return out


def pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}"


def render_markdown(result: dict, transforms: list[str]) -> str:
    lines = []
    for layer in ("regex", "ner", "union"):
        for kind, title in (("recall", "Recall on positives"), ("fp_rate", "FP rate on negatives")):
            lines += [f"\n#### {layer}: {title} (percent; each cell is `new (old)`; delta in points vs unperturbed `new / old`)\n",
                      "| Transform | " + " | ".join(GROUPS) + " |", "|---|" + "---|" * len(GROUPS)]
            for t in transforms:
                cells = []
                for g in GROUPS:
                    n = result["new"][t][g][layer]["all"]
                    o = result["old"][t][g][layer]["all"]
                    if t == "identity":
                        cells.append(f"{pct(n[kind])} ({pct(o[kind])})")
                    else:
                        dn = None if n[kind] is None else 100 * (n[kind] - n["base_" + kind])
                        do = None if o[kind] is None else 100 * (o[kind] - o["base_" + kind])
                        f = lambda v: "n/a" if v is None else f"{v:+.1f}"
                        cells.append(f"{pct(n[kind])} ({pct(o[kind])}) d {f(dn)} / {f(do)}")
                lines.append(f"| {t} | " + " | ".join(cells) + " |")
    for label, per_t in result.get("variants", {}).items():
        lines += [f"\n#### Variant `{label}` versus the unmodified new tree (percent; `variant (new)`)\n",
                  "| Transform | Layer | dev recall | dev FP | personalized recall | personalized FP | openai recall | openai FP |",
                  "|---|---|---|---|---|---|---|---|"]
        for t, per_g in per_t.items():
            for layer in ("regex", "ner", "union"):
                cells = []
                for g in ("dev", "personalized", "openai"):
                    v, n = per_g[g][layer], result["new"][t][g][layer]["all"]
                    cells += [f"{pct(v['recall'])} ({pct(n['recall'])})", f"{pct(v['fp_rate'])} ({pct(n['fp_rate'])})"]
                lines.append(f"| {t} | {layer} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--tree", type=Path, required=True)
    run.add_argument("--label", required=True)
    run.add_argument("--data-root", type=Path, required=True)
    run.add_argument("--generated", type=Path, required=True)
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--defence", action="store_true", help="apply candidate_canonicalise to the probe input (simulation)")
    run.add_argument("--set-flag", nargs="*", default=[], metavar="NAME=BOOL", help="override GLOBAL_CONFIG booleans")
    run.add_argument("--splits", nargs="+", choices=sorted(SPLIT_FILES), default=sorted(SPLIT_FILES))
    run.add_argument("--transforms", nargs="+", choices=["identity", *TRANSFORMS], default=["identity", *TRANSFORMS])
    rep = sub.add_parser("report")
    rep.add_argument("--old", type=Path, nargs="+", required=True)
    rep.add_argument("--new", type=Path, nargs="+", required=True)
    rep.add_argument("--variants", type=Path, nargs="*", default=[], help="run files of simulation variants (e.g. a defence)")
    rep.add_argument("--data-root", type=Path, required=True)
    rep.add_argument("--out-md", type=Path, required=True)
    rep.add_argument("--out-json", type=Path, required=True)
    args = parser.parse_args()
    command_run(args) if args.command == "run" else command_report(args)


if __name__ == "__main__":
    main()
