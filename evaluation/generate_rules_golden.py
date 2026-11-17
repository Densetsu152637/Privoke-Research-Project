"""Golden output and Unicode tables for the Rust ``privoke-rules`` crate (RUST-S12).

The Rust crate ports the regex layer (``extension/client-runtime/src/regex``) and the
canonical-text preprocessing (``detection/preprocessing.py``). This tool produces everything
the crate is checked against, from the unchanged Python client runtime and host Python
(``evaluation/.venv-v1-v3-pipeline``).

Every regex-layer run selects the layer explicitly: ``pipeline.analyse_text(text,
layers=["regex"])`` and the returned layer execution is asserted to be exactly one ``regex``
layer. The semantic layer and NER are never requested, and an empty layer list is never sent
(an empty list means the whole detector pipeline).

Subcommands::

    tables      write rust/crates/privoke-rules/src/unicode_tables.rs (Python's Unicode data)
    inventory   write tests/fixtures/rule_inventory.json (every shipped rule, in order)
    synthetic   write the committed synthetic fixture (inputs live beside it)
    sets        write golden for the recorded detector sets into an ignored directory
    sweep       write the code point sweep (NFKC, lower, upper) into an ignored directory

``sets`` reads datasets from ``--data-root`` (the main checkout holds the ignored data) and
refuses any path named like ``final``: the locked-public final endpoint is consumed and is not
opened. Golden output from recorded sets goes under ``evaluation/results/`` (ignored by Git)
and is never committed. The protobuf clients must exist first (``evaluation/setup-host.py``).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import re
import sys
import time
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CRATE = REPO / "rust" / "crates" / "privoke-rules"
FIXTURES = CRATE / "tests" / "fixtures"
SURROGATES = range(0xD800, 0xE000)
MAX_CP = 0x110000

# --- configurations ---------------------------------------------------------------------------
# Normalisation: (lowercase, strip_format_chars, canonicalise_digits, canonicalise_email_words)
NORM_CONFIGS = {
    "lower": (True, False, False, False),
    "case": (False, False, False, False),
    "case+format": (False, True, False, False),
    "case+digits": (False, False, True, False),
    "case+email": (False, False, False, True),
    "case+all": (False, True, True, True),
    "lower+all": (True, True, True, True),
}
# Regex layer: (case_preserving, strip_format, digits, email, presidio, gitleaks)
LAYER_CONFIGS = {
    "default": (True, False, False, False, True, True),
    "lowercase": (False, False, False, False, True, True),
    "format": (True, True, False, False, True, True),
    "digits": (True, False, True, False, True, True),
    "email": (True, False, False, True, True, True),
    "all-flags": (True, True, True, True, True, True),
    "no-presidio": (True, False, False, False, False, True),
    "no-gitleaks": (True, False, False, False, True, False),
    "no-external": (True, False, False, False, False, False),
}
SET_FILES = {
    "development": "evaluation/results/locked-public/development.jsonl",
    "personalized": "evaluation/datasets/privoke_personalized_synthetic.jsonl",
    "openai": "evaluation/datasets/privoke_openai_synthetic.jsonl",
    "f1": "evaluation/results/fresh_sets_20261024/f1_piimb/piimb_fresh_f1.jsonl",
    "f2": "evaluation/results/fresh_sets_20261024/f2_natural_prompts/f2_natural_prompts.jsonl",
    "f3": "evaluation/results/fresh_sets_20261024/f3_spy/f3_spy.jsonl",
    "f4": "evaluation/results/fresh_sets_20261025/f4_piimb/piimb_fresh_f4.jsonl",
}
PROBE_PREFIX = "probe-"
FUZZ_SET = "fuzz"
FUZZ_FRAGMENTS = [
    "jane.doe@example.com", "john dot smith at gmail dot com", "a[at]b(dot)com", "x (at) y [dot] org", "415-555-2671",
    "(212) 555 0199", "+61 412 345 678", "123-45-6789", "123 45 6789", "4111 1111 1111 1111", "4111-1111-1111-1112",
    "GB82 WEST 1234 5698 7654 32", "DE89370400440532013000", "943 476 5919", "192.168.1.1", "10.0.0.1/24", "2001:db8::1",
    "00:1A:2B:3C:4D:5E", "https://example.com/a?token=abc", "www.example.org", "my doctor", "my salary is $85,000", "I live in Paris",
    "passport A1234567", "student ID 12345", "customer id: AB-12345", "password: hunter2", "ssn", "iban", "card", "AKIA" + "IOSFODNN7EXAMPLE",
    "gh" + "p_1234567890abcdefghijklmnopqrstuvwxyz12", "-----BEGIN " + "PRIVATE KEY-----", "five five five one two three four",
    "oh one two three four five six", "5-5-5-1-2-3-4", "1.2.3.4.5.6.7.8", "one two three", "explain what", "for example", "placeholder",
    "my wife", "my son aged 7", "I work at Acme", "address: 12 Main St", "plate ABC-1234", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "٤١٥ ٥٥٥ ٢٦٧١", "４１５５５５", "café",
    "résumé", "สวัสดี", "İstanbul", "ı", "ſ", "K", "Σ", "ΑΣ",
    "ﬁ", "①", "​", "‍", "­", "﻿", "‮", " ", "　", "\x1c", "\x85", "\U0001f600",
    "각", "ạ̇", "’", "'", '"', "`", "\\", "$", "^", "{", "}", "[", "]", "(", ")", ".", "-", "_", "@", ":",
    "=", "#", "/", "|", "?", "*", "+", "sumo", "SUMO", "ſumo", "okta", "Key", "i", "I", "id", "number", "no.", "ref", "code",
]
FUZZ_SEPARATORS = [" ", " ", " ", "  ", "\t", "\n", "\r\n", "", "", ", ", "; ", ": ", "\n\n"]


def bootstrap() -> None:
    for path in (REPO / "extension" / "client-runtime", REPO / "shared" / "python", REPO / "extension" / "client-runtime" / "generated"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def refuse_final(path: Path) -> None:
    if "final" in path.name.lower():
        raise SystemExit(f"refusing to read {path}: the final endpoint is consumed")


# --- run-length encoding of origins -------------------------------------------------------------
def encode_origins(origins) -> list[list[int]]:
    runs: list[list[int]] = []
    for start, end in origins:
        if runs and runs[-1][0] == start and runs[-1][1] == end:
            runs[-1][2] += 1
        else:
            runs.append([start, end, 1])
    return runs


def normalised_record(normalised) -> dict:
    return {"text": normalised.text, "runs": encode_origins(normalised.origins)}


def hit_record(result) -> dict:
    classification = result.classification
    return {
        "rule": (result.metadata or {}).get("rule_name"),
        "span": list(result.span) if result.span is not None else None,
        "text": result.section_of_text,
        "packed": classification.pack(),
        "confidence": result.confidence,
    }


def has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) < 0xE000 for ch in text)


# --- Python runtime handles -----------------------------------------------------------------------
class Runtime:
    """The regex layer behind the real pipeline entry point, with one detector per rule set."""

    def __init__(self) -> None:
        bootstrap()
        from src import pipeline
        from src.config import GLOBAL_CONFIG
        from src.detection import preprocessing
        from src.regex.rule_detector import RuleDetector

        self.pipeline = pipeline
        self.config = GLOBAL_CONFIG
        self.preprocessing = preprocessing
        self._detector_type = RuleDetector
        self._detectors: dict[tuple[bool, bool], object] = {}
        self._current = (True, True)
        original = pipeline._detector_for

        def detector_for(layer, semantic_model_id=None):
            if layer != pipeline.REGEX_LAYER:
                raise AssertionError(f"layer {layer!r} requested by a regex-only run")
            return self._detector(self._current).analyze

        self._original_detector_for = original
        pipeline._detector_for = detector_for

    def _detector(self, key: tuple[bool, bool]):
        if key not in self._detectors:
            os.environ["PRIVOKE_REGEX_PRESIDIO"] = "1" if key[0] else "0"
            os.environ["PRIVOKE_REGEX_GITLEAKS"] = "1" if key[1] else "0"
            try:
                self._detectors[key] = self._detector_type()
            finally:
                os.environ.pop("PRIVOKE_REGEX_PRESIDIO", None)
                os.environ.pop("PRIVOKE_REGEX_GITLEAKS", None)
        return self._detectors[key]

    def normalise(self, text: str, name: str):
        lowercase, fmt, digits, email = NORM_CONFIGS[name]
        options = self.preprocessing.RobustnessOptions(
            strip_format_chars=fmt, canonicalise_digits=digits, canonicalise_email_words=email
        )
        return self.preprocessing.normalize_with_offsets(text, lowercase=lowercase, robustness=options)

    def layer(self, text: str, name: str):
        case_preserving, fmt, digits, email, presidio, gitleaks = LAYER_CONFIGS[name]
        config = self.config
        config.case_preserving_detectors = case_preserving
        config.strip_format_chars = fmt
        config.canonicalise_digits = digits
        config.canonicalise_email_words = email
        self._current = (presidio, gitleaks)
        analysis = self.pipeline.analyse_text(text, layers=["regex"], regex_first=True)
        layers = [(item.layer, item.status) for item in analysis.layers]
        if len(layers) != 1 or layers[0][0] != "regex":
            raise AssertionError(f"unexpected layer execution {layers}")
        execution = analysis.layers[0]
        if execution.status == "error":
            return {"error": execution.error}
        if execution.status != "ok":
            raise AssertionError(f"unexpected layer status {execution.status}")
        return [hit_record(result) for result in execution.results]


def error_message(exc: Exception) -> str:
    return str(exc).strip() or exc.__class__.__name__


def attempt(function, *args):
    """Record an exception as the pipeline does (its message), instead of failing the run."""
    try:
        return function(*args)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 - mirrors pipeline._error_message
        return {"error": error_message(exc)}


def golden_row(runtime: Runtime, row_id: str, text: str, norm_names, layer_names) -> dict:
    def norm(name):
        result = attempt(runtime.normalise, text, name)
        return result if isinstance(result, dict) else normalised_record(result)

    return {
        "id": row_id,
        "text": text,
        "norm": {name: norm(name) for name in norm_names},
        "layer": {name: runtime.layer(text, name) for name in layer_names},
    }


# --- inventory ----------------------------------------------------------------------------------
def inventory() -> list[dict]:
    bootstrap()
    from src.regex.rule_registry import all_rule_definitions

    rows = []
    for rule in all_rule_definitions():
        row = {
            "name": rule.name,
            "signal": rule.signal,
            "packed": rule.classification.pack(),
            "flags": int(rule.flags),
            "pattern_sha256": hashlib.sha256(rule.pattern.encode("utf-8")).hexdigest(),
            "validator": rule.validator is not None,
            "downgrades": [
                {
                    "name": d.name,
                    "signal": d.signal,
                    "packed": d.classification.pack(),
                    "confidence": d.confidence,
                    "accept": d.accept is not None,
                }
                for d in rule.downgrades
            ],
        }
        if not rule.name.startswith("gitleaks_"):
            row["pattern"] = rule.pattern
        rows.append(row)
    return rows


# --- Unicode tables -------------------------------------------------------------------------------
def ranges(predicate) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    start = None
    for cp in range(MAX_CP + 1):
        hit = cp < MAX_CP and cp not in SURROGATES and predicate(chr(cp))
        if hit and start is None:
            start = cp
        elif not hit and start is not None:
            out.append((start, cp - 1))
            start = None
    return out


def rust_string(value: str) -> str:
    return '"' + "".join(f"\\u{{{ord(ch):x}}}" for ch in value) + '"'


def fmt_ranges(name: str, items, doc: str) -> str:
    body = ", ".join(f"(0x{a:x}, 0x{b:x})" for a, b in items)
    return f"/// {doc}\npub static {name}: &[(u32, u32)] = &[{body}];\n\n"


def generate_tables() -> str:
    out = [
        "// @generated by evaluation/generate_rules_golden.py tables. Do not edit.\n"
        "// Unicode data of the reference interpreter (CPython), not of any Rust crate.\n\n"
        "#![allow(clippy::unreadable_literal)]\n\n"
        f'/// Unicode version of the reference Python (`unicodedata.unidata_version`).\npub const UNICODE_VERSION: &str = "{unicodedata.unidata_version}";\n\n'
        f'/// Python version that produced the tables.\npub const PYTHON_VERSION: &str = "{sys.version.split()[0]}";\n\n'
    ]
    out.append(fmt_ranges("WORD", ranges(lambda c: c.isalnum() or c == "_"), "Python `\\w` (`str.isalnum()` or `_`)."))
    out.append(fmt_ranges("DECIMAL", ranges(str.isdecimal), "Python `\\d` (`str.isdecimal()`)."))
    out.append(fmt_ranges("ISDIGIT", ranges(str.isdigit), "`str.isdigit()`."))
    out.append(fmt_ranges("SPACE", ranges(str.isspace), "Python `\\s` and `str.isspace()`."))
    out.append(fmt_ranges("FORMAT", ranges(lambda c: unicodedata.category(c) == "Cf"), "General category `Cf`."))

    # Decimal digit values as runs (start, end, value at start).
    runs: list[tuple[int, int, int]] = []
    for cp in range(MAX_CP):
        if cp in SURROGATES or not chr(cp).isdecimal():
            continue
        value = unicodedata.decimal(chr(cp))
        if runs and runs[-1][1] == cp - 1 and runs[-1][2] + (cp - runs[-1][0]) == value:
            runs[-1] = (runs[-1][0], cp, runs[-1][2])
        else:
            runs.append((cp, cp, value))
    out.append("/// Decimal digit values: `(first, last, value of first)`.\npub static DECIMAL_VALUES: &[(u32, u32, u8)] = &["
               + ", ".join(f"(0x{a:x}, 0x{b:x}, {v})" for a, b, v in runs) + "];\n\n")

    # Canonical combining classes as runs.
    ccc: list[tuple[int, int, int]] = []
    for cp in range(MAX_CP):
        if cp in SURROGATES:
            continue
        value = unicodedata.combining(chr(cp))
        if not value:
            continue
        if ccc and ccc[-1][1] == cp - 1 and ccc[-1][2] == value:
            ccc[-1] = (ccc[-1][0], cp, value)
        else:
            ccc.append((cp, cp, value))
    out.append("/// Canonical combining classes: `(first, last, class)`; absent means 0.\npub static COMBINING: &[(u32, u32, u8)] = &["
               + ", ".join(f"(0x{a:x}, 0x{b:x}, {v})" for a, b, v in ccc) + "];\n\n")

    # Case maps (full mappings) for non-ASCII code points.
    lower = [(cp, chr(cp).lower()) for cp in range(0x80, MAX_CP) if cp not in SURROGATES and chr(cp).lower() != chr(cp)]
    upper = [(cp, chr(cp).upper()) for cp in range(0x80, MAX_CP) if cp not in SURROGATES and chr(cp).upper() != chr(cp)]
    out.append("/// `str.lower()` of a single non-ASCII character that changes.\npub static LOWER: &[(u32, &str)] = &["
               + ", ".join(f"(0x{cp:x}, {rust_string(s)})" for cp, s in lower) + "];\n\n")
    out.append("/// `str.upper()` of a single non-ASCII character that changes.\npub static UPPER: &[(u32, &str)] = &["
               + ", ".join(f"(0x{cp:x}, {rust_string(s)})" for cp, s in upper) + "];\n\n")

    # Final-sigma context, measured through the interpreter (the properties are not exposed).
    def cased_not_ignorable(c: str) -> bool:
        return (c + "Σ").lower()[-1] == "ς"

    def ignorable(c: str) -> bool:
        return not cased_not_ignorable(c) and ("a" + c + "Σ").lower()[-1] == "ς"

    out.append(fmt_ranges("CASED", ranges(cased_not_ignorable), "Cased and not case-ignorable (final sigma context)."))
    out.append(fmt_ranges("CASE_IGNORABLE", ranges(ignorable), "Case-ignorable (final sigma context)."))

    # IGNORECASE equivalents of ASCII letters among non-ASCII characters (sre semantics).
    probe = re.compile(r"[a-z]", re.IGNORECASE)
    equivalents = []
    for cp in range(0x80, MAX_CP):
        if cp in SURROGATES:
            continue
        c = chr(cp)
        if probe.fullmatch(c):
            letters = [x for x in "abcdefghijklmnopqrstuvwxyz" if re.fullmatch(x, c, re.IGNORECASE)]
            assert len(letters) == 1, (hex(cp), letters)
            equivalents.append((cp, letters[0]))
    out.append("/// Non-ASCII characters that `re.IGNORECASE` treats as an ASCII letter.\npub static ICASE_ASCII: &[(u32, char)] = &["
               + ", ".join(f"(0x{cp:x}, '{letter}')" for cp, letter in equivalents) + "];\n\n")

    # Normalisation data: full compatibility decomposition, composition pairs.
    nfkd = []
    for cp in range(0x80, MAX_CP):
        if cp in SURROGATES or 0xAC00 <= cp <= 0xD7A3:
            continue
        decomposed = unicodedata.normalize("NFKD", chr(cp))
        if decomposed != chr(cp):
            nfkd.append((cp, [ord(ch) for ch in decomposed]))
    out.append("/// Full compatibility decomposition (`NFKD`) of one character, Hangul syllables excluded.\npub static NFKD: &[(u32, &[u32])] = &[\n"
               + ",\n".join(f"    (0x{cp:x}, &[{', '.join(f'0x{x:x}' for x in seq)}])" for cp, seq in nfkd) + ",\n];\n\n")
    pairs = []
    for cp in range(0x80, MAX_CP):
        if cp in SURROGATES or 0xAC00 <= cp <= 0xD7A3:
            continue
        decomposition = unicodedata.decomposition(chr(cp))
        if not decomposition or decomposition.startswith("<"):
            continue
        parts = [int(item, 16) for item in decomposition.split()]
        if len(parts) == 2 and unicodedata.normalize("NFC", chr(parts[0]) + chr(parts[1])) == chr(cp):
            pairs.append((parts[0], parts[1], cp))
    pairs.sort()
    out.append("/// Primary composites: `(first, second, composite)`, sorted.\npub static COMPOSE: &[(u32, u32, u32)] = &["
               + ", ".join(f"(0x{a:x}, 0x{b:x}, 0x{c:x})" for a, b, c in pairs) + "];\n")
    return "".join(out)


# --- sweeps -----------------------------------------------------------------------------------------
def sweep_rows(seed: int = 20261117, sequences: int = 20000, stride: int = 1):
    for cp in range(0, MAX_CP, stride):
        if cp in SURROGATES:
            continue
        c = chr(cp)
        yield {"cp": cp, "nfkc": unicodedata.normalize("NFKC", c), "lower": c.lower(), "upper": c.upper(),
               "space": c.isspace(), "word": bool(re.fullmatch(r"\w", c)), "digit": bool(re.fullmatch(r"\d", c)),
               "cf": unicodedata.category(c) == "Cf", "ccc": unicodedata.combining(c)}
    rng = random.Random(seed)
    pool = [cp for cp in range(0x20, 0x3400) if cp not in SURROGATES]
    pool += [cp for cp in range(0xA000, 0x10000) if cp not in SURROGATES]
    marks = [cp for cp in range(MAX_CP) if cp not in SURROGATES and unicodedata.combining(chr(cp))]
    for index in range(sequences):
        length = rng.randint(1, 9)
        text = "".join(chr(rng.choice(marks if rng.random() < 0.4 else pool)) for _ in range(length))
        yield {"seq": index, "text": text, "nfkc": unicodedata.normalize("NFKC", text),
               "lower": text.lower(), "upper": text.upper()}


def synthetic_inputs() -> list[dict]:
    # Stored base64-encoded so that no token-shaped literal is committed.
    return json.loads(base64.b64decode((FIXTURES / "synthetic_inputs.b64").read_text()).decode("utf-8"))


# --- commands -------------------------------------------------------------------------------------------
def write_json(path: Path, value, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":")) if compact else json.dumps(value, ensure_ascii=False, indent=1)
    path.write_text(text + "\n", encoding="utf-8", newline="\n")


def cmd_tables(args) -> None:
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_tables(), encoding="utf-8", newline="\n")
    print(f"wrote {path} (Unicode {unicodedata.unidata_version}, Python {sys.version.split()[0]})")


def cmd_inventory(args) -> None:
    rows = inventory()
    write_json(Path(args.out), rows)
    print(f"wrote {args.out}: {len(rows)} rules")


def cmd_synthetic(args) -> None:
    runtime = Runtime()
    rows = []
    for case in synthetic_inputs():
        rows.append(golden_row(runtime, case["id"], case["text"], NORM_CONFIGS, LAYER_CONFIGS))
    payload = json.dumps({"unicode": unicodedata.unidata_version, "python": sys.version.split()[0], "rows": rows},
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    Path(args.out).write_text(base64.b64encode(payload).decode("ascii") + "\n", encoding="ascii", newline="\n")
    print(f"wrote {args.out}: {len(rows)} rows x {len(NORM_CONFIGS)} normalisations x {len(LAYER_CONFIGS)} layer configs")


def read_rows(name: str, data_root: Path) -> list[tuple[str, str]]:
    path = data_root / SET_FILES[name]
    refuse_final(path)
    rows = []
    with path.open(encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if not line.strip():
                continue
            record = json.loads(line)
            rows.append((str(record.get("id", record.get("uid", index))), record["text"]))
    return rows


def fuzz_rows(count: int = 6000, seed: int = 20261117) -> list[tuple[str, str]]:
    """Seeded random concatenations of identifier, obfuscation and Unicode fragments."""
    rng = random.Random(seed)
    rows = []
    for index in range(count):
        parts = []
        for _ in range(rng.randint(1, 14)):
            parts.append(rng.choice(FUZZ_FRAGMENTS))
            parts.append(rng.choice(FUZZ_SEPARATORS))
        rows.append((f"fuzz-{index:05d}", "".join(parts)))
    return rows


def load_set(name: str, data_root: Path) -> list[tuple[str, str]]:
    """Rows of a recorded set, its perturbed variants for ``probe-<set>``, or the fuzz corpus.

    The probe variants are the 15 pure, seeded input transforms of the detector robustness
    study (``evaluation/robustness_probe.py``: digit separators and words, bracketed e-mail,
    homoglyphs, zero-width characters, full-width digits, label typos) applied to every row.
    """
    if name == FUZZ_SET:
        return fuzz_rows()
    if not name.startswith(PROBE_PREFIX):
        return read_rows(name, data_root)
    sys.path.insert(0, str(REPO / "evaluation"))
    import robustness_probe

    rows = []
    for row_id, text in read_rows(name[len(PROBE_PREFIX):], data_root):
        for transform in robustness_probe.TRANSFORMS:
            changed = robustness_probe.apply_transform(transform, text, row_id)
            if changed != text:
                rows.append((f"{row_id}#{transform}", changed))
    return rows


def cmd_sets(args) -> None:
    runtime = Runtime()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    layer_names = args.layer_configs or list(LAYER_CONFIGS)
    norm_names = args.norm_configs or list(NORM_CONFIGS)
    summary = {"unicode": unicodedata.unidata_version, "python": sys.version.split()[0], "sets": {}}
    for name in args.sets:
        rows = load_set(name, Path(args.data_root))
        if args.limit:
            rows = rows[: args.limit]
        started = time.time()
        kept = skipped = 0
        with (out / f"{name}.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
            for row_id, text in rows:
                if has_surrogate(text):
                    skipped += 1
                    continue
                handle.write(json.dumps(golden_row(runtime, row_id, text, norm_names, layer_names), ensure_ascii=False) + "\n")
                kept += 1
        summary["sets"][name] = {"rows": kept, "skipped_lone_surrogate": skipped, "seconds": round(time.time() - started, 1),
                                 "norm_configs": norm_names, "layer_configs": layer_names}
        print(name, summary["sets"][name], flush=True)
    write_json(out / f"summary-{'-'.join(args.sets)}.json", summary)


def cmd_sweep(args) -> None:
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in sweep_rows(sequences=args.sequences, stride=args.stride):
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    print(f"wrote {path}: {count} rows")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    tables = sub.add_parser("tables")
    tables.add_argument("--out", default=str(CRATE / "src" / "unicode_tables.rs"))
    tables.set_defaults(func=cmd_tables)
    inv = sub.add_parser("inventory")
    inv.add_argument("--out", default=str(FIXTURES / "rule_inventory.json"))
    inv.set_defaults(func=cmd_inventory)
    synthetic = sub.add_parser("synthetic")
    synthetic.add_argument("--out", default=str(FIXTURES / "synthetic_golden.b64"))
    synthetic.set_defaults(func=cmd_synthetic)
    sets = sub.add_parser("sets")
    sets.add_argument("sets", nargs="+", choices=sorted(SET_FILES) + [PROBE_PREFIX + name for name in sorted(SET_FILES)] + [FUZZ_SET])
    sets.add_argument("--data-root", default=str(REPO), help="checkout that holds the ignored dataset files")
    sets.add_argument("--out", default=str(REPO / "evaluation" / "results" / "rules-golden-20261117"))
    sets.add_argument("--limit", type=int, default=0)
    sets.add_argument("--layer-configs", nargs="*", choices=sorted(LAYER_CONFIGS))
    sets.add_argument("--norm-configs", nargs="*", choices=sorted(NORM_CONFIGS))
    sets.set_defaults(func=cmd_sets)
    sweep = sub.add_parser("sweep")
    sweep.add_argument("--out", default=str(REPO / "evaluation" / "results" / "rules-golden-20261117" / "unicode_sweep.jsonl"))
    sweep.add_argument("--stride", type=int, default=1, help="code point step (1 sweeps every code point)")
    sweep.add_argument("--sequences", type=int, default=20000, help="random multi-character sequences")
    sweep.set_defaults(func=cmd_sweep)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
