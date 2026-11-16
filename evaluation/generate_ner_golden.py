"""Golden output and Unicode tables for the Rust ``privoke-ner-layer`` crate (RUST-S13).

The Rust crate ports the NER layer of the client runtime (``extension/client-runtime/src/NER``): the spaCy
detector with its caseless gate, the post-filter, the use-case table and the experimental pattern detector.
This tool produces everything the crate is checked against, from the unchanged Python client runtime and host
Python (``evaluation/.venv-v1-v3-pipeline``).

Every NER-layer run selects the layer explicitly: ``pipeline.analyse_text(text, layers=["ner"])`` and the returned
layer execution is asserted to be exactly one ``ner`` layer with status ``ok`` or ``error``. The regex and semantic
layers are never requested, and an empty layer list is never sent (an empty list means the whole detector
pipeline). Each run also records the post-filter's decision log (rule, candidate, outcome) by wrapping
``ner_detector.postfilter`` without changing its behaviour.

Subcommands::

    tables      write rust/crates/privoke-ner-layer/src/unicode_tables.rs (Python's Unicode data)
    synthetic   write the committed synthetic fixture (inputs are generic sentences defined here), with the spaCy
                results the run saw, so that the Rust crate can replay them without a worker
    sets        write golden for the recorded NER sets into an ignored directory

``sets`` reads datasets through ``rust/services/spacy-worker/tools/parity_sets.py`` (the sets of the stage 11 parity
gate: development, personalized, openai, piimb, dolly15k, oasst2 and the synthetic stress set) from ``--data-root``
(the main checkout holds the ignored data). ``final.jsonl`` is never opened. Golden output from recorded sets goes
under ``evaluation/results/`` (ignored by Git) and is never committed. The protobuf clients must exist first
(``evaluation/setup-host.py``).
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import random
import sys
import time
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CRATE = REPO / "rust" / "crates" / "privoke-ner-layer"
FIXTURES = CRATE / "tests" / "fixtures"
PARITY_SETS = REPO / "rust" / "services" / "spacy-worker" / "tools" / "parity_sets.py"
SURROGATES = range(0xD800, 0xE000)
MAX_CP = 0x110000

# NER-layer configurations: (case_preserving, strip_format, digits, email, caseless_gate, postfilter)
LAYER_CONFIGS = {
    "default": (True, False, False, False, False, True),
    "caseless": (True, False, False, False, True, True),
    "format": (True, True, False, False, False, True),
    "digits": (True, False, True, False, False, True),
    "email": (True, False, False, True, False, True),
    "all-flags": (True, True, True, True, False, True),
    "caseless-all-flags": (True, True, True, True, True, True),
    "lowercase": (False, False, False, False, False, True),
    "no-postfilter": (True, False, False, False, False, False),
}
# Pattern-detector configurations: (use_cues, use_shape, use_recurrence, use_gazetteer, hybrid)
PATTERN_CONFIGS = {
    "default": (True, True, True, False, False),
    "gazetteer": (True, True, True, True, False),
    "cues": (True, False, False, False, False),
    "shape": (False, True, False, False, False),
    "no-recurrence": (True, True, False, False, False),
    "hybrid": (True, True, True, False, True),
}
SET_NAMES = ["development", "personalized", "openai", "piimb", "dolly15k", "oasst2", "stress"]
DERIVED_PREFIXES = ("lower-", "upper-")
FUZZ_SET = "fuzz"


def bootstrap() -> None:
    for path in (REPO / "extension" / "client-runtime", REPO / "shared" / "python", REPO / "extension" / "client-runtime" / "generated"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def refuse_final(path: Path) -> None:
    if "final" in path.name.lower():
        raise SystemExit(f"refusing to read {path}: the final endpoint is consumed")


def has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) < 0xE000 for ch in text)


def error_message(exc: Exception) -> str:
    return str(exc).strip() or exc.__class__.__name__


# --- records -------------------------------------------------------------------------------------------------
def result_record(result) -> dict:
    return {
        "span": list(result.span) if result.span is not None else None,
        "text": result.section_of_text,
        "packed": result.classification.pack(),
        "confidence": result.confidence,
        "reasoning": result.reasoning,
        "metadata": dict(result.metadata or {}),
    }


def decision_record(decision) -> dict:
    cand = decision.candidate
    return {
        "rule": decision.rule,
        "stage": decision.stage,
        "keep": decision.keep,
        "sensitivity": decision.sensitivity.value if decision.sensitivity is not None else None,
        "label": cand.label,
        "start": cand.start,
        "end": cand.end,
        "text": cand.text,
        "strong_cue": cand.strong_cue,
        "multi_token": cand.multi_token,
        "relation_cue": cand.relation_cue,
        "geo_or_org_cue": cand.geo_or_org_cue,
    }


def doc_body(doc) -> dict:
    """The tokens and entities of a spaCy document, in the field order of the stage 11 worker protocol."""
    return {
        "tokens": [[t.text, t.idx, t.whitespace_, t.is_alpha, t.lower_, t.tag_, t.pos_, t.lemma_, t.dep_, t.head.i] for t in doc],
        "ents": [[e.start_char, e.end_char, e.label_] for e in doc.ents],
    }


class RecordingNlp:
    """Wraps the spaCy pipeline: results are cached per document and, when asked, recorded for replay."""

    def __init__(self, nlp) -> None:
        self._nlp = nlp
        self._mode = "full"
        self.cache: dict = {}
        self.log: list[dict] = []
        self.record = False

    def __getattr__(self, name):
        return getattr(self._nlp, name)

    def __call__(self, text):
        key = (self._mode, text)
        doc = self.cache.get(key)
        if doc is None:
            doc = self._nlp(text)
            self.cache[key] = doc
            if self.record:
                self.log.append({"sel": self._mode, "text": text, "body": doc_body(doc)})
        return doc

    def select_pipes(self, **kwargs):
        return _Selection(self, self._nlp.select_pipes(**kwargs))

    def reset(self) -> None:
        self.cache = {}
        self.log = []


class _Selection:
    def __init__(self, owner: RecordingNlp, inner) -> None:
        self._owner = owner
        self._inner = inner

    def __enter__(self):
        self._inner.__enter__()
        self._owner._mode = "tagger"
        return self

    def __exit__(self, *exc):
        self._owner._mode = "full"
        return self._inner.__exit__(*exc)


# --- Python runtime handles -----------------------------------------------------------------------------------------
class Runtime:
    """The NER layer behind the real pipeline entry point, with the post-filter's decisions recorded."""

    def __init__(self, record_spacy: bool = False) -> None:
        bootstrap()
        from src import pipeline
        from src.config import GLOBAL_CONFIG
        from src.NER import ner_detector, build_ner_detector
        from src.NER.pattern_entity_detector import PatternEntityDetector

        self.pipeline = pipeline
        self.config = GLOBAL_CONFIG
        self.pattern_type = PatternEntityDetector
        self.detector = build_ner_detector()
        self.nlp = RecordingNlp(self.detector.nlp)
        self.nlp.record = record_spacy
        self.detector.nlp = self.nlp
        self.decisions: list[list[dict]] = []

        original = ner_detector.postfilter

        def recording_postfilter(doc, entities, **kwargs):
            decided = original(doc, entities, **kwargs)
            self.decisions.append([decision_record(d) for d in decided])
            return decided

        ner_detector.postfilter = recording_postfilter

        def detector_for(layer, semantic_model_id=None):
            if layer != pipeline.NER_LAYER:
                raise AssertionError(f"layer {layer!r} requested by an NER-only run")
            return self.detector.extract_entities

        pipeline._detector_for = detector_for

    def layer(self, text: str, name: str) -> dict:
        case_preserving, fmt, digits, email, caseless, postfilter = LAYER_CONFIGS[name]
        config = self.config
        config.case_preserving_detectors = case_preserving
        config.strip_format_chars = fmt
        config.canonicalise_digits = digits
        config.canonicalise_email_words = email
        config.ner_caseless_gate = caseless
        config.ner_postfilter = postfilter
        self.decisions = []
        analysis = self.pipeline.analyse_text(text, layers=["ner"])
        layers = [(item.layer, item.status) for item in analysis.layers]
        if len(layers) != 1 or layers[0][0] != "ner":
            raise AssertionError(f"unexpected layer execution {layers}")
        execution = analysis.layers[0]
        if execution.status == "error":
            return {"error": execution.error, "decisions": [d for d in self.decisions]}
        if execution.status != "ok":
            raise AssertionError(f"unexpected layer status {execution.status}")
        if len(self.decisions) != (1 if postfilter else 0):
            raise AssertionError(f"post-filter ran {len(self.decisions)} times for {name}")
        return {
            "results": [result_record(r) for r in execution.results],
            "decisions": self.decisions[0] if self.decisions else [],
        }

    def pattern(self, text: str, name: str, seeds) -> list[dict]:
        cues, shape, recurrence, gazetteer, hybrid = PATTERN_CONFIGS[name]
        detector = self.pattern_type(use_cues=cues, use_shape=shape, use_recurrence=recurrence, use_gazetteer=gazetteer)
        if hybrid:
            return [result_record(r) for r in detector.augment_entities(text, seeds)]
        return [result_record(r) for r in detector.extract_entities(text)]

    def seeds(self, text: str):
        """spaCy results on the text itself, the hybrid mode's seeds (default configuration)."""
        config = self.config
        config.ner_caseless_gate = False
        config.ner_postfilter = True
        return self.detector.extract_entities(text)


def attempt(function, *args):
    try:
        return function(*args)
    except AssertionError:
        raise
    except Exception as exc:  # noqa: BLE001 - recorded as the pipeline would
        return {"error": error_message(exc)}


def golden_row(runtime: Runtime, row_id, text: str, layer_names, pattern_names, record_spacy: bool = False) -> dict:
    runtime.nlp.reset()
    row = {"id": row_id, "text": text, "layer": {}, "pattern": {}}
    for name in layer_names:
        row["layer"][name] = runtime.layer(text, name)
    if pattern_names:
        seeds = attempt(runtime.seeds, text)
        seed_records = [result_record(r) for r in seeds] if not isinstance(seeds, dict) else seeds
        row["seeds"] = seed_records
        for name in pattern_names:
            if isinstance(seeds, dict):
                row["pattern"][name] = {"error": seeds["error"]}
            else:
                result = attempt(runtime.pattern, text, name, seeds)
                row["pattern"][name] = {"results": result} if isinstance(result, list) else result
    if record_spacy:
        row["spacy"] = runtime.nlp.log
    return row


# --- Unicode tables ---------------------------------------------------------------------------------------------------
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


def fmt_ranges(name: str, items, doc: str) -> str:
    body = ", ".join(f"(0x{a:x}, 0x{b:x})" for a, b in items)
    return f"/// {doc}\npub static {name}: &[(u32, u32)] = &[{body}];\n\n"


def generate_tables() -> str:
    out = [
        "// @generated by evaluation/generate_ner_golden.py tables. Do not edit.\n"
        "// Unicode data of the reference interpreter (CPython), not of any Rust crate.\n\n"
        "#![allow(clippy::unreadable_literal)]\n\n"
        f'/// Unicode version of the reference Python (`unicodedata.unidata_version`).\npub const UNICODE_VERSION: &str = "{unicodedata.unidata_version}";\n\n'
    ]
    out.append(fmt_ranges("ALPHA", ranges(str.isalpha), "`str.isalpha()`."))
    out.append(fmt_ranges("UPPER", ranges(str.isupper), "`str.isupper()` of one character."))
    out.append(fmt_ranges("LOWER", ranges(str.islower), "`str.islower()` of one character."))
    out.append(fmt_ranges("PUNCT", ranges(lambda c: unicodedata.category(c).startswith("P")), "General category `P*` (spaCy `is_punct`)."))
    return "".join(out).rstrip("\n") + "\n"


# --- inputs ------------------------------------------------------------------------------------------------------------
GIVEN = ["Sara", "Angela", "Dana", "Maria", "Ethan", "Priya", "Omar", "Jun", "Lena", "Marcus", "Chloe", "Tariq", "Nora", "Felix", "Ines"]
FAMILY = ["Okafor", "Smith", "Nguyen", "Lopez", "Brown", "Haddad", "Kowalski", "Rossi", "Tanaka", "Murphy", "Silva", "Novak"]
PLACES = ["Boston", "Paris", "Lagos", "Toronto", "Denver", "Berlin", "Osaka", "Nairobi", "Lima", "Austin", "Cairo", "Oslo"]
ORGS = ["Acme Corp", "Globex", "Initech", "Northwind University", "Contoso Bank", "Umbrella Health", "Stark Industries", "Wayne Foundation"]
ROLES = ["sister", "manager", "doctor", "therapist", "neighbour", "boss", "friend", "nurse", "teacher", "landlord", "son", "colleague"]
COMMON = ["Will", "Rose", "Grace", "Hope", "Mark", "Bill", "Art", "Sue", "Page", "Young", "Park", "Hunter", "Baker", "Summer", "June"]
TEMPLATES = [
    "My {role} {person} lives in {place}.",
    "I work at {org} in {place}.",
    "Dear {person},\n\nThanks for the update from {place}.\n\nBest,\n{given}",
    "Name: {person}\nCity: {place}\nEmployer: {org}",
    "# {org} Quarterly Review\n\n{given} will present on Monday.",
    "{org} Annual Report Summary",
    "Hi, I'm {given} and I live in {place} with my {role}.",
    "Can you draft an email to {person} about the move to {place}?",
    "{common} joined us yesterday, and {common} said the weather in {place} was fine.",
    "Meeting notes with {person}: budget, hiring, travel to {place}.",
    "{person} said that {given} is leaving {org} next week.",
    "Please send the report to {person} at {org} before Friday.",
    "I was born in {place} and my {role} {given} still works for {org}.",
    "the {role} {given} called from {place} about the invoice",
    "{person}: I will be in {place} on the 5th, call me back please.",
    "XXXX lives in YYYY and works at ZZZZ, according to the form.",
    "[Name] from [City] contacted {org} on behalf of {person}.",
    "In 2019 {org} opened an office at 221 Baker Street, {place}.",
    "What is the capital of {place}? Is {place} bigger than {place}?",
    "{given} and {given} met {person} near the {place} station.",
]


def fuzz_rows(count: int = 4000, seed: int = 20261117):
    rng = random.Random(seed)
    rows = []
    for index in range(count):
        parts = []
        for _ in range(rng.randint(1, 3)):
            template = rng.choice(TEMPLATES)
            parts.append(template.format(
                role=rng.choice(ROLES), person=f"{rng.choice(GIVEN)} {rng.choice(FAMILY)}", given=rng.choice(GIVEN),
                place=rng.choice(PLACES), org=rng.choice(ORGS), common=rng.choice(COMMON),
            ))
        text = rng.choice(["\n\n", " ", "\n"]).join(parts)
        shape = rng.random()
        if shape < 0.12:
            text = text.lower()
        elif shape < 0.2:
            text = text.upper()
        elif shape < 0.25:
            text = text.title()
        rows.append((f"fuzz-{index:05d}", text))
    return rows


SYNTHETIC_TEXTS = [
    "My name is Alice Smith and I live in Paris.",
    "my sister sara works at acme corp in boston and her manager is dana.",
    "MY SISTER SARA WORKS AT ACME CORP IN BOSTON AND HER MANAGER IS DANA.",
    "I met Dr. Okafor in Lagos. Dr. Okafor said hello.",
    "Dear Mr. Haddad,\n\nI am writing from Cairo.\n\nSincerely,\nNora Lovelace\n",
    "Name: John Smith\nCity: Chicago\nState: IL\n\n\n\nZip: 60601",
    "# Meeting Notes\n\n## Budget Review Meeting\n\nAction items for Q3 Planning and Roadmap",
    "Project Phoenix Status Report Summary",
    "XXXX lives in YYYY and works at ZZZZ.",
    "Xs and Ns were replaced in the form [Name] <City> {{Org}}.",
    "will you meet grace in june? mark said hope is in the park.",
    "Will and Rose went to Park Avenue with Hunter Baker.",
    "Contact: ***** at ******** about the claim.",
    "Visit https://www.example.com/contact or mail jane_doe@example.org for Jane Doe in Austin.",
    "Order A12345B shipped to Denver; reference 12ab34cd for Acme.",
    "I was born in NYC and moved to the U.S. as a child; my hometown is LA.",
    "In the US, the UK, and the EU, Apple and Google compete; NASA and the FBI watch.",
    "Sara's account was closed. Sara, age 34, lives in Berlin.",
    "Alice: I think we should leave.\nBob: Where to? Osaka? Maybe Nairobi next month.",
    "Thanks,\nPriya\n\nPriya Raman, Infosys, Bengaluru",
    "Summary of 123 Main Street, Springfield, IL 62704 and 45 Park Avenue, Boston, MA 02108.",
    "my doctor, angela, is based in lima and the clinic is near oslo.",
    "She said the Eiffel Tower in Paris is taller than the Tower of London.",
    "Ask Jun Tanaka (patient) to bring the report from Northwind University.",
    "Friend of mine named Marcus works for Contoso Bank; Marcus lives near Toronto.",
    "Hello, I'm Lena and my husband Felix is from Oslo; we live in Austin now.",
    "Café owner José Álvarez lives in München; his fiancée Zoë is in Zürich.",
    "Name – Maria Silva — contact – Omar Haddad, tel 555 0100",
    "Alice’s phone and Bob’s email were shared with Carol Danvers in Seattle.",
    "\U0001F600 Alice met Bob in Paris \U0001F1EB\U0001F1F7 on Monday.",
    "我叫张伟，住在北京市。 Tom visited 東京 with 张伟.",
    "Jo​hn Sm‌ith l‍ives in Lon​don with his wife Mary Jones.",
    "j o h n   d o e   l i v e s   i n   p a r i s",
    "call me at five five five one two three four or zero one two three four five six",
    "reach me at jane dot doe at example dot com or jane(at)example(dot)com, thanks Jane",
    "ALICE SMITH LIVES IN PARIS AND WORKS AT GOOGLE. HER PHONE IS 555-0100.",
    "alice smith lives in paris and works at google. her phone is 555-0100.",
    "Mixed Case sENTence WiTh RaNdOm CaPs In New YORK",
    "I'm Tom, I'd like to book a table; I've been to London. I'll go with Anna.",
    "I I I I am here",
    "i live in london and i work at google; ask sarah smith.",
    "Dr. Prof. Mr. Mrs. Ms. Smith lives at 5 Elm St. in Springfield. Mr. Brown knows.",
    "Maria Garcia, maria.garcia@example.com, policy INS-4471, 12 Oak Lane, Dallas, TX 75201",
    "The patient, Avery Ali, was seen at Umbrella Health by Dr. Rossi on Tuesday.",
    "Student Alex Davis from Stark Industries Training Centre.",
    "Sincerely yours, the team at Globex, 7 Wall Street, New York.",
    "Hunter, Baker, Young, Page and Summer are all in the list.",
    "A. B. Smith and J. R. R. Tolkien lived in Oxford; Smith, A. B. wrote to Tolkien.",
    "   leading and trailing spaces   ",
    "tabs\tand\r\nwindows\r\nnewlines\x0b\x0c done in Rome",
    "!!! ??? ... --- ((( ))) [[[ ]]] {{{ }}}",
    "Born 12/03/1985 in Springfield, Illinois. Mother: Linda Lee. Father: Paul Lee.",
    "Alice Smith Alice Smith Alice Smith lives in Boston Boston",
    "Berlin Berlin Berlin",
    "ORG: Acme Corp; PERSON: Carol Smith; PLACE: Seattle",
    "Name:\tJohn Smith\nCity:\tChicago",
    "I think Apple released a new iPhone in California last year, said Tim.",
    "Hi Dana, could you ask Priya in Lagos about Initech and Umbrella Health?",
    "he lives in 10 downing street, london, uk. his friend is boris.",
    "x" * 20,
    "",
    " ",
    "a",
    "I",
]


def synthetic_inputs() -> list[tuple[str, str]]:
    rows = [(f"synthetic-{i:03d}", text) for i, text in enumerate(SYNTHETIC_TEXTS) if text != ""]
    rows.extend(fuzz_rows(count=60, seed=20261118))
    return rows


# --- commands -------------------------------------------------------------------------------------------------------------
def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")


def cmd_tables(args) -> None:
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_tables(), encoding="utf-8", newline="\n")
    print(f"wrote {path} (Unicode {unicodedata.unidata_version})")


def queried_lexicon(runtime: Runtime, rows) -> list[str]:
    """The post-filter's lexicon words that the recorded tagger runs ask about (a replay needs no more).

    The common-word rule tests ``lemma.lower()`` and ``lower_`` of each re-tagged word against the model's lemma-index
    word list; membership of those words is all a replay has to answer, and the list is never empty when the model's is
    not (the rule checks that first).
    """
    from src.NER.ner_postfilter import _english_lexicon

    lexicon = _english_lexicon(runtime.nlp)
    asked = set()
    for row in rows:
        for record in row.get("spacy", []):
            if record["sel"] != "tagger":
                continue
            for token in record["body"]["tokens"]:
                asked.add(token[7].lower())
                asked.add(token[4])
    present = sorted(word for word in asked if word in lexicon)
    if not present and lexicon:
        present = [sorted(lexicon)[0]]
    return present


def cmd_synthetic(args) -> None:
    runtime = Runtime(record_spacy=True)
    rows = [golden_row(runtime, row_id, text, list(LAYER_CONFIGS), list(PATTERN_CONFIGS), record_spacy=True) for row_id, text in synthetic_inputs()]
    payload = json.dumps({"unicode": unicodedata.unidata_version, "python": sys.version.split()[0],
                          "lexicon": queried_lexicon(runtime, rows), "rows": rows},
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    Path(args.out).write_bytes(base64.b64encode(payload) + b"\n")
    print(f"wrote {args.out}: {len(rows)} rows x {len(LAYER_CONFIGS)} layer configs x {len(PATTERN_CONFIGS)} pattern configs")


def load_parity_sets():
    spec = importlib.util.spec_from_file_location("parity_sets", PARITY_SETS)
    module = importlib.util.module_from_spec(spec)
    sys.modules["parity_sets"] = module
    spec.loader.exec_module(module)
    return module


def load_sets(names: list[str], data_root: Path) -> dict[str, list[str]]:
    """Texts of the requested sets: the stage 11 sets, ``lower-``/``upper-`` variants of them, and the fuzz corpus."""
    base = {n[6:] if n.startswith(DERIVED_PREFIXES) else n for n in names if n != FUZZ_SET}
    sets: dict[str, list[str]] = {}
    if base:
        parity = load_parity_sets()
        raw, _ = parity.extract(data_root)
        for name in base:
            sets[name] = [t for t in raw[name] if parity.encodable(t)]
    out: dict[str, list[str]] = {}
    for name in names:
        if name == FUZZ_SET:
            out[name] = [text for _, text in fuzz_rows()]
        elif name.startswith("lower-"):
            out[name] = [t.lower() for t in sets[name[6:]]]
        elif name.startswith("upper-"):
            out[name] = [t.upper() for t in sets[name[6:]]]
        else:
            out[name] = sets[name]
    return out


def cmd_sets(args) -> None:
    runtime = Runtime()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    layer_names = args.layer_configs or list(LAYER_CONFIGS)
    pattern_names = [] if args.no_pattern else (args.pattern_configs or list(PATTERN_CONFIGS))
    texts_by_set = load_sets(args.sets, Path(args.data_root))
    summary = {"unicode": unicodedata.unidata_version, "python": sys.version.split()[0], "sets": {}}
    for name in args.sets:
        texts = texts_by_set[name]
        indices = list(range(args.shard, len(texts), args.shards))
        if args.limit:
            indices = indices[: args.limit]
        started = time.time()
        kept = skipped = 0
        suffix = "" if args.shards == 1 else f".{args.shard}of{args.shards}"
        with (out / f"{name}{suffix}.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
            for index in indices:
                text = texts[index]
                if has_surrogate(text):
                    skipped += 1
                    continue
                handle.write(json.dumps(golden_row(runtime, index, text, layer_names, pattern_names), ensure_ascii=False) + "\n")
                kept += 1
        summary["sets"][name] = {"rows": kept, "skipped_lone_surrogate": skipped, "seconds": round(time.time() - started, 1),
                                 "layer_configs": layer_names, "pattern_configs": pattern_names, "shard": [args.shard, args.shards]}
        print(name, summary["sets"][name], flush=True)
    write_json(out / f"summary-{'-'.join(args.sets)}{'' if args.shards == 1 else f'.{args.shard}of{args.shards}'}.json", summary)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    tables = sub.add_parser("tables")
    tables.add_argument("--out", default=str(CRATE / "src" / "unicode_tables.rs"))
    tables.set_defaults(func=cmd_tables)
    synthetic = sub.add_parser("synthetic")
    synthetic.add_argument("--out", default=str(FIXTURES / "synthetic_golden.b64"))
    synthetic.set_defaults(func=cmd_synthetic)
    sets = sub.add_parser("sets")
    choices = SET_NAMES + [p + n for p in DERIVED_PREFIXES for n in ("development", "personalized", "openai")] + [FUZZ_SET]
    sets.add_argument("sets", nargs="+", choices=choices)
    sets.add_argument("--data-root", default=str(REPO), help="checkout that holds the ignored dataset files")
    sets.add_argument("--out", default=str(REPO / "evaluation" / "results" / "ner-golden-20261117"))
    sets.add_argument("--limit", type=int, default=0)
    sets.add_argument("--shard", type=int, default=0)
    sets.add_argument("--shards", type=int, default=1)
    sets.add_argument("--layer-configs", nargs="*", choices=sorted(LAYER_CONFIGS))
    sets.add_argument("--pattern-configs", nargs="*", choices=sorted(PATTERN_CONFIGS))
    sets.add_argument("--no-pattern", action="store_true", help="skip the pattern detector (it needs no spaCy of its own)")
    sets.set_defaults(func=cmd_sets)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
