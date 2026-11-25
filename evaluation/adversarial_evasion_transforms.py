"""Deterministic adversarial transforms for the ADVEVADE-20261116 privacy-evasion evaluation.

Every transform is a pure function ``(row, rng) -> str | None`` of a seed row and a
``random.Random`` seeded from ``sha256(SEED : variant : row id)``. A transform never reads
PriVoke output and never contains dataset-specific phrases. It returns ``None`` when it cannot
change the row (not applicable), and the harness then excludes that (row, variant) pair from
the denominators instead of counting it as a survival.

Transforms act on the annotated identifier spans of the seed row (``entities``: start, end,
label), which models an attacker who knows which substrings carry the sensitive value. Context
words are changed only by the spelling and paraphrase families.

Paraphrase, indirect-reference and multilingual variants come from declared tables and
templates in this file (generator revision ``GENERATOR_REVISION``). The tables were written
once, before any PriVoke output on the evaluation rows existed, and are never edited in
response to results. They are limited and fixed; the record states what they cannot cover.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
from pathlib import Path
from typing import Callable

try:  # tables only; reused read-only from the earlier robustness study
    from robustness_probe import DIGIT_WORDS, HOMOGLYPHS, ZERO_WIDTH
except ImportError:  # pragma: no cover - import path fallback when run as a package
    from evaluation.robustness_probe import DIGIT_WORDS, HOMOGLYPHS, ZERO_WIDTH

SEED = 20261116
GENERATOR_REVISION = "advevade-transforms-1"
LABEL_FAMILY_FILE = Path(__file__).resolve().parents[1] / "docs/research/label-family-mapping-20261024.json"

DIGIT_HOMOGLYPHS = {"0": ["О"], "3": ["З"]}  # Cyrillic O and Ze; NFKC leaves them alone
HOMOGLYPH_RATE = 0.5
ZERO_WIDTH_RATE = 0.5
SPELLING_CONTEXT_RATE = 0.25
LONG_FILLER_CHARS = 6000
WINDOW_FILLER_CHARS = 800


def row_rng(variant: str, row_id: str) -> random.Random:
    digest = hashlib.sha256(f"{SEED}:{variant}:{row_id}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


# --------------------------------------------------------------------------- spans
def merged_spans(row: dict) -> list[tuple[int, int, str]]:
    """Entity spans of the row, overlapping or empty spans merged/dropped, sorted by start."""
    text = row["text"]
    spans = sorted((int(e["start"]), int(e["end"]), str(e.get("label", ""))) for e in row.get("entities", []))
    merged: list[tuple[int, int, str]] = []
    for start, end, label in spans:
        if not (0 <= start < end <= len(text)):
            continue
        if merged and start < merged[-1][1]:
            previous = merged[-1]
            merged[-1] = (previous[0], max(previous[1], end), previous[2])
        else:
            merged.append((start, end, label))
    return merged


def rewrite_spans(text: str, spans: list[tuple[int, int, str]], fn: Callable[[str, str], str]) -> str:
    """Replace each span by ``fn(span_text, label)``, applied right to left."""
    for start, end, label in reversed(spans):
        text = text[:start] + fn(text[start:end], label) + text[end:]
    return text


def _changed(original: str, new: str) -> str | None:
    return new if new != original else None


_FAMILY_CACHE: dict | None = None


def label_family(label: str) -> str:
    global _FAMILY_CACHE
    if _FAMILY_CACHE is None:
        _FAMILY_CACHE = json.loads(LABEL_FAMILY_FILE.read_text(encoding="utf-8"))["label_to_family"]
    key = re.sub(r"[^a-z0-9]", "", label.lower())
    return _FAMILY_CACHE.get(key, "UNMAPPED")


def label_family_file_sha256() -> str:
    return hashlib.sha256(LABEL_FAMILY_FILE.read_bytes()).hexdigest()


# --------------------------------------------------------------------------- unicode and spacing
def t_homoglyph_span(row: dict, rng: random.Random) -> str | None:
    def convert(value: str, label: str) -> str:
        out = []
        for ch in value:
            options = HOMOGLYPHS.get(ch) or DIGIT_HOMOGLYPHS.get(ch)
            out.append(rng.choice(options) if options and rng.random() < HOMOGLYPH_RATE else ch)
        return "".join(out)
    return _changed(row["text"], rewrite_spans(row["text"], merged_spans(row), convert))


def t_zero_width_span(row: dict, rng: random.Random) -> str | None:
    def convert(value: str, label: str) -> str:
        out = []
        for index, ch in enumerate(value):
            out.append(ch)
            if index < len(value) - 1 and not ch.isspace() and rng.random() < ZERO_WIDTH_RATE:
                out.append(rng.choice(ZERO_WIDTH))
        return "".join(out)
    return _changed(row["text"], rewrite_spans(row["text"], merged_spans(row), convert))


def t_space_span(row: dict, rng: random.Random) -> str | None:
    def convert(value: str, label: str) -> str:
        chars = [ch for ch in value if not ch.isspace()]
        return " ".join(chars) if len(chars) > 1 else value
    return _changed(row["text"], rewrite_spans(row["text"], merged_spans(row), convert))


# --------------------------------------------------------------------------- spelling
def _typo(word: str, rng: random.Random) -> str:
    """One edit at an interior position: transpose, delete or double a character."""
    if len(word) < 4:
        return word
    i = rng.randint(1, len(word) - 3)
    kind = rng.choice(("swap", "drop", "double"))
    if kind == "swap":
        return word[:i] + word[i + 1] + word[i] + word[i + 2:]
    if kind == "drop":
        return word[:i] + word[i + 1:]
    return word[:i + 1] + word[i] + word[i + 1:]


def t_spelling(row: dict, rng: random.Random) -> str | None:
    text = row["text"]
    spans = merged_spans(row)

    def in_span(position: int) -> bool:
        return any(start <= position < end for start, end, _ in spans)

    def perturb(match: re.Match) -> str:
        token = match.group(0)
        inside = in_span(match.start())
        if token.isdigit():
            if inside and len(token) >= 4:
                i = rng.randint(0, len(token) - 2)
                return token[:i] + token[i + 1] + token[i] + token[i + 2:]
            return token
        if len(token) < 4:
            return token
        if inside or rng.random() < SPELLING_CONTEXT_RATE:
            return _typo(token, rng)
        return token
    return _changed(text, re.sub(r"[A-Za-z]+|\d+", perturb, text))


# --------------------------------------------------------------------------- paraphrase
PARAPHRASE_LEXICON = (  # (pattern, replacement); case of the first letter is preserved
    ("can you", "would you be able to"), ("could you", "would you mind helping to"),
    ("please", "kindly"), ("help me", "assist me"), ("i need", "I require"), ("i want", "I would like"),
    ("send", "forward"), ("tell me", "let me know"), ("write", "draft"), ("show me", "present to me"),
    ("my", "the"), ("phone number", "telephone contact"), ("email address", "electronic mail contact"),
    ("number", "identifier"), ("address", "residence"), ("name", "full designation"),
    ("account", "profile"), ("card", "payment instrument"), ("patient", "individual under care"),
    ("customer", "client"), ("employee", "staff member"), ("record", "file"), ("information", "details"),
    ("about", "regarding"), ("with", "alongside"), ("and", "as well as"), ("is", "happens to be"),
    ("born", "delivered into the world"), ("lives", "resides"), ("works", "is employed"),
    ("contact", "reach"), ("update", "revise"), ("check", "verify"), ("find", "locate"),
)
PARAPHRASE_FRAMES = (
    "{t}", "I was wondering about this: {t}", "Regarding the following, {t_l}", "{t} Thanks in advance.",
    "Quick question. {t}", "For context, here is what I have: {t}",
)


def _lexical_paraphrase(text: str, protected: list[tuple[int, int, str]]) -> str:
    pattern = re.compile(r"\b(" + "|".join(re.escape(p) for p, _ in PARAPHRASE_LEXICON) + r")\b", re.IGNORECASE)
    table = {p: r for p, r in PARAPHRASE_LEXICON}

    def swap(match: re.Match) -> str:
        if any(start < match.end() and match.start() < end for start, end, _ in protected):
            return match.group(0)
        word = match.group(0)
        replacement = table[word.lower()]
        return replacement[:1].upper() + replacement[1:] if word[:1].isupper() else replacement
    return pattern.sub(swap, text)


def t_paraphrase_rules(row: dict, rng: random.Random) -> str | None:
    rewritten = _lexical_paraphrase(row["text"], merged_spans(row))
    frame = rng.choice(PARAPHRASE_FRAMES)
    lowered = rewritten[:1].lower() + rewritten[1:] if rewritten[:1].isupper() and not rewritten[:2].isupper() else rewritten
    return _changed(row["text"], frame.format(t=rewritten, t_l=lowered))


# --------------------------------------------------------------------------- indirect reference
INDIRECT_POINTERS = {
    "NAME": ("my neighbour", "the person I mentioned before", "the colleague you know"),
    "CONTACT": ("the contact details I gave last time", "the way to reach me that we discussed", "my usual contact"),
    "GOV_ID": ("the number on my government identity document", "my official identifier from the usual paperwork", "the ID I showed earlier"),
    "ACCOUNT_ID": ("my usual account identifier", "the login identifier from my profile", "the id from my previous message"),
    "FINANCIAL": ("the card I always pay with", "my main bank account", "the payment details on file"),
    "DOB": ("the day I was born", "my birthday from the form", "the date on my birth certificate"),
    "HEALTH": ("my usual diagnosis", "the condition my doctor mentioned", "my current treatment"),
    "LOCATION": ("the place where I live", "my home address from before", "the street near my house"),
    "ORG": ("my employer", "the company I work for", "my organisation"),
    "TEMPORAL": ("that day", "the date we discussed", "the time from earlier"),
    "DEMOGRAPHIC": ("my group", "my personal background", "that detail about me"),
    "OCCUPATION": ("my job", "what I do for a living", "my line of work"),
    "POLITICS": ("my political leaning", "how I vote", "my party"),
    "RELIGION": ("my faith", "my religious background", "the beliefs I hold"),
    "SEXUAL": ("my private orientation", "that personal matter", "my intimate details"),
    "UNMAPPED": ("that information", "the item I mentioned", "the thing from before"),
}


def _pointer(label: str, rng: random.Random) -> str:
    return rng.choice(INDIRECT_POINTERS[label_family(label)])


def t_indirect_pointer(row: dict, rng: random.Random) -> str | None:
    """Replace each identifier value by a reference to it. The value is removed (value-removing family)."""
    return _changed(row["text"], rewrite_spans(row["text"], merged_spans(row), lambda v, label: _pointer(label, rng)))


def t_indirect_partial(row: dict, rng: random.Random) -> str | None:
    """Replace each value by a partial reference: initials for names, last four characters otherwise."""
    def convert(value: str, label: str) -> str:
        family = label_family(label)
        words = re.findall(r"[A-Za-z]+", value)
        if family == "NAME" and words:
            return " ".join(w[0].upper() + "." for w in words)
        alnum = re.sub(r"[^A-Za-z0-9]", "", value)
        if len(alnum) >= 6:
            return "the one ending in " + alnum[-4:]
        return _pointer(label, rng)
    return _changed(row["text"], rewrite_spans(row["text"], merged_spans(row), convert))


# --------------------------------------------------------------------------- encodings
def t_base64_span(row: dict, rng: random.Random) -> str | None:
    return _changed(row["text"], rewrite_spans(
        row["text"], merged_spans(row), lambda v, label: base64.b64encode(v.encode("utf-8")).decode("ascii")))


def t_hex_span(row: dict, rng: random.Random) -> str | None:
    return _changed(row["text"], rewrite_spans(
        row["text"], merged_spans(row), lambda v, label: v.encode("utf-8").hex()))


def t_spelled_digits_span(row: dict, rng: random.Random) -> str | None:
    """Spell each digit of a span as an English word (spans without digits are unchanged)."""
    def convert(value: str, label: str) -> str:
        if not any(c.isdigit() for c in value):
            return value
        out, previous_digit = [], False
        for ch in value:
            if ch.isdigit():
                out.append((" " if previous_digit else "") + DIGIT_WORDS[int(ch)])
                previous_digit = True
            else:
                out.append(ch)
                previous_digit = False
        return "".join(out)
    return _changed(row["text"], rewrite_spans(row["text"], merged_spans(row), convert))


# --------------------------------------------------------------------------- long-context placement
FILLER_SENTENCES = (
    "The committee reviewed the quarterly schedule and agreed to postpone the discussion to next week.",
    "Weather conditions along the coast remained mild, with light winds and scattered clouds throughout the afternoon.",
    "The library extended its opening hours so that students could study for the upcoming examinations.",
    "A new bakery opened near the station and quickly became popular for its sourdough bread.",
    "The research group compared several approaches to scheduling and found that simple heuristics performed well.",
    "Please remember to recycle paper, glass and plastic in the separate containers behind the building.",
    "The museum added a gallery about ancient pottery, with explanations for each of the displayed pieces.",
    "Engineers tested the bridge under heavy loads and reported that all measurements stayed within safe limits.",
    "The orchestra rehearsed the second movement several times before moving on to the finale.",
    "Gardeners recommend watering the vegetables early in the morning to reduce evaporation during the day.",
    "A short story can describe a whole season of life in only a few paragraphs.",
    "The train service will run on a reduced timetable while the tracks are being repaired.",
    "Volunteers cleaned the riverbank and collected several bags of litter before noon.",
    "The textbook explains how glaciers shape valleys over thousands of years.",
    "Several teams are working on improving the documentation so that new users can get started faster.",
    "The market sells fresh fruit, herbs and flowers every weekend throughout the summer.",
    "An overview of the project timeline is available in the shared planning notes.",
    "The football match was delayed for twenty minutes because of heavy rain.",
    "Students are encouraged to ask questions whenever a topic in the lecture is unclear.",
    "The recipe calls for flour, butter, sugar and a pinch of salt, baked until golden.",
)


def filler(rng: random.Random, chars: int) -> str:
    parts: list[str] = []
    total = 0
    while total < chars:
        sentence = rng.choice(FILLER_SENTENCES)
        parts.append(sentence)
        total += len(sentence) + 1
    return " ".join(parts)


def _place(row: dict, rng: random.Random, chars: int, where: str) -> str:
    text = row["text"]
    if where == "end":  # the sensitive prompt sits at the end of a long context
        return filler(rng, chars) + " " + text
    if where == "start":
        return text + " " + filler(rng, chars)
    half = chars // 2
    return filler(rng, half) + " " + text + " " + filler(rng, half)


def t_long_start(row: dict, rng: random.Random) -> str | None:
    return _place(row, rng, LONG_FILLER_CHARS, "start")


def t_long_middle(row: dict, rng: random.Random) -> str | None:
    return _place(row, rng, LONG_FILLER_CHARS, "middle")


def t_long_end(row: dict, rng: random.Random) -> str | None:
    return _place(row, rng, LONG_FILLER_CHARS, "end")


def t_window_middle(row: dict, rng: random.Random) -> str | None:
    return _place(row, rng, WINDOW_FILLER_CHARS, "middle")


# --------------------------------------------------------------------------- multilingual
# Declared translation templates for identifier-carrying sentences (written by the harness author
# before scoring; the value is inserted unchanged). One template per (language, label family).
MULTILINGUAL = {
    "es": {
        "NAME": "Mi nombre es {v}.", "CONTACT": "Mi dato de contacto es {v}.",
        "GOV_ID": "Mi número de documento de identidad es {v}.", "ACCOUNT_ID": "Mi identificador de cuenta es {v}.",
        "FINANCIAL": "Mi número de tarjeta o cuenta bancaria es {v}.", "DOB": "Mi fecha de nacimiento es {v}.",
        "HEALTH": "Mi dato de salud es {v}.", "LOCATION": "Mi dirección es {v}.", "ORG": "Mi empresa es {v}.",
        "TEMPORAL": "La fecha es {v}.", "DEMOGRAPHIC": "Un dato personal mío es {v}.",
        "OCCUPATION": "Mi ocupación es {v}.", "POLITICS": "Mi afiliación política es {v}.",
        "RELIGION": "Mi religión es {v}.", "SEXUAL": "Mi orientación personal es {v}.", "UNMAPPED": "El dato es {v}.",
    },
    "fr": {
        "NAME": "Mon nom est {v}.", "CONTACT": "Mes coordonnées sont {v}.",
        "GOV_ID": "Mon numéro de pièce d'identité est {v}.", "ACCOUNT_ID": "Mon identifiant de compte est {v}.",
        "FINANCIAL": "Mon numéro de carte ou de compte bancaire est {v}.", "DOB": "Ma date de naissance est {v}.",
        "HEALTH": "Mon information de santé est {v}.", "LOCATION": "Mon adresse est {v}.", "ORG": "Mon entreprise est {v}.",
        "TEMPORAL": "La date est {v}.", "DEMOGRAPHIC": "Une information personnelle me concernant est {v}.",
        "OCCUPATION": "Ma profession est {v}.", "POLITICS": "Mon appartenance politique est {v}.",
        "RELIGION": "Ma religion est {v}.", "SEXUAL": "Mon orientation personnelle est {v}.", "UNMAPPED": "L'information est {v}.",
    },
    "de": {
        "NAME": "Mein Name ist {v}.", "CONTACT": "Meine Kontaktdaten lauten {v}.",
        "GOV_ID": "Meine Ausweisnummer lautet {v}.", "ACCOUNT_ID": "Meine Konto-Kennung lautet {v}.",
        "FINANCIAL": "Meine Karten- oder Kontonummer lautet {v}.", "DOB": "Mein Geburtsdatum ist {v}.",
        "HEALTH": "Meine Gesundheitsangabe lautet {v}.", "LOCATION": "Meine Adresse lautet {v}.", "ORG": "Mein Unternehmen ist {v}.",
        "TEMPORAL": "Das Datum ist {v}.", "DEMOGRAPHIC": "Eine persönliche Angabe von mir ist {v}.",
        "OCCUPATION": "Mein Beruf ist {v}.", "POLITICS": "Meine politische Zugehörigkeit ist {v}.",
        "RELIGION": "Meine Religion ist {v}.", "SEXUAL": "Meine persönliche Orientierung ist {v}.", "UNMAPPED": "Die Angabe lautet {v}.",
    },
    "pt": {
        "NAME": "O meu nome é {v}.", "CONTACT": "O meu contacto é {v}.",
        "GOV_ID": "O número do meu documento de identificação é {v}.", "ACCOUNT_ID": "O identificador da minha conta é {v}.",
        "FINANCIAL": "O número do meu cartão ou conta bancária é {v}.", "DOB": "A minha data de nascimento é {v}.",
        "HEALTH": "A minha informação de saúde é {v}.", "LOCATION": "A minha morada é {v}.", "ORG": "A minha empresa é {v}.",
        "TEMPORAL": "A data é {v}.", "DEMOGRAPHIC": "Um dado pessoal meu é {v}.",
        "OCCUPATION": "A minha profissão é {v}.", "POLITICS": "A minha filiação política é {v}.",
        "RELIGION": "A minha religião é {v}.", "SEXUAL": "A minha orientação pessoal é {v}.", "UNMAPPED": "O dado é {v}.",
    },
    "zh": {
        "NAME": "我的名字是{v}。", "CONTACT": "我的联系方式是{v}。",
        "GOV_ID": "我的身份证件号码是{v}。", "ACCOUNT_ID": "我的账户标识是{v}。",
        "FINANCIAL": "我的银行卡或账户号码是{v}。", "DOB": "我的出生日期是{v}。",
        "HEALTH": "我的健康信息是{v}。", "LOCATION": "我的地址是{v}。", "ORG": "我的公司是{v}。",
        "TEMPORAL": "日期是{v}。", "DEMOGRAPHIC": "我的一项个人信息是{v}。",
        "OCCUPATION": "我的职业是{v}。", "POLITICS": "我的政治倾向是{v}。",
        "RELIGION": "我的宗教信仰是{v}。", "SEXUAL": "我的个人取向是{v}。", "UNMAPPED": "信息是{v}。",
    },
    "ru": {
        "NAME": "Меня зовут {v}.", "CONTACT": "Мои контактные данные: {v}.",
        "GOV_ID": "Номер моего удостоверения личности: {v}.", "ACCOUNT_ID": "Идентификатор моей учётной записи: {v}.",
        "FINANCIAL": "Номер моей карты или банковского счёта: {v}.", "DOB": "Моя дата рождения: {v}.",
        "HEALTH": "Мои данные о здоровье: {v}.", "LOCATION": "Мой адрес: {v}.", "ORG": "Моя компания: {v}.",
        "TEMPORAL": "Дата: {v}.", "DEMOGRAPHIC": "Мои личные данные: {v}.",
        "OCCUPATION": "Моя профессия: {v}.", "POLITICS": "Мои политические взгляды: {v}.",
        "RELIGION": "Моя религия: {v}.", "SEXUAL": "Моя личная ориентация: {v}.", "UNMAPPED": "Данные: {v}.",
    },
}
MULTILINGUAL_MAX_ENTITIES = 4


def _multilingual(language: str) -> Callable[[dict, random.Random], str | None]:
    def transform(row: dict, rng: random.Random) -> str | None:
        text = row["text"]
        seen, sentences = set(), []
        for start, end, label in merged_spans(row):
            value = text[start:end].strip()
            if not value or value in seen:
                continue
            seen.add(value)
            sentences.append(MULTILINGUAL[language][label_family(label)].format(v=value))
            if len(sentences) >= MULTILINGUAL_MAX_ENTITIES:
                break
        return " ".join(sentences) if sentences else None
    transform.__name__ = f"t_multilingual_{language}"
    return transform


# --------------------------------------------------------------------------- registry
# variant -> (family, function, value_removing)
VARIANTS: dict[str, tuple[str, Callable[[dict, random.Random], str | None], bool]] = {
    "homoglyph": ("unicode", t_homoglyph_span, False),
    "zero_width": ("unicode", t_zero_width_span, False),
    "spaces": ("inserted_spaces", t_space_span, False),
    "spelling": ("spelling", t_spelling, False),
    "paraphrase": ("paraphrase", t_paraphrase_rules, False),
    "indirect_partial": ("indirect_reference", t_indirect_partial, False),
    "indirect_pointer": ("indirect_reference", t_indirect_pointer, True),
    "base64": ("encoded_identifier", t_base64_span, False),
    "hex": ("encoded_identifier", t_hex_span, False),
    "spelled_digits": ("encoded_identifier", t_spelled_digits_span, False),
    "ctx_window_middle": ("long_context", t_window_middle, False),
    "ctx_long_start": ("long_context", t_long_start, False),
    "ctx_long_middle": ("long_context", t_long_middle, False),
    "ctx_long_end": ("long_context", t_long_end, False),
}
for _language in MULTILINGUAL:
    VARIANTS[f"multilingual_{_language}"] = ("multilingual", _multilingual(_language), False)

FAMILIES = ("unicode", "inserted_spaces", "spelling", "paraphrase", "indirect_reference",
            "encoded_identifier", "long_context", "multilingual")


def apply_variant(variant: str, row: dict) -> str | None:
    family, fn, _ = VARIANTS[variant]
    return fn(row, row_rng(variant, row["id"]))
