"""
Opt-in post-filter for spaCy NER output (``PRIVOKE_NER_POSTFILTER``).

spaCy labels are cheap evidence, not disclosures: a capitalised heading, a mask
such as ``XXXX``, or a bare organisation name is not personal information.
This module turns raw entity candidates into final sensitivity decisions in two
sequential stages. Every rule is a general linguistic or quasi-identifier
principle; no rule names a token, phrase or dataset row.

Stage 1, per-span cleaning (``SPAN_RULES``): drop a candidate that is not a
real named mention.

``placeholder``        letters collapse to one repeated letter (``XXXX``,
                       ``Xs``), no letters at all, or the span sits inside
                       template delimiters (``[..]``, ``<..>``, ``{{..}}``).
``identifier``         e-mail/URL/underscore/code-like token (two or more digits
                       and two or more letters in one token); the regex layer
                       owns structured identifiers.
``structural``         the span is part of a markdown heading or a title-case
                       line with several other words and no verb (a heading
                       has no sentence context). Cue-introduced
                       names ("Dear X", "Name: X") are exempt.
``short_acronym``      a very short place (<= 3 letters) or organisation
                       acronym (<= 4 letters) needs a locating/affiliation
                       preposition immediately before it ("in", "from", "at").
``common_phrase``      every word of the span is an ordinary common word when
                       the sentence is re-tagged without capitalisation (no
                       proper-noun reading), and no context cue says otherwise.

Stage 2, category combination (``COMBINATION_RULES``): quasi-identifier logic.
A lone weak entity type is not an identifying disclosure; combinations of a
person with a place or organisation are. The first matching rule per entity
decides; an entity that no rule keeps is dropped (final sensitivity S0).

Case-dependent rules (title-case heading detection) are inert on lower-cased
text; the remaining rules, the combination table and POS-based common-word
detection (the lowercase doc already carries no capitalisation) still apply.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from ..classification import Sensitivity

PERSON = "PERSON"
PLACE_LABELS = frozenset({"GPE", "LOC", "FAC"})
ORG = "ORG"

# --------------------------------------------------------------------------
# Context cues (matched against the text immediately before/after a span).
# --------------------------------------------------------------------------

_SENTENCE_BREAK = re.compile(r"(?<!\b[mM]r)(?<!\b[mM]rs)(?<!\b[mM]s)(?<!\b[dD]r)(?<!\b[pP]rof)[.!?]+[\"')\]]*\s+|\n\s*\n")

_PERSON_CUE = re.compile(
    r"(?:"
    # self introduction / naming
    r"\b(?:my|his|her|their|our|your)\s+(?:full\s+|legal\s+|first\s+|last\s+|real\s+)?name\s*(?:is|was|:)?"
    r"|\b(?:i\s+am|i'm|im|this\s+is|call\s+me|named|called|name's)"
    # salutations and sign-offs
    r"|\b(?:dear|hi|hello|hey|attn|attention|regards|thanks|thank\s+you|sincerely|cheers|best|signed|cc)\b[,:]?"
    # honorifics and role nouns that precede a person's name
    r"|\b(?:mr|mrs|ms|mx|miss|dr|prof|sir|madam|patient|student|client|customer|tenant|employee|applicant|resident)\b\.?"
    # kinship / social relation ("my sister Sara")
    r"|\bmy\s+(?:[a-z]+\s+)?(?:mother|father|mom|dad|wife|husband|son|daughter|brother|sister|friend|boss|manager|doctor|colleague|neighbou?r|partner|girlfriend|boyfriend|cousin|uncle|aunt|teacher|landlord|coworker|roommate|fianc[ée]e?)\b[,:]?(?:\s+(?:is|named|called))?"
    # labelled field values
    r"|\b(?:name|full\s+name|contact|author|signed\s+by|prepared\s+by|submitted\s+by|reported\s+by|attn)\s*[:\-–]"
    r")\s*[,:\-–]?\s*(?:the\s+)?$",
    re.IGNORECASE,
)
# A person who owns personal-data nouns ("Sara's account", "Sara, age 34").
_PERSON_TRAILING_CUE = re.compile(
    r"^(?:['’]s\s+(?:account|email|e-mail|phone|number|address|password|card|record|file|appointment|"
    r"id|passport|licen[cs]e|insurance|salary|diagnosis|medical|bank|login)"
    r"|,\s*(?:age[d]?\s+)?\d{1,3}\b"
    r"|\s+(?:born|was\s+born|lives|resides|works)\b"
    # a parenthetical that says what the value is: "X (full name)"
    r"|\s*\(\s*(?:full\s+|legal\s+)?name\b"
    # speaker label opening a quoted chat line: Name: "..."
    r"|(?:\s+\w+)?\s*:\s*[\"“])",
    re.IGNORECASE,
)

_GEO_CUE = re.compile(
    r"(?:\b(?:in|from|to|near|at|around|across|within|outside|into|inside|of|toward|towards|visiting|"
    r"moved\s+to|based\s+in|located\s+in|live\s+in|lives\s+in)\s+(?:the\s+)?"
    r"|\b(?:state|city|country|region|province|county|location|address|town|district)\s*[:=\-–]\s*)$",
    re.IGNORECASE,
)

_ORG_PREP_CUE = re.compile(
    r"\b(?:at|for|with|by|from|to|of|joined|via|between)\s+(?:the\s+)?$",
    re.IGNORECASE,
)

# Personal-relation cues: the speaker (or a named other) is tied to the place or
# organisation, so the mention discloses something about a person.
_PLACE_RELATION_CUE = re.compile(
    r"(?:"
    r"\b(?:i|we|he|she|they|you)\s+(?:currently\s+|now\s+|just\s+|recently\s+|still\s+|also\s+)?"
    r"(?:live|lives|living|lived|reside|resides|residing|moved|move|relocated|grew\s+up|was\s+born|were\s+born|"
    r"stay|stays|staying|work|works|worked|working|study|studied|studying)\s*(?:in|at|near|to|around)?"
    r"|\b(?:i\s+am|i'm|we're|we\s+are|he's|she's|they're)\s+(?:currently\s+|originally\s+)?(?:from|in|based\s+in|located\s+in|living\s+in|staying\s+in|born\s+in)"
    r"|\b(?:born|raised|based|living|residing|located)\s+(?:and\s+raised\s+)?in"
    r"|\bmy\s+(?:[a-z]+\s+)?(?:home|house|address|hometown|city|town|neighbou?rhood|apartment|flat|office|location|street|country)\s*(?:is|are|:)?\s*(?:in|at|on)?"
    r")\s*(?:the\s+)?$",
    re.IGNORECASE,
)
_ORG_RELATION_CUE = re.compile(
    r"(?:"
    r"\b(?:i|we|he|she|they)\s+(?:currently\s+|now\s+|just\s+|recently\s+|still\s+|also\s+)?"
    r"(?:work|works|worked|working|volunteer|volunteers|volunteered|study|studies|studied|studying|intern|interned|interning|"
    r"joined|am\s+employed|is\s+employed|are\s+employed)\s*(?:at|for|with|by)?"
    r"|\bemployed\s+(?:at|by|with)"
    r"|\b(?:i\s+am|i'm|we're|he's|she's|they're)\s+(?:currently\s+)?(?:at|with|from|a\s+member\s+of|enrolled\s+(?:at|in))"
    r"|\b(?:my|our|his|her|their)\s+(?:[a-z]+\s+)?(?:employer|company|school|university|college|firm|workplace|organi[sz]ation|employer's\s+name|team)\s*(?:is|are|:|,)?\s*(?:called|named)?"
    r")\s*(?:the\s+)?$",
    re.IGNORECASE,
)

_FUNCTION_TITLE_WORDS = frozenset(
    "a an the of and or for in on at to by with from & vs de la le".split()
)
_OPEN_DELIMS = {"[": "]", "<": ">", "{": "}", "(": ")"}
_ALPHA_TOKEN = re.compile(r"[A-Za-z][A-Za-z'’\-]*")


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Candidate:
    """A spaCy entity with the context features the rules need."""

    span: object
    label: str
    text: str
    start: int
    end: int
    strong_cue: bool = False      # person cue, recurrence or place/org context cue
    multi_token: bool = False
    relation_cue: bool = False
    geo_or_org_cue: bool = False


@dataclass
class Decision:
    """Final decision for one candidate."""

    candidate: Candidate
    keep: bool
    rule: str
    stage: str
    sensitivity: Optional[Sensitivity] = None   # None keeps the label's default


# --------------------------------------------------------------------------
# Text helpers
# --------------------------------------------------------------------------

def _before(text: str, start: int, width: int = 90) -> str:
    """Text before ``start`` within the current sentence/paragraph."""
    window = text[max(0, start - width):start]
    last_end = 0
    for match in _SENTENCE_BREAK.finditer(window):
        last_end = match.end()
    return window[last_end:]


def _after(text: str, end: int, width: int = 40) -> str:
    return text[end:end + width]


def _line_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    return line_start, (len(text) if line_end < 0 else line_end)


def _letters(text: str) -> str:
    return "".join(ch.lower() for ch in text if ch.isalpha())


def _alpha_tokens(text: str) -> list[str]:
    return _ALPHA_TOKEN.findall(text)


# --------------------------------------------------------------------------
# Candidate features
# --------------------------------------------------------------------------

def _is_recurring(text: str, candidate: Candidate) -> bool:
    """The same name (or one of its parts) occurs again elsewhere in the text."""
    lowered = text.lower()
    needle = candidate.text.lower()
    pattern = r"(?<!\w)" + re.escape(needle) + r"(?!\w)"
    if len(re.findall(pattern, lowered)) >= 2:
        return True
    tokens = [t for t in _alpha_tokens(candidate.text) if len(t) >= 3]
    if len(tokens) < 2:
        return False
    for token in (tokens[0], tokens[-1]):
        occurrences = re.findall(r"(?<!\w)" + re.escape(token.lower()) + r"(?!\w)", lowered)
        if len(occurrences) >= 2:
            return True
    return False


def _annotate(text: str, candidate: Candidate) -> None:
    before = _before(text, candidate.start)
    after = _after(text, candidate.end)
    tokens = _alpha_tokens(candidate.text)
    candidate.multi_token = len(tokens) >= 2
    if candidate.label == PERSON:
        candidate.strong_cue = bool(
            _PERSON_CUE.search(before)
            or _PERSON_TRAILING_CUE.match(after)
            or _is_recurring(text, candidate)
        )
    elif candidate.label in PLACE_LABELS:
        candidate.geo_or_org_cue = bool(_GEO_CUE.search(before))
        candidate.relation_cue = bool(_PLACE_RELATION_CUE.search(before))
        candidate.strong_cue = candidate.geo_or_org_cue or candidate.relation_cue
    elif candidate.label == ORG:
        candidate.geo_or_org_cue = bool(_ORG_PREP_CUE.search(before))
        candidate.relation_cue = bool(_ORG_RELATION_CUE.search(before))
        candidate.strong_cue = candidate.relation_cue


# --------------------------------------------------------------------------
# Stage 1: per-span rules (each returns True when the candidate must be dropped)
# --------------------------------------------------------------------------

def _placeholder(text: str, c: Candidate, _ctx) -> bool:
    letters = _letters(c.text)
    if not letters or len(set(letters)) == 1:
        return True
    if re.fullmatch(r"([A-Z])*s", c.text.strip()):   # pluralised capital mask: "Xs"
        return True
    open_char = text[c.start - 1] if c.start > 0 else ""
    close_char = text[c.end] if c.end < len(text) else ""
    return _OPEN_DELIMS.get(open_char) == close_char and open_char in "[<{"


def _identifier(text: str, c: Candidate, _ctx) -> bool:
    if "@" in c.text or "_" in c.text or "://" in c.text or c.text.lower().startswith("www."):
        return True
    for token in c.text.split():
        digits = sum(ch.isdigit() for ch in token)
        alphas = sum(ch.isalpha() for ch in token)
        if digits >= 2 and alphas >= 2:
            return True
    return False


def _structural(text: str, c: Candidate, ctx) -> bool:
    if c.strong_cue and c.label == PERSON:
        return False
    line_start, line_end = _line_bounds(text, c.start, c.end)
    line = text[line_start:line_end]
    if line.lstrip().startswith("#"):
        return True
    # Title-case line with other words and no verb: a heading, not a sentence.
    if not any(ch.isupper() for ch in line):
        return False        # lower-cased input carries no heading evidence
    if line.rstrip()[-1:] in ".!?" or ":" in line or any(ch.isdigit() for ch in line):
        return False        # sentences, "Label: value" fields and numeric records
    tokens = _alpha_tokens(line)
    own = {t.lower() for t in _alpha_tokens(c.text)}
    others = [t for t in tokens if t.lower() not in own]
    if len(others) < 2:
        return False
    if not all(t[0].isupper() or t.lower() in _FUNCTION_TITLE_WORDS for t in tokens):
        return False
    return not ctx.line_has_verb(line_start, line_end)


def _short_acronym(text: str, c: Candidate, _ctx) -> bool:
    letters = _letters(c.text)
    before = _before(text, c.start)
    if c.label in PLACE_LABELS and len(letters) <= 3:
        return not _GEO_CUE.search(before)
    if c.label == ORG and len(letters) <= 4 and " " not in c.text.strip():
        return not (_ORG_PREP_CUE.search(before) or c.relation_cue)
    return False


def _common_phrase(text: str, c: Candidate, ctx) -> bool:
    if c.strong_cue:
        return False
    # Places and organisations legitimately use ordinary words in multi-word
    # names ("Park Avenue"); only a lone ordinary word is a collision there.
    if c.label != PERSON and c.multi_token:
        return False
    return ctx.all_common(c)


SPAN_RULES: tuple[tuple[str, Callable[[str, Candidate, object], bool]], ...] = (
    ("placeholder", _placeholder),
    ("identifier", _identifier),
    ("structural", _structural),
    ("short_acronym", _short_acronym),
    ("common_phrase", _common_phrase),
)


# --------------------------------------------------------------------------
# Stage 2: category combination table
# --------------------------------------------------------------------------

@dataclass
class _Combo:
    persons: list
    places: list
    orgs: list


def _is_place(c: Candidate) -> bool:
    return c.label in PLACE_LABELS


def _person_linked(c, combo):
    return c.label == PERSON and bool(combo.places or combo.orgs)


def _place_org_linked(c, combo):
    return (_is_place(c) or c.label == ORG) and bool(combo.persons)


def _person_corroborated(c, combo):
    return c.label == PERSON and (c.strong_cue or c.multi_token)


def _relation_tied(c, combo):
    return (_is_place(c) or c.label == ORG) and c.relation_cue


def _relation_anchored(c, combo):
    """Another place/organisation in the prompt is tied to the speaker."""
    if not (_is_place(c) or c.label == ORG):
        return False
    return any(o is not c and o.relation_cue for o in combo.places + combo.orgs)


def _address_shape(c, combo):
    """A street-like place directly beside a number (house/plot/unit number)."""
    if c.label not in ("FAC", "LOC"):
        return False
    text = c.span.doc.text
    nearby = text[max(0, c.start - 8):c.start] + " " + text[c.end:c.end + 8]
    return bool(re.search(r"\d", nearby))


def _weak_person(c, combo):
    return c.label == PERSON


def _lone_place_org(c, combo):
    return _is_place(c) or c.label == ORG


@dataclass(frozen=True)
class CombinationRule:
    name: str
    principle: str
    matches: Callable[[Candidate, _Combo], bool]
    keep: bool
    sensitivity: Optional[Sensitivity]


COMBINATION_RULES: tuple[CombinationRule, ...] = (
    CombinationRule("person_linked", "A named person co-occurring with a place or organisation is a linked disclosure.",
                    _person_linked, True, Sensitivity.S2),
    CombinationRule("place_org_linked", "A place or organisation co-occurring with a named person identifies where the person is.",
                    _place_org_linked, True, Sensitivity.S2),
    CombinationRule("person_corroborated", "A multi-token, cue-introduced or recurring name is a real person mention.",
                    _person_corroborated, True, Sensitivity.S2),
    CombinationRule("relation_tied", "A place or organisation tied to a person by a personal-relation cue is about that person.",
                    _relation_tied, True, None),
    CombinationRule("relation_anchored", "A place or organisation beside a relation-tied one (employer and city) narrows who the speaker is.",
                    _relation_anchored, True, None),
    CombinationRule("address_shape", "A street-like place beside a number is an address, not a bare place name.",
                    _address_shape, True, Sensitivity.S2),
    CombinationRule("weak_person", "A single uncorroborated capitalised token is a weak name guess.",
                    _weak_person, False, None),
    CombinationRule("lone_place_org", "A lone place or organisation is not an identifying disclosure.",
                    _lone_place_org, False, None),
)


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

_LEXICON_CACHE: dict[int, frozenset] = {}
_TAGGER_PIPES = ("tok2vec", "tagger", "attribute_ruler", "lemmatizer")


def _english_lexicon(nlp) -> frozenset:
    """Base forms of the model's installed rule-lemmatizer index (an offline
    general English word list). Empty when the model has no such table."""
    if nlp is None or "lemmatizer" not in nlp.pipe_names:
        return frozenset()
    lemmatizer = nlp.get_pipe("lemmatizer")
    cached = _LEXICON_CACHE.get(id(lemmatizer))
    if cached is None:
        words: set = set()
        lookups = getattr(lemmatizer, "lookups", None)
        if lookups is not None and lookups.has_table("lemma_index"):
            for entries in lookups.get_table("lemma_index").values():
                words.update(w for w in entries if isinstance(w, str))
        cached = _LEXICON_CACHE[id(lemmatizer)] = frozenset(words)
    return cached


class _Context:
    """Lazy doc-level helpers shared by the rules."""

    def __init__(self, doc, nlp):
        self.doc = doc
        self._nlp = nlp
        self._lexicon = _english_lexicon(nlp)

    def line_has_verb(self, line_start: int, line_end: int) -> bool:
        for token in self.doc:
            if token.idx >= line_end:
                break
            if token.idx >= line_start and token.pos_ in ("VERB", "AUX"):
                return True
        return False

    def all_common(self, c: Candidate) -> bool:
        """True when every word of the span is a lexicon word that the tagger
        reads as a common word (no proper-noun reading) in isolation,
        lower-cased. Isolation avoids mis-parses of non-prose (tables, lists)."""
        if not self._lexicon or self._nlp is None:
            return False
        phrase = c.text.lower()
        if not _alpha_tokens(phrase):
            return False
        with self._nlp.select_pipes(enable=[n for n in _TAGGER_PIPES if n in self._nlp.pipe_names]):
            tagged = self._nlp(phrase)
        words = [t for t in tagged if t.is_alpha]
        if not words:
            return False
        return all(
            t.pos_ not in ("PROPN", "X") and (t.lemma_.lower() in self._lexicon or t.lower_ in self._lexicon)
            for t in words
        )


def _stage_one(text: str, candidates: list, ctx: _Context, disabled: frozenset) -> tuple[list, list]:
    kept, decisions = [], []
    for c in candidates:
        dropped_by = None
        for name, rule in SPAN_RULES:
            if name in disabled:
                continue
            if rule(text, c, ctx):
                dropped_by = name
                break
        if dropped_by is None:
            kept.append(c)
        else:
            decisions.append(Decision(c, False, dropped_by, "span"))
    return kept, decisions


def _stage_two(kept: list, disabled: frozenset, weak_person: Optional[Sensitivity]) -> list:
    combo = _Combo(
        [c for c in kept if c.label == PERSON],
        [c for c in kept if _is_place(c)],
        [c for c in kept if c.label == ORG],
    )
    decisions = []
    for c in kept:
        decision = Decision(c, True, "default", "combination")
        for rule in COMBINATION_RULES:
            if rule.name in disabled or not rule.matches(c, combo):
                continue
            sens = rule.sensitivity
            keep = rule.keep
            if rule.name == "weak_person" and weak_person is not None:
                keep, sens = True, weak_person
            decision = Decision(c, keep, rule.name, "combination", sens)
            break
        decisions.append(decision)
    return decisions


def postfilter(
    doc,
    entities: Iterable,
    *,
    nlp=None,
    disabled: Iterable[str] = (),
    weak_person: Optional[Sensitivity] = None,
) -> list[Decision]:
    """Run both stages over ``entities`` (spaCy spans of ``doc``).

    ``nlp`` is the spaCy pipeline that produced ``doc``: its lemmatizer table is
    the offline word list and its tagger re-tags lower-cased sentences for the
    common-word rule; without it that rule never fires. ``disabled``
    names rules to skip (ablation). ``weak_person`` keeps uncorroborated single
    names at that sensitivity instead of dropping them.
    """
    disabled = frozenset(disabled)
    text = doc.text
    candidates = []
    for ent in entities:
        c = Candidate(ent, ent.label_, ent.text, ent.start_char, ent.end_char)
        _annotate(text, c)
        candidates.append(c)
    ctx = _Context(doc, nlp)
    kept, decisions = _stage_one(text, candidates, ctx, disabled)
    decisions.extend(_stage_two(kept, disabled, weak_person))
    decisions.sort(key=lambda d: (d.candidate.start, d.candidate.end))
    return decisions
