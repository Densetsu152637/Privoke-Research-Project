"""
Experimental pattern-based replacement for the spaCy NER layer (no ML).

``PatternEntityDetector.extract_entities(text)`` keeps the contract of
``EntityNERDetector`` (a list of ``ClassificationResult``) and the label ->
classification mapping of ``use_cases.NER_LABEL_USE_CASES`` (PERSON, GPE, LOC,
FAC, ORG).  Every result records the mechanism that produced it in
``metadata["mechanism"]``:

``cue``         a field label, self-introduction, salutation, sign-off,
                honorific, relation or location/organisation cue introduced the
                value.  Case-insensitive; most cues also accept lowercase values
                so they survive the runtime's lowercasing.
``shape``       a value-shape pattern fired without a cue (street address,
                ``City, ST 12345``, ``Firstname Lastname`` mid-sentence,
                ``<Name> Inc``).  Mostly capitalisation dependent.
``gazetteer``   optional (off by default) closed-class lists: US states,
                countries, a few well known cities, common given names.
``recurrence``  a value already found elsewhere in the same text occurs again
                (also its first/last-name parts), or a capitalised 2-3 word
                sequence occurs at least twice.

Spans are character offsets into the text passed to the detector.  The module
is self-contained and not wired into the runtime pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .use_cases import NER_LABEL_USE_CASES
from ..classification import ClassificationResult

MODEL_NAME = "pattern-entity-detector"

# Mechanism priority: lower wins when candidate spans overlap.
_PRIORITY = {"cue": 0, "shape": 1, "gazetteer": 2, "seed": 2, "recurrence": 3}

# --------------------------------------------------------------------------
# Word lists.  All are generic English closed classes, not derived from data.
# --------------------------------------------------------------------------

_FUNCTION_WORDS = frozenset("""
a an the and or but nor so yet if then than that this these those there here
who whom whose which what when where why how while although because since
i me my mine myself we us our ours you your yours he him his she her hers it
its they them their theirs
is am are was were be been being do does did done have has had having
can could will would shall should may might must
not no yes also just really very too only even still already always never
of in on at by for with without from to into onto over under about after before
between during through against around near as per via up down out off
please thanks thank hi hello hey dear ok okay sir madam
some any all each every both either neither many much more most less few other
another such own same
get got make made go going gone come came take took give gave tell told say said
need needs needed want wants wanted like help helps know think see look looking
let use using used write wrote draft send sent
one two three four five six seven eight nine ten
""".split())

_PLACEHOLDERS = frozenset("""
n/a na none unknown redacted anonymous placeholder example test tbd blank
required optional name names first last full middle surname nickname your
email phone address number account id here
""".split())

_MONTHS_DAYS = frozenset("""
january february march april may june july august september october november
december jan feb mar apr jun jul aug sep sept oct nov dec monday tuesday
wednesday thursday friday saturday sunday mon tue tues wed thu thur thurs fri
sat sun
""".split())

_ROLE_WORDS = frozenset("""
manager boss supervisor coworker colleague friend neighbor neighbour landlord
tenant doctor therapist lawyer attorney teacher professor son daughter wife
husband partner spouse mother father mom dad brother sister uncle aunt cousin
nephew niece grandmother grandfather girlfriend boyfriend roommate client
patient student mentor employee assistant nurse child kid baby team desk
department support service services customer hr human resources staff office
admin administrator representative rep agent advisor officer director
president ceo cfo cto hiring recruiter committee board everyone everybody
anyone someone somebody folks guys all there
""".split())

_ORG_WORDS = frozenset("""
inc llc ltd corp corporation co company university college hospital bank clinic
institute foundation group associates partners insurance health systems
technologies school church court agency association authority ministry
department center centre services solutions labs
""".split())

# Title-case words that routinely appear in prompts but are not name parts.
_COMMON_TITLE_WORDS = frozenset("""
social security number card account bank banking credit debit tax medical
records record policy plan benefits insurance driver license licence passport
visa travel booking flight hotel email phone mobile home work personal private
confidential information data privacy password login username api key token
code python java javascript excel word outlook gmail google microsoft apple
amazon facebook instagram twitter linkedin zoom slack teams github docker
windows linux android iphone ios mac internet web website app application
form document file report letter message request support help center
english spanish french german chinese japanese
mr mrs ms miss dr prof
street st avenue ave road rd boulevard blvd drive dr lane ln court ct way
terrace place pl circle parkway highway
north south east west
project review meeting meetings notes summary update updates schedule budget quarterly annual weekly daily
""".split())

_ADDRESS_SUFFIX = {
    "street": "street", "st": "street", "avenue": "street", "ave": "street",
    "road": "street", "rd": "street", "boulevard": "street", "blvd": "street",
    "drive": "amb", "dr": "amb", "lane": "amb", "ln": "amb", "court": "amb",
    "ct": "amb", "way": "amb", "terrace": "amb", "ter": "amb", "place": "amb",
    "pl": "amb", "circle": "amb", "cir": "amb", "parkway": "street",
    "pkwy": "street", "highway": "street", "hwy": "street", "trail": "amb",
    "square": "amb", "sq": "amb",
}
_UNIT_WORDS = frozenset("""
minute minutes min mins hour hours day days week weeks month months year years
mile miles km kilometers meter meters foot feet people times items words
dollars dollar percent pages steps ways things more other
""".split())

_US_STATES = {
    "AL": "alabama", "AK": "alaska", "AZ": "arizona", "AR": "arkansas",
    "CA": "california", "CO": "colorado", "CT": "connecticut", "DE": "delaware",
    "DC": "district of columbia", "FL": "florida", "GA": "georgia",
    "HI": "hawaii", "ID": "idaho", "IL": "illinois", "IN": "indiana",
    "IA": "iowa", "KS": "kansas", "KY": "kentucky", "LA": "louisiana",
    "ME": "maine", "MD": "maryland", "MA": "massachusetts", "MI": "michigan",
    "MN": "minnesota", "MS": "mississippi", "MO": "missouri", "MT": "montana",
    "NE": "nebraska", "NV": "nevada", "NH": "new hampshire", "NJ": "new jersey",
    "NM": "new mexico", "NY": "new york", "NC": "north carolina",
    "ND": "north dakota", "OH": "ohio", "OK": "oklahoma", "OR": "oregon",
    "PA": "pennsylvania", "RI": "rhode island", "SC": "south carolina",
    "SD": "south dakota", "TN": "tennessee", "TX": "texas", "UT": "utah",
    "VT": "vermont", "VA": "virginia", "WA": "washington", "WV": "west virginia",
    "WI": "wisconsin", "WY": "wyoming",
}
_STATE_NAMES = frozenset(_US_STATES.values())
_AMBIGUOUS_ABBR = frozenset({"ID", "IN", "OR", "ME", "HI", "OK", "LA", "OH", "DE"})
# State names that are also common given names / words: skip when lowercase.
_AMBIGUOUS_PLACES = frozenset({"georgia", "washington", "indiana", "jordan", "turkey", "chad", "china"})
_COUNTRIES = frozenset("""
canada mexico brazil argentina chile colombia peru france germany spain italy
portugal ireland england scotland wales netherlands belgium sweden norway
denmark finland poland ukraine russia turkey greece egypt nigeria kenya
ethiopia ghana india pakistan bangladesh china japan korea vietnam thailand
philippines indonesia malaysia singapore australia zealand israel iran iraq
""".split()) | {"united states", "united kingdom", "south africa", "saudi arabia",
                 "new zealand", "south korea", "hong kong", "united arab emirates"}
_CITIES = frozenset("""
new york|los angeles|chicago|houston|phoenix|philadelphia|san antonio|san diego
|dallas|san jose|austin|jacksonville|san francisco|columbus|fort worth
|indianapolis|charlotte|seattle|denver|boston|detroit|portland|las vegas
|memphis|baltimore|milwaukee|atlanta|miami|oakland|minneapolis|tampa|orlando
|toronto|vancouver|montreal|london|paris|berlin|madrid|rome|amsterdam|dublin
|tokyo|beijing|shanghai|delhi|mumbai|sydney|melbourne
""".replace("\n", "").split("|"))

# ~150 common US given names.  Names that are also very common words (will,
# mark, grant, rose, ...) are deliberately omitted.
_GIVEN_NAMES = frozenset("""
james john robert michael william david richard joseph thomas charles daniel
matthew anthony donald steven paul andrew joshua kenneth kevin brian george
timothy ronald edward jason jeffrey ryan jacob gary nicholas eric jonathan
stephen larry justin scott brandon benjamin samuel gregory alexander patrick
frank raymond jack dennis jerry tyler aaron jose adam nathan henry zachary
douglas peter kyle noah ethan jeremy walter christian keith roger terry austin
sean gerald carl harold dylan arthur lawrence jordan jesse bryan billy bruce
gabriel joe logan alan juan albert willie elijah wayne randy vincent philip
eugene russell bobby harry johnny howard evan casey riley sam alex
mary patricia jennifer linda elizabeth barbara susan jessica sarah karen lisa
nancy betty margaret sandra ashley kimberly emily donna michelle carol amanda
dorothy melissa deborah stephanie rebecca sharon laura cynthia kathleen amy
angela shirley anna brenda pamela emma nicole helen samantha katherine
christine debra rachel carolyn janet maria heather diane olivia julie joyce
victoria kelly christina lauren joan evelyn judith megan cheryl andrea hannah
jacqueline martha gloria teresa sara janice marie julia kathryn maya sophia
isabella mia charlotte amelia grace chloe zoe leah lily ella
""".split())
_SURNAMES = frozenset("""
smith johnson williams brown jones garcia miller davis rodriguez martinez
hernandez lopez gonzalez wilson anderson thomas taylor moore jackson martin lee
perez thompson white harris sanchez clark ramirez lewis robinson walker young
allen king wright scott torres nguyen hill flores green adams nelson baker hall
rivera campbell mitchell carter roberts gomez phillips evans turner diaz parker
cruz edwards collins reyes stewart morris morales murphy cook rogers gutierrez
ortiz morgan cooper peterson bailey reed kelly howard ramos kim cox ward
richardson watson brooks chavez wood james bennett gray mendoza ruiz hughes
price alvarez castillo sanders patel myers long ross foster jimenez chen wang
li zhang liu singh kumar khan ali ahmed tan lin huang yang wu
""".split())

# --------------------------------------------------------------------------
# Regular expressions.
# --------------------------------------------------------------------------

_TOKEN = re.compile(r"[ \t]*([A-Za-z][A-Za-z'’\-]*)(\.?)")
_TITLE_TOKEN = r"[A-Z][a-z]+(?:['’\-][A-Z]?[a-z]+)*"
_TITLE_RUN = re.compile(
    rf"(?<![\w'’])({_TITLE_TOKEN}(?:[ \t]+(?:[A-Z]\.[ \t]*)?{_TITLE_TOKEN}){{1,2}})(?![\w])"
)
_ZIP = r"\d{5}(?:-\d{4})?"
_STATE_ABBR = "|".join(sorted(_US_STATES, key=len, reverse=True))
_STATE_NAME_RE = "|".join(sorted((re.escape(n) for n in _STATE_NAMES), key=len, reverse=True))
_REGION_TAIL = re.compile(
    rf"[ \t]*,[ \t]*(?:(?P<abbr>{_STATE_ABBR})|(?P<lowabbr>{_STATE_ABBR.lower()})(?=[ \t]+{_ZIP})|(?P<name>{_STATE_NAME_RE}))"
    rf"\b(?:[ \t]+(?P<zip>{_ZIP}))?",
    re.IGNORECASE,
)
_SUFFIXES = "|".join(sorted(_ADDRESS_SUFFIX, key=len, reverse=True))
_STREET = re.compile(
    rf"(?<![\w.#-])(?P<num>\d{{1,6}})[ \t]+(?P<mid>(?:[A-Za-z0-9'’.\-]+[ \t]+){{1,4}}?)"
    rf"(?P<suffix>{_SUFFIXES})\b",
    re.IGNORECASE,
)
_TITLE_STREET = re.compile(
    rf"(?<![\w'’])(?:{_TITLE_TOKEN}[ \t]+){{1,2}}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Lane|Court|Way|Terrace|Parkway|Highway)\b"
)
_ORG_SUFFIX_TITLE = re.compile(
    rf"(?<![\w'’])((?:{_TITLE_TOKEN}[ \t]+){{1,3}}(?:Inc|LLC|Ltd|Corp|Corporation|Co|Company|University|College|Hospital|Bank|Clinic|Institute|Foundation|Group|Associates|Partners|Insurance|Technologies|Systems|Labs|Church|School))\b"
)
_ORG_PREFIX_TITLE = re.compile(
    rf"(?<![\w'’])((?:Bank|University|College|Institute|Hospital|Church|Department|City|County|State)[ \t]+of[ \t]+(?:{_TITLE_TOKEN})(?:[ \t]+{_TITLE_TOKEN})?)"
)
_ORG_LEGAL_ANY_CASE = re.compile(
    r"(?<![\w'’])((?:[A-Za-z][\w&'’\-]*[ \t]+){1,3}(?:inc|llc|ltd|corp|plc|gmbh))\b",
    re.IGNORECASE,
)
_ORG_PREFIX_ANY_CASE = re.compile(
    r"(?<![\w'’])((?:university|college|bank|institute)[ \t]+of[ \t]+[A-Za-z][\w'’\-]*(?:[ \t]+[A-Za-z][\w'’\-]*)?)",
    re.IGNORECASE,
)

_REL = (
    r"manager|boss|supervisor|co-?worker|colleague|friend|neighbou?r|landlord|tenant|doctor|"
    r"therapist|lawyer|attorney|teacher|professor|son|daughter|wife|husband|partner|spouse|"
    r"mother|father|mom|dad|brother|sister|uncle|aunt|cousin|nephew|niece|grandmother|"
    r"grandfather|girlfriend|boyfriend|roommate|client|patient|student|mentor|employee|"
    r"assistant|nurse|child|kid|baby|fianc[ée]e?|ex"
)
_PERSON_LABELS = (
    r"full[ \t]+name|legal[ \t]+name|first[ \t]+name|last[ \t]+name|sur-?name|family[ \t]+name|"
    r"(?:patient|customer|employee|tenant|applicant|contact|student|client|account[ \t]*holder|"
    r"card[ \t]*holder|policy[ \t]*holder|beneficiary|owner|emergency[ \t]+contact)(?:[ \t]+name)?|"
    r"name|signed|signature|requested[ \t]+by|submitted[ \t]+by|prepared[ \t]+by|"
    r"written[ \t]+by|attn|attention|reporter|author"
)

@dataclass(frozen=True)
class _Cue:
    name: str
    pattern: "re.Pattern[str]"
    label: str
    scan: str            # "name" | "place" | "org"
    allow_lower: bool    # value may be lowercase (survives case folding)
    max_tokens: int = 3
    allow_cap: bool = True


def _cue(name, regex, label, scan, allow_lower, max_tokens=3, allow_cap=True, flags=re.IGNORECASE):
    return _Cue(name, re.compile(regex, flags), label, scan, allow_lower, max_tokens, allow_cap)


_B = r"(?<![\w'’])"
# "Name:" / "Name =" or a spaced dash ("Name - X"); a hyphen inside a word is not a delimiter.
_FIELD_DELIM = r"(?:[ \t]*[:=]|[ \t]+[–—\-])[ \t]*"
_CUES: Tuple[_Cue, ...] = (
    # label fields: "Name:", "Full name -", "Patient name = ..."
    _cue("field_name", rf"{_B}(?:{_PERSON_LABELS}){_FIELD_DELIM}", "PERSON", "name", True),
    # role word directly before a capitalised name: "Student Alex Davis", "patient Avery Ali"
    _cue("role_prefix", rf"{_B}(?:student|patient|customer|client|employee|tenant|applicant|member|resident|claimant|passenger|candidate|beneficiary|cardholder|policyholder)[ \t]+", "PERSON", "name", False),
    # self introduction
    _cue("self_intro_my_name", rf"{_B}my[ \t]+(?:(?:full|legal|first|last)[ \t]+)?name(?:[ \t]+is|['’]s)[ \t]+", "PERSON", "name", True),
    _cue("self_intro_call_me", rf"{_B}(?:(?:you[ \t]+can|please|just)[ \t]+)?(?:call|address)[ \t]+me[ \t]+", "PERSON", "name", True),
    _cue("self_intro_called", rf"{_B}(?:i[ \t]+am|i['’]m|im|they[ \t]+call[ \t]+me|known[ \t]+as|go[ \t]+by)[ \t]+(?:called|named|known[ \t]+as)?[ \t]*", "PERSON", "name", False, 3),
    _cue("self_intro_this_is", rf"{_B}(?:this[ \t]+is|it['’]s|hi,?[ \t]+i['’]m|my[ \t]+name['’]s)[ \t]+", "PERSON", "name", False, 3),
    _cue("named", rf"{_B}(?:named|nicknamed|under[ \t]+the[ \t]+name)[ \t]+", "PERSON", "name", False),
    # salutations and sign-offs
    _cue("salutation_dear", rf"{_B}dear[ \t]+(?:(?:mr|mrs|ms|miss|dr|prof)\.?[ \t]+)?", "PERSON", "name", True),
    _cue("salutation_greeting", rf"{_B}(?:hi|hello|hey|greetings)[ \t]+", "PERSON", "name", False),
    _cue("signoff", rf"{_B}(?:(?:best|kind|warm|many|with|sincere)[ \t]+)?(?:regards|sincerely|thanks|thank[ \t]+you|cheers|respectfully|yours[ \t]+(?:truly|sincerely|faithfully))[ \t]*[,.!]?[ \t]*\r?\n[ \t]*[\-–—~]?[ \t]*", "PERSON", "name", True),
    # honorifics
    _cue("honorific_period", rf"{_B}(?:mr|mrs|ms|miss|mx|dr|prof|mister)\.[ \t]*", "PERSON", "name", True, 2),
    _cue("honorific_word", rf"{_B}(?:mr|mrs|dr|prof|professor|mister)[ \t]+", "PERSON", "name", True, 2),
    _cue("honorific_title_case", rf"{_B}(?:Ms|Miss|Mx)[ \t]+", "PERSON", "name", False, 2, flags=0),
    # relation cues: "my manager Sarah Lee", "my son named Ethan"
    _cue("relation_named", rf"{_B}(?:my|our|his|her|their)[ \t]+(?:(?:ex|step|half|future|late|former)[ \t\-])?(?:{_REL})[ \t]*,?[ \t]*(?:named|called)[ \t]+", "PERSON", "name", True),
    _cue("relation_apposition", rf"{_B}(?:my|our|his|her|their)[ \t]+(?:(?:ex|step|half|future|late|former)[ \t\-])?(?:{_REL})(?:[ \t]*,[ \t]*|[ \t]+(?:is|was)[ \t]+|[ \t]+)", "PERSON", "name", False),
    _cue("agent_by", rf"{_B}(?:signed|submitted|prepared|written|authored|sent|created|reported|approved)[ \t]+by[ \t]+", "PERSON", "name", True),
    _cue("on_behalf", rf"{_B}on[ \t]+behalf[ \t]+of[ \t]+", "PERSON", "name", False),
    # location cues
    _cue("residence_verb", rf"{_B}(?:(?:i|we|he|she|they)[ \t]+(?:(?:am|are|is|was|were|have|has)[ \t]+)?|(?:i['’]m|we['’]re|he['’]s|she['’]s|they['’]re|im)[ \t]+)(?:currently[ \t]+|now[ \t]+|still[ \t]+|recently[ \t]+)?(?:live[sd]?|living|reside[sd]?|residing|located|based|stay(?:s|ing)?|moved|relocated|relocating|born|raised|grew[ \t]+up|stationed|headquartered)[ \t]+(?:in|at|near|to|on|from|around)[ \t]+", "GPE", "place", True),
    _cue("from_place", rf"{_B}(?:i['’]m|i[ \t]+am|im|we['’]re|he['’]s|she['’]s)[ \t]+(?:originally[ \t]+)?from[ \t]+", "GPE", "place", False),
    _cue("lives_in", rf"{_B}(?:live[sd]?|living|resid(?:e|es|ed|ing)|based|located|born|raised)[ \t]+(?:in|at|near)[ \t]+", "GPE", "place", True),
    _cue("field_place", rf"{_B}(?:city|town|state|province|country|hometown|birthplace|place[ \t]+of[ \t]+birth|residence|current[ \t]+location|home[ \t]+location){_FIELD_DELIM}", "GPE", "place", True),
    _cue("my_location", rf"{_B}(?:my|our|his|her|their)[ \t]+(?:home[ \t]+)?(?:hometown|residence|city|birthplace|place[ \t]+of[ \t]+birth)[ \t]*(?:is|was|[:=])[ \t]*", "GPE", "place", True),
    # organisation cues
    _cue("works_at", rf"{_B}(?:work(?:s|ed|ing)?|employed|interning|intern(?:ed)?|volunteer(?:s|ed|ing)?|consult(?:s|ed|ing)?)[ \t]+(?:at|for|with|by)[ \t]+(?:the[ \t]+)?", "ORG", "org", True, 4),
    _cue("employer_field", rf"{_B}(?:employer|company|organi[sz]ation|school|university|college|workplace|insurer|insurance[ \t]+(?:company|provider)|bank|hospital|clinic)(?:[ \t]+name)?[ \t]*(?:[:=–—]|\-|is|was)[ \t]+(?:the[ \t]+)?", "ORG", "org", True, 4),
    _cue("studies_at", rf"{_B}(?:student|enrolled|studying|study|studied|graduated|alumn\w+|attend(?:s|ed|ing)?)[ \t]+(?:at|from|in)[ \t]+(?:the[ \t]+)?", "ORG", "org", True, 4),
    _cue("customer_of", rf"{_B}(?:bank(?:s|ed|ing)?[ \t]+with|insured[ \t]+(?:by|with|through)|insurance[ \t]+(?:with|through|from)|treated[ \t]+at|admitted[ \t]+to|patient[ \t]+at|account[ \t]+(?:at|with))[ \t]+(?:the[ \t]+)?", "ORG", "org", True, 4),
)

_W = r"[A-Za-z][A-Za-z'’\-]*"
_PII_NOUN = (
    r"(?:ssn|social[ \t]+security|employee|account|passport|policy|dob|date[ \t]+of[ \t]+birth|"
    r"e-?mail|phone|mobile|id|licen[sc]e|address|insurance|salary|card|contact|callback|mailing)\b"
)
# (pattern, cue name, accepts lowercase runs).  Group "run" is the name candidate.
_ADJACENT = (
    (re.compile(rf"(?<![\w'’])(?P<run>(?:{_W}[ \t]+)?{_W})['’]s[ \t]+{_PII_NOUN}", re.IGNORECASE),
     "possessive_pii_noun", True),
    (re.compile(rf"(?<![\w'’])(?P<run>(?:{_W}[ \t]+){{0,2}}{_W})[ \t]*,[ \t]*(?:{_PII_NOUN}|[\w.+\-]+@)", re.IGNORECASE),
     "record_pii_noun", True),
    (re.compile(rf"(?:for|to|about|regarding)[ \t]+(?P<run>{_W}[ \t]+{_W})[ \t]*[.,:;][ \t]*(?:(?:the|my|his|her|their)[ \t]+)?{_PII_NOUN}", re.IGNORECASE),
     "benefactive_pii_noun", False),
)

# --------------------------------------------------------------------------
# Candidate handling
# --------------------------------------------------------------------------

_ORG_LEAD_STOP = frozenset("""
home night nights weekends weekend days day times nowhere least most once
present school work office the a an my our your their his her this that it
scale scales speed pace random best full max most
what which anything something nothing everything whatever
""".split())
_PLACE_STOP = _FUNCTION_WORDS | frozenset("""
home work town city house apartment flat area neighborhood neighbourhood country
state school campus dorm region suburbs suburb office street building
""".split()) | _PLACEHOLDERS
_NAME_STOP = _FUNCTION_WORDS | _PLACEHOLDERS | _MONTHS_DAYS | _ROLE_WORDS | _ORG_WORDS


@dataclass
class _Candidate:
    start: int
    end: int
    label: str
    mechanism: str
    cue: str

    @property
    def priority(self) -> Tuple[int, int]:
        return (_PRIORITY[self.mechanism], -(self.end - self.start))


def _fold(text: str) -> str:
    """Lowercase without changing string length, so offsets stay valid."""
    return "".join(c.lower() if len(c.lower()) == 1 else c for c in text)


def _strip_possessive(token: str) -> Tuple[str, bool]:
    for suffix in ("'s", "’s", "'", "’"):
        if token.lower().endswith(suffix) and len(token) > len(suffix) + 1:
            return token[: -len(suffix)], True
    return token, False


def _scan_value(
    text: str, pos: int, *, kind: str, max_tokens: int, allow_lower: bool, allow_cap: bool = True
) -> Optional[Tuple[int, int]]:
    """Read up to ``max_tokens`` word tokens starting at ``pos``.

    The first token fixes the casing mode: a capitalised token starts a
    capitalised run (every token must be capitalised); a lowercase token starts a
    lowercase run that stops at the first stop word.  Returns ``(start, end)``.
    """
    stop = {"name": _NAME_STOP, "place": _PLACE_STOP, "org": _ORG_LEAD_STOP | _FUNCTION_WORDS}[kind]
    mode = None
    first = None
    end = None
    count = 0
    i = pos
    if kind in ("place", "org"):
        lead = re.compile(r"[ \t]*the[ \t]+", re.IGNORECASE).match(text, i)
        if lead:
            i = lead.end()
    while count < max_tokens:
        m = _TOKEN.match(text, i)
        if not m:
            break
        raw, dot = m.group(1), m.group(2)
        word, possessive = _strip_possessive(raw)
        low = word.lower()
        is_cap = word[0].isupper()
        if mode is None:
            mode = "cap" if is_cap else "lower"
            if (mode == "cap" and not allow_cap) or (mode == "lower" and not allow_lower):
                return None
        if (mode == "cap") != is_cap:
            break
        if kind == "name" and count > 0 and len(word) == 1 and dot:
            pass  # middle initial
        elif len(word) < 2 or low in stop:
            break
        if kind == "name" and count == 0 and low.endswith("ing") and len(low) > 5:
            break
        if kind == "name" and low in _COMMON_TITLE_WORDS and mode == "cap" and count == 0 and low not in _GIVEN_NAMES:
            break
        if first is None:
            first = m.start(1)
        end = m.start(1) + len(word)
        count += 1
        i = m.end(1) if not possessive else m.end(1)
        if dot and len(word) == 1:
            end = m.end(2)
            i = m.end(2)
        if possessive:
            break
    if first is None or end is None:
        return None
    if kind == "name" and text[first:end].strip().endswith("."):
        end = len(text[:end].rstrip("."))
    return first, end


def _extend_region(text: str, end: int, *, require_zip_if_lower_abbr: bool = True) -> int:
    """Extend a place ending at ``end`` with ``, ST [ZIP]`` / ``, State``."""
    m = _REGION_TAIL.match(text, end)
    if not m:
        return end
    abbr = m.group("abbr")
    if abbr is not None and not (abbr.isupper() or m.group("zip")):
        return end
    if abbr is not None and abbr.upper() in _AMBIGUOUS_ABBR and not m.group("zip"):
        return end  # ", ID" / ", OR" / ", IN" ... are usually not states
    return m.end()


class PatternEntityDetector:
    """Regex-style entity extraction with the ``EntityNERDetector`` contract."""

    def __init__(
        self,
        *,
        use_cues: bool = True,
        use_shape: bool = True,
        use_recurrence: bool = True,
        use_gazetteer: bool = False,
    ):
        self.backend_name = "patterns"
        self.model_name = MODEL_NAME
        self.use_cues = use_cues
        self.use_shape = use_shape
        self.use_recurrence = use_recurrence
        self.use_gazetteer = use_gazetteer

    # ------------------------------------------------------------------ API

    def extract_entities(self, text: str) -> List[ClassificationResult]:
        return self._run(text, seeds=())

    def augment_entities(
        self, text: str, seeds: Sequence[ClassificationResult]
    ) -> List[ClassificationResult]:
        """Hybrid mode: treat ``seeds`` (e.g. spaCy NER results on the same
        text) as already-found values, add cue/shape candidates, then apply
        recurrence over the union.  Seeds are returned unchanged."""
        return self._run(text, seeds=seeds)

    # ------------------------------------------------------------ internals

    def _run(self, text: str, seeds: Sequence[ClassificationResult]) -> List[ClassificationResult]:
        if not text:
            return list(seeds)
        candidates: List[_Candidate] = []
        for seed in seeds:
            label = (seed.metadata or {}).get("label")
            if seed.span and label in NER_LABEL_USE_CASES:
                candidates.append(_Candidate(seed.span[0], seed.span[1], label, "seed", "seed"))
        if self.use_cues:
            candidates.extend(self._cue_candidates(text))
        if self.use_shape:
            candidates.extend(self._shape_candidates(text))
        if self.use_gazetteer:
            candidates.extend(self._gazetteer_candidates(text))
        selected = self._resolve(candidates)
        if self.use_recurrence:
            selected = self._resolve(selected + self._recurrence_candidates(text, selected))
        results: List[ClassificationResult] = []
        by_span = {(s.span, (s.metadata or {}).get("label")): s for s in seeds if s.span}
        for cand in selected:
            if cand.mechanism == "seed":
                results.append(by_span[((cand.start, cand.end), cand.label)])
            else:
                results.append(self._result(text, cand))
        return results

    @staticmethod
    def _resolve(candidates: Iterable[_Candidate]) -> List[_Candidate]:
        """Greedy non-overlapping selection: best mechanism, then longest."""
        chosen: List[_Candidate] = []
        for cand in sorted(candidates, key=lambda c: (c.priority, c.start)):
            if cand.end <= cand.start:
                continue
            if any(cand.start < o.end and o.start < cand.end for o in chosen):
                continue
            chosen.append(cand)
        return sorted(chosen, key=lambda c: c.start)

    def _result(self, text: str, cand: _Candidate) -> ClassificationResult:
        use_case = NER_LABEL_USE_CASES[cand.label]
        return ClassificationResult(
            classification=use_case.classification,
            section_of_text=text[cand.start:cand.end],
            reasoning=f"pattern detector ({cand.mechanism}:{cand.cue}) labelled this span as {cand.label}",
            span=(cand.start, cand.end),
            confidence=use_case.confidence,
            metadata={
                "label": cand.label,
                "entity_type": use_case.entity_type,
                "model": self.model_name,
                "mechanism": cand.mechanism,
                "cue": cand.cue,
            },
        )

    # ------------------------------------------------------------------ cues

    def _cue_candidates(self, text: str) -> List[_Candidate]:
        found: List[_Candidate] = []
        for cue in _CUES:
            for match in cue.pattern.finditer(text):
                value = _scan_value(
                    text, match.end(), kind=cue.scan, max_tokens=cue.max_tokens,
                    allow_lower=cue.allow_lower, allow_cap=cue.allow_cap,
                )
                if value is None:
                    continue
                start, end = value
                if cue.scan == "name" and not self._plausible_name(text, start, end, cue):
                    continue
                if cue.scan == "place":
                    end = _extend_region(text, end)
                if cue.scan == "org" and not self._plausible_org(text[start:end]):
                    continue
                found.append(_Candidate(start, end, cue.label, "cue", cue.name))
        found.extend(self._adjacent_candidates(text))
        return found

    @staticmethod
    def _adjacent_candidates(text: str) -> List[_Candidate]:
        """Name-like runs next to an identifier noun: ``X's employee id``,
        ``X, policy INS-1``, ``for X. The account ...`` (the last one only for
        capitalised values)."""
        found: List[_Candidate] = []
        for pattern, cue_name, allow_lower in _ADJACENT:
            for m in pattern.finditer(text):
                tokens = list(re.finditer(r"[A-Za-z][A-Za-z'’\-]*", m.group("run")))
                words = [t.group(0) for t in tokens]
                # trim stop words / role words from the left
                lead = 0
                while lead < len(words) and (words[lead].lower() in _NAME_STOP
                                             or words[lead].lower() in _COMMON_TITLE_WORDS):
                    lead += 1
                words, tokens = words[lead:], tokens[lead:]
                if not words or any(w.lower() in _NAME_STOP or w.lower() in _COMMON_TITLE_WORDS for w in words):
                    continue
                capped = all(w[0].isupper() for w in words)
                lowered = all(w[0].islower() for w in words)
                if not (capped or (lowered and allow_lower and len(words) >= 2)):
                    continue
                start = m.start("run") + tokens[0].start()
                end = m.start("run") + tokens[-1].end()
                found.append(_Candidate(start, end, "PERSON", "cue", cue_name))
        return found

    @staticmethod
    def _plausible_name(text: str, start: int, end: int, cue: _Cue) -> bool:
        value = text[start:end]
        tokens = [t.strip(".").lower() for t in value.split()]
        if any(t in _ROLE_WORDS or t in _ORG_WORDS for t in tokens):
            return False
        # "dear travel desk team": a following role/organisation word means the
        # run is a team or department name, not a person.
        following = re.match(r"[ \t]*([A-Za-z]+)", text[end:end + 40])
        if following and following.group(1).lower() in (_ROLE_WORDS | _ORG_WORDS):
            return False
        return True

    @staticmethod
    def _plausible_org(value: str) -> bool:
        first = value.split()[0].lower()
        return first not in _ORG_LEAD_STOP and len(value) > 2

    # ----------------------------------------------------------------- shape

    def _shape_candidates(self, text: str) -> List[_Candidate]:
        found: List[_Candidate] = []
        found.extend(self._street_candidates(text))
        for m in _TITLE_STREET.finditer(text):
            found.append(_Candidate(m.start(), m.end(), "FAC", "shape", "title_street"))
        for m in _ORG_SUFFIX_TITLE.finditer(text):
            if self._org_shape_ok(m.group(1)):
                found.append(_Candidate(m.start(1), m.end(), "ORG", "shape", "org_suffix"))
        for m in _ORG_PREFIX_TITLE.finditer(text):
            found.append(_Candidate(m.start(1), m.end(1), "ORG", "shape", "org_of"))
        for pattern in (_ORG_LEGAL_ANY_CASE, _ORG_PREFIX_ANY_CASE):
            for m in pattern.finditer(text):
                if self._org_shape_ok(m.group(1)):
                    found.append(_Candidate(m.start(1), m.end(1), "ORG", "shape", "org_legal_form"))
        found.extend(self._city_state_candidates(text))
        found.extend(self._person_shape_candidates(text))
        return found

    @staticmethod
    def _org_shape_ok(value: str) -> bool:
        tokens = [t.lower() for t in value.replace(",", " ").split()]
        lead = tokens[: -1] if tokens[0] not in ("university", "college", "bank", "institute") else tokens[:1]
        return bool(lead) and all(t not in _FUNCTION_WORDS and t not in _MONTHS_DAYS for t in lead)

    def _street_candidates(self, text: str) -> List[_Candidate]:
        found: List[_Candidate] = []
        for m in _STREET.finditer(text):
            mid = m.group("mid").split()
            suffix_kind = _ADDRESS_SUFFIX[m.group("suffix").lower()]
            lowered = [t.lower().strip(".") for t in mid]
            if any(t in _FUNCTION_WORDS or t in _UNIT_WORDS for t in lowered):
                continue
            region_end = m.end()
            tail = re.compile(r"[ \t]*,[ \t]*").match(text, m.end())
            has_tail = False
            if tail:
                place = _scan_value(text, tail.end(), kind="place", max_tokens=3, allow_lower=True)
                if place:
                    region_end = _extend_region(text, place[1])
                    has_tail = True
                    found.append(_Candidate(place[0], region_end, "GPE", "shape", "street_city"))
            if suffix_kind == "amb" and not (
                has_tail or all(t[:1].isupper() for t in mid) and len(m.group("num")) >= 2
            ):
                continue
            if not mid or not mid[0]:
                continue
            found.append(_Candidate(m.start("num"), m.end(), "FAC", "shape", "street_address"))
        return found

    def _city_state_candidates(self, text: str) -> List[_Candidate]:
        found: List[_Candidate] = []
        city = re.compile(rf"(?<![\w'’])({_TITLE_TOKEN}(?:[ \t]+{_TITLE_TOKEN}){{0,2}})(?=[ \t]*,[ \t]*)")
        for m in city.finditer(text):
            tail_start = m.end(1)
            end = _extend_region(text, tail_start)
            if end > tail_start:
                if any(t.lower() in _PLACE_STOP for t in m.group(1).split()):
                    continue
                found.append(_Candidate(m.start(1), end, "GPE", "shape", "city_state"))
        lower_city = re.compile(rf"(?<![\w'’])([a-z][a-z\-]+(?:[ \t]+[a-z][a-z\-]+){{0,2}})(?=[ \t]*,[ \t]*(?:{_STATE_ABBR.lower()})[ \t]+{_ZIP})")
        for m in lower_city.finditer(text):
            tokens = m.group(1).split()
            while tokens and tokens[0] in _PLACE_STOP:
                tokens.pop(0)
            if not tokens:
                continue
            start = text.rfind(tokens[0], m.start(1), m.end(1))
            end = _extend_region(text, m.end(1))
            found.append(_Candidate(start, end, "GPE", "shape", "city_state_zip"))
        return found

    def _person_shape_candidates(self, text: str) -> List[_Candidate]:
        found: List[_Candidate] = []
        for m in _TITLE_RUN.finditer(text):
            run = m.group(1)
            tokens = list(re.finditer(r"\S+", run))
            words = [t.group(0) for t in tokens]
            lowered = [re.sub(r"[^a-z]", "", w.lower()) for w in words]
            # strip possessive from the final token
            last, had = _strip_possessive(words[-1])
            span_end = m.start(1) + tokens[-1].start() + len(last)
            words[-1] = last
            lowered[-1] = re.sub(r"[^a-z]", "", last.lower())
            lead, tail = 0, len(words)
            while lead < tail and (lowered[lead] in _NAME_STOP or lowered[lead] in _COMMON_TITLE_WORDS):
                lead += 1
            while tail > lead and (lowered[tail - 1] in _NAME_STOP or lowered[tail - 1] in _COMMON_TITLE_WORDS):
                tail -= 1
            if tail - lead < 2:
                continue
            kept = lowered[lead:tail]
            if any(t in _NAME_STOP or t in _COMMON_TITLE_WORDS or t in _COUNTRIES or t in _STATE_NAMES
                   or t in _CITIES for t in kept):
                continue
            start = m.start(1) + tokens[lead].start()
            end = span_end if tail == len(words) else m.start(1) + tokens[tail - 1].end()
            if self._sentence_start(text, start):
                # Sentence-initial Title-case pairs need corroboration (cue,
                # recurrence, gazetteer) unless they head a form record:
                # "<Name>, <something with digits or an @>".
                if not re.match(r"[ \t]*,[^\n]{0,40}?[\d@]", text[end:end + 60]):
                    continue
                found.append(_Candidate(start, end, "PERSON", "shape", "title_record"))
                continue
            found.append(_Candidate(start, end, "PERSON", "shape", "title_sequence"))
        return found

    @staticmethod
    def _sentence_start(text: str, pos: int) -> bool:
        before = text[:pos].rstrip(" \t")
        if not before:
            return True
        if before[-1] in ".!?:;\n\r\"“(":
            return True
        # bullet / list marker
        return bool(re.search(r"(?:^|\n)[ \t]*(?:[-*•]|\d+[.)])$", before))

    # ------------------------------------------------------------- gazetteer

    def _gazetteer_candidates(self, text: str) -> List[_Candidate]:
        found: List[_Candidate] = []
        for m in re.finditer(r"[A-Za-z][A-Za-z'’\-]*(?:[ \t]+[A-Za-z][A-Za-z'’\-]*){0,2}", text):
            pass
        lowered = text.lower()
        # places: states, countries, cities
        for name in _STATE_NAMES | _COUNTRIES | _CITIES:
            for m in re.finditer(rf"(?<![\w'’]){re.escape(name)}(?![\w])", lowered):
                raw = text[m.start():m.end()]
                if name in _AMBIGUOUS_PLACES and not raw[:1].isupper():
                    continue
                if raw[:1].islower() and name in _CITIES:
                    before = lowered[:m.start()].rstrip().rsplit(" ", 1)[-1]
                    if before not in {"in", "to", "from", "near", "around", "outside", "visit", "visiting"}:
                        continue
                found.append(_Candidate(m.start(), m.end(), "GPE", "gazetteer", "place_list"))
        # <given name> <surname-ish>
        for m in re.finditer(rf"(?<![\w'’])([A-Za-z][a-z]+)[ \t]+([A-Za-z][a-z]+)(?![\w])", text):
            first, second = m.group(1), m.group(2)
            if first.lower() not in _GIVEN_NAMES or second.lower() in _NAME_STOP:
                continue
            capped = first[0].isupper() and second[0].isupper()
            if capped or second.lower() in _SURNAMES:
                found.append(_Candidate(m.start(), m.end(), "PERSON", "gazetteer", "given_name_pair"))
        return found

    # ------------------------------------------------------------ recurrence

    def _recurrence_candidates(self, text: str, selected: Sequence[_Candidate]) -> List[_Candidate]:
        found: List[_Candidate] = []
        lowered = _fold(text)
        needles: Dict[Tuple[str, str], None] = {}
        for cand in selected:
            value = text[cand.start:cand.end].strip()
            lowered_value = value.lower()
            if len(lowered_value) < 3:
                continue
            needles[(lowered_value, cand.label)] = None
            if cand.label == "PERSON":
                parts = [re.sub(r"[^a-z'’\-]", "", p) for p in lowered_value.split()]
                if len(parts) > 1:
                    for part in (parts[0], parts[-1]):
                        if len(part) >= 3 and part not in _NAME_STOP and part not in _COMMON_TITLE_WORDS:
                            needles[(part, "PERSON")] = None
        for (needle, label), _ in needles.items():
            for m in re.finditer(rf"(?<![\w'’\-]){re.escape(needle)}(?![\w\-])", lowered):
                found.append(_Candidate(m.start(), m.end(), label, "recurrence", "repeat_of_found"))
        found.extend(self._promoted_sequences(text))
        return found

    def _promoted_sequences(self, text: str) -> List[_Candidate]:
        """Capitalised 2-3 word sequences that occur at least twice."""
        occurrences: Dict[str, List[Tuple[int, int, bool]]] = {}
        for m in _TITLE_RUN.finditer(text):
            run = m.group(1)
            words = run.split()
            last, _ = _strip_possessive(words[-1])
            words[-1] = last
            lowered = [re.sub(r"[^a-z]", "", w.lower()) for w in words]
            if any(t in _NAME_STOP or t in _COMMON_TITLE_WORDS or t in _COUNTRIES
                   or t in _STATE_NAMES or t in _CITIES for t in lowered):
                continue
            end = m.start(1) + len(run) - (len(run.split()[-1]) - len(last))
            occurrences.setdefault(" ".join(words), []).append(
                (m.start(1), end, self._sentence_start(text, m.start(1)))
            )
        found = []
        for key, hits in occurrences.items():
            if len(hits) >= 2:
                for start, end, _ in hits:
                    found.append(_Candidate(start, end, "PERSON", "recurrence", "promoted_sequence"))
        return found
