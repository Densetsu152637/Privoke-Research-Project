"""Canonical detector text with provenance into the original prompt."""
from dataclasses import dataclass
import re
import unicodedata
from typing import Optional


@dataclass(frozen=True)
class NormalizedText:
    text: str
    original: str
    origins: tuple[tuple[int, int], ...]

    def original_span(self, span: tuple[int, int]) -> tuple[int, int] | None:
        start, end = span
        if (type(start) is not int or type(end) is not int
                or not 0 <= start < end <= len(self.text)):
            return None
        selected = self.origins[start:end]
        return min(item[0] for item in selected), max(item[1] for item in selected)


@dataclass(frozen=True)
class RobustnessOptions:
    """Optional canonicalisations that undo common input obfuscation.

    All default off. When ``robustness`` is omitted they follow the
    ``PRIVOKE_*`` flags for the case-preserved detector view only
    (``lowercase=False``), so semantic input and the semantic training and
    reference preprocessing stay unchanged.
    """

    strip_format_chars: bool = False
    canonicalise_digits: bool = False
    canonicalise_email_words: bool = False

    @classmethod
    def from_config(cls) -> "RobustnessOptions":
        from ..config import GLOBAL_CONFIG
        return cls(
            strip_format_chars=GLOBAL_CONFIG.strip_format_chars,
            canonicalise_digits=GLOBAL_CONFIG.canonicalise_digits,
            canonicalise_email_words=GLOBAL_CONFIG.canonicalise_email_words,
        )


# --- e-mail addresses spelled with words or brackets -------------------------------
_LABEL = r"[\w%+\-]+"
_DOT_MARK = r"(?:[ \t]?[\[(]dot[\])][ \t]?|[ \t]+dot[ \t]+)"
_DOT_OR_PLAIN = rf"(?:{_DOT_MARK}|\.)"
_DOT_MARK_RE = re.compile(_DOT_MARK, re.IGNORECASE)
# local@domain whose final label is letters only; rewritten only if a marker occurs
_EMAIL_WITH_AT_SIGN = re.compile(
    rf"(?<![\w.%+\-])({_LABEL}(?:{_DOT_OR_PLAIN}{_LABEL})*)([ 	]*@[ 	]*)"
    rf"({_LABEL}(?:{_DOT_OR_PLAIN}{_LABEL})*{_DOT_OR_PLAIN}[A-Za-z]{{2,24}})(?![\w@\-])", re.IGNORECASE)
# local at domain dot tld: no at-sign to anchor on, so the final label must be a common TLD
_EMAIL_WITH_AT_WORD = re.compile(
    rf"(?<![\w.%+\-])({_LABEL}(?:{_DOT_OR_PLAIN}{_LABEL})*)[ \t]+at[ \t]+"
    rf"({_LABEL}(?:{_DOT_OR_PLAIN}{_LABEL})*{_DOT_MARK}([A-Za-z]{{2,24}}))(?![\w@\-])", re.IGNORECASE)
# Two-letter country codes are accepted as they are; longer TLDs must be common ones.
_COMMON_TLDS = frozenset("""
com org net edu gov mil int info biz app dev xyz online site tech blog shop cloud mobi name pro
""".split())
# Pronouns, function words and verbs that take an "at" complement ("look at ...
# dot ..."): ordinary prose, never an e-mail local part on their own.
_NOT_A_LOCAL_PART = frozenset("""
i me my mine you your yours he him his she her hers it its we us our ours they them their theirs
who whom what which that this these those here there then now when where how why one someone anyone everyone
and or but so if of on in to for with from by as is are was were be been am do does did has have had
look looks looked looking see sees saw seen meet meets met arrive arrives arrived stay stays stayed stare glance
check checks checked call calls called text wait waiting available live lives lived work works worked working
found find start starts started stop stopped smile smiled laugh laughed come comes came go goes went
""".split())

# --- obfuscated digit identifiers ----------------------------------------------------
_DIGIT_WORDS = {"zero": 0, "oh": 0, "one": 1, "two": 2, "three": 3, "four": 4,
                "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9}
_DIGIT_WORD = "(?:" + "|".join(sorted(_DIGIT_WORDS, key=len, reverse=True)) + ")"
_SPELLED_SEPARATOR = r"(?:[ \t]*-[ \t]*|[ \t]+)"
_SPELLED_RUN = re.compile(
    rf"(?<![\w]){_DIGIT_WORD}(?:{_SPELLED_SEPARATOR}{_DIGIT_WORD})*(?![\w])", re.IGNORECASE)
_SPELLED_TOKEN = re.compile(rf"({_DIGIT_WORD})|([ \t]*-[ \t]*)|([ \t]+)", re.IGNORECASE)
_MIN_SPELLED_DIGITS = 7
_MIN_UNAMBIGUOUS_SPELLED_DIGITS = 4   # "oh" is also an interjection
# Single digits joined by one repeated separator, e.g. "5-5-5-1-2-3-4". The
# minimum chain length keeps short punctuated numbers (dates, ratios, versions,
# IPv4 addresses) untouched. Only the single-digit chain is joined: a grouping
# separator before or after it, and any longer digit group beside it, stay as
# written ("1-9-7-3-01-29" becomes "1973-01-29").
_MIN_SINGLE_DIGIT_CHAIN = {"-": 4, ".": 7, "/": 7}
_SINGLE_DIGIT_CHAIN = re.compile(r"(?<!\d)\d([.\-/])(?:\d\1)+\d(?!\w)")

# A rewrite segment: (replacement text, source start, source end) in canonical coordinates.
_Segment = tuple[str, int, int]


def normalize_text(text: str) -> str:
    """Return canonical text; use normalize_with_offsets for evidence spans."""
    return normalize_with_offsets(text).text


def normalize_with_offsets(
    text: str,
    *,
    lowercase: bool = True,
    robustness: Optional[RobustnessOptions] = None,
) -> NormalizedText:
    """Map each canonical character to the original interval that produced it.

    Expanded Unicode characters share an interval. Collapsed/replaced sequences
    cover their complete source interval, including obfuscation and whitespace.
    ``lowercase=False`` keeps the original letter case (for case-sensitive
    detector layers such as NER); semantic models require the default.
    ``robustness`` selects the optional obfuscation canonicalisations; omitted,
    it follows the ``PRIVOKE_*`` flags for the case-preserved view
    (``lowercase=False``) and is off for the lowercased semantic view.
    """
    if robustness is None:
        robustness = RobustnessOptions() if lowercase else RobustnessOptions.from_config()
    characters: list[str] = []
    origins: list[tuple[int, int]] = []
    cluster = ''
    cluster_start = 0

    def flush(end: int) -> None:
        normalized = unicodedata.normalize('NFKC', cluster)
        characters.extend(normalized)
        origins.extend([(cluster_start, end)] * len(normalized))

    for index, character in enumerate(text):
        if robustness.strip_format_chars and unicodedata.category(character) == 'Cf':
            # Zero-width, bidi, soft-hyphen and tag characters carry no text; the
            # interval of the preceding cluster (flushed at the next kept
            # character) still covers them.
            continue
        # Combining marks and Hangul composition must stay with their starter.
        if cluster and (unicodedata.combining(character) or
                unicodedata.normalize('NFKC', cluster + character) !=
                unicodedata.normalize('NFKC', cluster) +
                unicodedata.normalize('NFKC', character)):
            cluster += character
        else:
            if cluster:
                flush(index)
            cluster = character
            cluster_start = index
    if cluster:
        flush(len(text))

    canonical = ''.join(characters)
    if lowercase:
        lowered_origins = [origin for character, origin in zip(canonical, origins)
                           for _ in character.lower()]
        canonical = canonical.lower()
        origins = lowered_origins

    def substitute(pattern: str, replacement: str, flags: int = 0) -> None:
        nonlocal canonical, origins
        parts: list[str] = []
        mapped: list[tuple[int, int]] = []
        cursor = 0
        for match in re.finditer(pattern, canonical, flags):
            start, end = match.span()
            parts.append(canonical[cursor:start])
            mapped.extend(origins[cursor:start])
            parts.append(replacement)
            source = origins[start:end]
            interval = (min(item[0] for item in source), max(item[1] for item in source))
            mapped.extend([interval] * len(replacement))
            cursor = end
        parts.append(canonical[cursor:])
        mapped.extend(origins[cursor:])
        canonical, origins = ''.join(parts), mapped

    def rewrite(pattern: re.Pattern, plan) -> None:
        """Apply ``plan(match) -> list[_Segment] | None`` to each match.

        Segments tile the match. A segment whose text equals its source keeps
        per-character origins; any other covers its whole source interval.
        """
        nonlocal canonical, origins
        parts: list[str] = []
        mapped: list[tuple[int, int]] = []
        cursor = 0
        for match in pattern.finditer(canonical):
            segments = plan(match)
            if segments is None:
                continue
            parts.append(canonical[cursor:match.start()])
            mapped.extend(origins[cursor:match.start()])
            for replacement, seg_start, seg_end in segments:
                parts.append(replacement)
                if replacement == canonical[seg_start:seg_end]:
                    mapped.extend(origins[seg_start:seg_end])
                elif replacement:
                    source = origins[seg_start:seg_end]
                    interval = (min(item[0] for item in source), max(item[1] for item in source))
                    mapped.extend([interval] * len(replacement))
            cursor = match.end()
        parts.append(canonical[cursor:])
        mapped.extend(origins[cursor:])
        canonical, origins = ''.join(parts), mapped

    def dotted(start: int, end: int) -> list[_Segment]:
        """Segments for canonical[start:end] with dot markers replaced by '.'."""
        segments: list[_Segment] = []
        cursor = start
        for mark in _DOT_MARK_RE.finditer(canonical, start, end):
            if mark.start() > cursor:
                segments.append((canonical[cursor:mark.start()], cursor, mark.start()))
            segments.append(('.', mark.start(), mark.end()))
            cursor = mark.end()
        if cursor < end:
            segments.append((canonical[cursor:end], cursor, end))
        return segments

    def plan_email_at_sign(match: re.Match) -> Optional[list[_Segment]]:
        if not _DOT_MARK_RE.search(canonical, match.start(), match.end()):
            return None     # nothing spelled out: leave real addresses untouched
        return (dotted(match.start(1), match.end(1)) + [('@', match.start(2), match.end(2))]
                + dotted(match.start(3), match.end(3)))

    def plan_email_at_word(match: re.Match) -> Optional[list[_Segment]]:
        local = match.group(1).lower()
        if (not (len(match.group(3)) == 2 or match.group(3).lower() in _COMMON_TLDS)
                or local in _NOT_A_LOCAL_PART
                or re.split(r'[ \t]+', local)[-1] in _NOT_A_LOCAL_PART):
            return None
        local_end, domain_start = match.end(1), match.start(2)
        return (dotted(match.start(1), local_end) + [('@', local_end, domain_start)]
                + dotted(domain_start, match.end(2)))

    def plan_spelled_digits(match: re.Match) -> Optional[list[_Segment]]:
        tokens = list(_SPELLED_TOKEN.finditer(canonical, match.start(), match.end()))
        words = [t.group(1).lower() for t in tokens if t.group(1)]
        digits = [_DIGIT_WORDS[w] for w in words]
        if len(digits) < _MIN_SPELLED_DIGITS:
            return None
        if sum(1 for w in words if w != 'oh') < _MIN_UNAMBIGUOUS_SPELLED_DIGITS:
            return None
        if {b - a for a, b in zip(digits, digits[1:])} in ({1}, {-1}):
            return None     # a counting sequence is not an identifier
        segments: list[_Segment] = []
        for token in tokens:
            if token.group(1):
                segments.append((str(_DIGIT_WORDS[token.group(1).lower()]), token.start(), token.end()))
            elif token.group(2):
                segments.append(('-', token.start(), token.end()))   # keep the stated grouping
            else:
                segments.append(('', token.start(), token.end()))
        return segments

    def plan_digit_chain(match: re.Match) -> Optional[list[_Segment]]:
        separator = match.group(1)
        if (match.end() - match.start() + 1) // 2 < _MIN_SINGLE_DIGIT_CHAIN[separator]:
            return None
        return [('' if canonical[i] == separator else canonical[i], i, i + 1)
                for i in range(match.start(), match.end())]

    substitute(r'\[at\]|\(at\)', '@', re.IGNORECASE)
    if robustness.canonicalise_email_words:
        rewrite(_EMAIL_WITH_AT_SIGN, plan_email_at_sign)
        rewrite(_EMAIL_WITH_AT_WORD, plan_email_at_word)
    if robustness.canonicalise_digits:
        rewrite(_SPELLED_RUN, plan_spelled_digits)
        rewrite(_SINGLE_DIGIT_CHAIN, plan_digit_chain)
    substitute(r'(?<=\d)[ \t]+(?=\d)', '')
    substitute(r'[ \t]+', ' ')
    substitute(r'\n+', '\n')
    left = len(canonical) - len(canonical.lstrip())
    right = len(canonical.rstrip())
    return NormalizedText(canonical[left:right], text, tuple(origins[left:right]))
