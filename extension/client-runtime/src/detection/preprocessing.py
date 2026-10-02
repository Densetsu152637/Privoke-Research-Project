"""Canonical detector text with provenance into the original prompt."""
from dataclasses import dataclass
import re
import unicodedata


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


def normalize_text(text: str) -> str:
    """Return canonical text; use normalize_with_offsets for evidence spans."""
    return normalize_with_offsets(text).text


def normalize_with_offsets(text: str) -> NormalizedText:
    """Map each canonical character to the original interval that produced it.

    Expanded Unicode characters share an interval. Collapsed/replaced sequences
    cover their complete source interval, including obfuscation and whitespace.
    """
    characters: list[str] = []
    origins: list[tuple[int, int]] = []
    cluster = ''
    cluster_start = 0

    def flush(end: int) -> None:
        normalized = unicodedata.normalize('NFKC', cluster)
        characters.extend(normalized)
        origins.extend([(cluster_start, end)] * len(normalized))

    for index, character in enumerate(text):
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
    lowered_origins = [origin for character, origin in zip(canonical, origins)
                       for _ in character.lower()]
    canonical = canonical.lower()
    origins = lowered_origins

    def substitute(pattern: str, replacement: str) -> None:
        nonlocal canonical, origins
        parts: list[str] = []
        mapped: list[tuple[int, int]] = []
        cursor = 0
        for match in re.finditer(pattern, canonical):
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

    substitute(r'\[at\]|\(at\)', '@')
    substitute(r'(?<=\d)[ \t]+(?=\d)', '')
    substitute(r'[ \t]+', ' ')
    substitute(r'\n+', '\n')
    left = len(canonical) - len(canonical.lstrip())
    right = len(canonical.rstrip())
    return NormalizedText(canonical[left:right], text, tuple(origins[left:right]))
