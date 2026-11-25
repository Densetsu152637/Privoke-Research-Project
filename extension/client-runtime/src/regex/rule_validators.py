"""Structural validators and context checks applied to regex hits.

Validators reject hits that match a pattern's shape but cannot be a real value
of that kind (failed checksum, impossible number range) or that lack the
context the pattern needs to be more than an arbitrary token.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable

from .rule_types import MatchValidator


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn_valid(value: str) -> bool:
    digits = [int(char) for char in _digits(value)]
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def iban_valid(value: str) -> bool:
    compact = re.sub(r"[\s\-]", "", value).upper()
    if not 15 <= len(compact) <= 34:
        return False
    rotated = compact[4:] + compact[:4]
    try:
        return int("".join(str(int(char, 36)) for char in rotated)) % 97 == 1
    except ValueError:
        return False


def nhs_number_valid(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 10:
        return False
    total = sum(int(digits[index]) * (10 - index) for index in range(9))
    check = 11 - total % 11
    check = 0 if check == 11 else check
    return check != 10 and check == int(digits[9])


def us_ssn_valid(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


# Context words that make a failed-checksum number still a value of its kind: a typo in a
# card number or IBAN that the user labels as one is still that user's card or account.
CARD_CONTEXT = (
    "card", "credit", "debit", "visa", "mastercard", "amex", "cvv", "cvc",
    "payment", "expiry", "expires", "expiration",
)
IBAN_CONTEXT = (
    "iban", "bank", "account", "transfer", "wire", "payment", "swift", "bic", "sort code",
)
SSN_CONTEXT = ("ssn", "social security", "tax file", "national insurance")


def alphanumeric_identifier_shape(value: str) -> bool:
    """Number-like token: 8+ characters, 5+ digits and at least one letter."""
    compact = re.sub(r"[\s\-]", "", value)
    digits = len(_digits(compact))
    return len(compact) >= 8 and digits >= 5 and digits < len(compact)


def checksum_validator(check: Callable[[str], bool]) -> MatchValidator:
    return lambda match: check(match.group(0))


def has_context_word(
    match: "re.Match[str]",
    words: Iterable[str],
    before: int = 80,
    after: int = 40,
) -> bool:
    """Whole-word context lookup around a match (never a substring test)."""
    text = match.string
    window = text[max(0, match.start() - before):match.end() + after].lower()
    return any(
        re.search(r"(?<!\w)" + re.escape(word.lower()) + r"(?!\w)", window)
        for word in words
    )


def match_shape_validator(shape: Callable[[str], bool]) -> MatchValidator:
    return lambda match: shape(match.group(0))


def digits_or_context_validator(min_digits: int, words: Iterable[str]) -> MatchValidator:
    """Accept hits with enough digits, or weaker hits that have a context word."""
    context = tuple(words)

    def validate(match: "re.Match[str]") -> bool:
        if len(_digits(match.group(0))) >= min_digits:
            return True
        return has_context_word(match, context)

    return validate


def context_required_validator(words: Iterable[str]) -> MatchValidator:
    context = tuple(words)
    return lambda match: has_context_word(match, context)
