"""Labelled identifier values: "<qualifier> ID / number / no. / # / code" followed by a value.

An identifier is disclosed when a value of identifier shape is introduced by an
explicit label naming what it identifies. The value shape alone ("a letter plus
a short digit run") also describes part numbers and promo codes, which is why
the shape-only patterns need checksums or context; the label is that context.
This family is general: its vocabulary is identifier nouns, not the wording of
any dataset, and it accepts any value of identifier shape rather than only the
formats a checksum or country pattern recognises.

Sensitivity follows the identifier class: government, health and payment
identifiers are S3 (they authenticate or directly identify a person to an
institution); customer, account, membership and similar reference identifiers
are S2 (they identify a person to one organisation).
"""

from __future__ import annotations

import re
from typing import List

from .rule_types import RuleDefinition
from ..classification import Category, Sensitivity, Visibility, initialise_unpacked


# Nouns that turn a qualifier into an identifier label ("passport number").
_WORD_NOUN = r"(?:id|identifier|numbers?|no|num|nr|code|ref(?:erence)?)\b\.?"

# "card" names a payment or identity card unless it is a store, library or similar card.
_PAYMENT_CARD = r"(?<!loyalty\s)(?<!library\s)(?<!gift\s)(?<!store\s)(?<!reward\s)(?<!rewards\s)(?<!club\s)card"

# Qualifiers whose identifiers authenticate or directly identify a person to an
# institution: government, health-insurance and payment identifiers.
SENSITIVE_QUALIFIERS = (
    r"passport", r"licen[cs]e", r"national", r"social\s+(?:security|insurance)",
    r"tax(?:\s+(?:file|payer|registration))?", r"identity", r"identification",
    r"citizen(?:ship)?", r"voter", r"visa", r"residen(?:ce|cy)\s+permit", r"immigration",
    r"military", r"birth\s+certificate", r"patient", r"medical(?:\s+record)?",
    r"health(?:\s+plan)?", r"(?:health|medical|insurance)(?:\s+plan)?\s+member",
    r"insurance", r"medicare", r"medicaid", r"beneficiary",
    r"bank(?:\s+account)?", _PAYMENT_CARD,
)

# Qualifiers whose identifiers identify a person to one organisation or record.
GENERIC_QUALIFIERS = (
    r"customer", r"client", r"account", r"member(?:ship)?", r"subscriber", r"employee",
    r"staff", r"personnel", r"user", r"policy", r"claim", r"registration", r"plate",
    r"(?:loyalty|library|rewards?|club|gift|store)\s+card", r"reference",
)

# Identifier acronyms that name their own class and so need no "number" noun ("SSN 123...").
SENSITIVE_ACRONYMS = (r"ssn", r"tfn", r"nino", r"ein", r"itin", r"mrn", r"nric")

# Document nouns that label their own value with a colon ("Passport: X1234567"). "Licence",
# "visa" and similar are left out: "License: Apache-2.0" is a software licence, not an ID.
SELF_LABELLING_DOCUMENTS = (r"passport", r"id\s+card", r"identity\s+card", r"medicare", r"medicaid")

# Between label and value: optional closing quote or markdown emphasis, "is"/"was", a
# separator (":" "=" "#"), then optional opening quote, bracket or emphasis ("**", `"`).
_CONNECTOR = r"[\"'*_]*(?:\s*(?:is|was|are)\b)?\s*[:=#]?[*_\s\"'(\[]*"

# An identifier value: tokens of letters, digits and underscores joined by hyphens or
# single spaces. The first token carries a digit (or is a 1-3 letter prefix directly
# followed by a digit group), and every spaced group carries a digit, so ordinary words
# after the label ("number is required") are not values. At most five further groups.
_TOKEN = r"[A-Z0-9_]+"
_VALUE = (
    r"(?:(?=[A-Z0-9_\-]*\d)" + _TOKEN + r"(?:-" + _TOKEN + r")*"
    r"|[A-Z]{1,3}(?=\s[A-Z0-9_\-]*\d))"
    r"(?:-" + _TOKEN + r"|\s(?=[A-Z0-9_\-]*\d)" + _TOKEN + r"(?:-" + _TOKEN + r")*){0,5}"
)

_DATE_VALUE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}-\d{1,2}-\d{2,4}")


def _alternation(parts) -> str:
    return "(?:" + "|".join(parts) + ")"


def labelled_identifier_pattern(qualifiers, *, acronyms=(), self_labelling=()) -> str:
    noun_form = (
        _alternation(qualifiers)
        + r"(?:[\s_-]*" + _WORD_NOUN + r"(?:[\s_-]+" + _WORD_NOUN + r")?|\s*#)"
    )
    shapes = [noun_form]
    if acronyms:
        shapes.append(_alternation(acronyms) + r"(?:[\s_-]*" + _WORD_NOUN + r")?")
    if self_labelling:
        shapes.append(_alternation(self_labelling) + r"\s*(?=[:=#])")
    return r"\b" + _alternation(shapes) + _CONNECTOR + r"(?P<value>" + _VALUE + r")\b"


def has_identifier_shape(match: "re.Match[str]") -> bool:
    """Value of a labelled-identifier hit: a digit present, 5-24 compact characters, not a date."""
    value = match.group("value")
    compact = re.sub(r"[\s\-]", "", value)
    if _DATE_VALUE.fullmatch(value.strip()):
        return False
    return 5 <= len(compact) <= 24 and any(char.isdigit() for char in compact)


def identifier_rules() -> List[RuleDefinition]:
    """General labelled-identifier rules, by identifier class."""
    return [
        RuleDefinition(
            "labelled_identifier_sensitive",
            labelled_identifier_pattern(
                SENSITIVE_QUALIFIERS,
                acronyms=SENSITIVE_ACRONYMS,
                self_labelling=SELF_LABELLING_DOCUMENTS,
            ),
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.IDENTITY]),
            "labelled_identifier",
            validator=has_identifier_shape,
        ),
        RuleDefinition(
            "labelled_identifier_generic",
            labelled_identifier_pattern(GENERIC_QUALIFIERS),
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.IDENTITY]),
            "labelled_identifier",
            validator=has_identifier_shape,
        ),
    ]
