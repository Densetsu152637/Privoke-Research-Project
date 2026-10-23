from typing import List

from .rule_types import RuleDefinition
from ..classification import Category, Sensitivity, Visibility, initialise_unpacked


# Closed-class (function) words never name a place, so a connector followed by
# one of them ("my address or ...", "I live in the ...") is not a disclosure.
_CLOSED_CLASS_WORDS = "|".join((
    "a", "an", "the", "this", "that", "these", "those", "some", "any", "all",
    "each", "every", "either", "neither", "both", "another", "other", "such",
    "anything", "anyone", "something", "someone", "everything", "everyone",
    "nothing", "nobody", "somewhere", "anywhere", "everywhere", "nowhere",
    "i", "me", "my", "mine", "you", "your", "we", "our", "us", "they", "their",
    "them", "he", "him", "his", "she", "her", "it", "its",
    "and", "or", "but", "nor", "so", "if", "than", "then", "as", "because",
    "to", "of", "in", "on", "at", "for", "with", "without", "by", "from",
    "about", "into", "over", "after", "before", "between", "through", "during",
    "under", "again", "near", "up", "out", "off",
    "is", "are", "was", "were", "be", "been", "am", "do", "does", "did",
    "can", "could", "will", "would", "should", "may", "might", "must",
    "not", "no", "just", "only", "also", "too", "very", "more", "most",
    "what", "which", "who", "whom", "whose", "how", "when", "where", "why",
    "there", "here",
))


def location_rules() -> List[RuleDefinition]:
    """Precise and quasi-location rules."""
    return [
        RuleDefinition(
            "street_address",
            r"\b\d{1,6}\s+[A-Z][\w.'-]*(?:\s+[A-Z][\w.'-]*){0,4}\s+(?:st|street|ave|avenue|rd|road|blvd|boulevard|drive|dr|lane|ln|court|ct|way|terrace|pl|place)\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.LOCATION]),
            "street_address",
        ),
        RuleDefinition(
            "geo_coordinates",
            r"\b-?\d{1,2}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.LOCATION]),
            "geo_coordinates",
        ),
        RuleDefinition(
            "license_plate",
            r"\b(?:license\s+plate|plate)\s*[:#=]?\s*[A-Z]{2,4}[-\s]?\d{3,4}\b|\b(?!(?:rfc|cve|iso|iec|bcp|std)-)[A-Z]{3}-\d{4}\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.LOCATION]),
            "license_plate",
        ),
        RuleDefinition(
            "location_keyword",
            r"\b(?:(?:(?:i|we|he|she|they)\s+(?:(?:am|are|is)\s+)?"
            r"|(?:i['’]m|we['’]re|he['’]s|she['’]s|they['’]re)\s+)(?:currently\s+)?"
            r"(?:live|lives|living|located|from|(?:come|comes)\s+from|stay|staying|alone\s+tonight)"
            r"\s+(?:in\s+|on\s+|at\s+|near\s+)?"
            r"|(?:my|our|his|her|their)\s+(?:home\s+)?(?:address|hometown|residence|location)"
            r"\s*(?:is\s+|was\s+|[:=]\s*|(?:in|on|at|near)\s+)"
            r"|(?:home\s+)?(?:address|hometown|residence)\s*[:=]\s*)"
            r"(?!(?:" + _CLOSED_CLASS_WORDS + r")\b)[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.LOCATION]),
            "location",
        ),
        RuleDefinition(
            "route_or_commute",
            r"\b(?:commute|route|walk|drive|bus|train)\s+(?:from|to|between)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.LOCATION]),
            "route_location",
        ),
    ]
