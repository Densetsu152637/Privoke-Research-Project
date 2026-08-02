from typing import List

from .rule_types import RuleDefinition
from ..classification import Category, Sensitivity, Visibility, initialise_unpacked


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
            r"\b(?:license\s+plate|plate)\s*[:#=]?\s*[A-Z]{2,4}[-\s]?\d{3,4}\b|\b[A-Z]{3}-\d{4}\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.LOCATION]),
            "license_plate",
        ),
        RuleDefinition(
            "location_keyword",
            r"\b(live|lives|living|located|from|address|hometown|residence|staying|alone tonight)\s*(?:in|at|near)?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?",
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
