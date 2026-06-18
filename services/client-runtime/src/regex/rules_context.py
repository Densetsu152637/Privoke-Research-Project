from typing import List

from src import Category, Sensitivity, Visibility, initialise_unpacked
from src import RuleDefinition


def contextual_rules() -> List[RuleDefinition]:
    """Relationship, workplace, and temporal context rules."""
    return [
        RuleDefinition(
            "family_disclosure",
            r"\b(spouse|husband|wife|partner|boyfriend|girlfriend|children|kids|son|daughter|mother|father|siblings?|family)\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.THIRD_PARTY]),
            "family_info",
        ),
        RuleDefinition(
            "workplace_keyword",
            r"\b(work(?:s|ing)?|employ(?:ee|er|ment)|company|office|boss|colleague|manager|department)\b",
            initialise_unpacked(Sensitivity.S1, Visibility.PU, [Category.IDENTITY]),
            "workplace_info",
        ),
        RuleDefinition(
            "timestamp_field",
            r"\b(timestamp|visited|accessed|logged|created|modified|updated|date|time)\s*[:=]\s*[\d\s\-/:T.Z]+",
            initialise_unpacked(Sensitivity.S1, Visibility.PU, [Category.IDENTITY]),
            "timestamp",
        ),
    ]
