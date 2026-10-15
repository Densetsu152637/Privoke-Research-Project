from typing import List

from .rule_types import RuleDefinition
from ..classification import Category, Sensitivity, Visibility, initialise_unpacked


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
            r"\b(?:(?:i|we)\s+(?:work|worked|am\s+employed|are\s+employed)\s+(?:at|for|by)"
            r"|(?:my|our)\s+(?:employer|company|workplace|office|manager|boss)\s*(?:is|are|[:=])"
            r"|(?:employer|company|department)\s*[:=])\s+[a-z][\w&.-]*",
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
