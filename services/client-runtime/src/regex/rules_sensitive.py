from typing import List

from .rule_types import RuleDefinition
from ..classification import Category, Sensitivity, Visibility, initialise_unpacked


def sensitive_category_rules() -> List[RuleDefinition]:
    """PDPA-sensitive and harm-sensitive category rules."""
    return [
        RuleDefinition(
            "politics",
            r"\b(voted?\s+for|political\s+(?:party|view|belief|campaign)|democrat|republican|labor party|liberal party|conservative|socialist|communist|activist|protest(?:ed|ing)?|union member)\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.POLITICS]),
            "political_info",
        ),
        RuleDefinition(
            "religion",
            r"\b(christian|muslim|islam|jewish|judaism|hindu|buddhist|atheist|agnostic|church|mosque|synagogue|temple|priest|pastor|imam|rabbi|religion|faith|prayer group)\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.RELIGION]),
            "religious_info",
        ),
        RuleDefinition(
            "criminal",
            r"\b(arrest(?:ed)?|convict(?:ed|ion)|felony|misdemeanor|probation|parole|criminal\s+record|charged\s+with|court\s+case|restraining\s+order)\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.CRIMINAL]),
            "criminal_info",
        ),
        RuleDefinition(
            "sexual",
            r"\b(sexual\s+(?:orientation|history)|gay|lesbian|bisexual|transgender|queer|lgbtq|dating\s+profile|intimate|pregnancy termination|abortion)\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.SEXUAL]),
            "sexual_info",
        ),
        RuleDefinition(
            "child",
            r"\b(?:my\s+)?(?:child|children|kid|kids|son|daughter|minor|underage|schoolchild|student)\b|\b(?:age|aged)\s+(?:[1-9]|1[0-7])\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.CHILD]),
            "child_info",
        ),
        RuleDefinition(
            "third_party_disclosure",
            r"\b(?:my|his|her|their)\s+(?:spouse|husband|wife|partner|boyfriend|girlfriend|child|son|daughter|mother|father|friend|coworker|colleague|boss|employee)\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.THIRD_PARTY]),
            "third_party_info",
        ),
    ]
