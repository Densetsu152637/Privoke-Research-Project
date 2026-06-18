from typing import List

from src.classification import Category, Sensitivity, Visibility, initialise_unpacked
from src.regex.rule_types import RuleDefinition


def health_rules() -> List[RuleDefinition]:
    """Physical and mental health disclosure rules."""
    return [
        RuleDefinition(
            "health_keyword",
            r"\b(hospital|doctor|medication|medicine|prescription|disease|cancer|diabetes|depression|anxiety|therapy|psychiatric|diagnosis|prognosis|allergy|symptom|treatment|pregnan(?:t|cy)|hiv|aids|autism|adhd)\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH]),
            "health_info",
        ),
        RuleDefinition(
            "health_statement",
            r"\b(?:i|my|he|she|they)\s+(?:have|has|had|take|takes|was diagnosed with|am diagnosed with|suffer from)\s+(?:medication|medicine|prescription|cancer|diabetes|depression|anxiety|therapy|diagnosis|allergy|symptom|treatment|hiv|aids|autism|adhd|ptsd|bipolar|asthma)\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH]),
            "health_disclosure",
        ),
    ]
