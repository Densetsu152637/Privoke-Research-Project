from typing import List

from .rule_types import RuleDefinition
from ..classification import Category, Sensitivity, Visibility, initialise_unpacked


def health_rules() -> List[RuleDefinition]:
    """Physical and mental health disclosure rules."""
    return [
        RuleDefinition(
            "health_keyword",
            r"\b(?:my|his|her|their|patient|child|son|daughter|spouse|partner)\s+(?:hospital|doctor|medication|medicine|prescription|disease|cancer|diabetes|depression|anxiety|therapy|psychiatric|diagnosis|prognosis|allergy|symptom|treatment|pregnan(?:t|cy)|hiv|aids|autism|adhd)\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH]),
            "health_info",
        ),
        RuleDefinition(
            "health_statement",
            r"\b(?:i|my|he|she|they|patient|client|child|son|daughter|spouse|partner)\s+(?:have|has|had|take|takes|was diagnosed with|am diagnosed with|is diagnosed with|suffer from|suffers from|tested positive for)\s+(?:medication|medicine|prescription|cancer|diabetes|depression|anxiety|therapy|diagnosis|allergy|symptom|treatment|hiv|aids|autism|adhd|ptsd|bipolar|asthma|strep|chest pain)\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH]),
            "health_disclosure",
        ),
        RuleDefinition(
            "medical_identifier",
            r"\b(?:insurance\s+id|policy\s+id|member\s+id|medical\s+license|medicare\s+(?:id|number))\s*[:#=]?\s*[A-Z0-9\-]{5,24}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.HEALTH]),
            "medical_identifier",
        ),
    ]
