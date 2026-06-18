from typing import List

from src import RuleDefinition
from src import contextual_rules
from src import financial_rules
from src import health_rules
from src import identity_rules
from src import location_rules
from src import sensitive_category_rules
from src import visibility_rules


def all_rule_definitions() -> List[RuleDefinition]:
    """Return all regex rule definitions in deterministic execution order."""
    rules: List[RuleDefinition] = []
    rules.extend(visibility_rules())
    rules.extend(identity_rules())
    rules.extend(location_rules())
    rules.extend(health_rules())
    rules.extend(financial_rules())
    rules.extend(sensitive_category_rules())
    rules.extend(contextual_rules())
    return rules
