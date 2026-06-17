from typing import List

from regex.rule_types import RuleDefinition
from regex.rules_context import contextual_rules
from regex.rules_financial import financial_rules
from regex.rules_health import health_rules
from regex.rules_identity import identity_rules
from regex.rules_location import location_rules
from regex.rules_sensitive import sensitive_category_rules
from regex.rules_visibility import visibility_rules


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
