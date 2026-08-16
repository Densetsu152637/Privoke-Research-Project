import os
from typing import List

from .rule_types import RuleDefinition
from .rules_context import contextual_rules
from .rules_financial import financial_rules
from .rules_health import health_rules
from .rules_identity import identity_rules
from .rules_location import location_rules
from .rules_gitleaks import gitleaks_rules
from .rules_sensitive import sensitive_category_rules
from .rules_visibility import visibility_rules
from .rules_presidio import presidio_rules

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
    if _env_enabled("PRIVOKE_REGEX_GITLEAKS", default=True):
        rules.extend(gitleaks_rules())
    if _env_enabled("PRIVOKE_REGEX_PRESIDIO", default=True):
        rules.extend(presidio_rules())
    return rules


def _env_enabled(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}
