"""
Import secret-detection regex rules from the Gitleaks default rule catalog.

Gitleaks maintains a large TOML catalog of regex rules for API keys, tokens,
private keys, and other credentials. PriVoke maps those imported regexes into
its existing RuleDefinition structure without changing the detector pipeline.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import tomllib
from typing import Iterable, List

from .rule_types import RuleDefinition
from ..classification import Category, Sensitivity, Visibility, initialise_unpacked


GITLEAKS_CONFIG_PATH = Path(__file__).resolve().parent / "external_rules/gitleaks.toml"

_POSIX_CLASS_REPLACEMENTS = {
    "[:alnum:]": "A-Za-z0-9",
    "[:alpha:]": "A-Za-z",
    "[:digit:]": "0-9",
    "[:xdigit:]": "A-Fa-f0-9",
    "[:lower:]": "a-z",
    "[:upper:]": "A-Z",
    "[:space:]": r"\s",
}


def gitleaks_rules(config_path: Path | None = None) -> List[RuleDefinition]:
    path = config_path or GITLEAKS_CONFIG_PATH
    if not path.exists():
        return []

    with path.open("rb") as config_file:
        config = tomllib.load(config_file)

    rules: List[RuleDefinition] = []
    seen_patterns = set()

    for source_rule in _source_rules(config):
        rule_id = source_rule.get("id")
        pattern = source_rule.get("regex")
        if not rule_id or not pattern or _has_allowlists(source_rule):
            continue

        pattern = _python_regex(pattern)
        if pattern in seen_patterns or not _is_python_regex(pattern):
            continue
        seen_patterns.add(pattern)

        rules.append(
            RuleDefinition(
                name=f"gitleaks_{_safe_name(rule_id)}",
                pattern=pattern,
                classification=initialise_unpacked(
                    Sensitivity.S3,
                    Visibility.PU,
                    [Category.IDENTITY],
                ),
                signal="gitleaks_secret",
                flags=re.IGNORECASE,
            )
        )

    return rules


def _source_rules(config: dict) -> Iterable[dict]:
    rules = config.get("rules", [])
    if isinstance(rules, list):
        return rules
    return []


def _has_allowlists(source_rule: dict) -> bool:
    return bool(source_rule.get("allowlist") or source_rule.get("allowlists"))


def _python_regex(pattern: str) -> str:
    converted = pattern.replace("(?i)", "")
    for posix_class, python_class in _POSIX_CLASS_REPLACEMENTS.items():
        converted = converted.replace(posix_class, python_class)
    return converted


def _is_python_regex(pattern: str) -> bool:
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error:
        return False
    return True


def _safe_name(rule_id: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", rule_id.lower()).strip("_")


if __name__ == "__main__":
    rules = gitleaks_rules()

    print(f"\nImported {len(rules)} Gitleaks secret regex rules.\n")

    counts = Counter(rule.signal for rule in rules)

    for signal, count in sorted(counts.items()):
        print(f"{signal:<35} {count}")
