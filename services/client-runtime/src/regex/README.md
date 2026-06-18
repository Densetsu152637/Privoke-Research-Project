# Regex Rule Detector

This directory contains layer 1 of the PriVoke detection pipeline: deterministic rule-based detection.

The rule detector should be fast, local, explainable, and conservative for high-confidence sensitive patterns. It is the first layer in the Casper-style three-layer framework, before NER and semantic context detection.

## Responsibilities

The rule detector should identify:

- direct identifiers: email, phone, SSN, passport, government ID, driver license,
- financial identifiers: credit cards, account numbers, IBAN, salary, debt, investment context,
- precise location: addresses, coordinates, routes, private whereabouts,
- sensitive topics: health, politics, religion, criminal history, sexuality, children,
- third-party disclosure cues,
- visibility context: public, semi-public, restricted, group-private, personal-private.

## Output Contract

`RuleDetector.analyze(text)` should return a dictionary containing:

- `classification`: merged `Classification`,
- `packed_classification`: 16-bit packed value,
- `matches`: internal rule match objects,
- `match_details`: JSON-friendly match records,
- `signals`: ordered signal names.

Rules must map directly to `Sensitivity`, `Visibility`, and `Category` values. Do not return category or severity strings.

## Rule Design

Each rule module should expose a wrapper function that returns `list[RuleDefinition]`.
Rules are grouped by concern:

- `rules_visibility.py`
- `rules_identity.py`
- `rules_location.py`
- `rules_health.py`
- `rules_financial.py`
- `rules_sensitive.py`
- `rules_context.py`

`rule_registry.py` assembles those lists in deterministic execution order.

Each rule should define:

- name,
- regex pattern,
- resulting `Classification`,
- signal name.

Visibility-only rules should use `Sensitivity.S0` and no categories. They still matter because fusion can combine visibility evidence with sensitive category evidence from another rule.

Example cases:

- `email@example.com` maps to `S3`, `PU`, `IDENTITY`.
- `username: alice` maps to `S2`, `P2`, `IDENTITY`.
- `group chat` maps to `S0`, `P3`, no category.
- `personal diary` maps to `S0`, `P4`, no category.

## Subagent Tasks

Rule-detector subagents should:

- add patterns for missing `Category` values,
- add counterexamples to reduce false positives,
- keep rules small and explainable,
- preserve packed classification round-trip behavior,
- place new rules in the concern-specific `rules_*.py` file,
- add tests for each new rule family,
- document rule intent in code only when the pattern is not self-evident.
