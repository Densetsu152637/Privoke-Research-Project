# Regex Rule Detector

> Source area: `extension/client-runtime/src/regex`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

This directory contains layer 1 of the PriVoke client-runtime detector pipeline: deterministic regex and heuristic detection.

`RuleDetector.analyze(text)` returns `list[ClassificationResult]`. It does not merge its matches. The client runtime combines classifications while retaining one primary evidence span and all per-layer findings.

## Files

- `rule_detector.py`: compiles rules, collects matches, adds heuristics, deduplicates matches, and converts them to `ClassificationResult`.
- `rule_types.py`: `RuleDefinition`, `CompiledRule`, and `RuleMatch`.
- `rule_registry.py`: deterministic rule ordering.
- `rule_validators.py`: checksum and context validators attached to rules.
- `rule_heuristics.py`: synthetic matches derived from aggregate match/text properties.
- `rules_visibility.py`: visibility-only cues.
- `rules_identity.py`: direct and structured identity patterns.
- `rules_location.py`: precise and quasi-location patterns.
- `rules_health.py`: medical and mental-health patterns.
- `rules_financial.py`: account, card, money, income, debt, and asset patterns.
- `rules_sensitive.py`: politics, religion, criminal, sexual, child, and third-party cues.
- `rules_context.py`: family, workplace, and timestamp context.

## Output Contract

Each regex or heuristic hit becomes:

```python
ClassificationResult(
    classification=Classification(...),
    section_of_text=matched_text,
    reasoning="Matched rule '<rule_name>'",
    span=(start, end),
    confidence=0.95,
    metadata={"rule_name": "<rule_name>"},
)
```

Heuristic matches use lower confidence values.

Rules map directly to `Sensitivity`, `Visibility`, and `Category` values. They should not return legacy severity/category strings.

## Current Heuristics

`rule_heuristics.py` adds synthetic matches for (prompt length alone is not evidence and is never used):

- two or more structured identity fields, as `S2` `IDENTITY`,
- short prompts with high-confidence `S3` matches, as concentrated sensitive data.

## Precision Rules

- Kin terms and `family` (`family_disclosure`) need a possessive determiner (my/our/his/her/their), optionally with up to two hyphen- or space-joined modifier words (`ex-wife`, `soon-to-be ex-husband`, `step-daughter`). Non-possessive self-statements such as "I have two kids" are intentionally not matched. `child` needs a possessive plus child noun, `aged N` (1-17), a possessive before `N-year-old`, or `N-year-old` followed by a person noun (son, girl, toddler, pupil...); object ages (`a 5-year-old laptop`) do not match, and bare "student"/"minor" no longer count.
- `financial_keyword` covers personal financial-state nouns only (salary, income, loan, mortgage, debt, balance, savings, net worth, credit score/history/report) after my/his/her/their with one optional modifier (`my monthly salary`, `my bank balance`); bare "my account"/"my bank" does not.
- `location_keyword` needs its connector (`live in/on/at/near`, `address is`, `address:`, `location in`) followed by a capture that is not a closed-class word (articles, pronouns, prepositions, conjunctions, auxiliaries).
- `structured_identity` values stay on one line and capture at most five tokens; a `phone` label needs a value starting with a digit, `+` or `(`.
- Validators reject shape-only hits: Luhn for card numbers, mod-97 for IBANs, mod-11 for NHS numbers, and issuable area/group/serial ranges for US SSNs (native and Presidio-derived rules). The Presidio alphanumeric driver-licence pattern needs five digits or a whole-word licence context term (`license`, `licence`, `lic`, `dl`, `cdl`); the ambiguous noun "driver" is not context. Context matching is word-bounded, never substring. The Presidio `mm/yy` date needs a date context word, so ratings like `7/10` do not match.
- `password_assignment` ignores placeholder values (required, optional, none, null, true, false and similar); `social_handle` ignores chat mentions (`@here`, `@everyone`, `@channel`, `@all`); `license_plate` ignores standards identifiers such as `rfc-`, `cve-` and `iso-` numbers.
- Known limit: the detector receives lowercased, normalised text, so capitalisation cannot gate proper nouns (`street_address`, `route_or_commute`, `vin`, `passport`). Fixing this needs the original-case text passed through `pipeline.py` and every layer's callable interface.

## Visibility Rules

Workplace matching requires a personal employer/workplace declaration or a
structured employment field. Generic discussion of work, companies, or managers
does not by itself establish identity disclosure.

Amount and coarse-location rules likewise require a personal declaration or a
relevant labeled field. Public prices, generic origins and venue descriptions
do not alone establish a person's financial or residential disclosure. Direct
account, card, street-address and coordinate patterns remain separate rules.

Visibility-only rules use `Sensitivity.S0` and no categories. The hosted pipeline retains these `ALLOW` findings and combines their strongest known visibility with sensitive evidence. Request-level `visibility_hint` can further increase privacy restrictions without weakening an existing decision.

## Subagent Tasks

Rule-detector subagents should:

- add missing patterns in the concern-specific `rules_*.py` module,
- add false-positive counterexamples,
- keep rule definitions small and auditable,
- preserve enum-backed `Classification` mappings,
- add tests around both direct `RuleDetector` output and hosted `/analyze` behavior when selection semantics matter.
