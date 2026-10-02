# Regex Rule Detector

> Source area: `extension/client-runtime/src/regex`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

This directory contains layer 1 of the PriVoke client-runtime detector pipeline: deterministic regex and heuristic detection.

`RuleDetector.analyze(text)` returns `list[ClassificationResult]`. It does not merge its matches. The client runtime later selects the strongest action-producing result.

## Files

- `rule_detector.py`: compiles rules, collects matches, adds heuristics, deduplicates matches, and converts them to `ClassificationResult`.
- `rule_types.py`: `RuleDefinition`, `CompiledRule`, and `RuleMatch`.
- `rule_registry.py`: deterministic rule ordering.
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

`rule_heuristics.py` adds synthetic matches for:

- prompts over 80 words, as `S1` `IDENTITY` personal narrative evidence,
- two or more structured identity fields, as `S2` `IDENTITY`,
- short prompts with high-confidence `S3` matches, as concentrated sensitive data.

## Visibility Rules

Visibility-only rules use `Sensitivity.S0` and no categories. In the current hosted pipeline, those `ALLOW`-level results are not merged with separate sensitive matches. They are still useful for direct layer probes and future fusion work, but request-level visibility should be passed through `visibility_hint` when the hosted API needs it applied to the selected result.

## Subagent Tasks

Rule-detector subagents should:

- add missing patterns in the concern-specific `rules_*.py` module,
- add false-positive counterexamples,
- keep rule definitions small and auditable,
- preserve enum-backed `Classification` mappings,
- add tests around both direct `RuleDetector` output and hosted `/analyze` behavior when selection semantics matter.
