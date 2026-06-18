# Detection Orchestration

This package contains the non-detector glue for the client runtime:

- preprocessing,
- fusion,
- enforcement.

It should not become a fourth detector layer. Its job is to normalize input, combine detector evidence, derive an operational `RiskVector`, and make enforcement decisions.

## Files

- `preprocessing.py`: text normalization before all detectors.
- `fusion.py`: combines rule, NER, and semantic evidence into one `Classification`.
- `enforcement_engine.py`: converts fused output into `ALLOW`, `WARN_AND_MASK`, or `BLOCK_PROMPT`.

## Preprocessing Responsibilities

The normalizer should:

- normalize Unicode,
- collapse repeated whitespace,
- de-obfuscate common evasions such as `[at]` or `(dot)`,
- preserve enough text structure for downstream span extraction,
- avoid deleting sensitive terms.

Preprocessing output is the canonical text passed to the three detection layers.

## Fusion Responsibilities

Fusion consumes three detector outputs:

- `RuleDetector.analyze(...) -> list[ClassificationResult]`,
- `EntityNERDetector.extract_entities(...) -> list[ClassificationResult]`,
- `AbstractClassifier.classify(...) -> list[ClassificationResult]`.

Fusion should:

- preserve the strongest sensitivity,
- merge categories,
- preserve the strongest known visibility,
- treat `Visibility.PU` as unknown with comparison score zero,
- account for entity combinations,
- derive `RiskVector` from the final `Classification`,
- carry detector evidence forward for telemetry.

Fusion should not classify by legacy strings such as `"PII"` or `"HIGH"`.

## Enforcement Responsibilities

Enforcement should be deterministic and easy to audit.

Current policy:

- block `S3` or `RiskVector.DIRECT_PII`,
- warn and mask `S2`, `RiskVector.QUASI_PII`, or `RiskVector.AUTH`,
- allow low-risk content.

Masking should prefer entity spans from NER or LLM output. Regex fallback is acceptable when spans are unavailable.

## Subagent Tasks

Good subagent tasks in this package:

- improve `RiskVector` derivation tests,
- add table-driven enforcement tests,
- improve masking span handling,
- add calibration hooks for entity boosts,
- add regression tests for detector disagreement.
