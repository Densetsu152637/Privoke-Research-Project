# Semantic Context Detector

This directory contains layer 3 of the PriVoke detection pipeline: semantic and contextual privacy detection.

This layer should catch privacy risks that regex rules and NER cannot reliably detect. It is responsible for implicit disclosure, sensitive-topic inference, and contextual identification risk.

## Responsibilities

The semantic detector should identify:

- health disclosures without explicit medical identifiers,
- political or religious affiliation,
- sexual orientation or intimate disclosures,
- criminal history or legal exposure,
- child or minor-related disclosures,
- third-party sensitive information,
- indirect identification through combinations of job, location, timing, relationship, and unique context,
- visibility cues when the prompt states where the text came from.

## Output Contract

`AbstractClassifier.classify(text)` should return `list[ClassificationResult]`.
Each semantic risk found by the model should produce one result containing:

- `classification`: parsed `Classification`,
- `section_of_text`: classified text section,
- `span`: optional section span,
- `reasoning`: concise explanation,
- `confidence`: optional model confidence,
- `metadata`: optional classifier-specific context.

The rest of the runtime should not consume model-specific category strings. The semantic layer is the boundary where model JSON is converted into `Classification`.

## Model Strategy

The current implementation may use a remote LLM for prototyping. Future work may replace or supplement it with:

- a local LLM,
- a lightweight topic classifier,
- a fine-tuned transformer,
- a rules-plus-embedding classifier.

Any replacement must preserve the same output contract.

## Prompting Requirements

The semantic classifier should ask for:

- sensitivity as `S0` through `S3`,
- visibility as `P0`, `P1`, `P2`, `P3`, `P4`, or `PU`,
- categories from the shared `Category` enum,
- concise reasoning.

Malformed model output should be ignored or converted to `S0`, `PU`, and no categories.

## Subagent Tasks

Semantic-detector subagents should:

- improve prompt reliability,
- add validation for enum values,
- test fallback paths,
- reduce overclassification of generic safe text,
- improve detection of implicit third-party and sensitive-topic disclosures,
- prepare a local-model interface that can replace remote API calls.
