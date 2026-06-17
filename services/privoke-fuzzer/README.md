# privoke-fuzzer

The fuzzer is a research worker for generating parameter perturbations and submitting update payloads. It is intended to support robustness, adaptive parameter experiments, and future detector hardening workflows.

It does not classify prompts directly.

## Responsibilities

The fuzzer should:

- fetch current parameter snapshots from `model-streaming-service`,
- generate controlled perturbations,
- submit update payloads to `param-update-service`,
- record experiment metadata,
- avoid producing updates that cannot be traced to an experiment configuration.

## Relationship to Detection Pipeline

The three-layer detection pipeline is:

1. regex/rule detection,
2. NER/entity extraction,
3. semantic context detection.

The fuzzer may later help generate hard examples or tune model parameters, but it should not bypass the client-runtime detector contracts. Any generated examples should be evaluated through `client-runtime`.

## Subagent Tasks

Subagents working here should:

- add deterministic seeds,
- add experiment configuration files,
- add bounds for perturbation magnitude,
- add provenance metadata to updates,
- add integration tests against the streaming and update services,
- optionally generate privacy prompt hard cases for offline evaluation.
