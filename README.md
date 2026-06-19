# PriVoke Research Project

PriVoke is a research prototype for client-side privacy protection around LLM prompts. The runtime is designed to inspect user text before it leaves the client, classify privacy risk using layered detectors, apply enforcement, and emit metadata-only telemetry for later analysis.

The detection design follows the same broad shape as Casper-style prompt sanitization research: a fast rule-based filter, an entity recognition layer, and a semantic context layer. Casper describes this as a three-layer mechanism using rules, named entity recognition, and a local topic or semantic identifier for privacy-sensitive prompts. PriVoke adapts that pattern into a modular service-oriented research codebase.

Reference: https://arxiv.org/abs/2408.07004

## Detection Architecture

The client runtime is the core privacy pipeline.

```text
Prompt text
  -> preprocessing and normalization
  -> layer 1: regex/rule detector
  -> layer 2: NER/entity detector
  -> layer 3: semantic context detector
  -> ClassificationResult evidence
  -> ClassificationResult-derived PriVokeAction
  -> metadata-only telemetry
```

Each detector should produce evidence that can be mapped into the shared `Classification` object:

- `Sensitivity`: `S0` through `S3`
- `Visibility`: `P0`, `P1`, `P2`, `P3`, `P4`, `PU`
- `Category`: health, politics, religion, criminal, financial, sexual, child, location, identity, and third-party disclosures

`PriVokeAction` is derived from `ClassificationResult`, not a bare `Classification`. Current policy blocks high-confidence `S3`, warns on `S2`, warns on identifier/location evidence combined with restricted/private visibility or each other, and allows low-risk `S0`/`S1` context. Very low-confidence `S3` is downgraded to `WARN` so detector confidence can affect enforcement.

## Repository Layout

- `services/client-runtime`: Python runtime for prompt detection, fusion, enforcement, CLI demos, and parameter fetching.
- `services/model-streaming-service`: Go gRPC service that serves model parameter snapshots.
- `services/param-update-service`: Python gRPC service that requests fuzzer training cycles and accepts parameter update payloads.
- `services/privoke-fuzzer`: Python gRPC worker for request-driven prompt generation, streamed semantic-model evaluation, and update traffic.
- `shared/proto`: Shared protobuf contracts used across services.
- `paper`: Research figures and experiment artifacts.

## Service Responsibilities

`client-runtime` should be treated as the reference implementation of the privacy detection pipeline. Subagents working on detection behavior should usually start there.

`model-streaming-service`, `param-update-service`, and `privoke-fuzzer` support later adaptive experiments. They are not part of the prompt classification path, but they are important for future parameter update, fuzzing, and distributed evaluation work.

`shared/proto` is the contract boundary. Any cross-service API change should start with protobuf updates, followed by generated code and service implementation updates.

## Development Commands

Run the full development stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Run the baseline stack:

```bash
docker compose up --build
```

Run the client runtime directly:

```bash
cd services/client-runtime
python cli.py pipeline
```

Fetch streamed parameters:

```bash
cd services/client-runtime
python cli.py fetch-params --target localhost:50051 --model-id privoke-baseline
```

## Subagent Work Model

Future subagents should work in bounded areas:

- Rule detector subagents: add or refine regex rules, signals, visibility cues, and `Classification` mappings.
- NER subagents: improve entity extraction, span handling, entity normalization, confidence, and fallback behavior.
- Semantic detector subagents: improve contextual classification prompts or local model behavior while preserving the `Classification` contract.
- Fusion/enforcement subagents: adjust scoring, disagreement handling, masking, and action policy.
- Telemetry subagents: improve privacy-preserving event shape without raw text leakage.
- Service subagents: improve gRPC contracts, parameter streaming, fuzzing, and update persistence.

Subagents should avoid reintroducing string-based category or severity flow. Use `ClassificationResult`, `PriVokeAction`, and shared protobuf contracts where applicable.
