# Services

This directory contains PriVoke's service-level components. The services are intentionally separated so prompt detection work, parameter streaming, update ingestion, and fuzzing can evolve independently.

## Service Map

- `client-runtime`: Python prompt privacy server. This is the hosted three-layer detection pipeline.
- `model-streaming-service`: Go gRPC service for exposing current model parameter snapshots.
- `param-update-service`: Python gRPC service for requesting fuzzer training cycles, accepting parameter update payloads, and writing them to a sink.
- `privoke-fuzzer`: Python gRPC worker that waits for training requests, generates labeled prompts, runs local layer-specific prompt tests, evaluates the streamed semantic model, and submits updates.

## Runtime Detection Path

Only `client-runtime` is currently in the prompt path:

```text
prompt
  -> regex/rule detector
  -> NER/entity detector
  -> semantic context detector
  -> fusion
  -> enforcement
  -> telemetry
```

The other services are research infrastructure for future adaptive and distributed experiments. They should not be made dependencies of the client-side privacy decision unless the architecture explicitly changes.

## Service Contracts

Cross-service data contracts should live under `shared/proto`. Do not create ad hoc JSON contracts between services if a protobuf API already exists or is likely to be reused.

Each service README describes:

- the service purpose,
- its expected inputs and outputs,
- how it participates in the research pipeline,
- what a subagent should improve next.

## Subagent Guidance

When assigning work:

- Keep detection changes in `client-runtime`.
- Keep gRPC contract changes in `shared/proto` and then update generated service code.
- Keep prompt generation and LLM-only adaptive update work in `privoke-fuzzer`.
- Keep fuzzer request initiation, persistence, and ingestion work in `param-update-service`.
- Keep snapshot serving and client fetch behavior in `model-streaming-service`.
