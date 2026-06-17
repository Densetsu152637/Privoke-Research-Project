# param-update-service

This Python service accepts model parameter update payloads over gRPC and persists them for downstream research workflows.

It is part of the adaptive-experiment infrastructure, not the prompt classification path.

## Responsibilities

The update service should:

- receive protobuf update messages,
- validate required metadata,
- persist updates to a durable sink,
- preserve enough metadata for later analysis,
- reject malformed or incompatible payloads,
- avoid storing raw prompt text unless an experiment explicitly requires and approves it.

## Inputs and Outputs

Input:

- parameter update protobuf message from `shared/proto`.

Output:

- acknowledgment or error,
- persisted JSONL or future database record.

## Relationship to Client Runtime

The client runtime may eventually emit aggregate feedback or parameter update signals, but current prompt classification should not depend on this service.

If future subagents add runtime feedback, they should keep privacy boundaries strict:

- no raw prompt text,
- bucketed or anonymized metrics where possible,
- detector version metadata,
- explicit experiment IDs.

## Subagent Tasks

Subagents working here should:

- add schema validation,
- add durable storage abstraction,
- add retry-safe idempotency keys,
- add tests for malformed updates,
- document retention and privacy behavior,
- coordinate protobuf changes through `shared/proto`.
