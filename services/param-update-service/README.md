# param-update-service

This Python service accepts model parameter update payloads over gRPC and persists them for downstream research workflows.

It is part of the adaptive-experiment infrastructure, not the prompt classification path.

## Responsibilities

The update service should:

- receive protobuf update messages,
- optionally request training cycles from `privoke-fuzzer`,
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

## Fuzzer Requests

Set `FUZZER_PROMPT_COUNT` above zero to have this service request a training
cycle from `privoke-fuzzer` after startup.

```bash
FUZZER_TARGET=privoke-fuzzer:50053
FUZZER_PROMPT_COUNT=8
FUZZER_REQUEST_INTERVAL_SECONDS=0
```

The fuzzer sends the trained parameter deltas back through
`SubmitParameterUpdate`, so updates still pass through this service's normal
persistence path.

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
