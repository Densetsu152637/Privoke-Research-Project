# model-streaming-service

This Go service exposes model parameter snapshots over gRPC. It supports research workflows where runtime components or fuzzing workers need to retrieve the current parameter state.

This service is not part of the prompt detection path. The prompt path lives in `services/client-runtime`.

## Responsibilities

The model streaming service should:

- serve parameter snapshots defined by `shared/proto/privoke/v1/parameters.proto`,
- expose stable gRPC methods for clients,
- include snapshot metadata such as model ID, version, and generation time,
- avoid embedding detector-specific policy in transport code,
- support local development through Docker Compose.

## Inputs and Outputs

Input:

- gRPC request containing consumer ID and model ID.

Output:

- model ID,
- version,
- generated timestamp,
- parameter list,
- metadata map.

## Relationship to Detection Pipeline

The three-layer privacy detection pipeline does not require this service to classify a prompt. This service is research infrastructure for future work such as:

- adaptive model parameter delivery,
- experiment configuration,
- fuzzing and feedback loops,
- runtime parameter synchronization.

## Subagent Tasks

Subagents working here should:

- improve gRPC error handling,
- add health checks,
- add snapshot versioning,
- add integration tests with `client-runtime fetch-params`,
- document parameter provenance,
- keep protobuf compatibility in mind.
