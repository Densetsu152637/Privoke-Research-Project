# Shared Contracts

This directory contains interfaces shared by more than one PriVoke service. Active contracts are `parameters.proto` and `runtime.proto` under `proto/privoke/v1`.

## Current Protobuf Contract

`parameters.proto` defines:

- `HealthRequest`
- `HealthResponse`
- `Parameter`
- `ModelParametersRequest`
- `ModelParametersResponse`
- `ParameterUpdateRequest`
- `ParameterUpdateAck`
- `FuzzerTrainingRequest`
- `FuzzerTrainingResponse`

Services:

- `ModelStreamingService`
  - `GetModelParameters(ModelParametersRequest) -> ModelParametersResponse`
  - `Health(HealthRequest) -> HealthResponse`
- `ParamUpdateService`
  - `SubmitParameterUpdate(ParameterUpdateRequest) -> ParameterUpdateAck`
  - `Health(HealthRequest) -> HealthResponse`
- `FuzzerService`
  - `RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
  - `Health(HealthRequest) -> HealthResponse`

## Producers and Consumers

- `model-streaming-service` implements `ModelStreamingService`.
- `client-runtime` consumes `ModelStreamingService` when using the `streamed` semantic backend.
- `client-runtime` implements `PrivokeRuntimeService`.
- `privoke-fuzzer` consumes `PrivokeRuntimeService` and `ModelStreamingService`, implements `FuzzerService`, and consumes `ParamUpdateService`.
- `param-update-service` implements `ParamUpdateService` and can consume `FuzzerService` when fuzzer requests are enabled.

## Generated Bindings

Each service keeps generated protobuf code locally:

- Go bindings under `services/model-streaming-service/gen`
- Python bindings under each Python service's `generated` directory

The Dockerfiles generate these bindings at image build time. `docker-compose.dev.yml` regenerates them at container startup before running the service.

## Contract Guidance

Shared files should define stable interfaces, not service-specific implementation details. Do not place detector rules, prompts, model weights, or service-local config here unless multiple services actually depend on them.

When changing the protobuf schema:

1. Update the relevant proto under `shared/proto/privoke/v1`.
2. Regenerate bindings in affected services.
3. Update the relevant service READMEs.
4. Add compatibility notes for any field semantics that older services cannot handle.

Avoid raw prompt text in shared telemetry or update contracts unless an experiment explicitly requires and approves it.
