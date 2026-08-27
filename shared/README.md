# Shared Contracts

This directory contains interfaces shared by more than one PriVoke service. Active protobuf contracts are `parameters.proto`, `runtime.proto`, and `telemetry.proto` under `proto/privoke/v1`; `python/privoke_contracts` contains the shared classification value contract.

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

`runtime.proto` defines requested detection layers, regex execution order, classifications, per-layer results, and:

- `PrivokeRuntimeService`
  - `AnalyzePrompt(AnalyzePromptRequest) -> AnalyzePromptResponse`
  - `Health(RuntimeHealthRequest) -> RuntimeHealthResponse`
- `PrivokeRuntimeControlService`
  - `SetRuntimeEnabled(SetRuntimeEnabledRequest) -> RuntimeControlStatus`
  - `Status(RuntimeHealthRequest) -> RuntimeControlStatus`
  - `ModelStreamingHealth(RuntimeHealthRequest) -> RuntimeHealthResponse`

`telemetry.proto` defines privacy-minimal telemetry packets and:

- `TelemetryService`
  - `RecordTelemetry(TelemetryPacket) -> RecordTelemetryResponse`
  - `ListTelemetry(ListTelemetryRequest) -> ListTelemetryResponse`
  - `Health(TelemetryHealthRequest) -> TelemetryHealthResponse`

## Producers and Consumers

- `model-streaming-service` implements `ModelStreamingService`.
- Both independently deployed `client-runtime` instances consume `ModelStreamingService` when configured with the `streamed` semantic backend.
- Both instances implement `PrivokeRuntimeService`: Compose runs one at `client-runtime:50054`, while the workstation supervisor owns another at `127.0.0.1:50057`.
- `extension/runtime-supervisor` implements `PrivokeRuntimeControlService` only for its workstation child and exposes both services to the WebExtension through its loopback bridge. Server Compose has no lifecycle control plane.
- `privoke-fuzzer` consumes only the Compose `PrivokeRuntimeService` plus `ModelStreamingService`, implements `FuzzerService`, and consumes `ParamUpdateService`.
- `param-update-service` implements `ParamUpdateService` and can consume `FuzzerService` when fuzzer requests are enabled.
- A `client-runtime` instance produces privacy-minimal `TelemetryPacket` messages when telemetry is enabled; Compose enables this for its server instance.
- `telemetry-service` implements `TelemetryService` and persists those packets.

## Generated Bindings

Each service keeps generated protobuf code locally:

- Go bindings under `services/model-streaming-service/gen`
- Python bindings under each Python service's `generated` directory
- Workstation control-plane bindings under `extension/runtime-supervisor/generated`

The Dockerfiles generate these bindings at image build time. `docker-compose.dev.yml` regenerates them at container startup before running the service.

## Contract Guidance

Shared files should define stable interfaces, not service-specific implementation details. Do not place detector rules, prompts, model weights, or service-local config here unless multiple services actually depend on them.

When changing the protobuf schema:

1. Update the relevant proto under `shared/proto/privoke/v1`.
2. Regenerate bindings in affected services.
3. Update the relevant service READMEs.
4. Add compatibility notes for any field semantics that older services cannot handle.

Avoid raw prompt text in shared telemetry or update contracts unless an experiment explicitly requires and approves it.
