# Shared Contracts

> Source area: `shared`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

This directory contains interfaces shared by more than one PriVoke service. Active protobuf contracts are `parameters.proto`, `runtime.proto`, and `telemetry.proto` under `proto/privoke/v1`; `python/privoke_contracts` contains the shared classification value contract.

## Current Protobuf Contract

`parameters.proto` defines:

- `HealthRequest`
- `HealthResponse`
- `Parameter`
- `ModelParametersRequest`
- `ModelParametersResponse`
- `ParameterChunk` and `ModelParameterChunk`
- `ParameterUpdateRequest`
- `ParameterUpdateAck`
- `ParameterUpdateStatusRequest` and `ParameterUpdateStatus`
- `FuzzerTrainingRequest`
- `FuzzerTrainingResponse`

Services:

- `ModelStreamingService`
  - `GetModelParameters(ModelParametersRequest) -> ModelParametersResponse`
  - `StreamModelParameters(ModelParametersRequest) -> stream ModelParameterChunk`
  - `Health(HealthRequest) -> HealthResponse`
- `ParamUpdateService`
  - `SubmitParameterUpdate(ParameterUpdateRequest) -> ParameterUpdateAck`
  - `GetParameterUpdateStatus(ParameterUpdateStatusRequest) -> ParameterUpdateStatus`
  - `Health(HealthRequest) -> HealthResponse`
- `FuzzerService`
  - `RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
  - `RunPresenceTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
  - `Health(HealthRequest) -> HealthResponse`

`runtime.proto` defines requested detection layers, regex execution order, classifications, per-layer results, and:

- `PrivokeRuntimeService`
  - `AnalyzePrompt(AnalyzePromptRequest) -> AnalyzePromptResponse`
  - `ComputeSemanticGradients(ComputeSemanticGradientsRequest) -> ComputeSemanticGradientsResponse`
  - `DetectAnnotationPresence(DetectAnnotationPresenceRequest) -> DetectAnnotationPresenceResponse`
  - `ComputePresenceGradients(ComputePresenceGradientsRequest) -> ComputePresenceGradientsResponse`
  - `Health(RuntimeHealthRequest) -> RuntimeHealthResponse`
- `PrivokeRuntimeControlService`
  - `SetRuntimeEnabled(SetRuntimeEnabledRequest) -> RuntimeControlStatus`
  - `Status(RuntimeHealthRequest) -> RuntimeControlStatus`
  - `ModelStreamingHealth(RuntimeHealthRequest) -> RuntimeHealthResponse`

`telemetry.proto` defines privacy-minimal telemetry packets and:

- `TelemetryService`
  - `RecordTelemetry(TelemetryPacket) -> RecordTelemetryResponse`
  - `GetTelemetrySummary(GetTelemetrySummaryRequest) -> GetTelemetrySummaryResponse`
  - `Health(TelemetryHealthRequest) -> TelemetryHealthResponse`

## Producers and Consumers

- `model-streaming-service` implements `ModelStreamingService`.
- Both independently deployed `client-runtime` instances consume `ModelStreamingService` when configured with the `streamed` semantic backend.
- Both instances implement `PrivokeRuntimeService`: Compose runs one at `client-runtime:50054`, while the workstation supervisor owns another at `127.0.0.1:50057`.
- `extension/runtime-supervisor` implements `PrivokeRuntimeControlService` only for its workstation child and exposes both services to the WebExtension through its loopback bridge. Server Compose has no lifecycle control plane.
- `privoke-fuzzer` consumes only the Compose `PrivokeRuntimeService`, implements `FuzzerService`, and consumes `ParamUpdateService`. Only `client-runtime` consumes `ModelStreamingService` during training.
- `param-update-service` implements `ParamUpdateService` and can consume `FuzzerService` when fuzzer requests are enabled.
- A `client-runtime` instance produces privacy-minimal `TelemetryPacket` messages when telemetry is enabled; Compose enables this for its server instance.
- `telemetry-service` implements `TelemetryService` and persists those packets.

## Generated Bindings

Each service keeps generated protobuf code locally:

- Go bindings under `services/model-streaming-service/gen`
- Python bindings under each Python service's `generated` directory
- Workstation control-plane bindings under `extension/runtime-supervisor/generated`

The Dockerfiles generate these bindings at image build time. `docker-compose.dev.yml` regenerates them at container startup before running the service.

The presence RPCs are additive. Rebuild affected service images and regenerate
runtime/fuzzer/evaluator and workstation consumers' bindings before calling them;
older servers do not implement these methods. Existing contextual RPCs retain
their field numbers and semantics.

## Annotation-presence contract

Presence is a separate `annotation_presence` task using an explicit
`privoke-presence-efficient`, `privoke-presence-balanced` or
`privoke-presence-quality` model ID. `DetectAnnotationPresence` requires request
ID and nonempty bounded text. It returns probability, stored threshold, typed
ABSENT/PRESENT prediction, model/version, artifact checksum, parameter fingerprint,
inference elapsed time and error. Check error first: UNSPECIFIED and default
numeric fields on failure are not a clean prediction. `elapsed_ms` measures
presence inference after model acquisition; it excludes fetch and browser overhead.

`PresenceTrainingExample` carries text, explicit ABSENT/PRESENT target, positive
weight and optional source group. UNSPECIFIED/unknown labels are rejected.
`ComputePresenceGradients` carries separate bounded training and held-out batches
and returns head deltas tied to the exact base version, binary metrics and
fingerprints. Runtime rejects normalized-text overlap and held-out group overlap;
grouped batches must provide group IDs consistently. The new fuzzer RPC samples
its binary curriculum and invokes this runtime path; it does not load model weights.
Its salted request fingerprint separates presence replay from contextual training.

Binary labels supply no contextual sensitivity, visibility, categories or action.
Presence output never maps a positive label to S3 or suppresses another detector's
private finding. `AnalyzePrompt`, contextual training and policy remain separate.
Read the [prospective model-refactor protocol](../paper/research/model-refactor-protocol.md)
for data exclusions, calibration, bounded update study and evidence limitations.

## Contract Guidance

Shared files should define stable interfaces, not service-specific implementation details. Do not place detector rules, prompts, model weights, or service-local config here unless multiple services actually depend on them.

When changing the protobuf schema:

1. Update the relevant proto under `shared/proto/privoke/v1`.
2. Regenerate bindings in affected services.
3. Update the relevant service READMEs.
4. Add compatibility notes for any field semantics that older services cannot handle.

Avoid raw prompt text in shared telemetry or update contracts unless an experiment explicitly requires and approves it.

`GetParameterUpdateStatus` is a private experiment-control RPC. It looks up a durable committed outcome by updater source, original request source, request ID, model ID, and training fingerprint. The fuzzer uses it to recover acknowledgments without repeating training or applying a payload twice. Regenerate bindings in all consumers when adopting this additive RPC. `ComputeSemanticGradients` carries separate training and held-out examples; their combined count/text limits apply before runtime model execution.
