# Services

This directory contains PriVoke's research-support services. Both production and development server deployments also include an always-on server instance of `extension/client-runtime`, for a total of five gRPC services. That instance is distinct from the workstation detector started for the WebExtension.

## Service Map

- `../extension/client-runtime`: Python gRPC service for server-side prompt privacy inspection. It owns detector selection/scheduling and also includes an optional local HTTP harness.
- `model-streaming-service`: Go gRPC server that returns the current parameter snapshot used by the streamed semantic backend.
- `param-update-service`: Python gRPC server that appends parameter updates to JSONL storage and can request fuzzer training cycles after startup.
- `privoke-fuzzer`: Python gRPC worker plus CLI for prompt generation, layer probes, streamed semantic-model evaluation, and update submission.
- `telemetry-service`: Python gRPC collector with SQLite persistence for privacy-minimal runtime events.

## Runtime Detection Path

Prompt inspection implementation lives in `extension/client-runtime`. In the server topology, the fuzzer reaches it only through the Compose gRPC service:

```text
prompt
  -> normalization
  -> regex/rule detector
  -> NER/entity detector
  -> semantic classifier backend
  -> strongest result/action selection
  -> local response serialization
```

The runtime chooses one semantic backend at a time:

- `streamed`: fetches parameters from `model-streaming-service` and applies the local parameter-backed semantic model.
- `local`: calls an OpenAI-compatible local API such as LM Studio.
- `openai`: calls the OpenAI SDK.

The fuzzer requests full-runtime or isolated-layer execution through `PrivokeRuntimeService`; it never imports detector implementations.

The WebExtension is a separate deployment of the same detector package. Its supervisor-owned runtime on `127.0.0.1:50057` and bridge on `127.0.0.1:8080` are outside Compose and are never fuzzer targets.

## gRPC Service Contracts

Cross-service APIs live in `shared/proto/privoke/v1/parameters.proto` and `runtime.proto`.

- `ModelStreamingService.GetModelParameters(ModelParametersRequest) -> ModelParametersResponse`
- `ParamUpdateService.SubmitParameterUpdate(ParameterUpdateRequest) -> ParameterUpdateAck`
- `FuzzerService.RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- The parameter-streaming, parameter-update, and fuzzer services each implement `Health(HealthRequest) -> HealthResponse`.
- `PrivokeRuntimeService.AnalyzePrompt(AnalyzePromptRequest) -> AnalyzePromptResponse`
- `PrivokeRuntimeService.Health(RuntimeHealthRequest) -> RuntimeHealthResponse`
- `PrivokeRuntimeControlService.SetRuntimeEnabled(SetRuntimeEnabledRequest) -> RuntimeControlStatus`, `Status(RuntimeHealthRequest) -> RuntimeControlStatus`, and `ModelStreamingHealth(RuntimeHealthRequest) -> RuntimeHealthResponse` are implemented by `extension/runtime-supervisor` for workstation-local extension control and are not started by server Compose.
- `TelemetryService.RecordTelemetry(TelemetryPacket) -> RecordTelemetryResponse`
- `TelemetryService.ListTelemetry(ListTelemetryRequest) -> ListTelemetryResponse`
- `TelemetryService.Health(TelemetryHealthRequest) -> TelemetryHealthResponse`

Do not create ad hoc JSON contracts between services when a protobuf boundary exists.

## Compose Wiring

Default ports:

- `model-streaming-service`: `50051`
- `param-update-service`: `50052`
- `privoke-fuzzer`: `50053`
- `client-runtime`: detector `50054`
- `telemetry-service`: `50055`

The production-style Compose file exposes these ports only to its internal service network and publishes none to the host. The development override publishes `50051`, `50052`, `50054`, and `50055` on `127.0.0.1` for local tests; `50053` remains internal.

`docker-compose.yml` is the production-style deployment: all five services are built into non-root runtime images with read-only root filesystems, dropped capabilities, `no-new-privileges`, and restart policies. A network-disabled one-shot initializer fixes named-volume ownership before the data-writing services start. Compose healthchecks exercise each gRPC `Health` contract rather than only checking that a TCP port is open. The fuzzer waits for `client-runtime` health, then reports healthy on `50053`, which allows `param-update-service` to start its optional requester without racing startup. `docker-compose.dev.yml` preserves that topology while using separately tagged development images, bind-mounting service source, regenerating protobuf bindings, disabling restart loops, and mounting fuzzer prompt-test dumps at `./dumps/privoke-fuzzer`.

The WebExtension, its supervisor, bridge, and workstation detector are not Docker services and are not part of either server deployment.

## Documentation Scope

Each service README should describe:

- current purpose and non-purpose,
- runtime inputs and outputs,
- ports and environment variables,
- how it participates in the stack,
- known prototype limitations that matter for future rewrites.

## Subagent Guidance

- Keep detector changes in `extension/client-runtime`.
- Keep shared API changes in `shared/proto` and regenerate affected bindings.
- Keep prompt generation, layer testing, and streamed semantic training in `privoke-fuzzer`.
- Keep update persistence and fuzzer request initiation in `param-update-service`.
- Keep parameter snapshot serving in `model-streaming-service`.
