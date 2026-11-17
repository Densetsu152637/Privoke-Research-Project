# Services

> Source area: `services`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

This directory contains PriVoke's research-support services. The server stack is the Rust topology of the [server rewrite plan](../plans/rust-server-rewrite.md): `model-streaming-service` and `telemetry-service` always run, and the opt-in `legacy-training` Compose profile adds `param-update-service`, `privoke-fuzzer` and the quarantined `analysis-service`. Every listener is mutual TLS and there is no reverse proxy. The WebExtension detector is a separate workstation deployment of `extension/client-runtime`; the server no longer runs a `client-runtime` container.

## Service Map

- `../extension/client-runtime`: Python package for prompt privacy inspection. It owns detector selection/scheduling. On the server its pipeline runs only inside the analysis service's sandboxed worker.
- `model-streaming-service`: Rust gRPC server (`rust/services/model-streaming`) that serves the model catalog and standard V3 packages to registered installations (public listener) and to registered services (internal listener). The Go service in `services/model-streaming-service` is retired from deployment and kept as the parity oracle.
- `param-update-service`: Rust gRPC server (`rust/services/param-update`) that appends parameter updates to JSONL storage with drift bounds and can request fuzzer training cycles after startup. The Python service is the retired oracle.
- `privoke-fuzzer`: Python gRPC worker plus CLI for prompt generation, layer probes, runtime-delegated semantic training, and update submission.
- `analysis-service`: Rust gRPC service (`rust/services/analysis`) in a quarantined container (no route out, read-only root, no capabilities) that runs the Python worker for the fuzzer's semantic-only analysis and gradient requests.
- `telemetry-service`: Rust gRPC collector (`rust/services/telemetry`) with SQLite persistence for privacy-minimal runtime events. The Python service is the retired oracle.

## Runtime Detection Path

Prompt inspection implementation lives in `extension/client-runtime`. In the server topology, the fuzzer reaches it only through the quarantined `analysis-service`:

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

The fuzzer requests prompt analysis or a bounded semantic-gradient batch through `PrivokeRuntimeService`; it never imports detector or model implementations and never fetches model parameters.

The WebExtension is a separate deployment of the same detector package. Its supervisor-owned runtime on `127.0.0.1:50057` and bridge on `127.0.0.1:8080` are outside Compose and are never fuzzer targets.

## gRPC Service Contracts

Cross-service APIs live in `shared/proto/privoke/v1/parameters.proto` and `runtime.proto`.

- `ModelStreamingService.GetModelParameters(ModelParametersRequest) -> ModelParametersResponse`
- `ParamUpdateService.SubmitParameterUpdate(ParameterUpdateRequest) -> ParameterUpdateAck`
- `FuzzerService.RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- The parameter-streaming, parameter-update, and fuzzer services each implement `Health(HealthRequest) -> HealthResponse`.
- `PrivokeRuntimeService.AnalyzePrompt(AnalyzePromptRequest) -> AnalyzePromptResponse`
- `PrivokeRuntimeService.ComputeSemanticGradients(ComputeSemanticGradientsRequest) -> ComputeSemanticGradientsResponse`
- `PrivokeRuntimeService.Health(RuntimeHealthRequest) -> RuntimeHealthResponse`
- `PrivokeRuntimeControlService.SetRuntimeEnabled(SetRuntimeEnabledRequest) -> RuntimeControlStatus`, `Status(RuntimeHealthRequest) -> RuntimeControlStatus`, and `ModelStreamingHealth(RuntimeHealthRequest) -> RuntimeHealthResponse` are implemented by `extension/runtime-supervisor` for workstation-local extension control and are not started by server Compose.
- `TelemetryService.RecordTelemetry(TelemetryPacket) -> RecordTelemetryResponse`
- `TelemetryService.GetTelemetrySummary(GetTelemetrySummaryRequest) -> GetTelemetrySummaryResponse`
- `TelemetryService.Health(TelemetryHealthRequest) -> TelemetryHealthResponse`

Do not create ad hoc JSON contracts between services when a protobuf boundary exists.

## Compose Wiring

Ports (container side; the internal ones are never published, and the public ones are published only by the deployment):

- `model-streaming-service`: public `50443` (published as `443`), internal `50051`
- `telemetry-service`: public `58443` (published as `8443`), internal `50055`
- `param-update-service`: `50052`
- `privoke-fuzzer`: `50053`
- `analysis-service`: `50054` (internal networks only)

`docker-compose.prod.yml` is the explicitly selected production-style stack: non-root images, read-only root filesystems, dropped capabilities, `no-new-privileges` and restart policies. Each service takes `--cert`, `--key`, `--client-ca`, `--crl` and `--registry` from a certificate directory (`PRIVOKE_PKI_DIR`, with the hot-reloaded CRL and registry in `PRIVOKE_PKI_LIVE_DIR`) and exits before binding without them; the Python fuzzer takes the equivalent `PRIVOKE_SERVER_TLS_*` settings and an allow list. A one-shot `model-seed` copies the shipped model artifacts into an empty `model-data` volume; `param-update-bootstrap` prepares the mutable model before the update service starts. The two public listeners are published on `127.0.0.1` unless `MODEL_PUBLISH` and `TELEMETRY_PUBLISH` say otherwise. The analysis service sits on two `internal: true` networks, one shared with the fuzzer and one with its own model-streaming instance. The default `docker-compose.yml` extends those definitions, publishes the internal listeners on `127.0.0.1` for host test clients and disables restart loops; there is no separate development image. `deploy/gce/compose.yml` is the same topology on registry images. `docker-compose.legacy.yml` is the retired Python and Go stack, kept only for the historical study stacks and the parity oracle.

The WebExtension, its controller and the workstation detector are not Docker services and are not part of either server deployment.

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
