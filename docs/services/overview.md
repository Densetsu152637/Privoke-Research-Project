# Services

> Source area: `services`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

This directory contains PriVoke's research-support services. The server stack is the Rust topology of the [server rewrite plan](../plans/rust-server-rewrite.md): `model-streaming-service` and `telemetry-service` always run, and the opt-in `v3-training` Compose profile adds `param-update-service`, `v3-fuzzer` and `v3-runtime`, which retrain all three standard V3 tiers. Every service is Rust. Each listener terminates mutual TLS in the service with a per-RPC role policy (`rust/crates/privoke-transport`), and there is no reverse proxy. The WebExtension detector is a separate workstation deployment of `extension/client-runtime`; the server no longer runs a `client-runtime` container.

## Service Map

- `../extension/client-runtime`: Python package for prompt privacy inspection. It owns detector selection/scheduling and runs on the workstation; no server container runs it.
- `model-streaming-service`: Rust gRPC server (`rust/services/model-streaming`) that serves the model catalog and standard V3 packages to registered installations (public listener) and to registered services (internal listener). The Go service in `services/model-streaming-service` is retired from deployment and kept as the parity oracle.
- `param-update-service`: Rust gRPC server (`rust/services/param-update`) that owns the V3 checkpoint store and the routine-training scheduler. It asks `v3-fuzzer` for one HEADS fit and one FULL_ENCODER fit of each V3 tier per round. Each candidate passes DriftGate, GuardGate and RetentionGate and is then published under an Ed25519-signed statement (`v3_*.rs`; see [V3 publication](../runtime/v3-publication.md)). The V1 gradient update RPCs were removed in stage V3-R8b: `SubmitParameterUpdate` answers `UNIMPLEMENTED`, and V1 models are served for detection only. The Python service is the retired oracle.
- `v3-fuzzer`: Rust gRPC service (`rust/services/v3-fuzzer`, `V3_MODE=routine` in the deployment) that samples the frozen BC01 and AU3 curricula, asks `v3-runtime` to fit a candidate (always semantic-only, layer list `[SEMANTIC]`) and sends it to the checkpoint service as a `trainer`. The Python `services/privoke-fuzzer` is frozen and not deployed; see [fuzzer](fuzzer.md).
- `v3-runtime`: Rust gRPC training service (`rust/services/v3-runtime`) on the internal `training` network. It fits V3 candidates and stages them in the checkpoint store; it never commits them.
- `analysis-service`: Rust gRPC service (`rust/services/analysis`) that still builds and serves `AnalyzePrompt`, `DetectAnnotationPresence` and `Health`, but is in no Compose file and is not deployed.
- `telemetry-service`: Rust gRPC collector (`rust/services/telemetry`) with SQLite persistence for privacy-minimal runtime events. The Python service is the retired oracle.

## Runtime Detection Path

Prompt inspection implementation lives in `extension/client-runtime` and runs on the workstation. The server stack runs no detector pipeline: V3 training fits only the semantic model in `v3-runtime`. The pipeline is:

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

`v3-fuzzer` never imports detector or model implementations; it requests fits from `v3-runtime` through `TrainingService`.

The WebExtension is a separate deployment of the same detector package. Its supervisor-owned runtime on `127.0.0.1:50057` and bridge on `127.0.0.1:8080` are outside Compose and are never fuzzer targets.

## gRPC Service Contracts

Cross-service APIs live in `shared/proto/privoke/v1/parameters.proto` and `runtime.proto`.

- `ModelStreamingService.GetModelParameters(ModelParametersRequest) -> ModelParametersResponse`
- `ParamUpdateService.GetParameterUpdateStatus(ParameterUpdateStatusRequest) -> ParameterUpdateStatus` and `Health`. `ParamUpdateService.SubmitParameterUpdate` stays in the proto but answers `UNIMPLEMENTED` for every caller (removed in stage V3-R8b; `rust/services/param-update/src/lib.rs`, `server.rs`).
- `CheckpointService` (`param-update-service`): `ResolveCurrent`, `FetchBlob`, `StageCheckpoint`, `CommitCandidate`, `GetCommitStatus`, `RollbackModel` and `Health`, defined in `shared/proto/privoke/experimental/v3.proto`.
- `TrainingService` (`v3-runtime`): `FitCandidate`, `GetFitStatus` and `Health`.
- `V3FuzzerService.RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`, `RunUnderlyingTrainingCycle` and `Health` (`v3-fuzzer`). The V1 `FuzzerService` proto remains for the frozen Python fuzzer only; no deployed service implements it.
- `ModelStreamingService` also implements `Health(HealthRequest) -> HealthResponse`.
- `PrivokeRuntimeService.AnalyzePrompt(AnalyzePromptRequest) -> AnalyzePromptResponse` and `Health(RuntimeHealthRequest) -> RuntimeHealthResponse` are served by the workstation runtime; `v3-runtime` serves only `AnalyzePrompt` with `layers == [SEMANTIC]` (V3 semantic inference) and answers every other method `UNIMPLEMENTED` (`rust/services/v3-runtime/src/lib.rs`). The gradient RPCs were removed from the Rust servers in stage V3-R8a.
- `PrivokeRuntimeControlService.SetRuntimeEnabled(SetRuntimeEnabledRequest) -> RuntimeControlStatus`, `Status(RuntimeHealthRequest) -> RuntimeControlStatus`, and `ModelStreamingHealth(RuntimeHealthRequest) -> RuntimeHealthResponse` are implemented by `extension/runtime-supervisor` for workstation-local extension control and are not started by server Compose.
- `TelemetryService.RecordTelemetry(TelemetryPacket) -> RecordTelemetryResponse`
- `TelemetryService.GetTelemetrySummary(GetTelemetrySummaryRequest) -> GetTelemetrySummaryResponse`
- `TelemetryService.Health(TelemetryHealthRequest) -> TelemetryHealthResponse`

Do not create ad hoc JSON contracts between services when a protobuf boundary exists.

## Compose Wiring

Ports (container side; the internal ones are never published, and the public ones are published only by the deployment):

- `model-streaming-service`: public `50443` (published as `443`), internal `50051`
- `telemetry-service`: public `58443` (published as `8443`), internal `50055`
- `param-update-service`: `50052` (profile `v3-training`)
- `v3-runtime`: `50171` (profile `v3-training`, internal `training` network)
- `v3-fuzzer`: `50172` (profile `v3-training`, internal `training` network)

`docker-compose.prod.yml` is the explicitly selected production-style stack: non-root images, read-only root filesystems, dropped capabilities, `no-new-privileges` and restart policies. Each service takes `--cert`, `--key`, `--client-ca`, `--crl` and `--registry` from a certificate directory (`PRIVOKE_PKI_DIR`, with the hot-reloaded CRL and registry in `PRIVOKE_PKI_LIVE_DIR`) and exits before binding without them; `v3-fuzzer` and `v3-runtime` take the equivalent settings. A one-shot `model-seed` copies the shipped model artifacts into an empty `model-data` volume. The two public listeners are published on `127.0.0.1` unless `MODEL_PUBLISH` and `TELEMETRY_PUBLISH` say otherwise. `v3-fuzzer` and `v3-runtime` sit on the `internal: true` network `training` with no route out and no published port. Select the training services with `--profile v3-training` or `COMPOSE_PROFILES=v3-training`. The default `docker-compose.yml` extends those definitions, publishes the internal listeners on `127.0.0.1` for host test clients and disables restart loops; there is no separate development image. `deploy/gce/compose.yml` is the same topology on registry images. `docker-compose.legacy.yml` is the retired Python and Go stack, kept only for the historical study stacks and the parity oracle.

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
- Keep V3 curriculum sampling and fit orchestration in `v3-fuzzer`, and candidate fitting in `v3-runtime`.
- Keep the checkpoint store, the gates, signed publication and the routine scheduler in `param-update-service`.
- Keep parameter snapshot serving in `model-streaming-service`.
