# Services

This directory contains PriVoke's local client runtime and research-support services. Docker Compose deploys four gRPC services: prompt inspection, parameter streaming, fuzzer training requests, and update ingestion.

## Service Map

- `client-runtime`: Python gRPC service for local prompt privacy inspection. It owns detector selection/scheduling and also includes an optional local HTTP harness.
- `model-streaming-service`: Go gRPC server that returns the current parameter snapshot used by the streamed semantic backend.
- `param-update-service`: Python gRPC server that appends parameter updates to JSONL storage and can request fuzzer training cycles after startup.
- `privoke-fuzzer`: Python gRPC worker plus CLI for prompt generation, layer probes, streamed semantic-model evaluation, and update submission.

## Runtime Detection Path

Prompt inspection happens in `client-runtime`, through gRPC in Compose or its optional HTTP harness:

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

## gRPC Service Contracts

Cross-service APIs live in `shared/proto/privoke/v1/parameters.proto` and `runtime.proto`.

- `ModelStreamingService.GetModelParameters(ModelParametersRequest) -> ModelParametersResponse`
- `ParamUpdateService.SubmitParameterUpdate(ParameterUpdateRequest) -> ParameterUpdateAck`
- `FuzzerService.RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- Each gRPC service also implements `Health(HealthRequest) -> HealthResponse`
- `PrivokeRuntimeService.AnalyzePrompt(AnalyzePromptRequest) -> AnalyzePromptResponse`

Do not create ad hoc JSON contracts between services when a protobuf boundary exists.

## Compose Wiring

Default ports:

- `model-streaming-service`: `50051`
- `param-update-service`: `50052`
- `privoke-fuzzer`: `50053`
- `privoke-runtime`: `50054`

`docker-compose.dev.yml` bind-mounts each service's own source tree and regenerates protobuf bindings before startup. Fuzzer prompt-test dumps are bind-mounted to `./dumps/privoke-fuzzer`.

## Documentation Scope

Each service README should describe:

- current purpose and non-purpose,
- runtime inputs and outputs,
- ports and environment variables,
- how it participates in the stack,
- known prototype limitations that matter for future rewrites.

## Subagent Guidance

- Keep detector changes in `client-runtime`.
- Keep shared API changes in `shared/proto` and regenerate affected bindings.
- Keep prompt generation, layer testing, and streamed semantic training in `privoke-fuzzer`.
- Keep update persistence and fuzzer request initiation in `param-update-service`.
- Keep parameter snapshot serving in `model-streaming-service`.
